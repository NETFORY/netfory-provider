//! Описание протокола `api://` — формат Mesh-пакета и подписанного ответа.
//!
//! Транспорт: двунаправленный QUIC-стрим Iroh.
//!   * клиент открывает bi-stream, пишет JSON `MeshPacket`, закрывает свою
//!     половину на запись (`finish`);
//!   * провайдер читает пакет целиком, обрабатывает (прокси или ретрансляция)
//!     и пишет обратно JSON `SignedResponse`.

use serde::{Deserialize, Serialize};

/// ALPN нашего кастомного протокола (отдельный от blobs/gossip).
///
/// v0: raw JSON + EOF (send.finish) — legacy, HTTP-only, one request per stream.
/// v1: `[LE_u32 handshake_len][handshake JSON]` + опциональный WS-tunnel
///     (WsFrame'ы после handshake, если `method == "WS"`).
pub const ALPN: &[u8] = b"netfory/api/0";
pub const ALPN_V1: &[u8] = b"netfory/api/1";

/// Прочитать length-prefixed handshake JSON (протокол v1). Возвращает сырые
/// байты JSON — вызывающий сам десериализует в `MeshPacket`.
pub async fn read_handshake_v1<R: tokio::io::AsyncReadExt + Unpin>(
    r: &mut R,
) -> anyhow::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len == 0 || len > MAX_FRAME {
        return Err(anyhow::anyhow!("v1 handshake len out of range: {len}"));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Записать length-prefixed handshake (клиентская сторона v1).
pub async fn write_handshake_v1<W: tokio::io::AsyncWriteExt + Unpin>(
    w: &mut W,
    json: &[u8],
) -> anyhow::Result<()> {
    if json.len() > MAX_FRAME {
        return Err(anyhow::anyhow!("v1 handshake too big: {}", json.len()));
    }
    w.write_all(&(json.len() as u32).to_le_bytes()).await?;
    w.write_all(json).await?;
    Ok(())
}

/// Максимальный размер одного пакета/ответа на стриме (анти-DoS бюджет).
pub const MAX_FRAME: usize = 8 * 1024 * 1024; // 8 МБ

/// TTL по умолчанию (количество разрешённых прыжков ретрансляции).
pub const DEFAULT_TTL: u8 = 5;

/// Mesh-пакет запроса. Поддерживает multi-hop через поле `ttl`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshPacket {
    /// Имя целевого API (например "node1-smartholdem"). Сопоставляется с
    /// `endpoints[*].name` в конфиге провайдера-получателя.
    pub target_provider: String,
    /// HTTP-метод для локального прокси-вызова.
    pub method: String,
    /// Путь, добавляемый к `local_url` (например "/blocks/getHeight").
    pub path: String,
    /// Полезная нагрузка (тело HTTP-запроса; для клиента — «зашифрованный»
    /// запрос, для провайдера — непрозрачные байты, передаваемые как есть).
    #[serde(with = "b64")]
    pub body: Vec<u8>,
    /// HTTP-заголовки от клиента (Authorization, X-Custom-* и т.п.).
    /// Провайдер применяет к ним свой safe-whitelist перед форвардом в
    /// апстрим — hop-by-hop и потенциально опасные (`Host`, `Origin`) не
    /// пробрасываются. Пустая map / отсутствие поля — обратная совместимость
    /// со старыми клиентами.
    #[serde(default)]
    pub headers: std::collections::BTreeMap<String, String>,
    /// Сколько прыжков ретрансляции ещё разрешено. Реле уменьшает на 1.
    pub ttl: u8,
    /// Идентификатор запроса для трассировки и сопоставления ответа.
    pub request_id: String,
}

impl MeshPacket {
    /// Удобный конструктор на стороне клиента.
    pub fn new(target: impl Into<String>, method: impl Into<String>, path: impl Into<String>, body: Vec<u8>) -> Self {
        Self {
            target_provider: target.into(),
            method: method.into(),
            path: path.into(),
            body,
            headers: Default::default(),
            ttl: DEFAULT_TTL,
            request_id: rand_id(),
        }
    }
}

/// Подписанный ответ провайдера. Подпись покрывает канонические байты
/// (`canonical_bytes`), что защищает от подмены данных (Data Poisoning)
/// промежуточными реле-нодами.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedResponse {
    /// NodeID провайдера, который РЕАЛЬНО выполнил локальный вызов (hex).
    /// Совпадает с Ed25519-ключом верификации подписи.
    pub provider_node_id: String,
    /// Эхо request_id из пакета.
    pub request_id: String,
    /// HTTP-статус локального ответа.
    pub status: u16,
    /// Тело ответа (как есть).
    #[serde(with = "b64")]
    pub body: Vec<u8>,
    /// Unix-время подписи (секунды).
    pub signed_at: u64,
    /// Был ли ответ получен через ретрансляцию (для прозрачности клиенту).
    pub relayed: bool,
    /// Ed25519-подпись над `canonical_bytes()` в hex.
    pub signature: String,
}

impl SignedResponse {
    /// Канонические байты для подписи/верификации:
    /// request_id | status | signed_at | body. Детерминированы и не зависят
    /// от порядка полей JSON.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut m = Vec::with_capacity(64 + self.body.len());
        m.extend_from_slice(self.request_id.as_bytes());
        m.push(b'|');
        m.extend_from_slice(&self.status.to_be_bytes());
        m.push(b'|');
        m.extend_from_slice(&self.signed_at.to_be_bytes());
        m.push(b'|');
        m.extend_from_slice(&self.body);
        m
    }
}

/// Короткий случайный идентификатор запроса.
pub fn rand_id() -> String {
    use rand::RngCore;
    let mut b = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut b);
    hex::encode(b)
}

/// (De)сериализация `Vec<u8>` как base64 внутри JSON.
mod b64 {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(s.as_bytes()).map_err(serde::de::Error::custom)
    }
}

// ============================================================
//  WebSocket-туннель по iroh bi-stream (protocol v0.5)
//
//  `MeshPacket { method: "WS", path, headers, body_b64: "" }` — сигнал
//  провайдеру: «переведи этот bi-stream в режим WS-туннеля». После
//  успешного handshake с апстримом провайдер отвечает **одним** пакетом
//  handshake-ответа (тем же форматом что HTTP-ответ: pdata + подпись), а
//  дальше и клиент, и провайдер общаются в этом же bi-stream уже
//  бинарными кадрами `WsFrame`. QUIC (iroh) гарантирует порядок и
//  надёжность, нам нужно только framing поверх байтового стрима.
//
//  Формат кадра на проводе (little-endian):
//    [ 1 byte  kind ][ 4 bytes  len ][ len bytes  payload ]
//    kind: 0x01 Text | 0x02 Binary | 0x09 Ping | 0x0A Pong | 0x08 Close
//    len : полезная нагрузка. Для Close первые 2 байта — code (u16 BE),
//          дальше UTF-8 reason.
// ============================================================

/// Максимум одного WS-кадра — 8 MiB. Больше — closer с code 1009.
pub const MAX_WS_FRAME: usize = 8 * 1024 * 1024;

/// Тег типа кадра (совпадает с числовыми opcode WebSocket RFC 6455 для
/// узнаваемости, но байт формируется НАШИМ фреймингом — не WS-битами).
pub mod ws_kind {
    pub const TEXT: u8 = 0x01;
    pub const BINARY: u8 = 0x02;
    pub const PING: u8 = 0x09;
    pub const PONG: u8 = 0x0A;
    pub const CLOSE: u8 = 0x08;
}

/// Кадр между клиентом и провайдером внутри WS-туннеля. `Close.code`
/// следует контракту RFC 6455 (1000=нормально, 1006=abnormal, 1009=too big,
/// 1011=server error).
#[derive(Debug, Clone)]
pub enum WsFrame {
    Text(String),
    Binary(Vec<u8>),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    Close { code: u16, reason: String },
}

impl WsFrame {
    /// Сериализовать кадр в байты (kind + LE len + payload).
    pub fn encode(&self) -> Vec<u8> {
        let (kind, payload): (u8, std::borrow::Cow<'_, [u8]>) = match self {
            WsFrame::Text(s) => (ws_kind::TEXT, std::borrow::Cow::Borrowed(s.as_bytes())),
            WsFrame::Binary(b) => (ws_kind::BINARY, std::borrow::Cow::Borrowed(b)),
            WsFrame::Ping(b) => (ws_kind::PING, std::borrow::Cow::Borrowed(b)),
            WsFrame::Pong(b) => (ws_kind::PONG, std::borrow::Cow::Borrowed(b)),
            WsFrame::Close { code, reason } => {
                let mut buf = Vec::with_capacity(2 + reason.len());
                buf.extend_from_slice(&code.to_be_bytes());
                buf.extend_from_slice(reason.as_bytes());
                (ws_kind::CLOSE, std::borrow::Cow::Owned(buf))
            }
        };
        let mut out = Vec::with_capacity(5 + payload.len());
        out.push(kind);
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&payload);
        out
    }

    /// Прочитать один кадр из iroh RecvStream (или любого AsyncRead).
    /// Возвращает `Ok(None)` только на чистом EOF на границе кадров.
    pub async fn read_from<R: tokio::io::AsyncReadExt + Unpin>(
        r: &mut R,
    ) -> anyhow::Result<Option<WsFrame>> {
        let mut hdr = [0u8; 5];
        // Прочитаем ровно 5 байт заголовка. `read_exact` вернёт UnexpectedEof
        // если поток закрылся ДО первого байта — трактуем как чистый EOF.
        if let Err(e) = r.read_exact(&mut hdr).await {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                return Ok(None);
            }
            return Err(e.into());
        }
        let kind = hdr[0];
        let len = u32::from_le_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]) as usize;
        if len > MAX_WS_FRAME {
            return Err(anyhow::anyhow!(
                "WS-кадр слишком большой: {len} > {MAX_WS_FRAME}"
            ));
        }
        let mut payload = vec![0u8; len];
        r.read_exact(&mut payload).await?;
        Ok(Some(match kind {
            ws_kind::TEXT => WsFrame::Text(String::from_utf8(payload)?),
            ws_kind::BINARY => WsFrame::Binary(payload),
            ws_kind::PING => WsFrame::Ping(payload),
            ws_kind::PONG => WsFrame::Pong(payload),
            ws_kind::CLOSE => {
                let (code, reason) = if payload.len() >= 2 {
                    let code = u16::from_be_bytes([payload[0], payload[1]]);
                    let reason = String::from_utf8_lossy(&payload[2..]).into_owned();
                    (code, reason)
                } else {
                    (1005, String::new())
                };
                WsFrame::Close { code, reason }
            }
            other => return Err(anyhow::anyhow!("неизвестный WS kind byte: {other:#x}")),
        }))
    }
}
