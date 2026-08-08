//! Прокси-движок: выполняет локальный HTTP-вызов в клирнет (reqwest) с
//! жёстким таймаутом 5 секунд и ВСТРАИВАЕТ в JSON-ответ узла объект `pdata`
//! с подписью провайдера.
//!
//! Формат ответа сохраняет совместимость со стандартным API нод SmartHoldem:
//!   { "data": { ... },                       // как у https://nodeX.smartholdem.io
//!     "pdata": {                              // наши P2P-метаданные + подпись
//!        "v": 1,
//!        "node_id": "<EndpointId провайдера-исполнителя>",
//!        "name": "node1-smartholdem",
//!        "status": 200,
//!        "signed_at": 1750000000,
//!        "relayed": false,
//!        "alg": "ed25519",
//!        "sig": "<hex>",                       // подпись над canonical (см. ниже)
//!        "body_b64": "<base64 исходного тела узла>"
//!     } }
//!
//! Канонические байты подписи: `node_id|status|signed_at|` + исходные байты
//! ответа узла. body_b64 позволяет клиенту проверить подпись и восстановить
//! точные исходные байты, не полагаясь на ре-сериализацию JSON.

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::SigningKey;
use std::collections::HashMap;
use std::time::Duration;

use crate::config::{Config, EndpointCfg};
use crate::crypto;
use crate::protocol::MeshPacket;

pub struct ProxyEngine {
    client: reqwest::Client,
    by_name: HashMap<String, EndpointCfg>,
    /// Имя «эндпоинта по умолчанию» — используется, когда клиент обращается
    /// по `api://<nodeId>` (имя цели неизвестно, target_provider пуст).
    default_name: Option<String>,
    node_id: String,
    signing: SigningKey,
}

impl ProxyEngine {
    pub fn new(cfg: &Config, root: &crypto::Root, node_id: String) -> Result<Self> {
        // Единый клиент с таймаутом 5с на любой запрос к клирнету.
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()?;

        let mut by_name = HashMap::new();
        for ep in cfg.endpoints.values() {
            by_name.insert(ep.name.clone(), ep.clone());
        }
        // Дефолтный эндпоинт — детерминированно первый по имени.
        let default_name = by_name.keys().min().cloned();

        Ok(Self {
            client,
            by_name,
            default_name,
            node_id,
            signing: crypto::signing_key(root),
        })
    }

    /// Разрешить имя цели в конфиг эндпоинта (пустое имя => дефолтный).
    fn resolve(&self, target: &str) -> Option<&EndpointCfg> {
        if target.is_empty() {
            self.default_name.as_ref().and_then(|n| self.by_name.get(n))
        } else {
            self.by_name.get(target)
        }
    }

    /// Обслуживаем ли мы эту цель локально (пустое имя => дефолтный эндпоинт).
    pub fn serves(&self, target: &str) -> bool {
        self.resolve(target).is_some()
    }

    /// Лимит запросов/сек для цели (для rate limiter).
    pub fn rate_for(&self, target: &str) -> u32 {
        self.resolve(target).map(|e| e.rate_limit_per_peer).unwrap_or(0)
    }

    /// Имена всех проксируемых целей.
    pub fn names(&self) -> Vec<String> {
        self.by_name.keys().cloned().collect()
    }

    /// Список активных протоколов для эндпоинта: всегда `rpc` (HTTP),
    /// плюс `ws`, если задан `local_ws_url`. Используется в дашборде для badge.
    pub fn protocols_for(&self, name: &str) -> Vec<String> {
        let Some(ep) = self.resolve(name) else { return Vec::new(); };
        let mut out = vec!["rpc".to_string()];
        if ep.local_ws_url.is_some() {
            out.push("ws".to_string());
        }
        out
    }

    /// Полный URL WS-апстрима для эндпоинта с данным именем + доп. путь.
    /// Возвращает `None`, если для этого имени в конфиге не задан `local_ws_url`.
    pub fn ws_url_for(&self, name: &str, sub_path: &str) -> Option<String> {
        let ep = self.resolve(name)?;
        let base = ep.local_ws_url.as_ref()?.trim_end_matches('/');
        Some(format!("{base}{sub_path}"))
    }

    /// Лимит частоты WS-фреймов (сообщений/сек) для эндпоинта.
    pub fn ws_msg_rate_for(&self, name: &str) -> u32 {
        self.resolve(name)
            .map(|e| e.ws_rate_limit_per_peer)
            .unwrap_or(30)
    }

    /// Health-check локального RPC: GET local_url, вернуть (online, latency_ms).
    pub async fn health(&self, name: &str) -> (bool, u64) {
        let Some(ep) = self.by_name.get(name) else {
            return (false, 0);
        };
        let t0 = std::time::Instant::now();
        let ok = self.client.get(&ep.local_url).send().await.is_ok();
        (ok, t0.elapsed().as_millis() as u64)
    }

    /// Выполнить локальный прокси-вызов и вернуть JSON-тело с `pdata`.
    pub async fn execute(&self, pkt: &MeshPacket, relayed: bool) -> Result<Vec<u8>> {
        let ep = self
            .resolve(&pkt.target_provider)
            .ok_or_else(|| anyhow!("цель {} не обслуживается локально", pkt.target_provider))?
            .clone();

        // Собираем URL: local_url + path.
        let url = format!("{}{}", ep.local_url.trim_end_matches('/'), pkt.path);
        let method = reqwest::Method::from_bytes(pkt.method.to_uppercase().as_bytes())
            .unwrap_or(reqwest::Method::GET);

        let mut req = self.client.request(method, &url);
        // Форвардим заголовки dApp'а, но не всё подряд: hop-by-hop и
        // потенциально опасные заголовки апстрим ожидает сгенерированные
        // здесь на новом HTTP-хопе, а не унаследованные с клиента.
        // Отсеиваем: Host / Connection / Content-Length / Transfer-Encoding /
        // Upgrade / Keep-Alive / Origin / Referer / User-Agent (последние два
        // не имеют смысла для не-браузерного апстрима, а Origin для
        // сервера-нашей-подписи вообще не нужен).
        fn is_forwardable(name: &str) -> bool {
            let l = name.to_ascii_lowercase();
            !matches!(
                l.as_str(),
                "host"
                    | "connection"
                    | "content-length"
                    | "transfer-encoding"
                    | "upgrade"
                    | "proxy-connection"
                    | "keep-alive"
                    | "origin"
                    | "referer"
                    | "user-agent"
            )
        }
        let mut has_ct = false;
        let mut has_accept = false;
        for (k, v) in &pkt.headers {
            if !is_forwardable(k) {
                continue;
            }
            let lk = k.to_ascii_lowercase();
            if lk == "content-type" {
                has_ct = true;
            }
            if lk == "accept" {
                has_accept = true;
            }
            // reqwest требует валидные ASCII-имена/значения; пропускаем
            // некорректные значения молча вместо падения.
            if let (Ok(hn), Ok(hv)) = (
                reqwest::header::HeaderName::from_bytes(k.as_bytes()),
                reqwest::header::HeaderValue::from_str(v),
            ) {
                req = req.header(hn, hv);
            }
        }
        if !pkt.body.is_empty() {
            // Весь RPC SmartNet/SmartHoldem — JSON. Узлы (например POST
            // /api/transactions для broadcast) отклоняют тело без явного
            // Content-Type, поэтому выставляем его для любого непустого тела —
            // если dApp сам не прислал.
            if !has_ct {
                req = req.header("Content-Type", "application/json");
            }
            if !has_accept {
                req = req.header("Accept", "application/json");
            }
            req = req.body(pkt.body.clone());
        }

        let (status, raw) = match req.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let bytes = resp.bytes().await.unwrap_or_default().to_vec();
                (status, bytes)
            }
            Err(e) => {
                let body = serde_json::to_vec(&serde_json::json!({
                    "error": "upstream_unreachable",
                    "detail": e.to_string(),
                }))
                .unwrap_or_default();
                (502, body)
            }
        };

        Ok(self.finalize(&ep.name, status, raw, relayed))
    }

    /// Ответ при превышении лимита (тоже с подписанным `pdata`).
    pub fn reject_body(&self, pkt: &MeshPacket) -> Vec<u8> {
        let raw = serde_json::to_vec(&serde_json::json!({
            "error": "rate_limited",
            "detail": "превышен лимит запросов на этот PeerID",
        }))
        .unwrap_or_default();
        self.finalize(&pkt.target_provider, 429, raw, false)
    }

    /// Встроить `pdata` (с подписью) в JSON-ответ узла.
    fn finalize(&self, name: &str, status: u16, raw: Vec<u8>, relayed: bool) -> Vec<u8> {
        let signed_at = now_secs();

        // Канонические байты: node_id|status|signed_at| + исходное тело узла.
        let mut canon = format!("{}|{}|{}|", self.node_id, status, signed_at).into_bytes();
        canon.extend_from_slice(&raw);
        let sig = crypto::sign_hex(&self.signing, &canon);

        let pdata = serde_json::json!({
            "v": 1,
            "node_id": self.node_id,
            "name": name,
            "status": status,
            "signed_at": signed_at,
            "relayed": relayed,
            "alg": "ed25519",
            "sig": sig,
            "body_b64": B64.encode(&raw),
        });

        // Если тело узла — JSON-объект, добавляем pdata рядом с data.
        // Иначе оборачиваем (raw полностью доступен в pdata.body_b64).
        match serde_json::from_slice::<serde_json::Value>(&raw) {
            Ok(serde_json::Value::Object(mut m)) => {
                m.insert("pdata".to_string(), pdata);
                serde_json::to_vec(&serde_json::Value::Object(m)).unwrap_or(raw)
            }
            _ => serde_json::to_vec(&serde_json::json!({ "pdata": pdata })).unwrap_or(raw),
        }
    }
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
