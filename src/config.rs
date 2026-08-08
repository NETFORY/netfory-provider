//! Парсинг и автоинициализация config.yaml (Zero-Configuration).
//!
//! При старте:
//!   1. читаем config.yaml (если его нет — создаём из дефолтов);
//!   2. если `bip39_mnemonic` пуст — генерируем новую мнемонику;
//!   3. выводим из мнемоники 32-байтный корень и записываем его hex в
//!      `iroh_secret_key`;
//!   4. сохраняем конфиг обратно на диск.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

use crate::crypto;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub identity: Identity,
    pub network: Network,
    #[serde(default)]
    pub status: Status,
    #[serde(default)]
    pub gossip: Gossip,
    /// Локальные провайдеры в клирнете. Ключ — произвольный id; `name` —
    /// публичное имя цели в протоколе api://.
    #[serde(default)]
    pub endpoints: HashMap<String, EndpointCfg>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Identity {
    #[serde(default)]
    pub bip39_mnemonic: String,
    #[serde(default)]
    pub iroh_secret_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Network {
    /// UDP-порт для iroh/QUIC. Число — фиксированный порт (откройте его в
    /// фаерволе VPS для прямых подключений). `random`/`auto`/`0` — случайный
    /// порт (как раньше; подходит, когда полагаемся на relay/holepunch).
    /// Игнорируется, если задан непустой `relays` (relay-only режим).
    #[serde(default = "default_listen_port")]
    pub listen_port: PortCfg,
    /// Свои relay-серверы (URL вида https://relay-ru1.sth.cx). Если список
    /// НЕ пуст — провайдер работает ТОЛЬКО через relay: прямые UDP-подключения
    /// отключаются (`clear_ip_transports`), реальный IP сервера НЕ раскрывается
    /// клиентам (они видят только адрес relay).
    #[serde(default)]
    pub relays: Vec<String>,
    /// Mainline DHT (pkarr) discovery — бессерверное обнаружение NodeID через
    /// сеть BitTorrent. По умолчанию ВКЛ: клиенты находят провайдер без n0/n1
    /// (релеи остаются транспортным fallback за NAT). Выключение: false.
    #[serde(default = "default_dht_enabled")]
    pub dht_enabled: bool,
    /// Кастомные bootstrap-узлы Mainline DHT (host:port), добавляются к
    /// дефолтным публичным роутерам. Полезно, когда дефолтные недостижимы
    /// (закрыт исходящий UDP к публичным DHT-роутерам) — укажите свои/доступные.
    /// Объединяются с кэшем живых узлов (dht_boot.dat).
    #[serde(default)]
    pub dht_bootstrap: Vec<String>,
    /// Bind на IPv6 (`[::]:listen_port`) параллельно с IPv4. По умолчанию ВКЛ —
    /// на VPS с IPv6 iroh получает прямой input-путь, минуя relay/holepunch,
    /// что исключает WARN `IPv4 address detected by QAD varies by destination`
    /// в CGNAT-сетях. Отключить (`false`), если VPS не имеет IPv6 или порт
    /// v6 занят другим процессом (иначе будет ошибка bind в логе).
    #[serde(default = "default_ipv6_enabled")]
    pub ipv6_enabled: bool,
}
impl Default for Network {
    fn default() -> Self {
        Self {
            listen_port: default_listen_port(),
            relays: Vec::new(),
            dht_enabled: true,
            dht_bootstrap: Vec::new(),
            ipv6_enabled: default_ipv6_enabled(),
        }
    }
}

/// Порт может быть числом (`11204`) или строкой (`random`/`auto`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PortCfg {
    Num(u16),
    Name(String),
}
impl PortCfg {
    /// Резолвит в номер порта; 0 == случайный.
    pub fn resolve(&self) -> u16 {
        match self {
            PortCfg::Num(n) => *n,
            PortCfg::Name(s) => parse_port_str(s),
        }
    }
}
impl std::fmt::Display for PortCfg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.resolve() {
            0 => write!(f, "random"),
            p => write!(f, "{p}"),
        }
    }
}

/// "11204" -> 11204; ""/"random"/"rand"/"auto"/"0" -> 0 (случайный).
pub fn parse_port_str(s: &str) -> u16 {
    let s = s.trim().to_ascii_lowercase();
    if s.is_empty() || s == "random" || s == "rand" || s == "auto" {
        return 0;
    }
    s.parse::<u16>().unwrap_or(0)
}

fn default_listen_port() -> PortCfg {
    // По умолчанию случайный порт: связь идёт через relay/holepunch и не
    // требует открытого порта в фаерволе. Фиксированный порт (напр. 11204) —
    // опционально, для прямых подключений: укажите число в config.yaml.
    PortCfg::Name("random".into())
}

fn default_dht_enabled() -> bool {
    true
}

fn default_ipv6_enabled() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Status {
    pub http_port: u16,
}
impl Default for Status {
    fn default() -> Self {
        Self { http_port: 8080 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Gossip {
    pub announce_interval_secs: u64,
}
impl Default for Gossip {
    fn default() -> Self {
        Self { announce_interval_secs: 300 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointCfg {
    #[serde(default = "default_protocol")]
    pub protocol: String,
    /// Публичное имя цели (TargetProviderName).
    pub name: String,
    /// Базовый URL локального инстанса в клирнете.
    pub local_url: String,
    /// Лимит запросов в секунду на один PeerID (токен-бакет).
    #[serde(default = "default_rate")]
    pub rate_limit_per_peer: u32,
    /// Опционально: базовый WebSocket-URL локального инстанса (например
    /// `ws://localhost:4003` или `wss://…`). Если задан — клиенты могут
    /// открывать WS-туннели через `api://<nodeId>/<name>/<path>` c
    /// `method: "WS"` (полифилл `window.WebSocket` в клиенте). Отсутствие
    /// поля отключает WS для этого эндпоинта — WS-запросы вернут 501.
    #[serde(default)]
    pub local_ws_url: Option<String>,
    /// Лимит WS-СООБЩЕНИЙ в секунду на один PeerID (в дополнение к rate_limit_per_peer,
    /// которое ограничивает частоту HANDSHAKE). Больше — фреймы дропаются с warning.
    #[serde(default = "default_ws_msg_rate")]
    pub ws_rate_limit_per_peer: u32,
}

fn default_protocol() -> String {
    "api".to_string()
}
fn default_rate() -> u32 {
    5
}
fn default_ws_msg_rate() -> u32 {
    30
}

impl Default for Config {
    fn default() -> Self {
        let mut endpoints = HashMap::new();
        endpoints.insert(
            "smartholdem-node".to_string(),
            EndpointCfg {
                protocol: "api".to_string(),
                name: "node1-smartholdem".to_string(),
                local_url: "http://localhost:4003/api".to_string(),
                rate_limit_per_peer: 5,
                local_ws_url: None,
                ws_rate_limit_per_peer: 30,
            },
        );
        Self {
            identity: Identity::default(),
            network: Network::default(),
            status: Status::default(),
            gossip: Gossip::default(),
            endpoints,
        }
    }
}

/// Загрузить конфиг с автоинициализацией ключей. Возвращает (конфиг, корень).
/// Если ключи были сгенерированы/дополнены — конфиг сохраняется на диск.
pub fn load_or_init(path: impl AsRef<Path>) -> Result<(Config, crypto::Root)> {
    let path = path.as_ref();

    let mut cfg: Config = if path.exists() {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("чтение {}", path.display()))?;
        serde_yaml::from_str(&raw).context("разбор YAML конфигурации")?
    } else {
        tracing::warn!("config.yaml не найден — создаю с дефолтами");
        Config::default()
    };

    let mut dirty = !path.exists();

    // (1-2) Нет мнемоники — генерируем.
    if cfg.identity.bip39_mnemonic.trim().is_empty() {
        let mnemonic = crypto::generate_mnemonic()?;
        tracing::warn!("BIP-39 мнемоника не задана — сгенерирована новая (сохранена в config.yaml)");
        cfg.identity.bip39_mnemonic = mnemonic;
        dirty = true;
    }

    // (3) Выводим детерминированный корень из мнемоники.
    let root = crypto::root_from_mnemonic(&cfg.identity.bip39_mnemonic)?;
    let root_hex = hex::encode(root);

    // Кэшируем hex корня в iroh_secret_key (всегда синхронизируем с мнемоникой).
    if cfg.identity.iroh_secret_key.trim().to_lowercase() != root_hex {
        cfg.identity.iroh_secret_key = root_hex;
        dirty = true;
    }

    if cfg.endpoints.is_empty() {
        return Err(anyhow!("в config.yaml нет ни одного endpoint для проксирования"));
    }

    // (4) Сохраняем обратно при изменениях.
    if dirty {
        save(path, &cfg)?;
    }

    Ok((cfg, root))
}

/// Записать конфиг в YAML.
pub fn save(path: impl AsRef<Path>, cfg: &Config) -> Result<()> {
    let yaml = serde_yaml::to_string(cfg).context("сериализация конфигурации")?;
    std::fs::write(path.as_ref(), yaml)
        .with_context(|| format!("запись {}", path.as_ref().display()))?;
    Ok(())
}
