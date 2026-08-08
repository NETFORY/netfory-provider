//! Локальная встроенная БД известных пиров (peers.dat) на Sled.
//!
//! Сюда складываются подписанные манифесты, собранные из gossip-анонсов.
//! Клиенты SmartNet используют такой же набор данных, формируя актуальный
//! список провайдеров (кого можно звать через api://<NodeID>).

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Подписанный манифест провайдера, анонсируемый в gossip.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    /// NodeID/PeerID провайдера (hex Ed25519 pubkey).
    pub node_id: String,
    /// Список публичных имён проксируемых эндпоинтов (TargetProviderName).
    pub endpoints: Vec<String>,
    /// Аптайм провайдера, сек.
    pub uptime_secs: u64,
    /// Средняя задержка до локальных RPC, мс.
    pub latency_ms: u64,
    /// Всего обработано запросов.
    pub requests_total: u64,
    /// Unix-время подписи.
    pub signed_at: u64,
    /// Версия провайдера.
    pub version: String,
    /// Ed25519-подпись над `canonical_bytes()`.
    pub signature: String,
    /// Локальная метка времени последнего получения (заполняется получателем).
    #[serde(default)]
    pub seen_at: u64,
}

impl Manifest {
    /// Канонические байты для подписи (без поля signature/seen_at).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(self.node_id.as_bytes());
        m.push(b'|');
        m.extend_from_slice(self.endpoints.join(",").as_bytes());
        m.push(b'|');
        m.extend_from_slice(&self.uptime_secs.to_be_bytes());
        m.push(b'|');
        m.extend_from_slice(&self.latency_ms.to_be_bytes());
        m.push(b'|');
        m.extend_from_slice(&self.requests_total.to_be_bytes());
        m.push(b'|');
        m.extend_from_slice(&self.signed_at.to_be_bytes());
        m
    }
}

/// Обёртка над Sled-деревом с манифестами.
#[derive(Clone)]
pub struct PeerStore {
    db: sled::Db,
}

impl PeerStore {
    pub fn open(path: &str) -> Result<Self> {
        let db = sled::open(path).with_context(|| format!("открытие peers.dat ({path})"))?;
        Ok(Self { db })
    }

    /// Сохранить/обновить манифест (ключ — node_id).
    pub fn upsert(&self, m: &Manifest) -> Result<()> {
        let bytes = serde_json::to_vec(m)?;
        self.db.insert(m.node_id.as_bytes(), bytes)?;
        Ok(())
    }

    /// Список всех известных пиров.
    pub fn list(&self) -> Vec<Manifest> {
        self.db
            .iter()
            .filter_map(|kv| kv.ok())
            .filter_map(|(_, v)| serde_json::from_slice::<Manifest>(&v).ok())
            .collect()
    }

    /// Найти пиров, которые проксируют целевое имя (для адресной ретрансляции).
    pub fn providers_of(&self, target: &str, exclude: &str) -> Vec<String> {
        self.list()
            .into_iter()
            .filter(|m| m.node_id != exclude && m.endpoints.iter().any(|e| e == target))
            .map(|m| m.node_id)
            .collect()
    }

    /// Любые другие известные пиры (фолбэк для флуд-ретрансляции с TTL).
    pub fn others(&self, exclude: &str) -> Vec<String> {
        self.list()
            .into_iter()
            .filter(|m| m.node_id != exclude)
            .map(|m| m.node_id)
            .collect()
    }
}
