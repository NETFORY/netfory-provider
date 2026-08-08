//! Жёсткий per-peer rate limiter (алгоритм «токен-бакет»).
//!
//! Каждому PeerID (отправителю P2P-стрима) выдаётся бакет с ёмкостью,
//! равной лимиту в секунду. Токены пополняются непрерывно во времени.
//! Если токенов нет — запрос отклоняется (защита локального RPC от DoS).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

struct Bucket {
    tokens: f64,
    last: Instant,
}

/// Лимитер, разделяемый между всеми входящими стримами.
pub struct RateLimiter {
    // peer_id -> бакет
    buckets: Mutex<HashMap<String, Bucket>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self { buckets: Mutex::new(HashMap::new()) }
    }

    /// Попытаться списать один токен у `peer` при лимите `rate` запросов/сек.
    /// Возвращает true, если запрос разрешён.
    pub fn allow(&self, peer: &str, rate: u32) -> bool {
        if rate == 0 {
            return true; // 0 => без лимита
        }
        let cap = rate as f64;
        let now = Instant::now();
        let mut map = self.buckets.lock().unwrap();
        let b = map.entry(peer.to_string()).or_insert(Bucket { tokens: cap, last: now });

        // Пополняем токены пропорционально прошедшему времени.
        let elapsed = now.duration_since(b.last).as_secs_f64();
        b.tokens = (b.tokens + elapsed * cap).min(cap);
        b.last = now;

        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}
