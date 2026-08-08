//! netfory-provider — API Bridge & Router для SmartNet (Web 4.0).
//!
//! Консольное приложение, которое принимает зашифрованные P2P-запросы по
//! кастомному протоколу `api://` (поверх QUIC/Iroh) и проксирует их на
//! локальные инстансы в клирнете (например, нода блокчейна на :4003).
//!
//! Цель: вместо `https://node0.smartholdem.io` клиентский кошелёк ходит на
//! `api://<NodeID>` (или `api://<имя-провайдера>`) через P2P-сеть, а данные
//! end-to-end подписываются ключом провайдера (защита от Data Poisoning).

// Часть хелперов протокола (MeshPacket::new, rand_id, verify_hex, DEFAULT_TTL)
// предназначена для клиентской стороны и тестов — не считаем их «мёртвым кодом».
#![allow(dead_code)]

mod config;
mod crypto;
mod p2p_server;
mod peers;
mod protocol;
mod proxy_engine;
mod ratelimit;
mod stats;

use anyhow::Result;

const CONFIG_PATH: &str = "config.yaml";

#[tokio::main]
async fn main() -> Result<()> {
    // Логирование: уровень управляется RUST_LOG (по умолчанию info).
    // По умолчанию глушим внутренний шум QUIC-стека iroh: `noq_proto`
    // (MultipathNotNegotiated / PTO expired — гонка путей, безвредно) и
    // WARN'ы `iroh::protocol` про "timed out / aborted during handshake"
    // (проигравшие кандидаты-пути при подключении). RUST_LOG это переопределяет.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                "info,netfory_provider=debug,noq_proto=off,iroh::protocol=error,n0_mainline::core=off,n0_mainline::actor=warn".into()
            }),
        )
        .init();

    tracing::info!("netfory-provider v{}", env!("CARGO_PKG_VERSION"));

    // Zero-Configuration: читаем/создаём конфиг и выводим/генерируем ключи.
    let (cfg, root) = config::load_or_init(CONFIG_PATH)?;
    tracing::info!(
        "Конфиг загружен: {} эндпоинт(ов), QUIC-порт {}",
        cfg.endpoints.len(),
        cfg.network.listen_port
    );

    // Запускаем P2P-слой (работает до Ctrl-C).
    p2p_server::run(cfg, root).await
}
