//! P2P-сервер: Iroh Endpoint + кастомный протокол `api://`, multi-hop
//! ретрансляция, анонс/сбор манифестов через iroh-gossip и периодический
//! health-check локальных RPC.
//!
//! Примечание о версиях API (iroh 1.0 / iroh-gossip 0.101):
//!   * `Endpoint::builder(presets::N0).secret_key(..).bind().await`
//!   * `Router::builder(ep).accept(ALPN, handler).spawn()`
//!   * `ProtocolHandler::accept(&self, Connection) -> Result<(), AcceptError>`
//!   * `Connection::accept_bi()/open_bi()`, `RecvStream::read_to_end(max)`
//!   * gossip: `Gossip::builder().spawn(ep)`, `gossip.subscribe(topic, boots)`,
//!     `sub.split() -> (GossipSender, GossipReceiver)`, `tx.broadcast(bytes)`.
//! На иной патч-версии iroh имена методов (`remote_id`, `as_bytes`) могут
//! слегка отличаться — это единственные места, требующие правки.

use anyhow::{anyhow, Result};
use std::sync::Arc;
use std::time::Duration;

use iroh::endpoint::{presets, Connection};
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::{Endpoint, EndpointId};
use iroh_gossip::api::{Event, GossipReceiver};
use iroh_gossip::{Gossip, TopicId};
use iroh_mainline_address_lookup::DhtAddressLookup;
use n0_mainline::Dht;

use crate::config::Config;
use crate::crypto::{self, Root};
use crate::peers::{Manifest, PeerStore};
use crate::protocol::{self, MeshPacket, MAX_FRAME};
use crate::proxy_engine::{now_secs, ProxyEngine};
use crate::ratelimit::RateLimiter;
use crate::stats::{RpcStatus, Stats};

/// Лимит запросов/сек для пакетов, идущих в ретрансляцию (цель не наша).
const RELAY_RATE: u32 = 10;

/// Файл с кэшем живых DHT-узлов (для extra_bootstrap при следующем старте).
const DHT_BOOT_FILE: &str = "dht_boot.dat";
/// Сколько узлов максимум храним в кэше bootstrap.
const DHT_BOOT_MAX: usize = 64;

/// Прочитать кэш bootstrap-узлов DHT (host:port в строках). Пусто — нет файла.
fn load_dht_bootstrap() -> Vec<String> {
    std::fs::read_to_string(DHT_BOOT_FILE)
        .ok()
        .map(|s| {
            s.lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .take(DHT_BOOT_MAX)
                .collect()
        })
        .unwrap_or_default()
}

/// Сохранить живые DHT-узлы из таблицы маршрутизации в кэш.
fn save_dht_bootstrap(nodes: &[String]) {
    let body = nodes.iter().take(DHT_BOOT_MAX).cloned().collect::<Vec<_>>().join("\n");
    let _ = std::fs::write(DHT_BOOT_FILE, body);
}

/// АСИНХРОННЫЙ резолв bootstrap-узлов Mainline DHT в IP:port.
/// Зачем: n0_mainline в build() резолвит хосты СИНХРОННО (std to_socket_addrs) и
/// при недоступном DNS блокирует поток на таймаут. Резолвим заранее без
/// блокировки (concurrent, таймаут 1.5с на хост) и отдаём IP-литералы.
async fn resolve_dht_bootstrap(cfg: &Config) -> Vec<String> {
    // SmartNet-собственный публичный DHT bootstrap-узел (headless seeder, открытый
    // UDP) — вход в DHT без зависимости от n0/n1 и публичных BT-роутеров.
    const SMARTNET_DHT: &str = "116.202.32.250:6881";
    const DEFAULTS: [&str; 5] = [
        SMARTNET_DHT,
        "router.bittorrent.com:6881",
        "dht.transmissionbt.com:6881",
        "dht.libtorrent.org:25401",
        "relay.pkarr.org:6881",
    ];
    let mut hosts: Vec<String> = DEFAULTS.iter().map(|s| s.to_string()).collect();
    hosts.extend(cfg.network.dht_bootstrap.clone());
    hosts.extend(load_dht_bootstrap());
    hosts.sort();
    hosts.dedup();
    let mut handles = Vec::new();
    for h in hosts {
        handles.push(tokio::spawn(async move {
            if h.parse::<std::net::SocketAddr>().is_ok() {
                return vec![h];
            }
            match tokio::time::timeout(
                std::time::Duration::from_millis(1500),
                tokio::net::lookup_host(&h),
            )
            .await
            {
                Ok(Ok(addrs)) => addrs.filter(|a| a.is_ipv4()).map(|a| a.to_string()).collect(),
                _ => Vec::new(),
            }
        }));
    }
    let mut out = Vec::new();
    for handle in handles {
        if let Ok(v) = handle.await {
            out.extend(v);
        }
    }
    out.sort();
    out.dedup();
    out
}


/// Главная точка входа P2P-слоя. Поднимает endpoint и работает до Ctrl-C.
pub async fn run(cfg: Config, root: Root) -> Result<()> {
    // --- 1. Endpoint с детерминированным ключом из корня (тот же NodeID) ---
    // Режимы транспорта:
    //  • relays НЕ пуст → RELAY-ONLY: прямые UDP-подключения выключены
    //    (clear_ip_transports), весь трафик идёт через указанные relay,
    //    реальный IP сервера НЕ раскрывается клиентам.
    //  • иначе → прямой UDP (presets::N0): порт из config.network.listen_port
    //    (число = фикс., random/0 = случайный). Env NETFORY_QUIC_PORT > конфиг.
    let secret = crypto::iroh_secret(&root);
    // Клонируем secret для потенциального fallback-пересоздания builder'а
    // (если bind IPv6 фейлится — восстанавливаем только-IPv4 endpoint).
    let secret_fallback = secret.clone();

    let relays: Vec<iroh::RelayUrl> = cfg
        .network
        .relays
        .iter()
        .filter_map(|s| {
            let s = s.trim();
            if s.is_empty() {
                return None;
            }
            match s.parse::<iroh::RelayUrl>() {
                Ok(u) => Some(u),
                Err(e) => {
                    tracing::warn!("пропускаю невалидный relay URL '{s}': {e}");
                    None
                }
            }
        })
        .collect();
    let relay_only = !relays.is_empty();

    let quic_port: u16 = if relay_only {
        0 // в relay-only прямой UDP-порт не биндится
    } else {
        std::env::var("NETFORY_QUIC_PORT")
            .ok()
            .map(|s| crate::config::parse_port_str(&s))
            .unwrap_or_else(|| cfg.network.listen_port.resolve())
    };

    let mut builder = Endpoint::builder(presets::N0).secret_key(secret);
    if relay_only {
        builder = builder
            .clear_ip_transports()
            .relay_mode(iroh::RelayMode::custom(relays.clone()));
    } else if quic_port != 0 {
        // Сбрасываем дефолтные (случайный порт) сокеты и биндим фиксированные:
        //   • IPv4  → 0.0.0.0:PORT (обязательно, backward-compat)
        //   • IPv6  → [::]:PORT  (опционально; для VPS с v6 адресом исключает
        //     `IPv4 address detected by QAD varies by destination` WARN,
        //     потому что клиенты бьют напрямую v6 без CGNAT-неопределённости).
        // Один и тот же порт для v4/v6 — так проще открыть UDP в фаерволе:
        // одно правило и для v4, и для v6 семейств.
        builder = builder
            .clear_ip_transports()
            .bind_addr(format!("0.0.0.0:{quic_port}").as_str())
            .map_err(|e| anyhow!("bind v4 udp {quic_port}: {e:?}"))?;
        if cfg.network.ipv6_enabled {
            match builder.bind_addr(format!("[::]:{quic_port}").as_str()) {
                Ok(b) => {
                    tracing::info!("iroh/QUIC также слушает IPv6 [::]:{quic_port}");
                    builder = b;
                }
                Err(e) => {
                    // Не критично — v4 продолжит работать. Обычная причина:
                    // порт уже занят или ОС без IPv6. Пересоздаём builder
                    // без IPv6 биндинга (secret был клонирован заранее).
                    tracing::warn!(
                        "bind IPv6 [::]:{quic_port} не удался ({e:?}) — работаем только на IPv4"
                    );
                    builder = Endpoint::builder(presets::N0)
                        .secret_key(secret_fallback)
                        .clear_ip_transports()
                        .bind_addr(format!("0.0.0.0:{quic_port}").as_str())
                        .map_err(|e| anyhow!("bind v4 udp {quic_port}: {e:?}"))?;
                }
            }
        }
    } else if cfg.network.ipv6_enabled {
        // listen_port=random: дефолтные unspecified сокеты v4+v6 уже настроены
        // конструктором. Ничего доп. не делаем — iroh биндит обе семьи на
        // случайные порты, минимальный сюрприз.
    }
    // Mainline DHT (pkarr) discovery: добавляем как ДОПОЛНИТЕЛЬНЫЙ address_lookup
    // поверх n0-DNS. Это бессерверное обнаружение NodeID через сеть BitTorrent —
    // клиент находит провайдер даже без доступа к n0/n1. По умолчанию ВКЛ.
    // Фильтр адресов по умолчанию relay_only → реальный IP в DHT не публикуется.
    // ВАЖНО: bootstrap-хосты резолвим АСИНХРОННО заранее (n0_mainline в build()
    // делает СИНХРОННЫЙ to_socket_addrs и блокирует поток на таймаут DNS).
    let dht_boot_ips: Vec<String> = if cfg.network.dht_enabled {
        resolve_dht_bootstrap(&cfg).await
    } else {
        Vec::new()
    };
    if cfg.network.dht_enabled {
        let mut db = Dht::builder();
        db.bootstrap(&dht_boot_ips);
        if !dht_boot_ips.is_empty() {
            tracing::info!("DHT: bootstrap-узлов (резолв IP): {}", dht_boot_ips.len());
        } else {
            tracing::warn!("DHT: ни один bootstrap-узел не зарезолвился (DNS/UDP закрыт?) — DHT может не подняться");
        }
        builder = builder.address_lookup(DhtAddressLookup::builder().dht_builder(db));
    }
    let endpoint = builder
        .bind()
        .await
        .map_err(|e| anyhow!("bind iroh endpoint: {e}"))?;
    if relay_only {
        tracing::info!(
            "RELAY-ONLY режим: {} relay, прямые UDP-подключения отключены, реальный IP скрыт",
            relays.len()
        );
        for u in &relays {
            tracing::info!("  relay: {u}");
        }
    } else if quic_port != 0 {
        tracing::info!("iroh/QUIC слушает UDP-порт {quic_port} — ОТКРОЙТЕ его (UDP) в фаерволе VPS для прямых подключений");
    } else {
        tracing::info!("iroh/QUIC слушает СЛУЧАЙНЫЙ UDP-порт (listen_port=random) — связь через relay/holepunch");
    }
    if quic_port != 0 {
        tracing::info!("iroh/QUIC слушает UDP-порт {quic_port} — ОТКРОЙТЕ его (UDP) в фаерволе VPS для прямых подключений");
    }

    let eid = endpoint.id();
    // Строковый адрес для протокола api://<NodeID> (как его парсит клиент).
    let node_id = eid.to_string();
    tracing::info!("=================================================");
    tracing::info!("  NodeID (api://адрес провайдера):");
    tracing::info!("  {node_id}");
    tracing::info!("=================================================");

    // --- 2. Сервисы: статистика, peers.dat, прокси, лимитер ---
    let stats = Arc::new(Stats::new(node_id.clone(), quic_port, cfg.network.dht_enabled));
    let peers = Arc::new(PeerStore::open("peers.dat")?);
    let proxy = Arc::new(ProxyEngine::new(&cfg, &root, node_id.clone())?);
    let limiter = Arc::new(RateLimiter::new());

    // --- Мониторинг Mainline DHT: счётчик узлов в таблице маршрутизации ---
    // Отдельный лёгкий DHT-клиент только для телеметрии (сам discovery работает
    // внутри address_lookup endpoint'а). Узлы видны на дашборде как «DHT-узлы».
    if cfg.network.dht_enabled {
        let stats_dht = stats.clone();
        let boot = dht_boot_ips.clone();
        tokio::spawn(async move {
            let mut mdb = Dht::builder();
            mdb.bootstrap(&boot);
            match mdb.build() {
                Ok(dht) => {
                    let ready = dht.bootstrapped().await.unwrap_or(false);
                    if !ready {
                        tracing::warn!(
                            "DHT не забутстрапился: публичные Mainline-роутеры недоступны. \
                             Откройте ИСХОДЯЩИЙ UDP (к :6881 и др.) ИЛИ задайте network.dht_bootstrap \
                             с доступными узлами. Иначе обнаружение через DHT работать не будет \
                             (останутся relay + n0/n1)."
                        );
                    }
                    let mut tick: u32 = 0;
                    loop {
                        if let Ok(info) = dht.info().await {
                            stats_dht.set_dht_nodes(info.routing_table_size() as u64);
                        }
                        // Раз в ~2 мин сохраняем живые узлы для extra_bootstrap.
                        tick = tick.wrapping_add(1);
                        if tick % 10 == 0 {
                            if let Ok(nodes) = dht.to_bootstrap().await {
                                if !nodes.is_empty() {
                                    save_dht_bootstrap(&nodes);
                                }
                            }
                        }
                        tokio::time::sleep(Duration::from_secs(12)).await;
                    }
                }
                Err(e) => tracing::warn!("DHT-монитор не запущен: {e}"),
            }
        });
        tracing::info!("Mainline DHT discovery ВКЛЮЧЁН (pkarr) — бессерверное обнаружение, без n0/n1");
        if relay_only {
            tracing::warn!(
                "Внимание: relay-only СКРЫВАЕТ IP от клиентов, но участие в Mainline DHT \
                 раскрывает IP сервера другим DHT-узлам (UDP). Для максимальной приватности \
                 отключите DHT (network.dht_enabled=false) или запускайте DHT за VPN."
            );
        }
    } else {
        tracing::info!("Mainline DHT discovery выключен (network.dht_enabled=false)");
    }

    // Локальный HTTP-дашборд мониторинга.
    {
        let (s, p) = (stats.clone(), peers.clone());
        let port = cfg.status.http_port;
        tokio::spawn(async move {
            if let Err(e) = crate::stats::serve(port, s, p).await {
                tracing::error!("HTTP-дашборд упал: {e:#}");
            }
        });
    }

    // --- 3. Gossip для discovery (анонс + сбор манифестов) ---
    let gossip = Gossip::builder().spawn(endpoint.clone());

    // --- 4. Обработчик кастомного протокола api:// ---
    let handler = Arc::new(Handler {
        node_id: node_id.clone(),
        endpoint: endpoint.clone(),
        proxy: proxy.clone(),
        limiter: limiter.clone(),
        stats: stats.clone(),
        peers: peers.clone(),
    });

    // Router принимает И наш ALPN, И gossip ALPN на одном endpoint.
    // Плюс новый ALPN v1 (length-prefixed handshake + WS-tunnels).
    let router = Router::builder(endpoint.clone())
        .accept(protocol::ALPN, ApiProtocol { inner: handler.clone(), v1: false })
        .accept(protocol::ALPN_V1, ApiProtocol { inner: handler, v1: true })
        .accept(iroh_gossip::ALPN, gossip.clone())
        .spawn();

    // --- 5. Discovery-задачи (анонс + слушатель) ---
    spawn_discovery(gossip, endpoint.clone(), root, cfg.clone(), stats.clone(), peers.clone());

    // --- 6. Периодический health-check локальных RPC ---
    spawn_health(proxy.clone(), stats.clone(), peers.clone());

    tracing::info!("netfory-provider запущен. Ожидаю api://-запросы. (Ctrl-C для выхода)");
    tokio::signal::ctrl_c().await.ok();
    tracing::info!("Завершение…");
    router.shutdown().await.ok();
    endpoint.close().await;
    Ok(())
}

// =====================================================================
//  Кастомный протокол api:// (ProtocolHandler)
// =====================================================================

/// Лёгкая обёртка-хендлер, регистрируемая в Router.
#[derive(Clone)]
struct ApiProtocol {
    inner: Arc<Handler>,
    /// true — соединение пришло на ALPN `/1` (length-prefixed handshake + WS).
    /// false — legacy `/0` (raw JSON + EOF).
    v1: bool,
}

// iroh 1.0 требует, чтобы ProtocolHandler реализовывал Debug.
impl std::fmt::Debug for ApiProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApiProtocol")
    }
}

impl ProtocolHandler for ApiProtocol {
    /// Вызывается на КАЖДОЕ входящее соединение нашего ALPN. iroh-Router сам
    /// запускает ОТДЕЛЬНУЮ tokio-задачу на каждое соединение, поэтому здесь
    /// можно спокойно работать долго — другие клиенты обслуживаются параллельно
    /// и НЕ блокируются (см. docs.rs/iroh ProtocolHandler).
    ///
    /// v0.5: **multi-request per connection**. Раньше мы принимали ровно один
    /// `accept_bi()` и ждали `connection.closed()`. Теперь loop'имся и
    /// обрабатываем КАЖДЫЙ входящий bi-stream от того же клиента в отдельной
    /// tokio-задаче — это позволяет клиенту переиспользовать один установленный
    /// QUIC connection для многих api://-запросов подряд без дорогого re-connect
    /// (hole-punch ~300-800ms). Concurrent streams в рамках одной connection
    /// капнуты семафором (см. `MAX_CONCURRENT_STREAMS_PER_CONN`), чтобы один
    /// клиент не мог положить провайдер параллельными тяжёлыми GET'ами.
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let inner = self.inner.clone();
        let v1 = self.v1;
        let peer = connection.remote_id().to_string();
        let _conn_guard = inner.stats.track_connection();
        let sem = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_STREAMS_PER_CONN));

        loop {
            match connection.accept_bi().await {
                Ok((send, recv)) => {
                    let inner = inner.clone();
                    let sem = sem.clone();
                    let peer = peer.clone();
                    tokio::spawn(async move {
                        let _permit = match sem.acquire_owned().await {
                            Ok(p) => p,
                            Err(_) => return,
                        };
                        if let Err(e) = inner.handle_stream(send, recv, &peer, v1).await {
                            tracing::warn!("api:// stream ({peer}): {e:#}");
                        }
                    });
                }
                Err(iroh::endpoint::ConnectionError::TimedOut)
                | Err(iroh::endpoint::ConnectionError::LocallyClosed)
                | Err(iroh::endpoint::ConnectionError::ApplicationClosed(_)) => {
                    break;
                }
                Err(e) => {
                    tracing::debug!("accept_bi завершил цикл ({peer}): {e}");
                    break;
                }
            }
        }
        Ok(())
    }
}

/// Максимум одновременно активных bi-streams в рамках ОДНОГО QUIC-соединения.
/// Клиент, открывающий больше — упрётся в семафор, следующие `open_bi()`
/// подождут освобождения слота. Защищает от DoS через flood параллельных
/// тяжёлых запросов.
const MAX_CONCURRENT_STREAMS_PER_CONN: usize = 16;

/// Состояние, нужное для обработки и ретрансляции пакетов.
struct Handler {
    node_id: String,
    endpoint: Endpoint,
    proxy: Arc<ProxyEngine>,
    limiter: Arc<RateLimiter>,
    stats: Arc<Stats>,
    peers: Arc<PeerStore>,
}

impl Handler {
    /// Обработать один bi-stream. Каждый stream — независимый запрос
    /// (protocol версии v0.5: multi-request per connection).
    async fn handle_stream(
        &self,
        mut send: iroh::endpoint::SendStream,
        mut recv: iroh::endpoint::RecvStream,
        peer: &str,
        v1: bool,
    ) -> Result<()> {
        // Handshake: v0 — весь stream до EOF; v1 — [LE_u32 len][JSON].
        let raw = if v1 {
            protocol::read_handshake_v1(&mut recv).await?
        } else {
            recv.read_to_end(MAX_FRAME).await?
        };
        let pkt: MeshPacket = serde_json::from_slice(&raw)?;

        self.stats.inc_total();

        // --- Rate limiting (анти-DoS на локальный RPC) ---
        let rate = if self.proxy.serves(&pkt.target_provider) {
            self.proxy.rate_for(&pkt.target_provider)
        } else {
            RELAY_RATE
        };
        if !self.limiter.allow(peer, rate) {
            self.stats.inc_rejected();
            let resp = self.proxy.reject_body(&pkt);
            write_response(&mut send, &resp).await?;
            return Ok(());
        }

        // --- WS-туннель (только на ALPN /1 — legacy /0 не поддерживает
        //     long-lived streams). Handshake прошёл — переходим в pump.
        if v1 && pkt.method.eq_ignore_ascii_case("WS") && self.proxy.serves(&pkt.target_provider) {
            self.stats.inc_proxied();
            return self
                .handle_ws_stream(&pkt, peer, send, recv)
                .await
                .map_err(|e| anyhow!("ws tunnel: {e:#}"));
        }

        // --- Обычный HTTP: наша цель vs ретрансляция ---
        let resp: Vec<u8> = if self.proxy.serves(&pkt.target_provider) {
            self.stats.inc_proxied();
            self.proxy.execute(&pkt, false).await?
        } else {
            self.stats.inc_relayed();
            self.relay(&pkt).await?
        };

        write_response(&mut send, &resp).await?;
        Ok(())
    }

    /// Обработать WebSocket-туннель. `send`/`recv` — уже открытый iroh
    /// bi-stream на ALPN `/1`; `pkt` — inbound handshake-пакет.
    async fn handle_ws_stream(
        &self,
        pkt: &MeshPacket,
        peer: &str,
        mut send: iroh::endpoint::SendStream,
        mut recv: iroh::endpoint::RecvStream,
    ) -> Result<()> {
        use crate::protocol::WsFrame;
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        use tokio_tungstenite::tungstenite::Message as TMsg;

        tracing::info!(
            "WS[{}] handshake от peer={} path={}",
            pkt.target_provider,
            peer,
            pkt.path
        );

        // 1) Резолвим апстрим-URL из конфига.
        let up_url = match self.proxy.ws_url_for(&pkt.target_provider, &pkt.path) {
            Some(u) => u,
            None => {
                tracing::warn!(
                    "WS[{}] отклонён: local_ws_url не задан в config.yaml",
                    pkt.target_provider
                );
                let ctrl = WsFrame::Close {
                    code: 1011,
                    reason: format!(
                        "provider '{}' не имеет local_ws_url в config.yaml (endpoints.<key>.local_ws_url) — WS-туннель отключён",
                        pkt.target_provider
                    ),
                };
                let _ = send.write_all(&ctrl.encode()).await;
                let _ = send.finish();
                return Ok(());
            }
        };
        tracing::info!("WS[{}] апстрим: {}", pkt.target_provider, up_url);

        // 2) Формируем HTTP-запрос handshake с whitelist'ом headers.
        let mut req = up_url
            .as_str()
            .into_client_request()
            .map_err(|e| anyhow!("into_client_request: {e}"))?;
        {
            let hdrs = req.headers_mut();
            for (k, v) in &pkt.headers {
                let lk = k.to_ascii_lowercase();
                if matches!(
                    lk.as_str(),
                    "host"
                        | "connection"
                        | "upgrade"
                        | "sec-websocket-key"
                        | "sec-websocket-version"
                        | "sec-websocket-accept"
                        | "content-length"
                        | "origin"
                        | "referer"
                        | "user-agent"
                ) {
                    continue;
                }
                if let (Ok(hn), Ok(hv)) = (
                    tokio_tungstenite::tungstenite::http::HeaderName::from_bytes(k.as_bytes()),
                    tokio_tungstenite::tungstenite::http::HeaderValue::from_str(v),
                ) {
                    hdrs.insert(hn, hv);
                }
            }
        }

        let (ws_stream, upstream_resp) = match tokio::time::timeout(
            Duration::from_secs(10),
            tokio_tungstenite::connect_async(req),
        )
        .await
        {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                tracing::warn!(
                    "WS[{}] upstream connect FAILED: {e} (url={up_url})",
                    pkt.target_provider
                );
                let ctrl = WsFrame::Close {
                    code: 1011,
                    reason: format!("upstream connect: {e}"),
                };
                let _ = send.write_all(&ctrl.encode()).await;
                let _ = send.finish();
                return Ok(());
            }
            Err(_) => {
                tracing::warn!(
                    "WS[{}] upstream connect TIMEOUT (10s, url={up_url})",
                    pkt.target_provider
                );
                let ctrl = WsFrame::Close {
                    code: 1011,
                    reason: "upstream connect timeout".to_string(),
                };
                let _ = send.write_all(&ctrl.encode()).await;
                let _ = send.finish();
                return Ok(());
            }
        };
        tracing::info!(
            "WS[{}] апстрим OK (HTTP {})",
            pkt.target_provider,
            upstream_resp.status().as_u16()
        );
        let (mut ws_sink, mut ws_recv) = ws_stream.split();

        // 3) Handshake-ACK клиенту (первый Text-фрейм).
        let handshake_ack = serde_json::json!({
            "status": upstream_resp.status().as_u16(),
        })
        .to_string();
        send.write_all(&WsFrame::Text(handshake_ack).encode()).await?;

        // 4) Bidirectional pump с backpressure.
        let msg_rate = self.proxy.ws_msg_rate_for(&pkt.target_provider);
        let limiter = self.limiter.clone();
        let peer_key = format!("{peer}:ws:{}", pkt.target_provider);

        let (up_tx, mut up_rx) = tokio::sync::mpsc::channel::<TMsg>(128);
        // client → upstream: читаем WsFrame из iroh RecvStream, толкаем в mpsc.
        let mut client_to_up = tokio::spawn(async move {
            loop {
                match WsFrame::read_from(&mut recv).await {
                    Ok(Some(WsFrame::Text(t))) => {
                        if !limiter.allow(&peer_key, msg_rate) {
                            continue;
                        }
                        // send с 5s timeout — если dApp/апстрим не читает,
                        // рвём сессию (slow_consumer_disconnect).
                        match tokio::time::timeout(Duration::from_secs(5), up_tx.send(TMsg::Text(t.into()))).await {
                            Ok(Ok(())) => {}
                            _ => break,
                        }
                    }
                    Ok(Some(WsFrame::Binary(b))) => {
                        if !limiter.allow(&peer_key, msg_rate) {
                            continue;
                        }
                        match tokio::time::timeout(Duration::from_secs(5), up_tx.send(TMsg::Binary(b.into()))).await {
                            Ok(Ok(())) => {}
                            _ => break,
                        }
                    }
                    Ok(Some(WsFrame::Ping(p))) => {
                        let _ = up_tx.send(TMsg::Ping(p.into())).await;
                    }
                    Ok(Some(WsFrame::Pong(p))) => {
                        let _ = up_tx.send(TMsg::Pong(p.into())).await;
                    }
                    Ok(Some(WsFrame::Close { code, reason })) => {
                        // Санитизация: reserved-коды (1005/1006/1015) по RFC 6455 §7.4.1
                        // ЗАПРЕЩЕНО отправлять в close-фрейме. Заменяем на 1000
                        // (Normal Closure) — иначе tungstenite на upstream отклонит
                        // фрейм с ошибкой «invalid status code 1006».
                        let safe_code = match code {
                            1005 | 1006 | 1015 => 1000,
                            _ => code,
                        };
                        let cf = tokio_tungstenite::tungstenite::protocol::CloseFrame {
                            code: safe_code.into(),
                            reason: reason.into(),
                        };
                        let _ = up_tx.send(TMsg::Close(Some(cf))).await;
                        break;
                    }
                    Ok(None) => break,
                    Err(_) => break,
                }
            }
        });

        // upstream → client + writer из up_rx.
        let mut pump = tokio::spawn(async move {
            loop {
                tokio::select! {
                    frame = ws_recv.next() => {
                        match frame {
                            Some(Ok(TMsg::Text(t))) => {
                                let bytes = WsFrame::Text(t.to_string()).encode();
                                if send.write_all(&bytes).await.is_err() { break; }
                            }
                            Some(Ok(TMsg::Binary(b))) => {
                                let bytes = WsFrame::Binary(b.to_vec()).encode();
                                if send.write_all(&bytes).await.is_err() { break; }
                            }
                            Some(Ok(TMsg::Ping(p))) => {
                                let bytes = WsFrame::Ping(p.to_vec()).encode();
                                let _ = send.write_all(&bytes).await;
                            }
                            Some(Ok(TMsg::Pong(p))) => {
                                let bytes = WsFrame::Pong(p.to_vec()).encode();
                                let _ = send.write_all(&bytes).await;
                            }
                            Some(Ok(TMsg::Close(cf))) => {
                                let (code, reason) = cf
                                    .map(|c| (u16::from(c.code), c.reason.to_string()))
                                    .unwrap_or((1000, String::new()));
                                let bytes = WsFrame::Close { code, reason }.encode();
                                let _ = send.write_all(&bytes).await;
                                break;
                            }
                            Some(Ok(_)) => {}
                            Some(Err(_)) | None => break,
                        }
                    }
                    Some(out) = up_rx.recv() => {
                        if ws_sink.send(out).await.is_err() { break; }
                    }
                    else => break,
                }
            }
            let _ = send.finish();
        });

        // Ждём пока любая из задач не завершится → сваливаемся, abort'им вторую.
        // Hard-cap 24h на всю сессию как страховка.
        let session = async move {
            tokio::select! {
                _ = &mut client_to_up => {},
                _ = &mut pump => {},
            }
            client_to_up.abort();
            pump.abort();
        };
        let _ = tokio::time::timeout(Duration::from_secs(24 * 3600), session).await;
        Ok(())
    }


    /// Multi-hop ретрансляция: уменьшаем TTL и пересылаем известному пиру.
    async fn relay(&self, pkt: &MeshPacket) -> Result<Vec<u8>> {
        if pkt.ttl == 0 {
            return Err(anyhow!("TTL истёк — пакет отброшен"));
        }
        let mut fwd = pkt.clone();
        fwd.ttl -= 1;

        // Сначала — пиры, которые ЯВНО проксируют нужную цель; иначе любые.
        let mut candidates = self.peers.providers_of(&pkt.target_provider, &self.node_id);
        if candidates.is_empty() {
            candidates = self.peers.others(&self.node_id);
        }
        if candidates.is_empty() {
            return Err(anyhow!("нет известных пиров для ретрансляции"));
        }

        for cand in candidates {
            match self.forward_to(&cand, &fwd).await {
                Ok(resp) => return Ok(resp),
                Err(e) => {
                    tracing::debug!("ретрансляция к {cand} не удалась: {e:#}");
                    continue;
                }
            }
        }
        Err(anyhow!("все кандидаты для ретрансляции недоступны"))
    }

    /// Открыть исходящий api://-стрим к конкретному пиру и прокинуть пакет.
    /// Возвращаем тело ответа как есть (подпись исполнителя внутри pdata).
    async fn forward_to(&self, node_id_str: &str, pkt: &MeshPacket) -> Result<Vec<u8>> {
        let eid: EndpointId = node_id_str
            .parse()
            .map_err(|_| anyhow!("невалидный NodeID пира: {node_id_str}"))?;

        let conn = self.endpoint.connect(eid, protocol::ALPN).await?;
        let (mut send, mut recv) = conn.open_bi().await?;
        send.write_all(&serde_json::to_vec(pkt)?).await?;
        send.finish()?;
        let raw = recv.read_to_end(MAX_FRAME).await?;
        Ok(raw)
    }
}

/// Записать тело ответа в стрим и закрыть его.
async fn write_response(send: &mut iroh::endpoint::SendStream, body: &[u8]) -> Result<()> {
    send.write_all(body).await?;
    send.finish()?;
    Ok(())
}

// =====================================================================
//  Discovery: анонс подписанного манифеста + сбор чужих анонсов
// =====================================================================

/// Топик gossip для анонсов провайдеров (детерминированный).
fn announce_topic() -> TopicId {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"netfory:announce:v0");
    let digest = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&digest);
    TopicId::from_bytes(arr)
}

fn spawn_discovery(
    gossip: Gossip,
    _endpoint: Endpoint,
    root: Root,
    cfg: Config,
    stats: Arc<Stats>,
    peers: Arc<PeerStore>,
) {
    tokio::spawn(async move {
        let topic = announce_topic();

        // Бутстрапим топик уже известными пирами (если есть в peers.dat).
        let boots: Vec<EndpointId> = peers
            .others("")
            .into_iter()
            .filter_map(|n| n.parse::<EndpointId>().ok())
            .collect();

        let sub = match gossip.subscribe(topic, boots).await {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("gossip subscribe: {e:#}");
                return;
            }
        };
        let (tx, rx) = sub.split();

        // Слушатель чужих анонсов.
        let (peers_l, stats_l) = (peers.clone(), stats.clone());
        tokio::spawn(async move {
            listen_announces(rx, peers_l, stats_l).await;
        });

        // Периодический анонс собственного манифеста.
        let interval = Duration::from_secs(cfg.gossip.announce_interval_secs.max(15));
        let signing = crypto::signing_key(&root);
        let names = cfg.endpoints.values().map(|e| e.name.clone()).collect::<Vec<_>>();
        let node_id = stats.node_id.clone();

        loop {
            let mut m = Manifest {
                node_id: node_id.clone(),
                endpoints: names.clone(),
                uptime_secs: stats.uptime_secs(),
                latency_ms: stats.avg_latency_ms(),
                requests_total: stats.requests_total.load(std::sync::atomic::Ordering::Relaxed),
                signed_at: now_secs(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                signature: String::new(),
                seen_at: 0,
            };
            m.signature = crypto::sign_hex(&signing, &m.canonical_bytes());

            if let Ok(bytes) = serde_json::to_vec(&m) {
                if let Err(e) = tx.broadcast(bytes.into()).await {
                    tracing::debug!("анонс не отправлен: {e:#}");
                }
            }
            tokio::time::sleep(interval).await;
        }
    });
}

/// Принимать анонсы, проверять подпись и складывать в peers.dat.
async fn listen_announces(mut rx: GossipReceiver, peers: Arc<PeerStore>, stats: Arc<Stats>) {
    use n0_future::StreamExt;
    while let Some(ev) = rx.next().await {
        match ev {
            Ok(Event::Received(msg)) => {
                if let Ok(mut m) = serde_json::from_slice::<Manifest>(&msg.content) {
                    // Принимаем только корректно подписанные манифесты —
                    // защита от поддельных записей о провайдерах.
                    if verify_manifest(&m) {
                        m.seen_at = now_secs();
                        let _ = peers.upsert(&m);
                        stats.set_active_peers(peers.list().len() as u64);
                    }
                }
            }
            Ok(_) => continue, // NeighborUp/Down и пр.
            Err(_) => break,
        }
    }
}

/// Проверить Ed25519-подпись манифеста по его node_id (EndpointId-строка).
fn verify_manifest(m: &Manifest) -> bool {
    let eid: EndpointId = match m.node_id.parse() {
        Ok(e) => e,
        Err(_) => return false,
    };
    // Публичный ключ EndpointId == ключ верификации подписи (один корень).
    let pk = eid.as_bytes();
    let vk = match ed25519_dalek::VerifyingKey::from_bytes(pk) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let sig_bytes = match hex::decode(&m.signature) {
        Ok(b) if b.len() == 64 => b,
        _ => return false,
    };
    let mut sarr = [0u8; 64];
    sarr.copy_from_slice(&sig_bytes);
    use ed25519_dalek::Verifier;
    vk.verify(&m.canonical_bytes(), &ed25519_dalek::Signature::from_bytes(&sarr))
        .is_ok()
}

// =====================================================================
//  Health-check локальных RPC-нод
// =====================================================================

fn spawn_health(proxy: Arc<ProxyEngine>, stats: Arc<Stats>, peers: Arc<PeerStore>) {
    tokio::spawn(async move {
        loop {
            let mut list = Vec::new();
            for name in proxy.names() {
                let (online, latency_ms) = proxy.health(&name).await;
                let protocols = proxy.protocols_for(&name);
                list.push(RpcStatus { name, online, latency_ms, protocols });
            }
            stats.set_rpc(list);
            stats.set_active_peers(peers.list().len() as u64);
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    });
}
