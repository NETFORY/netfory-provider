//! Сбор внутренней статистики + локальный HTTP-дашборд (axum).
//!
//! Эндпоинты:
//!   GET /         — HTML-дашборд (как страница trackers/headless-seeds);
//!   GET /status   — JSON со статистикой и NodeID;
//!   GET /peers    — JSON-список известных пиров из peers.dat.

use axum::{extract::State, response::Html, routing::get, Json, Router};
use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use crate::peers::PeerStore;

/// Атомарные счётчики (потокобезопасны, без блокировок).
pub struct Stats {
    started: Instant,
    pub node_id: String,
    /// UDP-порт iroh/QUIC (0 == случайный). Показывается в /status, чтобы
    /// оператор знал, какой порт открывать в фаерволе VPS.
    pub quic_udp_port: u16,
    pub requests_total: AtomicU64,
    pub requests_proxied: AtomicU64,
    pub requests_relayed: AtomicU64,
    pub requests_rejected: AtomicU64,
    pub active_peers: AtomicU64,
    /// Сколько клиентов ПРЯМО СЕЙЧАС держат входящее соединение и обрабатываются
    /// (в отличие от active_peers — это другие провайдеры в mesh, не клиенты).
    pub active_connections: AtomicU64,
    /// Включён ли Mainline DHT (pkarr) discovery.
    pub dht_enabled: bool,
    /// Узлов в таблице маршрутизации Mainline DHT (бессерверное обнаружение).
    pub dht_nodes: AtomicU64,
    // статус локальных RPC: имя -> (online, latency_ms) хранится в JSON-снимке
    rpc: std::sync::Mutex<Vec<RpcStatus>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RpcStatus {
    pub name: String,
    pub online: bool,
    pub latency_ms: u64,
    /// Поддерживаемые протоколы этого эндпоинта (для badge на дашборде).
    /// Всегда содержит `"rpc"` (HTTP `local_url`) и, если задан `local_ws_url`,
    /// добавляется `"ws"`.
    #[serde(default)]
    pub protocols: Vec<String>,
}

impl Stats {
    pub fn new(node_id: String, quic_udp_port: u16, dht_enabled: bool) -> Self {
        Self {
            started: Instant::now(),
            node_id,
            quic_udp_port,
            requests_total: AtomicU64::new(0),
            requests_proxied: AtomicU64::new(0),
            requests_relayed: AtomicU64::new(0),
            requests_rejected: AtomicU64::new(0),
            active_peers: AtomicU64::new(0),
            active_connections: AtomicU64::new(0),
            dht_enabled,
            dht_nodes: AtomicU64::new(0),
            rpc: std::sync::Mutex::new(Vec::new()),
        }
    }

    pub fn uptime_secs(&self) -> u64 {
        self.started.elapsed().as_secs()
    }

    pub fn inc_total(&self) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_proxied(&self) {
        self.requests_proxied.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_relayed(&self) {
        self.requests_relayed.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_rejected(&self) {
        self.requests_rejected.fetch_add(1, Ordering::Relaxed);
    }
    pub fn set_active_peers(&self, n: u64) {
        self.active_peers.store(n, Ordering::Relaxed);
    }
    pub fn set_dht_nodes(&self, n: u64) {
        self.dht_nodes.store(n, Ordering::Relaxed);
    }
    /// Зафиксировать новое клиентское соединение. Возвращает guard, который
    /// автоматически уменьшит счётчик при выходе из области видимости — даже
    /// при панике или отмене задачи (гарантия корректности телеметрии).
    pub fn track_connection(self: &Arc<Self>) -> ConnGuard {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
        ConnGuard { stats: self.clone() }
    }
    pub fn set_rpc(&self, list: Vec<RpcStatus>) {
        *self.rpc.lock().unwrap() = list;
    }

    /// Средняя задержка локальных RPC (для манифеста).
    pub fn avg_latency_ms(&self) -> u64 {
        let rpc = self.rpc.lock().unwrap();
        let online: Vec<u64> = rpc.iter().filter(|r| r.online).map(|r| r.latency_ms).collect();
        if online.is_empty() {
            0
        } else {
            online.iter().sum::<u64>() / online.len() as u64
        }
    }

    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            node_id: self.node_id.clone(),
            quic_udp_port: self.quic_udp_port,
            uptime_secs: self.uptime_secs(),
            requests_total: self.requests_total.load(Ordering::Relaxed),
            requests_proxied: self.requests_proxied.load(Ordering::Relaxed),
            requests_relayed: self.requests_relayed.load(Ordering::Relaxed),
            requests_rejected: self.requests_rejected.load(Ordering::Relaxed),
            active_peers: self.active_peers.load(Ordering::Relaxed),
            active_connections: self.active_connections.load(Ordering::Relaxed),
            dht_enabled: self.dht_enabled,
            dht_nodes: self.dht_nodes.load(Ordering::Relaxed),
            avg_latency_ms: self.avg_latency_ms(),
            rpc: self.rpc.lock().unwrap().clone(),
        }
    }
}

/// RAII-страж активного клиентского соединения: уменьшает счётчик при drop.
pub struct ConnGuard {
    stats: Arc<Stats>,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.stats.active_connections.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct StatsSnapshot {
    pub node_id: String,
    /// UDP-порт iroh/QUIC (0 == случайный).
    pub quic_udp_port: u16,
    pub uptime_secs: u64,
    pub requests_total: u64,
    pub requests_proxied: u64,
    pub requests_relayed: u64,
    pub requests_rejected: u64,
    pub active_peers: u64,
    pub active_connections: u64,
    pub dht_enabled: bool,
    pub dht_nodes: u64,
    pub avg_latency_ms: u64,
    pub rpc: Vec<RpcStatus>,
}

#[derive(Clone)]
struct AppState {
    stats: Arc<Stats>,
    peers: Arc<PeerStore>,
}

/// Запустить локальный HTTP-сервер мониторинга.
pub async fn serve(port: u16, stats: Arc<Stats>, peers: Arc<PeerStore>) -> anyhow::Result<()> {
    let state = AppState { stats, peers };
    let app = Router::new()
        .route("/", get(dashboard))
        .route("/status", get(status_json))
        .route("/peers", get(peers_json))
        .with_state(state);

    let addr = format!("0.0.0.0:{port}");
    tracing::info!("HTTP-дашборд: http://localhost:{port}/  (JSON: /status, /peers)");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn status_json(State(s): State<AppState>) -> Json<StatsSnapshot> {
    Json(s.stats.snapshot())
}

async fn peers_json(State(s): State<AppState>) -> Json<Vec<crate::peers::Manifest>> {
    Json(s.peers.list())
}

/// HTML-дашборд в стиле страниц trackers / headless-seeds: тёмная тема,
/// авто-обновление каждые 3с, ключевые метрики и таблицы.
async fn dashboard() -> Html<&'static str> {
    Html(DASHBOARD_HTML)
}

const DASHBOARD_HTML: &str = r#"<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>netfory-provider · SmartNet</title>
<style>
  :root { --bg:#0a0e14; --panel:#121821; --line:#1e2733; --txt:#cbd5e1; --dim:#64748b; --acc:#34d399; --warn:#fb923c; --bad:#f87171; }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--txt); font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace; }
  .wrap { max-width:1100px; margin:0 auto; padding:32px 24px; }
  h1 { font-size:20px; letter-spacing:1px; margin:0 0 4px; }
  .sub { color:var(--dim); margin:0 0 24px; word-break:break-all; }
  .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:14px; margin-bottom:28px; }
  .card { background:var(--panel); border:1px solid var(--line); border-left:2px solid var(--acc); border-radius:8px; padding:16px; }
  .card .v { font-size:26px; font-weight:700; color:#fff; }
  .card .l { color:var(--dim); font-size:11px; text-transform:uppercase; letter-spacing:.5px; margin-top:4px; }
  h2 { font-size:13px; color:var(--dim); text-transform:uppercase; letter-spacing:1px; margin:24px 0 10px; }
  table { width:100%; border-collapse:collapse; background:var(--panel); border:1px solid var(--line); border-radius:8px; overflow:hidden; }
  th,td { text-align:left; padding:10px 14px; border-bottom:1px solid var(--line); font-size:13px; }
  th { color:var(--dim); font-weight:600; text-transform:uppercase; font-size:11px; }
  tr:last-child td { border-bottom:none; }
  .dot { display:inline-block; width:8px; height:8px; border-radius:50%; margin-right:6px; }
  .on { background:var(--acc); box-shadow:0 0 8px rgba(52,211,153,.6); }
  .off { background:var(--bad); }
  .mono { word-break:break-all; }
  .nid { color:var(--acc); }
  .badge {
    display:inline-block; margin-left:6px; padding:1px 7px; font-size:10px;
    line-height:1.5; border-radius:999px; text-transform:uppercase;
    letter-spacing:.5px; border:1px solid var(--line); color:var(--dim);
    background:rgba(148,163,184,.06); vertical-align:middle;
  }
  .badge.rpc { color:var(--acc); border-color:rgba(52,211,153,.4); background:rgba(52,211,153,.08); }
  .badge.ws  { color:#60a5fa;  border-color:rgba(96,165,250,.4);  background:rgba(96,165,250,.08); }
  footer { color:var(--dim); margin-top:28px; font-size:11px; }
</style>
</head>
<body>
<div class="wrap">
  <h1>⛬ netfory-provider</h1>
  <p class="sub">API Bridge &amp; Router · SmartNet (Web 4.0) · NodeID: <span class="nid mono" id="nid">…</span></p>

  <div class="grid">
    <div class="card"><div class="v" id="uptime">—</div><div class="l">Аптайм</div></div>
    <div class="card"><div class="v" id="total">0</div><div class="l">Запросов всего</div></div>
    <div class="card"><div class="v" id="proxied">0</div><div class="l">Проксировано</div></div>
    <div class="card"><div class="v" id="relayed">0</div><div class="l">Ретранслировано</div></div>
    <div class="card"><div class="v" id="rejected">0</div><div class="l">Отклонено (лимит)</div></div>
    <div class="card"><div class="v" id="peers">0</div><div class="l">Активные пиры</div></div>
    <div class="card" style="border-left-color:var(--warn)"><div class="v" id="conns">0</div><div class="l">Активные клиенты</div></div>
    <div class="card"><div class="v" id="dht" style="font-size:22px">—</div><div class="l">DHT-узлы (Mainline)</div></div>
    <div class="card"><div class="v" id="lat">0<span style="font-size:14px"> ms</span></div><div class="l">Средний пинг RPC</div></div>
    <div class="card" style="border-left-color:var(--warn)"><div class="v" id="quic" style="font-size:22px">—</div><div class="l">UDP-порт (открыть в фаерволе)</div></div>
  </div>

  <h2>Локальные RPC-ноды (клирнет)</h2>
  <table>
    <thead><tr><th>Эндпоинт</th><th>Статус</th><th>Задержка</th></tr></thead>
    <tbody id="rpc"><tr><td colspan="3" style="color:#64748b">загрузка…</td></tr></tbody>
  </table>

  <h2>Известные пиры (peers.dat)</h2>
  <table>
    <thead><tr><th>NodeID</th><th>Эндпоинты</th><th>Аптайм</th><th>Пинг</th></tr></thead>
    <tbody id="peerlist"><tr><td colspan="4" style="color:#64748b">загрузка…</td></tr></tbody>
  </table>

  <footer>Авто-обновление каждые 3с · данные: <code>/status</code>, <code>/peers</code></footer>
</div>
<script>
function fmtUptime(s){ const d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60); return (d?d+"д ":"")+(h?h+"ч ":"")+m+"м"; }
async function tick(){
  try {
    const s = await (await fetch('/status')).json();
    document.getElementById('nid').textContent = s.node_id;
    document.getElementById('uptime').textContent = fmtUptime(s.uptime_secs);
    document.getElementById('total').textContent = s.requests_total;
    document.getElementById('proxied').textContent = s.requests_proxied;
    document.getElementById('relayed').textContent = s.requests_relayed;
    document.getElementById('rejected').textContent = s.requests_rejected;
    document.getElementById('peers').textContent = s.active_peers;
    document.getElementById('conns').textContent = s.active_connections;
    document.getElementById('dht').textContent = s.dht_enabled ? (s.dht_nodes + ' узл.') : 'выкл';
    document.getElementById('lat').innerHTML = s.avg_latency_ms + '<span style="font-size:14px"> ms</span>';
    document.getElementById('quic').textContent = (s.quic_udp_port && s.quic_udp_port !== 0) ? (s.quic_udp_port + '/udp') : 'random';
    document.getElementById('rpc').innerHTML = (s.rpc||[]).map(r => {
      const badges = (r.protocols||['rpc']).map(p => `<span class="badge ${p}">${p}</span>`).join('');
      return `<tr><td class="mono">${r.name}${badges}</td><td><span class="dot ${r.online?'on':'off'}"></span>${r.online?'ONLINE':'OFFLINE'}</td><td>${r.latency_ms} ms</td></tr>`;
    }).join('') || '<tr><td colspan="3" style="color:#64748b">нет эндпоинтов</td></tr>';

    const peers = await (await fetch('/peers')).json();
    document.getElementById('peerlist').innerHTML = (peers||[]).map(p =>
      `<tr><td class="mono nid">${p.node_id.slice(0,20)}…</td><td>${(p.endpoints||[]).join(', ')}</td><td>${fmtUptime(p.uptime_secs)}</td><td>${p.latency_ms} ms</td></tr>`
    ).join('') || '<tr><td colspan="4" style="color:#64748b">пиров пока нет</td></tr>';
  } catch(e) {}
}
tick(); setInterval(tick, 3000);
</script>
</body>
</html>"#;
