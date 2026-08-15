# Changelog

All notable changes to **netfory-provider** are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.2] - 2026-02-11

### Fixed — Sanitise reserved WS close codes in client→upstream path

Per RFC 6455 §7.4.1 close codes `1005`, `1006` and `1015` are reserved
for internal use and MUST NOT be sent in a Close frame. Previously the
provider forwarded whatever code the SmartNet client supplied to the
upstream WS server verbatim — when the client legitimately used `1006`
in a timeout path, tungstenite on the poker server rejected the frame
with «Invalid WebSocket frame: invalid status code 1006» and dropped the
connection abnormally.

Now `handle_ws_stream` remaps `1005 / 1006 / 1015 → 1000 (Normal
Closure)` before enqueueing to the upstream WS sink. The Reason string
is preserved. This is transparent to the client — it still sees whatever
close code the DApp initiated locally.

## [0.6.1] - 2026-02-11

### Added — Protocol badges on dashboard endpoints table

Every endpoint in the "Local RPC Nodes" table now shows badges for active
protocols next to the name: `pokersth [rpc] [ws]`.
- `[rpc]` — always (HTTP `local_url`)
- `[ws]` — only when `local_ws_url` is set in config.yaml

This lets you see at a glance whether the provider is ready to serve
WebSocket tunnels (e.g., for Socket.IO dApps). The JSON `/status` now
returns `rpc[].protocols: string[]`.

### Added — WebSocket tunnel: diagnostic logs

`handle_ws_stream` now writes `tracing::info!` at each key step:
- `WS[<provider>] handshake from peer=<hex> path=<path>` — incoming WS request
- `WS[<provider>] upstream: <ws-url>` — resolved `local_ws_url` + path
- `WS[<provider>] upstream OK (HTTP 101)` — upstream Socket.IO/WS responded
- `WS[<provider>] upstream connect FAILED: …` — could not connect to the
  local WS server (port closed, wrong host, TLS mismatch)
- `WS[<provider>] upstream connect TIMEOUT (10s)` — local WS hung
- `WS[<provider>] rejected: local_ws_url not set in config.yaml`

Without these logs it was impossible to distinguish "WS request never
arrived" from "arrived but upstream crashed". Now any WS tunnel failure
is visible at `INFO` level.

### Improved — clear error message in close(1011)

The Reason string now pinpoints the exact location of the missing field in
config.yaml: `endpoints.<key>.local_ws_url`.

## [0.6.0] - 2026-02-11

### Added — WebSocket tunnels are now live (`netfory/api/1` ALPN)

Companion to SmartNet client 1.55.29. dApps can `new WebSocket('ws://<nodeId>/<provider>/<path>')`
and get real-time bidirectional messaging over the same iroh QUIC
connection they already use for `api://` fetches. All headers
(`Authorization`, `Sec-WebSocket-Protocol`, custom `X-…`) are forwarded
to the upstream WS with the same hop-by-hop whitelist as HTTP.

- **`src/protocol.rs` — dual ALPN + length-prefix v1 handshake:**
  `ALPN_V1 = b"netfory/api/1"` alongside the legacy `ALPN` (=`/0`).
  `read_handshake_v1` / `write_handshake_v1` — `[LE_u32 len][JSON]`
  framing, `MAX_FRAME` (8 MiB) cap.
- **`src/p2p_server.rs`:** `Router::builder` accepts **both** ALPNs;
  `ApiProtocol { v1: bool }` remembers which one was used;
  `handle_stream(_, _, _, v1)` reads the handshake via
  `read_handshake_v1` on `/1` and via `recv.read_to_end()` on `/0`.
- **`src/p2p_server.rs`:** `handle_ws_stream()` **wired** into
  `handle_stream()` dispatch — activated when `v1 && method=="WS"`.
  Previously present but `#[allow(dead_code)]`. Now the real path.
  Framing on-wire: `[kind:u8][len:LE_u32][payload]` with
  `Text|Binary|Ping|Pong|Close` kinds and 8 MiB per-frame cap.
  Backpressure via bounded `mpsc(128)` in both directions; 5s
  slow-consumer disconnect; 24h session hard-cap; hop-by-hop headers
  whitelist for the upstream handshake.
- **`local_ws_url` in `EndpointCfg`**: if unset for a target, the
  provider replies with a `Close 1011` frame and hangs up cleanly —
  dApp sees `ws.onclose` with a helpful reason.

### Compatibility

- Client / provider negotiate ALPN transparently.
- Old client (`/0` only) + new provider: still works, HTTP-only, no WS.
- New client + old provider (`/0` only): client's `ws_open` returns
  `Err("provider does not support WS — upgrade to netfory-provider ≥ 0.6.0")`
  which surfaces to the dApp as `error` + `close(1006, ...)`.
- Old client + old provider: unchanged behavior.

## [0.5.0] - 2026-02-11

### Changed — Multi-request per connection (protocol v0.5)

Fundamental protocol change to enable connection pooling on the client
and open the door to WebSocket support (upcoming). Prior versions
handled exactly one bi-stream per QUIC connection and closed the
connection after replying. Now the provider **loops** on
`Connection::accept_bi()` and spawns each stream on its own tokio task,
letting a single client reuse an established QUIC connection for many
api://-requests in a row.

- **`src/p2p_server.rs` — `ApiProtocol::accept()`:** replaced the
  single-shot `handle_conn` + `connection.closed()` wait with a loop
  that dispatches every incoming bi-stream to a fresh `tokio::spawn`
  running `Handler::handle_stream`. Loop exits cleanly on
  `TimedOut` / `LocallyClosed` / `ApplicationClosed`.
- **`src/p2p_server.rs` — `MAX_CONCURRENT_STREAMS_PER_CONN = 16`:**
  new per-connection `tokio::sync::Semaphore` cap. A single client can
  keep at most 16 bi-streams in flight on the same connection —
  additional `open_bi()` calls wait for a slot. Protects the provider
  from DoS by a single peer flooding parallel heavy requests.
- **`src/p2p_server.rs` — `handle_stream()`:** renamed / extracted from
  `handle_conn`; accepts pre-opened `SendStream`/`RecvStream` +
  `&peer` string. Rate limiter, proxy routing and response writing
  logic unchanged.

### Added — WebSocket framing groundwork (not yet wired)

- **`src/protocol.rs` — `WsFrame` enum + wire framing**
  (`kind:u8 | len:LE_u32 | payload`, kinds Text/Binary/Ping/Pong/Close).
  `WsFrame::read_from()` / `WsFrame::encode()`. `MAX_WS_FRAME = 8 MiB`.
- **`src/config.rs` — `EndpointCfg.local_ws_url` (Option<String>)**
  and `ws_rate_limit_per_peer: u32` (default 30 msgs/sec).
  Absence disables WS tunnels for that endpoint.
- **`src/p2p_server.rs` — `handle_ws_stream()`** — full reference impl
  (tokio_tungstenite upstream, bounded mpsc(128) backpressure, 5s
  slow-consumer disconnect, hop-by-hop headers whitelist, 24h session
  hard-cap, WS↔iroh bi-directional pump).
  **Currently marked `#[allow(dead_code)]` and not called from
  `handle_stream()`** — the demarcation between the initial handshake
  JSON packet and the subsequent binary `WsFrame` stream on the same
  bi-stream is unresolved (`read_to_end()` waits for EOF, incompatible
  with a long-lived tunnel). A new `netfory/api/1` ALPN with length-
  prefixed handshake is planned for 0.6.0, at which point this code is
  wired in and paired with the client-side Rust pump + JS
  `WebSocket` polyfill.
- **`config.example.yaml`** documents the WS fields with commented
  examples.
- **`Cargo.toml`** — `tokio-tungstenite = "0.24"` (rustls-tls-webpki-roots)
  and `futures-util = "0.3"` added.

### Compatibility

- **Old clients (< 1.55.28)** open one stream, wait for the reply, then
  close the connection. Our new `accept_bi` loop sees the connection
  drop and exits cleanly — indistinguishable from prior behavior. No
  breakage.
- **New clients (≥ 1.55.28)** reuse the connection and get 10-20×
  latency wins on follow-up requests (no re-hole-punch).

## [0.4.5] - 2026-02-11

### Added — Dual-stack (IPv4 + IPv6) UDP bind

Providers on VPS with a public IPv6 address can now serve iroh/QUIC on
`[::]:listen_port` in parallel with `0.0.0.0:listen_port`. This lets
clients connect directly over v6, bypassing CGNAT / hole-punching and
eliminating the noisy iroh warning:

```
WARN iroh::net_report::report: IPv4 address detected by QAD varies by destination
```

Clients that only have IPv4 keep working (v4 socket is always bound
alongside v6, in that order).

- **`src/config.rs` — `network.ipv6_enabled: bool` (default `true`)**:
  new opt-out flag. Field is `#[serde(default)]` — old configs stay
  compatible and get IPv6 enabled on next start.
- **`src/p2p_server.rs` — dual-stack builder chain**: after
  `bind_addr("0.0.0.0:PORT")` we now call `bind_addr("[::]:PORT")`.
  If the v6 bind fails (port busy, no IPv6 on host), the builder is
  cleanly reconstructed with just v4 and a WARN is logged — the
  provider does not refuse to start.
- **`config.example.yaml`**: documents the `ipv6_enabled` field and
  the required `ip6tables` firewall rule for the same UDP port.

### Firewall

On Linux you now need one UDP rule per family for `listen_port`, e.g.
for port `11204`:

```bash
iptables  -A INPUT -p udp --dport 11204 -j ACCEPT
ip6tables -A INPUT -p udp --dport 11204 -j ACCEPT
```

## [0.4.4] - 2026-02-11

### Added — Forward client HTTP headers to upstream

`MeshPacket` gained an optional `headers: BTreeMap<String, String>` field
so dApp `fetch(url, { headers: { Authorization: 'Bearer …' } })` requests
survive the P2P round-trip and actually reach the upstream REST API.
Without this, authenticated endpoints (`/auth/me`, `/wallet`, …) returned
401 because the provider stripped the `Authorization` header before
proxying — the SmartNet client saw `[dapp] ERR GET 401 …/auth/me`.

- **`src/protocol.rs`:** `MeshPacket.headers` added, `#[serde(default)]`
  so older clients (no `headers` field) still deserialize cleanly.
- **`src/proxy_engine.rs`:** each incoming header is passed through a
  hop-by-hop safe-whitelist filter (drops `Host`, `Connection`,
  `Content-Length`, `Transfer-Encoding`, `Upgrade`, `Proxy-Connection`,
  `Keep-Alive`, `Origin`, `Referer`, `User-Agent`) before being applied
  to the `reqwest::RequestBuilder`. `Content-Type` /  `Accept` defaults
  to `application/json` **only** when the client did not send them
  itself (previously we clobbered the client's value).

### Compatibility
Forward-compatible for older clients (empty `headers` map → identical
behavior to 0.4.3). Backward-compatible for older providers (new
clients keep sending the field; a 0.4.3 provider simply ignores it and
still returns 401 on authenticated endpoints — same as today).
