# netfory-provider - API Bridge & Router (SmartNet / Web 4.0)

A console-based Rust application that accepts encrypted P2P requests over a
custom **`api://`** protocol (built on QUIC/Iroh) and proxies them to local
instances on the clearnet (e.g., a SmartHoldem node at `localhost:4003`).

> **Why:** Instead of `https://node0.smartholdem.io`, the built-in SmartNet
> wallet connects to `api://<NodeID>` over the P2P network. Node access is
> provided as a decentralized resource without a central gateway, and data is
> **end-to-end signed** by the provider's key (protection against Data Poisoning
> by intermediate relays).

---

## Features

- 🔑 **Zero-Configuration.** No `config.yaml` or empty keys → the application
  generates a BIP-39 mnemonic (12 words), deterministically derives an
  Ed25519 key from it (which serves as both the **NodeID** and **data signing
  key**), writes everything back to the config, and prints the `NodeID` to
  the console.
- 🛰️ **`api://` protocol** over bidirectional QUIC streams via Iroh.
- 🔀 **GET, POST (any method) + request body.** The method and base64 body are
  taken from the packet; for a non-empty body, `Content-Type/Accept:
  application/json` is automatically set — enabling **transaction broadcasting**
  (`POST /api/transactions`) as well.
- 🔁 **Multi-hop relaying.** If the target name is foreign, the packet is
  forwarded to the next known peer with a decremented `TTL` (software relay).
  The executor's signature is preserved across all hops.
- ✍️ **End-to-end response signing** (Ed25519). The client verifies authenticity
  by `NodeID` without trusting intermediate nodes.
- 🕶️ **RELAY-ONLY mode (privacy).** If a non-empty `network.relays` list is
  configured, direct UDP connections are disabled; all traffic goes exclusively
  through the specified relays (e.g., your own `smartnet-relay`), and the
  **origin server's real IP is never disclosed to clients**.
- 🔌 **Flexible transport port.** `network.listen_port`: a fixed number (open
  UDP in the firewall for direct connections) or `random`/`auto`/`0` (random,
  communication via relay/holepunch). The `NETFORY_QUIC_PORT` environment
  variable overrides the config. The current port is visible in `/status` →
  `quic_udp_port`.
- 📡 **Discovery via iroh-gossip.** Every N minutes the provider announces a
  signed manifest (NodeID, proxied names, uptime, ping). Foreign announcements
  are verified by signature and stored in `peers.dat` (Sled).
- 🛡️ **Strict per-peer rate limiter** (token bucket), configurable in YAML.
- ⏱️ **5-second timeout** on any clearnet request (reqwest).
- 📊 **Local HTTP dashboard** (`localhost:8080`) with statistics + JSON
  (`/status`, `/peers`). The `/status` endpoint includes `quic_udp_port` (or
  `random`).
- 🧹 **Clean logs.** Internal noise from the Iroh QUIC stack (`noq_proto`
  MultipathNotNegotiated / PTO, `iroh::protocol` path races) is suppressed by
  default; override via `RUST_LOG`.

> **Client compatibility.** The SmartNet desktop client (Settings → Network)
> includes toggles for **"Relay-only mode"** (hide your IP) and **"SmartNet
> Relays"** (connect through your own relays in addition to n0). This is the
> client side of the same relay infrastructure.

---

## Architecture (Modules)

| Module | Purpose |
|--------|---------|
| `config.rs` | Parses `config.yaml` + automatic key initialization (Zero-Config) |
| `crypto.rs` | Single root: BIP-39 → Ed25519 (NodeID + signing) |
| `protocol.rs` | `MeshPacket`, `SignedResponse`, ALPN `api://` |
| `proxy_engine.rs` | Clearnet proxy (reqwest, 5s timeout) + response signing |
| `p2p_server.rs` | Iroh Endpoint, ProtocolHandler, relay, gossip announcements, health |
| `stats.rs` | Metrics collection + axum HTTP dashboard |
| `ratelimit.rs` | Token bucket per PeerID |
| `peers.rs` | `peers.dat` (Sled): manifests of known peers |

---

## Build & Run

```bash
cd netfory-provider
cargo build --release
./target/release/netfory-provider
```

On first run, `config.yaml` is created, keys are generated, and the **NodeID**
is printed to the console — this is the `api://<NodeID>` address for clients.

Log level: `RUST_LOG=debug ./netfory-provider`.

---

## `api://` Addressing

Canonical, secure scheme:

```
api://<nodeId>/<providerName>/<path>
```

- **`nodeId`** — the cryptographic address of the node (iroh EndpointId). It
  **cannot be forged**: the iroh connection is authenticated to this Ed25519
  key, and the response is signed with the same key.
- **`providerName`** — the endpoint name from `endpoints[].name` in the node's
  config. It is a **selector in the context of a specific node** (which
  `local_url` to proxy), not a global alias — therefore it does not need to be
  registered and cannot be hijacked. A single node may serve multiple providers.

Examples:

```
api://5fcb21b2…082f/node1-smartholdem/api/wallets/SeTQeEAsHnHU1Y9EBjkRVNPB3fmUvfFUrk
api://5fcb21b2…082f/xbts-gate1/api/...
```

The client verifies that the signing node (`pdata.node_id`) matches the
requested `nodeId` (for direct, non-relay requests).

## `api://` Packet Format

Response — **standard node JSON + `pdata` object** (compatible with SmartHoldem
node API, no rewriting required):

```jsonc
{
  "data": { "address": "SeTQ…", "balance": "800000000", "nonce": "0" },
  "pdata": {
    "v": 1,
    "node_id": "<Executor's NodeID>",        // = Ed25519 verification key
    "name": "node1-smartholdem",
    "status": 200,
    "signed_at": 1750000000,
    "relayed": false,
    "alg": "ed25519",
    "sig": "<hex signature>",
    "body_b64": "<base64 of the original node body>"
  }
}
```

### How the client (Tauri) verifies the signature

1. Reads `pdata.{node_id, status, signed_at, sig, body_b64}`.
2. Canonical bytes: `node_id | status | signed_at |` + `base64decode(body_b64)`.
3. Parses `node_id` as `iroh::EndpointId`, verifies `sig` (Ed25519) over these
   bytes. For a direct request, additionally checks that `node_id` matches the
   requested `<nodeId>`.

This protects data from tampering even if it was relayed through a foreign relay
node.

---

## `api://` Packet Format

Request (`MeshPacket`, JSON over bi-directional stream):

```jsonc
{
  "target_provider": "node1-smartholdem", // endpoint name from the node's config
  "method": "GET",
  "path": "/api/wallets/SeTQ…",            // appended to local_url
  "body": "",                              // base64 (request body)
  "ttl": 5,                                // relay hops
  "request_id": "a1b2c3…"
}
```

---

## Configuration (`config.yaml`)

See `config.example.yaml`. Key fields:

```yaml
identity:
  bip39_mnemonic: ""      # empty => auto-generated
  iroh_secret_key: ""     # empty => derived from mnemonic (hex root)
network:
  listen_port: random     # number (open UDP in firewall) | random/auto/0 (random)
  relays: []              # non-empty => RELAY-ONLY (direct UDP off, IP hidden)
  #   - https://relay-ru1.sth.cx
  #   - https://relay-fsn7.sth.cx
status:
  http_port: 8080
gossip:
  announce_interval_secs: 300
endpoints:
  smartholdem-node:
    protocol: "api"
    name: "node1-smartholdem"
    local_url: "http://localhost:4003/api"
    rate_limit_per_peer: 5
```

Environment variables:
- `NETFORY_QUIC_PORT` — overrides `network.listen_port` (`0`/`random` = random).
- `RUST_LOG` — log level/filter (QUIC noise is suppressed by default).

---

## Privacy: Relay-Only (IP Hiding)

By default, Iroh opportunistically establishes a **direct** UDP connection
(holepunch). In this case the client sees the provider server's **real IP** (at
the network level and via direct address announcements in discovery). The
`api://<nodeId>` scheme hides the IP from the URL, but **not from the network**.

To hide the real IP — configure your own relays:

```yaml
network:
  relays:
    - https://relay-ru1.sth.cx
    - https://relay-fsn7.sth.cx
```

The provider then starts in **RELAY-ONLY** mode: `clear_ip_transports()` (no
direct UDP socket) + `RelayMode::custom(...)`. All traffic goes through relays;
clients see only the relay address. `listen_port` is ignored; in `/status`
`quic_udp_port = 0`. Startup log: `RELAY-ONLY mode: N relays …`.

Clients require no configuration — they discover the provider's relay URL via
discovery by `NodeID`. Relay servers are part of the **`smartnet-relay`**
project; they must be Iroh-compatible and accessible over HTTPS.

> ⚠️ Metadata remains: the public n0-discovery knows the `NodeID → relay`
> mapping. For full autonomy, discovery can later be migrated to your own
> infrastructure. But the **origin IP is not disclosed in relay-only mode**.

---

## Iroh Version Note

The code is written for **iroh 1.0 + iroh-gossip 0.101** (the same pair used
in the SmartNet client). Package version: **0.3.0**.
