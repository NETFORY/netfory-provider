# netfory-provider - API Bridge & Router (SmartNet / Web 4.0)

Консольное Rust-приложение, которое принимает зашифрованные P2P-запросы по
кастомному протоколу **`api://`** (поверх QUIC/Iroh) и проксирует их на
локальные инстансы в клирнете (например, нода SmartHoldem на `localhost:4003`).

> **Зачем:** вместо `https://node0.smartholdem.io` встроенный кошелёк
> SmartNet обращается к `api://<NodeID>` через P2P-сеть. Доступ к ноде
> раздаётся как децентрализованный ресурс, без центрального шлюза, а данные
> **end-to-end подписываются** ключом провайдера (защита от Data Poisoning
> промежуточными реле).

---

## Возможности

- 🔑 **Zero-Configuration.** Нет `config.yaml` или пустые ключи -> приложение
  само генерирует BIP-39 мнемонику (12 слов), детерминированно выводит из неё
  Ed25519-ключ (это одновременно **NodeID** и **ключ подписи данных**),
  записывает всё обратно в конфиг и печатает `NodeID` в консоль.
- 🛰️ **Протокол `api://`** на двунаправленных QUIC-стримах Iroh.
- 🔀 **GET и POST (любой метод) + тело запроса.** Метод и base64-тело берутся
  из пакета; для непустого тела автоматически выставляется
  `Content-Type/Accept: application/json` - благодаря этому работает в т.ч.
  **broadcast транзакций** (`POST /api/transactions`).
- 🔁 **Multi-hop ретрансляция.** Если имя цели чужое - пакет пересылается
  следующему известному пиру с уменьшением `TTL` (программный реле). Подпись
  исполнителя сохраняется сквозь все прыжки.
- ✍️ **Сквозная подпись ответов** (Ed25519). Клиент проверяет подлинность по
  `NodeID`, не доверяя промежуточным нодам.
- 🕶️ **RELAY-ONLY режим (приватность).** Если в конфиге задан непустой список
  `network.relays` - прямые UDP-подключения отключаются, весь трафик идёт
  только через указанные relay (например свои `smartnet-relay`), и **реальный
  IP origin-сервера клиентам не раскрывается**.
- 🔌 **Гибкий транспортный порт.** `network.listen_port`: фиксированное число
  (открыть UDP в фаерволе для прямых подключений) или `random`/`auto`/`0`
  (случайный, связь через relay/holepunch). Env `NETFORY_QUIC_PORT`
  переопределяет конфиг. Текущий порт виден в `/status` -> `quic_udp_port`.
- 📡 **Discovery через iroh-gossip.** Раз в N минут провайдер анонсирует
  подписанный манифест (NodeID, проксируемые имена, аптайм, пинг). Чужие
  анонсы проверяются по подписи и складываются в `peers.dat` (Sled).
- 🛡️ **Жёсткий per-peer rate limiter** (токен-бакет), настраиваемый в YAML.
- ⏱️ **Таймаут 5с** на любой запрос в клирнет (reqwest).
- 📊 **Локальный HTTP-дашборд** (`localhost:8080`) со статистикой + JSON
  (`/status`, `/peers`). В `/status` есть `quic_udp_port` (или `random`).
- 🧹 **Чистый лог.** Внутренний шум QUIC-стека iroh (`noq_proto`
  MultipathNotNegotiated / PTO, гонка путей `iroh::protocol`) по умолчанию
  заглушён; переопределяется через `RUST_LOG`.

> **Совместимость с клиентом.** В десктоп-клиенте SmartNet (Настройки -> Сеть)
> есть тумблеры **«Режим только через relay»** (скрыть свой IP) и **«SmartNet
> Relays»** (подключаться через свои relay в дополнение к n0). Это клиентская
> сторона той же relay-инфраструктуры.

---

## Архитектура (модули)

| Модуль | Назначение |
|--------|-----------|
| `config.rs` | Парсинг `config.yaml` + автоинициализация ключей (Zero-Config) |
| `crypto.rs` | Единый корень: BIP-39 -> Ed25519 (NodeID + подпись) |
| `protocol.rs` | `MeshPacket`, `SignedResponse`, ALPN `api://` |
| `proxy_engine.rs` | Прокси в клирнет (reqwest, таймаут 5с) + подпись ответа |
| `p2p_server.rs` | Iroh Endpoint, ProtocolHandler, реле, gossip-анонсы, health |
| `stats.rs` | Сбор метрик + axum HTTP-дашборд |
| `ratelimit.rs` | Токен-бакет на каждый PeerID |
| `peers.rs` | `peers.dat` (Sled): манифесты известных пиров |

---

## Сборка и запуск

```bash
cd netfory-provider
cargo build --release
./target/release/netfory-provider
```

При первом запуске будет создан `config.yaml`, сгенерированы ключи и в консоль
выведен **NodeID** - это и есть адрес `api://<NodeID>` для клиентов.

Уровень логов: `RUST_LOG=debug ./netfory-provider`.

---

## Адресация `api://`

Каноническая, безопасная схема:

```
api://<nodeId>/<providerName>/<path>
```

- **`nodeId`** - криптографический адрес узла (iroh EndpointId). Его **нельзя
  подделать**: соединение iroh аутентифицировано именно к этому Ed25519-ключу,
  а ответ подписывается тем же ключом.
- **`providerName`** - имя эндпоинта из `endpoints[].name` в конфиге узла.
  Это **селектор в контексте конкретного узла** (какой `local_url`
  проксировать), а не глобальный алиас - поэтому его не нужно регистрировать и
  невозможно угнать. Один узел может обслуживать несколько провайдеров.

Примеры:

```
api://5fcb21b2…082f/node1-smartholdem/api/wallets/SeTQeEAsHnHU1Y9EBjkRVNPB3fmUvfFUrk
api://5fcb21b2…082f/xbts-gate1/api/...
```

Клиент проверяет, что подписавший узел (`pdata.node_id`) совпадает с
запрошенным `nodeId` (для прямых, не-реле запросов).

## Формат пакета `api://`

Ответ - **стандартный JSON узла + объект `pdata`** (совместимо с API нод
SmartHoldem, ничего переписывать не нужно):

```jsonc
{
  "data": { "address": "SeTQ…", "balance": "800000000", "nonce": "0" },
  "pdata": {
    "v": 1,
    "node_id": "<NodeID исполнителя>",     // = Ed25519 ключ верификации
    "name": "node1-smartholdem",
    "status": 200,
    "signed_at": 1750000000,
    "relayed": false,
    "alg": "ed25519",
    "sig": "<hex подписи>",
    "body_b64": "<base64 исходного тела узла>"
  }
}
```

### Как клиент (Tauri) проверяет подпись

1. Читает `pdata.{node_id, status, signed_at, sig, body_b64}`.
2. Канонические байты: `node_id | status | signed_at |` + `base64decode(body_b64)`.
3. Парсит `node_id` как `iroh::EndpointId`, проверяет `sig` (Ed25519) над этими
   байтами. Для прямого запроса дополнительно сверяет, что `node_id` совпадает
   с запрошенным `<nodeId>`.

Так данные защищены от подмены даже если их пронёс через себя чужой реле-узел.

---

## Формат пакета `api://`

Запрос (`MeshPacket`, JSON по bi-stream):

```jsonc
{
  "target_provider": "node1-smartholdem", // имя эндпоинта из конфига узла
  "method": "GET",
  "path": "/api/wallets/SeTQ…",            // добавляется к local_url
  "body": "",                              // base64 (тело запроса)
  "ttl": 5,                                // прыжки ретрансляции
  "request_id": "a1b2c3…"
}
```


---

## Конфиг (`config.yaml`)

См. `config.example.yaml`. Ключевые поля:

```yaml
identity:
  bip39_mnemonic: ""      # пусто => сгенерируется
  iroh_secret_key: ""     # пусто => выведется из мнемоники (hex корня)
network:
  listen_port: random     # число (откр. UDP в фаерволе) | random/auto/0 (случайный)
  relays: []              # непусто => RELAY-ONLY (прямой UDP off, IP скрыт)
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

Переменные окружения:
- `NETFORY_QUIC_PORT` - переопределяет `network.listen_port` (`0`/`random` = случайный).
- `RUST_LOG` - уровень/фильтр логов (по умолчанию шум QUIC заглушён).

---

## Приватность: relay-only (скрытие IP)

По умолчанию iroh оппортунистически устанавливает **прямое** UDP-соединение
(holepunch). В этом случае клиент видит **реальный IP** сервера-провайдера (на
сетевом уровне и через анонс прямых адресов в discovery). Схема `api://<nodeId>`
прячет IP из URL, но **не из сети**.

Чтобы скрыть реальный IP - задайте свои relay:

```yaml
network:
  relays:
    - https://relay-ru1.sth.cx
    - https://relay-fsn7.sth.cx
```

Тогда провайдер стартует в **RELAY-ONLY** режиме: `clear_ip_transports()` (нет
прямого UDP-сокета) + `RelayMode::custom(...)`. Весь трафик идёт через relay,
клиенты видят только адрес relay. `listen_port` игнорируется, в `/status`
`quic_udp_port = 0`. В логе при старте: `RELAY-ONLY режим: N relay …`.

Клиентам ничего настраивать не нужно - relay-URL провайдера они узнают через
discovery по `NodeID`. Relay-серверы - проект **`smartnet-relay`**; должны быть
iroh-совместимы и доступны по HTTPS.

> ⚠️ Остаётся метаданными: публичный n0-discovery знает соответствие
> `NodeID -> relay`. Для полной автономии можно позже перевести и discovery на
> свою инфраструктуру. Но **origin IP в relay-only уже не раскрывается**.

---

## Замечание о версии Iroh

Код написан под **iroh 1.0 + iroh-gossip 0.101** (та же пара, что в клиенте
SmartNet). Версия пакета - **0.3.0**.
