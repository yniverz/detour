[![License: NCPUL](https://img.shields.io/badge/license-NCPUL-blue.svg)](./LICENSE.md)
[![ci](https://github.com/yniverz/detour/actions/workflows/ci.yml/badge.svg)](https://github.com/yniverz/detour/actions/workflows/ci.yml)

# detour

**A header-routed reverse proxy.** A trusted front proxy tells detour, per request, where to send it:

```
client ──► front proxy (TLS, auth, hostname routing) ──► detour ──► upstream(s)
              sets  X-Detour-Target: http://10.0.0.5:8080/app
                    X-Detour-Key:    <shared secret>
```

detour has **no routing configuration of its own**. Everything that varies per service lives in the
front proxy's per-route headers; detour only enforces *who may ask* (shared keys, trusted sources) and
*where it may go* (target allowlist). It adds the things many front proxies cannot do:

* 🧭 **Backend paths** – `study.example.com/page` → `http://10.0.0.5/study/page`
* ⚖️ **Load balancing** – round robin (weighted, smooth), random, failover, sticky IP hash, least connections, backup targets
* ❤️ **Passive health checks & retries** – failed upstreams are skipped for a while; idempotent requests move on to the next upstream
* ↩️ **Redirect & cookie path rewriting** – `Location: http://10.0.0.5/study/login` becomes `/login`
* 🔌 **WebSockets, streaming, HTTP/2 upstreams** – built on Go's `httputil.ReverseProxy`
* 🔒 **Safe by default** – refuses to start without keys and a target allowlist; allowlist is enforced on the IP actually dialed
* 📈 `/healthz`, Prometheus `/metrics`, JSON logs, single static binary, small distroless image

Typical front proxies: [NetBird reverse proxy](https://docs.netbird.io/manage/reverse-proxy) (custom headers per target), Traefik, Caddy, nginx, HAProxy, Cloudflare Workers – anything that can add request headers per route.

---

## Quick start

```bash
docker run -d --name detour -p 8080:8080 \
  -e DETOUR_KEYS=change-me-to-a-long-random-string \
  -e DETOUR_ALLOWED_TARGETS=10.0.0.0/8 \
  ghcr.io/yniverz/detour:latest

curl -H 'X-Detour-Key: change-me-to-a-long-random-string' \
     -H 'X-Detour-Target: http://10.0.0.5:8080/app' \
     http://localhost:8080/some/page
# → proxied to http://10.0.0.5:8080/app/some/page
```

See [`compose.example.yml`](compose.example.yml) for a fuller setup (admin port, secrets file, read-only container).

Generate a key with `openssl rand -hex 32`.

---

## Request headers

All header names use the prefix `X-Detour-` (configurable with `DETOUR_HEADER_PREFIX`).
**Every header with that prefix is removed before the request is forwarded**, so the key never reaches an upstream.

| Header | Required | Example | Meaning |
|---|---|---|---|
| `X-Detour-Key` | yes (unless auth disabled) | `3f9c…` | Shared secret; any of `DETOUR_KEYS` |
| `X-Detour-Target` | yes (unless `DETOUR_DEFAULT_TARGET`) | `http://10.0.0.5:8080/app` | One or more upstreams, see below |
| `X-Detour-Policy` | no | `iphash` | Balancing policy for this request |
| `X-Detour-Host` | no | `target` | `incoming` (default), `target`, or a literal Host value |
| `X-Detour-Strip-Prefix` | no | `/api` | Remove this path prefix before appending to the base path |
| `X-Detour-Rewrite-Redirects` | no | `false` | Toggle Location/Set-Cookie path rewriting |
| `X-Detour-Insecure` | no | `true` | Skip upstream TLS verification (only if `DETOUR_ALLOW_INSECURE_TLS=true`) |

`Policy`, `Host`, `Strip-Prefix` and `Rewrite-Redirects` can be disabled as a group with `DETOUR_ALLOW_OVERRIDES=false`.

### Target syntax

```
X-Detour-Target: <url>[;weight=N][;backup] [, <url>…]
```

* `<url>` – `http` or `https` URL; its path is the **base path**, its query is merged in front of the client's query.
* `weight=N` – relative weight (1–1000) for `roundrobin`, `random`, `iphash`, `leastconn`.
* `backup` – only used when no primary target is available.
* Separate targets with commas or whitespace; repeated headers are combined.

```
X-Detour-Target: https://10.0.0.11:8006, https://10.0.0.12:8006, https://10.0.0.13:8006
X-Detour-Target: http://app-a:8080;weight=3, http://app-b:8080, http://maintenance:8080;backup
```

### Path mapping

`upstream path = base path + (client path − strip prefix)`

| Target | Strip prefix | Client request | Upstream request |
|---|---|---|---|
| `http://h:80` | – | `/page?x=1` | `/page?x=1` |
| `http://h:80/study` | – | `/` | `/study/` |
| `http://h:80/study` | – | `/page?x=1` | `/study/page?x=1` |
| `http://h:80/svc?v=2` | – | `/a?x=1` | `/svc/a?v=2&x=1` |
| `http://h:80/study` | `/api` | `/api/page` | `/study/page` |

Prefixes match on whole path segments (`/api` does not strip from `/apiary`). Encoded paths (`%2F`) are preserved.

With rewriting enabled (default), responses are mapped back the same way:
`Location: http://h:80/study/login` → `/login`, `Set-Cookie: …; Path=/study` → `Path=/`.
Redirects to other origins are left untouched.

---

## Load balancing and health

| Policy | Aliases | Behaviour |
|---|---|---|
| `roundrobin` (default) | `rr`, `round-robin` | Smooth weighted round robin (nginx algorithm), state shared by identical target lists |
| `random` | | Weighted random |
| `failover` | `first`, `priority` | First available target in header order |
| `iphash` | `sticky`, `ip-hash` | Weighted rendezvous hashing on the client IP; a client only moves if its upstream goes down |
| `leastconn` | `least-conn` | Fewest in-flight requests relative to weight |

Order of attempts per request: available primaries (by policy) → available backups → unavailable primaries → unavailable backups.

**Passive health:** after `DETOUR_MAX_FAILS` consecutive failures (transport errors, plus any status in
`DETOUR_FAIL_STATUS`) an upstream is skipped for `DETOUR_FAIL_TIMEOUT`. Health is tracked per origin
(`scheme://host:port`) across all target lists.

**Retries:** on a transport error (connection refused, timeout, TLS error …) requests **without a body** are
retried on the next candidate, up to `DETOUR_RETRIES` extra attempts (default: all candidates).
Requests with a body are never retried because the body cannot be replayed.

The client IP for `iphash` is the TCP peer, or the right-most entry of `DETOUR_CLIENT_IP_HEADER`
(e.g. `X-Forwarded-For` behind a front proxy that appends the real client IP).

---

## Configuration

Everything is configured through environment variables. Durations accept Go syntax (`10s`, `2m`) or plain seconds.
Lists accept commas or whitespace.

### Security

| Variable | Default | Description |
|---|---|---|
| `DETOUR_KEYS` | – | Accepted keys (list). Several keys allow rotation |
| `DETOUR_KEYS_FILE` | – | File with one key per line (`#` comments), e.g. a Docker secret. Combined with `DETOUR_KEYS` |
| `DETOUR_AUTH_DISABLED` | `false` | Accept requests without a key. Only sensible together with `DETOUR_TRUSTED_SOURCES` |
| `DETOUR_TRUSTED_SOURCES` | – (any) | CIDRs/IPs allowed to connect (checked against the TCP peer address) |
| `DETOUR_ALLOWED_TARGETS` | – | Upstream allowlist: CIDRs (`10.0.0.0/8`), exact hosts (`app.lan`), suffix wildcards (`*.lan`) |
| `DETOUR_ALLOW_ANY_TARGET` | `false` | Disable the allowlist entirely (not recommended) |
| `DETOUR_ALLOWED_SCHEMES` | `http,https` | Upstream schemes accepted in targets |
| `DETOUR_MAX_TARGETS` | `16` | Maximum targets per request |
| `DETOUR_ALLOW_INSECURE_TLS` | `false` | Allow `X-Detour-Insecure: true` |
| `DETOUR_TLS_INSECURE_SKIP_VERIFY` | `false` | Skip upstream certificate verification for all requests |
| `DETOUR_CA_FILE` | – | Extra CA bundle (PEM) for verifying upstreams |
| `DETOUR_ALLOW_OVERRIDES` | `true` | Honour the Policy/Host/Strip-Prefix/Rewrite-Redirects headers |

detour refuses to start without keys (or `DETOUR_AUTH_DISABLED=true`) and without an allowlist (or
`DETOUR_ALLOW_ANY_TARGET=true`).

### Routing behaviour

| Variable | Default | Description |
|---|---|---|
| `DETOUR_DEFAULT_TARGET` | – | Target(s) used when no target header is sent (same syntax) |
| `DETOUR_DEFAULT_POLICY` | `roundrobin` | Policy when no policy header is sent |
| `DETOUR_HOST_MODE` | `incoming` | Host header sent upstream: `incoming` or `target` |
| `DETOUR_REWRITE_REDIRECTS` | `true` | Rewrite `Location`/`Content-Location` pointing at the upstream |
| `DETOUR_REWRITE_COOKIE_PATH` | `true` | Rewrite `Set-Cookie` `Path` from the base path |
| `DETOUR_FORWARDED` | `append` | `append`: add peer to `X-Forwarded-For`, keep/set `-Host`/`-Proto`; `preserve`: pass through; `none`: remove |
| `DETOUR_CLIENT_IP_HEADER` | – | Header to take the client IP from for `iphash` (right-most entry) |
| `DETOUR_HEADER_PREFIX` | `X-Detour-` | Prefix for all control headers |
| `DETOUR_EXPOSE_UPSTREAM` | `false` | Add `X-Detour-Upstream: <origin>` to responses (debugging) |

### Upstream connections and health

| Variable | Default | Description |
|---|---|---|
| `DETOUR_MAX_FAILS` | `1` | Failures before an upstream is marked down (`0` disables) |
| `DETOUR_FAIL_TIMEOUT` | `10s` | How long a marked-down upstream is skipped |
| `DETOUR_FAIL_STATUS` | – | Response codes counted as failures, e.g. `502,503,504` (not retried) |
| `DETOUR_RETRIES` | `-1` | Extra attempts for bodyless requests; `-1` = all candidates, `0` = none |
| `DETOUR_DIAL_TIMEOUT` | `5s` | TCP connect timeout |
| `DETOUR_RESPONSE_HEADER_TIMEOUT` | `0` | Max wait for response headers (`0` = none) |
| `DETOUR_IDLE_CONN_TIMEOUT` | `90s` | Keep-alive idle timeout to upstreams |
| `DETOUR_MAX_IDLE_CONNS_PER_HOST` | `32` | Idle connection pool per upstream |
| `DETOUR_FLUSH_INTERVAL` | `0` | Response flush interval (`-1` = flush immediately; SSE is always flushed) |
| `DETOUR_MAX_POOLS` | `1024` | Round-robin states kept (least recently used evicted) |

### Server

| Variable | Default | Description |
|---|---|---|
| `DETOUR_LISTEN` | `:8080` | Proxy listener |
| `DETOUR_TLS_CERT_FILE` / `DETOUR_TLS_KEY_FILE` | – | Serve the proxy listener over TLS |
| `DETOUR_TLS_SELF_SIGNED` | `false` | Serve the proxy listener over TLS with a certificate generated in memory at startup (new key on every start; SHA-256 fingerprint is logged). Cannot be combined with the cert/key files |
| `DETOUR_TLS_SELF_SIGNED_HOSTS` | hostname, `localhost`, local IPs | Names and IPs put into the self-signed certificate |
| `DETOUR_TLS_ALLOW_PLAIN` | `false` | With TLS enabled, also accept plain HTTP **on the same port** (detected per connection from the first byte) |
| `DETOUR_ADMIN_LISTEN` | – (off) | Admin listener with `GET /healthz` and `GET /metrics`, e.g. `127.0.0.1:9090` |
| `DETOUR_READ_HEADER_TIMEOUT` | `10s` | Client request header timeout |
| `DETOUR_IDLE_TIMEOUT` | `120s` | Client keep-alive timeout |
| `DETOUR_SHUTDOWN_TIMEOUT` | `15s` | Graceful shutdown on SIGTERM/SIGINT |
| `DETOUR_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `DETOUR_LOG_FORMAT` | `text` | `text` or `json` |
| `DETOUR_ACCESS_LOG` | `true` | One log line per request (keys are never logged) |

---

## Front proxy examples

**NetBird reverse proxy** – service target `http://<detour-ip>:8080`, path `/`, with *Pass Host Header* enabled and custom headers on the target (API: `targets[].options.custom_headers`):

```json
{ "X-Detour-Target": "http://10.0.0.5:80/study", "X-Detour-Key": "<key>" }
```

NetBird sets custom headers with overwrite semantics, so clients cannot inject their own values.

**Traefik** (dynamic configuration):

```yaml
http:
  middlewares:
    study-detour:
      headers:
        customRequestHeaders:
          X-Detour-Target: "http://10.0.0.5:80/study"
          X-Detour-Key: "<key>"
  routers:
    study:
      rule: Host(`study.example.com`)
      middlewares: [study-detour]
      service: detour
  services:
    detour:
      loadBalancer:
        servers: [{ url: "http://detour:8080" }]
```

**Caddy**:

```caddy
pve.example.com {
	reverse_proxy detour:8080 {
		header_up X-Detour-Target "https://10.0.0.11:8006, https://10.0.0.12:8006, https://10.0.0.13:8006"
		header_up X-Detour-Policy iphash
		header_up X-Detour-Insecure true
		header_up X-Detour-Key {env.DETOUR_KEY}
	}
}
```

**nginx**:

```nginx
location / {
    proxy_set_header X-Detour-Target "http://10.0.0.5:80/study";
    proxy_set_header X-Detour-Key    "<key>";
    proxy_set_header Host            $host;
    proxy_pass http://detour:8080;
}
```

Whatever the front proxy: it must **set (overwrite)** the detour headers rather than append to client-supplied ones,
and detour should only be reachable through it (bind to an internal network, use `DETOUR_TRUSTED_SOURCES`).

---

## Encrypting the hop to detour

By default the front proxy talks plain HTTP to detour. If that hop crosses a network you do not fully
trust, serve detour over TLS:

* **Own certificate:** `DETOUR_TLS_CERT_FILE` + `DETOUR_TLS_KEY_FILE` (e.g. from an internal CA) – the front
  proxy can then verify it properly.
* **Self-signed, zero setup:** `DETOUR_TLS_SELF_SIGNED=true`. Point the front proxy at `https://<detour>:8080`
  and disable certificate verification for that target (NetBird: *Skip TLS verify*; Traefik:
  `serversTransport` with `insecureSkipVerify`; Caddy: `transport http { tls_insecure_skip_verify }`).
  This protects against passive sniffing on the network. Because the front proxy does not verify the
  certificate, it does not protect against an active man-in-the-middle; use your own certificate for that.

To migrate front-proxy routes gradually, set `DETOUR_TLS_ALLOW_PLAIN=true`: the same port then serves
both `https://` and `http://`, so each route can switch independently. Leave it off once everything uses
HTTPS, otherwise the plain path stays available on the network.

The hop from detour to the upstream is encrypted when the target URL uses `https://`.

## Operations

* **Health:** `GET /healthz` on `DETOUR_ADMIN_LISTEN`; the container `HEALTHCHECK` runs `detour healthcheck`
  (uses the admin endpoint if configured, otherwise checks that the proxy port accepts connections).
* **Metrics:** `GET /metrics` – `detour_requests_total{class}`, `detour_rejected_total{reason}`,
  `detour_upstream_errors_total`, `detour_retries_total`, `detour_upstreams_marked_down_total`,
  `detour_inflight_requests`, `detour_upstreams_down`.
* **Status codes:** `403` bad key / untrusted source / target not allowed, `400` malformed headers,
  `502` all upstreams failed, `504` upstream timeout.

## Building

```bash
go test -race ./...
go build -o detour ./cmd/detour
docker build -t detour --build-arg VERSION=$(git describe --tags --always) .
```

Images for `linux/amd64` and `linux/arm64` are published to `ghcr.io/yniverz/detour` (`edge` from `main`, semver tags from releases).

Design notes and the security model: [DESIGN.md](DESIGN.md).

## License

[Non-Commercial Public Use License (NCPUL) v1.3](LICENSE.md)
