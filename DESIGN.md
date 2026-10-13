# detour – design notes

## Goal

Give front proxies that only route by hostname/path (and often cannot do load balancing, backend
base paths or response rewriting) a stateless companion that does exactly that, **without a second
place to configure routes**. The front proxy stays the single source of truth; per-route behaviour
travels with the request in headers that only the front proxy may set.

## Request lifecycle

1. **Source check** – if `DETOUR_TRUSTED_SOURCES` is set, the TCP peer must be inside it.
2. **Authentication** – `X-Detour-Key` must equal one of the configured keys (SHA-256 + constant-time
   comparison, so neither key length nor content leaks through timing).
3. **Target parsing** – `X-Detour-Target` (or `DETOUR_DEFAULT_TARGET`) is parsed; schemes, ports,
   weights and the maximum number of targets are validated. Userinfo and fragments are rejected.
4. **Allowlist (request time)** – IP literals must be inside an allowed prefix; hostnames must match a
   host pattern, or (if prefixes exist) are deferred to the dial-time check.
5. **Ordering** – the balancer orders all candidates (see README). Health state is per origin.
6. **Rewrite** – all `X-Detour-*` headers are dropped, Host and `X-Forwarded-*` are set.
7. **Transport** – the retry transport tries candidates in order. Each dial goes through the
   allowlisting dialer.
8. **Response** – `Location`, `Content-Location` and `Set-Cookie` paths are mapped back; failures and
   successes update passive health.

## Security model

detour is effectively a programmable proxy. Anyone who can make it accept a target header can make
it connect to that target (SSRF). The layers that prevent this:

| Layer | Protects against |
|---|---|
| Shared key (required by default) | Requests that bypass the front proxy, e.g. from the local network |
| Trusted sources (optional) | Same, at the network level |
| Front proxy overwrites headers | Clients injecting their own `X-Detour-*` values through the front proxy |
| Target allowlist, request time | Obvious misuse and configuration mistakes |
| Target allowlist, **dial time** | DNS answers pointing a permitted-looking hostname at forbidden addresses (incl. DNS rebinding). The IP actually connected to is checked; hostnames matching a host pattern are trusted by name |
| Header stripping | Leaking the key or control headers to upstreams |
| Insecure TLS gated by config | A route silently disabling certificate verification |
| `Proxy: nil` on the transport | `HTTP(S)_PROXY` environment variables redirecting upstream traffic |

Not in scope: rate limiting, authentication of end users (that is the front proxy's job), WAF.

Why a source check alone is not enough: in many setups the front proxy and other trusted clients reach
detour through the same NAT or routing hop and therefore share a source address. The key is what
binds a request to the front proxy's configuration.

## Path semantics

`upstream = base + (client − strip)`, joined with exactly one slash, encoded paths preserved
(same joining rules as `net/http/httputil`). The reverse mapping for redirects and cookies is
`client = strip + (upstream − base)`; paths outside the base are left alone, except that absolute
URLs pointing at the upstream origin are always made host-relative so internal hostnames never
reach clients.

## Load balancing details

* Smooth weighted round robin keeps per-target counters per *target list* (canonical string), so two
  services with different lists do not influence each other. States are LRU-evicted
  (`DETOUR_MAX_POOLS`).
* IP hash uses weighted rendezvous (highest random weight) hashing: removing or marking down one
  upstream only moves the clients that were on it.
* Least connections counts in-flight requests per origin, including long-lived WebSocket
  connections (released when the upstream body is closed).
* Backups and unavailable upstreams are appended to the candidate list, so a request still has a
  chance when everything is marked down (like nginx).

## Retries

Only transport errors trigger a retry and only for requests without a body: once a body has been
streamed to a failed upstream it is gone. Status-code based failures (`DETOUR_FAIL_STATUS`) affect
health but are returned to the client as-is, because the upstream may already have acted on the
request.

## Non-goals

* Configuration files, an API or a UI – the front proxy is the configuration.
* Active health checks – they would need per-upstream configuration, which contradicts the design.
  Passive checks plus retries cover the common "one node is down" case.
* TCP/UDP proxying.
