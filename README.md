# gwd - API gateway and quota governance backend

`gwd` is a minimal but real API gateway skeleton written with the Python standard
library only. It owns the cross cutting concerns of an internal API platform:
versioned routing, API key authentication, quota governance with a usage ledger,
circuit breaking, bounded retries, request/response header transformation,
idempotent replay protection, per tenant isolation and an audit trail.

It runs offline, on Python 3.10+, on Linux (WSL Ubuntu-24.04) or Windows. There
are no third party dependencies and no network calls except to the upstreams you
configure.

## Running it

```bash
# 1. run the test suite (94 tests, no network, no sleeping)
python3 -m unittest discover -s tests -v

# 2. start the gateway
python3 -m gwd --data-dir ./gwd_data serve --config ./config.json --host 127.0.0.1 --port 8080

# 3. talk to it
python3 -m gwd --data-dir ./gwd_data call --method GET --path /api/items --tenant acme --key <secret>
python3 -m gwd --data-dir ./gwd_data usage --tenant acme
python3 -m gwd --data-dir ./gwd_data audit --tenant acme
```

The global `--data-dir` (default `./gwd_data`) comes **before** the subcommand.
It holds `usage.jsonl` and `audit.jsonl`. `usage` and `audit` read those files
directly, so they work without a running server.

### CLI

| Command | Purpose |
| --- | --- |
| `serve --host --port --config` | run the HTTP server |
| `route-add --file <json>` | append a route object (or array) to the config |
| `key-add --tenant --scope ...` | create a key, print the plaintext secret once |
| `quota-set --file <json>` | append a quota policy (or array) |
| `call --method --path --tenant --key --idempotency-key` | call a running gateway through the proxy surface |
| `usage --tenant [--since]` | aggregate the local `usage.jsonl` ledger |
| `audit --tenant [--limit]` | read the local `audit.jsonl` trail |

Every command prints a single line of JSON on stdout, and on failure prints a
single line of JSON on stderr and exits non-zero.

## Request pipeline

`Gateway.handle(tenant, method, path, headers, body, now_ms)` runs these steps in
this exact order. `now_ms` is injected, so the whole pipeline is deterministic in
tests; only the HTTP front end reads the wall clock.

1. **Route match.** A route is a candidate when its `method` is `*` or equals the
   request method, its `path_prefix` is a prefix of the path, and its `tenant` is
   `*` or equals the request tenant. If nothing matches the tenant, matching is
   retried with the tenant filter relaxed so that a request without a valid key is
   rejected by authentication (401/403) rather than reported as 404.
2. **Weighted pick.** Among candidates the longest `path_prefix` wins. Ties are
   resolved by weighted stable hashing (see below).
3. **Auth.** Missing or unknown secret -> `401`; a stated `X-Api-Key` that does not
   match the presented secret -> `401`; key tenant different from the route tenant,
   or a missing route scope -> `403`. Routes with `"auth_required": false` skip
   this step. Only `sha256(secret)` is ever stored, and it is compared in constant
   time.
4. **Quota.** If the route names a `quota_policy`, one unit is charged against the
   policy's *partition* (see below). A rejected request gets `429` with
   `policy_id` and `reset_at_ms` plus a `Retry-After` header, and the *rejected
   attempt is still written to the ledger*. When the partition identity cannot
   be established the request is denied (`400`/`401`/`403`, see below) without
   consuming quota, writing usage or calling the upstream - but it is still
   audited.
5. **Idempotency.** See below; a replay short circuits the rest of the pipeline.
6. **Circuit breaker + retries.** One breaker per upstream name; an open breaker
   returns `503 {"error":"upstream unavailable","state":"open"}` without calling
   the upstream. Only `408, 429, 500, 502, 503, 504` and transport errors are
   retried, bounded by `RetryPolicy(max_attempts, base_ms, max_ms)`.
7. **Transforms.** `transform.request_headers` are added to the upstream call,
   `transform.response_headers` are added to the reply. Credential headers
   (`Authorization`, `X-Api-Key`) and hop-by-hop headers are stripped before the
   upstream call.
8. **Audit.** One JSON line per request is appended to `<data-dir>/audit.jsonl`
   with `at`, `request_id`, `tenant`, `key_id`, `route_id`, `upstream`, `status`,
   `latency_ms`, `attempts`, `quota{policy_id,allowed,remaining}` and
   `idempotent_replay`.

## Weighted routing (documented rule)

When several candidates share the longest matching prefix, the pick is:

```
selector = "<key_id>|<request_id>"          # key_id is "-" when unauthenticated
pool     = candidates sorted by route id
bucket   = int(sha256(selector).hexdigest()[:16], 16) % sum(weight for route in pool)
# walk the pool in order, accumulating weight; the first route whose
# cumulative weight is greater than bucket wins.
```

The choice depends only on the key id and the request id, never on time or on
process state, so the same caller is sticky to the same backend and a replay of
the same request id always lands on the same route. Weights are relative: routes
with weights 1 and 3 split traffic 25% / 75%.

## Idempotency (documented rule)

A request carrying `X-Idempotency-Key` is scoped by `(tenant, key)`:

* the body is hashed with sha256;
* the same key with the **same** body hash inside the window (default 10 minutes,
  `Gateway(idempotency_window_ms=...)`) replays the stored response, adds
  `X-Idempotent-Replay: true`, marks `idempotent_replay: true` in the audit entry
  and never calls the upstream again;
* the same key with a **different** body hash -> `409`;
* nothing is stored for `5xx`/transport failures, so a failed call can be retried.

## Rate limit algorithms

All three are driven purely by the injected `now_ms` and return
`{"allowed", "remaining", "reset_at_ms", "algorithm", "limit", "policy_id"}`.
`reset_at_ms` is the earliest timestamp at which a request of the same cost would
be admitted again (it equals `now_ms` when the bucket already has room).

| Algorithm | State | Admit rule | Refill / leak |
| --- | --- | --- | --- |
| `token-bucket` | `tokens`, `last_ms` | `tokens >= cost`, then `tokens -= cost` | `tokens = min(capacity, tokens + (now - last) * rate)`, `rate = limit / window_ms` |
| `leaky-bucket` | `level`, `last_ms` | `level + cost <= capacity` (queue free, overflow rejected), then `level += cost` | `level = max(0, level - (now - last) * rate)` |
| `sliding-window` | deque of admitted timestamps | `count(t > now - window_ms) + cost <= limit`, then append `cost` stamps | stamps at or before `now - window_ms` are evicted exactly |

`capacity` is `burst` when set, otherwise `limit`. With `burst` unset, a token
bucket allows an initial burst of `limit` and then sustains `limit` per
`window_ms`; the leaky bucket rejects as soon as the queue would overflow; the
sliding window is the exact count of timestamps in the trailing window.

### Quota partitions (`partition_by`)

Every quota policy carries a `partition_by` mode - `policy` (the default when
the field is omitted), `tenant` or `key`. Each partition gets its own bucket
with its own remaining quota and reset time, computed by the same algorithm
with the same `limit`/`window_ms`/`burst` rules:

| Mode | Partition identity |
| --- | --- |
| `policy` | one bucket shared by every caller of the policy |
| `tenant` | the owning tenant of a valid API key; anonymous callers use the request tenant (empty tenant -> `400`) |
| `key` | `<owning tenant>|<key_id>` of a valid API key; one key shares its bucket across routes |

The identity is resolved at the quota check. In `key` mode a missing key, an
unknown secret or a stated `X-Api-Key` that does not match the secret is a
`401` - even on routes with `"auth_required": false`. In both partitioned
modes a valid key whose tenant contradicts an explicitly stated request tenant
is a `403`. These denials never consume quota, never write usage and never
call the upstream, but they are audited like any other request.

Hot reload keeps the partition state of a policy only while its `id`, `tenant`,
`partition_by` and algorithm parameters are all unchanged; changing any of
them (or deleting and re-adding the policy) restarts every partition of that
policy from the initial state. An invalid reload keeps the last good config
and its quota state. `partition_by` must be one of the three mode strings -
`null`, an empty string, another value or a non-string is rejected with
`GatewayError` on load, `400` over HTTP and the standard CLI error format, in
every case without changing the live config or quotas. Concurrent requests on
the same partition are serialised so they can never overspend.

`QuotaLedger` appends one JSON object per line to `<data-dir>/usage.jsonl`
(`at`, `tenant`, `policy_id`, `key_id`, `cost`, `allowed`) with a single `write`
call per entry, so a crash can only leave a torn trailing line, which readers
skip. `usage(tenant, since_ms)` aggregates requests, allowed, rejected and cost,
overall and per policy.

## Configuration

```json
{
  "routes": [{
    "id": "r-api", "tenant": "acme",
    "match": {"method": "GET", "path_prefix": "/api"},
    "upstream": "echo",
    "auth_required": true, "weight": 1, "scopes": ["read"],
    "transform": {"request_headers": {"X-Tenant": "acme"},
                  "response_headers": {"X-Served-By": "gwd"}},
    "quota_policy": "p-api", "timeout_ms": 5000
  }],
  "keys": [{"key_id": "k-1", "tenant": "acme",
            "secret_sha256": "<64 lowercase hex>", "scopes": ["read"]}],
  "quota_policies": [{"id": "p-api", "tenant": "acme", "algorithm": "token-bucket",
                      "limit": 10, "window_ms": 1000, "burst": 20,
                      "partition_by": "tenant"}]
}
```

`scopes` defaults to `[]` (no scope required); a key holding the `*` scope
satisfies any requirement. `tenant: "*"` marks a route shared by every tenant.
`load()` rejects malformed documents with `GatewayError` (unknown algorithm,
non-positive `limit`/`window_ms`/`burst`/`weight`, `path_prefix` without a leading
`/`, malformed `secret_sha256`, duplicate ids, a route naming an unknown quota
policy). `reload_if_changed()` re-reads the file only when its mtime moved and
keeps `ready` true only when the new document is valid; an invalid reload keeps
the last known good config, sets `ready = false` and records `last_error`.

## HTTP API

Errors are always JSON: `{"error": "...", "request_id": "..."}`. Admin endpoints
are unauthenticated in this skeleton - front them with your own auth in production.

| Method | Path | Success | Errors |
| --- | --- | --- | --- |
| GET | `/healthz` | `200 {"ok","ready","revision","routes","upstreams","config_error"}` | - |
| GET | `/v1/config` | `200` sanitized config (never any secret or hash) | - |
| POST | `/v1/config/reload` | `200 {"reloaded","revision","ready","error"}` | - |
| POST | `/v1/keys` | `201 {"key_id","tenant","scopes","secret_sha256","secret"}` (secret returned once) | `400` bad JSON / missing tenant, `409` duplicate key id |
| POST | `/v1/quota/policies` | `201` policy object | `400` invalid policy, `409` duplicate id |
| GET | `/v1/quota/usage?tenant=&since=` | `200` ledger aggregate | `400` non-integer `since` |
| GET | `/v1/audit?tenant=&limit=` | `200 {"tenant","count","entries"}` | `400` non-integer `limit` |
| POST | `/v1/breaker/reset` | `200 {"reset":["upstream",...]}` | `400` bad JSON |
| * | any other path | proxied through the pipeline | `401` missing/unknown key, `403` scope or tenant, `404` no route, `409` idempotency conflict, `429` quota exceeded, `502` upstream error, `503` breaker open |

A `/gw/{path}` prefix on the proxy surface is stripped before matching upstreams,
so `/gw/api/items` is matched as `/api/items`.

## Upstreams

`gwd.upstream.UpstreamRegistry` maps a name to a handler. `register(name, fn)`
takes any callable returning `{"status", "body", "headers"}` or `(status, body)`;
`HttpUpstream` calls a real HTTP backend with `urllib`. The bundled `echo`
upstream replies with `{"method", "path", "headers", "body_sha256"}` and is what
the tests assert against.

## Layout

```
gwd/__init__.py    public surface: Gateway, QuotaLedger, create_server
gwd/config.py      models, validation, mtime hot reload
gwd/limits.py      token/leaky/sliding limiters, quota ledger, audit log
gwd/breaker.py     circuit breaker state machine, retry policy
gwd/gateway.py     the request pipeline
gwd/upstream.py    upstream registry, stdlib HTTP client, echo upstream
gwd/http_app.py    ThreadingHTTPServer, admin surface, proxy surface
gwd/cli.py         serve, route-add, key-add, quota-set, call, usage, audit
tests/             unittest suites for limits, breaker, gateway and HTTP
```
