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
# 1. run the test suite (99 tests, no network, no sleeping)
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
4. **Quota.** If the route names a `quota_policy`, one unit is charged against
   the partition resolved for that policy (see below). A rejected request gets
   `429` with `policy_id` and `reset_at_ms` plus a `Retry-After` header, and the
   *rejected attempt is still written to the ledger*. Identity rejections raised
   while resolving a partition (`400`/`401`/`403`) consume no quota, write no
   usage and never call the upstream, but are still audited.
5. **Idempotency.** See below; a replay short circuits the rest of the pipeline.
6. **Circuit breaker + retries + fallback.** One breaker per upstream name; an
   open breaker returns `503 {"error":"upstream unavailable","state":"open"}`
   without calling the upstream. Only `408, 429, 500, 502, 503, 504` and
   transport errors are retried, bounded by `RetryPolicy(max_attempts, base_ms,
   max_ms)`. When the route names `fallback_upstreams`, an eligible request
   (see below) that exhausts its retries on a transport error or a `5xx` fails
   over to the next upstream in order; any other status is returned
   immediately. See [Fallback upstreams](#fallback-upstreams).
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

## Fallback upstreams (documented rule)

A route may name `fallback_upstreams`, an ordered array of backup upstream
names tried after the primary. Omitting the field means `[]` (no failover, the
historical behaviour). Every element must be a non-empty upstream name string;
duplicates and the primary upstream itself are rejected, and so are `null`,
non-arrays and non-string elements — all with a `GatewayError` (`400` style
single-line JSON on the CLI, non-zero exit, configuration unchanged).

Failover is only offered to **GET requests** and requests carrying a
**non-empty `X-Idempotency-Key`**; every other request calls the primary
upstream only. For an eligible request the candidates are the primary followed
by the fallbacks in order:

* each candidate keeps its own circuit breaker and its own retry budget — a
  breaker-rejected candidate is skipped without a call;
* a candidate is called with the usual retry policy; when its retries end on a
  **transport error or a `5xx`** the next candidate is tried, and any other
  status (`2xx`/`3xx`/`4xx`, including a retried `408`/`429`) is returned
  immediately;
* an unregistered upstream name behaves as a transport error;
* every call keeps the original method, path, body, header transforms and
  credential stripping, and the weighted route pick is unaffected.

When the chain is exhausted the result of the last upstream actually called is
returned (a transport failure is the usual `502`, an HTTP response keeps its
status, body and response-header handling). When every candidate was skipped
by its breaker the response is the usual `503`, with `state` taken from the
primary upstream's rejection. The whole request is still billed and audited
exactly once: `attempts` sums the actual calls across all upstreams and
`upstream` names the last upstream actually called (the primary when none
was). The idempotency cache stores only the final non-`5xx` response, so a
replay never re-runs the failover and a final `5xx` or transport failure is
never cached. A valid hot reload applies the new order to new requests only
(in-flight requests keep the order they started with) and never resets quota
buckets or breaker state; an invalid reload keeps the last good configuration,
buckets, breakers and health feedback.

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

`QuotaLedger` appends one JSON object per line to `<data-dir>/usage.jsonl`
(`at`, `tenant`, `policy_id`, `key_id`, `cost`, `allowed`) with a single `write`
call per entry, so a crash can only leave a torn trailing line, which readers
skip. `usage(tenant, since_ms)` aggregates requests, allowed, rejected and cost,
overall and per policy.

## Quota partitions

A quota policy accepts `partition_by`, which must be one of `"policy"`,
`"tenant"` or `"key"`. Omitting the field (or loading a document written before
the field existed) keeps the historical `"policy"` mode: every route using the
policy shares one bucket. `null`, the empty string, any other value or a
non-string value fail validation with a `GatewayError` (`400` on
`POST /v1/quota/policies`; the CLI exits with its usual single-line JSON error),
and a rejected creation changes neither the configuration nor any quota state.

| `partition_by` | One bucket per | Identity used |
| --- | --- | --- |
| `policy` (default) | the policy id | none |
| `tenant` | policy id + tenant | the effective key's tenant; for an anonymous request the request tenant resolved by the existing rules (`?tenant=` / `X-Tenant`) |
| `key` | policy id + the key's tenant and `key_id` | the presented API key; the same key shares its quota across every route |

All three algorithms support partitions; each partition computes its remaining
quota and recovery time independently with the same time and burst rules. The
partition key is resolved at the original quota check point:

* **tenant mode:** an empty request tenant (no key and no request tenant) is
  `400`.
* **key mode:** a missing/unknown secret or a claimed `X-Api-Key` that does not
  match the presented secret is `401`, even when the matched route allows
  anonymous access (`auth_required: false`).
* **both modes:** when a valid key is presented together with an explicit
  request tenant that differs from the key's tenant, the request is `403`.

These responses keep the usual JSON body (`error`, `request_id`), write one
audit entry, but do not consume quota, do not write a usage record and do not
call the upstream. `Gateway.handle` and the HTTP proxy run identical partition
rules.

Each quota check is still a one-unit allow-then-consume guarded by a single
lock, so concurrent requests in the same partition can never exceed the limit.
An idempotent replay checks quota before replaying, and upstream retries are not
billed twice. `429` and `Retry-After` keep their meaning, and the usage and
audit summaries keep their existing shape.

A valid hot reload preserves a policy's partition buckets while its `id`,
`tenant`, `partition_by` and algorithm parameters (`algorithm`, `limit`,
`window_ms`, `burst`) are all unchanged. Changing any of them restarts only that
policy's partitions from their initial state; removing the policy and adding it
back also starts fresh. An invalid reload keeps the previous configuration,
health state, error feedback and every bucket.

## Configuration

```json
{
  "routes": [{
    "id": "r-api", "tenant": "acme",
    "match": {"method": "GET", "path_prefix": "/api"},
    "upstream": "echo",
    "fallback_upstreams": ["echo-dr"],
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
`fallback_upstreams` defaults to `[]` and lists backup upstreams in failover
order (see [Fallback upstreams](#fallback-upstreams)).
`partition_by` defaults to `"policy"` and accepts only `"policy"`, `"tenant"`
and `"key"` (see [Quota partitions](#quota-partitions)). `load()` rejects
malformed documents with `GatewayError` (unknown algorithm, an invalid
`partition_by`, non-positive `limit`/`window_ms`/`burst`/`weight`,
`path_prefix` without a leading `/`, malformed `secret_sha256`, duplicate ids, a
route naming an unknown quota policy, an invalid `fallback_upstreams`). `reload_if_changed()` re-reads the file
only when its mtime moved and keeps `ready` true only when the new document is
valid; an invalid reload keeps the last known good config, sets `ready = false`
and records `last_error`.

## HTTP API

Errors are always JSON: `{"error": "...", "request_id": "..."}`. Admin endpoints
are unauthenticated in this skeleton - front them with your own auth in production.

| Method | Path | Success | Errors |
| --- | --- | --- | --- |
| GET | `/healthz` | `200 {"ok","ready","revision","routes","upstreams","config_error"}` | - |
| GET | `/v1/config` | `200` sanitized config (never any secret or hash) | - |
| POST | `/v1/config/reload` | `200 {"reloaded","revision","ready","error"}` | - |
| POST | `/v1/keys` | `201 {"key_id","tenant","scopes","secret_sha256","secret"}` (secret returned once) | `400` bad JSON / missing tenant, `409` duplicate key id |
| POST | `/v1/quota/policies` | `201` policy object (echoes `partition_by`) | `400` invalid policy / `partition_by`, `409` duplicate id |
| GET | `/v1/quota/usage?tenant=&since=` | `200` ledger aggregate | `400` non-integer `since` |
| GET | `/v1/audit?tenant=&limit=` | `200 {"tenant","count","entries"}` | `400` non-integer `limit` |
| POST | `/v1/breaker/reset` | `200 {"reset":["upstream",...]}` | `400` bad JSON |
| * | any other path | proxied through the pipeline | `400` empty tenant (tenant partition), `401` missing/unknown key or key partition without a valid key, `403` scope or tenant, `404` no route, `409` idempotency conflict, `429` quota exceeded, `502` upstream error, `503` breaker open |

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
