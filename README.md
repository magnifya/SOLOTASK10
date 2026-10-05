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
# 1. run the test suite (160 tests, no network, no sleeping)
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
   match the presented secret -> `401`; a disabled or expired key -> `401`
   (`api key disabled` / `api key expired`, see
   [Key disabling and expiry](#key-disabling-and-expiry)); key tenant different
   from the route tenant, or a missing route scope -> `403`. Routes with
   `"auth_required": false` skip this step. Only `sha256(secret)` is ever stored,
   and it is compared in constant time.
4. **Quota.** A route names one policy (`quota_policy`, the historical form) or
   an ordered, non-empty list (`quota_policies`, joint admission). Each named
   policy charges one unit against the partition resolved for that policy (see
   below). For a joint check, partition identities are verified in declaration
   order and the first failure decides the response; the buckets themselves are
   admitted as a group — either every policy pays one unit or none does. A
   rejected request gets `429` with `policy_id` (the first policy in declaration
   order that was short), `reset_at_ms` (the latest recovery time among the
   short policies) and a `Retry-After` header, and the *rejected attempt is
   still written to the ledger* (one entry per named policy). Identity
   rejections raised while resolving a partition (`400`/`401`/`403`) consume no
   quota, write no usage and never call the upstream, but are still audited.
5. **Idempotency.** See below; a replay short circuits the rest of the
   pipeline. With no usable cache, the request claims the in-progress guard
   for its `(tenant, key)` scope: a same-body concurrent request gets `425`
   (`Retry-After: 1`) and a different-body one gets `409`, both without an
   upstream call, while the claim runs the chain alone and releases or
   publishes only when the chain ends.
6. **Circuit breaker + retries + failover.** One breaker per upstream name; an
   open breaker returns `503 {"error":"upstream unavailable","state":"open"}`
   without calling the upstream. Only `408, 429, 500, 502, 503, 504` and
   transport errors are retried, bounded by `RetryPolicy(max_attempts, base_ms,
   max_ms)`. When the route names `fallback_upstreams`, a GET request (or any
   request carrying a non-empty `X-Idempotency-Key`) walks the primary plus the
   fallbacks in order: each upstream keeps its own retry budget and breaker, a
   breaker rejection skips it silently, and only a transport error or a 5xx
   left after the retries moves to the next upstream (see
   [Fallback upstreams](#fallback-upstreams)).
7. **Transforms.** `transform.request_headers` are added to the upstream call,
   `transform.response_headers` are added to the reply. Credential headers
   (`Authorization`, `X-Api-Key`) and hop-by-hop headers are stripped before the
   upstream call.
8. **Audit.** One JSON line per request is appended to `<data-dir>/audit.jsonl`
   with `at`, `request_id`, `tenant`, `key_id`, `route_id`, `upstream`, `status`,
   `latency_ms`, `attempts`, `quota{policy_id,allowed,remaining}` and
   `idempotent_replay`. A `quota_policies` route additionally carries `quotas`,
   an ordered list of `{policy_id, allowed, remaining}` in declaration order; the
   legacy `quota` block equals its first entry. `quotas` is `[]` (and `quota`
   keeps its unchecked value) when such a request never reached the joint check.

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

A request carrying a non-empty `X-Idempotency-Key` is scoped by the
`(tenant, key)` pair (kept as a tuple, so a tenant or key value containing the
display separator `|` cannot alias another scope):

* the body is hashed with sha256;
* the same key with the **same** body hash inside the window (default 10 minutes,
  `Gateway(idempotency_window_ms=...)`) replays the stored response, adds
  `X-Idempotent-Replay: true`, marks `idempotent_replay: true` in the audit entry
  and never calls the upstream again;
* the same key with a **different** body hash -> `409`;
* nothing is stored for `5xx`/transport failures, so a failed call can be retried.

### In-progress concurrency guard

After routing, authentication and quota have passed, a request that finds no
usable cached response also joins the in-progress guard for its
`(tenant, key)` scope. Only one request per scope runs the upstream chain at a
time; the request that wins keeps its normal retry budget and fallback
failover. While it has not finished:

* a concurrent request with the **same** body hash is rejected immediately with
  `425 {"error":"idempotency request in progress","request_id": ...}` (its own
  request id) and `Retry-After: 1`;
* a concurrent request with a **different** body hash gets the existing `409`
  idempotency conflict;
* neither rejection calls an upstream and neither carries `X-Idempotent-Replay`.

The guard lasts until the whole upstream chain ends; it is not bounded by the
replay window, so a follower whose `now_ms` is already beyond the first
request's cache window is still refused rather than forwarded. When the final
upstream status is below 500, the response is published and the in-progress
state cleared in one atomic step (no window in which a duplicate could run);
within the window same-body requests then replay the stored status and body
with `X-Idempotent-Replay: true`, and different-body requests keep getting
`409`. A final `5xx`, a transport failure, or every upstream being refused by
its breaker returns the usual result to the first request, releases the guard
and caches nothing, so later requests execute again. The `425`/`409` answers
used to refuse concurrent requests are themselves never cached.

Different tenants or different full keys are independent scopes and proceed
concurrently. The state is per `Gateway` instance only. Requests without an
idempotency key (or with an empty one), the admin surface and the CLI keep
their existing behaviour.

Quota still runs before idempotency: every request that passes quota is
charged and recorded on its own (a joint admission is still all-or-nothing),
including requests later refused with `425`/`409`; retries and failover are
never billed twice. Authentication and quota rejections never occupy a scope.
Each request appends exactly one audit entry; an in-progress rejection has
`attempts: 0`, `idempotent_replay: false`, and its `quota`/`quotas` blocks
reflect that request's own check. A valid hot reload and response-cache
pruning preserve both unexpired responses and active in-progress guards.

## Fallback upstreams

A route may name `fallback_upstreams`, an ordered array of upstream names tried
after the primary. Omitting the field (or loading a document written before it
existed) means `[]`, which keeps the historical single-upstream behaviour. The
field is validated like every other config field: `null`, a non-array, an entry
that is not a non-empty string, a duplicate entry or an entry repeating the
primary upstream all fail with a `GatewayError` (the CLI prints its usual
single-line JSON error and exits non-zero; a rejected `route-add` changes
neither the configuration nor any runtime state). The sanitized config returned
by `GET /v1/config` echoes the field for every route.

Failover is **only** engaged for `GET` requests and requests carrying a
non-empty `X-Idempotency-Key`; every other request calls the primary upstream
alone. When engaged, the request walks `[primary] + fallback_upstreams` in
order after the route has been picked by the usual weighted rule:

* each upstream independently obeys the retry budget and its own circuit
  breaker — a breaker rejection skips that upstream without calling it;
* an upstream is called with the usual retry policy; only a transport error
  (an unregistered upstream counts as one) or a `5xx` status left after the
  retries moves on to the next upstream — any other status, including a
  retried `408`/`429`, is returned immediately;
* every call keeps the original method, path, body, request header transform
  and credential stripping;
* when the chain is exhausted, the result of the last upstream actually called
  is returned: a transport failure is the usual `502`, an HTTP response keeps
  its status, body and response headers;
* when every upstream was skipped by its breaker, the response is the usual
  `503` with `state` taken from the primary upstream's rejection.

The whole request is still charged and recorded **once** at the original quota
check point — retries and failovers are never billed twice, and auth failures,
quota rejections and idempotency conflicts/replays/in-progress refusals never
reach an upstream.
The idempotency cache stores only the final non-`5xx` response; a replay
short-circuits the pipeline before any failover runs, and a final `5xx` or
transport failure is never cached. The audit entry stays one line per request:
`attempts` sums the actual calls across every upstream and `upstream` is the
last upstream actually called (the primary when none was called).

A valid hot reload applies the new fallback order to new requests only —
in-flight requests keep the order they started with — and editing
`fallback_upstreams` resets neither quota buckets nor breaker state. An
invalid reload keeps the last valid configuration, the quota buckets, the
breaker states and the existing health feedback.

## Key disabling and expiry

Every key carries two optional validity fields:

* `enabled` — defaults to `true` and accepts only a JSON boolean (`null`
  included is rejected);
* `expires_at_ms` — omitted or `null` means the key never expires; anything
  else must be a positive integer millisecond timestamp (booleans are not
  integers here).

Both fields are validated like every other config field: a bad value fails
`load()` and `POST /v1/keys` with a `GatewayError` (`400`), changing neither
the configuration, the revision nor any runtime state. `GET /v1/config` echoes
both fields for every key (still never the secret or its hash), and
`POST /v1/keys` echoes them on success; `Gateway.add_key` accepts them as
optional keyword arguments, so existing callers create enabled, non-expiring
keys — as does the `key-add` CLI.

Credential resolution is unchanged — the secret's sha256 is matched and a
stated `X-Api-Key` is checked against it — and only then is validity checked
against the request's `now_ms` (the request start time on the HTTP proxy; a
key whose `expires_at_ms` equals `now_ms` is already expired). A key that is
both disabled and expired reports disabled. An invalid key resolves exactly
like an invalid secret: authenticated routes and key-partition quota checks
reject it with `401` (`api key disabled` / `api key expired`, keeping
`request_id`), while other anonymous routes treat it as no key at all — its
tenant and `key_id` are never derived from it, so the usual anonymous access
and tenant-partition rules apply (an empty tenant on a tenant partition is
still `400`). The rejection calls no upstream, consumes no quota and writes no
usage; it appends one audit entry with `attempts: 0` and
`idempotent_replay: false`. A stored idempotent response never lets an invalid
key bypass authentication, and once the key is valid again quota is still
checked before the replay.

Toggling `enabled` or moving `expires_at_ms` through the usual hot reload
applies to later requests only — in-flight requests keep their retry and
failover behaviour — and resets neither quota buckets, breaker state nor the
idempotency cache: a re-enabled key finds its quota bucket exactly as it was.
An invalid reload keeps the last valid configuration with the usual `ready` /
`last_error` feedback. Documents written before these fields existed load as
enabled and non-expiring.

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
skip. A joint admission writes one record per named policy for a single request:
every record has `cost: 1` and carries the whole group's verdict in `allowed`
(all `true` on admission, all `false` otherwise). `usage(tenant, since_ms)`
aggregates requests, allowed, rejected and cost, overall and per policy, so
`requests` counts records (one per policy per request) while `allowed_cost`
counts only the records of admitted groups.

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

Each single-policy quota check is a one-unit allow-then-consume guarded by a
single lock, so concurrent requests in the same partition can never exceed the
limit. An idempotent replay checks quota before replaying, and upstream retries
are not billed twice. `429` and `Retry-After` keep their meaning, and the usage
and audit summaries keep their existing shape.

A valid hot reload preserves a policy's partition buckets while its `id`,
`tenant`, `partition_by` and algorithm parameters (`algorithm`, `limit`,
`window_ms`, `burst`) are all unchanged. Changing any of them restarts only that
policy's partitions from their initial state; removing the policy and adding it
back also starts fresh. An invalid reload keeps the previous configuration,
health state, error feedback and every bucket.

## Joint quota admission

A route normally names one policy with `quota_policy`. It may instead name
`quota_policies`: an **ordered, non-empty** array of policy ids, letting one
request be jointly constrained by several budgets at once (for example the
tenant total and the per-key budget). Omitting `quota_policies` leaves the
historical `quota_policy` semantics untouched. The field is validated like
every other config field — `null`, an empty array, a non-array, a non-string or
empty-string entry, a duplicate id, an unknown policy, or setting it together
with a non-empty `quota_policy` all fail with a `GatewayError`. Config loading,
`route-add` and hot reload run the same validation; a rejected batch add writes
none of its routes and leaves the revision unchanged. `GET /v1/config` echoes
`quota_policies` only on routes that set it, so older route documents keep their
exact output.

`Gateway.handle` and the HTTP proxy run identical rules. After the existing
authentication step, the partition identity of every named policy is checked in
declaration order and the first failure decides the response: a tenant
partition without a tenant is `400`, a key partition without a valid key is
`401`, and a valid key presented alongside an explicit request tenant that does
not match the key's tenant is `403`. These responses consume no quota, write no
usage and call no upstream.

Once identities are resolved, the named buckets are admitted as a group under
one lock: every bucket is probed without mutating state, and the request
proceeds only when **all** policies have room, in which case each pays one unit.
If any policy is short, none pays — a concurrent group in the same partitions
can neither partially charge nor exceed a limit, and all three algorithms and
partition modes compose. On rejection the response is `429` with `policy_id`
set to the first short policy in declaration order, `reset_at_ms` the latest
recovery time across all short policies, and the usual `Retry-After`
conversion.

One joint check writes one usage record per named policy in the existing format,
each with `cost: 1`; every record's `allowed` is the whole group's verdict, so
`requests` counts records while `allowed_cost` counts only admitted groups.
Audit stays one line per request: a joint route adds `quotas` (ordered
`{policy_id, allowed, remaining}`, with `quota` equal to its first item); on
rejection `remaining` is the un deducted available balance, and when the request
never reached the joint check `quotas` is `[]` and `quota` keeps its unchecked
value. Idempotent replays, conflicts and in-progress `425` refusals still check
quota first, and retries, failover and the breaker never charge extra. A valid hot reload that only
changes a route's policy combination keeps quota buckets, breaker state and the
idempotency cache; in-flight requests keep the combination they started with,
and an invalid reload keeps the previous configuration, state and health
feedback through the usual `ready` / `last_error` channel.

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
    "quota_policy": "p-api", "timeout_ms": 5000,
    "fallback_upstreams": ["echo-dr"]
  }, {
    "id": "r-both", "tenant": "acme",
    "match": {"method": "GET", "path_prefix": "/both"},
    "upstream": "echo", "auth_required": true,
    "quota_policies": ["p-tenant-total", "p-key-budget"]
  }],
  "keys": [{"key_id": "k-1", "tenant": "acme",
            "secret_sha256": "<64 lowercase hex>", "scopes": ["read"],
            "enabled": true, "expires_at_ms": null}],
  "quota_policies": [{"id": "p-api", "tenant": "acme", "algorithm": "token-bucket",
                      "limit": 10, "window_ms": 1000, "burst": 20,
                      "partition_by": "tenant"},
                     {"id": "p-tenant-total", "tenant": "acme", "algorithm": "token-bucket",
                      "limit": 100, "window_ms": 1000, "partition_by": "tenant"},
                     {"id": "p-key-budget", "tenant": "acme", "algorithm": "sliding-window",
                      "limit": 5, "window_ms": 1000, "partition_by": "key"}]
}
```

`scopes` defaults to `[]` (no scope required); a key holding the `*` scope
satisfies any requirement. `tenant: "*"` marks a route shared by every tenant.
`enabled` defaults to `true` and `expires_at_ms` to `null` (see
[Key disabling and expiry](#key-disabling-and-expiry)).
`partition_by` defaults to `"policy"` and accepts only `"policy"`, `"tenant"`
and `"key"` (see [Quota partitions](#quota-partitions)). `fallback_upstreams`
defaults to `[]` and lists the ordered failover upstreams (see
[Fallback upstreams](#fallback-upstreams)). `load()` rejects
malformed documents with `GatewayError` (unknown algorithm, an invalid
`partition_by`, an invalid `fallback_upstreams`, a non-boolean `enabled`, an
invalid `expires_at_ms`, non-positive
`limit`/`window_ms`/`burst`/`weight`,
`path_prefix` without a leading `/`, malformed `secret_sha256`, duplicate ids, a
route naming an unknown quota policy, or a malformed `quota_policies` — `null`,
empty, non-array, non-string/empty entries, duplicates or both `quota_policy`
and `quota_policies` set). `reload_if_changed()` re-reads the file
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
| POST | `/v1/keys` | `201 {"key_id","tenant","scopes","secret_sha256","enabled","expires_at_ms","secret"}` (secret returned once) | `400` bad JSON / missing tenant / invalid `enabled` or `expires_at_ms`, `409` duplicate key id |
| POST | `/v1/quota/policies` | `201` policy object (echoes `partition_by`) | `400` invalid policy / `partition_by`, `409` duplicate id |
| GET | `/v1/quota/usage?tenant=&since=` | `200` ledger aggregate | `400` non-integer `since` |
| GET | `/v1/audit?tenant=&limit=` | `200 {"tenant","count","entries"}` | `400` non-integer `limit` |
| POST | `/v1/breaker/reset` | `200 {"reset":["upstream",...]}` | `400` bad JSON |
| * | any other path | proxied through the pipeline | `400` empty tenant (tenant partition), `401` missing/unknown/disabled/expired key or key partition without a valid key, `403` scope or tenant, `404` no route, `409` idempotency conflict, `425` idempotency request in progress, `429` quota exceeded, `502` upstream error, `503` breaker open |

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
