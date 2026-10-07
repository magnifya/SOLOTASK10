"""Admin surface authentication: the root-level ``admin_auth`` policy.

Covers config validation (load, write-time parse, hot reload all use one fixed
error message), the /v1 read/write auth wall, scope and tenant rules, and the
hot-reload semantics (replace vs retain).
"""

import hashlib
import json
import os
import shutil
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

from gwd.config import (ADMIN_AUTH_ERROR, GatewayError, parse)
from gwd.gateway import Gateway
from gwd.http_app import create_server

SECRET_ROOT = "root-secret"
SECRET_ACME_ADMIN = "acme-admin-secret"
SECRET_ACME_READ = "acme-read-secret"
SECRET_GLOB_ADMIN = "glob-admin-secret"
SECRET_STAR = "star-secret"
SECRET_OPS_AUDIT = "ops-audit-secret"
SECRET_OPS = "ops-secret"
SECRET_PROVISION = "provision-secret"
SECRET_DISABLED = "disabled-secret"
SECRET_EXPIRED = "expired-secret"


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def config_document(admin_auth=None):
    doc = {
        "quota_policies": [{"id": "p-http", "tenant": "acme", "algorithm": "sliding-window",
                            "limit": 100, "window_ms": 60000}],
        "keys": [
            {"key_id": "k-root", "tenant": "*", "secret_sha256": sha(SECRET_ROOT),
             "scopes": ["admin"]},
            {"key_id": "k-acme-admin", "tenant": "acme", "secret_sha256": sha(SECRET_ACME_ADMIN),
             "scopes": ["admin"]},
            {"key_id": "k-acme-read", "tenant": "acme", "secret_sha256": sha(SECRET_ACME_READ),
             "scopes": ["read"]},
            {"key_id": "k-glob-admin", "tenant": "globex", "secret_sha256": sha(SECRET_GLOB_ADMIN),
             "scopes": ["admin"]},
            {"key_id": "k-star", "tenant": "acme", "secret_sha256": sha(SECRET_STAR),
             "scopes": ["*"]},
            {"key_id": "k-ops-audit", "tenant": "acme", "secret_sha256": sha(SECRET_OPS_AUDIT),
             "scopes": ["ops", "audit"]},
            {"key_id": "k-ops", "tenant": "acme", "secret_sha256": sha(SECRET_OPS),
             "scopes": ["ops"]},
            {"key_id": "k-provision", "tenant": "acme", "secret_sha256": sha(SECRET_PROVISION),
             "scopes": ["provision"]},
            {"key_id": "k-disabled", "tenant": "acme", "secret_sha256": sha(SECRET_DISABLED),
             "scopes": ["admin"], "enabled": False},
            {"key_id": "k-expired", "tenant": "acme", "secret_sha256": sha(SECRET_EXPIRED),
             "scopes": ["admin"], "expires_at_ms": int(time.time() * 1000) - 10_000},
        ],
        "routes": [
            {"id": "r-api", "tenant": "acme", "match": {"method": "GET", "path_prefix": "/api"},
             "upstream": "echo", "quota_policy": "p-http", "scopes": ["read"]},
            {"id": "r-post", "tenant": "acme", "match": {"method": "POST", "path_prefix": "/api"},
             "upstream": "echo", "auth_required": False}],
    }
    if admin_auth is not None:
        doc["admin_auth"] = admin_auth
    return doc


class AdminAuthValidationTest(unittest.TestCase):
    def valid_doc(self, admin_auth):
        doc = config_document()
        if admin_auth is not None:
            doc["admin_auth"] = admin_auth
        return doc

    def test_defaults(self):
        config = parse(self.valid_doc({"enabled": True}))
        self.assertEqual(config.admin_auth.enabled, True)
        self.assertEqual(config.admin_auth.read_scopes, ["admin"])
        self.assertEqual(config.admin_auth.write_scopes, ["admin"])
        config = parse(self.valid_doc({}))
        self.assertEqual(config.admin_auth.enabled, False)
        self.assertEqual(config.admin_auth.read_scopes, ["admin"])
        self.assertEqual(config.admin_auth.write_scopes, ["admin"])
        custom = {"enabled": False, "read_scopes": ["r1", "r2"], "write_scopes": ["w"]}
        config = parse(self.valid_doc(custom))
        self.assertEqual(config.admin_auth.to_dict(), custom)

    def test_omitted_section_is_absent(self):
        config = parse(self.valid_doc(None))
        self.assertIsNone(config.admin_auth)
        self.assertNotIn("admin_auth", config.sanitized())

    def test_sanitized_echoes_only_when_declared(self):
        declared = {"enabled": False}
        config = parse(self.valid_doc(declared))
        self.assertEqual(config.sanitized()["admin_auth"],
                         {"enabled": False, "read_scopes": ["admin"],
                          "write_scopes": ["admin"]})

    def test_null_section_is_rejected(self):
        doc = self.valid_doc(None)
        doc["admin_auth"] = None  # a JSON null section, distinct from omission
        with self.assertRaises(GatewayError) as ctx:
            parse(doc)
        self.assertEqual(ctx.exception.message, ADMIN_AUTH_ERROR)

    def test_invalid_shapes(self):
        bad_values = [
            True, False, 1, "enabled", [], ["admin"],
            {"enabled": "yes"}, {"enabled": None}, {"enabled": 1},
            {"enabled": True, "extra": 1},
            {"enabled": True, "read_scopes": "admin"},
            {"enabled": True, "read_scopes": None},
            {"enabled": True, "read_scopes": []},
            {"enabled": True, "read_scopes": ["ok", 1]},
            {"enabled": True, "read_scopes": ["ok", None]},
            {"enabled": True, "read_scopes": ["ok", ""]},
            {"enabled": True, "write_scopes": "admin"},
            {"enabled": True, "write_scopes": None},
            {"enabled": True, "write_scopes": []},
            {"enabled": True, "write_scopes": [1]},
            {"enabled": True, "write_scopes": [""]},
        ]
        for bad in bad_values:
            with self.assertRaises(GatewayError) as ctx:
                parse(self.valid_doc(bad))
            self.assertEqual(ctx.exception.message, ADMIN_AUTH_ERROR, bad)
            self.assertEqual(ctx.exception.status, 400, bad)

    def test_write_time_parse_rejects_invalid_section(self):
        # _mutate re-parses the whole document before writing, so a config file
        # carrying a bad section makes every admin write fail validation.
        gateway, root, path = _make_gateway({"enabled": True})
        self.addCleanup(shutil.rmtree, root, True)
        revision = gateway.store.revision
        _write(path, config_document({"enabled": "yes"}))
        with self.assertRaises(GatewayError) as ctx:
            gateway.add_key("acme", ["read"])
        self.assertEqual(ctx.exception.message, ADMIN_AUTH_ERROR)
        self.assertEqual(gateway.store.revision, revision)  # nothing adopted


def _write(path, doc):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(doc, handle)
    stat = os.stat(path)
    os.utime(path, ns=(stat.st_atime_ns + 2_000_000, stat.st_mtime_ns + 2_000_000))


def _make_gateway(admin_auth=None, doc=None, **kwargs):
    root = tempfile.mkdtemp(prefix="gwd-admin-")
    path = os.path.join(root, "config.json")
    _write(path, config_document(admin_auth) if doc is None else doc)
    gateway = Gateway(config_path=path, data_dir=os.path.join(root, "data"), **kwargs)
    return gateway, root, path


class AdminAuthHttpTest(unittest.TestCase):
    def setUp(self):
        self.gateway, self.root, self.config_path = _make_gateway(
            {"enabled": True},
            breaker_settings={"failure_threshold": 1, "open_ms": 60_000,
                              "success_threshold": 1})
        self.addCleanup(shutil.rmtree, self.root, True)
        self.server = create_server(self.gateway, "127.0.0.1", 0, quiet=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self._stop)
        self.base = "http://127.0.0.1:%d" % self.server.server_address[1]

    def _stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)

    def bearer(self, secret):
        return {"authorization": "Bearer " + secret}

    def request(self, method, path, body=None, headers=None, raw=None):
        if raw is not None:
            data = raw.encode("utf-8")
        else:
            data = json.dumps(body).encode("utf-8") if body is not None else None
        request = urllib.request.Request(self.base + path, data=data, method=method,
                                         headers=headers or {})
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                text = response.read().decode("utf-8")
                return response.status, dict(response.headers), text
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers or {}), exc.read().decode("utf-8")

    def json_request(self, method, path, body=None, headers=None, raw=None):
        status, response_headers, text = self.request(method, path, body, headers, raw)
        return status, response_headers, json.loads(text)

    # ------------------------------------------------------------ open surfaces
    def test_healthz_stays_open(self):
        status, _, payload = self.json_request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])

    def test_proxy_surface_is_unaffected(self):
        # no key: the proxy answers with its own 401, not the admin wall
        status, _, payload = self.json_request("GET", "/api/items")
        self.assertEqual(status, 401)
        self.assertEqual(payload["error"], "missing api key")
        # a valid proxy key works even without any admin scope
        status, _, payload = self.json_request(
            "GET", "/api/items", headers=self.bearer(SECRET_ACME_READ))
        self.assertEqual(status, 200)
        self.assertEqual(payload["path"], "/api/items")
        # admin scopes never leak into route scope checks: the star-tenant key
        # fails the proxy with its own tenant error, not an admin 403
        status, _, payload = self.json_request(
            "GET", "/api/items", headers=self.bearer(SECRET_ROOT))
        self.assertEqual(status, 403)
        self.assertTrue(payload["error"].startswith("api key tenant"))
        self.assertNotIn("admin", payload["error"])

    def test_disabled_policy_leaves_admin_open(self):
        gateway, root, path = _make_gateway({"enabled": False})
        self.addCleanup(shutil.rmtree, root, True)
        server = create_server(gateway, "127.0.0.1", 0, quiet=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(lambda: (server.shutdown(), server.server_close(), thread.join(5)))
        base = "http://127.0.0.1:%d" % server.server_address[1]
        request = urllib.request.Request(base + "/v1/config")
        with urllib.request.urlopen(request, timeout=5) as response:
            self.assertEqual(response.status, 200)
        # the breaker status read keeps its historical open behaviour too
        request = urllib.request.Request(base + "/v1/breaker/status")
        with urllib.request.urlopen(request, timeout=5) as response:
            self.assertEqual(response.status, 200)
            self.assertEqual(json.loads(response.read().decode("utf-8")),
                             {"breakers": {}})

    # ------------------------------------------------------------- 401 reasons
    def test_read_requires_a_key(self):
        for path in ("/v1/config", "/v1/quota/usage", "/v1/audit",
                     "/v1/breaker/status"):
            status, _, payload = self.json_request("GET", path)
            self.assertEqual(status, 401, path)
            self.assertEqual(payload["error"], "missing api key", path)
            self.assertIn("request_id", payload)

    def test_write_requires_a_key(self):
        status, _, payload = self.json_request("POST", "/v1/keys", {"tenant": "acme"})
        self.assertEqual(status, 401)
        self.assertEqual(payload["error"], "missing api key")

    def test_unknown_disabled_expired_and_mismatched_keys(self):
        status, _, payload = self.json_request(
            "GET", "/v1/config", headers=self.bearer("nope"))
        self.assertEqual(status, 401)
        self.assertEqual(payload["error"], "unknown api key")
        status, _, payload = self.json_request(
            "GET", "/v1/config", headers={"x-api-key-secret": "nope"})
        self.assertEqual(status, 401)
        self.assertEqual(payload["error"], "unknown api key")
        status, _, payload = self.json_request(
            "GET", "/v1/config", headers=self.bearer(SECRET_DISABLED))
        self.assertEqual(status, 401)
        self.assertEqual(payload["error"], "api key disabled")
        status, _, payload = self.json_request(
            "GET", "/v1/config", headers=self.bearer(SECRET_EXPIRED))
        self.assertEqual(status, 401)
        self.assertEqual(payload["error"], "api key expired")
        status, _, payload = self.json_request(
            "GET", "/v1/config",
            headers={**self.bearer(SECRET_ACME_ADMIN), "x-api-key": "k-other"})
        self.assertEqual(status, 401)
        self.assertEqual(payload["error"], "api key id does not match the presented secret")

    def test_x_api_key_secret_header_is_accepted(self):
        status, _, payload = self.json_request(
            "GET", "/v1/config", headers={"x-api-key-secret": SECRET_ROOT})
        self.assertEqual(status, 200)
        self.assertIn("admin_auth", payload)

    def test_auth_precedes_body_parsing_and_modification(self):
        # malformed JSON without a credential is 401, not 400
        status, _, text = self.request("POST", "/v1/keys", raw="{not json", headers={})
        self.assertEqual(status, 401)
        payload = json.loads(text)
        self.assertEqual(payload["error"], "missing api key")
        revision = self.gateway.store.revision
        # scoped caller, malformed body: auth passes then parsing fails with 400
        status, _, reply = self.json_request(
            "POST", "/v1/keys", raw="{not json", headers=self.bearer(SECRET_ACME_ADMIN))
        self.assertEqual(status, 400)
        self.assertEqual(self.gateway.store.revision, revision)

    # ------------------------------------------------------------------ scopes
    def test_scope_shortage_is_fixed_403(self):
        # k-acme-read holds "read"; reads need the admin scope
        status, _, payload = self.json_request(
            "GET", "/v1/quota/usage", headers=self.bearer(SECRET_ACME_READ))
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"], "admin scope is missing")
        self.assertIn("request_id", payload)
        status, _, payload = self.json_request(
            "GET", "/v1/breaker/status", headers=self.bearer(SECRET_ACME_READ))
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"], "admin scope is missing")
        status, _, payload = self.json_request(
            "POST", "/v1/keys", {"tenant": "acme"},
            headers=self.bearer(SECRET_ACME_READ))
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"], "admin scope is missing")

    def test_star_scope_satisfies_any_admin_scope(self):
        status, _, payload = self.json_request(
            "GET", "/v1/quota/usage", headers=self.bearer(SECRET_STAR))
        self.assertEqual(status, 200)  # tenant defaults to acme
        self.assertEqual(payload["tenant"], "acme")

    def test_custom_scopes_via_hot_reload(self):
        self._reload({"enabled": True, "read_scopes": ["ops", "audit"],
                      "write_scopes": ["provision"]})
        # both read scopes required: k-ops-audit holds both, k-ops lacks audit
        status, _, _ = self.json_request(
            "GET", "/v1/quota/usage", headers=self.bearer(SECRET_OPS))
        self.assertEqual(status, 403)
        status, _, payload = self.json_request(
            "GET", "/v1/quota/usage", headers=self.bearer(SECRET_OPS_AUDIT))
        self.assertEqual(status, 200)
        self.assertEqual(payload["tenant"], "acme")
        # writes need the provision scope; extra scopes do not block a caller
        # that holds every required scope, and a missing scope is 403
        status, _, payload = self.json_request(
            "POST", "/v1/keys", {"tenant": "acme", "scopes": ["read"]},
            headers=self.bearer(SECRET_PROVISION))
        self.assertEqual(status, 201)
        status, _, payload = self.json_request(
            "POST", "/v1/keys", {"tenant": "acme", "scopes": ["read"]},
            headers=self.bearer(SECRET_OPS_AUDIT))
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"], "admin scope is missing")
        # "*" satisfies every scope set, but tenant rules still apply to writes
        status, _, payload = self.json_request(
            "POST", "/v1/keys", {"tenant": "globex", "scopes": ["read"]},
            headers=self.bearer(SECRET_STAR))
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"], "admin tenant mismatch")
        status, _, payload = self.json_request(
            "POST", "/v1/keys", {"tenant": "acme", "scopes": ["read"]},
            headers=self.bearer(SECRET_STAR))
        self.assertEqual(status, 201)

    # ------------------------------------------------------------- read tenant
    def test_usage_audit_tenant_default_and_match(self):
        for path in ("/v1/quota/usage", "/v1/audit"):
            status, _, payload = self.json_request(
                "GET", path, headers=self.bearer(SECRET_ACME_ADMIN))
            self.assertEqual(status, 200, path)
            self.assertEqual(payload["tenant"], "acme", path)
            status, _, payload = self.json_request(
                "GET", path + "?tenant=acme", headers=self.bearer(SECRET_ACME_ADMIN))
            self.assertEqual(status, 200, path)
            self.assertEqual(payload["tenant"], "acme", path)
            status, _, payload = self.json_request(
                "GET", path + "?tenant=globex", headers=self.bearer(SECRET_ACME_ADMIN))
            self.assertEqual(status, 403, path)
            self.assertEqual(payload["error"], "admin tenant mismatch", path)

    def test_star_key_reads_any_or_all_tenants(self):
        # omitted tenant -> all tenants: usage renders it as null, audit as ""
        status, _, payload = self.json_request(
            "GET", "/v1/quota/usage", headers=self.bearer(SECRET_ROOT))
        self.assertEqual(status, 200)
        self.assertIsNone(payload["tenant"])
        status, _, payload = self.json_request(
            "GET", "/v1/audit", headers=self.bearer(SECRET_ROOT))
        self.assertEqual(status, 200)
        self.assertEqual(payload["tenant"], "")
        for path in ("/v1/quota/usage", "/v1/audit"):
            status, _, payload = self.json_request(
                "GET", path + "?tenant=globex", headers=self.bearer(SECRET_ROOT))
            self.assertEqual(status, 200)
            self.assertEqual(payload["tenant"], "globex")

    # ------------------------------------------------------------ write tenant
    def test_key_creation_tenant_must_match(self):
        revision = self.gateway.store.revision
        status, _, payload = self.json_request(
            "POST", "/v1/keys", {"tenant": "globex", "scopes": ["read"]},
            headers=self.bearer(SECRET_ACME_ADMIN))
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"], "admin tenant mismatch")
        # an omitted tenant can never equal a scoped key's tenant
        status, _, payload = self.json_request(
            "POST", "/v1/keys", {"scopes": ["read"]},
            headers=self.bearer(SECRET_ACME_ADMIN))
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"], "admin tenant mismatch")
        self.assertEqual(self.gateway.store.revision, revision)
        status, _, config = self.json_request(
            "GET", "/v1/config", headers=self.bearer(SECRET_ROOT))
        self.assertEqual({k["tenant"] for k in config["keys"] if k["key_id"].startswith("key-")},
                         set())
        # same tenant succeeds
        status, _, payload = self.json_request(
            "POST", "/v1/keys", {"tenant": "acme", "scopes": ["read"]},
            headers=self.bearer(SECRET_ACME_ADMIN))
        self.assertEqual(status, 201)
        # a "*" key may create for any tenant
        status, _, payload = self.json_request(
            "POST", "/v1/keys", {"tenant": "globex", "scopes": ["read"]},
            headers=self.bearer(SECRET_ROOT))
        self.assertEqual(status, 201)
        self.assertEqual(payload["tenant"], "globex")

    def test_policy_creation_tenant_must_match(self):
        policy = {"id": "p-acme-x", "algorithm": "token-bucket",
                  "limit": 1, "window_ms": 1000, "tenant": "acme"}
        status, _, payload = self.json_request(
            "POST", "/v1/quota/policies", policy,
            headers=self.bearer(SECRET_ACME_ADMIN))
        self.assertEqual(status, 201)
        foreign = dict(policy, id="p-glob-x", tenant="globex")
        status, _, payload = self.json_request(
            "POST", "/v1/quota/policies", foreign,
            headers=self.bearer(SECRET_ACME_ADMIN))
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"], "admin tenant mismatch")
        # omitted tenant defaults to "*" and is therefore foreign to acme
        wildcard = dict(policy, id="p-wild-x")
        del wildcard["tenant"]
        status, _, payload = self.json_request(
            "POST", "/v1/quota/policies", wildcard,
            headers=self.bearer(SECRET_ACME_ADMIN))
        self.assertEqual(status, 403)
        status, _, payload = self.json_request(
            "POST", "/v1/quota/policies", foreign,
            headers=self.bearer(SECRET_ROOT))
        self.assertEqual(status, 201)

    def test_key_rotation_is_owner_scoped(self):
        status, _, payload = self.json_request(
            "POST", "/v1/keys/k-glob-admin/rotate", {},
            headers=self.bearer(SECRET_ACME_ADMIN))
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"], "admin tenant mismatch")
        # an unknown key stays a 404 even for a scoped caller
        status, _, payload = self.json_request(
            "POST", "/v1/keys/k-nope/rotate", {},
            headers=self.bearer(SECRET_ACME_ADMIN))
        self.assertEqual(status, 404)
        self.assertEqual(payload["error"], "api key not found")
        # own tenant rotates
        status, _, payload = self.json_request(
            "POST", "/v1/keys/k-acme-read/rotate", {},
            headers=self.bearer(SECRET_ACME_ADMIN))
        self.assertEqual(status, 200)
        self.assertIn("secret", payload)
        # a "*" key rotates anyone
        status, _, payload = self.json_request(
            "POST", "/v1/keys/k-glob-admin/rotate", {},
            headers=self.bearer(SECRET_ROOT))
        self.assertEqual(status, 200)

    # ------------------------------------------------------------ global ops
    def test_global_ops_require_a_star_tenant_key(self):
        # scope is satisfied (admin) but the tenant is not "*"
        status, _, payload = self.json_request(
            "GET", "/v1/config", headers=self.bearer(SECRET_ACME_ADMIN))
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"], "admin tenant mismatch")
        status, _, payload = self.json_request(
            "POST", "/v1/config/reload", {}, headers=self.bearer(SECRET_ACME_ADMIN))
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"], "admin tenant mismatch")
        status, _, payload = self.json_request(
            "POST", "/v1/breaker/reset", {"upstream": "echo"},
            headers=self.bearer(SECRET_GLOB_ADMIN))
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"], "admin tenant mismatch")
        # the global breaker status read needs a tenant "*" key as well
        status, _, payload = self.json_request(
            "GET", "/v1/breaker/status", headers=self.bearer(SECRET_GLOB_ADMIN))
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"], "admin tenant mismatch")
        # the star-tenant key passes all four
        status, _, _ = self.json_request(
            "GET", "/v1/config", headers=self.bearer(SECRET_ROOT))
        self.assertEqual(status, 200)
        status, _, payload = self.json_request(
            "POST", "/v1/config/reload", {}, headers=self.bearer(SECRET_ROOT))
        self.assertEqual(status, 200)
        status, _, payload = self.json_request(
            "GET", "/v1/breaker/status", headers=self.bearer(SECRET_ROOT))
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"breakers": {}})
        status, _, payload = self.json_request(
            "POST", "/v1/breaker/reset", {"upstream": "echo"},
            headers=self.bearer(SECRET_ROOT))
        self.assertEqual(status, 200)
        self.assertEqual(payload["reset"], ["echo"])

    def test_breaker_status_is_read_only_for_the_star_key(self):
        breaker = self.gateway.breakers.get("echo")
        breaker.allow(0)
        breaker.record(False, 0)  # threshold is 1 in this suite: trips open
        self.assertEqual(breaker.state, "open")
        revision = self.gateway.store.revision
        status, _, payload = self.json_request(
            "GET", "/v1/breaker/status", headers=self.bearer(SECRET_ROOT))
        self.assertEqual(status, 200)
        self.assertEqual(list(payload["breakers"]), ["echo"])
        snapshot = payload["breakers"]["echo"]
        self.assertEqual(snapshot["state"], "open")  # query does not advance it
        self.assertEqual(snapshot["trips"], 1)
        self.assertEqual(snapshot["failure_threshold"], 1)
        self.assertEqual(snapshot["open_ms"], 60_000)
        self.assertEqual(snapshot["success_threshold"], 1)
        # repeated reads return identical state: no counters move, and the
        # request changed no revision, usage or audit state
        _, _, again = self.json_request(
            "GET", "/v1/breaker/status", headers=self.bearer(SECRET_ROOT))
        self.assertEqual(again, payload)
        self.assertEqual(self.gateway.store.revision, revision)
        self.assertEqual(self.gateway.breakers.get("echo").state, "open")
        self.assertEqual(self.gateway.breakers.get("echo").rejected, 0)
        # an open window elapsed long ago is still reported open: the read
        # never calls allow(), so open -> half_open never happens
        breaker.opened_at_ms = 0
        breaker.last_change_ms = 0
        status, _, payload = self.json_request(
            "GET", "/v1/breaker/status", headers=self.bearer(SECRET_ROOT))
        self.assertEqual(payload["breakers"]["echo"]["state"], "open")
        self.assertEqual(self.gateway.breakers.get("echo").state, "open")

    def test_failed_auth_changes_no_state(self):
        before = self.gateway.sanitized_config()
        self.gateway.breakers.get("echo").allow(0)
        self.gateway.breakers.get("echo").record(False, 0)
        self.json_request("GET", "/v1/config")
        self.json_request("GET", "/v1/config", headers=self.bearer(SECRET_ACME_READ))
        self.json_request("GET", "/v1/config", headers=self.bearer(SECRET_ACME_ADMIN))
        self.json_request("GET", "/v1/quota/usage?tenant=globex",
                          headers=self.bearer(SECRET_ACME_ADMIN))
        self.json_request("GET", "/v1/breaker/status")  # 401: no credential
        self.json_request("GET", "/v1/breaker/status",
                          headers=self.bearer(SECRET_ACME_READ))  # 403: scope
        self.json_request("GET", "/v1/breaker/status",
                          headers=self.bearer(SECRET_ACME_ADMIN))  # 403: tenant
        self.json_request("POST", "/v1/keys", {"tenant": "globex"},
                          headers=self.bearer(SECRET_ACME_ADMIN))
        self.assertEqual(self.gateway.sanitized_config(), before)
        self.assertEqual(self.gateway.store.revision, before["revision"])
        self.assertEqual(self.gateway.breakers.get("echo").state, "open")
        # the rejected status queries neither created another breaker nor
        # advanced the open one past its state
        self.assertEqual(sorted(self.gateway.breakers.snapshot()), ["echo"])

    # ------------------------------------------------------------- hot reload
    def _reload(self, admin_auth):
        _write(self.config_path, config_document(admin_auth))
        status, _, payload = self.json_request(
            "POST", "/v1/config/reload", {}, headers=self.bearer(SECRET_ROOT))
        self.assertEqual(status, 200)
        return payload

    def test_valid_hot_reload_enables_and_disables(self):
        # enabled by default in setUp; a read without credentials is 401
        status, _, _ = self.json_request("GET", "/v1/quota/usage")
        self.assertEqual(status, 401)
        payload = self._reload({"enabled": False})
        self.assertTrue(payload["reloaded"])
        # disabling affects only later requests: the wall is gone
        status, _, payload = self.json_request("GET", "/v1/quota/usage")
        self.assertEqual(status, 200)
        # re-enable
        self._reload({"enabled": True})
        status, _, _ = self.json_request("GET", "/v1/quota/usage")
        self.assertEqual(status, 401)

    def test_invalid_hot_reload_keeps_the_previous_policy(self):
        revision = self.gateway.store.revision
        # spend some proxy quota and trip a breaker so we can assert they survive
        self.gateway.breakers.get("echo").allow(0)
        self.gateway.breakers.get("echo").record(False, 0)
        _write(self.config_path, config_document({"enabled": "yes"}))
        status, _, payload = self.json_request(
            "POST", "/v1/config/reload", {}, headers=self.bearer(SECRET_ROOT))
        self.assertEqual(status, 200)
        self.assertFalse(payload["reloaded"])
        self.assertFalse(payload["ready"])
        self.assertEqual(payload["error"], ADMIN_AUTH_ERROR)
        # the last good config, revision and runtime state survive
        self.assertEqual(self.gateway.store.revision, revision)
        self.assertEqual(self.gateway.breakers.get("echo").state, "open")
        status, _, reply = self.json_request(
            "GET", "/v1/quota/usage", headers=self.bearer(SECRET_ACME_ADMIN))
        self.assertEqual(status, 200)  # still enabled with the old policy
        status, _, reply = self.json_request("GET", "/v1/quota/usage")
        self.assertEqual(status, 401)
        self.assertEqual(reply["error"], "missing api key")

    def test_reload_only_changes_revision_on_valid_config(self):
        first = self._reload({"enabled": True, "read_scopes": ["admin"]})
        self.assertEqual(first["revision"], 2)
        second = self._reload({"enabled": True, "read_scopes": ["admin"]})
        self.assertEqual(second["revision"], 3)
        # a valid policy change applies to subsequent requests: the read-scope
        # key still fails admin, but after widening reads to "read" it passes
        self._reload({"enabled": True, "read_scopes": ["read"]})
        status, _, payload = self.json_request(
            "GET", "/v1/quota/usage", headers=self.bearer(SECRET_ACME_READ))
        self.assertEqual(status, 200)


if __name__ == "__main__":
    unittest.main()
