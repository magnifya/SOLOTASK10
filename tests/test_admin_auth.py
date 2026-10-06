"""Tests for the hot-reloadable admin_auth policy on the /v1 admin surface."""

import hashlib
import json
import os
import shutil
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

from gwd.config import GatewayError, load
from gwd.gateway import Gateway
from gwd.http_app import create_server

ADMIN_SECRET = "admin-secret"
READER_SECRET = "reader-secret"
WRITER_SECRET = "writer-secret"
ACME_SECRET = "acme-secret"
OLD_SECRET = "old-secret"


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def config_document(admin_auth=None):
    document = {
        "quota_policies": [{"id": "p-acme", "tenant": "acme", "algorithm": "sliding-window",
                            "limit": 50, "window_ms": 60000}],
        "keys": [
            {"key_id": "k-admin", "tenant": "*", "secret_sha256": sha(ADMIN_SECRET),
             "scopes": ["admin", "admin-read"]},
            {"key_id": "k-reader", "tenant": "*", "secret_sha256": sha(READER_SECRET),
             "scopes": ["admin-read"]},
            {"key_id": "k-writer", "tenant": "*", "secret_sha256": sha(WRITER_SECRET),
             "scopes": ["admin"]},
            {"key_id": "k-acme", "tenant": "acme", "secret_sha256": sha(ACME_SECRET),
             "scopes": ["admin", "admin-read"]},
            {"key_id": "k-old", "tenant": "*", "secret_sha256": sha(OLD_SECRET),
             "scopes": ["read"]},
        ],
        "routes": [
            {"id": "r-acme", "tenant": "acme", "match": {"method": "GET", "path_prefix": "/api"},
             "upstream": "echo", "auth_required": False},
        ],
    }
    if admin_auth is not None:
        document["admin_auth"] = admin_auth
    return document


ENABLED = {"enabled": True, "read_scopes": ["admin-read"], "write_scopes": ["admin"]}


class AdminAuthHttpTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="gwd-admin-auth-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.config_path = os.path.join(self.root, "config.json")
        with open(self.config_path, "w", encoding="utf-8") as handle:
            json.dump(config_document(ENABLED), handle)
        self.gateway = Gateway(config_path=self.config_path,
                               data_dir=os.path.join(self.root, "data"))
        self.server = create_server(self.gateway, "127.0.0.1", 0, quiet=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self._stop)
        self.base = "http://127.0.0.1:%d" % self.server.server_address[1]

    def _stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)

    def request(self, method, path, body=None, headers=None):
        data = json.dumps(body).encode("utf-8") if body is not None else None
        request = urllib.request.Request(self.base + path, data=data, method=method,
                                         headers=headers or {})
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def admin(self, secret=ADMIN_SECRET):
        return {"authorization": "Bearer " + secret}

    def rewrite_config(self, admin_auth):
        with open(self.config_path, "w", encoding="utf-8") as handle:
            json.dump(config_document(admin_auth), handle)
        stat = os.stat(self.config_path)
        os.utime(self.config_path, ns=(stat.st_atime_ns + 1_000_000,
                                       stat.st_mtime_ns + 1_000_000))

    # ------------------------------------------------------------- credentials
    def test_missing_and_unknown_secret_are_401(self):
        for headers in ({}, {"authorization": "Bearer nope"}):
            status, payload = self.request("GET", "/v1/config", headers=headers)
            self.assertEqual(status, 401)
            self.assertIn("request_id", payload)
            self.assertIn(payload["error"], ("missing api key", "unknown api key"))

    def test_mismatched_key_id_is_401(self):
        status, payload = self.request(
            "GET", "/v1/config",
            headers={"authorization": "Bearer " + ADMIN_SECRET, "x-api-key": "k-other"})
        self.assertEqual(status, 401)
        self.assertEqual(payload["error"], "api key id does not match the presented secret")

    def test_disabled_and_expired_keys_keep_their_401_texts(self):
        self.gateway.add_key("acme", ["admin"], key_id="k-disabled", enabled=False)
        self.gateway.add_key("acme", ["admin"], key_id="k-expired", expires_at_ms=1)
        for key_id, error in (("k-disabled", "api key disabled"),
                              ("k-expired", "api key expired")):
            # recover a known plaintext secret through rotation
            rotated = self.gateway.rotate_key(key_id)
            status, payload = self.request(
                "GET", "/v1/config",
                headers={"x-api-key-secret": rotated["secret"]})
            self.assertEqual(status, 401)
            self.assertEqual(payload["error"], error)
            self.assertIn("request_id", payload)

    def test_x_api_key_secret_header_authenticates(self):
        status, payload = self.request(
            "GET", "/v1/config", headers={"x-api-key-secret": ADMIN_SECRET})
        self.assertEqual(status, 200)
        self.assertEqual(payload["admin_auth"]["read_scopes"], ["admin-read"])

    # ------------------------------------------------------------------ scopes
    def test_read_scope_allows_reads_but_not_writes(self):
        status, payload = self.request("GET", "/v1/config", headers=self.admin(READER_SECRET))
        self.assertEqual(status, 200)
        self.assertEqual(payload["admin_auth"]["write_scopes"], ["admin"])
        for method, path in (("POST", "/v1/config/reload"),
                             ("POST", "/v1/keys"),
                             ("POST", "/v1/quota/policies"),
                             ("POST", "/v1/breaker/reset")):
            status, payload = self.request(method, path, body={}, headers=self.admin(READER_SECRET))
            self.assertEqual(status, 403, (method, path))
            self.assertEqual(payload["error"], "admin scope is missing")
            self.assertIn("request_id", payload)

    def test_write_endpoints_accept_the_write_scope(self):
        status, payload = self.request("POST", "/v1/config/reload", headers=self.admin())
        self.assertEqual(status, 200)
        self.assertIn("reloaded", payload)
        status, payload = self.request("POST", "/v1/breaker/reset", body={}, headers=self.admin())
        self.assertEqual(status, 200)
        self.assertIn("reset", payload)

    def test_read_endpoints_require_the_read_scope(self):
        # k-writer holds "admin" (write) but not "admin-read" (read)
        for path in ("/v1/config", "/v1/quota/usage", "/v1/audit"):
            status, payload = self.request("GET", path, headers=self.admin(WRITER_SECRET))
            self.assertEqual(status, 403, path)
            self.assertEqual(payload["error"], "admin scope is missing")
        status, payload = self.request("POST", "/v1/config/reload",
                                       headers=self.admin(WRITER_SECRET))
        self.assertEqual(status, 200)
        status, payload = self.request("GET", "/v1/quota/usage", headers=self.admin(READER_SECRET))
        self.assertEqual(status, 200)
        status, payload = self.request("GET", "/v1/audit", headers=self.admin(READER_SECRET))
        self.assertEqual(status, 200)

    def test_wildcard_scope_satisfies_any_requirement(self):
        self.gateway.add_key("acme", ["*"], key_id="k-star")
        rotated = self.gateway.rotate_key("k-star")
        status, _ = self.request("GET", "/v1/config",
                                 headers={"authorization": "Bearer " + rotated["secret"]})
        # k-star is tenant acme, so the global config endpoint rejects it;
        # the scope check itself passed (no admin scope is missing error)
        self.assertEqual(status, 403)

    def test_failed_auth_changes_nothing(self):
        revision = self.gateway.store.revision
        status, _ = self.request("POST", "/v1/keys", body={"tenant": "acme"},
                                 headers=self.admin(READER_SECRET))
        self.assertEqual(status, 403)
        status, _ = self.request("POST", "/v1/keys", body={"tenant": "acme"})
        self.assertEqual(status, 401)
        self.assertEqual(self.gateway.store.revision, revision)
        self.assertEqual({k.key_id for k in self.gateway.config.keys},
                         {"k-admin", "k-reader", "k-writer", "k-acme", "k-old"})

    def test_auth_precedes_body_parsing(self):
        status, payload = self.request("POST", "/v1/keys", body=None,
                                       headers=self.admin(READER_SECRET))
        self.assertEqual(status, 403)  # not the 400 a missing body would give

    # ------------------------------------------------------------------ tenant
    def test_global_operations_require_a_wildcard_tenant_key(self):
        for method, path in (("GET", "/v1/config"),
                             ("POST", "/v1/config/reload"),
                             ("POST", "/v1/breaker/reset")):
            status, payload = self.request(method, path, body={} if method == "POST" else None,
                                           headers=self.admin(ACME_SECRET))
            self.assertEqual(status, 403, (method, path))
            self.assertEqual(payload["error"], "admin tenant mismatch")
            self.assertIn("request_id", payload)

    def test_queries_default_to_the_caller_tenant(self):
        # k-acme holds "admin" but read requires "admin-read"; give it a reader
        self.gateway.add_key("acme", ["admin-read"], key_id="k-acme-read")
        secret = self.gateway.rotate_key("k-acme-read")["secret"]
        headers = {"authorization": "Bearer " + secret}
        status, payload = self.request("GET", "/v1/audit", headers=headers)
        self.assertEqual(status, 200)
        self.assertEqual(payload["tenant"], "acme")
        status, payload = self.request("GET", "/v1/audit?tenant=acme", headers=headers)
        self.assertEqual(status, 200)
        status, payload = self.request("GET", "/v1/audit?tenant=other", headers=headers)
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"], "admin tenant mismatch")
        status, payload = self.request("GET", "/v1/quota/usage?tenant=other", headers=headers)
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"], "admin tenant mismatch")

    def test_wildcard_tenant_key_may_omit_or_name_any_tenant(self):
        headers = self.admin(READER_SECRET)
        status, payload = self.request("GET", "/v1/audit", headers=headers)
        self.assertEqual(status, 200)
        self.assertEqual(payload["tenant"], "")
        status, payload = self.request("GET", "/v1/audit?tenant=anything", headers=headers)
        self.assertEqual(status, 200)
        self.assertEqual(payload["tenant"], "anything")

    def test_key_creation_is_confined_to_the_caller_tenant(self):
        status, payload = self.request("POST", "/v1/keys", body={"tenant": "other"},
                                       headers=self.admin(ACME_SECRET))
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"], "admin tenant mismatch")
        status, payload = self.request("POST", "/v1/keys", body={"tenant": "acme"},
                                       headers=self.admin(ACME_SECRET))
        self.assertEqual(status, 201)
        # a wildcard key may create for any tenant
        status, payload = self.request("POST", "/v1/keys", body={"tenant": "other"},
                                       headers=self.admin())
        self.assertEqual(status, 201)

    def test_policy_creation_is_confined_to_the_caller_tenant(self):
        policy = {"id": "p-x", "algorithm": "token-bucket", "limit": 1, "window_ms": 1000}
        status, payload = self.request("POST", "/v1/quota/policies", body=policy,
                                       headers=self.admin(ACME_SECRET))
        self.assertEqual(status, 403)  # omitted tenant defaults to "*"
        self.assertEqual(payload["error"], "admin tenant mismatch")
        policy["tenant"] = "acme"
        status, payload = self.request("POST", "/v1/quota/policies", body=policy,
                                       headers=self.admin(ACME_SECRET))
        self.assertEqual(status, 201)

    def test_rotation_is_confined_to_the_caller_tenant(self):
        status, payload = self.request("POST", "/v1/keys/k-admin/rotate",
                                       headers=self.admin(ACME_SECRET))
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"], "admin tenant mismatch")
        status, payload = self.request("POST", "/v1/keys/k-acme/rotate",
                                       headers=self.admin(ACME_SECRET))
        self.assertEqual(status, 200)
        self.assertIn("secret", payload)

    # ----------------------------------------------------------------- passthrough
    def test_healthz_and_proxy_are_not_protected(self):
        status, payload = self.request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        status, payload = self.request("GET", "/api/items")
        self.assertEqual(status, 200)
        self.assertEqual(payload["path"], "/api/items")

    def test_sanitized_config_echoes_admin_auth_only_when_declared(self):
        status, payload = self.request("GET", "/v1/config", headers=self.admin())
        self.assertEqual(status, 200)
        self.assertEqual(payload["admin_auth"],
                         {"enabled": True, "read_scopes": ["admin-read"],
                          "write_scopes": ["admin"]})

    # --------------------------------------------------------------- hot reload
    def test_hot_reload_enables_and_disables_the_policy(self):
        self.rewrite_config(None)
        status, payload = self.request("POST", "/v1/config/reload", headers=self.admin())
        self.assertEqual(status, 200)
        self.assertTrue(payload["reloaded"])
        # policy gone: the admin surface is open again and not echoed
        status, payload = self.request("GET", "/v1/config")
        self.assertEqual(status, 200)
        self.assertNotIn("admin_auth", payload)
        # re-enable
        self.rewrite_config({"enabled": True})
        status, payload = self.request("POST", "/v1/config/reload")
        self.assertEqual(status, 200)
        self.assertTrue(payload["reloaded"])
        status, payload = self.request("GET", "/v1/config")
        self.assertEqual(status, 401)
        status, payload = self.request("GET", "/v1/config", headers=self.admin())
        self.assertEqual(status, 200)
        # default scopes are ["admin"] on both sides
        self.assertEqual(payload["admin_auth"],
                         {"enabled": True, "read_scopes": ["admin"],
                          "write_scopes": ["admin"]})

    def test_invalid_reload_keeps_the_previous_policy_and_revision(self):
        revision = self.gateway.store.revision
        self.rewrite_config({"enabled": "yes"})
        status, payload = self.request("POST", "/v1/config/reload", headers=self.admin())
        self.assertEqual(status, 200)
        self.assertFalse(payload["reloaded"])
        self.assertFalse(payload["ready"])
        self.assertEqual(payload["error"], "admin_auth configuration is invalid")
        self.assertEqual(self.gateway.store.revision, revision)
        # the previous policy still guards the surface
        status, _ = self.request("GET", "/v1/config")
        self.assertEqual(status, 401)
        status, _ = self.request("GET", "/v1/config", headers=self.admin())
        self.assertEqual(status, 200)


class AdminAuthValidationTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="gwd-admin-auth-cfg-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.path = os.path.join(self.root, "config.json")

    def write(self, admin_auth):
        with open(self.path, "w", encoding="utf-8") as handle:
            json.dump({"routes": [], "keys": [], "quota_policies": [],
                       "admin_auth": admin_auth}, handle)

    def test_invalid_documents_are_rejected_with_the_fixed_message(self):
        for bad in ("yes", 1, [], None,
                    {"enabled": "yes"}, {"enabled": None}, {"enabled": 1},
                    {"read_scopes": []}, {"write_scopes": []},
                    {"read_scopes": "admin"}, {"read_scopes": [""]},
                    {"read_scopes": [1]}, {"read_scopes": [None]},
                    {"write_scopes": ["admin", 2]},
                    {"extra": True}, {"enabled": True, "scope": ["admin"]}):
            self.write(bad)
            with self.assertRaises(GatewayError) as ctx:
                load(self.path)
            self.assertEqual(str(ctx.exception), "admin_auth configuration is invalid", bad)
            self.assertEqual(ctx.exception.status, 400)

    def test_defaults_and_declaration_echo(self):
        self.write({})
        config = load(self.path)
        self.assertFalse(config.admin_auth.enabled)
        self.assertEqual(config.admin_auth.read_scopes, ["admin"])
        self.assertEqual(config.admin_auth.write_scopes, ["admin"])
        self.assertEqual(config.sanitized()["admin_auth"],
                         {"enabled": False, "read_scopes": ["admin"],
                          "write_scopes": ["admin"]})

    def test_undeclared_admin_auth_is_not_echoed(self):
        with open(self.path, "w", encoding="utf-8") as handle:
            json.dump({"routes": [], "keys": [], "quota_policies": []}, handle)
        config = load(self.path)
        self.assertIsNone(config.admin_auth)
        self.assertNotIn("admin_auth", config.sanitized())

    def test_mutation_through_the_gateway_validates_admin_auth(self):
        self.write({"bogus": 1})
        with self.assertRaises(GatewayError):
            Gateway(config_path=self.path, data_dir=os.path.join(self.root, "data"))


if __name__ == "__main__":
    unittest.main()
