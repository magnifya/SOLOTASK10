"""Command line interface: serve, route-add, key-add, key-rotate, quota-set, call, usage, audit."""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

from .config import ANY_SCOPE, GatewayError
from .gateway import Gateway
from .http_app import create_server
from .limits import AuditLog, QuotaLedger, parse_audit_filters, parse_usage_filters


def _out(payload: Any) -> None:
    sys.stdout.write(json.dumps(payload, sort_keys=True) + "\n")
    sys.stdout.flush()


def _err(message: str) -> int:
    sys.stderr.write(json.dumps({"error": message}, sort_keys=True) + "\n")
    sys.stderr.flush()
    return 1


def _read_json_arg(value: str) -> Any:
    """Read a JSON document from a path, or from stdin when the value is '-'."""
    if value == "-":
        text = sys.stdin.read()
    else:
        try:
            with open(value, "r", encoding="utf-8") as handle:
                text = handle.read()
        except OSError as exc:
            raise GatewayError("cannot read %s: %s" % (value, exc))
    try:
        return json.loads(text)
    except ValueError as exc:
        raise GatewayError("%s is not valid JSON: %s" % (value, exc))


def cmd_serve(args: argparse.Namespace) -> Dict[str, Any]:
    gateway = Gateway(config_path=args.config, data_dir=args.data_dir)
    server = create_server(gateway, args.host, args.port)
    host, port = server.server_address[0], server.server_address[1]
    _out({"listening": "http://%s:%d" % (host, port), "config": args.config,
          "data_dir": args.data_dir, "routes": len(gateway.config.routes),
          "revision": gateway.store.revision})
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return {"stopped": True}


def cmd_route_add(args: argparse.Namespace) -> Dict[str, Any]:
    gateway = Gateway(config_path=args.config, data_dir=args.data_dir)
    return gateway.add_route(_read_json_arg(args.file))


def cmd_key_add(args: argparse.Namespace) -> Dict[str, Any]:
    gateway = Gateway(config_path=args.config, data_dir=args.data_dir)
    scopes: List[str] = args.scopes or [ANY_SCOPE]
    return gateway.add_key(args.tenant, scopes, args.key_id)


def cmd_key_rotate(args: argparse.Namespace) -> Dict[str, Any]:
    gateway = Gateway(config_path=args.config, data_dir=args.data_dir)
    return gateway.rotate_key(args.key_id)


def cmd_quota_set(args: argparse.Namespace) -> Dict[str, Any]:
    gateway = Gateway(config_path=args.config, data_dir=args.data_dir)
    return gateway.add_policy(_read_json_arg(args.file))


def cmd_call(args: argparse.Namespace) -> Dict[str, Any]:
    key_id, secret = args.key_id or "", args.key or ""
    if not key_id and ":" in secret:
        key_id, secret = secret.split(":", 1)
    body = args.body or ""
    request = urllib.request.Request(args.base_url.rstrip("/") + args.path,
                                     data=body.encode("utf-8") if body else None,
                                     method=args.method.upper())
    if secret:
        request.add_header("Authorization", "Bearer " + secret)
    if key_id:
        request.add_header("X-Api-Key", key_id)
    if args.tenant:
        request.add_header("X-Tenant", args.tenant)
    if args.idempotency_key:
        request.add_header("X-Idempotency-Key", args.idempotency_key)
    request.add_header("Content-Type", "application/json")
    timeout = max(0.001, args.timeout_ms / 1000.0)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status, headers = response.status, dict(response.headers)
            text = response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        status, headers = exc.code, dict(exc.headers or {})
        text = exc.read().decode("utf-8", "replace")
    except (urllib.error.URLError, OSError) as exc:
        raise GatewayError("call failed: %s" % exc)
    return {"status": int(status), "replayed": headers.get("X-Idempotent-Replay") == "true",
            "headers": headers, "body": _maybe_json(text)}


def _maybe_json(text: str) -> Any:
    try:
        return json.loads(text)
    except ValueError:
        return text


def cmd_usage(args: argparse.Namespace) -> Dict[str, Any]:
    filters = parse_usage_filters(request_id=args.request_id, trace_id=args.trace_id)
    return QuotaLedger(args.data_dir).usage(args.tenant or None, args.since, **filters)


def cmd_audit(args: argparse.Namespace) -> Dict[str, Any]:
    filters = parse_audit_filters(request_id=args.request_id, trace_id=args.trace_id,
                                  route_id=args.route_id, status=args.status,
                                  since=args.since, until=args.until)
    entries = AuditLog(args.data_dir).entries(args.tenant or None, args.limit, **filters)
    return {"tenant": args.tenant, "count": len(entries), "entries": entries}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="gwd", description="API gateway and quota governance backend")
    parser.add_argument("--data-dir", default="./gwd_data",
                        help="directory for usage.jsonl and audit.jsonl (default ./gwd_data)")
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="run the gateway HTTP server")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)
    serve.add_argument("--config", default="./config.json")
    serve.set_defaults(func=cmd_serve)

    route_add = sub.add_parser("route-add", help="append a route from a JSON file")
    route_add.add_argument("--file", required=True, help="JSON file with a route object or array")
    route_add.add_argument("--config", default="./config.json")
    route_add.set_defaults(func=cmd_route_add)

    key_add = sub.add_parser("key-add", help="create an API key; prints the secret once")
    key_add.add_argument("--tenant", required=True)
    key_add.add_argument("--scope", action="append", dest="scopes")
    key_add.add_argument("--key-id")
    key_add.add_argument("--config", default="./config.json")
    key_add.set_defaults(func=cmd_key_add)

    key_rotate = sub.add_parser("key-rotate",
                                help="rotate an API key secret; prints the new secret once")
    key_rotate.add_argument("--key-id", default="")
    key_rotate.add_argument("--config", default="./config.json")
    key_rotate.set_defaults(func=cmd_key_rotate)

    quota_set = sub.add_parser("quota-set", help="append a quota policy from a JSON file")
    quota_set.add_argument("--file", required=True)
    quota_set.add_argument("--config", default="./config.json")
    quota_set.set_defaults(func=cmd_quota_set)

    call = sub.add_parser("call", help="call a running gateway through the proxy surface")
    call.add_argument("--method", default="GET")
    call.add_argument("--path", required=True)
    call.add_argument("--tenant", default="")
    call.add_argument("--key", default="", help="secret, or key_id:secret")
    call.add_argument("--key-id", default="")
    call.add_argument("--idempotency-key", default="")
    call.add_argument("--body", default="")
    call.add_argument("--base-url", default="http://127.0.0.1:8080")
    call.add_argument("--timeout-ms", type=int, default=5000)
    call.set_defaults(func=cmd_call)

    usage = sub.add_parser("usage", help="aggregate the local usage ledger")
    usage.add_argument("--tenant", default="")
    usage.add_argument("--since", type=int, default=None)
    usage.add_argument("--request-id", default=None, help="exact request_id match")
    usage.add_argument("--trace-id", default=None,
                       help="exact trace_id match (32 lowercase hex digits)")
    usage.set_defaults(func=cmd_usage)

    audit = sub.add_parser("audit", help="read the local audit trail")
    audit.add_argument("--tenant", default="")
    audit.add_argument("--limit", type=int, default=50)
    audit.add_argument("--request-id", default=None, help="exact request_id match")
    audit.add_argument("--trace-id", default=None,
                       help="exact trace_id match (32 lowercase hex digits)")
    audit.add_argument("--route-id", default=None, help="exact route_id match")
    audit.add_argument("--status", default=None, help="exact status match (100-599)")
    audit.add_argument("--since", default=None,
                       help="inclusive lower bound on the entry timestamp in ms")
    audit.add_argument("--until", default=None,
                       help="exclusive upper bound on the entry timestamp in ms")
    audit.set_defaults(func=cmd_audit)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        _out(args.func(args))
    except GatewayError as exc:
        return _err(exc.message)
    except KeyboardInterrupt:
        return 130
    except Exception as exc:  # never traceback on the operator surface
        return _err("%s: %s" % (type(exc).__name__, exc))
    return 0
