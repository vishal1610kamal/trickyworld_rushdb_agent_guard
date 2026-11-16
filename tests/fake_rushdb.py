"""A small stand-in for a RushDB 3 node, for tests: the native protocol's envelope, its errors, capability tokens, and
the catalog reads the guard uses, following the shapes in RushDB's manual (docs/manual in rush-db/rushdb, v3.0.10).
It is not RushDB: just enough of its documented behaviour to test the client offline."""
from __future__ import annotations

import base64
import difflib
import hashlib
import hmac
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# One single-tenant store: label -> list of records (flat properties). ORDER links to CUSTOMER through "customer".
DATA = {
    "CUSTOMER": [
        {"name": "Acme", "plan": "enterprise", "country": "US"},
        {"name": "Globex", "plan": "pro", "country": "DE"},
        {"name": "Initech", "plan": "enterprise", "country": "IN"},
    ],
    "ORDER": [
        {"status": "paid", "amount": 120, "placed": "2026-10-02T09:00:00Z", "customer": "Acme"},
        {"status": "refunded_full", "amount": 80, "placed": "2026-10-05T10:00:00Z", "customer": "Acme"},
        {"status": "paid", "amount": "45.50", "placed": "2026-10-06T11:00:00Z", "customer": "Globex"},
        {"status": "pending", "amount": 300, "placed": "2026-10-09T12:00:00Z", "customer": "Initech"},
        {"status": "refunded_partial", "amount": 60, "placed": "2026-10-11T13:00:00Z", "customer": "Initech"},
    ],
}
DATETIME_PROPS = {("ORDER", "placed")}
READ_OPS = {"query", "describe", "backup"}


def _type(label, prop, value):
    if (label, prop) in DATETIME_PROPS:
        return "datetime"
    if isinstance(value, bool):
        return "boolean"
    return "number" if isinstance(value, (int, float)) else "string"


def _unb64(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class FakeRushDB:
    def __init__(self, token="boot-token", secret_hex="00112233445566778899aabbccddeeff"):
        self.token, self.secret = token, bytes.fromhex(secret_hex)
        self.requests = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                outer.requests.append(body)
                status, reply = outer.handle(self.headers, body)
                raw = json.dumps(reply).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    # --- auth, as in docs/manual/operations/security.md --------------------------------------------------------
    def permissions(self, headers):
        token = headers.get("X-RushDB-Token") or headers.get("Authorization", "").removeprefix("Bearer ")
        if hmac.compare_digest(token.encode(), self.token.encode()):
            return {"read", "write"}
        try:
            claims_b64, sig_b64 = token.split(".")
            expected = hmac.new(self.secret, claims_b64.encode(), hashlib.sha256).digest()
            if not hmac.compare_digest(expected, _unb64(sig_b64)):
                return None
            claims = json.loads(_unb64(claims_b64))
        except (ValueError, json.JSONDecodeError):
            return None
        if claims.get("exp", 0) <= time.time() or "tenant" in claims:
            return None  # expired, or a tenant claim on a single-tenant server
        words = set(claims.get("scope", "").split())
        return {"read", "write"} if "*" in words else words

    def handle(self, headers, body):
        perms = self.permissions(headers)
        if perms is None:
            return 401, {"error": "unauthorized"}
        op = body["operation"]
        need = "read" if op["kind"] in READ_OPS else "write"
        if need not in perms:
            return 401, {"error": "unauthorized"}
        try:
            return 200, {"protocolVersion": 1, "serverTimingMs": 0, "response": self.run(op)}
        except KeyError as exc:
            return 400, {"protocolVersion": 1, "error": {"code": "invalid_request", "message": str(exc),
                                                         "retryable": False}}

    # --- operations ------------------------------------------------------------------------------------------
    def run(self, op):
        if op["kind"] == "describe":
            d = op["describe"]
            if d["kind"] == "labels":
                return {"kind": "labels", "labels": sorted(DATA)}
            if d["kind"] == "schema":
                labels = d["query"].get("labels") or sorted(DATA)
                props = {}
                for label in labels:
                    for rec in DATA.get(label, []):
                        for prop, value in rec.items():
                            key = (prop, _type(label, prop, value))
                            props[key] = props.get(key, 0) + 1
                return {"kind": "schema", "schema": {
                    "labels": [{"name": l, "recordsCount": len(DATA[l])} for l in labels if l in DATA],
                    "properties": [{"id": f"p{i:016x}", "name": n, "type": t, "recordsCount": c, "isArray": False}
                                   for i, ((n, t), c) in enumerate(sorted(props.items()))],
                    "relationships": []}}
        if op["kind"] == "query":
            q = op["query"]
            if q["kind"] == "propertyValues":
                return self.property_values(q)
            if q["kind"] == "records":
                return self.records(q["query"])
        raise KeyError(f"unsupported operation in the fake: {op['kind']}")

    def property_values(self, q):
        label = q["query"]["labels"][0]
        want = q["property"].lower()  # the fake's names are lower-case ASCII, so this is RushDB's normalisation
        counts = {}
        for rec in DATA.get(label, []):
            for prop, value in rec.items():
                if prop == want:
                    counts[value] = counts.get(value, 0) + 1
        search = q.get("search")
        if search:
            text, match = search["text"], search.get("match", "contains")
            fold = (lambda s: s) if search.get("caseSensitive") else str.lower

            def hit(v):
                s, t = fold(str(v)), fold(text)
                if match == "exact":
                    return s == t
                if match == "prefix":
                    return s.startswith(t)
                if match == "similar":
                    return difflib.SequenceMatcher(None, s, t).ratio() >= search.get("minSimilarity", 0.6)
                return t in s

            matched = {v: c for v, c in counts.items() if hit(v)}
            if not matched and search.get("domainOnMiss") and len(counts) <= search["domainOnMiss"]:
                matched = counts
            counts = matched
        ordered = sorted(counts.items(), key=lambda kv: (-kv[1], str(kv[0])))[: q.get("limit", 10)]
        reply = {"kind": "propertyValues", "property": q["property"], "distinctCount": len(counts)}
        if q.get("mode") != "count":
            reply["values"] = [v for v, _ in ordered]
        if q.get("mode") == "topK":
            reply["counts"] = [c for _, c in ordered]
        return reply

    def records(self, query):
        label = query["labels"][0]

        def ok(rec, pred):
            for key, cond in pred.items():
                if key == "CUSTOMER":  # the one related block the fake understands
                    owner = [c for c in DATA["CUSTOMER"] if c["name"] == rec.get("customer")]
                    if not owner or not ok(owner[0], cond):
                        return False
                elif isinstance(cond, dict):
                    value = rec.get(key)
                    if "$in" in cond and value not in cond["$in"]:
                        return False
                    if "$eq" in cond and value != cond["$eq"]:
                        return False
                elif isinstance(cond, list):
                    if rec.get(key) not in cond:
                        return False
                elif rec.get(key) != cond:
                    return False
            return True

        hits = [r for r in DATA[label] if ok(r, query.get("predicate", {}))]
        return {"kind": "records", "total": len(hits),
                "records": [{"id": f"id-{i}", "label": label, "properties": r}
                            for i, r in enumerate(hits[: query.get("limit", 100)])]}
