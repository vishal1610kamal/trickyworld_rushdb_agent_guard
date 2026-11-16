#!/usr/bin/env python3
"""rushdb_guard: give an AI agent a read-only RushDB token, and check its filters against the catalog before they run.

RushDB 3 answers a filter on a value it does not store with zero rows, not an error, so an agent that guesses
"Enterprise" for a stored "enterprise" reports "no results" and moves on. This module reads RushDB's schema catalog
(describe.schema, propertyValues) and refuses a records query whose filter cannot match, with the stored spellings
the agent should use instead.

Python 3.10+, standard library only. Talks to the native protocol: POST /protocol/v1/execute.
"""
from __future__ import annotations

import argparse
import base64
import difflib
import hashlib
import hmac
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

LOGIC = {"$and", "$or", "$nor"}
IGNORED_KEYS = {"$id", "$relation", "$alias"}
SCOPES = {"read", "write", "*"}
MAX_TTL = 24 * 3600
ISO_DATE = re.compile(r"^-?\d{4}-\d{2}-\d{2}([Tt ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?([Zz]|[+-]\d{2}:\d{2})?)?$")


# --- capability tokens -------------------------------------------------------------------------------------------

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def mint_token(secret_hex: str, scope: str = "read", tenant: str | None = None, ttl: int = 900,
               sub: str = "agent", now: int | None = None) -> str:
    """Sign a capability token in RushDB's format: base64url(claims) "." base64url(HMAC-SHA256(secret, claims))."""
    try:
        secret = bytes.fromhex(secret_hex)
    except ValueError as exc:
        raise ValueError("the capability secret must be hex, as given to --capability-secret") from exc
    if len(secret) < 16:
        raise ValueError("the capability secret must be at least 16 bytes (32 hex characters)")
    words = scope.split()
    if not words or not set(words) <= SCOPES:
        raise ValueError(f"scope must be space-separated words from {sorted(SCOPES)}")
    if not 0 < ttl <= MAX_TTL:
        raise ValueError(f"ttl must be between 1 and {MAX_TTL} seconds")
    issued = int(time.time()) if now is None else now
    claims = {"sub": sub, "scope": " ".join(words), "iat": issued, "exp": issued + ttl}
    if tenant:
        claims["tenant"] = tenant
    body = _b64url(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode())
    signature = hmac.new(secret, body.encode("ascii"), hashlib.sha256).digest()
    return f"{body}.{_b64url(signature)}"


# --- client ------------------------------------------------------------------------------------------------------

class RushDBError(Exception):
    def __init__(self, status: int, code: str, message: str = ""):
        super().__init__(f"{status} {code}: {message}".rstrip(": "))
        self.status, self.code, self.message = status, code, message


class RushDB:
    """A minimal client for the native protocol of a RushDB 3 engine."""

    def __init__(self, url: str, token: str, tenant: str | None = None, timeout: float = 15):
        self.endpoint = url.rstrip("/") + "/protocol/v1/execute"
        self.token, self.tenant, self.timeout = token, tenant, timeout

    def execute(self, operation: dict) -> dict:
        envelope: dict = {"protocolVersion": 1, "operation": operation}
        headers = {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}
        if self.tenant:
            envelope["context"] = {"scope": self.tenant}
            headers["X-RushDB-Tenant"] = self.tenant
        request = urllib.request.Request(self.endpoint, json.dumps(envelope).encode(), headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as reply:
                return json.load(reply)["response"]
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                error = json.loads(raw).get("error")
            except ValueError:
                error = raw.decode(errors="replace")[:200]
            if isinstance(error, dict):
                raise RushDBError(exc.code, error.get("code", "error"), error.get("message", "")) from None
            raise RushDBError(exc.code, str(error or "error")) from None

    def labels(self) -> list[str]:
        return self.execute({"kind": "describe", "describe": {"kind": "labels", "query": {}}})["labels"]

    def properties(self, label: str) -> list[dict]:
        """Catalog entries (name, type, recordsCount) for one label, without reading records."""
        op = {"kind": "describe", "describe": {"kind": "schema", "query": {"labels": [label]}, "detail": "catalog"}}
        return self.execute(op)["schema"]["properties"]

    def search_values(self, label: str, prop: str, text: str, match: str, *, mode: str = "topK", limit: int = 5,
                      case_sensitive: bool = False, **extra) -> dict:
        search = {"text": text, "match": match, "caseSensitive": case_sensitive, **extra}
        op = {"kind": "query", "query": {"kind": "propertyValues", "property": prop, "mode": mode, "limit": limit,
                                         "search": search, "query": {"labels": [label]}}}
        return self.execute(op)

    def find(self, label: str, predicate: dict, limit: int = 20) -> dict:
        query = {"labels": [label], "predicate": predicate, "limit": limit}
        return self.execute({"kind": "query", "query": {"kind": "records", "query": query}})


# --- the guard ---------------------------------------------------------------------------------------------------

def normalise(name: str) -> str:
    """RushDB's property-name folding: ASCII letters to lower case, letters and digits kept, the rest to '_'."""
    return "".join(c.lower() if c.isascii() and c.isalpha() else c if c.isalnum() else "_" for c in name)


@dataclass
class Problem:
    path: str
    message: str
    suggestions: list = field(default_factory=list)
    blocking: bool = True

    def as_dict(self) -> dict:
        return {"path": self.path, "message": self.message, "suggestions": self.suggestions,
                "blocking": self.blocking}


class Guard:
    """Checks a SearchQuery predicate against what the tenant actually stores."""

    def __init__(self, db: RushDB):
        self.db = db
        self._labels: list[str] | None = None
        self._props: dict[str, dict[str, set]] = {}
        self._names: dict[str, dict[str, str]] = {}

    def _all_labels(self) -> list[str]:
        if self._labels is None:
            self._labels = self.db.labels()
        return self._labels

    def _close_labels(self, label: str) -> list[str]:
        """Labels are case-sensitive, so 'Order' for a stored 'ORDER' is the usual miss: compare case-folded."""
        folded = {name.lower(): name for name in self._all_labels()}
        return [folded[m] for m in difflib.get_close_matches(label.lower(), list(folded), n=3, cutoff=0.5)]

    def _types(self, label: str) -> dict[str, set]:
        """normalised property name -> set of stored display types on this label."""
        if label not in self._props:
            types: dict[str, set] = {}
            names: dict[str, str] = {}
            for entry in self.db.properties(label):
                if entry.get("label", label) == label and entry.get("type") != "null":
                    types.setdefault(normalise(entry["name"]), set()).add(entry["type"])
                    names.setdefault(normalise(entry["name"]), entry["name"])
            self._props[label], self._names[label] = types, names
        return self._props[label]

    def check(self, label: str, predicate: dict) -> list[Problem]:
        if label not in self._all_labels():
            return [Problem(label, f"no records carry the label '{label}' (labels are case-sensitive)",
                            self._close_labels(label))]
        problems: list[Problem] = []
        self._walk(label, predicate, label, problems)
        return problems

    def _walk(self, label: str, predicate: dict, path: str, out: list[Problem]) -> None:
        for key, value in predicate.items():
            here = f"{path}.{key}"
            if key in LOGIC and isinstance(value, list):
                for i, part in enumerate(value):
                    if isinstance(part, dict):
                        self._walk(label, part, f"{here}[{i}]", out)
            elif key in ("$not", "$xor"):
                parts = value if isinstance(value, list) else [value]
                for i, part in enumerate(parts):
                    if isinstance(part, dict):
                        self._walk(label, part, f"{here}[{i}]", out)
            elif key.startswith("$"):
                continue  # $id, $relation, $alias, or an operator the server itself will reject
            elif isinstance(value, dict) and value and not all(k.startswith("$") for k in value):
                self._related(key, value, here, out)
            else:
                self._condition(label, key, value, here, out)

    def _related(self, label: str, block: dict, path: str, out: list[Problem]) -> None:
        if label not in self._all_labels():
            out.append(Problem(path, f"no label '{label}' to traverse to (labels are case-sensitive)",
                               self._close_labels(label)))
            return
        self._walk(label, {k: v for k, v in block.items() if k not in IGNORED_KEYS}, path, out)

    def _condition(self, label: str, prop: str, value, path: str, out: list[Problem]) -> None:
        types = self._types(label).get(normalise(prop))
        if types is None:
            names = list(self._types(label))
            close = difflib.get_close_matches(normalise(prop), names, n=3, cutoff=0.5)
            out.append(Problem(path, f"'{label}' records have no property '{prop}'; the filter would match nothing",
                               close))
            return
        if len(types) > 1:
            out.append(Problem(path, f"'{prop}' is stored as {' and '.join(sorted(types))} on '{label}'; a filter "
                                     "only matches values of its own type", blocking=False))
        stored_name = self._names[label][normalise(prop)]
        for literal in _equality_literals(value):
            self._literal(label, stored_name, literal, types, path, out)

    def _literal(self, label: str, prop: str, literal, types: set, path: str, out: list[Problem]) -> None:
        if isinstance(literal, bool) or not isinstance(literal, (str, int, float)):
            return
        if isinstance(literal, str):
            if "string" not in types:
                if "datetime" in types and ISO_DATE.match(literal):
                    return  # RushDB 3.0.10 compares an ISO string with a stored datetime as an instant
                hint = " (datetimes are compared as ISO 8601 text, e.g. 2026-10-02T09:00:00Z)" \
                    if "datetime" in types else ""
                out.append(Problem(path, f"'{prop}' is stored as {'/'.join(sorted(types))}; the text "
                                         f"'{literal}' never equals it{hint}"))
                return
            # Value search matches numbers by how they render ("120" finds 120), so look at each hit's JSON type.
            hits = self.db.search_values(label, prop, literal, "exact", mode="values", limit=10,
                                         case_sensitive=True).get("values", [])
            if any(isinstance(v, str) and v == literal for v in hits):
                return
            out.append(Problem(path, f"'{prop}' stores no '{literal}'", self._closest(label, prop, literal)))
        elif "number" not in types:
            out.append(Problem(path, f"'{prop}' is stored as {'/'.join(sorted(types))}; the number {literal} "
                                     "never equals it"))

    def _closest(self, label: str, prop: str, literal: str) -> list:
        reply = self.db.search_values(label, prop, literal, "similar", minSimilarity=0.5, domainOnMiss=30)
        values = reply.get("values", [])
        exact_ci = [v for v in values if isinstance(v, str) and v.lower() == literal.lower()]
        return exact_ci or values


def _equality_literals(value):
    """Yield every value a condition compares by equality: plain values, lists, $eq, $ne, $in, $nin."""
    if isinstance(value, list):
        yield from value
    elif isinstance(value, dict):
        for op, operand in value.items():
            if op in ("$eq", "$ne"):
                yield operand
            elif op in ("$in", "$nin") and isinstance(operand, list):
                yield from operand
            elif op in ("$and", "$or", "$nor") and isinstance(operand, list):
                for part in operand:
                    if isinstance(part, dict) and all(k.startswith("$") for k in part):
                        yield from _equality_literals(part)
            elif op == "$not" and isinstance(operand, dict):
                yield from _equality_literals(operand)
    elif value is not None:
        yield value


def guarded_find(db: RushDB, label: str, predicate: dict, limit: int = 20, guard: Guard | None = None) -> dict:
    """The tool an agent calls: refuse a query that cannot match, with suggestions; otherwise run it."""
    problems = (guard or Guard(db)).check(label, predicate)
    blocking = [p for p in problems if p.blocking]
    result: dict = {"ok": not blocking, "problems": [p.as_dict() for p in problems]}
    if blocking:
        return result
    reply = db.find(label, predicate, limit)
    result.update(total=reply.get("total"), records=[r.get("properties", r) for r in reply.get("records", [])])
    return result


# --- command line ------------------------------------------------------------------------------------------------

def _env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        sys.exit(f"set {name} first")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    tok = sub.add_parser("token", help="mint a capability token (reads RUSHDB_CAPABILITY_SECRET)")
    tok.add_argument("--scope", default="read")
    tok.add_argument("--tenant")
    tok.add_argument("--ttl", type=int, default=900)
    tok.add_argument("--sub", default="agent")
    for name in ("check", "find"):
        cmd = sub.add_parser(name, help=f"{name} a filter (reads RUSHDB_URL, RUSHDB_TOKEN, optional RUSHDB_TENANT)")
        cmd.add_argument("--label", required=True)
        cmd.add_argument("--where", required=True, help="the predicate, as JSON")
        cmd.add_argument("--limit", type=int, default=20)
    args = parser.parse_args(argv)

    try:
        if args.command == "token":
            print(mint_token(_env("RUSHDB_CAPABILITY_SECRET"), args.scope, args.tenant, args.ttl, args.sub))
            return 0
        db = RushDB(_env("RUSHDB_URL"), _env("RUSHDB_TOKEN"), os.environ.get("RUSHDB_TENANT"))
        predicate = json.loads(args.where)
        if args.command == "check":
            problems = Guard(db).check(args.label, predicate)
            print(json.dumps({"ok": not any(p.blocking for p in problems),
                              "problems": [p.as_dict() for p in problems]}, indent=2, ensure_ascii=False))
            return 1 if any(p.blocking for p in problems) else 0
        result = guarded_find(db, args.label, predicate, args.limit)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0 if result["ok"] else 1
    except (RushDBError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
