# rushdb_guard: stop an AI agent's empty answers before they happen

A RushDB filter on a value the database does not store returns zero rows, not an error. An agent that writes
`{"status": "Paid"}` when the data says `paid`, or `"Enterprise"` for `enterprise`, gets an empty result and
reports "no orders found" as if it were true.

`rushdb_guard.py` puts a check in front of the agent's queries. It reads RushDB's schema catalog (the labels,
properties, types and stored values the engine keeps up to date on every write) and refuses a query whose filter
cannot match, returning the spellings that are actually stored. It also mints the short-lived, read-only capability
token the agent should use, so the agent can read but never write.

This is the code from the TrickyWorld article
[RushDB 3.0 review: use cases, pros and cons](https://www.trickyworld.in/artificial-intelligence-machine-learning/ai-agents/rushdb-review-ai-agent-database/).

One file, Python 3.10 or newer, standard library only. Tested against RushDB 3.0.10.

## What it catches

| The agent writes | What RushDB returns | What the guard says |
|---|---|---|
| `{"status": "Paid"}` | 0 rows | `'status' stores no 'Paid'`, suggestions `["paid"]` |
| `{"status": "refunded"}` | 0 rows | suggestions `["refunded_full", "refunded_partial"]` |
| `{"state": "paid"}` | 0 rows | `'ORDER' records have no property 'state'`, suggestions `["status"]` |
| label `Order` for `ORDER` | 0 rows | no such label, suggestions `["ORDER"]` (labels are case-sensitive) |
| `{"amount": "120"}` when amounts are numbers | 0 rows | `'amount' stores no '120'`, suggestions `[120]` |
| `{"placed": "2 October 2026"}` on a datetime | 0 rows | stored as datetime; use ISO 8601 text |
| `{"CUSTOMER": {"plan": "Enterprise"}}` (a related record) | 0 rows | checked the same way, path `ORDER.CUSTOMER.plan` |

It walks `$and`, `$or`, `$nor`, `$not`, `$xor`, related-record blocks, plain values, lists, `$eq`, `$ne`, `$in` and
`$nin`. Property names are matched the way RushDB matches them (`FirstName` and `firstname` are one property). A
property stored with two types (some services send `amount` as text) produces a non-blocking warning.

## Use it

Start RushDB with a capability secret, so you can hand out scoped tokens instead of the boot token:

```bash
export RUSHDB_CAPABILITY_SECRET=$(openssl rand -hex 32)
RUSHDB_TOKEN=$(openssl rand -hex 32) rushdb serve --data-dir ./data --capability-secret "$RUSHDB_CAPABILITY_SECRET"
```

Mint a read-only token for the agent (15 minutes by default), then check or run a filter:

```bash
export RUSHDB_URL=http://127.0.0.1:3000
export RUSHDB_TOKEN=$(python3 rushdb_guard.py token --scope read --ttl 900 --sub support-agent)

python3 rushdb_guard.py check --label ORDER --where '{"status": "Paid"}'      # exit 1, with suggestions
python3 rushdb_guard.py find  --label ORDER --where '{"status": "paid"}'      # checks, then runs; exit 0
```

`--tenant` (or `RUSHDB_TENANT`) selects a tenant on a multitenant server. Exit codes: `0` clean, `1` the filter
cannot match, `2` an error (bad token, server unreachable).

In an agent, expose `guarded_find()` as the query tool. It returns `{"ok": false, "problems": [...]}` with the
stored spellings when a filter cannot match, so the model can retry with real values, and the records when it can:

```python
import rushdb_guard as g

db = g.RushDB("http://127.0.0.1:3000", token)   # a read-only capability token
guard = g.Guard(db)                               # caches the catalog for the session
result = g.guarded_find(db, "ORDER", {"status": "Paid"}, guard=guard)
```

## Tests

```bash
python3 -m unittest discover -s tests -v
```

15 tests run offline against `tests/fake_rushdb.py`, a stand-in that follows the request and response shapes in
RushDB's manual. 5 more in `tests/test_live.py` run against a real node when these are set (use a scratch node: the
test loads `examples/orders.json`):

```bash
RUSHDB_LIVE_URL=http://127.0.0.1:3000 RUSHDB_LIVE_TOKEN=<boot token> RUSHDB_CAPABILITY_SECRET=<hex> \
  python3 -m unittest discover -s tests -v
```

All 20 passed on 16 November 2026 against the RushDB 3.0.10 Linux x86-64 release (SHA-256 and Sigstore signature
checked), on Python 3.10.12, 3.11 and 3.12.12.

## What the live run showed

- A read-only capability token is refused on writes over HTTP (`401 {"error":"unauthorized"}`) and over the
  PostgreSQL wire (`the session's credential does not grant write`).
- RushDB's filtering page says a plain ISO string does not match a datetime property unless you write `$eq`. On
  3.0.10 it does match: `{"placed": "2026-10-02T09:00:00Z"}` and `{"$in": [...]}` both found the record. The guard
  follows the engine, not the page.
- Value search matches numbers by how they render, so searching the text `"120"` finds the number `120`. The guard
  checks the JSON type of each hit, because the filter `{"amount": "120"}` matches nothing.

## Limits

- It checks names and equality values. It does not check ranges, `$contains`, vector or text search, or whether
  the question means what the filter says ("active customer" is a business definition no catalog holds).
- It uses `propertyValues` value search, which reads RushDB's value dictionaries. Text values over 96 bytes are kept
  out of those and read from the records instead; that path was not tested here.
- A clean check means the filter can match, not that the answer is right. Keep running the query and reading the
  result.
