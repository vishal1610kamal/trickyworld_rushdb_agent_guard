import base64
import contextlib
import hashlib
import hmac
import io
import json
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

import rushdb_guard as g  # noqa: E402
from fake_rushdb import FakeRushDB  # noqa: E402

SECRET = "00112233445566778899aabbccddeeff"


def unb64(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class TokenTests(unittest.TestCase):
    def test_format_and_signature(self):
        token = g.mint_token(SECRET, "read", ttl=600, sub="report-bot", now=1_700_000_000)
        claims_b64, sig_b64 = token.split(".")
        self.assertNotIn("=", token)
        expected = hmac.new(bytes.fromhex(SECRET), claims_b64.encode(), hashlib.sha256).digest()
        self.assertEqual(unb64(sig_b64), expected)
        claims = json.loads(unb64(claims_b64))
        self.assertEqual(claims, {"sub": "report-bot", "scope": "read", "iat": 1_700_000_000, "exp": 1_700_000_600})

    def test_tenant_claim_only_when_given(self):
        claims = json.loads(unb64(g.mint_token(SECRET, tenant="acme").split(".")[0]))
        self.assertEqual(claims["tenant"], "acme")

    def test_rejects_bad_input(self):
        for kwargs in ({"secret_hex": "abcd"}, {"secret_hex": "zz" * 16}, {"secret_hex": SECRET, "scope": "admin"},
                       {"secret_hex": SECRET, "ttl": 0}, {"secret_hex": SECRET, "ttl": 90_000}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                g.mint_token(**kwargs)


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fake = FakeRushDB(secret_hex=SECRET)

    @classmethod
    def tearDownClass(cls):
        cls.fake.close()

    def setUp(self):
        self.fake.requests.clear()
        self.db = g.RushDB(self.fake.url, g.mint_token(SECRET, "read"))
        self.guard = g.Guard(self.db)

    def check(self, predicate, label="ORDER"):
        return self.guard.check(label, predicate)

    # tokens against the server
    def test_read_only_token_cannot_write(self):
        self.assertIn("ORDER", self.db.labels())
        with self.assertRaises(g.RushDBError) as err:
            self.db.execute({"kind": "ingest", "ingest": {"kind": "documents", "label": "X", "documents": {"a": 1}}})
        self.assertEqual((err.exception.status, err.exception.code), (401, "unauthorized"))

    def test_expired_token_is_refused(self):
        stale = g.RushDB(self.fake.url, g.mint_token(SECRET, "read", ttl=60, now=int(time.time()) - 120))
        with self.assertRaises(g.RushDBError) as err:
            stale.labels()
        self.assertEqual(err.exception.status, 401)

    # the guard
    def test_stored_value_passes(self):
        self.assertEqual(self.check({"status": "paid"}), [])

    def test_wrong_case_is_caught_with_the_stored_spelling(self):
        [p] = self.check({"status": "Paid"})
        self.assertTrue(p.blocking)
        self.assertEqual(p.suggestions, ["paid"])

    def test_unstored_value_lists_close_values(self):
        [p] = self.check({"status": "refunded"})
        self.assertIn("stores no 'refunded'", p.message)
        self.assertEqual(set(p.suggestions), {"refunded_full", "refunded_partial"})

    def test_unknown_property_and_label(self):
        [p] = self.check({"state": "paid"})
        self.assertEqual(p.suggestions, ["status"])
        [p] = self.check({"status": "paid"}, label="Order")
        self.assertEqual(p.suggestions, ["ORDER"])

    def test_property_names_are_normalised_like_rushdb(self):
        self.assertEqual(g.normalise("FirstName"), "firstname")
        self.assertEqual(g.normalise("first-name"), "first_name")
        self.assertEqual(self.check({"STATUS": "paid"}), [])

    def test_datetimes(self):
        # RushDB 3.0.10 matched an ISO string against a datetime with or without $eq (checked on a live node).
        for predicate in ({"placed": "2026-10-02T09:00:00Z"}, {"placed": {"$eq": "2026-10-02T09:00:00Z"}},
                          {"placed": {"$in": ["2026-10-02", "2026-10-05T10:00:00"]}}):
            with self.subTest(predicate=predicate):
                self.assertEqual(self.check(predicate), [])
        [p] = self.check({"placed": "2 October 2026"})
        self.assertIn("ISO 8601", p.message)

    def test_type_mismatches(self):
        problems = self.check({"amount": "120"})
        self.assertEqual([p.blocking for p in problems], [False, True])  # mixed types warning, then the miss
        self.assertIn("number and string", problems[0].message)
        [p] = self.check({"country": 91}, label="CUSTOMER")
        self.assertIn("never equals", p.message)

    def test_related_block_and_logic(self):
        [p] = self.check({"CUSTOMER": {"plan": "Enterprise"}})
        self.assertEqual(p.path, "ORDER.CUSTOMER.plan")
        self.assertEqual(p.suggestions, ["enterprise"])
        problems = self.check({"$or": [{"status": {"$in": ["paid", "cancelled"]}}, {"amount": {"$gte": 100}}]})
        [p] = [p for p in problems if p.blocking]
        self.assertEqual(p.path, "ORDER.$or[0].status")
        self.assertIn("cancelled", p.message)
        [p] = self.check({"Customer": {"plan": "pro"}})
        self.assertEqual(p.suggestions, ["CUSTOMER"])

    def test_guarded_find_runs_only_clean_queries(self):
        ok = g.guarded_find(self.db, "ORDER", {"status": "paid", "CUSTOMER": {"plan": "enterprise"}})
        self.assertTrue(ok["ok"])
        self.assertEqual(ok["total"], 1)
        self.fake.requests.clear()
        refused = g.guarded_find(self.db, "ORDER", {"status": "Paid"})
        self.assertFalse(refused["ok"])
        self.assertNotIn("records", refused)
        kinds = [r["operation"].get("query", {}).get("kind") for r in self.fake.requests]
        self.assertNotIn("records", kinds)

    def test_cli(self):
        env = {"RUSHDB_URL": self.fake.url, "RUSHDB_TOKEN": self.db.token, "RUSHDB_CAPABILITY_SECRET": SECRET}
        old = {k: os.environ.get(k) for k in env}
        os.environ.update(env)
        try:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = g.main(["check", "--label", "ORDER", "--where", '{"status": "Paid"}'])
            self.assertEqual(code, 1)
            self.assertEqual(json.loads(out.getvalue())["problems"][0]["suggestions"], ["paid"])
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(g.main(["token", "--ttl", "60"]), 0)
            self.assertEqual(out.getvalue().count("."), 1)
        finally:
            for k, v in old.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v


if __name__ == "__main__":
    unittest.main()
