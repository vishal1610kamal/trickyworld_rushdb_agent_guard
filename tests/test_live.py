"""The same checks against a real RushDB 3 node. Skipped unless these are set:

    RUSHDB_LIVE_URL            e.g. http://127.0.0.1:3000 (use a scratch node: this test writes the demo data)
    RUSHDB_LIVE_TOKEN          the node's boot token, used only to load examples/orders.json
    RUSHDB_CAPABILITY_SECRET   the hex secret the node was started with (--capability-secret)
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import rushdb_guard as g  # noqa: E402

URL, BOOT, SECRET = (os.environ.get(k) for k in ("RUSHDB_LIVE_URL", "RUSHDB_LIVE_TOKEN", "RUSHDB_CAPABILITY_SECRET"))
DEMO = os.path.join(os.path.dirname(__file__), "..", "examples", "orders.json")


@unittest.skipUnless(URL and BOOT and SECRET, "set RUSHDB_LIVE_URL, RUSHDB_LIVE_TOKEN and RUSHDB_CAPABILITY_SECRET")
class LiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        admin = g.RushDB(URL, BOOT)
        if "CUSTOMER" not in admin.labels():
            with open(DEMO) as fh:
                documents = json.load(fh)
            admin.execute({"kind": "ingest", "ingest": {"kind": "documents", "label": "CUSTOMER",
                                                        "documents": documents}})
        cls.db = g.RushDB(URL, g.mint_token(SECRET, "read", ttl=300, sub="live-test"))

    def setUp(self):
        self.guard = g.Guard(self.db)

    def blocking(self, predicate, label="ORDER"):
        return [p for p in self.guard.check(label, predicate) if p.blocking]

    def test_read_token_cannot_write(self):
        with self.assertRaises(g.RushDBError) as err:
            self.db.execute({"kind": "ingest", "ingest": {"kind": "documents", "label": "X", "documents": {"a": 1}}})
        self.assertEqual(err.exception.status, 401)

    def test_catches_what_returns_zero_rows(self):
        for predicate in ({"status": "Paid"}, {"status": "refunded"}, {"state": "paid"}, {"amount": "120"},
                          {"placed": "2 October 2026"}, {"CUSTOMER": {"plan": "Enterprise"}}):
            with self.subTest(predicate=predicate):
                self.assertEqual(self.db.find("ORDER", predicate)["total"], 0)  # the silent empty answer
                self.assertTrue(self.blocking(predicate))

    def test_lets_through_what_matches(self):
        for predicate in ({"status": "paid"}, {"amount": 120}, {"amount": "45.50"},
                          {"placed": "2026-10-02T09:00:00Z"}, {"placed": {"$in": ["2026-10-02T09:00:00Z"]}}):
            with self.subTest(predicate=predicate):
                self.assertGreater(self.db.find("ORDER", predicate)["total"], 0)
                self.assertEqual(self.blocking(predicate), [])

    def test_suggestions(self):
        self.assertEqual(self.blocking({"status": "Paid"})[0].suggestions, ["paid"])
        self.assertEqual(set(self.blocking({"status": "refunded"})[0].suggestions),
                         {"refunded_full", "refunded_partial"})
        self.assertEqual(self.blocking({"status": "paid"}, label="Order")[0].suggestions, ["ORDER"])

    def test_clean_queries_run(self):
        result = g.guarded_find(self.db, "ORDER", {"status": "paid", "CUSTOMER": {"plan": "enterprise"}})
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["total"], 1)
        self.assertEqual(self.db.find("ORDER", {"placed": {"$eq": "2026-10-02T09:00:00Z"}})["total"], 1)


if __name__ == "__main__":
    unittest.main()
