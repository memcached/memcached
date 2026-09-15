"""
test_basic.py - Test core memcached protocol operations.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from memcached_harness import MemcachedServer


class TestBasicProtocol(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = MemcachedServer().start()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def setUp(self):
        self.mc = self.server.client()

    def tearDown(self):
        self.mc.close()

    def test_version(self):
        v = self.mc.version()
        self.assertTrue(len(v) > 0)
        self.assertTrue("1.6" in v or "1." in v)

    def test_set_and_get(self):
        res = self.mc.set("foo", "fooval")
        self.assertEqual(res, "STORED")

        data = self.mc.get("foo")
        self.assertIn("foo", data)
        self.assertEqual(data["foo"][0], "fooval")

    def test_multiget(self):
        self.mc.set("k1", "v1")
        self.mc.set("k2", "v2")
        self.mc.set("k3", "v3")

        data = self.mc.get("k1", "k2", "k3", "nonexistent")
        self.assertEqual(data.get("k1", (None,))[0], "v1")
        self.assertEqual(data.get("k2", (None,))[0], "v2")
        self.assertEqual(data.get("k3", (None,))[0], "v3")
        self.assertNotIn("nonexistent", data)

    def test_add_and_replace(self):
        # Adding non-existing key should store
        self.mc.delete("add_key")
        res = self.mc.add("add_key", "initial_val")
        self.assertEqual(res, "STORED")

        # Adding existing key should fail
        res = self.mc.add("add_key", "new_val")
        self.assertEqual(res, "NOT_STORED")

        # Replace existing key should store
        res = self.mc.replace("add_key", "replaced_val")
        self.assertEqual(res, "STORED")
        self.assertEqual(self.mc.get("add_key")["add_key"][0], "replaced_val")

        # Replace non-existing key should fail
        self.mc.delete("nonexistent_replace")
        res = self.mc.replace("nonexistent_replace", "val")
        self.assertEqual(res, "NOT_STORED")

    def test_delete(self):
        self.mc.set("del_key", "del_val")
        res = self.mc.delete("del_key")
        self.assertEqual(res, "DELETED")

        # Second delete should be NOT_FOUND
        res = self.mc.delete("del_key")
        self.assertEqual(res, "NOT_FOUND")

    def test_append_prepend(self):
        self.mc.set("ap_key", "middle")
        res = self.mc.append("ap_key", "_end")
        self.assertEqual(res, "STORED")

        res = self.mc.prepend("ap_key", "start_")
        self.assertEqual(res, "STORED")

        data = self.mc.get("ap_key")
        self.assertEqual(data["ap_key"][0], "start_middle_end")

    def test_incr_decr(self):
        self.mc.set("num_key", "10")
        self.assertEqual(self.mc.incr("num_key", 5), 15)
        self.assertEqual(self.mc.decr("num_key", 3), 12)
        # Underflow stays at 0
        self.assertEqual(self.mc.decr("num_key", 100), 0)

    def test_stats(self):
        s = self.mc.stats()
        self.assertIn("version", s)
        self.assertIn("curr_connections", s)
        self.assertIn("cmd_get", s)
        self.assertIn("cmd_set", s)

    def test_flush_all(self):
        self.mc.set("flush_me", "data")
        self.assertIn("flush_me", self.mc.get("flush_me"))

        res = self.mc.flush_all()
        self.assertEqual(res, "OK")
        self.assertNotIn("flush_me", self.mc.get("flush_me"))


if __name__ == "__main__":
    unittest.main()
