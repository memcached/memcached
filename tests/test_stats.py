"""
test_stats.py - Test server statistics reporting.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from memcached_harness import MemcachedServer


class TestStats(unittest.TestCase):
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

    def test_general_stats(self):
        st = self.mc.stats()
        self.assertIn("pid", st)
        self.assertIn("uptime", st)
        self.assertIn("time", st)
        self.assertIn("version", st)
        self.assertIn("curr_items", st)
        self.assertIn("total_items", st)
        self.assertIn("bytes", st)
        self.assertIn("curr_connections", st)
        self.assertIn("total_connections", st)
        self.assertIn("cmd_get", st)
        self.assertIn("cmd_set", st)

    def test_settings_stats(self):
        st = self.mc.stats("settings")
        self.assertIn("maxconns", st)
        self.assertIn("tcpport", st)
        self.assertIn("udpport", st)
        self.assertIn("inter", st)
        self.assertIn("verbosity", st)
        self.assertIn("oldest", st)

    def test_items_and_slabs_stats(self):
        self.mc.set("stat_key", "stat_val")
        items_st = self.mc.stats("items")
        self.assertIsInstance(items_st, dict)

        slabs_st = self.mc.stats("slabs")
        self.assertIsInstance(slabs_st, dict)
        self.assertIn("active_slabs", slabs_st)


if __name__ == "__main__":
    unittest.main()
