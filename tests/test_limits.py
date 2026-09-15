"""
test_limits.py - Test item size limits and maximum key lengths.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from memcached_harness import MemcachedServer


class TestLimits(unittest.TestCase):
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

    def test_max_key_length(self):
        # Memcached default max key length is 250 bytes
        max_key = "k" * 250
        res = self.mc.set(max_key, "val")
        self.assertEqual(res, "STORED")
        self.assertEqual(self.mc.get(max_key)[max_key][0], "val")

        # Exceeding 250 bytes should be rejected
        too_long_key = "k" * 251
        self.mc.send_cmd(f"set {too_long_key} 0 0 3\r\nval\r\n")
        res = self.mc.readline().strip()
        self.assertTrue("CLIENT_ERROR" in res or "ERROR" in res)

    def test_oversized_value(self):
        # Default item_size_max is 1MB (1048576)
        oversized = "x" * (1024 * 1024 + 1024)
        self.mc.send_cmd(f"set over_key 0 0 {len(oversized)}\r\n{oversized}\r\n")
        res = self.mc.readline().strip()
        self.assertTrue(
            "SERVER_ERROR" in res or "CLIENT_ERROR" in res or "ERROR" in res
        )


if __name__ == "__main__":
    unittest.main()
