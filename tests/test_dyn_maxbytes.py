"""
test_dyn_maxbytes.py - Test dynamically resizing maximum memory limit.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from memcached_harness import MemcachedServer


class TestDynMaxbytes(unittest.TestCase):
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

    def test_resize_maxbytes(self):
        st = self.mc.stats("settings")
        orig_maxbytes = int(st["maxbytes"])

        # Change maxbytes to 128MB using cache_memlimit command
        self.mc.send_cmd("cache_memlimit 128")
        res = self.mc.readline().strip()
        self.assertEqual(res, "OK")

        st2 = self.mc.stats("settings")
        self.assertEqual(int(st2["maxbytes"]), 128 * 1024 * 1024)


if __name__ == "__main__":
    unittest.main()
