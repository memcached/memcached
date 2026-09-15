"""
test_touch.py - Test touch and gat (get and touch) commands.
"""

import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from memcached_harness import MemcachedServer


class TestTouch(unittest.TestCase):
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

    def test_touch_extends_ttl(self):
        # Set with 2-second TTL
        self.assertEqual(self.mc.set("touch_key", "val", exptime=2), "STORED")

        # Touch to extend to 10 seconds
        self.assertEqual(self.mc.touch("touch_key", 10), "TOUCHED")

        # Sleep 2.5s (longer than original TTL)
        time.sleep(2.5)

        # Key should still exist
        res = self.mc.get("touch_key")
        self.assertIn("touch_key", res)
        self.assertEqual(res["touch_key"][0], "val")

    def test_touch_nonexistent(self):
        self.assertEqual(self.mc.touch("nonexistent_touch_key", 10), "NOT_FOUND")


if __name__ == "__main__":
    unittest.main()
