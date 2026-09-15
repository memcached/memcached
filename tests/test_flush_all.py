"""
test_flush_all.py - Test cache flushing commands.
"""

import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from memcached_harness import MemcachedServer


class TestFlushAll(unittest.TestCase):
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

    def test_immediate_flush(self):
        self.mc.set("f1", "val1")
        self.mc.set("f2", "val2")
        self.assertEqual(len(self.mc.get("f1", "f2")), 2)

        self.assertEqual(self.mc.flush_all(), "OK")
        self.assertEqual(len(self.mc.get("f1", "f2")), 0)

    def test_delayed_flush(self):
        self.mc.set("df1", "val1")
        self.assertEqual(len(self.mc.get("df1")), 1)

        # Flush in 2 seconds
        self.assertEqual(self.mc.flush_all(delay=2), "OK")

        # Immediately after flush_all call, item should still exist
        self.assertEqual(len(self.mc.get("df1")), 1)

        # Wait 2.5 seconds
        time.sleep(2.5)

        # Item should now be invalidated
        self.assertEqual(len(self.mc.get("df1")), 0)


if __name__ == "__main__":
    unittest.main()
