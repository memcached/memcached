"""
test_incrdecr.py - Test arithmetic increment and decrement operations.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from memcached_harness import MemcachedServer


class TestIncrDecr(unittest.TestCase):
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

    def test_incr_decr_flow(self):
        self.assertEqual(self.mc.set("counter", "0"), "STORED")

        # Increment by 1
        self.assertEqual(self.mc.incr("counter", 1), 1)
        # Increment by 99
        self.assertEqual(self.mc.incr("counter", 99), 100)

        # Decrement by 30
        self.assertEqual(self.mc.decr("counter", 30), 70)
        # Decrement by 70 -> 0
        self.assertEqual(self.mc.decr("counter", 70), 0)
        # Decrement below 0 stays at 0 (underflow)
        self.assertEqual(self.mc.decr("counter", 5), 0)

    def test_incr_nonexistent(self):
        self.assertEqual(self.mc.incr("nonexistent_counter", 1), "NOT_FOUND")
        self.assertEqual(self.mc.decr("nonexistent_counter", 1), "NOT_FOUND")

    def test_incr_non_numeric(self):
        self.assertEqual(self.mc.set("text_val", "hello"), "STORED")
        res = self.mc.incr("text_val", 1)
        self.assertTrue("CLIENT_ERROR" in str(res))


if __name__ == "__main__":
    unittest.main()
