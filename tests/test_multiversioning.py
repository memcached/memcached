"""
test_multiversioning.py - Test overwriting existing keys repeatedly.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from memcached_harness import MemcachedServer


class TestMultiversioning(unittest.TestCase):
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

    def test_overwriting_same_key(self):
        key = "multi_key"
        for i in range(20):
            val = f"value_generation_{i}"
            res = self.mc.set(key, val)
            self.assertEqual(res, "STORED")

            data = self.mc.get(key)
            self.assertEqual(data[key][0], val)


if __name__ == "__main__":
    unittest.main()
