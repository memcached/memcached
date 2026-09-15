"""
test_flags.py - Test flag handling across numeric ranges.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from memcached_harness import MemcachedServer


class TestFlags(unittest.TestCase):
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

    def test_flag_ranges(self):
        fset = [0, 123, 65535, 2147483647, 4294967295]
        for flags in fset:
            key = f"flag_key_{flags}"
            res = self.mc.set(key, "flagval", flags=flags)
            self.assertEqual(res, "STORED")

            data = self.mc.get(key)
            self.assertIn(key, data)
            val, got_flags = data[key]
            self.assertEqual(val, "flagval")
            self.assertEqual(got_flags, flags)


if __name__ == "__main__":
    unittest.main()
