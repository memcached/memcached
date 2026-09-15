"""
test_bogus.py - Test server error handling for malformed/bogus commands.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from memcached_harness import MemcachedServer


class TestBogusCommands(unittest.TestCase):
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

    def test_unknown_command(self):
        self.mc.send_cmd("boguscommand")
        res = self.mc.readline().strip()
        self.assertEqual(res, "ERROR")

    def test_malformed_set(self):
        # Missing arguments in set
        self.mc.send_cmd("set foo 0")
        res = self.mc.readline().strip()
        self.assertTrue(res.startswith("CLIENT_ERROR") or res.startswith("ERROR"))

    def test_non_numeric_flags(self):
        self.mc.send_cmd("set foo notanumber 0 5\r\nhello")
        res = self.mc.readline().strip()
        self.assertTrue("ERROR" in res)

    def test_negative_bytes(self):
        self.mc.send_cmd("set foo 0 0 -1\r\nhello")
        res = self.mc.readline().strip()
        self.assertTrue("ERROR" in res)


if __name__ == "__main__":
    unittest.main()
