"""
test_quit.py - Test quit command clean connection termination.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from memcached_harness import MemcachedServer


class TestQuit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = MemcachedServer().start()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def test_quit_command(self):
        mc = self.server.client()
        mc.send_cmd("quit")
        # After quit, further reads should return EOF
        res = mc.sock.recv(1024)
        self.assertEqual(res, b"")
        mc.close()

    def test_quit_after_operations(self):
        mc = self.server.client()
        self.assertEqual(mc.set("qkey", "qval"), "STORED")
        self.assertIn("qkey", mc.get("qkey"))
        mc.send_cmd("quit")
        res = mc.sock.recv(1024)
        self.assertEqual(res, b"")
        mc.close()


if __name__ == "__main__":
    unittest.main()
