"""
test_getset.py - Test get/set operations, pipelining, and binary safety.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from memcached_harness import MemcachedServer


class TestGetSet(unittest.TestCase):
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

    def test_basic_set_get(self):
        self.assertEqual(self.mc.set("k_basic", "val_basic"), "STORED")
        res = self.mc.get("k_basic")
        self.assertEqual(res["k_basic"][0], "val_basic")

    def test_empty_value(self):
        self.assertEqual(self.mc.set("empty_k", ""), "STORED")
        res = self.mc.get("empty_k")
        self.assertEqual(res["empty_k"][0], "")

    def test_whitespace_in_value(self):
        val = "line1	line2   end"
        self.assertEqual(self.mc.set("complex_v", val), "STORED")
        res = self.mc.get("complex_v")
        self.assertEqual(res["complex_v"][0], val)

    def test_binary_characters_in_value(self):
        val = bytes([0, 1, 2, 255, 128, 64, 0, 10, 13, 0])
        self.assertEqual(self.mc.set("bin_val", val), "STORED")
        self.mc.send_cmd("get bin_val")
        line = self.mc.readline()
        parts = line.strip().split()
        self.assertEqual(parts[0], "VALUE")
        nbytes = int(parts[3])
        data = self.mc.read_bytes(nbytes)
        self.mc.read_bytes(2)  # consume

        self.mc.readline()  # consume END
        self.assertEqual(data, val)

    def test_pipelining(self):
        cmds = (
            b"set pipe1 0 0 4\r\nval1\r\nset pipe2 0 0 4\r\nval2\r\nget pipe1 pipe2\r\n"
        )
        self.mc.sock.sendall(cmds)
        self.assertEqual(self.mc.readline().strip(), "STORED")
        self.assertEqual(self.mc.readline().strip(), "STORED")
        res = {}
        while True:
            line = self.mc.readline().strip()
            if not line or line == "END":
                break
            parts = line.split()
            if len(parts) >= 4 and parts[0] == "VALUE":
                k = parts[1]
                nbytes = int(parts[3])
                data = self.mc.read_bytes(nbytes)
                self.mc.read_bytes(2)
                res[k] = data.decode("utf-8")
        self.assertEqual(res["pipe1"], "val1")
        self.assertEqual(res["pipe2"], "val2")


if __name__ == "__main__":
    unittest.main()
