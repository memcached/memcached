"""
test_binary.py - Test binary protocol commands.
"""

import os
import sys
import unittest
import struct

sys.path.insert(0, os.path.dirname(__file__))
from memcached_harness import MemcachedServer


class TestBinaryProtocol(unittest.TestCase):
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

    def test_bin_noop(self):
        self.mc.bin_send(0x0A)  # NOOP
        resp = self.mc.bin_recv()
        self.assertIsNotNone(resp)
        self.assertEqual(resp["opcode"], 0x0A)
        self.assertEqual(resp["status"], 0x00)  # SUCCESS

    def test_bin_version(self):
        self.mc.bin_send(0x0B)  # VERSION
        resp = self.mc.bin_recv()
        self.assertIsNotNone(resp)
        self.assertEqual(resp["opcode"], 0x0B)
        self.assertEqual(resp["status"], 0x00)
        self.assertTrue(len(resp["val"]) > 0)

    def test_bin_set_and_get(self):
        # SET: opcode 0x01
        # Extras: 4 bytes flags, 4 bytes exp
        extras = struct.pack("!II", 0, 0)
        self.mc.bin_send(0x01, key=b"bin_k1", val=b"bin_v1", extras=extras)
        resp = self.mc.bin_recv()
        self.assertIsNotNone(resp)
        self.assertEqual(resp["opcode"], 0x01)
        self.assertEqual(resp["status"], 0x00)
        self.assertTrue(resp["cas"] > 0)

        # GET: opcode 0x00
        self.mc.bin_send(0x00, key=b"bin_k1")
        resp = self.mc.bin_recv()
        self.assertIsNotNone(resp)
        self.assertEqual(resp["opcode"], 0x00)
        self.assertEqual(resp["status"], 0x00)
        self.assertEqual(resp["val"], b"bin_v1")

        # GET non-existent key
        self.mc.bin_send(0x00, key=b"nonexistent_bin_key")
        resp = self.mc.bin_recv()
        self.assertIsNotNone(resp)
        self.assertEqual(resp["status"], 0x01)  # KEY_ENOENT

    def test_bin_delete(self):
        extras = struct.pack("!II", 0, 0)
        self.mc.bin_send(0x01, key=b"del_bink", val=b"del_val", extras=extras)
        resp = self.mc.bin_recv()
        self.assertEqual(resp["status"], 0x00)

        # DELETE: opcode 0x04
        self.mc.bin_send(0x04, key=b"del_bink")
        resp = self.mc.bin_recv()
        self.assertIsNotNone(resp)
        self.assertEqual(resp["opcode"], 0x04)
        self.assertEqual(resp["status"], 0x00)

        # DELETE non-existent key: opcode 0x04
        self.mc.bin_send(0x04, key=b"del_bink")
        resp = self.mc.bin_recv()
        self.assertEqual(resp["status"], 0x01)  # KEY_ENOENT

    def test_bin_add_and_replace(self):
        extras = struct.pack("!II", 0, 0)
        # ADD on non-existent: opcode 0x02
        self.mc.bin_send(0x02, key=b"add_bink", val=b"val1", extras=extras)
        resp = self.mc.bin_recv()
        self.assertEqual(resp["status"], 0x00)

        # ADD on existing key should fail with KEY_EEXISTS (0x02)
        self.mc.bin_send(0x02, key=b"add_bink", val=b"val2", extras=extras)
        resp = self.mc.bin_recv()
        self.assertEqual(resp["status"], 0x02)

        # REPLACE on existing: opcode 0x03
        self.mc.bin_send(0x03, key=b"add_bink", val=b"val3", extras=extras)
        resp = self.mc.bin_recv()
        self.assertEqual(resp["status"], 0x00)

        # Verify replaced value
        self.mc.bin_send(0x00, key=b"add_bink")
        resp = self.mc.bin_recv()
        self.assertEqual(resp["val"], b"val3")

    def test_bin_flush(self):
        extras = struct.pack("!II", 0, 0)
        self.mc.bin_send(0x01, key=b"fl_bink", val=b"fl_val", extras=extras)
        self.assertEqual(self.mc.bin_recv()["status"], 0x00)

        # FLUSH: opcode 0x08
        self.mc.bin_send(0x08)
        resp = self.mc.bin_recv()
        self.assertIsNotNone(resp)
        self.assertEqual(resp["opcode"], 0x08)
        self.assertEqual(resp["status"], 0x00)

        # Verify key is gone
        self.mc.bin_send(0x00, key=b"fl_bink")
        resp = self.mc.bin_recv()
        self.assertEqual(resp["status"], 0x01)  # KEY_ENOENT


if __name__ == "__main__":
    unittest.main()
