"""
test_metaget.py - Test meta command protocol (mg, ms, md).
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from memcached_harness import MemcachedServer


class TestMetaGet(unittest.TestCase):
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

    def test_meta_set_and_get(self):
        # Set using ms (meta set)
        self.mc.send_cmd("ms mg_key 5 T3600\r\nhello\r\n")
        res = self.mc.readline().strip()
        self.assertTrue(res.startswith("HD"))

        # Get using mg (meta get) with flags
        self.mc.send_cmd("mg mg_key v s c\r\n")
        line = self.mc.readline().strip()
        self.assertTrue(line.startswith("VA 5"))
        val = self.mc.readline().strip()
        self.assertEqual(val, "hello")

    def test_meta_delete(self):
        self.mc.set("md_key", "val")
        self.mc.send_cmd("md md_key\r\n")
        res = self.mc.readline().strip()
        self.assertTrue(res.startswith("HD"))

        # Getting deleted key with mg should return EN
        self.mc.send_cmd("mg md_key\r\n")
        res = self.mc.readline().strip()
        self.assertTrue(res.startswith("EN"))


if __name__ == "__main__":
    unittest.main()
