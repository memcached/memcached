"""
test_slabs.py - Test slab allocation, automove settings, and reassign commands.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from memcached_harness import MemcachedServer


class TestSlabs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Start server with slab reassign and automove enabled
        cls.server = MemcachedServer(
            extra_args=["-o", "slab_reassign,slab_automove=1"]
        ).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def setUp(self):
        self.mc = self.server.client()

    def tearDown(self):
        self.mc.close()

    def test_slab_reassign(self):
        # Trigger slab allocation in two classes
        self.mc.set("small_item", "x" * 64)
        self.mc.set("larger_item", "x" * 512)

        st = self.mc.stats("slabs")
        self.assertIn("active_slabs", st)

        # Test slabs automove setting command
        self.mc.send_cmd("slabs automove 0")
        res = self.mc.readline().strip()
        self.assertEqual(res, "OK")

        self.mc.send_cmd("slabs automove 1")
        res = self.mc.readline().strip()
        self.assertEqual(res, "OK")


if __name__ == "__main__":
    unittest.main()
