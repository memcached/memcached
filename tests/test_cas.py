"""
test_cas.py - Test compare-and-swap (CAS) protocol operations.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from memcached_harness import MemcachedServer


class TestCas(unittest.TestCase):
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

    def test_cas_workflow(self):
        # Set initial item
        self.assertEqual(self.mc.set("cas_key", "val1"), "STORED")

        # Fetch with gets to obtain CAS id
        res = self.mc.gets("cas_key")
        self.assertIn("cas_key", res)
        val, flags, cas_id = res["cas_key"]
        self.assertEqual(val, "val1")
        self.assertTrue(cas_id > 0)

        # Successful CAS
        self.assertEqual(self.mc.cas("cas_key", "val2", cas_id), "STORED")
        val, flags, cas_id2 = self.mc.gets("cas_key")["cas_key"]
        self.assertEqual(val, "val2")
        self.assertNotEqual(cas_id, cas_id2)

        # Stale CAS should fail with EXISTS
        self.assertEqual(self.mc.cas("cas_key", "val3", cas_id), "EXISTS")

        # Normal set overwrites and updates CAS
        self.assertEqual(self.mc.set("cas_key", "val4"), "STORED")
        val, flags, cas_id3 = self.mc.gets("cas_key")["cas_key"]
        self.assertEqual(val, "val4")

        # CAS on non-existing key returns NOT_FOUND
        self.assertEqual(self.mc.cas("nonexistent_cas", "v", 12345), "NOT_FOUND")


if __name__ == "__main__":
    unittest.main()
