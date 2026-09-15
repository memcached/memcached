"""
test_expirations.py - Test item TTL expiration behavior.
"""

import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from memcached_harness import MemcachedServer


class TestExpirations(unittest.TestCase):
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

    def test_ttl_expiration(self):
        # Set with 2-second TTL
        self.assertEqual(self.mc.set("expire_key", "expire_val", exptime=2), "STORED")
        res = self.mc.get("expire_key")
        self.assertIn("expire_key", res)

        # Wait 2.5s for expiration
        time.sleep(2.5)

        # Should now be gone
        res = self.mc.get("expire_key")
        self.assertNotIn("expire_key", res)

    def test_permanent_item(self):
        # Exptime 0 means never expire
        self.assertEqual(self.mc.set("perm_key", "perm_val", exptime=0), "STORED")
        time.sleep(1)
        res = self.mc.get("perm_key")
        self.assertIn("perm_key", res)


if __name__ == "__main__":
    unittest.main()
