"""
test_startup.py - Test server command-line options and startup validation.
"""

import os
import sys
import subprocess
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from memcached_harness import (
    MemcachedServer,
    get_memcached_binary,
    get_emulator,
    find_free_port,
)


class TestStartup(unittest.TestCase):
    def test_default_startup(self):
        server = MemcachedServer()
        server.start()
        with server.client() as mc:
            self.assertTrue(len(mc.version()) > 0)
        server.stop()

    def test_illegal_threads(self):
        cmd = get_emulator() + [get_memcached_binary(), "-t", "0"]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertNotEqual(proc.returncode, 0)

    def test_help(self):
        cmd = get_emulator() + [get_memcached_binary(), "-h"]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out = (proc.stdout + proc.stderr).decode("utf-8", errors="replace")
        self.assertTrue("-p" in out or "memcached" in out)

    def test_custom_maxconns(self):
        port = find_free_port()
        server = MemcachedServer(port=port, extra_args=["-c", "512"])
        server.start()
        with server.client() as mc:
            st = mc.stats("settings")
            self.assertEqual(st.get("maxconns"), "512")
        server.stop()


if __name__ == "__main__":
    unittest.main()
