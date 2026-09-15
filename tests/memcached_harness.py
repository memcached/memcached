"""
memcached_harness.py - Cross-platform test harness for memcached.
Provides server process management and protocol clients (ASCII & Binary)
without requiring Perl, Bash, or any third-party dependencies.
"""

import os
import sys
import time
import socket
import struct
import subprocess


def find_free_port():
    """Allocate an ephemeral port on 127.0.0.1."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def get_memcached_binary():
    """Locate the memcached executable."""
    env_bin = os.environ.get("MEMCACHED_BIN")
    if env_bin and os.path.exists(env_bin):
        return env_bin

    candidates = [
        os.path.join(".", "memcached.exe"),
        os.path.join(".", "memcached"),
        os.path.join("build_msvc", "memcached.exe"),
        os.path.join("build", "memcached"),
        os.path.join(os.path.dirname(__file__), "..", "build_msvc", "memcached.exe"),
        os.path.join(os.path.dirname(__file__), "..", "build", "memcached"),
    ]
    for c in candidates:
        if os.path.exists(c):
            return os.path.abspath(c)

    return "memcached.exe" if sys.platform == "win32" else "memcached"


def get_emulator():
    """Return emulator command list (e.g. ['wine'] when running Windows binaries on non-Windows)."""
    emulator = os.environ.get("MEMCACHED_EMULATOR")
    if emulator:
        return [emulator]
    bin_path = get_memcached_binary()
    if bin_path.endswith(".exe") and sys.platform != "win32":
        return ["wine"]
    return []


class MemcachedServer:
    """Manages the lifecycle of a memcached server process."""

    def __init__(self, port=None, extra_args=None):
        self.port = port or find_free_port()
        self.extra_args = extra_args or []
        self.proc = None
        self.bin_path = get_memcached_binary()
        self.emulator = get_emulator()

    def start(self, timeout=10.0):
        cmd = (
            self.emulator
            + [
                self.bin_path,
                "-l",
                "127.0.0.1",
                "-p",
                str(self.port),
                "-U",
                "0",
            ]
            + (["-u", "root"] if hasattr(os, "geteuid") and os.geteuid() == 0 else [])
            + self.extra_args
        )

        env = os.environ.copy()
        env["WINEDEBUG"] = "-all"
        env["MVK_CONFIG_LOG_LEVEL"] = "0"

        self.proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
        )

        start_time = time.time()
        connected = False
        while time.time() - start_time < timeout:
            if self.proc.poll() is not None:
                raise RuntimeError(
                    f"memcached exited prematurely with code {self.proc.returncode}"
                )
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    s.connect(("127.0.0.1", self.port))
                    connected = True
                    break
            except (ConnectionRefusedError, socket.timeout, OSError):
                time.sleep(0.1)

        if not connected:
            self.stop()
            raise TimeoutError(
                f"Failed to connect to memcached on port {self.port} within {timeout}s"
            )
        return self

    def stop(self):
        if self.proc:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=3)
            except Exception:
                try:
                    self.proc.kill()
                    self.proc.wait(timeout=2)
                except Exception:
                    pass
            self.proc = None

    def __enter__(self):
        return self.start()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()

    def client(self):
        """Create and connect a client to this server."""
        return MemcachedClient("127.0.0.1", self.port)


class MemcachedClient:
    """Socket client for interacting with memcached ASCII and binary protocols."""

    def __init__(self, host="127.0.0.1", port=11211, timeout=5.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)
        self.sock.connect((host, port))
        self._buf = b""

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    # --- ASCII Protocol Methods ---

    def send_cmd(self, cmd_str):
        if isinstance(cmd_str, str):
            cmd_str = cmd_str.encode("utf-8")
        if not cmd_str.endswith(b"\r\n"):
            cmd_str += b"\r\n"
        self.sock.sendall(cmd_str)

    def readline(self):
        while b"\r\n" not in self._buf:
            try:
                chunk = self.sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            self._buf += chunk
        if b"\r\n" in self._buf:
            idx = self._buf.index(b"\r\n")
            line = self._buf[:idx]
            self._buf = self._buf[idx + 2 :]
            return line.decode("utf-8", errors="replace")
        line = self._buf
        self._buf = b""
        return line.decode("utf-8", errors="replace")

    def read_bytes(self, n):
        while len(self._buf) < n:
            try:
                chunk = self.sock.recv(max(4096, n - len(self._buf)))
            except socket.timeout:
                break
            if not chunk:
                break
            self._buf += chunk
        data = self._buf[:n]
        self._buf = self._buf[n:]
        return data

    def set(self, key, val, flags=0, exptime=0, noreply=False):
        val_bytes = val.encode("utf-8") if isinstance(val, str) else bytes(val)
        cmd = f"set {key} {flags} {exptime} {len(val_bytes)}"
        if noreply:
            cmd += " noreply"
        self.send_cmd(cmd)
        self.sock.sendall(val_bytes + b"\r\n")
        if noreply:
            return None
        return self.readline().strip()

    def add(self, key, val, flags=0, exptime=0):
        val_bytes = val.encode("utf-8") if isinstance(val, str) else bytes(val)
        self.send_cmd(f"add {key} {flags} {exptime} {len(val_bytes)}")
        self.sock.sendall(val_bytes + b"\r\n")
        return self.readline().strip()

    def replace(self, key, val, flags=0, exptime=0):
        val_bytes = val.encode("utf-8") if isinstance(val, str) else bytes(val)
        self.send_cmd(f"replace {key} {flags} {exptime} {len(val_bytes)}")
        self.sock.sendall(val_bytes + b"\r\n")
        return self.readline().strip()

    def append(self, key, val):
        val_bytes = val.encode("utf-8") if isinstance(val, str) else bytes(val)
        self.send_cmd(f"append {key} 0 0 {len(val_bytes)}")
        self.sock.sendall(val_bytes + b"\r\n")
        return self.readline().strip()

    def prepend(self, key, val):
        val_bytes = val.encode("utf-8") if isinstance(val, str) else bytes(val)
        self.send_cmd(f"prepend {key} 0 0 {len(val_bytes)}")
        self.sock.sendall(val_bytes + b"\r\n")
        return self.readline().strip()

    def cas(self, key, val, cas_id, flags=0, exptime=0):
        val_bytes = val.encode("utf-8") if isinstance(val, str) else bytes(val)
        self.send_cmd(f"cas {key} {flags} {exptime} {len(val_bytes)} {cas_id}")
        self.sock.sendall(val_bytes + b"\r\n")
        return self.readline().strip()

    def get(self, *keys):
        """Retrieve one or more keys. Returns a dict {key: (value, flags)}."""
        self.send_cmd(f"get {' '.join(keys)}")
        results = {}
        while True:
            line = self.readline()
            if not line or line.startswith("END"):
                break
            parts = line.strip().split()
            if len(parts) >= 4 and parts[0] == "VALUE":
                k = parts[1]
                flags = int(parts[2])
                nbytes = int(parts[3])
                data = self.read_bytes(nbytes)
                self.read_bytes(2)  # consume trailing \r\n
                results[k] = (data.decode("utf-8", errors="replace"), flags)
        return results

    def gets(self, *keys):
        """Retrieve keys with CAS. Returns a dict {key: (value, flags, cas_id)}."""
        self.send_cmd(f"gets {' '.join(keys)}")
        results = {}
        while True:
            line = self.readline()
            if not line or line.startswith("END"):
                break
            parts = line.strip().split()
            if len(parts) >= 5 and parts[0] == "VALUE":
                k = parts[1]
                flags = int(parts[2])
                nbytes = int(parts[3])
                cas_id = int(parts[4])
                data = self.read_bytes(nbytes)
                self.read_bytes(2)  # consume trailing \r\n
                results[k] = (data.decode("utf-8", errors="replace"), flags, cas_id)
        return results

    def delete(self, key):
        self.send_cmd(f"delete {key}")
        return self.readline().strip()

    def incr(self, key, value=1):
        self.send_cmd(f"incr {key} {value}")
        res = self.readline().strip()
        try:
            return int(res)
        except ValueError:
            return res

    def decr(self, key, value=1):
        self.send_cmd(f"decr {key} {value}")
        res = self.readline().strip()
        try:
            return int(res)
        except ValueError:
            return res

    def touch(self, key, exptime):
        self.send_cmd(f"touch {key} {exptime}")
        return self.readline().strip()

    def stats(self, arg=None):
        cmd = f"stats {arg}" if arg else "stats"
        self.send_cmd(cmd)
        res = {}
        while True:
            line = self.readline()
            if not line or line.startswith("END"):
                break
            parts = line.strip().split(None, 2)
            if len(parts) == 3 and parts[0] == "STAT":
                res[parts[1]] = parts[2]
            elif len(parts) == 2 and parts[0] == "STAT":
                res[parts[1]] = ""
        return res

    def flush_all(self, delay=0):
        cmd = f"flush_all {delay}" if delay else "flush_all"
        self.send_cmd(cmd)
        return self.readline().strip()

    def version(self):
        self.send_cmd("version")
        line = self.readline().strip()
        if line.startswith("VERSION "):
            return line[8:]
        return line

    def quit(self):
        self.send_cmd("quit")
        self.close()

    # --- Binary Protocol Methods ---

    def bin_send(self, opcode, key=b"", val=b"", extras=b"", cas=0, opaque=0):
        if isinstance(key, str):
            key = key.encode("utf-8")
        if isinstance(val, str):
            val = val.encode("utf-8")

        extlen = len(extras)
        keylen = len(key)
        bodylen = extlen + keylen + len(val)
        magic = 0x80  # Request
        datatype = 0
        vbucket = 0

        header = struct.pack(
            "!BBHBBHIIQ",
            magic,
            opcode,
            keylen,
            extlen,
            datatype,
            vbucket,
            bodylen,
            opaque,
            cas,
        )
        packet = header + extras + key + val
        self.sock.sendall(packet)

    def bin_recv(self):
        header = self.read_bytes(24)
        if len(header) < 24:
            return None
        magic, opcode, keylen, extlen, datatype, status, bodylen, opaque, cas = (
            struct.unpack("!BBHBBHIIQ", header)
        )
        body = self.read_bytes(bodylen) if bodylen > 0 else b""
        extras = body[:extlen]
        key = body[extlen : extlen + keylen]
        val = body[extlen + keylen :]
        return {
            "magic": magic,
            "opcode": opcode,
            "keylen": keylen,
            "extlen": extlen,
            "datatype": datatype,
            "status": status,
            "bodylen": bodylen,
            "opaque": opaque,
            "cas": cas,
            "extras": extras,
            "key": key,
            "val": val,
        }
