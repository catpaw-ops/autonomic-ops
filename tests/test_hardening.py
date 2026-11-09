"""Hardening tests: hostile / malformed input must be rejected gracefully.

These exist because "you never know what a user will type". Every guard must
return a clean (False, reason) instead of raising, and must never let the agent
ban a range that could lock the operator out of the box.
"""

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from autonomic.config import Config          # noqa: E402
from autonomic.security import Firewall      # noqa: E402


class TestGuardIP(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ao-harden-")
        self.config = Config({
            "agent": {"data_dir": self.tmp},
            "security": {"protect_private_ips": True, "firewall_backend": "recorder"},
        })
        self.fw = Firewall(self.config)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_public_addresses_allowed(self):
        for ip in ("1.2.3.4", "8.8.8.8", "2606:4700:4700::1111"):
            ok, why = self.fw.guard_ip(ip)
            self.assertTrue(ok, "%s should be allowed: %s" % (ip, why))

    def test_private_loopback_linklocal_blocked(self):
        for ip in ("10.0.0.1", "172.16.0.1", "192.168.1.1", "127.0.0.1",
                   "169.254.1.1", "::1"):
            ok, _ = self.fw.guard_ip(ip)
            self.assertFalse(ok, ip)

    def test_reserved_documentation_cgnat_blocked(self):
        for ip in ("0.0.0.0", "255.255.255.255", "240.0.0.1", "::",
                   "192.0.2.1", "198.51.100.7", "203.0.113.9", "100.64.0.1",
                   "2001:db8::1"):
            ok, _ = self.fw.guard_ip(ip)
            self.assertFalse(ok, ip)

    def test_garbage_is_rejected_without_raising(self):
        for bad in ("", " ", "not-an-ip", "1.2.3.4/24", "999.1.1.1",
                    "1.2.3.4; rm -rf /", "\x00", "1.2.3", "1.2.3.4.5"):
            try:
                ok, why = self.fw.guard_ip(bad)
            except Exception as exc:  # noqa: BLE001 - the point is "never raise"
                self.fail("guard_ip(%r) raised %r" % (bad, exc))
            self.assertFalse(ok, repr(bad))
            self.assertIsInstance(why, str)

    def test_surrounding_whitespace_is_tolerated(self):
        # CLI users paste IPs with stray spaces/newlines; those are stripped,
        # not rejected, and the address itself is still validated.
        ok, why = self.fw.guard_ip("  1.2.3.4  \n")
        self.assertTrue(ok, why)


if __name__ == "__main__":
    unittest.main()
