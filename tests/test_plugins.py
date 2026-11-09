"""Unit tests for the built-in detector plugins.

Plugins are loaded by path (their file names start with digits, so they cannot be
imported as normal modules). Each plugin exposes a few pure helpers that are
tested here, plus a `setup()` smoke test against a minimal context stub.
"""

import importlib.util
import os
import unittest

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "plugins", "builtin")


def load(name):
    path = os.path.join(BASE, name + ".py")
    spec = importlib.util.spec_from_file_location("ao_plugin_" + name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _Cfg:
    def get(self, key, default=None):
        return default


class _Ctx:
    def __init__(self):
        self.config = _Cfg()
        self.detectors = []
        self.rules = []
        self.logs = []

    def register_detector(self, name, fn, interval=0):
        self.detectors.append((name, interval))
        return name

    def register_rule(self, rule):
        self.rules.append(rule)
        return rule.get("id")

    def log(self, level, message):
        self.logs.append((level, message))


PLUGINS = ["60_inode_pressure", "61_oom_watch", "62_time_drift", "63_fd_pressure", "64_disk_growth"]


class TestPluginContract(unittest.TestCase):
    def test_every_plugin_setup_registers_something(self):
        for name in PLUGINS:
            mod = load(name)
            self.assertTrue(hasattr(mod, "PLUGIN"), name)
            self.assertTrue(hasattr(mod, "setup"), name)
            ctx = _Ctx()
            mod.setup(ctx)
            self.assertTrue(ctx.detectors, "%s registered no detector" % name)


class TestInodePressure(unittest.TestCase):
    def test_parse_df(self):
        mod = load("60_inode_pressure")
        text = (
            "Filesystem Type Inodes IUsed IFree IUse% Mounted on\n"
            "/dev/vda1 ext4 655360 1000 654360 1% /\n"
            "tmpfs tmpfs 1000 10 990 1% /run\n"
            "/dev/vda1 ext4 655360 640000 15360 98% /var\n"
        )
        rows = mod.parse_df(text)
        self.assertIn(("/", "ext4", 1.0), rows)
        self.assertIn(("/var", "ext4", 98.0), rows)


class TestFdPressure(unittest.TestCase):
    def test_parse_file_nr(self):
        mod = load("63_fd_pressure")
        self.assertEqual(mod.parse_file_nr("1234\t0\t9223372036854775807\n"),
                         (1234, 9223372036854775807))
        self.assertIsNone(mod.parse_file_nr("bad"))
        self.assertIsNone(mod.parse_file_nr(""))


class TestDiskGrowth(unittest.TestCase):
    def test_project(self):
        mod = load("64_disk_growth")
        # 10% -> 20% in one hour = 10%/h, 80% left => 8h to full.
        self.assertAlmostEqual(mod.project(10, 20, 0, 3600, 24), 8.0, places=3)
        # Flat usage never projects.
        self.assertIsNone(mod.project(10, 10, 0, 3600, 24))
        # 1%/h => 90h to full, beyond the 24h horizon.
        self.assertIsNone(mod.project(10, 11, 0, 3600, 24))


class TestOomWatch(unittest.TestCase):
    def test_oom_lines(self):
        mod = load("61_oom_watch")
        text = (
            "normal line\n"
            "Out of memory: Killed process 123 (java)\n"
            "oom-kill:constraint=CONSTRAINT_NONE\n"
            "Killed process 456 (python3)\n"
        )
        self.assertEqual(len(mod.oom_lines(text)), 3)


class _CtxWithCommand(_Ctx):
    def __init__(self, stdout=""):
        super().__init__()
        self._stdout = stdout

    def run_command(self, argv, timeout=10, allow_network=False):
        return {"ok": True, "stdout": self._stdout, "stderr": ""}


class TestInodeDetect(unittest.TestCase):
    def test_detects_high_inode(self):
        mod = load("60_inode_pressure")
        ctx = _CtxWithCommand(
            "Filesystem Type Inodes IUsed IFree IUse% Mounted on\n"
            "/dev/vda1 ext4 655360 640000 15360 98% /var\n"
        )
        findings = mod.detect(ctx, {})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["kind"], "inode.high")
        self.assertEqual(findings[0]["target"], "/var")


class TestFdDetect(unittest.TestCase):
    def test_detects_high_fd(self):
        mod = load("63_fd_pressure")
        ctx = _Ctx()
        ctx.read_text = lambda path: "900 0 1000"
        findings = mod.detect(ctx, {})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["kind"], "fd.high")


class TestPrometheus(unittest.TestCase):
    def test_renders_metrics(self):
        import sys
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
        from autonomic.dashboard import _prometheus
        status = {
            "metrics": {"cpu_percent": 12.3, "mem_percent": 45.6, "load1": 0.5,
                        "ssh_failures": 3, "disks": [{"path": "/", "percent": 69.2}]},
            "queue": {"queue_depth": 0, "running": 0, "workers": {"size": 4}},
            "security": {"firewall": {"simulated": False}},
            "audit": {"records": 10}, "rules": {"count": 15}, "plugins": {"loaded": 10},
            "uptime_seconds": 100, "pending_approval": 2,
        }
        text = _prometheus(status, {"bans": [{"ip": "1.2.3.4"}]})
        self.assertIn("autonomic_cpu_percent 12.3", text)
        self.assertIn('autonomic_disk_percent{mount="/"} 69.2', text)
        self.assertIn("autonomic_bans_active 1", text)
        self.assertIn("autonomic_simulated 0", text)


if __name__ == "__main__":
    unittest.main()
