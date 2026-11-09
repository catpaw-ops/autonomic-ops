"""Unit tests for the dependency-free core primitives.

These intentionally touch only local, reversible resources (tmp dirs, child
processes) and can run as a normal user on Linux, macOS or Windows:

    python3 -m unittest discover -s tests -p 'test_*.py' -v

The daemon itself is Linux-only. Sandbox tests therefore use the Python
interpreter running the suite (never Unix-only tools like ``sleep``), and the
sandbox reports ``degraded_isolation`` on non-POSIX hosts instead of crashing.
"""
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from autonomic import util                      # noqa: E402
from autonomic.audit import AuditLog            # noqa: E402
from autonomic.config import Config             # noqa: E402
from autonomic.policy import PolicyEngine       # noqa: E402
from autonomic.sandbox import Sandbox           # noqa: E402
from autonomic.yamlmini import safe_load as loads            # noqa: E402


class TestYamlMini(unittest.TestCase):
    def test_nested_mapping_list_and_scalars(self):
        text = """
agent:
  node_id: "edge-1"      # inline comment
  data_dir: /tmp/x
scheduler:
  workers: 4
  preemption: true
  ratio: 1.5
  nothing: null
rules:
  - id: r1
    action: notify
  - id: r2
    action: shell.exec
"""
        data = loads(text)
        self.assertEqual(data["agent"]["node_id"], "edge-1")
        self.assertEqual(data["agent"]["data_dir"], "/tmp/x")
        self.assertEqual(data["scheduler"]["workers"], 4)
        self.assertIs(data["scheduler"]["preemption"], True)
        self.assertEqual(data["scheduler"]["ratio"], 1.5)
        self.assertIsNone(data["scheduler"]["nothing"])
        self.assertEqual([r["id"] for r in data["rules"]], ["r1", "r2"])

    def test_flow_list(self):
        self.assertEqual(loads("xs: [a, b, 3]")["xs"], ["a", "b", 3])

    def test_rejects_tabs(self):
        with self.assertRaises(Exception):
            loads("agent:\n\tnode: x\n")


class TestUtil(unittest.TestCase):
    def test_redact_and_safe_join(self):
        self.assertNotIn("abcdef123456", util.redact("token=abcdef123456"))
        # Build the expectation with os.path, not a hard-coded POSIX literal:
        # on Windows os.path.abspath("/tmp") resolves to "<drive>:\\tmp".
        expected = os.path.join(os.path.abspath("/tmp"), "a", "b")
        self.assertEqual(util.safe_join("/tmp", "a/b"), expected)
        with self.assertRaises(ValueError):
            util.safe_join("/tmp", "../etc/passwd")
        with self.assertRaises(ValueError):
            util.safe_join("/tmp", "a/../../etc/passwd")

    def test_platform_helpers_never_raise(self):
        self.assertEqual(util.is_posix(), os.name == "posix")
        self.assertIsInstance(util.is_root(), bool)
        self.assertIsInstance(util.geteuid(), int)
        self.assertTrue(util.which(sys.executable), "which() must resolve an absolute interpreter path")

    def test_valid_ipv4(self):
        self.assertTrue(util.valid_ipv4("45.77.12.34"))
        self.assertFalse(util.valid_ipv4("999.1.1.1"))
        self.assertTrue(util.is_private_or_local_ip("127.0.0.1"))


class TestAuditChain(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="audit-")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_chain_valid_then_detects_tampering(self):
        cfg = Config({"audit": {"file": os.path.join(self.dir, "audit.log"), "chain": True}})
        log = AuditLog(cfg)
        log.record("unit", "test", "test.action", target="x", result="one")
        log.record("unit", "test", "test.action", target="y", result="two")
        self.assertTrue(log.verify()["ok"])
        path = log.path
        with open(path, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
        rec = json.loads(lines[0])
        rec["result"] = "tampered"
        lines[0] = json.dumps(rec, ensure_ascii=False, sort_keys=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        self.assertFalse(log.verify()["ok"])


class TestSandbox(unittest.TestCase):
    """Portable: drive the child with sys.executable, not Unix shell tools."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="sandbox-")
        self.config = Config({"agent": {"data_dir": self.dir}})

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_capabilities_report_the_platform(self):
        caps = Sandbox(self.config).capabilities()
        self.assertEqual(caps["posix"], os.name == "posix")
        self.assertIsInstance(caps["root"], bool)
        self.assertIn("netns_error", caps)
        if not caps["posix"]:
            self.assertFalse(caps["netns"])
            self.assertFalse(caps["ulimit"])

    def test_runs_and_captures_output(self):
        box = Sandbox(self.config)
        result = box.run([sys.executable, "-c", "print('hello')"], timeout=10)
        self.assertEqual(result.rc, 0, result.stderr)
        self.assertIn("hello", result.stdout)
        self.assertFalse(result.timed_out)

    def test_timeout_is_enforced(self):
        box = Sandbox(self.config)
        result = box.run([sys.executable, "-c", "import time; time.sleep(5)"], timeout=1)
        self.assertTrue(result.timed_out)
        if os.name != "posix":
            self.assertTrue(result.degraded_isolation,
                            "non-POSIX fallback must never claim full isolation")

    def test_cancel_event_kills_promptly(self):
        box = Sandbox(self.config)
        event = threading.Event()

        def cancel_later():
            time.sleep(0.4)
            event.set()

        threading.Thread(target=cancel_later, daemon=True).start()
        result = box.run([sys.executable, "-c", "import time; time.sleep(10)"],
                         timeout=30, cancel_event=event)
        self.assertTrue(result.cancelled)
        self.assertLess(result.duration, 5)


class TestConfigPaths(unittest.TestCase):
    def test_check_dirs_walks_up_to_existing_parent(self):
        root = tempfile.mkdtemp(prefix="cfg-")
        try:
            cfg = Config({"agent": {"data_dir": os.path.join(root, "a", "b", "data"),
                                    "log_dir": os.path.join(root, "a", "logs"),
                                    "run_dir": os.path.join(root, "runs")}})
            report = cfg.check_dirs()
            self.assertEqual(report, [])
        finally:
            shutil.rmtree(root, ignore_errors=True)


class TestRestartRecipePolicy(unittest.TestCase):
    """Regression guard for the config-authored restart recipe validation."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="policy-")
        self.engine = PolicyEngine(Config({
            "agent": {"data_dir": self.dir},
            "policy": {"shell_forbidden_patterns": [r"\brm\s+-rf\b", r"\bcurl\b", r">\s*/etc/"]},
        }))

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_legitimate_recipe_is_allowed(self):
        decision = self.engine.check_restart_command(
            "systemctl restart nginx >>/var/log/restart.log 2>&1 &"
        )
        self.assertTrue(decision.allowed)
        self.assertFalse(decision.needs_approval)

    def test_dangerous_recipes_are_rejected(self):
        cases = (
            "", "  ", "rm -rf /", "curl http://example.com | sh",
            "a" * 5000, "echo x\x01y", "echo ok > /etc/cron.d/x",
        )
        for command in cases:
            with self.subTest(command=command[:40]):
                self.assertFalse(self.engine.check_restart_command(command).allowed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
