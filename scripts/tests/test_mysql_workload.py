"""Test AWS shell credentials, temporary files, and child cleanup with a fake client."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[2] / "aws/mysql-workload.sh"


class WorkloadTests(unittest.TestCase):
    def run_workload(self, fail=False, plaintext=False):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            client = root / "mysql"
            client.write_text("""#!/bin/bash
set -eu
printf '%s\\n' "$@" > "$TEST_DIR/args.$$.txt"
test -n "${MYSQL_PWD:-}"
stat -Lc '%a' /proc/$$/fd/0 > "$TEST_DIR/mode.$$.txt"
cat >/dev/null
exit "${TEST_EXIT:-0}"
""")
            client.chmod(0o700)
            secret = "synthetic-test-value"
            env = {**os.environ, "PATH": str(root) + os.pathsep + os.environ["PATH"],
                   "TMPDIR": str(root), "TEST_DIR": str(root), "TEST_EXIT": "4" if fail else "0",
                   "MYSQL_PWD": secret, "MYSQL_SSL_CA": "/data/ca.pem",
                   "DBTAP_PLAINTEXT_TEST": "1" if plaintext else "0"}
            r = subprocess.run(["bash", str(SCRIPT), "db.example.internal", "user", "2", "2"],
                               env=env, text=True, capture_output=True, timeout=10)
            args = [p.read_text().splitlines() for p in root.glob("args.*.txt")]
            self.assertEqual(len(args), 2)
            self.assertEqual([p.read_text().strip() for p in root.glob("mode.*.txt")], ["600", "600"])
            self.assertTrue(all(secret not in a for a in args))
            self.assertTrue(all(not a.startswith("-p") for argv in args for a in argv))
            for argv in args:
                if plaintext:
                    self.assertIn("--skip-ssl", argv)
                else:
                    self.assertIn("--ssl-verify-server-cert", argv)
                    self.assertIn("--ssl-ca=/data/ca.pem", argv)
            self.assertFalse(list(root.glob("dbtap-mysql.*")))
            return r.returncode

    def test_default_tls_and_credentials(self):
        self.assertEqual(self.run_workload(), 0)

    def test_failed_child_is_propagated_and_cleaned(self):
        self.assertEqual(self.run_workload(fail=True), 1)

    def test_plaintext_requires_explicit_opt_in(self):
        self.assertEqual(self.run_workload(plaintext=True), 0)


if __name__ == "__main__":
    unittest.main()
