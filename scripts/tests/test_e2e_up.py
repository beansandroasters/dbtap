"""Check startup failure reporting and cleanup without a Docker daemon."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class StartupTests(unittest.TestCase):
    def run_script(self, *, ready=False, down=False):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            calls = directory / "calls"
            docker = directory / "docker"
            docker.write_text("""#!/bin/bash
printf '%s\\n' "$*" >> "$FAKE_DOCKER_CALLS"
case "$1" in
  exec) [ "$FAKE_DOCKER_READY" = 1 ];;
  inspect) echo false;;
  logs) echo 'synthetic initialization failure';;
  *) exit 0;;
esac
""")
            docker.chmod(0o700)
            env = {
                **os.environ,
                "PATH": f"{directory}:{os.environ['PATH']}",
                "FAKE_DOCKER_CALLS": str(calls),
                "FAKE_DOCKER_READY": str(int(ready)),
            }
            command = ["bash", str(ROOT / "e2e/up.sh")]
            if down:
                command.append("down")
            result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=5)
            return result, calls.read_text().splitlines()

    def test_stopped_container_fails_promptly_with_diagnostics(self):
        result, calls = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("did not become ready", result.stderr)
        self.assertIn("synthetic initialization failure", result.stderr)
        self.assertNotIn("ready\n", result.stdout)
        self.assertTrue(any(call.startswith("logs --tail 25 ") for call in calls))

    def test_ready_and_down_remove_only_named_test_containers_and_their_volumes(self):
        result, _ = self.run_script(ready=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "ready\n")
        result, calls = self.run_script(down=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, ["rm -fv dbtap-pg-src dbtap-pg-dst dbtap-my-src dbtap-my-dst"])


if __name__ == "__main__":
    unittest.main()
