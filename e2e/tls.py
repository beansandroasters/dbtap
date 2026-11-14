"""Configure temporary certificates on both test destinations and validate CA/hostnames.

uv run --no-project e2e/tls.py cap.dbtap new-output-directory
Run after e2e/up.sh and capture; certificates change, so finish with e2e/up.sh down.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
journal, work = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
os.umask(0o077)
work.mkdir(mode=0o700, parents=True)
certs = work / "certs"
certs.mkdir()


def run(*args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True, **kwargs)


run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
    "-subj", "/CN=dbtap e2e CA", "-keyout", str(certs / "ca.key"), "-out", str(certs / "ca.pem"))
run("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost",
    "-keyout", str(certs / "server-key.pem"), "-out", str(certs / "server.csr"))
(certs / "extensions").write_text(
    "basicConstraints=CA:FALSE\nsubjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n")
run("openssl", "x509", "-req", "-in", str(certs / "server.csr"),
    "-CA", str(certs / "ca.pem"), "-CAkey", str(certs / "ca.key"), "-CAcreateserial",
    "-days", "1", "-extfile", str(certs / "extensions"), "-out", str(certs / "server-cert.pem"))

# Never distribute the CA private key to DBs; PG files are readable only by postgres.
run("docker", "exec", "dbtap-pg-dst", "mkdir", "-p", "/tmp/dbtap-tls")
for name in ("server-cert.pem", "server-key.pem"):
    run("docker", "cp", str(certs / name), f"dbtap-pg-dst:/tmp/dbtap-tls/{name}")
run("docker", "exec", "dbtap-pg-dst", "chown", "-R", "postgres:postgres", "/tmp/dbtap-tls")
run("docker", "exec", "dbtap-pg-dst", "chmod", "600", "/tmp/dbtap-tls/server-key.pem")
for sql in (
    "ALTER SYSTEM SET ssl_cert_file = '/tmp/dbtap-tls/server-cert.pem'",
    "ALTER SYSTEM SET ssl_key_file = '/tmp/dbtap-tls/server-key.pem'",
    "ALTER SYSTEM SET ssl = on",
    "SELECT pg_reload_conf()",
):
    run("docker", "exec", "dbtap-pg-dst", "psql", "-U", "postgres", "-d", "shop", "-c", sql)
for name in ("ca.pem", "server-cert.pem", "server-key.pem"):
    run("docker", "cp", str(certs / name), f"dbtap-my-dst:/var/lib/mysql/{name}")
    run("docker", "exec", "dbtap-my-dst", "chown", "mysql:mysql", f"/var/lib/mysql/{name}")
run("docker", "exec", "dbtap-my-dst", "chmod", "600", "/var/lib/mysql/server-key.pem")
run("docker", "exec", "-e", "MYSQL_PWD=secret", "dbtap-my-dst",
    "mysql", "-uroot", "-e", "ALTER INSTANCE RELOAD TLS")
time.sleep(1)

evidence = []
for name, host, trust in (
    ("trusted", "localhost", True),
    ("untrusted-ca", "localhost", False),
    ("wrong-hostname", "127.0.0.1", True),
):
    run(str(ROOT / "e2e/seed.sh"), "dst")
    report, samples = work / f"{name}.json", work / f"{name}.jsonl"
    # Omit --tls to verify require is the default.
    args = [str(ROOT / "target/release/dbtap"), "replay", str(journal),
            "--pg", f"{host}:15433", "--mysql", f"{host}:13307",
            "--samples", str(samples), "--report", str(report)]
    if trust:
        args += ["--tls-ca", str(certs / "ca.pem")]
    result = run(*args, env={**os.environ, "DBTAP_PASSWORD": "secret"})
    (work / f"{name}.stderr").write_text(result.stderr)
    r = json.loads(report.read_text())
    units = [s for line in samples.read_text().splitlines()
             if (s := json.loads(line))["type"] == "sample"]
    assert units and len(units) == r["units"]
    if name == "trusted":
        assert r["failed"] == r["skipped"] == 0 and r["ran"] == r["units"]
        assert all(v in ("Match", "NonDeterministic", "Reordered") for v, _ in r["verdicts"])
        assert all(s["timing"] is not None for s in units)
    else:
        assert r["ran"] == 0 and r["failed"] == r["units"], r["failures"]
        assert all(s["status"] == "failed" and s["timing"] is None for s in units)
    evidence.append({"case": name, "units": r["units"], "ran": r["ran"], "failed": r["failed"],
                     "unattempted": sum(s["timing"] is None for s in units)})
(work / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
print(json.dumps(evidence, indent=2))
