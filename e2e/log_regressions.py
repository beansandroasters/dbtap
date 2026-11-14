"""Test log-specific boundaries after e2e/up.sh; do not run other DB tests concurrently."""
import json
import pathlib
import subprocess
import tempfile

dbtap = "target/release/dbtap"


def run(*args, check=True):
    return subprocess.run(args, check=check, capture_output=True, text=True)


def mysql(sql):
    return run("docker", "exec", "dbtap-my-dst", "mysql", "-N", "--raw",
               "-uroot", "-psecret", "-h127.0.0.1", "shop", "-e", sql).stdout


def entry(sql, rows, offset, identity=""):
    start = f"2026-11-14T04:27:00.{445101 + offset:06d}Z"
    end = f"2026-11-14T04:27:00.{445161 + offset:06d}Z"
    return (f"# Time: {end}\n# User@Host: root[root] @ localhost [127.0.0.1]  Id: 43\n"
            f"# Query_time: 0.000060 Lock_time: 0.000000 Rows_sent: {rows} Rows_examined: 0 "
            f"Thread_id: 43 Errno: 0 Killed: 0 Start: {start} End: {end}\n"
            f"use shop;\nSET {identity}timestamp=1794630420;\n{sql}\n")


with tempfile.TemporaryDirectory(prefix="dbtap-log-regressions-") as directory:
    w = pathlib.Path(directory)
    mysql("DROP TABLE IF EXISTS dbtap_log_edge; CREATE TABLE dbtap_log_edge "
          "(id BIGINT AUTO_INCREMENT PRIMARY KEY, prev BIGINT, v TEXT)")
    try:
        value = "a\nTcp port: text\n# Time: text\nb"
        text = entry(f"INSERT INTO dbtap_log_edge(prev,v) VALUES (LAST_INSERT_ID(),'{value}');",
                     0, 0, "last_insert_id=12,insert_id=34,")
        text += entry("SELECT id,prev,v FROM dbtap_log_edge;", 1, 1000)
        (w / "slow.log").write_text(text)
        run(dbtap, "import-logs", "--mysql-slow", str(w / "slow.log"), "--server", "source:3306",
            "-o", str(w / "log.dbtap"))
        run(dbtap, "replay", str(w / "log.dbtap"), "--mysql", "127.0.0.1:13307",
            "--password", "secret", "--tls", "disable", "--report", str(w / "report.json"))
        report = json.loads((w / "report.json").read_text())
        assert report["ran"] == 2 and report["failed"] == 0 and report["verdicts"] == [["Match", 2]], report["verdicts"]
        assert mysql("SELECT id,prev,v FROM dbtap_log_edge") == f"34\t12\t{value}\n"
    finally:
        mysql("DROP TABLE dbtap_log_edge")

    # Failed import must not expose a finished journal or overwrite an existing output.
    (w / "bad.csv").write_text("not,a,postgres,csv\n")
    output = w / "bad.dbtap"
    args = [dbtap, "import-logs", "--pg-csv", str(w / "bad.csv"), "--server", "source:5432", "-o", str(output)]
    assert run(*args, check=False).returncode != 0
    assert not output.exists() and not output.with_name(output.name + ".partial").exists()
    output.write_text("existing")
    assert run(*args, check=False).returncode != 0 and output.read_text() == "existing"

print("OK: MySQL ID metadata/multiline values, final state, failed import and existing-output protection")
