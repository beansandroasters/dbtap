# /// script
# dependencies = ["boto3"]
# ///
"""Download every page of a rotated RDS/Aurora log from the beginning.

Usage: source aws/lib.sh
        uv run aws/download-log.py <DB instance ID> <LogFileName> <output>
Concatenate LogFileData unchanged, including page boundaries inside CSV records.
"""
import os
import pathlib
import sys

import boto3

instance, name, output = sys.argv[1:]
region = os.environ.get("AWS_REGION")
if region != "ap-northeast-1":
    raise SystemExit("Run source aws/lib.sh first (Tokyo region)")
client = boto3.Session(profile_name=os.environ.get("AWS_PROFILE"), region_name=region).client("rds")
out = pathlib.Path(output)
partial = out.with_name(out.name + ".partial")
if out.exists():
    raise SystemExit(f"Output already exists: {out}")
marker = "0"
pages = size = 0
try:
    fd = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        while True:
            response = client.download_db_log_file_portion(
                DBInstanceIdentifier=instance, LogFileName=name, Marker=marker, NumberOfLines=10000)
            data = response["LogFileData"].encode("utf-8")
            f.write(data)
            pages += 1
            size += len(data)
            if not response["AdditionalDataPending"]:
                break
            next_marker = response["Marker"]
            if next_marker == marker:
                raise RuntimeError("Pagination marker did not advance")
            marker = next_marker
    os.link(partial, out)  # Refuse to overwrite a concurrent writer's output.
    partial.unlink()
except Exception:
    # Keep partial data for diagnosis without exposing a finished file.
    raise
print(f"{pages} pages / {size} bytes -> {out}")
