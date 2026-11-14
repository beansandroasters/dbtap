"""Check candidate files, local links, known secret patterns, and embedded PNG diagrams."""
import argparse
import base64
import json
from pathlib import Path
import re
import urllib.parse
import xml.etree.ElementTree as ET
import zlib

ROOT = Path(__file__).resolve().parents[1]
TREES = {"crates", "integrations", "aws", "e2e", "docs", "scripts", ".github"}
TOP = {
    "README.md", "README.ja.md", "SECURITY.md", "SECURITY.ja.md",
    "CONTRIBUTING.md", "CONTRIBUTING.ja.md",
    "THIRD_PARTY_NOTICES.md", "THIRD_PARTY_NOTICES.ja.md",
    "LICENSE", "LICENSE-MIT", "LICENSE-APACHE", "NOTICE",
    "Cargo.toml", "Cargo.lock", "deny.toml", ".gitignore",
}
EXCLUDED = {".git", "target", ".venv", "__pycache__", ".pytest_cache", "artifacts", "dist"}
FORBIDDEN = {".dbtap", ".pcap", ".pcapng", ".pem", ".key", ".log", ".partial", ".tgz", ".zip"}
PATTERNS = {
    "aws-access-key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "private-key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "github-token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{40,}\b"),
    "credential-url": re.compile(r"(?:postgres(?:ql)?|mysql|https?)://[^/\s:@]+:[^/\s@]+@"),
    "personal-path": re.compile(r"/(?:home|Users)/[A-Za-z0-9_.-]+/"),
    "aws-resource-id": re.compile(r"\b(?:i|eni|vpc|subnet|sg|tms|tmt)-[0-9a-f]{8,}\b"),
    "aws-account-arn": re.compile(r"arn:aws[a-z-]*:[^:\s]+:[^:\s]*:\d{12}:"),
}


def inflate(data, window=zlib.MAX_WBITS):
    obj = zlib.decompressobj(window)
    result = obj.decompress(data, 16 * 1024 * 1024)
    if not obj.eof:
        raise ValueError("oversized or incomplete compressed metadata")
    return result


def png_text(data):
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError("invalid PNG signature")
    offset = 8
    texts = []
    while offset + 12 <= len(data):
        size = int.from_bytes(data[offset:offset + 4], "big")
        kind = data[offset + 4:offset + 8]
        body = data[offset + 8:offset + 8 + size]
        if offset + 12 + size > len(data):
            raise ValueError("truncated PNG chunk")
        offset += size + 12
        if kind == b"tEXt":
            texts.append(body.split(b"\0", 1)[1].decode("utf-8"))
        elif kind == b"zTXt":
            value = body.split(b"\0", 1)[1]
            texts.append(inflate(value[1:]).decode("utf-8"))
        elif kind == b"iTXt":
            value = body.split(b"\0", 1)[1]
            flag = value[0]
            value = value[2:].split(b"\0", 2)[2]
            texts.append((inflate(value) if flag else value).decode("utf-8"))
        if kind == b"IEND":
            return texts
    raise ValueError("PNG end chunk missing")


def expanded_text(text):
    """Also inspect URL-encoded and compressed draw.io diagrams."""
    decoded = urllib.parse.unquote(text)
    values = [text, decoded]
    try:
        xml = ET.fromstring(decoded)
    except ET.ParseError:
        return values
    if xml.tag == "mxfile":
        for diagram in xml.findall("diagram"):
            if diagram.text and diagram.text.strip() and len(diagram) == 0:
                raw = inflate(base64.b64decode(diagram.text.strip(), validate=True), -15)
                values.append(urllib.parse.unquote(raw.decode("utf-8")))
    return values


def heading_ids(path):
    counts, ids = {}, set()
    for heading in re.findall(r"^#{1,6} (.+)$", path.read_text(), re.MULTILINE):
        slug = re.sub(r"[^\w\- ]", "", heading.lower()).replace(" ", "-")
        n = counts.get(slug, 0)
        counts[slug] = n + 1
        ids.add(slug + (f"-{n}" if n else ""))
    return ids


def scan(root):
    files, errors = [], []
    excluded = set()
    metadata_count = 0

    def walk(directory):
        for path in sorted(directory.iterdir()):
            relative = path.relative_to(root)
            if path.name in EXCLUDED:
                excluded.add(str(relative))
                continue
            if path.is_symlink():
                errors.append({"path": str(relative), "rule": "symlink"})
            elif path.is_dir():
                if directory == root and path.name not in TREES:
                    errors.append({"path": str(relative), "rule": "unexpected-root-directory"})
                else:
                    yield from walk(path)
            elif path.is_file():
                yield path

    for path in walk(root):
        relative = str(path.relative_to(root))
        files.append(relative)
        if path.parent == root and path.name not in TOP:
            errors.append({"path": relative, "rule": "unexpected-root-file"})
        if path.suffix in FORBIDDEN or path.name.startswith((".env", ".secret", ".versions", ".targets")):
            errors.append({"path": relative, "rule": "private-artifact"})
        if path.stat().st_size > 16 * 1024 * 1024:
            errors.append({"path": relative, "rule": "oversized-file-needs-review"})
            continue
        try:
            if path.suffix == ".png":
                texts = png_text(path.read_bytes())
                metadata_count += len(texts)
            else:
                texts = [path.read_text()]
            for text in texts:
                values = expanded_text(text)
                for rule, pattern in PATTERNS.items():
                    if any(pattern.search(v) for v in values):
                        errors.append({"path": relative, "rule": rule})
        except (ValueError, UnicodeError, zlib.error, IndexError):
            errors.append({"path": relative, "rule": "unreadable-file-or-metadata"})
            continue
        if path.suffix == ".md":
            for link in re.findall(r"\]\(([^)\n]+)\)", texts[0]):
                link = link.strip().strip("<>")
                parsed = urllib.parse.urlsplit(link)
                if parsed.scheme in {"http", "https", "mailto"}:
                    continue
                if parsed.scheme or link.startswith("/"):
                    errors.append({"path": relative, "rule": "nonportable-link"})
                    continue
                target = (path.parent / urllib.parse.unquote(parsed.path)).resolve() if parsed.path else path
                if not target.is_relative_to(root) or not target.exists():
                    errors.append({"path": relative, "rule": "missing-or-outside-link"})
                elif parsed.fragment and target.suffix == ".md":
                    if urllib.parse.unquote(parsed.fragment) not in heading_ids(target):
                        errors.append({"path": relative, "rule": "missing-heading-link"})
    return {
        "files_checked": len(files), "png_metadata_chunks_checked": metadata_count,
        "excluded_local_directories": sorted(excluded), "findings": errors,
        "license_present": (root / "LICENSE").is_file() or all(
            (root / name).is_file() for name in ("LICENSE-MIT", "LICENSE-APACHE")
        ),
        "scope": "Working-tree files only; not a complete secret detector or Git history audit.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit results as JSON")
    args = parser.parse_args()
    result = scan(ROOT)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f'{result["files_checked"]} files / {result["png_metadata_chunks_checked"]} PNG metadata chunks')
        for error in result["findings"]:
            print(f'{error["path"]}: {error["rule"]}')  # Never print detected secret values.
        print(f'{len(result["findings"])} findings; license present: {result["license_present"]}')
    raise SystemExit(bool(result["findings"]))


if __name__ == "__main__":
    main()
