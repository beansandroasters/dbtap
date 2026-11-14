# Third-party dependencies and notices

English | [日本語](THIRD_PARTY_NOTICES.ja.md)

The dbtap source is dual-licensed under MIT OR Apache-2.0. **Dependencies retain their own licenses.** The project license does not replace their copyright notices or license conditions.

## Rust

`Cargo.lock` pins the Rust dependency graph. [Dependency inventory](docs/dependencies.json) records the registry package names, versions, and declared license expressions checked for this source tree, including build and platform-specific dependencies. It is an inventory, not a replacement for the license texts.

| Dependency group | Purpose / distribution consideration |
|---|---|
| rustls, tokio-rustls, aws-lc-rs, aws-lc-sys, ring | TLS and cryptography; native vendored components have their own notices |
| webpki-roots | Bundled Mozilla-derived root certificate data, CDLA-Permissive-2.0 |
| zstd, zstd-safe, zstd-sys | Compression; include notices for the bundled native zstd code |
| tokio, libc | Runtime, networking and OS interfaces |
| serde, serde_json, csv, chrono | Journal metadata, reports, logs and timestamps |
| clap, anyhow | CLI and error handling |
| rsa, sha1, sha2, md-5, base64, subtle, rand | Database authentication and supporting primitives |
| xxhash-rust | Result and SQL-shape fingerprints |

`deny.toml` permits only reviewed license identifiers and crates.io sources. `cargo deny --locked check` checks advisories, licenses, source policy, and dependency bans. Alternative license expressions can be satisfied through an allowed branch; the presence of an alternative license in an inventory is not a requirement to use that alternative.

## Python and external tools

The standard-library converter in `integrations/` has no required runtime dependencies. The optional Locust extra is pinned in `integrations/uv.lock`; Locust and its transitive packages retain their respective licenses. The Python distribution includes copies of both dbtap license files.

PostgreSQL, MySQL, Docker, pgbench, JMeter, k6, Locust, and AWS services are separate projects/products. Their names describe compatibility and do not imply affiliation or endorsement. Their binaries and container images are not part of this source distribution.

## Preparing a binary distribution

Ship LICENSE-MIT and LICENSE-APACHE with dbtap. For the exact target/features being built, also collect the applicable dependency LICENSE/COPYING/NOTICE files, including notices embedded in native vendored code and root-certificate data. Preserve required attribution and modification notices. An inventory or a successful license scan does not replace those files.

This repository prepares source publication; it does not contain a prebuilt release archive or a complete binary notice bundle. Review that bundle before distributing binaries, and re-check it whenever the lockfiles, build features, or target change. The [publication checklist](docs/publishing.md) covers that final packaging step.
