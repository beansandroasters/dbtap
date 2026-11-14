# Contributing

English | [日本語](CONTRIBUTING.ja.md)

Read the [README](README.md), [architecture](docs/architecture.md), and the relevant input guide before changing behavior. Use synthetic workloads and isolated databases for examples and tests. Report security issues privately as described in [SECURITY.md](SECURITY.md).

## Language and documentation

English is the default for documentation, source comments, docstrings, CLI help, and diagnostic messages. Keep Japanese documentation in sibling `*.ja.md` files with reciprocal language links. Update both versions when changing commands, defaults, limitations, or measurements. Machine-readable keys and protocol fixtures are not translated. Avoid development-session history in user documentation; describe the current behavior and name the conditions behind measured results.

## Development checks

From the repository root, with Rust 1.93+, a native build toolchain, and uv:

```bash
cargo build --release --locked
cargo test --workspace --locked
uv run --project integrations --extra locust -m unittest discover -s integrations/tests -v
uv run --no-project -m unittest discover -s scripts/tests -v
uv run --no-project scripts/check_publication.py
```

Use uv for Python tasks and retain both lockfiles. Add focused regression tests for protocol, parsing, authentication, and lifecycle changes. Do not substitute report agreement for a direct comparison of the final database state. Run the relevant [real-database tests](e2e/README.md) after such changes. Run tests against the same disposable databases sequentially.

Keep patches focused, explain behavior and validation, and document residual limitations. Before modifying uncommitted code substantially, make a local backup outside the repository. Do not include captures, actual DB logs, keys, credentials, or local result directories in a contribution.

## Dependencies and releases

Use [the publication checklist](docs/publishing.md) to audit dependencies and prepare distributable files. A binary release must include the project licenses and the applicable dependency notices. Do not claim a benchmark or supported platform without measuring it. Journal/schema compatibility changes need an explicit format/version decision and a migration or rejection policy.

## Contribution license

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this work, as defined in the Apache-2.0 license, shall be dual licensed under MIT OR Apache-2.0, without additional terms or conditions.
