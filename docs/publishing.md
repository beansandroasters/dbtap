# Publication checklist

English | [日本語](publishing.ja.md)

The source publication consists of code, lockfiles, English/Japanese documentation, editable diagrams, license files, CI configuration, and reviewed synthetic-workload aggregates. Exclude target/, virtual environments, captures, DB logs, credentials, test private keys, and local artifacts. `.gitignore` alone does not determine safe publication contents.

## Documents and candidate files

```bash
uv run --no-project scripts/check_publication.py
```

The working-tree check scans unexpected root files, symlinks, private artifacts, repository-local Markdown links, known AWS/GitHub key formats, private-key PEM, credential URLs, personal home paths, concrete AWS resource identifiers, and embedded PNG/draw.io text. It prints paths/rules rather than detected values.

It is not a complete password/personal-data detector, Git-history audit, or external-link availability check. Review the actual publish diff/archive. `docs/*validation*.json` and `aws/results/` contain synthetic aggregates; do not replace them with production reports. Update both language versions and measurement conditions when changing documented values. English is the default for comments, help, and new documentation.

## Build, tests, and dependencies

```bash
cargo build --release --locked
cargo test --workspace --locked
uv run --locked --project integrations --extra locust -m unittest discover -s integrations/tests -v
uv run --no-project -m unittest discover -s scripts/tests -v

mkdir -p artifacts/security
cargo deny --locked check
cargo audit --json > artifacts/security/cargo-audit.json
uv export --locked --project integrations --extra locust --no-dev --no-emit-project \
  -o artifacts/security/requirements.txt >/dev/null
uvx pip-audit==2.9.0 -r artifacts/security/requirements.txt --format json > artifacts/security/pip-audit.json
```

Install cargo-deny/cargo-audit separately. `deny.toml` checks advisories, licenses, crates.io-only sources, and dependency restrictions. Advisory results depend on scan time/database; zero known findings is not proof of no unknown vulnerabilities. Refresh [the inventory](dependencies.json) from `cargo metadata --locked --format-version 1` when Cargo.lock changes, without copying local manifest paths.

## AWS checks

```bash
source aws/lib.sh
uvx cfn-lint aws/verify.yaml --regions ap-northeast-1
uv run aws/check_security.py
uvx checkov==3.3.17 -f aws/verify.yaml --framework cloudformation \
  --output json > artifacts/security/checkov.json
```

Checkov returns nonzero for the nine [documented findings](security.md). They are not suppressed. Static checks do not validate deployment, SSM access, or log delivery. No AWS deployment is required to publish these source files.

## Real database checks

After protocol, authentication, parsing, replay, or CLI-output changes, run the relevant [local tests](../e2e/README.md), including final-state comparison. For load-tool changes check Locust shutdown/counts and export semantics. Documentation-only changes do not require repeating performance benchmarks.

## Licenses and packaging

- Root LICENSE-MIT and LICENSE-APACHE define MIT OR Apache-2.0. Every Rust crate inherits that expression; the Python package declares it and includes identical license copies.
- Keep [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) and its inventory current. A binary archive must additionally include applicable third-party license/notice texts, including native vendored components and certificate data. A complete binary notice bundle is not included yet.
- Test installation from the actual release artifact, record the toolchain/target, and publish checksums only for artifacts actually built. This source tree does not claim a registry publication or signed binary release.
- Review the actual selected source files and any existing history before making a repository public. The scanner does not inspect Git history.

## GitHub configuration

The public source repository is [beansandroasters/dbtap](https://github.com/beansandroasters/dbtap), with `main` as the default branch. Private vulnerability reporting, Dependabot alerts/security updates, secret scanning, and secret scanning push protection are enabled. Use the [private reporting channel](https://github.com/beansandroasters/dbtap/security/advisories/new) described in the [security policy](../SECURITY.md). Only the latest default-branch code is supported during the 0.1 pre-release phase.

Workflows in `.github/workflows/` run builds/unit tests/local DB round trips and dependency audits, plus CodeQL for Rust, Python, and Actions. Actions are pinned to official commit SHAs; default token permissions are empty, checkout credentials are not retained, and no pull_request_target or shared cache is used. Dependabot is configured for Cargo, uv, and Actions with a seven-day cooldown.

The [main branch ruleset](https://github.com/beansandroasters/dbtap/rules/27256329) requires a pull request and the `test`, `dependencies`, and three `codeql` checks against an up-to-date branch. It blocks force pushes and deletion, requires linear history, and has no bypass actors. An independent approving review is not required. Repository Actions permissions default to read-only, and Actions cannot approve pull requests.

Before considering a revision verified, check its [CI](https://github.com/beansandroasters/dbtap/actions/workflows/ci.yml) and [security](https://github.com/beansandroasters/dbtap/actions/workflows/security.yml) runs. Repository settings are external configuration and are not changed by adding workflow files. Publishing to a registry or creating a binary release is a separate operation with the packaging requirements above.
