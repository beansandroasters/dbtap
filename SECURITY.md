# Security policy

English | [日本語](SECURITY.ja.md)

## Reporting a vulnerability

Please do not report vulnerabilities in public issues. Use [GitHub private vulnerability reporting](https://github.com/beansandroasters/dbtap/security/advisories/new), also available under **Security → Report a vulnerability**. Include the affected version, a minimal reproduction using synthetic data, expected/actual behavior, and the security impact. Do not attach production journals, database logs, passwords, or private keys.

If that action is unavailable, do not post exploit details publicly; ask the maintainer to enable private reporting without including sensitive details. No separate email address or response-time guarantee is specified.

## Supported versions

Only the latest code on the default branch receives fixes during the 0.1 pre-release phase. There is no commitment to backport fixes to older revisions. A Cargo package version is not a claim that a public release exists. Upgrade and repeat the relevant replay and final-state checks before using a fix.

## Trust boundary

**dbtap executes SQL from its input against the configured target.** It is not a SQL sandbox. Use recordings from trusted sources, an isolated clone, and only the database permissions the workload requires. dbtap cannot detect that a target is a production database. Journals have no digital signature or authenticity check.

Individual input lengths are checked, but total memory and processing time are not globally bounded. Large CSV records, many connections, or partially reconstructed pipelines can consume substantial resources. Use an unprivileged account and OS/container resource limits for parsing files. Live capture requires root or CAP_NET_RAW; keep that privilege confined to capture.

## Credentials and transport

- Replay defaults to `--tls require`, validating the hostname against bundled WebPKI roots and any `--tls-ca` PEM roots. The OS trust store is not loaded automatically.
- `--tls prefer` permits plaintext fallback; `--tls-insecure` disables certificate verification; `--tls disable` disables TLS. These exceptions are intended for isolated tests.
- PostgreSQL supports SCRAM-SHA-256, MD5, and cleartext authentication. MySQL supports caching_sha2_password, mysql_native_password, and mysql_clear_password. Cleartext password authentication is allowed only over TLS.
- Supply the password via `DBTAP_PASSWORD`. Real passwords in `--password` can be exposed through process arguments. Environment variables are also accessible to the same account and privileged processes.
- MySQL RSA full authentication without TLS is allowed only with explicit `--tls disable`. The server-supplied RSA key does not authenticate the server.

## Sensitive recordings and outputs

| Data | May contain | Handling |
|---|---|---|
| Journal / pcap / DB logs | SQL, bind values, users, addresses, authentication messages | Treat as sensitive database data for storage, transfer and deletion |
| inspect / normal reports / stdout / stderr | SQL, values, database errors and connection details | Review before sharing |
| samples / exported load-tool results | Timing, latency, SQL-shape hashes, counts and error codes | No SQL text, but still exposes workload patterns; not an anonymity guarantee |

dbtap creates journals, reports, and samples exclusively with Unix mode 0600 and refuses to overwrite existing files or symlinks. This is not encryption at rest. Configure disk/backup/transport encryption and retention separately. Use `umask 077` for shell redirects and external tools, which do not inherit dbtap's file-creation policy.

Locust runs a locally configured argv array without a shell. Protect its configuration as operator input. The adapter does not add authentication or encryption to Locust control traffic: bind the master to a private address and allow port 5557 only from participating workers.

The fixed `secret` credentials in `e2e/` are for disposable Docker databases published to loopback. Containers on the same Docker network can also reach them. Do not use this setup for long-lived shared environments.

## AWS and assurance

The [AWS template](aws/verify.yaml) creates private test infrastructure with no public IPs, TLS required by default, encryption at rest, Secrets Manager, IMDSv2, restricted security groups, and VPC Flow Logs. It is not a production baseline. See [Security review](docs/security.md) for the nine unsuppressed Checkov findings and the limits of the audit.

Dependency audits and static checks do not establish that all inputs are safe. Full fuzzing, a host/container audit, a Git history audit, and deployment of the complete current AWS template are outside the validated scope. See [Publication checklist](docs/publishing.md) for repeatable checks.
