# Security review

English | [日本語](security.ja.md)

Review date: 2026-11-14. Scope: Rust, log import, load-tool integrations, local/AWS test scripts, CloudFormation, dependency lockfiles, candidate documentation and diagrams.

## Current protections

| Boundary | Implementation/configuration |
|---|---|
| Target transport | TLS required by default; CA and hostname verification |
| PostgreSQL authentication | SCRAM state, nonce, and server signature checks; constant-time signature comparison; cleartext passwords only over TLS |
| MySQL authentication | Mechanism and nonce validation; mysql_clear_password only over TLS; non-TLS full authentication only with explicit disable |
| Authentication resources | At most 64 PG / 16 MySQL messages; 4 KiB SCRAM challenge and 1–200,000 iterations; PBKDF2 outside async worker threads |
| Input | 64 MiB journal fields, replay receive messages, and continued MySQL messages; varint, pcapng length, reversed time and non-finite number checks |
| Capture settings | At most 4,096 MiB ring and 32 selected ports |
| Files | New journals/reports/samples use 0600; existing files/symlinks are not overwritten |
| Export | Validates run-id, complete shards, sequence and end before exposing output |
| Locust | Local argv without shell; private 0700 directories; child cleanup; unreachable targets reported as failures |
| AWS scripts | Passwords in environment; MySQL helper verifies CA/hostname by default and protects temporary SQL |
| AWS network | No public IP, IGW, or NAT; private DBs; egress limited to DBs/endpoints/S3 |
| AWS credentials | Secrets Manager generates the password; only the workload EC2 role can read that secret |
| AWS storage/audit | Encrypted DB/EBS/S3, S3 TLS-only/public-access block, VPC Flow Logs, IMDSv2 with hop limit 1 |

MD5/SHA-1 are used for the corresponding database authentication protocols, not a custom password-storage scheme.

## Validation results

| Check | Result |
|---|---|
| Rust release/unit tests | No build warnings; 84 tests passed |
| Python input/export tests | 4 passed |
| Publication/AWS workload script tests | 8 passed |
| cargo-deny 0.20.2 | Advisories, licenses, bans and sources passed |
| GitHub workflows | actionlint 1.7.7 passed; CI, dependency audits and Rust/Python/Actions CodeQL runs succeeded |
| cargo-audit | 0 known vulnerabilities, 0 warnings |
| pip-audit | 36 packages including Locust; 0 known vulnerabilities |
| cfn-lint | No errors/warnings for ap-northeast-1 |
| CFN configuration assertions | Private settings, TLS default and IAM boundaries checked across 44 resources |
| Checkov 3.3.17 | 76 passed, 9 findings, 0 skipped, 0 parse errors |
| Real DB TLS | PG/MySQL executed 1,450 units with trusted CA/hostname; untrusted CA and wrong hostname rejected all before sending |
| Locust failure paths | Child reaped on interruption; unreachable targets exit 1; no invented latency for unsent requests |

See [audit evidence](security-validation-20261114.json), [publication scan](publication-validation-20261114.json), and [measurements](validation.md). AWS helper arguments, temporary files, and failure propagation were tested using a fake client; real AWS/MariaDB connection behavior of the helper remains unverified.

## CodeQL findings

The [GitHub scan](https://github.com/beansandroasters/dbtap/actions/runs/43576140388) reported 20 findings. Workflow success means analysis completed; it does not mean zero findings.

| Finding | Count | Review |
|---|---|---|
| Hard-coded cryptographic values | 16 | Synthetic credentials/nonces and RFC test vectors inside `#[cfg(test)]` modules; dismissed as used in tests. These modules are excluded from the release binary |
| SHA-256 sensitive-data hashing | 2 | HMAC key normalization inside SCRAM's PBKDF2, and MySQL `caching_sha2_password` challenge-response; dismissed as false positives for password storage |
| Legacy MD5 / SHA-1 authentication | 2 | Kept open: PostgreSQL MD5 ([#4](https://github.com/beansandroasters/dbtap/security/code-scanning/4)) and MySQL native password ([#2](https://github.com/beansandroasters/dbtap/security/code-scanning/2)) compatibility paths |

The two legacy mechanisms are negotiated by the target server. Prefer PostgreSQL SCRAM-SHA-256 and MySQL `caching_sha2_password`, and retain `--tls require`. TLS protects transport but does not modernize the server's password verifier. dbtap does not offer an authentication-mechanism allowlist; configure the target account/server to disallow legacy authentication when required. No CodeQL query is disabled.

## AWS findings and limits

These settings are for short-lived tests. Findings are not suppressed and are not production exceptions.

| Checkov ID | Current setting | Consideration for continued use |
|---|---|---|
| CKV_AWS_158 | No customer-managed KMS key on FlowLogGroup | Standard encryption is used; use a CMK for independent key control/audit |
| CKV_AWS_149 | No customer-managed KMS key for DbSecret | AWS-managed key; separate keys if required |
| CKV_AWS_18 | No S3 access logging | Use CloudTrail data events or access logs for object access audit; Flow Logs are not a substitute |
| CKV_AWS_21 | S3 versioning disabled | Objects expire after 7 days; design version/noncurrent retention for durable storage |
| CKV_AWS_162 / CKV_AWS_161 | IAM DB authentication disabled | Password authentication; dbtap does not generate/refresh IAM tokens |
| CKV_AWS_118 (two) | No enhanced monitoring on AuroraInstance/MySQL | Configure a monitoring role/interval for OS metrics |
| CKV_AWS_157 | MySQL Single-AZ | Use Multi-AZ for availability/failover evaluation |

There is no deletion protection; DB backup retention is one day, Flow Logs retention seven days, and the two test DBs share a secret. Long-term recovery and credential rotation are not provided. SSM uses an AWS-managed policy. Flow Logs DescribeLogGroups uses `Resource: "*"` because that action does not support resource-level restriction.

## Residual risks and untested scope

- Recorded SQL executes as provided. Use a clone and minimum privileges; no production-target detection or journal signature exists.
- Per-field limits do not bound total resource use. Large CSV, many connections, and incomplete pipelines consume memory. Comprehensive hostile-input fuzzing and formal verification of unsafe AF_PACKET code have not been performed.
- Follow [SECURITY.md](../SECURITY.md) for TLS exceptions, Locust control traffic, and data handling. Shape hashes are not anonymization.
- Deployment of the complete current AWS template, SSM/package/secret retrieval over restricted routes, and Flow Logs delivery are unverified on live infrastructure.
- Account-wide CloudTrail/GuardDuty/Security Hub settings, host OS/container images, and Git history are outside this review.
- GitHub private vulnerability reporting, secret scanning/push protection, Dependabot alerts, and main branch protection are enabled; see [repository settings](publishing.md#github-configuration). The support and license policies are defined in the root documents. Check the linked Actions runs for each revision's CI and CodeQL results.

Repeatable audit commands and release settings are in [Publication](publishing.md).
