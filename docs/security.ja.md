# セキュリティ検査

[English](security.md) | 日本語

確認日: 2026-11-14。対象は Rust 本体、DB ログ入力、負荷ツール連携、ローカル / AWS 検証スクリプト、CloudFormation、依存ロックファイル、公開候補の文書と図です。

## 現在の保護

| 境界 | 実装・設定 |
|---|---|
| 再生先の通信 | TLS 必須が既定。CA とホスト名を検証 |
| PostgreSQL 認証 | SCRAM の状態・nonce・サーバー署名を検証。署名は定数時間比較。cleartext は TLS のみ |
| MySQL 認証 | 認証方式・nonce を検査。mysql_clear_password は TLS のみ。非 TLS の full authentication は明示した disable の場合のみ |
| 認証の資源使用 | PG 最大 64 / MySQL 最大 16 メッセージ。SCRAM challenge 4 KiB、反復数 1〜200,000。PBKDF2 は非同期ワーカーの外で実行 |
| 入力 | ジャーナルのフィールド・再生の受信・MySQL 継続メッセージは 64 MiB を上限に検査。varint、pcapng の長さ、時刻逆転、非有限の数値も検査 |
| キャプチャ設定 | リング最大 4,096 MiB、対象ポート最大 32 個 |
| ファイル | ジャーナル・レポート・samples は新規作成 0600。既存ファイルと symlink を上書きしない |
| 結果変換 | run-id、全 shard、連番、end を検査し、完全な入力から新規出力を作成 |
| Locust | ローカル argv を shell なしで実行。専用ディレクトリ 0700、停止時に子を回収。接続不能も実行失敗として通知 |
| AWS 検証スクリプト | パスワードは環境変数。MySQL 負荷は既定で CA / ホスト名を検証し、一時 SQL を専用ディレクトリで管理 |
| AWS ネットワーク | 公開 IP・IGW・NAT なし、DB 非公開。DB / VPC エンドポイント / S3 に外向きを限定 |
| AWS 資格情報 | Secrets Manager で生成。対象 secret の取得は負荷用 EC2 のみ |
| AWS 保存・監査 | DB / EBS / S3 の保存時暗号化、S3 TLS 強制・公開遮断、VPC Flow Logs、IMDSv2・hop limit 1 |

MD5 / SHA-1 は対応する DB 認証プロトコルの計算に使います。アプリケーションが独自にパスワードを保存する方式ではありません。

## 検証結果

| 検査 | 結果 |
|---|---|
| Rust release / 単体テスト | 警告なし、84 件通過 |
| Python の入力・結果変換 | 4 件通過 |
| 公開チェック / AWS 負荷スクリプト | 8 件通過 |
| cargo-deny 0.20.2 | advisories / licenses / bans / sources すべて通過 |
| GitHub workflow の構文 | actionlint 1.7.7 通過。GitHub 上の実行は未確認 |
| cargo-audit | 既知脆弱性 0、警告 0 |
| pip-audit | Locust を含む 36 パッケージ、既知脆弱性 0 |
| cfn-lint | 東京リージョンを指定し、エラー・警告なし |
| CFN 設定 assertion | 44 リソースの非公開設定・TLS 既定・IAM 境界を確認 |
| Checkov 3.3.17 | 76 通過、9 指摘、skip 0、構文エラー 0 |
| 実 DB の TLS | PG / MySQL の両方で、正しい CA・ホスト名なら 1,450 単位を実行。未登録 CA / ホスト名不一致では全件を送信前に拒否 |
| Locust の異常終了 | 途中停止で子を回収、接続不能は終了コード 1。未送信に応答時間を作らない |

[監査の数値](security-validation-20261114.json)、[公開候補ファイルの検査](publication-validation-20261114.json)、[通し検証の実測](validation.ja.md)に確認範囲を記載しています。AWS 用負荷スクリプトの引数・一時ファイル・エラー伝播は偽のクライアントによるテストで確認し、実 AWS 接続は未検証です。

## AWS の指摘と制約

短期間の検証用途として次の設定を持ちます。指摘の抑制はしていません。本番向けの例外承認を意味しません。

| Checkov | 対象の現状 | 継続利用時に必要な検討 |
|---|---|---|
| CKV_AWS_158 | FlowLogGroup にカスタマー管理 KMS キーなし | 標準の保存時暗号化を使用。独立した鍵管理・鍵の利用監査には CMK |
| CKV_AWS_149 | DbSecret にカスタマー管理 KMS キーなし | AWS 管理キーを使用。鍵の分離要件に応じて CMK |
| CKV_AWS_18 | S3 アクセスログなし | オブジェクト操作の監査に CloudTrail データイベントまたはアクセスログ。VPC Flow Logs では代替不可 |
| CKV_AWS_21 | S3 バージョニングなし | 資材は 7 日で失効。長期保管では版管理・非現行版の保持を設計 |
| CKV_AWS_162 / CKV_AWS_161 | Aurora / MySQL の IAM DB 認証なし | パスワード認証を使用。dbtap に IAM トークンの生成・再取得機能はない |
| CKV_AWS_118 (2 件) | AuroraInstance / Mysql の拡張モニタリングなし | OS 指標が必要なら monitoring role と収集間隔を設定 |
| CKV_AWS_157 | MySQL Single-AZ | 可用性・フェイルオーバーを評価するなら Multi-AZ |

削除保護なし、DB バックアップ保持 1 日、Flow Logs 保持 7 日、検証用の 2 DB で secret を共有します。長期の復旧・資格情報ローテーションを備えた構成ではありません。SSM の AWS 管理ポリシーを利用し、Flow Logs の DescribeLogGroups はリソース制限非対応のため `Resource: "*"` としています。

## 信頼境界と未検証範囲

- 入力の SQL はそのまま実行されます。複製 DB と必要最小限の権限を使います。再生先が本番かどうかの自動判別やジャーナルの電子署名はありません。
- 個々のサイズ制限はプロセス全体の資源上限ではありません。大きな CSV、多数の接続、復元途中のパイプライン等はメモリを使います。未信頼ファイルへの包括的な耐性、ファジング、AF_PACKET の unsafe コードの形式的検証は未実施です。
- TLS の例外指定、Locust 制御通信、機密データの保管条件は [SECURITY.md](../SECURITY.ja.md)に従います。samples の SQL 形状ハッシュも匿名化を保証しません。
- AWS テンプレート全体のデプロイ、制限した経路での SSM / パッケージ / secret 取得、Flow Logs の配信は実機未検証です。静的設定だけでは動作を保証できません。
- CloudTrail / GuardDuty / Security Hub のアカウント単位の状態、ホスト OS / Docker イメージ全体、Git 履歴はこの検査の対象外です。
- GitHub の非公開報告、secret scanning / push protection、Dependabot の通知、main ブランチ保護を有効にしています。[リポジトリ設定](publishing.ja.md#github-の設定)と、各リビジョンの Actions による CI / CodeQL 結果を確認してください。報告窓口・サポート方針・ライセンスはルート文書に定義しています。

再検査のコマンドと公開対象の扱いは [公開前の確認](publishing.ja.md)を参照してください。
