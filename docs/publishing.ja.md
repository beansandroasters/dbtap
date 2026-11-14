# 公開チェックリスト

[English](publishing.md) | 日本語

公開対象はソース、ロックファイル、英日ドキュメント、編集可能な図、ライセンス、CI 設定、確認済みの合成負荷の集計です。target/、仮想環境、キャプチャ、DB ログ、資格情報、秘密鍵、ローカルの成果物を除外します。`.gitignore` だけで安全性は決まりません。

## 文書と公開候補

```bash
uv run --no-project scripts/check_publication.py
```

想定外のルートファイル、symlink、秘密情報を含み得るファイル、Markdown のローカルリンク、AWS/GitHub キー・秘密鍵・資格情報入り URL の既知形式、個人ホームパス、具体的な AWS ID、PNG / draw.io 内の文字列を確認します。検出値自体は出力しません。

任意のパスワード・個人情報を網羅する検査ではなく、Git 履歴と外部リンクも対象外です。実際の公開差分・アーカイブは人が確認します。`docs/*validation*.json` と `aws/results/` は合成負荷の集計です。本番データで置き換えないでください。数値や仕様を変更したら英日両方を更新します。コメント・ヘルプ・新規文書は英語を標準にします。

## ビルド・依存関係

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

cargo-deny / cargo-audit は別途インストールします。`deny.toml` で既知脆弱性、ライセンス、crates.io 由来、依存制限を確認します。検出 0 は未知の問題がない保証ではありません。Cargo.lock を更新したら `cargo metadata --locked --format-version 1` から [依存一覧](dependencies.json)も更新し、ローカルの manifest パスは転記しません。

## AWS と実 DB の確認

```bash
source aws/lib.sh
uvx cfn-lint aws/verify.yaml --regions ap-northeast-1
uv run aws/check_security.py
uvx checkov==3.3.17 -f aws/verify.yaml --framework cloudformation \
  --output json > artifacts/security/checkov.json
```

Checkov は [文書化した9件](security.ja.md)で非 0 になります。抑制はしていません。静的検査は展開、SSM、ログ配信の成功を保証しません。ソース公開のために AWS 展開を行う必要はありません。

プロトコル、認証、解析、再生、CLI 出力を変更したら [ローカル検証](../e2e/README.ja.md)で最終状態まで確認します。連携を変えたら Locust の終了・件数と変換形式を確認します。文書だけの変更で性能測定をやり直す必要はありません。

## ライセンスと配布物

- MIT OR Apache-2.0 を LICENSE-MIT / LICENSE-APACHE で定義しています。各 Rust crate は継承し、Python パッケージにも同じ本文を同梱します。
- [第三者ライセンス](../THIRD_PARTY_NOTICES.ja.md)と一覧を維持します。バイナリ配布時はネイティブコード内の依存・証明書データも含め、必要な本文・通知を追加します。バイナリ用の完全な通知セットはまだ含みません。
- 実際の配布物からのインストールを試し、toolchain / target と実際に作ったファイルの checksum を記録します。現時点でレジストリ公開や署名付きリリースを行ったという意味ではありません。
- リポジトリを公開する前に、選択したファイルと既存の履歴を確認します。検査スクリプトは Git 履歴を読みません。

## GitHub の設定

ソースの公開先は [beansandroasters/dbtap](https://github.com/beansandroasters/dbtap)、デフォルトブランチは main です。非公開の脆弱性報告、Dependabot の通知・セキュリティ更新、secret scanning、secret scanning push protection を有効にしています。[報告方針](../SECURITY.ja.md)に従い、[非公開の報告窓口](https://github.com/beansandroasters/dbtap/security/advisories/new)を使ってください。0.1 プレリリース中の修正対象はデフォルトブランチの最新コードだけです。

`.github/workflows/` にはビルド、単体・ローカル DB テスト、依存監査、Rust / Python / Actions の CodeQL を用意しています。公式 Action をコミット SHA に固定し、既定権限なし、checkout の資格情報を保持せず、pull_request_target と共有キャッシュを使いません。Dependabot は Cargo / uv / Actions を対象に7日間の cooldown を設定しています。

[main の保護ルール](https://github.com/beansandroasters/dbtap/rules/27256329)は PR と、最新ブランチに対する test・dependencies・3種類の codeql チェック成功を必須にします。force push と削除を禁止し、直線的な履歴を要求し、迂回できる利用者は設定していません。別のレビュアーによる承認は必須にしていません。Actions の既定権限は読み取りのみで、Actions による PR 承認は無効です。

各リビジョンの検証完了を判断する前に、[CI](https://github.com/beansandroasters/dbtap/actions/workflows/ci.yml) と [security](https://github.com/beansandroasters/dbtap/actions/workflows/security.yml) の成功を確認します。これらの外部設定は workflow ファイルの追加だけでは変わりません。レジストリ公開やバイナリリリースは、上記の配布物の要件を満たして別途行います。
