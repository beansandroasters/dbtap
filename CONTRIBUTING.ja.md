# コントリビューション

[English](CONTRIBUTING.md) | 日本語

変更前に [README](README.ja.md)、[設計](docs/architecture.ja.md)、対象の入力ガイドを確認してください。例とテストには合成負荷と隔離した DB を使います。脆弱性は [SECURITY.md](SECURITY.ja.md) の非公開窓口へ報告します。

## 言語と文書

ドキュメント、ソースコメント、docstring、CLI ヘルプ、診断メッセージは英語を標準にします。日本語版は同じ場所の `*.ja.md` に置き、相互リンクを付けます。コマンド、既定値、制約、実測値を変えるときは両言語を更新します。機械可読のキーやプロトコルのテストデータは翻訳しません。利用者向け文書には開発セッションの経緯を載せず、現状と測定条件を記載します。

## 開発時の確認

Rust 1.93 以降、ネイティブコードのビルド環境、uv を用意し、リポジトリのルートで実行します。

```bash
cargo build --release --locked
cargo test --workspace --locked
uv run --project integrations --extra locust -m unittest discover -s integrations/tests -v
uv run --no-project -m unittest discover -s scripts/tests -v
uv run --no-project scripts/check_publication.py
```

Python は uv を使い、両方のロックファイルを維持します。プロトコル、入力解析、認証、プロセスの終了処理を変える場合は、その失敗を検出する回帰テストを追加し、[実 DB の検証](e2e/README.ja.md)も実行します。レポートの一致だけでなく、最終データも直接比較します。同じ DB を使う検証は順番に実行します。

変更の目的、結果、検証、残る制約を説明してください。未コミットのコードを大きく変える前にはリポジトリ外に退避します。キャプチャ、実 DB のログ、鍵、資格情報、ローカルの結果ディレクトリを提出物へ含めないでください。

## 依存関係と公開

依存監査と配布物の確認は [公開チェックリスト](docs/publishing.ja.md)に従います。バイナリにはプロジェクトのライセンスと該当する依存ライブラリの通知を同梱します。性能・動作環境は実測した範囲だけを記載します。ジャーナルやスキーマの互換性を変える場合は、形式のバージョンと移行または拒否の方針を明示します。

## 提供する変更のライセンス

明示的に別段の指定がない限り、本プロジェクトへ意図的に提供する変更は、追加条件なしの MIT OR Apache-2.0 のデュアルライセンスで提供されるものとします。正式な条件は [MIT](LICENSE-MIT) / [Apache-2.0](LICENSE-APACHE) を参照してください。
