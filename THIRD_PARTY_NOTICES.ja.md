# 依存ライブラリとライセンス通知

[English](THIRD_PARTY_NOTICES.md) | 日本語

dbtap のソースは MIT OR Apache-2.0 ですが、**依存ライブラリはそれぞれのライセンスに従います**。プロジェクトのライセンスで依存物の著作権表示・条件を置き換えることはできません。

## Rust

`Cargo.lock` が依存関係を固定します。[依存一覧](docs/dependencies.json)には、このソースツリーについて確認したレジストリ上の名前・版・宣言ライセンスを記載しています。ビルド用・別 OS 用も含む一覧であり、ライセンス本文の代わりにはなりません。

- rustls / tokio-rustls / aws-lc-rs / aws-lc-sys / ring: TLS と暗号処理。内包するネイティブコードの通知も必要です。
- webpki-roots: Mozilla 由来のルート証明書データ。CDLA-Permissive-2.0。
- zstd / zstd-safe / zstd-sys: 圧縮。内包する zstd の通知も対象です。
- tokio / libc: 実行環境と OS インターフェイス。
- serde / serde_json / csv / chrono: 記録、レポート、ログ、時刻。
- clap / anyhow: CLI とエラー処理。
- rsa / sha1 / sha2 / md-5 / base64 / subtle / rand: DB 認証など。
- xxhash-rust: 結果と文の形のハッシュ。

`deny.toml` は確認したライセンスと crates.io 由来の依存だけを許可します。`cargo deny --locked check` で既知脆弱性、ライセンス、取得元、依存制限を確認します。選択式ライセンスは許可した選択肢で満たせます。一覧に別の選択肢があるだけで、その条件を選ぶ義務はありません。

## Python と外部ツール

`integrations/` の標準ライブラリによる変換器に必須の外部依存はありません。任意の Locust 連携は `integrations/uv.lock` に固定し、Locust と推移依存は各ライセンスに従います。Python 配布物には dbtap の両ライセンスを同梱します。

PostgreSQL、MySQL、Docker、pgbench、JMeter、k6、Locust、AWS は独立した製品・プロジェクトです。名称は互換性を示し、提携や推奨を意味しません。それらのバイナリとコンテナイメージはソース配布物に含みません。

## バイナリを配布する場合

LICENSE-MIT と LICENSE-APACHE に加え、対象プラットフォームと feature で使用する依存の LICENSE / COPYING / NOTICE を集めます。ネイティブコード内の依存とルート証明書データの条件、著作権表示、変更通知も確認します。一覧やライセンス検査だけでは本文の同梱を代替できません。

現在準備しているのはソース公開です。完成したリリースアーカイブやバイナリ用の全通知セットは含みません。バイナリ配布前、および lockfile・feature・対象環境の変更時に同梱物を確認してください。[公開チェックリスト](docs/publishing.ja.md)も参照してください。
