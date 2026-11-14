# 再生の設計

[English](architecture.md) | 日本語

## 構成

| crate | 役割 |
|---|---|
| dbtap-core | ジャーナル、単位、観測項目 |
| dbtap-proto | PostgreSQL / MySQL の通信復元、Extractor |
| dbtap-capture | TCP、pcap / pcapng、AF_PACKET |
| dbtap-logs | PostgreSQL CSV / MySQL slow log の変換 |
| dbtap-replay | 依存関係の計画、DB 接続、再生、比較、集計、時系列 |
| dbtap-cli | capture / import-logs / inspect / replay / report |

負荷ツールとの連携は `integrations/` の Python パッケージです。

## ジャーナルと単位

ジャーナルは `DBTAPJ1\n` のマジックと zstd ストリームからなります。レコードは Header、ConnOpen、Data、ConnClose、Lost、Session、Unit です。Data は接続・向き・時刻・バイト列、Session / Unit は DB ログからの復元済み情報を持ちます。詳細は [journal.rs](../crates/dbtap-core/src/journal.rs)にあります。形式には電子署名・改変検知はありません。

通信由来の単位は PostgreSQL の Query または Sync から ReadyForQuery まで、MySQL の 1 コマンドと応答です。1 単位に SQL が複数含まれることがあります。要求のバイト列を再生し、認証は再生先の資格情報でやり直します。MySQL のプリペアド文 ID は再生先の応答に合わせて置き換えます。

ログ由来では 1 実行を 1 単位へ組み直します。パラメータ付き PostgreSQL は Parse / Bind / Execute / Sync、パラメータなしは Query、MySQL は COM_QUERY を作ります。元の型指定・バイナリ転送・パイプライン境界などは保持できません。

`Unit.observed` はエラー、行数、影響行数、内容、所要時間の観測可否です。比較・時間の集計はこの情報に従います。

## 復元と先読み

TCP は向きごとのシーケンス番号と、向きをまたぐ ACK の順序を使います。ミラーの到着順が要求・応答の順と異なる場合も復元します。SYN を見ない接続は 20 ms 待ってから途中接続として扱います。

Extractor は単位を応答完了時に出力します。読み手が依存関係を付け、接続ごとのタスクが予定時刻と依存関係の完了を待って送信します。接続内は直列です。複数ジャーナルは時刻順に混ぜ、接続 ID は入力間で分離します。

先読みは既定 10 秒、待機中の単位数は既定 100,000 件です。先読みより長い要求は、単位を復元できる時点が遅くなるため送信も遅れます。接続管理・復元途中の要求・大きな SQL にもメモリを使うので、全体の使用バイト数を制限する仕組みではありません。

専用スレッドのタイマーで予定時刻を待ちます。実測の開始時刻と応答時間は、開始時の実時計と単調時計の対応から求めます。samples は完了キュー (最大 4,096 件) を経由し、100 ms ごとに flush します。出力が遅いと送信にも待ちが伝わります。

## 依存関係

| order | 待つ相手 | 制約 |
|---|---|---|
| row (既定) | 同じサーバー・テーブルで値が共通する操作。値なしはテーブル全体 | 範囲検索や別の列の条件を完全には扱えない |
| table | 同じサーバー・テーブルに触る操作 | 待ちが広く伝わり、送信時系列が伸びやすい |
| time | 予定時刻と接続内の順序のみ | 接続間の書き込み順を保たない |

一方が書き込みで、記録上で重なっていない操作の順序を保ちます。重なった書き込みは、同じ形の文の速い所要時間と値の共通性からロック競合を推定します。COMMIT / ROLLBACK は、そのトランザクションが触ったテーブル・値に反映します。エラーで終わった書き込みは広めに依存関係を取ります。

テーブルは SQL の字句から抽出します。ビュー・ストアド内部の参照先は分かりません。特定できない書き込みはサーバー全体に依存させます。これは DB 内部の実行順やトランザクション可視性を復元する仕組みではありません。

## ロック待ち

再生側の依存関係と DB 内のロック待ちが循環するときは、待ちを解除して先へ進み、その件数を記録します。

- PostgreSQL は `pg_blocking_pids` を使います。
- MySQL は `performance_schema.data_lock_waits` を使い、performance_schema と SELECT 権限が必要です。
- 取得できない場合や `--no-lock-probe` 指定時は、トランザクション状態と時間で判定します。猶予は記録の所要時間の 2 倍 + `--lock-grace-ms` (既定 100 ms) です。

依存関係を待つ上限は `--causal-timeout-ms` (既定 1,000 ms)。解除した順序、待ち切れない相手、送信遅れはレポートで確認します。

## 複数プロセス・ホスト

全台に同じジャーナル一式を同じ順で渡し、時計を同期します。`--shard K/N` の K は 0 始まり、`--shard-by conn` は接続単位、`client` は記録上のクライアントホスト単位の担当です。

```bash
start_at=$(( $(date +%s) + 30 ))
./target/release/dbtap replay capture.dbtap --pg clone:5432 \
  --shard 0/2 --start-at "$start_at" --run-id trial1 --samples w0.jsonl --report r0.json
# もう一方は同じ start_at / run-id と --shard 1/2、別の出力先を指定
```

各ワーカーは別担当の単位を完了済みとして扱い、ワーカー間の依存関係は同期しません。途中の台数変更や再起動からの継続は未対応です。負荷ツールからの起動と全 shard の結果検査は [integrations](../integrations/README.ja.md)を参照してください。
