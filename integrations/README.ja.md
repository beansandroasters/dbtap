# 負荷テストツールとの連携

[English](README.md) | 日本語

まず 1 台で再生し、CPU・メモリ・ファイル記述子・ネットワークと `lag` (予定からの送信遅れ) を見る。十分な台数やインスタンスサイズは負荷次第で、まだ上限を測っていない。1 台でも Rust/Tokio が複数コアと多数の接続を使う。複数台では全台に**同じジャーナル一式を同じ順で**置き、接続を `--shard K/N` で分担する。各台の時計も同期する。

時間帯ごとの増減、SQL の構成、接続の寿命、接続内の順序を再現する。再生先が遅ければ、同じ接続の次の要求も遅れる。`--speed 2` は予定時刻を半分に縮める指定で、実際の TPS が必ず 2 倍になる指定ではない。CPU 使用率・I/O・ロック競合は DB の状態や構成によって変わる。

**ワーカー間のトランザクション依存関係は同期しない。** 結果一致の確認はまず 1 台で行い、複数台は負荷を送る能力が必要なときに使う。実行途中の台数変更やワーカー再起動による途中再開には対応していない。

| ツール | 対応範囲 |
|---|---|
| Locust 2.43.3 | 実行・固定ワーカーへの分割・完了時の request イベント・集計 |
| Apache JMeter 5.6.3 | JTL CSV の出力。`jmeter -g` で HTML レポートを生成 |
| k6 | Metric/Point JSON 形式の結果出力。k6 スクリプトへの変換や k6 本体からの再生ではない |
| pgbench / sysbench | 発生させた DB 負荷を既存の通信/ログ取り込みで記録できる。専用プラグインは不要。sysbench 自体の実行は未検証 |

## 共通の時系列

```bash
dbtap replay cap.dbtap --pg clone:5432 --tls require \
  --samples samples.jsonl --run-id trial1 --report report.json
uv run --project integrations dbtap-export jmeter samples.jsonl -o result.jtl
uv run --project integrations dbtap-export k6 samples.jsonl -o result.k6.json
```

リポジトリのルートで実行し、ビルドした `dbtap` を PATH に配置する。

`--samples` は新規ファイルだけに書く (Unix 0600)。`schema: 1` の start、完了ごとの sample、処理終了時の end が並ぶ。100 ms ごとに flush する。出力が遅いと再生側にも待ちが伝わり、送信遅れとして現れる。出力キューは 4,096 件に制限し、書き込みに失敗した場合は終了コードを非 0 にする。負荷容量を測るときは、samples ありの構成でも測る。

- `timing.started_unix_ns`: 実際の送信開始時刻。開始時に実時計と単調時計を対応させ、以後の時刻・応答時間は単調時計から求める。
- `timing.latency_ns`、`lag_ns`、`waited_ns`: 応答時間、送信遅れ、そのうち依存関係を待った時間。
- `captured_start_ns` / `captured_end_ns`: 元の記録の時刻。未知の所要時間は `captured_duration_ns: null`。
- `request_success`: 再生先の DB エラー/通信エラーがなかったか。未送信は null。
- `comparison`: 記録に残っていた項目での一致判定。元と同じエラーなら Match でも request_success は false。
- `observed`: 比較できた項目。`shape_id` は文の形のハッシュ。

SQL・バインド値・要求本体・接続先・ユーザー名・エラー本文は出さない。ただし時系列や shape_id も業務の傾向を表す情報で、匿名化の保証ではない。通常の `--report` と標準出力には SQL が含まれる。

分散実行の結果は、全ワーカーで同じ run-id にする。変換器は別実行の混在、重複 shard、欠けた shard、途中で切れたファイル、連番の欠けを拒否する。既存出力を上書きせず、全入力を検査してから完成ファイルを公開する。

```bash
uv run --project integrations dbtap-export jmeter w0.jsonl w1.jsonl -o all.jtl
```

## Locust

ホストごとにローカル設定を書く。パスワードは `DBTAP_PASSWORD` から渡す。argv は配列で、シェルによる展開はしない。

```json
{
  "argv": ["/opt/dbtap", "replay", "/data/cap.dbtap", "--pg", "clone:5432", "--tls", "require"],
  "output_dir": "/data/results"
}
```

単独実行:

```bash
uv run --project integrations --extra locust locust -f integrations/locustfile.py \
  --headless -u 1 -r 1 --run-time 30m --dbtap-config /data/locust.json --csv /data/trial1
```

`-u` は DB 接続数を増やさない。プロセスごとに dbtap を一度だけ起動し、DB 接続数は記録に従う。最終集計は `trial1_final_stats.csv`。Locust 標準の `trial1_stats.csv` は定期出力で、終了直前の要求を含まないことがある。各実行の samples/stdout/stderr は output_dir 以下の専用ディレクトリに残る。

2 ワーカー (制御ポート 5557 はワーカーの SG だけに許可する。Locust の制御通信に認証機構を追加するアダプターではない):

```bash
# master: --master-bind-host は master のプライベート IP
uv run --project integrations --extra locust locust -f integrations/locustfile.py \
  --headless --master --master-bind-host 10.0.1.10 --expect-workers 2 \
  -u 2 -r 2 --run-time 30m --csv /data/trial1

# 各ワーカーで 1 回。同じ記録と再生先、ホストごとのローカル設定を用意する
uv run --project integrations --extra locust locust -f integrations/locustfile.py \
  --headless --worker --master-host 10.0.1.10 --dbtap-config /data/locust.json
```

master は再生せず、開始時点のワーカーを 0/N … N-1/N に割り振り、5 秒後の共通時刻を指定する。途中参加には割り当てない。再実行にはプロセスを新しく起動する。停止時は子 dbtap も終了する。途中終了の samples には end がなく、変換時に拒否される。

Locust では DB エラーを失敗に数える。記録どおりのエラーでも失敗なので、再現性の成否は dbtap の comparison / report も見る。Locust のエラー時終了コードを意図的に無効にするなら `--exit-code-on-error 0`。アダプターの異常終了はそれでも 1 になる。Locust の起動待ち時間も全体の平均 RPS の分母に入り、CSV の秒単位履歴には flush 周期 100 ms とスケジューリングによる通知の遅れがある。正確な送信時系列は samples を使う。

## JMeter

```bash
jmeter -g result.jtl -o html-report
```

時刻は要求開始の UNIX ミリ秒、elapsed は実測応答時間のミリ秒。エラー率は request_success を使う。未送信や skip は要求の標本に数えないので、元の samples/report で別に確認する。

標準の HTML 生成が必要とする bytes/sentBytes/grpThreads/allThreads/Latency/Connect は未計測なので **0 のプレースホルダー**。転送量・スレッド数・最初の応答までの時間・接続時間のグラフは使わない。応答時間・件数・エラー・時間帯の傾向を見るための連携。elapsed は整数 ms のため、小さい応答時間は 0 に丸められる。

## k6 JSON

1 単位を `iterations` の 1 件、実測応答時間を `iteration_duration` とする。`dbtap_lag` / `dbtap_dependency_wait` は ms、`dbtap_failed` は DB/通信エラーの rate、`checks` は比較判定で許容された割合。HTTP の要求としては記録しない。ラベルは最大 128 種類、それ以上は other。ポイントは完了時刻順にディスク上で整列する。

**k6-web-dashboard v0.8.1 の `aggregate` には終了時の未処理バッファが落ちる問題がある。** 検証では JSON 1,450 件に対して、この版の HTML は 1,341 件となった。公式ソースの `dashboard/aggregate.go` で EOF 時に flush しないことも確認した。この版の HTML を正しい総数の検証には使わない。JSON 自体には 1,450 件すべて含まれる。

## 検証

```bash
uv run --project integrations --extra locust -m unittest discover -s integrations/tests -v
# e2e/up.sh の後。どちらも未使用の出力先を指定する
WORK=/tmp/dbtap/tools-capture e2e/run.sh --workers 4 --ops 40
uv run --project integrations --extra locust e2e/loadtools.py /tmp/dbtap/tools-capture/cap.dbtap /tmp/dbtap/tools-test
```

2026-11-14 の実測では、単独と同一ホストの 2 ワーカーで各 1,450 件・DB エラー 24 件が最終 CSV と一致し、再生後のテーブルと採番 ID も一致した。途中停止は子プロセスを回収して終了コード 1、接続不能は 1,450 件すべてを未送信として扱い、架空の 0 ms の標本を足さないことも確認した。[検証結果](../docs/loadtools-validation-20261114.json)を参照。複数インスタンスでの実行と容量の上限は未測定。

参照: [Locust custom protocols](https://docs.locust.io/en/stable/testing-other-systems.html)、
[JMeter result formats](https://jmeter.apache.org/usermanual/listeners.html)、
[k6 JSON](https://grafana.com/docs/k6/latest/results-output/real-time/json/)。
