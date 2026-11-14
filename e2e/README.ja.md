# ローカル検証

[English](README.md) | 日本語

リポジトリのルートで実行します。Linux、Docker、Rust / Cargo、uv が必要です。キャプチャには sudo、tcpdump 経路には tcpdump、TLS 検証には OpenSSL が必要です。Python スクリプトは uv で実行します。

`up.sh` は `dbtap-pg-src` / `dbtap-pg-dst` / `dbtap-my-src` / `dbtap-my-dst` を作り直します。同名の既存コンテナは削除します。PostgreSQL 17 と MySQL 8.4 を使用し、ポートは 127.0.0.1 の 15432 / 15433 / 13306 / 13307、検証用パスワードは `secret` です。

起動中に DB が停止するか、180秒以内に準備できない場合は、直近のコンテナログを表示して終了します。ディスク不足の場合は Docker の保存先容量を確認し、自分が管理する使い捨て資源だけを整理します。`up.sh` の作り直しと `down` は4コンテナに付属する匿名データボリュームも削除します。

## 基本の通し検証

```bash
cargo build --release --locked
cargo test --workspace --locked
e2e/up.sh
e2e/run.sh
e2e/up.sh down
```

`run.sh` は初期化、負荷を流しながらの記録、複製への再生、テーブルの直接比較を行います。結果は毎回新しい `/tmp/dbtap/e2e-XXXXXX` に保存し、終了時にパスを表示します。`WORK=/任意の新しいディレクトリ` でも指定できます。既存のジャーナル・レポートは上書きできません。

accounts の残高、orders の業務列、PostgreSQL の bulk を比較します。採番 ID は並行実行で変わり得るため別に表示します。`run.sh` と `state.sh` の結果に加え、レポートの実行失敗・skip・比較判定も確認してください。

## 入力と再生方式

DB が起動した状態で、各コマンドを順番に実行します。同じ DB の初期化を行うため、並列には実行しません。

```bash
CAPTURE=tcpdump e2e/run.sh
REPLAY_ARGS="--speed 4" e2e/run.sh
REPLAY_ARGS="--order table" e2e/run.sh
e2e/multi.sh
e2e/logs.sh
e2e/logs.sh --full
e2e/logs.sh --mysql
```

`logs.sh` は DB ログと通信の SQL 実行数・時刻を照合してから再生します。`--full` は PostgreSQL の COPY が再生不可となり、bulk のデータが不足することを期待した検査です。通信の単位数には管理コマンド等も含まれるため、SQL 実行数と分けて集計します。

```bash
uv run e2e/log_probe.py /tmp/dbtap/probe-new
uv run --no-project e2e/log_regressions.py
uv run --no-project e2e/logging_bench.py --out /tmp/dbtap/log-bench-new --seconds 30
```

ログの設定だけを操作する場合:

```bash
e2e/logging.sh on
uv run -q e2e/workload.py --pg 15432 --my 13306
e2e/logging.sh off
e2e/logging.sh fetch /tmp/dbtap/logs-new
```

## Locust と TLS

```bash
WORK=/tmp/dbtap/tools-capture-new e2e/run.sh --workers 4 --ops 40
uv run --project integrations --extra locust -m unittest discover -s integrations/tests -v
uv run --project integrations --extra locust e2e/loadtools.py \
  /tmp/dbtap/tools-capture-new/cap.dbtap /tmp/dbtap/tools-new

# dst 2 台の証明書を変更するので、最後に実行する
uv run --no-project e2e/tls.py /tmp/dbtap/tools-capture-new/cap.dbtap /tmp/dbtap/tls-new
e2e/up.sh down
```

Locust は単独・同一ホストの 2 ワーカー、途中停止、接続不能を検査します。TLS は正しい CA・ホスト名での成功と、未登録 CA・ホスト名不一致での送信前の失敗を確認します。成果物には秘密鍵・ジャーナル・ログが含まれるため、公開対象に入れません。

## pgbench

`up.sh` の後に実行します。CPU・I/O の影響を測る場合は、他の負荷やビルドと同時に実行しません。

```bash
src=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' dbtap-pg-src)
dst=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' dbtap-pg-dst)
for name in dbtap-pg-src dbtap-pg-dst; do
  docker exec -e PGPASSWORD=secret "$name" pgbench -q -i -s 10 -U postgres shop
done
sudo ./target/release/dbtap capture --iface docker0 --pg-port 5432 -o bench.dbtap --duration 14 &
capture_pid=$!
sleep 1
docker exec -e PGPASSWORD=secret dbtap-pg-dst pgbench -h "$src" -U postgres -c 32 -j 8 -T 10 -M prepared shop
wait "$capture_pid"
sudo chown "$(id -u)" bench.dbtap
DBTAP_PASSWORD=secret ./target/release/dbtap replay bench.dbtap --pg "$dst:5432" --tls disable
e2e/pgbench_check.sh
e2e/up.sh down
```

実測値と未検証の範囲は [検証結果](../docs/validation.ja.md)を参照してください。
