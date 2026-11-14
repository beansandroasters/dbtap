# End-to-end helpers; load with `source aws/lib.sh`.
export AWS_PROFILE=default
# Pin validation to Tokyo instead of inheriting the caller's region.
export AWS_REGION=ap-northeast-1
export AWS_DEFAULT_REGION=ap-northeast-1
export AWS_PAGER=""
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
STACK=dbtap-verify

# Read one stack output.
out() { aws cloudformation describe-stacks --stack-name $STACK --query "Stacks[0].Outputs[?OutputKey=='$1'].OutputValue" --output text; }

# Run stdin as a script on an instance, wait, then display its output.
#   ssm <instance-id> <wait-seconds> <<'SH' ... SH
ssm() {
  local id=$1 wait=${2:-120} script cmd status
  script=$(cat)
  cmd=$(uv run --no-project python - "$id" "$wait" "$script" <<'PY'
import json, subprocess, sys
iid, wait, script = sys.argv[1], sys.argv[2], sys.argv[3]
params = {"commands": ["set -o pipefail"] + script.split("\n"), "executionTimeout": [str(int(wait) + 30)]}
r = subprocess.run(["aws", "ssm", "send-command", "--instance-ids", iid, "--document-name", "AWS-RunShellScript",
                    "--parameters", json.dumps(params), "--query", "Command.CommandId", "--output", "text"],
                   capture_output=True, text=True)
sys.stdout.write(r.stdout.strip() or ("ERR " + r.stderr.strip()))
PY
)
  case "$cmd" in ERR*) echo "$cmd" >&2; return 1;; esac
  local t=0
  while :; do
    status=$(aws ssm get-command-invocation --command-id "$cmd" --instance-id "$id" --query Status --output text 2>/dev/null || echo Pending)
    case "$status" in Success|Failed|TimedOut|Cancelled) break;; esac
    sleep 3; t=$((t + 3))
    [ $t -gt $((wait + 60)) ] && { echo "(Timed out: $cmd)" >&2; return 1; }
  done
  aws ssm get-command-invocation --command-id "$cmd" --instance-id "$id" --query StandardOutputContent --output text
  if [ "$status" != Success ]; then
    echo "--- $status ---" >&2
    aws ssm get-command-invocation --command-id "$cmd" --instance-id "$id" --query StandardErrorContent --output text >&2
    return 1
  fi
}
