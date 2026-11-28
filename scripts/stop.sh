#!/usr/bin/env bash
# Stop AuditGuard.
#
#   scripts/stop.sh             stop the Docker Compose stack (project "auditguard-v3"); data volumes are kept
#   scripts/stop.sh --volumes   also delete the stack's volumes (Postgres and Grafana data). Irreversible.
#   scripts/stop.sh --local     stop the local-mode API started by scripts/start.sh --local
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MODE="compose"
VOLUMES=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --local) MODE="local" ;;
    --volumes) VOLUMES="--volumes" ;;
    -h|--help) sed -n '2,7p' "$0"; exit 0 ;;
    *) echo "unknown option: $1 (see --help)" >&2; exit 2 ;;
  esac
  shift
done

stop_local() {
  local pid_file="runs/local/api.pid"
  if [[ ! -f "$pid_file" ]]; then
    echo "No local AuditGuard PID file ($pid_file); nothing to stop."
    return 0
  fi
  local pid
  pid="$(cat "$pid_file")"
  if kill -0 "$pid" 2>/dev/null; then
    kill -TERM "$pid"
    for _ in $(seq 1 20); do
      kill -0 "$pid" 2>/dev/null || break
      sleep 0.5
    done
    if kill -0 "$pid" 2>/dev/null; then
      echo "PID $pid did not exit after SIGTERM; sending SIGKILL."
      kill -KILL "$pid"
    fi
    echo "Stopped local AuditGuard (PID $pid)."
  else
    echo "Local AuditGuard (PID $pid) was not running; removing stale PID file."
  fi
  rm -f "$pid_file"
}

if [[ "$MODE" == "local" ]]; then
  stop_local
else
  # shellcheck disable=SC2086  # VOLUMES is intentionally empty or a single flag
  docker compose down $VOLUMES
fi
