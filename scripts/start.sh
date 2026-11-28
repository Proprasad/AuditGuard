#!/usr/bin/env bash
# Start AuditGuard and wait until it is healthy.
#
#   scripts/start.sh                 full Docker Compose stack (project "auditguard-v3"), builds images
#   scripts/start.sh --no-build      same, reusing existing images
#   scripts/start.sh --local         API + workbench only, from the local venv (SQLite, in-process MCP)
#   scripts/start.sh --timeout 300   seconds to wait for health (default 240)
#
# Local mode honours PORT (default 8000) and HOST (default 127.0.0.1), writes its PID to runs/local/api.pid and
# its log to runs/local/api.log. Stop with scripts/stop.sh (add --local for local mode).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MODE="compose"
BUILD="--build"
TIMEOUT=240
while [[ $# -gt 0 ]]; do
  case "$1" in
    --local) MODE="local" ;;
    --no-build) BUILD="" ;;
    --timeout) TIMEOUT="${2:?--timeout needs a value}"; shift ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "unknown option: $1 (see --help)" >&2; exit 2 ;;
  esac
  shift
done

if [[ ! -f .env ]]; then
  echo "No .env found. Create one first:  cp .env.example .env && python scripts/init_env.py" >&2
  exit 1
fi

wait_for_url() {  # url, seconds
  local url="$1" deadline=$((SECONDS + $2))
  until curl -fs -o /dev/null --max-time 3 "$url"; do
    if (( SECONDS >= deadline )); then return 1; fi
    sleep 2
  done
}

start_local() {
  local host="${HOST:-127.0.0.1}" port="${PORT:-8000}" pid_dir="runs/local"
  local pid_file="$pid_dir/api.pid" log_file="$pid_dir/api.log"
  local py=".venv/bin/python"
  [[ -x "$py" ]] || py="$(command -v python3)"
  mkdir -p "$pid_dir"
  if [[ -f "$pid_file" ]] && kill -0 "$(cat "$pid_file")" 2>/dev/null; then
    echo "AuditGuard (local) already running: PID $(cat "$pid_file"), http://$host:$port/"
    return 0
  fi
  if lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
    echo "Port $port is already in use by another process; set PORT=<free port> or stop that process." >&2
    exit 1
  fi
  nohup "$py" -m uvicorn src.api.main:app --host "$host" --port "$port" >"$log_file" 2>&1 &
  echo $! >"$pid_file"
  if ! wait_for_url "http://$host:$port/health" "$TIMEOUT"; then
    echo "API did not become healthy within ${TIMEOUT}s; last log lines:" >&2
    tail -n 30 "$log_file" >&2
    exit 1
  fi
  echo "AuditGuard (local) is up: PID $(cat "$pid_file")"
  echo "  Workbench:  http://$host:$port/"
  echo "  API docs:   http://$host:$port/api/docs"
  echo "  Log:        $log_file"
}

start_compose() {
  if ! docker compose version >/dev/null 2>&1; then
    echo "Docker Compose v2 is required (docker compose ...). Use --local to run without Docker." >&2
    exit 1
  fi
  # shellcheck disable=SC2086  # BUILD is intentionally empty or a single flag
  docker compose up -d $BUILD
  local deadline=$((SECONDS + TIMEOUT)) health=""
  until [[ "$health" == "healthy" ]]; do
    health="$(docker compose ps api --format '{{.Health}}' 2>/dev/null | head -n 1)"
    if (( SECONDS >= deadline )); then
      echo "API container not healthy within ${TIMEOUT}s (state: ${health:-unknown})." >&2
      docker compose ps >&2
      echo "Inspect with: docker compose logs api" >&2
      exit 1
    fi
    [[ "$health" == "healthy" ]] || sleep 3
  done
  docker compose ps
  echo "AuditGuard (compose project auditguard-v3) is up:"
  echo "  Workbench:  http://127.0.0.1:8000/      API docs: http://127.0.0.1:8000/api/docs"
  echo "  Chainlit:   http://127.0.0.1:8001/      Grafana:  http://127.0.0.1:3001/   Prometheus: http://127.0.0.1:9090/"
}

if [[ "$MODE" == "local" ]]; then start_local; else start_compose; fi
