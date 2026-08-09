#!/usr/bin/env bash
set -Eeuo pipefail

readonly project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly management_port="${JUI_E2E_MANAGEMENT_PORT:-18081}"
readonly node_port="${JUI_E2E_NODE_PORT:-18082}"
runtime_directory="$(mktemp -d /tmp/j-ui-browser-smoke.XXXXXX)"
server_pid=""

cleanup() {
  local exit_code=$?
  trap - EXIT
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" >/dev/null 2>&1 || true
    wait "$server_pid" >/dev/null 2>&1 || true
  fi
  rm -rf -- "$runtime_directory"
  exit "$exit_code"
}
trap cleanup EXIT

if [[ ! "$management_port" =~ ^[0-9]+$ ]] ||
  ((10#$management_port < 1 || 10#$management_port > 65535)); then
  echo "Invalid JUI_E2E_MANAGEMENT_PORT." >&2
  exit 1
fi
if [[ ! "$node_port" =~ ^[0-9]+$ ]] ||
  ((10#$node_port < 1 || 10#$node_port > 65535)); then
  echo "Invalid JUI_E2E_NODE_PORT." >&2
  exit 1
fi

npm --prefix "${project_root}/web" run build
go build -o "${runtime_directory}/j-ui" "${project_root}/cmd/j-ui"

export JUI_DATA_DIR="${runtime_directory}/data"
export JUI_CONFIG_DIR="${runtime_directory}/config"
export JUI_COUNTRY_CODE=CN
export JUI_ENGINE_MODE=mock
export JUI_LISTEN_ADDRESS="127.0.0.1:${management_port}"
export JUI_SERVICE_MODE=server

initialization_output="$("${runtime_directory}/j-ui" init)"
password="$(sed -n 's/^Password: //p' <<<"$initialization_output")"
management_url="$(sed -n 's/^Management URL: //p' <<<"$initialization_output")"
admin_path="${management_url%/}"
admin_path="${admin_path##*/}"
if [[ -z "$password" || ! "$admin_path" =~ ^manage-[0-9a-f]{24}$ ]]; then
  echo "Unable to parse isolated J-UI credentials." >&2
  exit 1
fi

"${runtime_directory}/j-ui" >"${runtime_directory}/server.log" 2>&1 &
server_pid=$!
health_url="http://127.0.0.1:${management_port}/api/v1/health"
for _ in {1..50}; do
  if curl -fsS "$health_url" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$server_pid" >/dev/null 2>&1; then
    cat "${runtime_directory}/server.log" >&2
    exit 1
  fi
  sleep 0.1
done
if ! curl -fsS "$health_url" >/dev/null; then
  cat "${runtime_directory}/server.log" >&2
  exit 1
fi

export JUI_E2E_BASE_URL="http://127.0.0.1:${management_port}"
export JUI_E2E_ADMIN_PATH="$admin_path"
export JUI_E2E_PASSWORD="$password"
export JUI_E2E_NODE_PORT="$node_port"
if [[ -z "${JUI_E2E_BROWSER_PATH:-}" ]]; then
  expected_browser="$(
    node -e 'process.stdout.write(require("playwright").chromium.executablePath())' \
      2>/dev/null || true
  )"
  if [[ -n "$expected_browser" && -x "$expected_browser" ]]; then
    export JUI_E2E_BROWSER_PATH="$expected_browser"
  else
    browser_cache="${XDG_CACHE_HOME:-${HOME}/.cache}/ms-playwright"
    fallback_browser=""
    if [[ -d "$browser_cache" ]]; then
      fallback_browser="$(
        find "$browser_cache" -path '*/chrome-linux/headless_shell' -type f \
          -executable -print | sort -V | tail -n 1
      )"
    fi
    if [[ -n "$fallback_browser" ]]; then
      export JUI_E2E_BROWSER_PATH="$fallback_browser"
      echo "Using compatible cached Chromium: $fallback_browser"
    fi
  fi
fi
node "${project_root}/web/e2e/smoke.mjs"
