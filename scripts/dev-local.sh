#!/usr/bin/env bash
set -Eeuo pipefail

readonly project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
jui_user_home="$(getent passwd "$(id -u)" | cut -d: -f6)"
readonly tools_root="${JUI_DEV_TOOLS_DIR:-${jui_user_home}/.local/share/j-ui-dev}"
readonly go_binary="${tools_root}/go1.25.12/bin/go"
readonly node_bin="${tools_root}/node22.22.2/bin"
readonly runtime_root="${JUI_DEV_RUNTIME_DIR:-${jui_user_home}/.local/state/j-ui-dev}"
readonly data_directory="${runtime_root}/data"
readonly config_directory="${runtime_root}/config"
readonly certificate_directory="${runtime_root}/certs"
readonly country_code="${JUI_COUNTRY_CODE:-CN}"

if [[ ! -x "$go_binary" || ! -x "${node_bin}/node" ]]; then
  echo "Local toolchain is missing under ${tools_root}." >&2
  echo "Install Go 1.25.12 and Node 22.22.2, or set JUI_DEV_TOOLS_DIR." >&2
  exit 1
fi

export PATH="${node_bin}:${PATH}"
install -d -m 0700 \
  "$runtime_root" \
  "$data_directory" \
  "$config_directory" \
  "$certificate_directory" \
  "${runtime_root}/bin"

if [[ ! -s "${certificate_directory}/localhost.crt" ||
      ! -s "${certificate_directory}/localhost.key" ]]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
    -keyout "${certificate_directory}/localhost.key" \
    -out "${certificate_directory}/localhost.crt" >/dev/null 2>&1
  chmod 0600 \
    "${certificate_directory}/localhost.crt" \
    "${certificate_directory}/localhost.key"
fi

echo "Building Vue frontend with $(node --version)..."
npm --prefix "${project_root}/web" run build
echo "Building Go backend with $("$go_binary" version)..."
"$go_binary" build -o "${runtime_root}/bin/j-ui" "${project_root}/cmd/j-ui"

echo "Starting isolated local instance on http://127.0.0.1:8080"
echo "Runtime data: ${runtime_root}"
echo "TLS test certificate: ${certificate_directory}/localhost.crt"
echo "TLS test private key: ${certificate_directory}/localhost.key"
echo "Press Ctrl-C to stop."

env \
  JUI_DATA_DIR="$data_directory" \
  JUI_CONFIG_DIR="$config_directory" \
  JUI_ALLOW_WEAK_PASSWORDS=1 \
  JUI_COUNTRY_CODE="$country_code" \
  JUI_ENGINE_MODE=mock \
  JUI_MOCK_LIVE_IP_INSPECTION=1 \
  JUI_SERVICE_MODE=server \
  JUI_LISTEN_ADDRESS=127.0.0.1:8080 \
  "${runtime_root}/bin/j-ui" init

exec env \
  JUI_DATA_DIR="$data_directory" \
  JUI_CONFIG_DIR="$config_directory" \
  JUI_ALLOW_WEAK_PASSWORDS=1 \
  JUI_COUNTRY_CODE="$country_code" \
  JUI_ENGINE_MODE=mock \
  JUI_MOCK_LIVE_IP_INSPECTION=1 \
  JUI_SERVICE_MODE=server \
  JUI_LISTEN_ADDRESS=127.0.0.1:8080 \
  "${runtime_root}/bin/j-ui"
