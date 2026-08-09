#!/usr/bin/env bash
set -Eeuo pipefail

readonly repository="${JUI_GITHUB_REPOSITORY:-Suparluxi/j-ui}"
readonly singbox_version="1.13.16"
temporary_directory=""
result_recorded=0
target_version="${JUI_VERSION:-unknown}"
backup_path=""
mutation_started=0
rollback_attempted=0
services_quiesced=0
previous_jui_active=0
previous_jui_enabled=0
previous_singbox_active=0
previous_singbox_enabled=0
recovery_path=""

github_curl() {
  if [[ -n "${JUI_GITHUB_TOKEN:-}" ]]; then
    if [[ ! "$JUI_GITHUB_TOKEN" =~ ^[A-Za-z0-9_]+$ ]]; then
      echo "JUI_GITHUB_TOKEN contains unsupported characters." >&2
      return 2
    fi
    {
      printf 'header = "Authorization: Bearer %s"\n' "$JUI_GITHUB_TOKEN"
      printf 'header = "X-GitHub-Api-Version: 2022-11-28"\n'
    } | curl --config - "$@"
  else
    curl "$@"
  fi
}

download_release_asset() {
  local name="$1"
  local destination="$2"
  if [[ -z "${JUI_GITHUB_TOKEN:-}" ]]; then
    github_curl -fsSL "${release_base}/${name}" -o "$destination"
    return
  fi
  local metadata asset_url
  metadata="$(github_curl -fsSL \
    "https://api.github.com/repos/${repository}/releases/tags/v${version}")"
  asset_url="$(
    printf '%s' "$metadata" |
      jq -r --arg name "$name" '.assets[] | select(.name == $name) | .url' |
      head -n 1
  )"
  if [[ ! "$asset_url" =~ ^https://api\.github\.com/repos/.+/releases/assets/[0-9]+$ ]]; then
    echo "Release asset ${name} was not found." >&2
    return 1
  fi
  github_curl -fsSL -H "Accept: application/octet-stream" \
    "$asset_url" -o "$destination"
}

rollback_update() {
  rollback_attempted=1
  rollback_failed=0
  systemctl stop j-ui.service j-ui-sing-box.service 2>/dev/null || true
  if [[ -x /usr/local/bin/j-ui ]]; then
    /usr/local/bin/j-ui cleanup-firewall >/dev/null 2>&1 || rollback_failed=1
    if systemctl list-units --all --plain --no-legend 'jui-vpngate-*' | grep -q .; then
      /usr/local/bin/j-ui cleanup-vpngate >/dev/null 2>&1 || rollback_failed=1
    fi
  fi
  rm -f -- /usr/local/bin/j-ui.new || rollback_failed=1
  for target in "${managed_targets[@]}"; do
    if ! rm -f -- "$target"; then
      rollback_failed=1
      continue
    fi
    snapshot="${temporary_directory}/managed${target}"
    if [[ -e "$snapshot" || -L "$snapshot" ]]; then
      if ! cp -a -- "$snapshot" "$target"; then
        rollback_failed=1
      fi
    fi
  done
  for tree in /etc/j-ui /var/lib/j-ui; do
    if ! rm -rf -- "$tree"; then
      rollback_failed=1
      continue
    fi
    snapshot="${temporary_directory}/trees${tree}"
    if [[ -d "$snapshot" ]]; then
      if ! install -d -m 0755 "$(dirname "$tree")" ||
        ! cp -a -- "$snapshot" "$tree"; then
        rollback_failed=1
      fi
    fi
  done
  if ! systemctl daemon-reload; then
    rollback_failed=1
  fi
  systemctl disable j-ui.service j-ui-sing-box.service >/dev/null 2>&1 || true
  if [[ $previous_singbox_enabled -eq 1 ]]; then
    systemctl enable j-ui-sing-box.service >/dev/null 2>&1 || rollback_failed=1
  fi
  if [[ $previous_jui_enabled -eq 1 ]]; then
    systemctl enable j-ui.service >/dev/null 2>&1 || rollback_failed=1
  fi
  if [[ $previous_singbox_active -eq 1 ]]; then
    systemctl start j-ui-sing-box.service >/dev/null 2>&1 || rollback_failed=1
    systemctl is-active --quiet j-ui-sing-box.service >/dev/null 2>&1 || rollback_failed=1
  fi
  if [[ $previous_jui_active -eq 1 ]]; then
    systemctl start j-ui.service >/dev/null 2>&1 || rollback_failed=1
    systemctl is-active --quiet j-ui.service >/dev/null 2>&1 || rollback_failed=1
  fi
  return "$rollback_failed"
}

preserve_recovery() {
  local destination="/var/backups/j-ui/recovery-update-$(date -u +%Y%m%dT%H%M%SZ)-$$"
  install -d -m 0700 "$(dirname "$destination")" >/dev/null 2>&1 || true
  if [[ -n "$backup_path" && -f "$backup_path" ]]; then
    cp -a -- "$backup_path" "${temporary_directory}/logical-backup.tar.gz" >/dev/null 2>&1 || true
  fi
  # The updater runs with PrivateTmp=true, so /tmp and /var may be different
  # mounts. Copy rather than rename to make the recovery bundle persistent.
  if cp -a -- "$temporary_directory" "$destination" >/dev/null 2>&1; then
    sync -f "$destination" >/dev/null 2>&1 || true
    recovery_path="$destination"
    rm -rf -- "$temporary_directory"
    temporary_directory=""
  else
    recovery_path="persistent recovery copy failed (transient source: ${temporary_directory})"
  fi
}

cleanup() {
  local exit_code=$?
  trap - EXIT
  set +e
  if [[ $exit_code -ne 0 && $mutation_started -eq 1 && $rollback_attempted -eq 0 ]]; then
    if rollback_update; then
      echo "Update failed; the previous binary, units, scripts, database, and configuration were restored." >&2
    else
      preserve_recovery
      echo "Update and automatic rollback both failed; recovery bundle: ${recovery_path}; logical backup: ${backup_path}" >&2
    fi
  elif [[ $exit_code -ne 0 && $services_quiesced -eq 1 ]]; then
    if [[ $previous_singbox_active -eq 1 ]]; then systemctl start j-ui-sing-box.service >/dev/null 2>&1 || true; fi
    if [[ $previous_jui_active -eq 1 ]]; then systemctl start j-ui.service >/dev/null 2>&1 || true; fi
  fi
  if [[ $exit_code -ne 0 && $result_recorded -eq 0 && -x /usr/local/bin/j-ui ]]; then
    /usr/local/bin/j-ui internal-update-result failed "$target_version" >/dev/null 2>&1 || true
  fi
  if [[ -n "$temporary_directory" && -d "$temporary_directory" && -z "$recovery_path" ]]; then
    rm -rf -- "$temporary_directory"
  fi
  exit "$exit_code"
}
trap cleanup EXIT

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Run this updater as root." >&2
  exit 1
fi
if [[ ! "$repository" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
  echo "Invalid JUI_GITHUB_REPOSITORY." >&2
  exit 1
fi
exec 9>/run/lock/j-ui-lifecycle.lock
if ! flock -n 9; then
  echo "Another J-UI install, update, or restore operation is running." >&2
  exit 1
fi
case "$(uname -m)" in
  x86_64) architecture="amd64" ;;
  aarch64|arm64) architecture="arm64" ;;
  *) echo "Unsupported architecture." >&2; exit 1 ;;
esac
if [[ -n "${JUI_GITHUB_TOKEN:-}" ]] && ! command -v jq >/dev/null 2>&1; then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y jq
fi

version="${JUI_VERSION:-}"
if [[ -z "$version" ]]; then
  version="$(github_curl -fsSL "https://api.github.com/repos/${repository}/releases/latest" |
    jq -r '.tag_name // empty' | sed -n 's/^v//p' | head -n 1)"
fi
target_version="$version"
if [[ -z "$version" ]]; then
  echo "Unable to determine the latest J-UI version." >&2
  exit 1
fi
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
  echo "Invalid J-UI version: ${version}" >&2
  exit 1
fi
temporary_directory="$(mktemp -d /tmp/j-ui-update.XXXXXX)"
declare -a managed_targets=(
  /usr/local/bin/j-ui
  /usr/local/bin/J-UI
  /usr/local/bin/jui
  /usr/local/bin/J-Ui
  /usr/local/bin/J-uI
  /usr/local/bin/J-ui
  /usr/local/bin/j-UI
  /usr/local/bin/j-Ui
  /usr/local/bin/j-uI
  /usr/local/bin/jui-menu
  /usr/local/lib/j-ui/sing-box
  /etc/systemd/system/j-ui.service
  /etc/systemd/system/j-ui-update.service
  /etc/systemd/system/j-ui-sing-box.service
  /etc/systemd/system/j-ui-certificate-renew.service
  /etc/systemd/system/j-ui-certificate-renew.timer
  /etc/systemd/system/j-ui-certificate-issue@.service
  /usr/local/lib/j-ui/update.sh
  /usr/local/lib/j-ui/uninstall.sh
  /usr/local/lib/j-ui/manage.sh
  /usr/local/lib/j-ui/ssl.sh
  /usr/local/lib/j-ui/argo.sh
)
archive="j-ui_${version}_linux_${architecture}.tar.gz"
release_base="https://github.com/${repository}/releases/download/v${version}"
download_release_asset "$archive" "${temporary_directory}/${archive}"
download_release_asset "checksums.txt" "${temporary_directory}/checksums.txt"
(
  cd "$temporary_directory"
  grep " ${archive}\$" checksums.txt | sha256sum --check --status
)
tar -xzf "${temporary_directory}/${archive}" -C "$temporary_directory"
for required in j-ui deploy/j-ui.service deploy/j-ui-update.service deploy/j-ui-sing-box.service \
  deploy/j-ui-certificate-renew.service deploy/j-ui-certificate-renew.timer \
  deploy/j-ui-certificate-issue@.service \
  scripts/update.sh scripts/uninstall.sh scripts/manage.sh scripts/ssl.sh scripts/argo.sh sing-box; do
  if [[ ! -e "${temporary_directory}/${required}" ]]; then
    echo "Release archive is missing ${required}." >&2
    exit 1
  fi
done
candidate_singbox_version="$("${temporary_directory}/sing-box" version | sed -n '1s/^sing-box version //p')"
if [[ "$candidate_singbox_version" != "$singbox_version" ]]; then
  echo "Release archive contains sing-box ${candidate_singbox_version:-unknown}; expected ${singbox_version}." >&2
  exit 1
fi
if [[ -s /etc/j-ui/sing-box.json ]]; then
  "${temporary_directory}/sing-box" check -c /etc/j-ui/sing-box.json
fi

backup_path="/var/backups/j-ui/pre-update-$(date -u +%Y%m%dT%H%M%SZ).tar.gz"
/usr/local/bin/j-ui backup "$backup_path" >/dev/null
install -d -m 0700 "${temporary_directory}/managed"
for target in "${managed_targets[@]}"; do
  rollback_path="${temporary_directory}/managed${target}"
  install -d -m 0700 "$(dirname "$rollback_path")"
  if [[ -e "$target" || -L "$target" ]]; then
    cp -a -- "$target" "$rollback_path"
  else
    touch "${rollback_path}.missing"
  fi
done
systemctl is-active --quiet j-ui.service && previous_jui_active=1 || true
systemctl is-enabled --quiet j-ui.service && previous_jui_enabled=1 || true
systemctl is-active --quiet j-ui-sing-box.service && previous_singbox_active=1 || true
systemctl is-enabled --quiet j-ui-sing-box.service && previous_singbox_enabled=1 || true
install -d -m 0700 "${temporary_directory}/trees"
services_quiesced=1
if [[ $previous_jui_active -eq 1 ]]; then systemctl stop j-ui.service; fi
if [[ $previous_singbox_active -eq 1 ]]; then systemctl stop j-ui-sing-box.service; fi
if systemctl list-units --all --plain --no-legend 'jui-vpngate-*' | grep -q .; then
  /usr/local/bin/j-ui cleanup-vpngate
fi
for tree in /etc/j-ui /var/lib/j-ui; do
  if [[ -d "$tree" ]]; then
    snapshot="${temporary_directory}/trees${tree}"
    install -d -m 0700 "$(dirname "$snapshot")"
    cp -a -- "$tree" "$snapshot"
  fi
done

mutation_started=1
install -m 0755 "${temporary_directory}/j-ui" /usr/local/bin/j-ui.new
mv -f /usr/local/bin/j-ui.new /usr/local/bin/j-ui
install -m 0755 "${temporary_directory}/sing-box" /usr/local/lib/j-ui/sing-box
install -m 0644 "${temporary_directory}/deploy/j-ui.service" /etc/systemd/system/j-ui.service
install -m 0644 "${temporary_directory}/deploy/j-ui-update.service" /etc/systemd/system/j-ui-update.service
install -m 0644 "${temporary_directory}/deploy/j-ui-sing-box.service" /etc/systemd/system/j-ui-sing-box.service
install -m 0644 "${temporary_directory}/deploy/j-ui-certificate-renew.service" /etc/systemd/system/j-ui-certificate-renew.service
install -m 0644 "${temporary_directory}/deploy/j-ui-certificate-renew.timer" /etc/systemd/system/j-ui-certificate-renew.timer
install -m 0644 "${temporary_directory}/deploy/j-ui-certificate-issue@.service" /etc/systemd/system/j-ui-certificate-issue@.service
install -m 0755 "${temporary_directory}/scripts/update.sh" /usr/local/lib/j-ui/update.sh
install -m 0755 "${temporary_directory}/scripts/uninstall.sh" /usr/local/lib/j-ui/uninstall.sh
install -m 0755 "${temporary_directory}/scripts/manage.sh" /usr/local/lib/j-ui/manage.sh
install -m 0755 "${temporary_directory}/scripts/ssl.sh" /usr/local/lib/j-ui/ssl.sh
install -m 0755 "${temporary_directory}/scripts/argo.sh" /usr/local/lib/j-ui/argo.sh
ln -sfn /usr/local/bin/j-ui /usr/local/bin/J-UI
rm -f \
  /usr/local/bin/jui \
  /usr/local/bin/J-Ui \
  /usr/local/bin/J-uI \
  /usr/local/bin/J-ui \
  /usr/local/bin/j-UI \
  /usr/local/bin/j-Ui \
  /usr/local/bin/j-uI \
  /usr/local/bin/jui-menu
systemctl daemon-reload
if systemctl is-enabled --quiet j-ui-certificate-renew.timer; then
  systemctl restart j-ui-certificate-renew.timer
fi
health_url="$(/usr/local/bin/j-ui internal-health-url)"

if ! systemctl restart j-ui-sing-box.service j-ui.service ||
  ! systemctl is-active --quiet j-ui-sing-box.service j-ui.service; then
  exit 1
fi
health_ready=0
for _ in {1..60}; do
  if curl -kfsS --max-time 2 "$health_url" >/dev/null 2>&1; then
    health_ready=1
    break
  fi
  sleep 1
done
if [[ $health_ready -ne 1 ]]; then
  systemctl status j-ui.service j-ui-sing-box.service --no-pager -n 30 >&2 || true
  journalctl -u j-ui.service -u j-ui-sing-box.service --no-pager -n 60 >&2 || true
  exit 1
fi
/usr/local/bin/j-ui internal-update-result success "$version" >/dev/null 2>&1 || true
result_recorded=1
mutation_started=0
services_quiesced=0
echo "J-UI updated to ${version}."
