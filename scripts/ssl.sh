#!/usr/bin/env bash
set -Eeuo pipefail

readonly certbot="/opt/j-ui/certbot/bin/certbot"
firewall_opened=0

close_acme_firewall() {
  if [[ $firewall_opened -eq 1 ]]; then
    /usr/local/bin/j-ui close-acme-firewall >/dev/null 2>&1 || true
  fi
}
trap close_acme_firewall EXIT

enable_panel_tls() {
  local certificate_path="$1"
  local private_key_path="$2"
  local env_file=/etc/j-ui/j-ui.env
  [[ -f "$env_file" ]] || return 0
  if grep -q '^JUI_TLS_CERTIFICATE_PATH=' "$env_file"; then
    sed -i "s|^JUI_TLS_CERTIFICATE_PATH=.*$|JUI_TLS_CERTIFICATE_PATH=${certificate_path}|" "$env_file"
  else
    printf 'JUI_TLS_CERTIFICATE_PATH=%s\n' "$certificate_path" >> "$env_file"
  fi
  if grep -q '^JUI_TLS_KEY_PATH=' "$env_file"; then
    sed -i "s|^JUI_TLS_KEY_PATH=.*$|JUI_TLS_KEY_PATH=${private_key_path}|" "$env_file"
  else
    printf 'JUI_TLS_KEY_PATH=%s\n' "$private_key_path" >> "$env_file"
  fi
  chmod 0600 "$env_file"
  systemctl try-restart j-ui.service >/dev/null 2>&1 || true
}

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  printf '%s\n' 'Run SSL certificate management as root.' >&2
  exit 1
fi
if [[ ! -x "$certbot" ]]; then
  printf '%s\n' 'Certbot is not installed. Re-run the J-UI installer first.' >&2
  exit 1
fi

if [[ "${1:-}" == "--renew" ]]; then
  /usr/local/bin/j-ui ensure-acme-firewall >/dev/null
  firewall_opened=1
  "$certbot" renew --quiet
  systemctl try-restart j-ui-sing-box.service >/dev/null 2>&1 || true
  systemctl try-restart j-ui.service >/dev/null 2>&1 || true
  exit 0
fi

host="${1:-}"
if [[ -z "$host" ]]; then
  host="$(/usr/local/bin/j-ui get-public-host)"
fi
host="${host#[}"
host="${host%]}"
if [[ -z "$host" || "$host" == *://* || "$host" == */* || "$host" == *:* ]]; then
  printf 'Invalid SSL certificate host: %s\n' "$host" >&2
  exit 1
fi

certificate="/etc/letsencrypt/live/${host}/fullchain.pem"
private_key="/etc/letsencrypt/live/${host}/privkey.pem"
hostname_check=(-checkhost "$host")
if [[ "$host" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
  hostname_check=(-checkip "$host")
fi
if [[ -s "$certificate" && -s "$private_key" ]] &&
  openssl x509 -in "$certificate" -noout -checkend 86400 "${hostname_check[@]}" >/dev/null 2>&1; then
  enable_panel_tls "$certificate" "$private_key"
  printf 'Reusing valid SSL certificate: %s\n' "$certificate"
  exit 0
fi

/usr/local/bin/j-ui ensure-acme-firewall >/dev/null
firewall_opened=1
common_args=(
  certonly --standalone --non-interactive --agree-tos
  --register-unsafely-without-email --preferred-challenges http
)
if [[ "$host" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
  "$certbot" "${common_args[@]}" --preferred-profile shortlived --ip-address "$host"
else
  "$certbot" "${common_args[@]}" -d "$host"
fi

if [[ ! -s "$certificate" || ! -s "$private_key" ]]; then
  printf 'Certbot completed without producing the expected certificate for %s.\n' "$host" >&2
  exit 1
fi
touch /etc/j-ui/certificate-managed-by-jui
if ! grep -Fxq "$host" /etc/j-ui/certificate-managed-by-jui; then
  printf '%s\n' "$host" >> /etc/j-ui/certificate-managed-by-jui
fi
chmod 0600 /etc/j-ui/certificate-managed-by-jui
enable_panel_tls "$certificate" "$private_key"
printf 'SSL certificate issued: %s\n' "$certificate"
