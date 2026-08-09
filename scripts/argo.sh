#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  printf '%s\n' 'Run the Argo setup as root.' >&2
  exit 1
fi

language="${JUI_LANGUAGE:-}"
if [[ -z "$language" && -r /etc/j-ui/j-ui.env ]]; then
  language="$(sed -n 's/^JUI_LANGUAGE=//p' /etc/j-ui/j-ui.env | head -n 1)"
fi
[[ "$language" == "en" ]] || language="zh-CN"

t() {
  local key="$1"
  case "$language:$key" in
    zh-CN:title) printf 'J-UI 固定域名 Argo 配置' ;;
    zh-CN:intro) printf '只需受限 Cloudflare API Token 和子域名；J-UI 会自动创建 Tunnel、DNS、回源规则和本机服务。' ;;
    zh-CN:guide) printf '配置说明：https://github.com/Suparluxi/j-ui/blob/main/docs/argo-quickstart.zh-CN.md' ;;
    zh-CN:domain) printf 'Argo 固定子域名%s：' "$2" ;;
    zh-CN:port) printf '本机回源端口%s：' "$2" ;;
    zh-CN:api_token) printf 'Cloudflare API Token（输入不可见）：' ;;
    zh-CN:api_help) printf 'Token 需限定到目标账户和域名，并授予 Cloudflare Tunnel 编辑、DNS 编辑、Zone 读取权限；配置成功后可在 Cloudflare 撤销。' ;;
    zh-CN:api_required) printf 'API Token 格式无效。' ;;
    zh-CN:invalid_domain) printf '域名格式无效，请输入类似 argo.example.com 的完整子域名。' ;;
    zh-CN:invalid_port) printf '端口必须在 1 到 65535 之间。' ;;
    zh-CN:foreign_service) printf '检测到非 J-UI 管理的 cloudflared.service。为避免中断其他应用，本向导不会覆盖它。' ;;
    zh-CN:installing) printf '正在安装 cloudflared 并检查 Cloudflare 权限…' ;;
    zh-CN:zone_missing) printf '无法找到该域名对应的 Cloudflare Zone，请检查域名是否已托管以及 Token 的 Zone 读取权限。' ;;
    zh-CN:dns_conflict) printf '该子域名已有非 J-UI 管理的 DNS 记录，请更换空闲子域名或先手动移除冲突记录。' ;;
    zh-CN:provisioning) printf '正在自动创建固定 Tunnel、回源规则和 DNS…' ;;
    zh-CN:verifying) printf '正在通过公网固定域名执行端到端检测…' ;;
    zh-CN:dns_wait) printf 'DNS 尚未生效，正在等待 Cloudflare 传播（最长约 2 分钟）…' ;;
    zh-CN:success) printf '固定域名 Argo 配置完成，网页端 Argo 协议现已解锁。' ;;
    zh-CN:rollback) printf 'Argo 配置失败，本轮创建的 Cloudflare 资源和本机配置已回滚。' ;;
    en:title) printf 'J-UI Fixed-Domain Argo Setup' ;;
    en:intro) printf 'Provide a scoped Cloudflare API token and subdomain. J-UI creates the Tunnel, DNS, origin route, and local service automatically.' ;;
    en:guide) printf 'Guide: https://github.com/Suparluxi/j-ui/blob/main/docs/argo-quickstart.en.md' ;;
    en:domain) printf 'Argo fixed subdomain%s: ' "$2" ;;
    en:port) printf 'Local origin port%s: ' "$2" ;;
    en:api_token) printf 'Cloudflare API token (input hidden): ' ;;
    en:api_help) printf 'Scope the token to the target account and zone with Cloudflare Tunnel Edit, DNS Edit, and Zone Read. You may revoke it after setup.' ;;
    en:api_required) printf 'The API token format is invalid.' ;;
    en:invalid_domain) printf 'Enter a complete subdomain such as argo.example.com.' ;;
    en:invalid_port) printf 'The port must be between 1 and 65535.' ;;
    en:foreign_service) printf 'A cloudflared.service not managed by J-UI already exists. This wizard will not overwrite another application\047s connector.' ;;
    en:installing) printf 'Installing cloudflared and checking Cloudflare permissions...' ;;
    en:zone_missing) printf 'The Cloudflare zone was not found. Check that the domain is hosted by Cloudflare and the token has Zone Read.' ;;
    en:dns_conflict) printf 'This hostname already has a DNS record not managed by J-UI. Use an unused subdomain or remove the conflict first.' ;;
    en:provisioning) printf 'Creating the fixed Tunnel, origin route, and DNS automatically...' ;;
    en:verifying) printf 'Running an end-to-end check through the fixed public hostname...' ;;
    en:dns_wait) printf 'DNS is not active yet. Waiting up to about two minutes for Cloudflare propagation...' ;;
    en:success) printf 'Fixed-domain Argo setup is complete. Argo is now unlocked in the web UI.' ;;
    en:rollback) printf 'Argo setup failed. Cloudflare resources and local configuration created by this run were rolled back.' ;;
    *) printf '%s' "$key" ;;
  esac
}

read_value() {
  local prompt="$1"
  read -r -p "$prompt" REPLY || REPLY=""
}

read_secret() {
  local prompt="$1"
  read -r -s -p "$prompt" REPLY || REPLY=""
  printf '\n'
}

valid_domain() {
  [[ "$1" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$ ]]
}

valid_tunnel_token() {
  local token="$1" decoded
  [[ ${#token} -ge 80 && ${#token} -le 4096 ]] || return 1
  decoded="$(printf '%s' "$token" | base64 --decode 2>/dev/null)" || return 1
  jq -e '
    type == "object" and
    (.a | type == "string" and length > 0) and
    (.s | type == "string" and length > 0) and
    (.t | type == "string" and length > 0)
  ' >/dev/null 2>&1 <<< "$decoded"
}

marker_value() {
  local key="$1"
  [[ -r /etc/j-ui/cloudflared-managed-by-jui ]] || { printf '0'; return; }
  sed -n "s/^${key}=//p" /etc/j-ui/cloudflared-managed-by-jui | head -n 1
}

temporary_directory="$(mktemp -d /tmp/j-ui-argo.XXXXXX)"
chmod 0700 "$temporary_directory"
api_config="$temporary_directory/cloudflare-api.conf"
api_base='https://api.cloudflare.com/client/v4'
api_token=""
new_account_id=""
new_zone_id=""
new_tunnel_id=""
new_dns_id=""
new_tunnel_name=""
old_account_id=""
old_zone_id=""
old_tunnel_id=""
old_dns_id=""
old_domain=""
old_origin_port=""
old_dns_content=""
old_dns_proxied="true"
profile_existed=0
marker_existed=0
unit_existed=0
token_file_existed=0
package_created=0
key_created=0
source_created=0
tunnel_created=0
dns_created=0
dns_updated=0
service_mutated=0
completed=0
mutation_started=0
previous_service_active=0
previous_service_enabled=0

api_request() {
  local method="$1" path="$2" data_file="${3:-}"
  local args=(--silent --show-error --fail --connect-timeout 10 --max-time 45 --retry 2 --config "$api_config" --request "$method")
  [[ -n "$data_file" ]] && args+=(--data-binary "@$data_file")
  curl "${args[@]}" "${api_base}${path}"
}

delete_new_cloudflare_resources() {
  [[ -s "$api_config" ]] || return 0
  if [[ $dns_created -eq 1 && -n "$new_zone_id" && -n "$new_dns_id" ]]; then
    api_request DELETE "/zones/${new_zone_id}/dns_records/${new_dns_id}" >/dev/null 2>&1 || true
  elif [[ $dns_updated -eq 1 && -n "$new_zone_id" && -n "$new_dns_id" && -n "$old_dns_content" ]]; then
    jq -n --arg name "$domain" --arg content "$old_dns_content" --argjson proxied "$old_dns_proxied" \
      '{type:"CNAME",name:$name,content:$content,proxied:$proxied}' > "$temporary_directory/restore-dns.json"
    api_request PUT "/zones/${new_zone_id}/dns_records/${new_dns_id}" "$temporary_directory/restore-dns.json" >/dev/null 2>&1 || true
  fi
  if [[ $tunnel_created -eq 1 && -n "$new_account_id" && -n "$new_tunnel_id" ]]; then
    api_request DELETE "/accounts/${new_account_id}/cfd_tunnel/${new_tunnel_id}?cascade=true" >/dev/null 2>&1 || true
  fi
}

restore_local_state() {
  if [[ $profile_existed -eq 1 ]]; then
    install -m 0600 "$temporary_directory/argo-profile.previous" /etc/j-ui/argo-profile.json || true
  else
    rm -f -- /etc/j-ui/argo-profile.json
  fi
  if [[ $marker_existed -eq 1 ]]; then
    install -m 0600 "$temporary_directory/cloudflared-marker.previous" /etc/j-ui/cloudflared-managed-by-jui || true
  else
    rm -f -- /etc/j-ui/cloudflared-managed-by-jui
  fi
  if [[ $token_file_existed -eq 1 ]]; then
    install -m 0600 "$temporary_directory/cloudflared-token.previous" /etc/j-ui/cloudflared.token || true
  else
    rm -f -- /etc/j-ui/cloudflared.token
  fi
  if [[ $unit_existed -eq 1 ]]; then
    install -m 0644 "$temporary_directory/cloudflared-service.previous" /etc/systemd/system/cloudflared.service || true
  else
    rm -f -- /etc/systemd/system/cloudflared.service
  fi
  systemctl daemon-reload >/dev/null 2>&1 || true
  if [[ $previous_service_enabled -eq 1 ]]; then
    systemctl enable cloudflared.service >/dev/null 2>&1 || true
  else
    systemctl disable cloudflared.service >/dev/null 2>&1 || true
  fi
  if [[ $previous_service_active -eq 1 ]]; then
    systemctl restart cloudflared.service >/dev/null 2>&1 || true
  else
    systemctl stop cloudflared.service >/dev/null 2>&1 || true
  fi
}

cleanup() {
  local exit_code=$?
  api_token=""
  if [[ $exit_code -ne 0 && $completed -eq 0 && $mutation_started -eq 1 ]]; then
    if [[ $service_mutated -eq 1 ]]; then
      systemctl stop cloudflared.service >/dev/null 2>&1 || true
      restore_local_state
    fi
    delete_new_cloudflare_resources
    if [[ $package_created -eq 1 ]]; then
      DEBIAN_FRONTEND=noninteractive apt-get purge -y cloudflared >/dev/null 2>&1 || true
    fi
    [[ $source_created -eq 1 ]] && rm -f -- /etc/apt/sources.list.d/cloudflared.list
    [[ $key_created -eq 1 ]] && rm -f -- /usr/share/keyrings/cloudflare-main.gpg
    printf '%s\n' "$(t rollback)" >&2
  fi
  rm -rf -- "$temporary_directory"
}
trap cleanup EXIT

exec 9>/run/lock/j-ui-lifecycle.lock
if ! flock -n 9; then
  printf '%s\n' 'Another J-UI lifecycle operation is running.' >&2
  exit 1
fi
if [[ ! -x /usr/local/bin/j-ui ]]; then
  printf '%s\n' 'J-UI is not installed.' >&2
  exit 1
fi

current_domain=""
current_port="2080"
if [[ -r /etc/j-ui/argo-profile.json ]]; then
  profile_existed=1
  cp -a -- /etc/j-ui/argo-profile.json "$temporary_directory/argo-profile.previous"
  current_domain="$(jq -r '.domain // empty' /etc/j-ui/argo-profile.json 2>/dev/null || true)"
  current_port="$(jq -r '.originPort // 2080' /etc/j-ui/argo-profile.json 2>/dev/null || printf '2080')"
  old_domain="$current_domain"
  old_origin_port="$current_port"
  old_account_id="$(jq -r '.accountId // empty' /etc/j-ui/argo-profile.json 2>/dev/null || true)"
  old_zone_id="$(jq -r '.zoneId // empty' /etc/j-ui/argo-profile.json 2>/dev/null || true)"
  old_tunnel_id="$(jq -r '.tunnelId // empty' /etc/j-ui/argo-profile.json 2>/dev/null || true)"
  old_dns_id="$(jq -r '.dnsRecordId // empty' /etc/j-ui/argo-profile.json 2>/dev/null || true)"
fi
if [[ -r /etc/j-ui/cloudflared-managed-by-jui ]]; then
  marker_existed=1
  cp -a -- /etc/j-ui/cloudflared-managed-by-jui "$temporary_directory/cloudflared-marker.previous"
fi
if [[ -r /etc/j-ui/cloudflared.token ]]; then
  token_file_existed=1
  cp -a -- /etc/j-ui/cloudflared.token "$temporary_directory/cloudflared-token.previous"
fi
if [[ -f /etc/systemd/system/cloudflared.service ]]; then
  unit_existed=1
  cp -a -- /etc/systemd/system/cloudflared.service "$temporary_directory/cloudflared-service.previous"
fi
systemctl is-active --quiet cloudflared.service >/dev/null 2>&1 && previous_service_active=1 || true
systemctl is-enabled --quiet cloudflared.service >/dev/null 2>&1 && previous_service_enabled=1 || true
if systemctl cat cloudflared.service >/dev/null 2>&1 && [[ $marker_existed -eq 0 ]]; then
  printf '%s\n' "$(t foreign_service)" >&2
  exit 1
fi

printf '%s\n' '════════════════════════════════════════════════════'
printf '  %s\n' "$(t title)"
printf '%s\n' '════════════════════════════════════════════════════'
printf '%s\n' "$(t intro)"
printf '%s\n\n' "$(t guide)"

domain_hint=""
[[ -n "$current_domain" ]] && domain_hint=" [${current_domain}]"
read_value "$(t domain "$domain_hint")"
domain="${REPLY:-$current_domain}"
if ! valid_domain "$domain"; then
  printf '%s\n' "$(t invalid_domain)" >&2
  exit 1
fi
domain="${domain,,}"

port_hint=" [${current_port}]"
read_value "$(t port "$port_hint")"
origin_port="${REPLY:-$current_port}"
if [[ ! "$origin_port" =~ ^[0-9]+$ ]] || ((10#$origin_port < 1 || 10#$origin_port > 65535)); then
  printf '%s\n' "$(t invalid_port)" >&2
  exit 1
fi

printf '%s\n' "$(t api_help)"
read_secret "$(t api_token)"
api_token="$REPLY"
if [[ ! "$api_token" =~ ^[A-Za-z0-9_-]{20,256}$ ]]; then
  printf '%s\n' "$(t api_required)" >&2
  exit 1
fi
printf 'header = "Authorization: Bearer %s"\nheader = "Content-Type: application/json"\n' "$api_token" > "$api_config"
chmod 0600 "$api_config"

printf '\n%s\n' "$(t installing)"
mutation_started=1
if ! command -v cloudflared >/dev/null 2>&1; then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl jq openssl
  install -d -m 0755 /usr/share/keyrings
  if [[ ! -e /usr/share/keyrings/cloudflare-main.gpg ]]; then
    curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg -o "$temporary_directory/cloudflare-main.gpg"
    install -m 0644 "$temporary_directory/cloudflare-main.gpg" /usr/share/keyrings/cloudflare-main.gpg
    key_created=1
  fi
  if [[ ! -e /etc/apt/sources.list.d/cloudflared.list ]]; then
    printf '%s\n' 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main' \
      > /etc/apt/sources.list.d/cloudflared.list
    source_created=1
  fi
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y cloudflared
  package_created=1
fi
cloudflared_binary="$(command -v cloudflared 2>/dev/null || true)"
cloudflared_binary="$(readlink -f -- "$cloudflared_binary" 2>/dev/null || true)"
if [[ -z "$cloudflared_binary" || "$cloudflared_binary" != /* || ! -x "$cloudflared_binary" ]]; then
  printf '%s\n' 'cloudflared executable was not found after installation.' >&2
  exit 1
fi

zone_candidate="$domain"
zone_response=""
while [[ "$zone_candidate" == *.* ]]; do
  zone_response="$(api_request GET "/zones?name=${zone_candidate}&status=active&per_page=1" 2>/dev/null || true)"
  if [[ "$(jq -r '.result | length' <<< "$zone_response" 2>/dev/null || printf '0')" == "1" ]]; then
    break
  fi
  zone_candidate="${zone_candidate#*.}"
done
new_zone_id="$(jq -r '.result[0].id // empty' <<< "$zone_response" 2>/dev/null || true)"
new_account_id="$(jq -r '.result[0].account.id // empty' <<< "$zone_response" 2>/dev/null || true)"
if [[ ! "$new_zone_id" =~ ^[a-f0-9]{32}$ || ! "$new_account_id" =~ ^[a-f0-9]{32}$ ]]; then
  printf '%s\n' "$(t zone_missing)" >&2
  exit 1
fi
if [[ "$domain" == "$zone_candidate" ]]; then
  printf '%s\n' "$(t invalid_domain)" >&2
  exit 1
fi

printf '%s\n' "$(t provisioning)"
new_tunnel_name="j-ui-${domain//./-}-$(openssl rand -hex 3)"
tunnel_secret="$(openssl rand -base64 32)"
jq -n --arg name "$new_tunnel_name" --arg secret "$tunnel_secret" \
  '{name:$name,config_src:"cloudflare",tunnel_secret:$secret}' > "$temporary_directory/create-tunnel.json"
tunnel_response="$(api_request POST "/accounts/${new_account_id}/cfd_tunnel" "$temporary_directory/create-tunnel.json")"
new_tunnel_id="$(jq -r '.result.id // empty' <<< "$tunnel_response")"
tunnel_token="$(jq -r '.result.token // empty' <<< "$tunnel_response")"
if [[ ! "$new_tunnel_id" =~ ^[a-f0-9-]{36}$ ]]; then
  printf '%s\n' 'Cloudflare Tunnel creation returned an invalid ID.' >&2
  exit 1
fi
tunnel_created=1
if [[ -z "$tunnel_token" ]]; then
  token_response="$(api_request GET "/accounts/${new_account_id}/cfd_tunnel/${new_tunnel_id}/token")"
  tunnel_token="$(jq -r '.result // empty' <<< "$token_response")"
fi
if ! valid_tunnel_token "$tunnel_token"; then
  printf '%s\n' 'Cloudflare did not return a valid Tunnel token.' >&2
  exit 1
fi

jq -n --arg hostname "$domain" --arg service "http://127.0.0.1:${origin_port}" \
  '{config:{ingress:[{hostname:$hostname,service:$service},{service:"http_status:404"}],"warp-routing":{enabled:false}}}' \
  > "$temporary_directory/tunnel-config.json"
api_request PUT "/accounts/${new_account_id}/cfd_tunnel/${new_tunnel_id}/configurations" \
  "$temporary_directory/tunnel-config.json" >/dev/null

dns_response="$(api_request GET "/zones/${new_zone_id}/dns_records?name=${domain}&per_page=100")"
dns_count="$(jq -r '.result | length' <<< "$dns_response")"
if [[ "$dns_count" != "0" ]]; then
  existing_dns_id="$(jq -r '.result[0].id // empty' <<< "$dns_response")"
  existing_dns_content="$(jq -r '.result[0].content // empty' <<< "$dns_response")"
  if [[ "$domain" != "$old_domain" || "$existing_dns_id" != "$old_dns_id" || "$existing_dns_content" != "${old_tunnel_id}.cfargotunnel.com" ]]; then
    printf '%s\n' "$(t dns_conflict)" >&2
    exit 1
  fi
  new_dns_id="$existing_dns_id"
  old_dns_content="$existing_dns_content"
  old_dns_proxied="$(jq -r '.result[0].proxied // true' <<< "$dns_response")"
fi
jq -n --arg name "$domain" --arg content "${new_tunnel_id}.cfargotunnel.com" \
  '{type:"CNAME",name:$name,content:$content,proxied:true}' > "$temporary_directory/dns.json"
if [[ -n "$new_dns_id" ]]; then
  api_request PUT "/zones/${new_zone_id}/dns_records/${new_dns_id}" "$temporary_directory/dns.json" >/dev/null
  dns_updated=1
else
  created_dns="$(api_request POST "/zones/${new_zone_id}/dns_records" "$temporary_directory/dns.json")"
  new_dns_id="$(jq -r '.result.id // empty' <<< "$created_dns")"
  [[ "$new_dns_id" =~ ^[a-f0-9]{32}$ ]] || { printf '%s\n' 'Cloudflare DNS creation returned an invalid ID.' >&2; exit 1; }
  dns_created=1
fi

install -d -m 0700 /etc/j-ui
printf '%s\n' "$tunnel_token" > "$temporary_directory/cloudflared.token"
service_mutated=1
install -m 0600 "$temporary_directory/cloudflared.token" /etc/j-ui/cloudflared.token
cat > "$temporary_directory/cloudflared.service" <<UNIT
[Unit]
Description=J-UI managed Cloudflare Tunnel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${cloudflared_binary} --no-autoupdate tunnel run --token-file /etc/j-ui/cloudflared.token
Restart=on-failure
RestartSec=5s
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
NoNewPrivileges=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
LockPersonality=true
RestrictRealtime=true
RestrictSUIDSGID=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
UMask=0077

[Install]
WantedBy=multi-user.target
UNIT
systemctl stop cloudflared.service >/dev/null 2>&1 || true
install -m 0644 "$temporary_directory/cloudflared.service" /etc/systemd/system/cloudflared.service
systemctl daemon-reload
systemctl enable --now cloudflared.service

jq -n --arg domain "$domain" --argjson originPort "$origin_port" \
  --arg accountId "$new_account_id" --arg zoneId "$new_zone_id" --arg tunnelId "$new_tunnel_id" \
  --arg tunnelName "$new_tunnel_name" --arg dnsRecordId "$new_dns_id" \
  '{domain:$domain,originPort:$originPort,managed:true,accountId:$accountId,zoneId:$zoneId,tunnelId:$tunnelId,tunnelName:$tunnelName,dnsRecordId:$dnsRecordId}' \
  > "$temporary_directory/argo-profile.json"
install -m 0600 "$temporary_directory/argo-profile.json" /etc/j-ui/argo-profile.json

old_package_created="$(marker_value packageCreated)"
old_key_created="$(marker_value keyCreated)"
old_source_created="$(marker_value sourceCreated)"
((package_created == 1)) && old_package_created=1
((key_created == 1)) && old_key_created=1
((source_created == 1)) && old_source_created=1
printf 'packageCreated=%s\nserviceCreated=1\nkeyCreated=%s\nsourceCreated=%s\napiManaged=1\n' \
  "${old_package_created:-0}" "${old_key_created:-0}" "${old_source_created:-0}" \
  > "$temporary_directory/cloudflared-managed-by-jui"
install -m 0600 "$temporary_directory/cloudflared-managed-by-jui" /etc/j-ui/cloudflared-managed-by-jui

printf '%s\n' "$(t verifying)"
verification_succeeded=0
verification_output=""
for attempt in {1..24}; do
  if verification_output="$(/usr/local/bin/j-ui configure-argo --domain "$domain" --origin-port "$origin_port" 2>&1)"; then
    [[ -n "$verification_output" ]] && printf '%s\n' "$verification_output"
    verification_succeeded=1
    break
  fi
  ((attempt == 1)) && printf '%s\n' "$(t dns_wait)"
  ((attempt < 24)) && sleep 5
done
if [[ $verification_succeeded -ne 1 ]]; then
  [[ -n "$verification_output" ]] && printf '%s\n' "$verification_output" >&2
  exit 1
fi

# Remove only resources recorded as previously managed by J-UI, after the new route is healthy.
if [[ -n "$old_dns_id" && -n "$old_zone_id" && "$old_dns_id" != "$new_dns_id" ]]; then
  api_request DELETE "/zones/${old_zone_id}/dns_records/${old_dns_id}" >/dev/null 2>&1 || true
fi
if [[ -n "$old_tunnel_id" && -n "$old_account_id" && "$old_tunnel_id" != "$new_tunnel_id" ]]; then
  api_request DELETE "/accounts/${old_account_id}/cfd_tunnel/${old_tunnel_id}?cascade=true" >/dev/null 2>&1 || true
fi

api_token=""
completed=1
printf '\n%s\n' "$(t success)"
