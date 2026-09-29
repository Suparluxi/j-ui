#!/usr/bin/env bash
set -euo pipefail

# Run on Japan as root. This instance never edits J-UI or Xray services.
[[ $EUID -eq 0 ]] || { echo 'Run as root on the Japan VPS.' >&2; exit 1; }
for tool in curl sha256sum tar mktemp openssl systemctl ss useradd install; do
  command -v "$tool" >/dev/null || { echo "Missing prerequisite: $tool" >&2; exit 1; }
done

public_port="${JP_PORT:-14443}"
listen_port="${JP_LISTEN_PORT:-$public_port}"
sni="${JP_SNI:-www.microsoft.com}"
[[ $public_port =~ ^[0-9]+$ ]] && (( 10#$public_port >= 1 && 10#$public_port <= 65535 )) || { echo 'Invalid JP_PORT.' >&2; exit 1; }
[[ $listen_port =~ ^[0-9]+$ ]] && (( 10#$listen_port >= 1 && 10#$listen_port <= 65535 )) || { echo 'Invalid JP_LISTEN_PORT.' >&2; exit 1; }
public_port=$((10#$public_port))
listen_port=$((10#$listen_port))
[[ $sni =~ ^[a-zA-Z0-9.-]+$ && $sni == *.* && $sni != .* && $sni != *. ]] || { echo 'Invalid JP_SNI.' >&2; exit 1; }

config_dir=/etc/j-ui-landing
binary=/opt/j-ui-landing/sing-box
unit=/etc/systemd/system/j-ui-landing.service
info="$config_dir/connection"
listen_info="$config_dir/listen-port"
if [[ -e $info ]]; then
  [[ -f $config_dir/config.json && -f $unit && -x $binary ]] || { echo 'Incomplete landing installation; inspect it before retrying.' >&2; exit 1; }
  saved_port=$(sed -n 's/^JP_PORT=//p' "$info")
  saved_sni=$(sed -n 's/^JP_SNI=//p' "$info")
  [[ $public_port == "$saved_port" && $sni == "$saved_sni" ]] || { echo 'Landing instance already exists with different public port or SNI; do not rerun to migrate it.' >&2; exit 1; }
  if [[ -n ${JP_LISTEN_PORT+x} ]]; then
    [[ -f $listen_info && $listen_port == "$(<"$listen_info")" ]] || { echo 'Existing listen port cannot be changed by rerunning this script.' >&2; exit 1; }
  fi
  systemctl is-active --quiet j-ui-landing.service || systemctl start j-ui-landing.service
else
  [[ ! -e $config_dir && ! -e $unit && ! -e $binary ]] || { echo 'Landing paths already exist; refusing to overwrite them.' >&2; exit 1; }
  if ss -H -ltn "sport = :$listen_port" | grep -q .; then
    echo "TCP listen port $listen_port is already in use; choose JP_LISTEN_PORT before running." >&2
    exit 1
  fi
  case "$(uname -m)" in
    x86_64) arch=amd64; digest=2375de6999f4f56ab46b4fc5ddf26a6aba1d3e61a0f4e7ddec2f4690457d5f63 ;;
    aarch64) arch=arm64; digest=04d9b40bc98dc55b6f509ce3292145c65478f65866bea64826ebb2f382385088 ;;
    *) echo 'Only Linux amd64 and arm64 are supported.' >&2; exit 1 ;;
  esac
  tmp=$(mktemp -d)
  trap 'rm -rf -- "$tmp"' EXIT
  archive="sing-box-1.14.0-linux-$arch.tar.gz"
  curl -fL --retry 3 -o "$tmp/$archive" "https://github.com/SagerNet/sing-box/releases/download/v1.14.0/$archive"
  printf '%s  %s\n' "$digest" "$tmp/$archive" | sha256sum -c - >/dev/null
  tar -xzf "$tmp/$archive" -C "$tmp" "sing-box-1.14.0-linux-$arch/sing-box"
  local_binary="$tmp/sing-box-1.14.0-linux-$arch/sing-box"
  uuid=$($local_binary generate uuid)
  keys=$($local_binary generate reality-keypair)
  private=$(printf '%s\n' "$keys" | awk -F ': ' '$1 == "PrivateKey" {print $2}')
  public=$(printf '%s\n' "$keys" | awk -F ': ' '$1 == "PublicKey" {print $2}')
  [[ $uuid =~ ^[0-9a-f-]{36}$ && $private =~ ^[a-zA-Z0-9_-]{43}$ && $public =~ ^[a-zA-Z0-9_-]{43}$ ]] || { echo 'Could not generate Reality credentials.' >&2; exit 1; }
  sid=$(openssl rand -hex 4)
  id jui-landing >/dev/null 2>&1 || useradd --system --user-group --no-create-home --shell /usr/sbin/nologin jui-landing
  install -d -m 0755 /opt/j-ui-landing
  install -m 0755 "$local_binary" "$binary"
  install -d -m 0750 -o root -g jui-landing "$config_dir"
  umask 077
  cat > "$config_dir/config.json" <<EOF
{
  "log": {"level": "warn"},
  "inbounds": [{
    "type": "vless", "tag": "landing-in", "listen": "0.0.0.0", "listen_port": $listen_port,
    "users": [{"name": "hk", "uuid": "$uuid", "flow": "xtls-rprx-vision"}],
    "tls": {"enabled": true, "server_name": "$sni", "reality": {
      "enabled": true, "handshake": {"server": "$sni", "server_port": 443},
      "private_key": "$private", "short_id": ["$sid"]
    }}
  }],
  "outbounds": [{"type": "direct", "tag": "direct"}],
  "route": {"final": "direct"}
}
EOF
  chown root:jui-landing "$config_dir/config.json"
  chmod 0640 "$config_dir/config.json"
  "$binary" check -c "$config_dir/config.json"
  privileged_port_capability=''
  if (( listen_port < 1024 )); then
    privileged_port_capability=$'AmbientCapabilities=CAP_NET_BIND_SERVICE\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE'
  fi
  cat > "$unit" <<EOF
[Unit]
Description=Independent Japan VLESS Reality landing for J-UI
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=jui-landing
Group=jui-landing
ExecStart=$binary run -c $config_dir/config.json
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
$privileged_port_capability

[Install]
WantedBy=multi-user.target
EOF
  printf 'JP_PORT=%s\nJP_UUID=%s\nJP_PUB=%s\nJP_SID=%s\nJP_SNI=%s\n' "$public_port" "$uuid" "$public" "$sid" "$sni" > "$info"
  chmod 0600 "$info"
  printf '%s\n' "$listen_port" > "$listen_info"
  chmod 0600 "$listen_info"
  systemctl daemon-reload
  systemctl start j-ui-landing.service
  systemctl is-active --quiet j-ui-landing.service || { echo 'Landing service failed; inspect journalctl -u j-ui-landing.' >&2; exit 1; }
  systemctl enable j-ui-landing.service >/dev/null
fi

address="${JP_ADDR:-$(curl -4fsS --max-time 8 https://api.ipify.org)}"
if [[ ! $address =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  echo 'Could not detect a public IPv4 address; rerun with JP_ADDR=<Japan public IPv4>.' >&2
  exit 1
fi
IFS=. read -r a b c d <<< "$address"
for octet in "$a" "$b" "$c" "$d"; do
  (( 10#$octet <= 255 )) || { echo 'Invalid JP_ADDR.' >&2; exit 1; }
done
echo 'Japan landing service is running. Copy only the following block into the Hong Kong panel:' >&2
printf 'JP_ADDR=%s\n' "$address"
cat "$info"
echo "Japan listens on TCP $listen_port; Hong Kong connects to public TCP $public_port. Verify the provider NAT mapping and firewall before enabling routing." >&2
