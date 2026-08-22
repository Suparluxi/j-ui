#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Run this uninstaller as root." >&2
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
    zh-CN:remove_prompt) printf '是否卸载 J-UI 服务和程序文件？[y/N]：' ;;
    zh-CN:keep_prompt) printf '是否保留 J-UI 数据和备份？[Y/n]：' ;;
    zh-CN:invalid) printf '请输入 Y 或 N。\n' ;;
    zh-CN:cleanup_failed) printf '无法完整清除 VPNGate 隔离资源，卸载已中止。\n' ;;
    zh-CN:firewall_failed) printf '无法清除全部防火墙规则，卸载已中止。\n' ;;
    zh-CN:remove_all_done) printf 'J-UI 已卸载，程序、配置、数据库、密钥、运行数据和备份均已清除。\n' ;;
    zh-CN:remove_done) printf 'J-UI 已卸载，数据保留在 /var/lib/j-ui 和 /etc/j-ui。\n' ;;
    en:remove_prompt) printf 'Remove J-UI services and program files? [y/N] ' ;;
    en:keep_prompt) printf 'Keep J-UI data and backups? [Y/n] ' ;;
    en:invalid) printf 'Enter Y or N.\n' ;;
    en:cleanup_failed) printf 'Unable to fully remove VPNGate isolation resources; uninstall aborted.\n' ;;
    en:firewall_failed) printf 'Unable to remove all managed firewall rules; uninstall aborted.\n' ;;
    en:remove_all_done) printf 'J-UI removed; program files, configuration, database, keys, runtime data, and backups were deleted.\n' ;;
    en:remove_done) printf 'J-UI removed. Data remains in /var/lib/j-ui and /etc/j-ui.\n' ;;
    *) printf '%s\n' "$key" ;;
  esac
}

read -r -p "$(t remove_prompt)" answer
if [[ ! "$answer" =~ ^[Yy]$ ]]; then
  exit 0
fi
while :; do
  read -r -p "$(t keep_prompt)" data_answer || data_answer=""
  case "${data_answer,,}" in
    ""|y|yes) keep_data=1; break ;;
    n|no) keep_data=0; break ;;
    *) t invalid >&2 ;;
  esac
done
cloudflared_package_created=0
cloudflared_service_created=0
cloudflared_key_created=0
cloudflared_source_created=0
bbr_previous_qdisc=""
bbr_previous_congestion=""
bbr_managed=0
if [[ -r /etc/j-ui/cloudflared-managed-by-jui ]]; then
  cloudflared_package_created="$(sed -n 's/^packageCreated=//p' /etc/j-ui/cloudflared-managed-by-jui | head -n 1)"
  cloudflared_service_created="$(sed -n 's/^serviceCreated=//p' /etc/j-ui/cloudflared-managed-by-jui | head -n 1)"
  cloudflared_key_created="$(sed -n 's/^keyCreated=//p' /etc/j-ui/cloudflared-managed-by-jui | head -n 1)"
  cloudflared_source_created="$(sed -n 's/^sourceCreated=//p' /etc/j-ui/cloudflared-managed-by-jui | head -n 1)"
fi
if [[ -r /etc/sysctl.d/99-j-ui-bbr.conf ]] &&
  grep -qx '# Managed by J-UI. Remove this file to stop persisting these settings.' /etc/sysctl.d/99-j-ui-bbr.conf; then
  bbr_managed=1
  bbr_previous_qdisc="$(sed -n 's/^# previous_default_qdisc=//p' /etc/sysctl.d/99-j-ui-bbr.conf | head -n 1)"
  bbr_previous_congestion="$(sed -n 's/^# previous_congestion_control=//p' /etc/sysctl.d/99-j-ui-bbr.conf | head -n 1)"
fi
exec 9>/run/lock/j-ui-lifecycle.lock
if ! flock -n 9; then
  echo "Another J-UI install, update, restore, or uninstall operation is running." >&2
  exit 1
fi
systemctl stop j-ui.service j-ui-sing-box.service j-ui-certificate-renew.timer 2>/dev/null || true
cleanup_failed=0
cleanup_command() {
  local output=""
  if output="$("$@" 2>&1)"; then
    return
  fi
  case "${output,,}" in
    *"not loaded"*|*"not found"*|*"no such file"*|*"cannot find device"*|*"does not exist"*)
      return
      ;;
  esac
  echo "Cleanup failed: $*${output:+: ${output}}" >&2
  cleanup_failed=1
}
while IFS= read -r residential_unit; do
  [[ "$residential_unit" == j-ui-residential@*.service ]] || continue
  cleanup_command systemctl disable --now "$residential_unit"
  systemctl reset-failed "$residential_unit" 2>/dev/null || true
done < <(systemctl list-units --all --plain --no-legend 'j-ui-residential@*.service' 2>/dev/null | awk '{print $1}')
for slot in 1 2 3 4 5; do
  cleanup_command systemctl stop "jui-vpngate-${slot}-bridge.service"
  cleanup_command systemctl stop "jui-vpngate-${slot}-openvpn.service"
  systemctl reset-failed \
    "jui-vpngate-${slot}-bridge.service" \
    "jui-vpngate-${slot}-openvpn.service" 2>/dev/null || true
  cleanup_command ip netns delete "jui-vpn-${slot}"
  cleanup_command ip link delete "jvh${slot}"
  cleanup_command nft delete table ip "jui_vpn_${slot}"
done
if [[ $cleanup_failed -ne 0 ]]; then
  t cleanup_failed >&2
  systemctl start j-ui-sing-box.service j-ui.service 2>/dev/null || true
  exit 1
fi
rm -rf -- /var/lib/j-ui/vpngate
if [[ -x /usr/local/bin/j-ui ]]; then
  if ! /usr/local/bin/j-ui close-management-firewall; then
    t firewall_failed >&2
    systemctl start j-ui-sing-box.service j-ui.service 2>/dev/null || true
    exit 1
  fi
  if ! /usr/local/bin/j-ui cleanup-firewall; then
    t firewall_failed >&2
    systemctl start j-ui-sing-box.service j-ui.service 2>/dev/null || true
    exit 1
  fi
  /usr/local/bin/j-ui close-acme-firewall 2>/dev/null || true
fi
systemctl disable j-ui.service j-ui-sing-box.service j-ui-certificate-renew.timer 2>/dev/null || true
rm -f /etc/systemd/system/j-ui.service /etc/systemd/system/j-ui-update.service /etc/systemd/system/j-ui-sing-box.service /etc/systemd/system/j-ui-residential@.service /etc/systemd/system/j-ui-certificate-renew.service /etc/systemd/system/j-ui-certificate-renew.timer /etc/systemd/system/j-ui-certificate-issue@.service
rm -rf -- \
  /etc/systemd/system/j-ui.service.d \
  /etc/systemd/system/j-ui-update.service.d \
  /etc/systemd/system/j-ui-sing-box.service.d \
  /etc/systemd/system/j-ui-residential@.service.d
rm -f \
  /usr/local/bin/j-ui \
  /usr/local/bin/J-UI \
  /usr/local/bin/jui \
  /usr/local/bin/J-Ui \
  /usr/local/bin/J-uI \
  /usr/local/bin/J-ui \
  /usr/local/bin/j-UI \
  /usr/local/bin/j-Ui \
  /usr/local/bin/j-uI \
  /usr/local/bin/jui-menu
rm -rf /usr/local/lib/j-ui
if [[ $bbr_managed -eq 1 ]]; then
  rm -f -- /etc/sysctl.d/99-j-ui-bbr.conf
  if [[ "$bbr_previous_qdisc" =~ ^[A-Za-z0-9_-]+$ ]]; then
    sysctl -q -w "net.core.default_qdisc=${bbr_previous_qdisc}" >/dev/null 2>&1 || true
  fi
  if [[ "$bbr_previous_congestion" =~ ^[A-Za-z0-9_-]+$ ]]; then
    sysctl -q -w "net.ipv4.tcp_congestion_control=${bbr_previous_congestion}" >/dev/null 2>&1 || true
  fi
fi
if [[ "$keep_data" -eq 0 ]]; then
  if [[ -s /etc/j-ui/certificate-managed-by-jui && -x /opt/j-ui/certbot/bin/certbot ]]; then
    while IFS= read -r certificate_name; do
      [[ -n "$certificate_name" ]] || continue
      /opt/j-ui/certbot/bin/certbot delete --non-interactive --cert-name "$certificate_name" 2>/dev/null || true
    done < /etc/j-ui/certificate-managed-by-jui
  fi
  rm -rf -- /opt/j-ui/certbot
  if [[ "$cloudflared_service_created" == "1" ]] && command -v cloudflared >/dev/null 2>&1; then
    systemctl disable --now cloudflared.service >/dev/null 2>&1 || true
    rm -f -- /etc/systemd/system/cloudflared.service /etc/j-ui/cloudflared.token
    systemctl daemon-reload >/dev/null 2>&1 || true
  fi
  if [[ "$cloudflared_package_created" == "1" ]]; then
    DEBIAN_FRONTEND=noninteractive apt-get purge -y cloudflared >/dev/null 2>&1 || true
  fi
  [[ "$cloudflared_source_created" == "1" ]] && rm -f -- /etc/apt/sources.list.d/cloudflared.list
  [[ "$cloudflared_key_created" == "1" ]] && rm -f -- /usr/share/keyrings/cloudflare-main.gpg
  rm -rf -- /var/lib/j-ui /etc/j-ui /var/backups/j-ui /var/log/j-ui /run/j-ui
  rm -f -- /run/lock/j-ui-lifecycle.lock
  t remove_all_done
else
  rm -rf -- /opt/j-ui/certbot
  t remove_done
fi
systemctl daemon-reload
