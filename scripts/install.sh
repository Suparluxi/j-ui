#!/usr/bin/env bash
set -Eeuo pipefail

readonly repository="${JUI_GITHUB_REPOSITORY:-Suparluxi/j-ui}"
readonly singbox_version="1.13.16"
language="${JUI_LANGUAGE:-}"
temporary_directory=""
installation_started=0
previous_jui_active=0
previous_jui_enabled=0
previous_singbox_active=0
previous_singbox_enabled=0
services_quiesced=0
management_firewall_added=0
acme_firewall_added=0
certbot_created=0
certificate_created=0
installation_listen=""
node_start_port=""
public_host=""
certificate_mode="auto"
certificate_path=""
certificate_key_path=""
reset_output=""
admin_path=""
admin_username=""
admin_password=""
credentials_verified=0
preserve_existing_data=1
enable_bbr_fq=0
bbr_live_changed=0
previous_default_qdisc=""
previous_congestion_control=""
terminal_blue=""
terminal_reset=""
if [[ -z "${NO_COLOR:-}" && ( -t 0 || -t 1 ) ]]; then
  terminal_blue=$'\033[38;5;39m'
  terminal_reset=$'\033[0m'
fi
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
  /etc/sysctl.d/99-j-ui-bbr.conf
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

i18n() {
  local key="$1"
  shift
  if [[ "$language" == "zh-CN" ]]; then
    case "$key" in
      language_menu) printf '请选择安装语言 / Choose installation language:\n  1) 简体中文\n  2) English\n' ;;
      language_prompt) printf '请输入选项 [1] / Select [1]: ' ;;
      language_invalid) printf '无效选择，请输入 1 或 2。 / Invalid choice, enter 1 or 2.\n' ;;
      invalid_yes_no) printf '请输入 Y 或 N。 / Enter Y or N.\n' ;;
      confirm_port) printf '当前节点起始端口为 %s，是否使用默认配置 [Y/n]：' "$1" ;;
      custom_port_prompt) printf '请输入自定义节点起始端口：' ;;
      confirm_public_host) printf '当前公网地址为 %s，是否使用默认配置 [Y/n]：' "$1" ;;
      custom_public_host_prompt) printf '请输入自定义域名或 IP 地址：' ;;
      public_host_unavailable) printf '无法自动获取 VPS 公网 IP，请手动输入域名或 IP。\n' ;;
      public_host_required) printf '必须配置公网地址；安装已停止。\n' ;;
      public_host_ipv4_only) printf '公网地址只允许使用 IPv4 或域名，不支持 IPv6。\n' ;;
      confirm_certificate) printf '当前证书配置为%s，是否使用默认配置 [Y/n]：' "$1" ;;
      certificate_auto) printf '自动申请 Let’s Encrypt SSL 证书' ;;
      certificate_manual) printf '自定义证书' ;;
      certificate_path_prompt) printf '请输入证书绝对路径：' ;;
      certificate_key_path_prompt) printf '请输入私钥绝对路径：' ;;
      confirm_admin_username) printf '当前管理员账号为 %s，是否使用默认配置 [Y/n]：' "$1" ;;
      custom_admin_username_prompt) printf '请输入管理员账号（3-32 位字母、数字、点、下划线或连字符）：' ;;
      confirm_admin_password) printf '当前管理员密码为 %s，是否使用默认配置 [Y/n]：' "$1" ;;
      custom_admin_password_prompt) printf '请输入管理员密码（至少 4 位）：' ;;
      confirm_admin_password_prompt) printf '请再次输入管理员密码：' ;;
      confirm_bbr) printf '当前 BBR + FQ 状态为%s，是否启用 [Y/n]：' "$1" ;;
      bbr_enabled) printf '已启用' ;;
      bbr_disabled) printf '未启用' ;;
      bbr_unsupported) printf '当前内核不支持 BBR，无法启用 BBR + FQ。\n' ;;
      bbr_verify_failed) printf 'BBR + FQ 应用后验证失败，安装将回滚。\n' ;;
      bbr_ready) printf 'BBR + FQ 已启用并写入持久配置。\n' ;;
      bbr_setting_invalid) printf 'JUI_ENABLE_BBR 只允许使用 yes、no 或 ask。\n' ;;
      confirm_preserve_data) printf '检测到现有 J-UI 数据。是否保留节点、订阅、设置和账号 [Y/n]：' ;;
      clean_install_selected) printf '已选择全新安装；旧 J-UI 数据将在创建可回滚快照后删除。\n' ;;
      preserve_data_invalid) printf 'JUI_PRESERVE_DATA 只允许使用 yes 或 no。\n' ;;
      admin_username_invalid) printf '管理员账号格式无效。\n' ;;
      admin_password_mismatch) printf '两次输入的密码不一致。\n' ;;
      admin_password_short) printf '管理员密码至少需要 4 位。\n' ;;
      installing_dependencies) printf '正在安装系统依赖并准备 J-UI 与 sing-box 安装包…\n' ;;
      dependencies_ready) printf '基础依赖与安装包已准备完成，现在开始配置 J-UI。\n' ;;
      profile_saved) printf '安装配置已保存。\n' ;;
      credentials_missing) printf '无法获取新管理员密码，安装已停止且不会输出不可用的登录信息。\n' ;;
      credentials_verification_failed) printf '新管理员账号或密码未能通过运行中面板的登录验证，安装将回滚且不会输出错误凭据。\n' ;;
      token_invalid) printf 'JUI_GITHUB_TOKEN 包含不支持的字符。\n' ;;
      release_asset_missing) printf '未找到发布文件 %s。\n' "$1" ;;
      install_rollback_success) printf '安装失败；受管理的文件、数据、配置和服务状态已恢复。\n' ;;
      install_rollback_failed) printf '安装失败且自动回滚失败；恢复文件保留在 %s。\n' "$1" ;;
      root_required) printf '请使用 root 用户运行安装脚本。\n' ;;
      repo_invalid) printf 'JUI_GITHUB_REPOSITORY 无效。\n' ;;
      lock_busy) printf '已有其他 J-UI 安装、更新或恢复操作正在运行。\n' ;;
      unsupported_linux) printf '不支持的 Linux 发行版。\n' ;;
      debian_version) printf '仅支持 Debian 11/12。\n' ;;
      ubuntu_version) printf '仅支持 Ubuntu 22.04/24.04。\n' ;;
      only_debian_ubuntu) printf '仅支持 Debian 和 Ubuntu。\n' ;;
      listen_loopback) printf 'JUI_LISTEN_ADDRESS 必须使用 0.0.0.0 或可迁移的本机回环地址。\n' ;;
      listen_invalid) printf '管理监听地址无效：%s。\n' "$1" ;;
      node_port_prompt) printf '节点起始端口 [8881]：' ;;
      node_port_invalid) printf 'JUI_NODE_START_PORT 必须在 1 到 65535 之间。\n' ;;
      architecture) printf '仅支持 amd64 和 arm64。\n' ;;
      management_port_busy) printf 'TCP 端口 %s 已被占用，请选择其他 JUI_LISTEN_ADDRESS。\n' "$1" ;;
      latest_version_failed) printf '无法确定最新的 J-UI 版本。\n' ;;
      version_invalid) printf 'J-UI 版本无效：%s。\n' "$1" ;;
      health_check_failed) printf 'J-UI 服务未能在 20 秒内启动，安装将回滚。以下是服务诊断：\n' ;;
      tun_status) printf 'TUN 设备：%s\n' "$1" ;;
      public_http_warning) printf '提示：当前测试地址使用 HTTP，请勿在不可信网络中传输生产凭据。\n' ;;
      *) printf '%s\n' "$key" ;;
    esac
    return
  fi
  case "$key" in
    language_menu) printf '请选择安装语言 / Choose installation language:\n  1) 简体中文\n  2) English\n' ;;
    language_prompt) printf '请输入选项 [1] / Select [1]: ' ;;
    language_invalid) printf '无效选择，请输入 1 或 2。 / Invalid choice, enter 1 or 2.\n' ;;
    invalid_yes_no) printf 'Please enter Y or N.\n' ;;
    confirm_port) printf 'The current node start port is %s. Use the default configuration [Y/n]: ' "$1" ;;
    custom_port_prompt) printf 'Enter a custom node start port: ' ;;
    confirm_public_host) printf 'The current public address is %s. Use the default configuration [Y/n]: ' "$1" ;;
    custom_public_host_prompt) printf 'Enter a custom domain or IP address: ' ;;
    public_host_unavailable) printf 'Unable to detect the VPS public IP; enter a domain or IP manually.\n' ;;
    public_host_required) printf 'A public address is required; installation stopped.\n' ;;
    public_host_ipv4_only) printf 'The public address must be an IPv4 address or domain name; IPv6 is not supported.\n' ;;
    confirm_certificate) printf 'The current certificate configuration is %s. Use the default configuration [Y/n]: ' "$1" ;;
    certificate_auto) printf 'automatic Let’s Encrypt SSL issuance' ;;
    certificate_manual) printf 'custom' ;;
    certificate_path_prompt) printf 'Enter the absolute certificate path: ' ;;
    certificate_key_path_prompt) printf 'Enter the absolute private-key path: ' ;;
    confirm_admin_username) printf 'The current administrator username is %s. Use the default configuration [Y/n]: ' "$1" ;;
    custom_admin_username_prompt) printf 'Enter an administrator username (3-32 letters, digits, dots, underscores, or hyphens): ' ;;
    confirm_admin_password) printf 'The current administrator password is %s. Use the default configuration [Y/n]: ' "$1" ;;
    custom_admin_password_prompt) printf 'Enter an administrator password (at least 4 characters): ' ;;
    confirm_admin_password_prompt) printf 'Enter the administrator password again: ' ;;
    confirm_bbr) printf 'BBR + FQ is currently %s. Enable it [Y/n]: ' "$1" ;;
    bbr_enabled) printf 'enabled' ;;
    bbr_disabled) printf 'disabled' ;;
    bbr_unsupported) printf 'The current kernel does not support BBR; BBR + FQ cannot be enabled.\n' ;;
    bbr_verify_failed) printf 'BBR + FQ verification failed after applying it; installation will roll back.\n' ;;
    bbr_ready) printf 'BBR + FQ is enabled and persisted.\n' ;;
    bbr_setting_invalid) printf 'JUI_ENABLE_BBR must be yes, no, or ask.\n' ;;
    confirm_preserve_data) printf 'Existing J-UI data was found. Preserve nodes, subscriptions, settings, and the account [Y/n]: ' ;;
    clean_install_selected) printf 'A clean installation was selected. Existing J-UI data will be removed after a rollback snapshot is created.\n' ;;
    preserve_data_invalid) printf 'JUI_PRESERVE_DATA must be yes or no.\n' ;;
    admin_username_invalid) printf 'Invalid administrator username.\n' ;;
    admin_password_mismatch) printf 'The passwords do not match.\n' ;;
    admin_password_short) printf 'The administrator password must contain at least 4 characters.\n' ;;
    installing_dependencies) printf 'Installing system dependencies and preparing the J-UI and sing-box packages...\n' ;;
    dependencies_ready) printf 'Base dependencies and packages are ready. J-UI configuration now begins.\n' ;;
    profile_saved) printf 'Installation profile saved.\n' ;;
    credentials_missing) printf 'Unable to obtain the new administrator password. Installation stopped without printing unusable login details.\n' ;;
    credentials_verification_failed) printf 'The new administrator credentials failed login verification against the running panel. Installation will roll back without printing invalid credentials.\n' ;;
    token_invalid) printf 'JUI_GITHUB_TOKEN contains unsupported characters.\n' ;;
    release_asset_missing) printf 'Release asset %s was not found.\n' "$1" ;;
    install_rollback_success) printf 'Installation failed; managed files, data, configuration, and service state were restored.\n' ;;
    install_rollback_failed) printf 'Installation and automatic rollback both failed; recovery files remain at %s.\n' "$1" ;;
    root_required) printf 'Run this installer as root.\n' ;;
    repo_invalid) printf 'Invalid JUI_GITHUB_REPOSITORY.\n' ;;
    lock_busy) printf 'Another J-UI install, update, or restore operation is running.\n' ;;
    unsupported_linux) printf 'Unsupported Linux distribution.\n' ;;
    debian_version) printf 'Only Debian 11/12 are supported.\n' ;;
    ubuntu_version) printf 'Only Ubuntu 22.04/24.04 are supported.\n' ;;
    only_debian_ubuntu) printf 'Only Debian and Ubuntu are supported.\n' ;;
    listen_loopback) printf 'JUI_LISTEN_ADDRESS must use 0.0.0.0 or a migratable loopback address.\n' ;;
    listen_invalid) printf 'Invalid management listen address: %s\n' "$1" ;;
    node_port_prompt) printf 'Node start port [8881]: ' ;;
    node_port_invalid) printf 'JUI_NODE_START_PORT must be between 1 and 65535.\n' ;;
    architecture) printf 'Only amd64 and arm64 are supported.\n' ;;
    management_port_busy) printf 'TCP port %s is already in use; choose another JUI_LISTEN_ADDRESS.\n' "$1" ;;
    latest_version_failed) printf 'Unable to determine the latest J-UI version.\n' ;;
    version_invalid) printf 'Invalid J-UI version: %s\n' "$1" ;;
    health_check_failed) printf 'J-UI did not become ready within 20 seconds. Installation will roll back. Service diagnostics follow:\n' ;;
    tun_status) printf 'TUN device: %s\n' "$1" ;;
    public_http_warning) printf 'Note: this test address uses HTTP. Do not send production credentials over an untrusted network.\n' ;;
    *) printf '%s\n' "$key" ;;
  esac
}

blue_text() {
  printf '%s%s%s' "$terminal_blue" "$1" "$terminal_reset"
}

choose_language() {
  case "$language" in
    zh-CN|en) return ;;
    *) language="" ;;
  esac
  if [[ -t 0 ]]; then
    printf '%s\n' "$(blue_text "$(i18n language_menu)")"
    while :; do
      local selection=""
      read -r -p "$(blue_text "$(i18n language_prompt)")" selection || selection=""
      case "$selection" in
        ""|1|zh|zh-CN) language="zh-CN"; return ;;
        2|en|EN|English) language="en"; return ;;
        *) i18n language_invalid >&2 ;;
      esac
    done
  elif [[ -t 1 && -r /dev/tty ]]; then
    printf '%s\n' "$(blue_text "$(i18n language_menu)")" > /dev/tty
    while :; do
      local selection=""
      read -r -p "$(blue_text "$(i18n language_prompt)")" selection </dev/tty || selection=""
      case "$selection" in
        ""|1|zh|zh-CN) language="zh-CN"; return ;;
        2|en|EN|English) language="en"; return ;;
        *) i18n language_invalid > /dev/tty ;;
      esac
    done
  else
    language="en"
  fi
}

choose_language

has_interactive_terminal() {
  [[ -t 0 || ( -t 1 && -r /dev/tty ) ]]
}

read_prompt_value() {
  local prompt="$1"
  prompt="$(blue_text "$prompt")"
  if [[ -t 0 ]]; then
    read -r -p "$prompt" REPLY || REPLY=""
  elif [[ -t 1 && -r /dev/tty ]]; then
    read -r -p "$prompt" REPLY </dev/tty || REPLY=""
  else
    REPLY=""
  fi
}

read_prompt_secret() {
  local prompt="$1"
  prompt="$(blue_text "$prompt")"
  if [[ -t 0 ]]; then
    read -r -s -p "$prompt" REPLY || REPLY=""
    printf '\n'
  elif [[ -t 1 && -r /dev/tty ]]; then
    read -r -s -p "$prompt" REPLY </dev/tty || REPLY=""
    printf '\n' > /dev/tty
  else
    REPLY=""
  fi
}

ask_yes_no() {
  local prompt="$1"
  local default="$2"
  local answer=""
  if ! has_interactive_terminal; then
    [[ "$default" == "yes" ]]
    return
  fi
  while :; do
    read_prompt_value "$prompt"
    answer="${REPLY,,}"
    case "$answer" in
      ""|y|yes) [[ "$default" == "yes" || -n "$answer" ]]; return ;;
      n|no) return 1 ;;
      *) i18n invalid_yes_no >&2 ;;
    esac
  done
}

is_ipv4_address() {
  local first second third fourth octet
  [[ "$1" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
  IFS=. read -r first second third fourth <<<"$1"
  for octet in "$first" "$second" "$third" "$fourth"; do
    ((10#$octet <= 255)) || return 1
  done
}

detect_public_ip() {
  command -v curl >/dev/null 2>&1 || return 0
  local candidate
  candidate="$(curl -4 -fsSL --max-time 5 'https://api.ipify.org' 2>/dev/null | tr -d '[:space:]' || true)"
  if is_ipv4_address "$candidate"; then
    printf '%s\n' "$candidate"
  fi
}

current_bbr_state() {
  local qdisc congestion
  qdisc="$(sysctl -n net.core.default_qdisc 2>/dev/null || true)"
  congestion="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)"
  [[ "$qdisc" == "fq" && "$congestion" == "bbr" ]]
}

enable_bbr_fq_now() {
  local available qdisc congestion persisted_qdisc persisted_congestion
  modprobe tcp_bbr >/dev/null 2>&1 || true
  modprobe sch_fq >/dev/null 2>&1 || true
  available="$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || true)"
  if [[ " $available " != *" bbr "* ]]; then
    i18n bbr_unsupported >&2
    return 1
  fi
  persisted_qdisc="$previous_default_qdisc"
  persisted_congestion="$previous_congestion_control"
  if [[ -r /etc/sysctl.d/99-j-ui-bbr.conf ]]; then
    persisted_qdisc="$(sed -n 's/^# previous_default_qdisc=//p' /etc/sysctl.d/99-j-ui-bbr.conf | head -n 1)"
    persisted_congestion="$(sed -n 's/^# previous_congestion_control=//p' /etc/sysctl.d/99-j-ui-bbr.conf | head -n 1)"
    persisted_qdisc="${persisted_qdisc:-$previous_default_qdisc}"
    persisted_congestion="${persisted_congestion:-$previous_congestion_control}"
  fi
  printf '%s\n' \
    '# Managed by J-UI. Remove this file to stop persisting these settings.' \
    "# previous_default_qdisc=${persisted_qdisc}" \
    "# previous_congestion_control=${persisted_congestion}" \
    'net.core.default_qdisc = fq' \
    'net.ipv4.tcp_congestion_control = bbr' \
    > "${temporary_directory}/99-j-ui-bbr.conf"
  install -m 0644 "${temporary_directory}/99-j-ui-bbr.conf" /etc/sysctl.d/99-j-ui-bbr.conf
  sysctl -q -w net.core.default_qdisc=fq
  sysctl -q -w net.ipv4.tcp_congestion_control=bbr
  bbr_live_changed=1
  qdisc="$(sysctl -n net.core.default_qdisc 2>/dev/null || true)"
  congestion="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)"
  if [[ "$qdisc" != "fq" || "$congestion" != "bbr" ]]; then
    i18n bbr_verify_failed >&2
    return 1
  fi
  i18n bbr_ready
}

render_initialization_output() {
  if [[ "$language" == "zh-CN" ]]; then
    printf '%s\n' "$1" |
      sed \
        -e 's/^J-UI initialized$/J-UI 初始化完成/' \
        -e 's/^Username: /用户名：/' \
        -e 's/^Password: /密码：/' \
        -e 's/^Management URL: /管理地址：/' \
        -e 's/^Subscription Token: /订阅 Token：/'
  else
    printf '%s\n' "$1"
  fi
}

render_profile_header() {
  printf '%s' "$terminal_blue"
  printf '\n%s\n' '═══════════════════════════════════════════'
  if [[ "$language" == "zh-CN" ]]; then
    printf '%s\n' '             J-UI 安装配置'
    printf '%s\n' '请依次确认节点端口、公网地址、SSL 证书、管理员凭据和 BBR + FQ。'
  else
    printf '%s\n' '         J-UI Installation Profile'
    printf '%s\n' 'Confirm the node port, public address, SSL certificate, administrator credentials, and BBR + FQ.'
  fi
  printf '%s\n\n' '═══════════════════════════════════════════'
  printf '%s' "$terminal_reset"
}

render_installation_summary() {
  local initialization_output="$1"
  local reset_output_value="$2"
  local current_admin_path="$3"
  local username password web_base_path management_url url_host certificate_summary bbr_summary existing_argo_domain existing_argo_port
  username="$(printf '%s\n' "$initialization_output" "$reset_output_value" | sed -n 's/^Username: //p' | tail -n 1)"
  password="$(printf '%s\n' "$initialization_output" "$reset_output_value" | sed -n 's/^Password: //p' | tail -n 1)"
  username="${username:-admin}"
  web_base_path="/${current_admin_path#/}"
  web_base_path="${web_base_path%/}/"
  url_host="$public_host"
  if [[ "$url_host" == *:* && "$url_host" != \[*\] ]]; then
    url_host="[${url_host}]"
  fi
  management_url="https://${url_host}:${management_port}${web_base_path}"
  if [[ "$certificate_mode" == "auto" ]]; then
    if is_ipv4_address "$public_host"; then
      certificate_summary="Let’s Encrypt IP short-lived (${public_host}, auto-renewed)"
    else
      certificate_summary="Let’s Encrypt (${public_host}, auto-renewed)"
    fi
  else
    certificate_summary="${certificate_path}"
  fi
  if current_bbr_state; then
    bbr_summary="BBR + FQ"
  else
    bbr_summary="disabled"
  fi
  if [[ -z "$password" ]]; then
    i18n credentials_missing >&2
    return 1
  fi
  if [[ $credentials_verified -ne 1 ]]; then
    i18n credentials_verification_failed >&2
    return 1
  fi
  printf '%s' "$terminal_blue"
  if [[ "$language" == "zh-CN" ]]; then
    printf '%s\n' '═══════════════════════════════════════════'
    printf '%s\n' '              J-UI 安装完成'
    printf '%s\n' '═══════════════════════════════════════════'
    printf '用户名：        %s\n' "$username"
    printf '密码：          %s\n' "$password"
    printf '管理端口：      %s\n' "$management_port"
    printf '节点起始端口：  %s\n' "$node_start_port"
    printf '节点 SSL 证书： %s\n' "$certificate_summary"
    if [[ "$bbr_summary" == "BBR + FQ" ]]; then
      printf '拥塞控制：      BBR + FQ（已启用）\n'
    else
      printf '拥塞控制：      未启用\n'
    fi
    existing_argo_domain="$(jq -r '.domain // empty' /etc/j-ui/argo-profile.json 2>/dev/null || true)"
    existing_argo_port="$(jq -r '.originPort // empty' /etc/j-ui/argo-profile.json 2>/dev/null || true)"
    if [[ -n "$existing_argo_domain" && -n "$existing_argo_port" ]] && systemctl is-active --quiet cloudflared.service; then
      printf 'Argo 隧道：     %s → 127.0.0.1:%s（保留现有配置）\n' "$existing_argo_domain" "$existing_argo_port"
    else
      printf 'Argo 隧道：     未部署（请运行 j-ui，在管理菜单中配置）\n'
    fi
    printf 'WebBasePath：   %s\n' "$web_base_path"
    printf '数据库：        SQLite (/var/lib/j-ui/j-ui.db)\n'
    printf '管理地址：      %s\n' "$management_url"
    printf '%s\n' '═══════════════════════════════════════════'
  else
    printf '%s\n' '==========================================='
    printf '%s\n' '          J-UI Installation Complete'
    printf '%s\n' '==========================================='
    printf 'Username:        %s\n' "$username"
    printf 'Password:        %s\n' "$password"
    printf 'Management port: %s\n' "$management_port"
    printf 'Node start port: %s\n' "$node_start_port"
    printf 'Node SSL cert:   %s\n' "$certificate_summary"
    printf 'Congestion:      %s\n' "$bbr_summary"
    existing_argo_domain="$(jq -r '.domain // empty' /etc/j-ui/argo-profile.json 2>/dev/null || true)"
    existing_argo_port="$(jq -r '.originPort // empty' /etc/j-ui/argo-profile.json 2>/dev/null || true)"
    if [[ -n "$existing_argo_domain" && -n "$existing_argo_port" ]] && systemctl is-active --quiet cloudflared.service; then
      printf 'Argo Tunnel:     %s -> 127.0.0.1:%s (existing setup preserved)\n' "$existing_argo_domain" "$existing_argo_port"
    else
      printf 'Argo Tunnel:     not deployed (run j-ui and configure it from the menu)\n'
    fi
    printf 'WebBasePath:     %s\n' "$web_base_path"
    printf 'Database:        SQLite (/var/lib/j-ui/j-ui.db)\n'
    printf 'Management URL:  %s\n' "$management_url"
    printf '%s\n' '==========================================='
  fi
  printf '%s' "$terminal_reset"
}

render_management_help() {
  printf '%s' "$terminal_blue"
  printf '\n%s\n' '───────────────────────────────────────────'
  if [[ "$language" == "zh-CN" ]]; then
    printf '%s\n' '常用管理命令'
    printf '  %-24s %s\n' 'j-ui' '打开管理菜单'
    printf '  %-24s %s\n' 'j-ui start|stop' '启动或停止服务'
    printf '  %-24s %s\n' 'j-ui restart|status' '重启面板或查看状态'
    printf '  %-24s %s\n' 'j-ui settings' '查看当前配置和管理地址'
    printf '  %-24s %s\n' 'j-ui log' '查看运行日志'
    printf '  %-24s %s\n' 'j-ui update' '更新并在失败时自动回滚'
    printf '  %-24s %s\n' 'j-ui ssl' '申请或更新 SSL 证书'
    printf '  %-24s %s\n' 'j-ui argo' '自动部署或重新配置固定域名 Argo'
    printf '  %-24s %s\n' 'j-ui backup|restore' '备份或恢复数据'
    printf '  %-24s %s\n' 'j-ui uninstall' '卸载并选择是否保留数据'
  else
    printf '%s\n' 'Common management commands'
    printf '  %-24s %s\n' 'j-ui' 'Open the management menu'
    printf '  %-24s %s\n' 'j-ui start|stop' 'Start or stop services'
    printf '  %-24s %s\n' 'j-ui restart|status' 'Restart the panel or show status'
    printf '  %-24s %s\n' 'j-ui settings' 'Show settings and management URL'
    printf '  %-24s %s\n' 'j-ui log' 'Show runtime logs'
    printf '  %-24s %s\n' 'j-ui update' 'Update with automatic rollback'
    printf '  %-24s %s\n' 'j-ui argo' 'Automatically deploy or reconfigure fixed-domain Argo'
    printf '  %-24s %s\n' 'j-ui ssl' 'Issue or renew the SSL certificate'
    printf '  %-24s %s\n' 'j-ui backup|restore' 'Back up or restore data'
    printf '  %-24s %s\n' 'j-ui uninstall' 'Uninstall and choose whether to keep data'
  fi
  printf '%s\n' '───────────────────────────────────────────'
  printf '%s' "$terminal_reset"
}

github_curl() {
  if [[ -n "${JUI_GITHUB_TOKEN:-}" ]]; then
    if [[ ! "$JUI_GITHUB_TOKEN" =~ ^[A-Za-z0-9_]+$ ]]; then
      i18n token_invalid >&2
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
    i18n release_asset_missing "$name" >&2
    return 1
  fi
  github_curl -fsSL -H "Accept: application/octet-stream" \
    "$asset_url" -o "$destination"
}

cleanup() {
  local exit_code=$?
  local rollback_failed=0
  trap - EXIT
  set +e
  if [[ $services_quiesced -eq 1 && $installation_started -eq 0 ]]; then
    if [[ $previous_singbox_active -eq 1 ]]; then systemctl start j-ui-sing-box.service >/dev/null 2>&1 || true; fi
    if [[ $previous_jui_active -eq 1 ]]; then systemctl start j-ui.service >/dev/null 2>&1 || true; fi
  fi
  if [[ $exit_code -ne 0 && $installation_started -eq 1 && -d "$temporary_directory/rollback" ]]; then
    systemctl stop j-ui.service j-ui-sing-box.service >/dev/null 2>&1 || rollback_failed=1
    if [[ $management_firewall_added -eq 1 && -x /usr/local/bin/j-ui ]]; then
      /usr/local/bin/j-ui close-management-firewall >/dev/null 2>&1 || rollback_failed=1
    fi
    if [[ $acme_firewall_added -eq 1 && -x /usr/local/bin/j-ui ]]; then
      /usr/local/bin/j-ui close-acme-firewall >/dev/null 2>&1 || rollback_failed=1
    fi
    if [[ -x /usr/local/bin/j-ui ]] &&
      systemctl list-units --all --plain --no-legend 'jui-vpngate-*' | grep -q .; then
      /usr/local/bin/j-ui cleanup-vpngate >/dev/null 2>&1 || rollback_failed=1
    fi
    for target in "${managed_targets[@]}"; do
      rollback_path="${temporary_directory}/rollback${target}"
      if [[ -e "$rollback_path" || -L "$rollback_path" ]]; then
        install -d -m 0755 "$(dirname "$target")" || rollback_failed=1
        rm -f -- "$target" || rollback_failed=1
        cp -a -- "$rollback_path" "$target" || rollback_failed=1
      elif [[ -e "${rollback_path}.missing" ]]; then
        rm -f -- "$target" || rollback_failed=1
      fi
    done
    if [[ $bbr_live_changed -eq 1 ]]; then
      [[ -n "$previous_default_qdisc" ]] && sysctl -q -w "net.core.default_qdisc=${previous_default_qdisc}" >/dev/null 2>&1 || true
      [[ -n "$previous_congestion_control" ]] && sysctl -q -w "net.ipv4.tcp_congestion_control=${previous_congestion_control}" >/dev/null 2>&1 || true
    fi
    for tree in /etc/j-ui /var/lib/j-ui; do
      rollback_tree="${temporary_directory}/trees${tree}"
      rm -rf -- "$tree" || rollback_failed=1
      if [[ -d "$rollback_tree" ]]; then
        install -d -m 0755 "$(dirname "$tree")" || rollback_failed=1
        cp -a -- "$rollback_tree" "$tree" || rollback_failed=1
      fi
    done
    systemctl daemon-reload >/dev/null 2>&1 || rollback_failed=1
    systemctl disable j-ui.service j-ui-sing-box.service j-ui-certificate-renew.timer >/dev/null 2>&1 || rollback_failed=1
    if [[ $previous_singbox_enabled -eq 1 ]]; then systemctl enable j-ui-sing-box.service >/dev/null 2>&1 || rollback_failed=1; fi
    if [[ $previous_jui_enabled -eq 1 ]]; then systemctl enable j-ui.service >/dev/null 2>&1 || rollback_failed=1; fi
    if [[ $previous_singbox_active -eq 1 ]]; then
      systemctl start j-ui-sing-box.service >/dev/null 2>&1 || rollback_failed=1
      systemctl is-active --quiet j-ui-sing-box.service >/dev/null 2>&1 || rollback_failed=1
    fi
    if [[ $previous_jui_active -eq 1 ]]; then
      systemctl start j-ui.service >/dev/null 2>&1 || rollback_failed=1
      systemctl is-active --quiet j-ui.service >/dev/null 2>&1 || rollback_failed=1
    fi
    if [[ $rollback_failed -eq 0 ]]; then
      i18n install_rollback_success >&2
    else
      i18n install_rollback_failed "$temporary_directory" >&2
    fi
  fi
  if [[ $exit_code -ne 0 && $certificate_created -eq 1 && -x /opt/j-ui/certbot/bin/certbot ]]; then
    /opt/j-ui/certbot/bin/certbot delete --non-interactive --cert-name "$public_host" >/dev/null 2>&1 || rollback_failed=1
  fi
  if [[ $exit_code -ne 0 && $certbot_created -eq 1 ]]; then
    rm -rf -- /opt/j-ui/certbot || rollback_failed=1
  fi
  if [[ $rollback_failed -eq 0 && -n "$temporary_directory" && -d "$temporary_directory" ]]; then
    rm -rf -- "$temporary_directory"
  fi
  exit "$exit_code"
}
trap cleanup EXIT

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  i18n root_required >&2
  exit 1
fi
if [[ ! "$repository" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
  i18n repo_invalid >&2
  exit 1
fi
exec 9>/run/lock/j-ui-lifecycle.lock
if ! flock -n 9; then
  i18n lock_busy >&2
  exit 1
fi

if [[ ! -r /etc/os-release ]]; then
  i18n unsupported_linux >&2
  exit 1
fi
. /etc/os-release
case "${ID:-}" in
  debian)
    case "${VERSION_ID:-}" in 11|12) ;; *) i18n debian_version >&2; exit 1 ;; esac
    ;;
  ubuntu)
    case "${VERSION_ID:-}" in 22.04|24.04) ;; *) i18n ubuntu_version >&2; exit 1 ;; esac
    ;;
  *) i18n only_debian_ubuntu >&2; exit 1 ;;
esac

case "$(uname -m)" in
  x86_64) architecture="amd64" ;;
  aarch64|arm64) architecture="arm64" ;;
  *) i18n architecture >&2; exit 1 ;;
esac

i18n installing_dependencies
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl iproute2 jq kmod nftables openvpn openssl procps python3-venv tar util-linux
temporary_directory="$(mktemp -d /tmp/j-ui-install.XXXXXX)"
version="${JUI_VERSION:-}"
if [[ -z "$version" ]]; then
  version="$(github_curl -fsSL "https://api.github.com/repos/${repository}/releases/latest" |
    jq -r '.tag_name // empty' | sed -n 's/^v//p' | head -n 1)"
fi
if [[ -z "$version" ]]; then
  i18n latest_version_failed >&2
  exit 1
fi
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
  i18n version_invalid "$version" >&2
  exit 1
fi
release_base="${JUI_RELEASE_BASE:-https://github.com/${repository}/releases/download/v${version}}"
archive="j-ui_${version}_linux_${architecture}.tar.gz"
download_release_asset "$archive" "${temporary_directory}/${archive}"
download_release_asset "checksums.txt" "${temporary_directory}/checksums.txt"
(
  cd "$temporary_directory"
  grep " ${archive}\$" checksums.txt | sha256sum --check --status
)
tar -xzf "${temporary_directory}/${archive}" -C "$temporary_directory"
for required in j-ui deploy/j-ui.service deploy/j-ui-update.service deploy/j-ui-sing-box.service \
  deploy/j-ui-certificate-renew.service deploy/j-ui-certificate-renew.timer \
  deploy/j-ui-certificate-issue@.service deploy/j-ui.env deploy/empty-sing-box.json \
  scripts/update.sh scripts/uninstall.sh scripts/manage.sh scripts/ssl.sh scripts/argo.sh sing-box; do
  if [[ ! -e "${temporary_directory}/${required}" ]]; then
    i18n release_asset_missing "$required" >&2
    exit 1
  fi
done

if [[ "$("${temporary_directory}/sing-box" version | sed -n '1s/^sing-box version //p')" != "$singbox_version" ]]; then
  i18n release_asset_missing "sing-box ${singbox_version}" >&2
  exit 1
fi
i18n dependencies_ready

if [[ -e /var/lib/j-ui/j-ui.db ]]; then
  case "${JUI_PRESERVE_DATA:-ask}" in
    yes|YES|true|TRUE|1) preserve_existing_data=1 ;;
    no|NO|false|FALSE|0)
      preserve_existing_data=0
      i18n clean_install_selected
      ;;
    ask|"")
      if ! ask_yes_no "$(i18n confirm_preserve_data)" yes; then
        preserve_existing_data=0
        i18n clean_install_selected
      fi
      ;;
    *)
      i18n preserve_data_invalid >&2
      exit 1
      ;;
  esac
fi

if [[ -r /etc/j-ui/j-ui.env ]]; then
  installation_listen="$(
    sed -n 's/^JUI_LISTEN_ADDRESS=//p' /etc/j-ui/j-ui.env | head -n 1
  )"
  installation_listen="${installation_listen%\"}"
  installation_listen="${installation_listen#\"}"
  installation_listen="${installation_listen%\'}"
  installation_listen="${installation_listen#\'}"
fi
installation_listen="${JUI_LISTEN_ADDRESS:-${installation_listen:-0.0.0.0:8080}}"
case "$installation_listen" in
  127.0.0.1:*)
    management_port="${installation_listen##*:}"
    installation_listen="0.0.0.0:${management_port}"
    ;;
  0.0.0.0:*) management_port="${installation_listen##*:}" ;;
  \[::1\]:*)
    management_port="${installation_listen##*:}"
    installation_listen="0.0.0.0:${management_port}"
    ;;
  *)
    i18n listen_loopback >&2
    exit 1
    ;;
esac
if [[ ! "$management_port" =~ ^[0-9]+$ ]] ||
  ((10#$management_port < 1 || 10#$management_port > 65535)); then
  i18n listen_invalid "$installation_listen" >&2
  exit 1
fi

render_profile_header

configured_node_start_port=""
if [[ -r /etc/j-ui/j-ui.env ]]; then
  configured_node_start_port="$(sed -n 's/^JUI_NODE_START_PORT=//p' /etc/j-ui/j-ui.env | head -n 1)"
  configured_node_start_port="${configured_node_start_port%\"}"
  configured_node_start_port="${configured_node_start_port#\"}"
  configured_node_start_port="${configured_node_start_port%\'}"
  configured_node_start_port="${configured_node_start_port#\'}"
fi
if [[ -x /usr/local/bin/j-ui ]]; then
  persisted_node_start_port="$(/usr/local/bin/j-ui get-node-start-port 2>/dev/null || true)"
  if [[ "$persisted_node_start_port" =~ ^[0-9]+$ ]]; then
    configured_node_start_port="$persisted_node_start_port"
  fi
fi
node_start_port="${JUI_NODE_START_PORT:-${configured_node_start_port:-8881}}"
if ! ask_yes_no "$(i18n confirm_port "$node_start_port")" yes; then
  read_prompt_value "$(i18n custom_port_prompt)"
  node_start_port="$REPLY"
fi
if [[ ! "$node_start_port" =~ ^[0-9]+$ ]] ||
  ((10#$node_start_port < 1 || 10#$node_start_port > 65535)); then
  i18n node_port_invalid >&2
  exit 1
fi

detected_public_host="${JUI_PUBLIC_HOST:-}"
if [[ -z "$detected_public_host" ]]; then
  detected_public_host="$(detect_public_ip)"
fi
if [[ -n "$detected_public_host" ]]; then
  if ask_yes_no "$(i18n confirm_public_host "$detected_public_host")" yes; then
    public_host="$detected_public_host"
  else
    read_prompt_value "$(i18n custom_public_host_prompt)"
    public_host="$REPLY"
  fi
elif has_interactive_terminal; then
  i18n public_host_unavailable >&2
  read_prompt_value "$(i18n custom_public_host_prompt)"
  public_host="$REPLY"
fi
if [[ -z "$public_host" ]] && has_interactive_terminal; then
  i18n public_host_required >&2
  exit 1
fi
if [[ "$public_host" == *:* ]]; then
  i18n public_host_ipv4_only >&2
  exit 1
fi

certificate_mode="${JUI_CERTIFICATE_MODE:-auto}"
certificate_path="${JUI_CERTIFICATE_PATH:-}"
certificate_key_path="${JUI_CERTIFICATE_KEY_PATH:-}"
certificate_label="$(i18n certificate_auto)"
if [[ "$certificate_mode" == "manual" ]]; then
  certificate_label="$(i18n certificate_manual)"
fi
if ! ask_yes_no "$(i18n confirm_certificate "$certificate_label")" yes; then
  certificate_mode="manual"
  read_prompt_value "$(i18n certificate_path_prompt)"
  certificate_path="$REPLY"
  read_prompt_value "$(i18n certificate_key_path_prompt)"
  certificate_key_path="$REPLY"
fi

admin_username="${JUI_ADMIN_USERNAME:-admin}"
if ! ask_yes_no "$(i18n confirm_admin_username "$admin_username")" yes; then
  read_prompt_value "$(i18n custom_admin_username_prompt)"
  admin_username="$REPLY"
fi
if [[ ! "$admin_username" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{2,31}$ ]]; then
  i18n admin_username_invalid >&2
  exit 1
fi

admin_password="${JUI_ADMIN_PASSWORD:-admin}"
if ! ask_yes_no "$(i18n confirm_admin_password "$admin_password")" yes; then
  read_prompt_secret "$(i18n custom_admin_password_prompt)"
  admin_password="$REPLY"
  read_prompt_secret "$(i18n confirm_admin_password_prompt)"
  if [[ "$admin_password" != "$REPLY" ]]; then
    i18n admin_password_mismatch >&2
    exit 1
  fi
fi
if ((${#admin_password} < 4)); then
  i18n admin_password_short >&2
  exit 1
fi

if current_bbr_state; then
  bbr_state_label="$(i18n bbr_enabled)"
else
  bbr_state_label="$(i18n bbr_disabled)"
fi
case "${JUI_ENABLE_BBR:-ask}" in
  yes|YES|true|TRUE|1) enable_bbr_fq=1 ;;
  no|NO|false|FALSE|0) enable_bbr_fq=0 ;;
  ask|"")
    if ask_yes_no "$(i18n confirm_bbr "$bbr_state_label")" yes; then
      enable_bbr_fq=1
    fi
    ;;
  *)
    i18n bbr_setting_invalid >&2
    exit 1
    ;;
esac

if [[ -c /dev/net/tun ]]; then
  tun_status="available"
else
  tun_status="unavailable (VPNGate exits will remain disabled until /dev/net/tun is available)"
fi
previous_default_qdisc="$(sysctl -n net.core.default_qdisc 2>/dev/null || true)"
previous_congestion_control="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)"
install -d -m 0700 "${temporary_directory}/rollback"
systemctl is-active --quiet j-ui.service >/dev/null 2>&1 && previous_jui_active=1 || true
systemctl is-enabled --quiet j-ui.service >/dev/null 2>&1 && previous_jui_enabled=1 || true
systemctl is-active --quiet j-ui-sing-box.service >/dev/null 2>&1 && previous_singbox_active=1 || true
systemctl is-enabled --quiet j-ui-sing-box.service >/dev/null 2>&1 && previous_singbox_enabled=1 || true

if ss -H -ltn "sport = :${management_port}" | grep -q . &&
  ! systemctl is-active --quiet j-ui.service >/dev/null 2>&1; then
  i18n management_port_busy "$management_port" >&2
  exit 1
fi

# Capture rollback state only after all downloads and validation have
# completed, so a long download cannot make the rollback point stale.
for target in "${managed_targets[@]}"; do
  rollback_path="${temporary_directory}/rollback${target}"
  install -d -m 0700 "$(dirname "$rollback_path")"
  if [[ -e "$target" || -L "$target" ]]; then
    cp -a -- "$target" "$rollback_path"
  else
    touch "${rollback_path}.missing"
  fi
done
install -d -m 0700 "${temporary_directory}/trees"
# Quiesce SQLite before copying its database and WAL. This creates a coherent,
# byte-for-byte rollback point while keeping downtime limited to the copy.
services_quiesced=1
if [[ $previous_jui_active -eq 1 ]]; then systemctl stop j-ui.service; fi
if [[ $previous_singbox_active -eq 1 ]]; then systemctl stop j-ui-sing-box.service; fi
if [[ -x /usr/local/bin/j-ui ]] &&
  systemctl list-units --all --plain --no-legend 'jui-vpngate-*' | grep -q .; then
  /usr/local/bin/j-ui cleanup-vpngate
fi
for tree in /etc/j-ui /var/lib/j-ui; do
  if [[ -d "$tree" ]]; then
    rollback_tree="${temporary_directory}/trees${tree}"
    install -d -m 0700 "$(dirname "$rollback_tree")"
    cp -a -- "$tree" "$rollback_tree"
  fi
done

installation_started=1
if [[ $enable_bbr_fq -eq 1 ]]; then
  enable_bbr_fq_now
fi
if [[ $preserve_existing_data -eq 0 ]]; then
  if [[ -x /usr/local/bin/j-ui ]]; then
    /usr/local/bin/j-ui cleanup-firewall
  fi
  rm -rf -- /etc/j-ui /var/lib/j-ui
fi
install -d -m 0700 /etc/j-ui /var/lib/j-ui /var/backups/j-ui
install -d -m 0755 /usr/local/lib/j-ui
install -m 0755 "${temporary_directory}/j-ui" /usr/local/bin/j-ui
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
install -m 0755 "${temporary_directory}/sing-box" /usr/local/lib/j-ui/sing-box
install -m 0644 "${temporary_directory}/deploy/j-ui.service" /etc/systemd/system/j-ui.service
install -m 0644 "${temporary_directory}/deploy/j-ui-update.service" /etc/systemd/system/j-ui-update.service
install -m 0644 "${temporary_directory}/deploy/j-ui-sing-box.service" /etc/systemd/system/j-ui-sing-box.service
install -m 0644 "${temporary_directory}/deploy/j-ui-certificate-renew.service" /etc/systemd/system/j-ui-certificate-renew.service
install -m 0644 "${temporary_directory}/deploy/j-ui-certificate-renew.timer" /etc/systemd/system/j-ui-certificate-renew.timer
install -m 0644 "${temporary_directory}/deploy/j-ui-certificate-issue@.service" /etc/systemd/system/j-ui-certificate-issue@.service
if [[ ! -e /etc/j-ui/j-ui.env ]]; then
  install -m 0600 "${temporary_directory}/deploy/j-ui.env" /etc/j-ui/j-ui.env
  sed -i "s|^JUI_LISTEN_ADDRESS=.*$|JUI_LISTEN_ADDRESS=${installation_listen}|" \
    /etc/j-ui/j-ui.env
  sed -i "s|^JUI_NODE_START_PORT=.*$|JUI_NODE_START_PORT=${node_start_port}|" \
    /etc/j-ui/j-ui.env
elif grep -qx 'JUI_SINGBOX_BINARY=/usr/local/bin/sing-box' /etc/j-ui/j-ui.env; then
  sed -i 's|^JUI_SINGBOX_BINARY=/usr/local/bin/sing-box$|JUI_SINGBOX_BINARY=/usr/local/lib/j-ui/sing-box|' \
    /etc/j-ui/j-ui.env
fi
if grep -q '^JUI_LISTEN_ADDRESS=' /etc/j-ui/j-ui.env; then
  sed -i "s|^JUI_LISTEN_ADDRESS=.*$|JUI_LISTEN_ADDRESS=${installation_listen}|" /etc/j-ui/j-ui.env
else
  printf '\nJUI_LISTEN_ADDRESS=%s\n' "$installation_listen" >> /etc/j-ui/j-ui.env
fi
if grep -q '^JUI_LANGUAGE=' /etc/j-ui/j-ui.env; then
  sed -i "s|^JUI_LANGUAGE=.*$|JUI_LANGUAGE=${language}|" /etc/j-ui/j-ui.env
else
  printf '\nJUI_LANGUAGE=%s\n' "$language" >> /etc/j-ui/j-ui.env
fi
if [[ "$certificate_mode" == "auto" ]]; then
  panel_certificate_path="/etc/letsencrypt/live/${public_host}/fullchain.pem"
  panel_certificate_key_path="/etc/letsencrypt/live/${public_host}/privkey.pem"
else
  panel_certificate_path="$certificate_path"
  panel_certificate_key_path="$certificate_key_path"
fi
for entry in "JUI_TLS_CERTIFICATE_PATH=${panel_certificate_path}" "JUI_TLS_KEY_PATH=${panel_certificate_key_path}"; do
  key="${entry%%=*}"
  value="${entry#*=}"
  if grep -q "^${key}=" /etc/j-ui/j-ui.env; then
    sed -i "s|^${key}=.*$|${key}=${value}|" /etc/j-ui/j-ui.env
  else
    printf '%s=%s\n' "$key" "$value" >> /etc/j-ui/j-ui.env
  fi
done
if [[ ! -e /etc/j-ui/sing-box.json ]]; then
  install -m 0600 "${temporary_directory}/deploy/empty-sing-box.json" /etc/j-ui/sing-box.json
fi
install -m 0755 "${temporary_directory}/scripts/update.sh" /usr/local/lib/j-ui/update.sh
install -m 0755 "${temporary_directory}/scripts/uninstall.sh" /usr/local/lib/j-ui/uninstall.sh
install -m 0755 "${temporary_directory}/scripts/manage.sh" /usr/local/lib/j-ui/manage.sh
install -m 0755 "${temporary_directory}/scripts/ssl.sh" /usr/local/lib/j-ui/ssl.sh
install -m 0755 "${temporary_directory}/scripts/argo.sh" /usr/local/lib/j-ui/argo.sh

if [[ "$certificate_mode" == "auto" ]]; then
  if [[ ! -x /opt/j-ui/certbot/bin/certbot ]]; then
    python3 -m venv /opt/j-ui/certbot
    certbot_created=1
  fi
  /opt/j-ui/certbot/bin/pip install --disable-pip-version-check --no-cache-dir --quiet 'certbot==5.7.0'
  certificate_existed=0
  [[ -s "/etc/letsencrypt/live/${public_host}/fullchain.pem" ]] && certificate_existed=1
  /usr/local/lib/j-ui/ssl.sh "$public_host"
  if [[ $certificate_existed -eq 0 && -s "/etc/letsencrypt/live/${public_host}/fullchain.pem" ]]; then
    certificate_created=1
  fi
fi

systemctl daemon-reload
initialization_output="$(
  env -u JUI_DATA_DIR -u JUI_CONFIG_DIR -u JUI_SINGBOX_BINARY \
    -u JUI_ENGINE_MODE -u JUI_LISTEN_ADDRESS \
    JUI_NODE_START_PORT="${node_start_port}" /usr/local/bin/j-ui init
)"
printf '%s\n' "$admin_password" | env -u JUI_DATA_DIR -u JUI_CONFIG_DIR \
  -u JUI_SINGBOX_BINARY -u JUI_ENGINE_MODE -u JUI_LISTEN_ADDRESS \
  /usr/local/bin/j-ui set-credentials --username "$admin_username" --password-stdin >/dev/null
reset_output="$(printf 'Username: %s\nPassword: %s\n' "$admin_username" "$admin_password")"
env -u JUI_DATA_DIR -u JUI_CONFIG_DIR -u JUI_SINGBOX_BINARY \
  -u JUI_ENGINE_MODE -u JUI_LISTEN_ADDRESS \
  /usr/local/bin/j-ui set-language "$language"
configure_args=(configure-install --language "$language" --certificate-mode "$certificate_mode")
if [[ -n "$public_host" ]]; then
  configure_args+=(--public-host "$public_host")
fi
if [[ "$certificate_mode" == "manual" ]]; then
  configure_args+=(--certificate-path "$certificate_path" --key-path "$certificate_key_path")
fi
env -u JUI_DATA_DIR -u JUI_CONFIG_DIR -u JUI_SINGBOX_BINARY \
  -u JUI_ENGINE_MODE -u JUI_LISTEN_ADDRESS \
  /usr/local/bin/j-ui "${configure_args[@]}" >/dev/null
/usr/local/lib/j-ui/sing-box check -c /etc/j-ui/sing-box.json
systemctl enable j-ui-sing-box.service j-ui.service
if [[ "$certificate_mode" == "auto" ]]; then
  systemctl enable --now j-ui-certificate-renew.timer
else
  systemctl disable --now j-ui-certificate-renew.timer 2>/dev/null || true
fi
systemctl restart j-ui-sing-box.service
systemctl restart j-ui.service
systemctl is-active --quiet j-ui-sing-box.service j-ui.service
health_url="$(
  env -u JUI_DATA_DIR -u JUI_CONFIG_DIR -u JUI_SINGBOX_BINARY \
    -u JUI_ENGINE_MODE -u JUI_LISTEN_ADDRESS \
    /usr/local/bin/j-ui internal-health-url
)"
health_ready=0
for _ in {1..60}; do
  if curl -kfsS --max-time 2 "$health_url" >/dev/null 2>&1; then
    health_ready=1
    break
  fi
  sleep 1
done
if [[ $health_ready -ne 1 ]]; then
  i18n health_check_failed >&2
  systemctl status j-ui.service j-ui-sing-box.service --no-pager -n 30 >&2 || true
  journalctl -u j-ui.service -u j-ui-sing-box.service --no-pager -n 60 >&2 || true
  exit 1
fi
login_url="${health_url%/api/v1/health}/api/v1/auth/login"
logout_url="${health_url%/api/v1/health}/api/v1/auth/logout"
login_cookie_file="${temporary_directory}/login-cookie.txt"
login_payload="$(jq -nc --arg username "$admin_username" --arg password "$admin_password" \
  '{username:$username,password:$password}')"
if ! login_response="$(curl -kfsS --max-time 5 -c "$login_cookie_file" \
  -H 'Content-Type: application/json' --data "$login_payload" "$login_url")" ||
  [[ "$(jq -r '.username // empty' <<<"$login_response")" != "$admin_username" ]]; then
  i18n credentials_verification_failed >&2
  exit 1
fi
login_csrf_token="$(jq -r '.csrfToken // empty' <<<"$login_response")"
if [[ -n "$login_csrf_token" ]]; then
  curl -kfsS --max-time 5 -b "$login_cookie_file" -X POST \
    -H "X-CSRF-Token: ${login_csrf_token}" "$logout_url" >/dev/null 2>&1 || true
fi
credentials_verified=1
management_firewall_output="$(/usr/local/bin/j-ui ensure-management-firewall)"
if grep -qx 'Ownership: owned' <<<"$management_firewall_output"; then
  management_firewall_added=1
fi
services_quiesced=0

admin_path="$(
  env -u JUI_DATA_DIR -u JUI_CONFIG_DIR -u JUI_SINGBOX_BINARY \
    -u JUI_ENGINE_MODE -u JUI_LISTEN_ADDRESS \
    /usr/local/bin/j-ui get-admin-path
)"
render_installation_summary "$initialization_output" "$reset_output" "$admin_path"
render_management_help
i18n profile_saved
i18n tun_status "$tun_status"
