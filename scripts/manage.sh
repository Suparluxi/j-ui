#!/usr/bin/env bash
set -Eeuo pipefail

readonly jui_binary="/usr/local/bin/j-ui"

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  printf '%s\n' 'Run the J-UI management menu as root.' >&2
  exit 1
fi

language="${JUI_LANGUAGE:-}"
if [[ -z "$language" && -r /etc/j-ui/j-ui.env ]]; then
  language="$(sed -n 's/^JUI_LANGUAGE=//p' /etc/j-ui/j-ui.env | head -n 1)"
fi
[[ "$language" == "en" ]] || language="zh-CN"

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  readonly reset=$'\033[0m' bold=$'\033[1m' blue=$'\033[38;5;39m' green=$'\033[32m'
else
  readonly reset="" bold="" blue="" green=""
fi

t() {
  local key="$1"
  case "$language:$key" in
    zh-CN:title) printf 'J-UI 管理菜单' ;;
    zh-CN:installed) printf '运行状态' ;;
    zh-CN:running) printf '运行中' ;;
    zh-CN:stopped) printf '已停止' ;;
    zh-CN:choose) printf '请输入数字 [0-16]：' ;;
    zh-CN:start) printf '启动 J-UI' ;;
    zh-CN:stop) printf '停止 J-UI' ;;
    zh-CN:restart) printf '重启面板' ;;
    zh-CN:status) printf '查看服务状态' ;;
    zh-CN:settings) printf '查看当前配置' ;;
    zh-CN:reset_password) printf '修改管理员账号和密码' ;;
    zh-CN:backup) printf '创建备份' ;;
    zh-CN:restore) printf '恢复备份' ;;
    zh-CN:logs) printf '查看运行日志' ;;
    zh-CN:update) printf '更新 J-UI' ;;
    zh-CN:enable) printf '启用开机自启' ;;
    zh-CN:disable) printf '关闭开机自启' ;;
    zh-CN:language) printf '切换 English' ;;
    zh-CN:uninstall) printf '卸载 J-UI' ;;
    zh-CN:ssl) printf '申请或更新 SSL 证书' ;;
    zh-CN:argo) printf '自动部署或重新配置固定域名 Argo' ;;
    zh-CN:exit) printf '退出菜单' ;;
    zh-CN:path) printf '请输入备份文件绝对路径：' ;;
    zh-CN:restore_confirm) printf '恢复将替换当前数据并重启面板，是否继续 [y/N]：' ;;
    zh-CN:uninstall_confirm) printf '即将进入卸载流程，是否继续 [y/N]：' ;;
    zh-CN:invalid) printf '无效选项，请重新输入。' ;;
    zh-CN:done) printf '操作完成，按 Enter 返回菜单。' ;;
    en:title) printf 'J-UI Management Menu' ;;
    en:installed) printf 'Service status' ;;
    en:running) printf 'running' ;;
    en:stopped) printf 'stopped' ;;
    en:choose) printf 'Enter a number [0-16]: ' ;;
    en:start) printf 'Start J-UI' ;;
    en:stop) printf 'Stop J-UI' ;;
    en:restart) printf 'Restart panel' ;;
    en:status) printf 'Show service status' ;;
    en:settings) printf 'Show current settings' ;;
    en:reset_password) printf 'Change administrator credentials' ;;
    en:backup) printf 'Create backup' ;;
    en:restore) printf 'Restore backup' ;;
    en:logs) printf 'Show runtime logs' ;;
    en:update) printf 'Update J-UI' ;;
    en:enable) printf 'Enable autostart' ;;
    en:disable) printf 'Disable autostart' ;;
    en:language) printf '切换简体中文' ;;
    en:uninstall) printf 'Uninstall J-UI' ;;
    en:ssl) printf 'Issue or renew the SSL certificate' ;;
    en:argo) printf 'Automatically deploy or reconfigure fixed-domain Argo' ;;
    en:exit) printf 'Exit menu' ;;
    en:path) printf 'Enter the absolute backup path: ' ;;
    en:restore_confirm) printf 'Restore replaces current data and restarts the panel. Continue [y/N]: ' ;;
    en:uninstall_confirm) printf 'Continue to the uninstall workflow [y/N]: ' ;;
    en:invalid) printf 'Invalid option. Try again.' ;;
    en:done) printf 'Operation finished. Press Enter to return.' ;;
    *) printf '%s' "$key" ;;
  esac
}

separator() {
  printf '%s\n' "${blue}────────────────────────────────────────────────────────${reset}"
}

render_banner() {
  printf '%s\n' "${blue}${bold}╔════════════════════════════════════════════════════════╗${reset}"
  printf '%s\n' "${blue}${bold}║                                                        ║${reset}"
  printf '%s\n' "${blue}${bold}║         ██╗       ██╗   ██╗ ██╗                        ║${reset}"
  printf '%s\n' "${blue}${bold}║         ██║       ██║   ██║ ██║  轻松订阅              ║${reset}"
  printf '%s\n' "${blue}${bold}║         ██║  ███  ██║   ██║ ██║  简单掌控              ║${reset}"
  printf '%s\n' "${blue}${bold}║    ██   ██║       ██║   ██║ ██║  Easy subscription     ║${reset}"
  printf '%s\n' "${blue}${bold}║    ╚█████╔╝       ╚██████╔╝ ██║  Easy management       ║${reset}"
  printf '%s\n' "${blue}${bold}║     ╚════╝         ╚═════╝  ╚═╝                        ║${reset}"
  printf '%s\n' "${blue}${bold}║                                                        ║${reset}"
  printf '%s\n' "${blue}${bold}╚════════════════════════════════════════════════════════╝${reset}"
}

pause_menu() {
  printf '\n%s%s%s ' "$blue" "$(t done)" "$reset"
  read -r _ || true
}

persist_language() {
  "$jui_binary" set-language "$language"
  if [[ -f /etc/j-ui/j-ui.env ]]; then
    if grep -q '^JUI_LANGUAGE=' /etc/j-ui/j-ui.env; then
      sed -i "s|^JUI_LANGUAGE=.*$|JUI_LANGUAGE=${language}|" /etc/j-ui/j-ui.env
    else
      printf '\nJUI_LANGUAGE=%s\n' "$language" >> /etc/j-ui/j-ui.env
    fi
    chmod 0600 /etc/j-ui/j-ui.env
  fi
}

replace_credentials() {
  local current_username default_username new_username password confirmation
  current_username="$($jui_binary get-admin-username)"
  default_username="${current_username:-jui-$(openssl rand -hex 3)}"
  if [[ "$language" == "zh-CN" ]]; then
    printf '当前管理员账号为 %s。请输入新账号，直接回车保留当前账号：' "$default_username"
  else
    printf 'Current administrator username: %s. Enter a new username, or press Enter to keep it: ' "$default_username"
  fi
  read -r new_username || new_username=""
  new_username="${new_username:-$default_username}"
  if [[ "$language" == "zh-CN" ]]; then
    printf '是否自动生成独立强密码 [Y/n]：'
  else
    printf 'Generate a unique strong password [Y/n]: '
  fi
  read -r confirmation || confirmation=""
  if [[ "$confirmation" =~ ^[Nn]$ ]]; then
    if [[ "$language" == "zh-CN" ]]; then
      read -r -s -p '请输入新密码（至少 4 位）：' password || password=""
      printf '\n'
      read -r -s -p '请再次输入新密码：' confirmation || confirmation=""
    else
      read -r -s -p 'Enter the new password (at least 4 characters): ' password || password=""
      printf '\n'
      read -r -s -p 'Enter the new password again: ' confirmation || confirmation=""
    fi
    printf '\n'
    if [[ "$password" != "$confirmation" ]]; then
      if [[ "$language" == "zh-CN" ]]; then printf '两次输入的密码不一致。\n' >&2; else printf 'The passwords do not match.\n' >&2; fi
      return 1
    fi
  else
    password="$(openssl rand -hex 18)"
  fi
  printf '%s\n' "$password" | "$jui_binary" set-credentials --username "$new_username" --password-stdin >/dev/null
  if [[ "$language" == "zh-CN" ]]; then
    printf '管理员凭据已替换，原账号、密码和全部登录会话已失效。\n用户名：%s\n密码：%s\n' "$new_username" "$password"
  else
    printf 'Administrator credentials replaced. The previous credentials and sessions are invalid.\nUsername: %s\nPassword: %s\n' "$new_username" "$password"
  fi
}

service_state() {
  if systemctl is-active --quiet j-ui.service; then
    printf '%s%s%s' "$green" "$(t running)" "$reset"
  else
    printf '%s%s%s' "$blue" "$(t stopped)" "$reset"
  fi
}

version_value() {
  "$jui_binary" info 2>/dev/null | sed -n 's/^Version: //p' | head -n 1
}

render_menu() {
  [[ -t 1 ]] && clear || true
  render_banner
  printf '%s\n' "${blue}${bold}$(t title)${reset}"
  printf '%s%s:%s %s  %sVersion: %s%s\n' "$blue" "$(t installed)" "$reset" "$(service_state)" "$blue" "$(version_value)" "$reset"
  separator
  printf '%s  1. %s\n' "$blue" "$(t start)"
  printf '  2. %s\n' "$(t stop)"
  printf '  3. %s\n' "$(t restart)"
  printf '  4. %s\n' "$(t status)"
  printf '  5. %s%s\n' "$(t settings)" "$reset"
  separator
  printf '%s  6. %s\n' "$blue" "$(t reset_password)"
  printf '  7. %s\n' "$(t backup)"
  printf '  8. %s\n' "$(t restore)"
  printf '  9. %s\n' "$(t logs)"
  printf ' 10. %s%s\n' "$(t update)" "$reset"
  separator
  printf '%s 11. %s\n' "$blue" "$(t enable)"
  printf ' 12. %s\n' "$(t disable)"
  printf ' 13. %s\n' "$(t language)"
  printf ' 14. %s\n' "$(t uninstall)"
  printf ' 15. %s\n' "$(t ssl)"
  printf ' 16. %s\n' "$(t argo)"
  printf '  0. %s%s\n' "$(t exit)" "$reset"
  separator
}

action_title() {
  case "$1" in
    1) t start ;; 2) t stop ;; 3) t restart ;; 4) t status ;; 5) t settings ;;
    6) t reset_password ;; 7) t backup ;; 8) t restore ;; 9) t logs ;; 10) t update ;;
    11) t enable ;; 12) t disable ;; 13) t language ;; 14) t uninstall ;;
    15) t ssl ;; 16) t argo ;;
  esac
}

render_action_header() {
  local title="$1"
  [[ -t 1 ]] && clear || true
  render_banner
  printf '%s%s%s\n' "${blue}${bold}" "$title" "$reset"
  separator
}

run_action() {
  local action="$1" backup_path answer
  if [[ "$action" != "0" ]]; then
    render_action_header "$(action_title "$action")"
  fi
  case "$action" in
    1) "$jui_binary" start ;;
    2) "$jui_binary" stop ;;
    3) "$jui_binary" restart ;;
    4) "$jui_binary" status ;;
    5) "$jui_binary" settings ;;
    6) replace_credentials ;;
    7) "$jui_binary" backup ;;
    8)
      printf '%s' "$(t path)"
      read -r backup_path || backup_path=""
      if [[ -z "$backup_path" ]]; then
        printf '%s\n' "$(t invalid)"
        return
      fi
      printf '%s' "$(t restore_confirm)"
      read -r answer || answer=""
      [[ "$answer" =~ ^[Yy]$ ]] || return
      "$jui_binary" restore "$backup_path"
      ;;
    9) "$jui_binary" log ;;
    10) "$jui_binary" update ;;
    11) "$jui_binary" enable ;;
    12) "$jui_binary" disable ;;
    13)
      if [[ "$language" == "en" ]]; then language="zh-CN"; else language="en"; fi
      persist_language
      return 2
      ;;
    14)
      printf '%s' "$(t uninstall_confirm)"
      read -r answer || answer=""
      [[ "$answer" =~ ^[Yy]$ ]] || return
      "$jui_binary" uninstall
      exit 0
      ;;
    15) "$jui_binary" ssl ;;
    16) "$jui_binary" argo ;;
    0) exit 0 ;;
    *) printf '%s\n' "$(t invalid)"; return 1 ;;
  esac
}

while :; do
  render_menu
  printf '%s%s%s' "$blue" "$(t choose)" "$reset"
  read -r menu_action || exit 0
  if run_action "$menu_action"; then
    pause_menu
  else
    action_status=$?
    [[ $action_status -eq 2 ]] || pause_menu
  fi
done
