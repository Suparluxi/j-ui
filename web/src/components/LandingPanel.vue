<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { request } from "../api";

const props = defineProps<{ language: "zh-CN" | "en"; preview?: boolean }>();
const tr = (zh: string, en: string) => props.language === "en" ? en : zh;
type Landing = { enabled: boolean; inboundId: number; configured: boolean };
type Rules = { source: string; sourceUrl?: string; updatedAt?: string; base: { rules: Array<{ domain: string[]; domain_suffix: string[]; domain_regex: string[] }> }; include: string[]; exclude: string[] };
const suggestedRulesURL = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/category-ai-!cn.json";
const tab = ref<"guide" | "rules">("guide");
const landing = ref<Landing | null>(null);
const rules = ref<Rules | null>(null);
const details = ref("");
const setupScript = ref("");
const generatedScript = ref("");
const enabled = ref(false);
const includeText = ref("");
const excludeText = ref("");
const filter = ref("");
const sourceURL = ref(suggestedRulesURL);
const publicAddress = ref("");
const publicPort = ref("14443");
const listenPort = ref("14443");
const sni = ref("www.microsoft.com");
const busy = ref(false);
const error = ref("");
const notice = ref("");
const baseDomains = computed(() => {
  const base = rules.value?.base.rules[0];
  return base ? [...base.domain_suffix, ...base.domain, ...base.domain_regex].filter(value => value.includes(filter.value.trim().toLowerCase())) : [];
});
const validPort = (value: string) => /^\d+$/.test(value) && Number(value) >= 1 && Number(value) <= 65535;
const validIPv4 = (value: string) => !value || (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(value) && value.split(".").every(octet => Number(octet) <= 255));
const validSNI = (value: string) => /^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(value);
const portGuideError = computed(() => {
  if (!validIPv4(publicAddress.value.trim())) return tr("公网 IPv4 地址格式不正确。", "Enter a valid public IPv4 address.");
  if (!validPort(publicPort.value)) return tr("公网端口必须是 1 到 65535 的数字。", "Public port must be a number from 1 to 65535.");
  if (!validPort(listenPort.value)) return tr("本机监听端口必须是 1 到 65535 的数字。", "Local listen port must be a number from 1 to 65535.");
  if (!validSNI(sni.value.trim())) return tr("Reality SNI 必须是有效的主机名。", "Reality SNI must be a valid hostname.");
  return "";
});
const shellQuote = (value: string) => `'${value.replaceAll("'", "'\\''")}'`;
function generateScript() {
  if (portGuideError.value || !setupScript.value) return;
  const assignments = [
    publicAddress.value.trim() ? `export LANDING_ADDR=${shellQuote(publicAddress.value.trim())}` : "",
    `export LANDING_PORT=${shellQuote(publicPort.value)}`,
    `export LANDING_LISTEN_PORT=${shellQuote(listenPort.value)}`,
    `export LANDING_SNI=${shellQuote(sni.value.trim())}`
  ].filter(Boolean);
  const body = setupScript.value.replace(/^#![^\r\n]*(?:\r?\n|$)/, "");
  generatedScript.value = `#!/usr/bin/env bash\n${assignments.join("\n")}\n\n${body}`;
  notice.value = tr("一键脚本已生成，请审查后在落地机运行", "One-click script generated; review and run it on the landing VPS");
}
function clearGeneratedScript() { generatedScript.value = ""; notice.value = ""; }

async function load() {
  try {
    const [state, list, setup] = await Promise.all([
      request<Landing>("/api/v1/landing"), request<Rules>("/api/v1/landing/rules"),
      request<{ script: string }>("/api/v1/landing/script")
    ]);
    landing.value = state;
    rules.value = list;
    sourceURL.value = list.sourceUrl || suggestedRulesURL;
    setupScript.value = setup.script;
    enabled.value = state.enabled;
    includeText.value = list.include.join("\n");
    excludeText.value = list.exclude.join("\n");
  } catch (caught) { error.value = String((caught as Error).message); }
}

async function saveLanding() {
  busy.value = true; error.value = ""; notice.value = "";
  try {
    landing.value = await request<Landing>("/api/v1/landing", {
      method: "PUT", body: JSON.stringify({ enabled: enabled.value, details: details.value.trim() })
    });
    details.value = "";
    notice.value = props.preview ? tr("演示状态已更新，未应用到 VPS", "Preview updated; no VPS was changed") : tr("配置已应用", "Configuration applied");
  } catch (caught) { enabled.value = landing.value?.enabled ?? false; error.value = String((caught as Error).message); }
  finally { busy.value = false; }
}

async function copyScript() {
  if (!generatedScript.value) return;
  try {
    if (navigator.clipboard?.writeText) {
      try {
        await navigator.clipboard.writeText(generatedScript.value);
        notice.value = tr("一键脚本已复制", "One-click script copied");
        return;
      } catch { /* Fall back for restricted browser contexts. */ }
    }
    const textarea = document.createElement("textarea");
    textarea.value = generatedScript.value;
    textarea.setAttribute("readonly", "");
    textarea.style.position = "fixed";
    textarea.style.left = "-9999px";
    document.body.append(textarea);
    textarea.select();
    try {
      if (!document.execCommand?.("copy")) throw new Error("clipboard copy was rejected");
    } finally { textarea.remove(); }
    notice.value = tr("一键脚本已复制", "One-click script copied");
  } catch { error.value = tr("复制失败，请手动选择脚本文本", "Copy failed; select the script text manually"); }
}

async function saveRules() {
  busy.value = true; error.value = ""; notice.value = "";
  try {
    const lines = (text: string) => text.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
    rules.value = await request<Rules>("/api/v1/landing/rules", {
      method: "PUT", body: JSON.stringify({ include: lines(includeText.value), exclude: lines(excludeText.value) })
    });
    notice.value = props.preview ? tr("演示规则已更新，未应用到 VPS", "Preview rules updated; no VPS was changed") : tr("规则已应用", "Rules applied");
  } catch (caught) { error.value = String((caught as Error).message); }
  finally { busy.value = false; }
}

async function refreshRules(restore = false) {
  busy.value = true; error.value = ""; notice.value = "";
  try {
    const list = await request<Rules>("/api/v1/landing/rules/refresh", {
      method: "POST", body: JSON.stringify({ sourceUrl: restore ? "" : sourceURL.value.trim() })
    });
    rules.value = list;
    sourceURL.value = list.sourceUrl || suggestedRulesURL;
    notice.value = props.preview ? tr("演示规则来源已更新，未连接 VPS", "Preview source updated; no VPS was changed") : tr("规则基线已检查并应用", "Rule baseline validated and applied");
  } catch (caught) { error.value = String((caught as Error).message); }
  finally { busy.value = false; }
}

onMounted(load);
</script>

<template>
  <div class="landing-panel">
    <p v-if="preview" class="landing-preview-note">{{ tr("演示模式 · 不连接 VPS", "Preview mode · no VPS connection") }}</p>
    <div class="landing-tabs" role="tablist">
      <button type="button" role="tab" :aria-selected="tab === 'guide'" :class="{ active: tab === 'guide' }" @click="tab = 'guide'">{{ tr("配置引导", "Configuration") }}</button>
      <button type="button" role="tab" :aria-selected="tab === 'rules'" :class="{ active: tab === 'rules' }" @click="tab = 'rules'">{{ tr("规则集管理", "Rules") }}</button>
    </div>
    <p v-if="error" class="alert error" role="alert">{{ error }}</p>
    <p v-if="notice" class="alert success" role="status">{{ notice }}</p>
    <form v-if="tab === 'guide' && landing" @submit.prevent="saveLanding">
      <p class="landing-state" role="status">{{ landing.enabled ? tr("AI 分流：已启用", "AI routing: enabled") : tr("AI 分流：未启用", "AI routing: disabled") }} · {{ landing.configured ? tr("落地出口：已配置", "Landing exit: configured") : tr("落地出口：未配置", "Landing exit: not configured") }}</p>
      <p>{{ tr("适用范围：本机所有已启用的常规入口协议；专用出口及临时住宅节点保留原有路由。新建的常规入口自动加入。", "Scope: all enabled regular inbounds on this server. Dedicated exits and temporary residential nodes retain their routes. New regular inbounds are included automatically.") }}</p>
      <p v-if="landing.enabled && landing.inboundId" class="landing-migration-note" role="status">{{ tr("现有配置仍只作用于旧入口。保存并应用后才扩展到所有常规入口。", "Existing routing still applies only to the previous inbound. Save and apply to expand it to all regular inbounds.") }}</p>
      <p>{{ tr("填写落地机参数并生成一键脚本。审查后在目标 VPS 上运行，再将输出的六行连接信息粘贴回来；客户端仍只连接当前中转节点。", "Set the landing parameters and generate one complete script. Review and run it on the target VPS, then paste the six connection detail lines it returns here; clients continue connecting only to the current relay.") }}</p>
      <details class="landing-port-guide" open>
        <summary>{{ tr("端口映射设置", "Port mapping") }}</summary>
        <p>{{ tr("普通公网 VPS 默认使用 TCP 14443；NAT VPS 分别填写服务商分配的公网端口和落地机本机监听端口。", "A regular public VPS defaults to TCP 14443; on a NAT VPS, enter the provider-assigned public port and the landing VPS local listen port separately.") }}</p>
        <div class="landing-port-fields">
          <label for="landing-public-address">{{ tr("公网 IPv4（可选）", "Public IPv4 (optional)") }}
            <input id="landing-public-address" v-model="publicAddress" type="text" inputmode="decimal" autocomplete="off" placeholder="203.0.113.10" :aria-invalid="Boolean(publicAddress && !validIPv4(publicAddress.trim()))" @input="clearGeneratedScript" />
            <small>{{ tr("留空时由脚本自动检测，仍需核对结果。", "Leave empty to detect it automatically; verify the result.") }}</small>
          </label>
          <label for="landing-public-port">{{ tr("公网映射端口", "Public mapped port") }}
            <input id="landing-public-port" v-model="publicPort" type="text" inputmode="numeric" autocomplete="off" :aria-invalid="!validPort(publicPort)" @input="clearGeneratedScript" />
            <small>{{ tr("香港 VPS 实际连接的端口；NAT 机填服务商分配的端口。", "Port Hong Kong connects to; use the provider-assigned port on a NAT VPS.") }}</small>
          </label>
          <label for="landing-listen-port">{{ tr("本机监听端口", "Local listen port") }}
            <input id="landing-listen-port" v-model="listenPort" type="text" inputmode="numeric" autocomplete="off" :aria-invalid="!validPort(listenPort)" @input="clearGeneratedScript" />
            <small>{{ tr("落地机上 sing-box 监听的 TCP 端口。", "TCP port sing-box listens on locally on the landing VPS.") }}</small>
          </label>
          <label for="landing-sni">{{ tr("Reality SNI", "Reality SNI") }}
            <input id="landing-sni" v-model="sni" type="text" autocomplete="off" :aria-invalid="!validSNI(sni.trim())" @input="clearGeneratedScript" />
            <small>{{ tr("必须是脚本可用的伪装主机名，例如 www.microsoft.com。", "Use a valid camouflage hostname, for example www.microsoft.com.") }}</small>
          </label>
        </div>
        <p v-if="portGuideError" class="landing-port-error" role="alert">{{ portGuideError }}</p>
        <button class="primary compact" type="button" @click="generateScript" :disabled="Boolean(portGuideError) || !setupScript">{{ tr("生成一键脚本", "Generate one-click script") }}</button>
        <p>{{ tr("如果服务商把公网端口和内网端口固定为同一个值，就把两个变量设为相同端口。如果没有 TCP 入站端口映射，不能直接使用这条 TCP 第二跳，需要服务商中转或其他隧道。", "If the provider fixes public and internal ports to the same value, set both variables to that port. Without TCP inbound port forwarding, this direct TCP second hop cannot work; use a provider relay or another tunnel.") }}</p>
      </details>
      <details v-if="generatedScript" class="landing-script" open>
        <summary>{{ tr("审查已生成的一键脚本", "Review generated one-click script") }}</summary>
        <div class="landing-script-actions"><button type="button" @click="copyScript" :title="tr('复制一键脚本', 'Copy one-click script')">{{ tr("复制一键脚本", "Copy one-click script") }}</button></div>
        <textarea :value="generatedScript" readonly rows="18" :aria-label="tr('已生成的一键脚本', 'Generated one-click script')" />
        <p>{{ tr("将整份脚本保存到目标 VPS，例如 landing-setup.sh，以 root 执行 bash landing-setup.sh。脚本完成后，把终端返回的六行连接信息粘贴到下方。", "Save the whole script on the target VPS, for example as landing-setup.sh, and run bash landing-setup.sh as root. Paste the six connection detail lines it returns below.") }}</p>
      </details>
      <label>Landing connection details
        <textarea v-model="details" rows="6" autocomplete="off" spellcheck="false" :placeholder="preview ? 'No real details in preview' : 'ADDR=...\nPORT=...\nUUID=...\nPUBLIC_KEY=...\nSHORT_ID=...\nSNI=...'" :disabled="preview" :required="enabled && !landing.configured" />
        <small>Paste the six ASCII connection detail lines returned by the setup script. UUID and public key are not shown again; leave blank to retain an existing connection.</small>
      </label>
      <label class="landing-toggle"><input v-model="enabled" type="checkbox" />{{ tr("启用 AI 分流", "Enable AI routing") }}</label>
      <button class="primary compact" type="submit" :disabled="busy">{{ tr("保存并应用", "Save and apply") }}</button>
    </form>
    <div v-if="tab === 'rules' && rules">
      <div class="landing-source-settings">
        <label for="landing-source-url">{{ tr("规则集来源 (GitHub Raw sing-box JSON)", "Rule source (GitHub Raw sing-box JSON)") }}</label>
        <input id="landing-source-url" v-model="sourceURL" type="url" autocomplete="off" spellcheck="false" />
        <div class="landing-source-actions">
          <button type="button" class="primary compact" :disabled="busy || !sourceURL.trim()" @click="refreshRules()">{{ tr("更新规则集", "Update rule set") }}</button>
          <button type="button" :disabled="busy || !rules.sourceUrl" @click="refreshRules(true)">{{ tr("恢复内置规则", "Restore bundled rules") }}</button>
        </div>
        <small>{{ tr("仅手动更新；来源校验失败或配置应用失败时保留旧规则。", "Manual updates only; failed downloads or apply checks keep the previous rules.") }}</small>
        <p class="landing-source">{{ rules.sourceUrl || tr("当前：内置快照", "Current: bundled snapshot") }} · {{ rules.source }}<span v-if="rules.updatedAt"> · {{ rules.updatedAt }}</span></p>
      </div>
      <input v-model="filter" type="search" :placeholder="tr('搜索基线域名', 'Search base domains')" :aria-label="tr('搜索基线域名', 'Search base domains')" />
      <div class="landing-domain-list" role="list"><span v-for="domain in baseDomains" :key="domain" role="listitem">{{ domain }}</span></div>
      <form @submit.prevent="saveRules">
        <div class="landing-overrides">
          <label>{{ tr("强制落地（每行一个域名后缀）", "Force landing (one domain suffix per line)") }}<textarea v-model="includeText" rows="5" /></label>
          <label>{{ tr("强制香港（优先于 AI 基线）", "Force Hong Kong (overrides AI baseline)") }}<textarea v-model="excludeText" rows="5" /></label>
        </div>
        <button class="primary compact" type="submit" :disabled="busy">{{ tr("保存规则", "Save rules") }}</button>
      </form>
    </div>
  </div>
</template>

<style scoped>
.landing-panel { padding: 20px 24px 26px; }
.landing-preview-note { margin: 0 0 12px; color: #0f766e; font-size: 12px; font-weight: 700; }
.landing-tabs { display: flex; gap: 12px; border-bottom: 1px solid #dce3ec; }
.landing-tabs button { padding: 10px 4px; background: transparent; color: #475569; }
.landing-tabs button.active { color: #0f766e; border-bottom: 2px solid currentColor; }
.landing-panel form { max-width: 860px; }
.landing-panel p { line-height: 1.6; }
.landing-migration-note { color: #b45309; font-weight: 600; }
.landing-script { max-width: 860px; margin: 16px 0; }
.landing-port-guide { max-width: 860px; margin: 16px 0; }
.landing-script summary { width: fit-content; cursor: pointer; color: #0f766e; font-weight: 600; }
.landing-port-guide summary { width: fit-content; cursor: pointer; color: #0f766e; font-weight: 600; }
.landing-port-fields { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 14px 18px; margin: 16px 0; }
.landing-port-fields label { display: grid; gap: 6px; }
.landing-port-fields input { box-sizing: border-box; width: 100%; padding: 9px 10px; border: 1px solid #dce3ec; border-radius: 6px; background: #fff; color: #1e293b; font: inherit; }
.landing-port-fields input[aria-invalid="true"] { border-color: #dc2626; }
.landing-port-fields small, .landing-port-guide > small { color: #64748b; font-size: 12px; line-height: 1.45; }
.landing-port-error { color: #b91c1c; font-size: 13px; }
.landing-script-actions { margin: 8px 0; }
.landing-script-actions button { padding: 6px 10px; color: #0f766e; background: #e6f4f1; border: 0; border-radius: 4px; cursor: pointer; }
.landing-script textarea, .landing-panel label > textarea { box-sizing: border-box; width: 100%; padding: 10px; border: 1px solid #dce3ec; border-radius: 6px; background: #fff; color: #1e293b; font-family: ui-monospace, monospace; resize: vertical; }
.landing-script textarea { min-height: 220px; white-space: pre; overflow: auto; }
.landing-script textarea:focus-visible, .landing-script-actions button:focus-visible, .landing-script summary:focus-visible { outline: 2px solid #0f766e; outline-offset: 2px; }
.landing-port-fields input:focus-visible { outline: 2px solid #0f766e; outline-offset: 2px; }
.landing-toggle { display: flex; align-items: center; gap: 10px; }
.landing-toggle input { width: auto; }
.landing-domain-list { display: flex; flex-wrap: wrap; align-content: flex-start; gap: 5px 12px; max-height: 190px; overflow: auto; margin: 12px 0 24px; font-size: 12px; }
.landing-domain-list span { color: #334155; }
.landing-overrides { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 18px; }
.landing-overrides textarea { width: 100%; min-height: 120px; padding: 12px; border: 1px solid #dce3ec; border-radius: 6px; resize: vertical; font: inherit; }
.landing-source { font-size: 12px; overflow-wrap: anywhere; }
.landing-state { font-weight: 600; color: #9a3412; }
.landing-source-settings { max-width: 860px; margin: 18px 0; display: grid; gap: 8px; }
.landing-source-settings input { box-sizing: border-box; width: 100%; padding: 9px 10px; border: 1px solid #dce3ec; border-radius: 6px; background: #fff; color: #1e293b; font: inherit; }
.landing-source-settings small { color: #64748b; font-size: 12px; }
.landing-source-actions { display: flex; gap: 12px; flex-wrap: wrap; }
.landing-source-actions button { padding: 8px 12px; border: 0; background: #e6f4f1; color: #0f766e; cursor: pointer; }
.landing-source-actions button:disabled { opacity: .55; cursor: default; }
.landing-source-actions button:focus-visible, .landing-source-settings input:focus-visible { outline: 2px solid #0f766e; outline-offset: 2px; }
@media (max-width: 650px) { .landing-panel { padding: 16px; } .landing-overrides, .landing-port-fields { grid-template-columns: 1fr; gap: 0; } .landing-port-fields label { margin-top: 14px; } }
:global(html[data-theme="dark"] .landing-tabs) { border-color: #334155; }
:global(html[data-theme="dark"] .landing-tabs button) { color: #cbd5e1; }
:global(html[data-theme="dark"] .landing-tabs button.active) { color: #5eead4; }
:global(html[data-theme="dark"] .landing-source),
:global(html[data-theme="dark"] .landing-domain-list span) { color: #cbd5e1; }
:global(html[data-theme="dark"] .landing-overrides textarea) { color: #e2e8f0; background: #111827; border-color: #334155; }
:global(html[data-theme="dark"] .landing-source-settings input) { color: #e2e8f0; background: #111827; border-color: #334155; }
:global(html[data-theme="dark"] .landing-source-settings small) { color: #94a3b8; }
:global(html[data-theme="dark"] .landing-source-actions button) { color: #5eead4; background: #164e4a; }
:global(html[data-theme="dark"] .landing-state) { color: #fbbf24; }
:global(html[data-theme="dark"] .landing-preview-note) { color: #5eead4; }
:global(html[data-theme="dark"] .landing-migration-note) { color: #fbbf24; }
:global(html[data-theme="dark"] .landing-script summary),
:global(html[data-theme="dark"] .landing-port-guide summary) { color: #5eead4; }
:global(html[data-theme="dark"] .landing-port-fields input) { color: #e2e8f0; background: #111827; border-color: #334155; }
:global(html[data-theme="dark"] .landing-port-fields small),
:global(html[data-theme="dark"] .landing-port-guide > small) { color: #94a3b8; }
:global(html[data-theme="dark"] .landing-port-error) { color: #fca5a5; }
:global(html[data-theme="dark"] .landing-script-actions button) { color: #5eead4; background: #164e4a; }
:global(html[data-theme="dark"] .landing-script textarea),
:global(html[data-theme="dark"] .landing-panel label > textarea) { color: #e2e8f0; background: #111827; border-color: #334155; }
</style>
