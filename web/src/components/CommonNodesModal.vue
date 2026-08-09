<script setup lang="ts">
import { computed, reactive } from "vue";
import { defaultRealityTarget, realityTargets } from "../realityTargets";
import DropdownField from "./DropdownField.vue";

const props = defineProps<{
  serverName: string;
  publicHost: string;
  certificateServerName: string;
  certificateMode: "auto" | "manual";
  certificatePath: string;
  certificateKeyPath: string;
  existingProtocols: string[];
  nextPort: number;
  error: string;
  submitting: boolean;
  theme: "light" | "dark";
  language: "zh-CN" | "en";
}>();
const emit = defineEmits<{ close: []; submit: [payloads: Record<string, unknown>[]] }>();

const protocolMissing = (protocol: string) => !props.existingProtocols.includes(protocol);

const form = reactive({
  serverName: props.serverName || "J-UI",
  realityPort: props.nextPort,
  hysteriaPort: props.nextPort + Number(protocolMissing("vless_reality")),
  tuicPort: props.nextPort + Number(protocolMissing("vless_reality")) + Number(protocolMissing("hysteria2")),
  certificateDomain: props.certificateServerName || props.publicHost || "",
  realityTarget: defaultRealityTarget,
  enabled: true
});

const existingProtocolSet = computed(() => new Set(props.existingProtocols));
const presets = computed(() => [
  { id: "vless_reality", name: `${form.serverName.trim()}丨XTLS-Reality_${form.realityPort}`, network: "TCP" },
  { id: "hysteria2", name: `${form.serverName.trim()}丨Hysteria2_${form.hysteriaPort}`, network: "UDP" },
  { id: "tuic", name: `${form.serverName.trim()}丨TUIC_${form.tuicPort}`, network: "UDP" }
].map(preset => ({ ...preset, exists: existingProtocolSet.value.has(preset.id) })));
const missingCount = computed(() => presets.value.filter(preset => !preset.exists).length);
const tr = (chinese: string, english: string) => props.language === "en" ? english : chinese;

function submit() {
  const serverName = form.serverName.trim();
  const certificate = {
    server_name: form.certificateDomain.trim(),
    certificate_mode: props.certificateMode,
    ...(props.certificateMode === "manual" ? {
      certificate_path: props.certificatePath,
      key_path: props.certificateKeyPath
    } : {})
  };
  const payloads = [
    {
      name: `${serverName}丨XTLS-Reality_${form.realityPort}`,
      protocol: "vless_reality", listen: "0.0.0.0", port: Number(form.realityPort),
      enabled: form.enabled, clientName: "default", publicHostOverride: "",
      settings: {
        handshake_server: form.realityTarget.trim(), handshake_port: 443,
        server_name: form.realityTarget.trim()
      },
      outboundId: null
    },
    {
      name: `${serverName}丨Hysteria2_${form.hysteriaPort}`,
      protocol: "hysteria2", listen: "0.0.0.0", port: Number(form.hysteriaPort),
      enabled: form.enabled, clientName: "default", publicHostOverride: "",
      settings: { ...certificate }, outboundId: null
    },
    {
      name: `${serverName}丨TUIC_${form.tuicPort}`,
      protocol: "tuic", listen: "0.0.0.0", port: Number(form.tuicPort),
      enabled: form.enabled, clientName: "default", publicHostOverride: "",
      settings: { ...certificate }, outboundId: null
    }
  ].filter(payload => !existingProtocolSet.value.has(payload.protocol));
  if (payloads.length) emit("submit", payloads);
}
</script>

<template>
  <div class="preset-backdrop" :class="`theme-${theme}`" @click.self="emit('close')">
    <form class="preset-modal" @submit.prevent="submit">
      <header>
        <div><h2>{{ tr("一键创建常用节点", "Create Common Nodes") }}</h2><p>{{ tr("一次生成 Reality、Hysteria2 与 TUIC。", "Create Reality, Hysteria2, and TUIC in one batch.") }}</p></div>
        <button type="button" :aria-label="tr('关闭', 'Close')" @click="emit('close')">×</button>
      </header>

      <div class="preset-body">
        <section>
          <h3>{{ tr("命名与端口", "Names & Ports") }}</h3>
          <label>{{ tr("服务器名", "Server Name") }}<input v-model="form.serverName" placeholder="J-UI" required><small>{{ tr("节点名称格式：服务器名丨协议名_端口", "Format: Server丨Protocol_Port") }}</small></label>
          <div class="port-grid">
            <label>Reality<input v-model.number="form.realityPort" type="number" min="1" max="65535" required></label>
            <label>Hysteria2<input v-model.number="form.hysteriaPort" type="number" min="1" max="65535" required></label>
            <label>TUIC<input v-model.number="form.tuicPort" type="number" min="1" max="65535" required></label>
          </div>
          <label>{{ tr("Reality 伪装目标", "Reality Target") }}
            <DropdownField v-model="form.realityTarget" :options="realityTargets" :theme="theme" :language="language" menu-id="common-reality-target-menu" :placeholder="defaultRealityTarget" editable required menu-placement="top" :menu-note="tr('也可以直接输入其他目标域名', 'You may also enter another target domain')" :trigger-label="tr('常用 Reality 目标', 'common Reality targets')" />
          </label>
        </section>

        <section>
          <h3>{{ tr("TLS 证书", "TLS Certificate") }}</h3>
          <p>{{ tr("Hysteria2 与 TUIC 共用证书。J-UI 会优先使用当前 VPS 域名已有的 Let's Encrypt 证书。", "Hysteria2 and TUIC share a certificate. J-UI prefers an existing Let's Encrypt certificate for the current VPS domain.") }}</p>
          <label>{{ tr("证书域名 / SNI", "Certificate Domain / SNI") }}<input v-model="form.certificateDomain" placeholder="node.example.com" required></label>
          <p class="certificate-note">{{ tr("当前演示环境会自动生成仅用于配置校验的自签名证书；正式部署不会静默生成假证书。", "The demo environment creates a self-signed certificate for validation only; production never creates a fake certificate silently.") }}</p>
          <label class="toggle"><input v-model="form.enabled" type="checkbox"><span>{{ tr("创建后立即启用全部节点", "Enable all nodes after creation") }}</span></label>
        </section>

        <aside>
          <h3>{{ missingCount ? (language === "en" ? `${missingCount} nodes will be created` : `将创建 ${missingCount} 个节点`) : tr("常用节点已齐全", "All common nodes exist") }}</h3>
          <div v-for="preset in presets" :key="preset.id" :class="{ skipped: preset.exists }">
            <strong>{{ preset.name }}</strong>
            <small>{{ preset.network }} · {{ preset.exists ? tr("已存在，将跳过", "Already exists; skipped") : tr("等待创建", "Pending") }}</small>
          </div>
          <p v-if="missingCount" class="rollback-note">{{ tr("任一节点失败时，J-UI 会删除本批次已经创建的节点。", "If any node fails, J-UI deletes nodes already created in this batch.") }}</p>
          <p v-else class="complete-note">{{ tr("Reality、Hysteria2 与 TUIC 均已存在，无需重复创建。", "Reality, Hysteria2, and TUIC already exist.") }}</p>
        </aside>
      </div>

      <footer>
        <p v-if="error">{{ error }}</p>
        <div><button type="button" @click="emit('close')">{{ tr("取消", "Cancel") }}</button><button class="deploy" type="submit" :disabled="submitting || !missingCount">{{ submitting ? tr("正在创建并校验…", "Creating and validating…") : missingCount ? (language === "en" ? `Create ${missingCount} missing nodes` : `创建 ${missingCount} 个缺失节点`) : tr("无需创建", "Nothing to create") }}</button></div>
      </footer>
    </form>
  </div>
</template>

<style scoped>
.preset-backdrop { position: fixed; inset: 0; z-index: 31; overflow-y: auto; padding: 28px; background: rgba(2, 8, 16, .9); backdrop-filter: blur(10px); }
.preset-modal { width: min(1120px, 100%); margin: auto; overflow: visible; color: #dbe7f5; border: 1px solid #1e3b53; border-radius: 18px; background: #081522; box-shadow: 0 30px 100px rgba(0,0,0,.48); }
header, footer { display: flex; align-items: flex-start; justify-content: space-between; gap: 20px; padding: 28px 34px; background: linear-gradient(120deg, #0d2637, #0a1928); }
header { border-bottom: 1px solid #183149; } footer { align-items: center; border-top: 1px solid #183149; }
header h2 { margin: 6px 0; color: #f8fafc; font-size: 29px; } header p, section p { margin: 0; color: #7890a5; font-size: 13px; }
button { min-height: 38px; padding: 0 15px; color: #cbd5e1; border: 0; border-radius: 9px; background: #0b1c2b; } header button { width: 38px; padding: 0; font-size: 24px; }
.preset-body { display: grid; grid-template-columns: 1fr 1fr 300px; gap: 0; }
section, aside { padding: 28px 30px; border-right: 1px solid #183149; } aside { grid-column: 3; grid-row: 1; border-right: 0; background: #091827; }
h3 { margin: 0 0 18px; color: #eef7ff; font-size: 18px; }
label { display: grid; gap: 7px; margin-top: 16px; color: #9db0c1; font-size: 12px; font-weight: 750; }
input { width: 100%; min-height: 42px; padding: 0 13px; color: #e7f3ff; border: 1px solid #234158; border-radius: 9px; background: #07131f; }
small { color: #668096; font-weight: 500; }
.port-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 0 12px; }
.toggle { display: flex; align-items: center; gap: 10px; }.toggle input { width: 16px; min-height: 16px; }
.certificate-note { margin-top: 16px; padding: 12px; border: 1px solid #29465d; border-radius: 9px; background: #0b1c2b; }
aside > div { display: grid; gap: 5px; padding: 13px 0; border-bottom: 1px solid #173047; } aside strong { color: #e8f4ff; font-size: 13px; overflow-wrap: anywhere; }
.skipped { opacity: .55; }.skipped small { color: #94a3b8; }
.rollback-note { margin-top: 20px; padding: 13px; color: #fcd34d; border: 1px solid #6b531b; border-radius: 9px; background: #2a220d; }
.complete-note { margin-top: 20px; padding: 13px; color: #86efac; border: 1px solid #23683b; border-radius: 9px; background: #0b2919; }
footer > p { margin: 0; color: #fda4af; } footer > div { display: flex; gap: 10px; margin-left: auto; }.deploy { color: #fff; background: #7258ed; }
@media (max-width: 820px) { .preset-backdrop { padding: 10px; }.preset-body { grid-template-columns: 1fr; } section, aside { grid-column: 1; grid-row: auto; border-right: 0; border-top: 1px solid #183149; }.port-grid { grid-template-columns: 1fr; } footer { align-items: stretch; flex-direction: column; } }

.preset-backdrop.theme-light { background: rgba(71, 85, 105, .36); }
.theme-light .preset-modal { color: #475569; border-color: #dbe3ee; background: #fff; box-shadow: 0 30px 100px rgba(71, 85, 105, .28); }
.theme-light header, .theme-light footer { background: linear-gradient(120deg, #f8fafc, #eef2ff); }
.theme-light header { border-bottom-color: #dbe3ee; }
.theme-light footer { border-top-color: #dbe3ee; }
.theme-light header h2, .theme-light h3 { color: #1e293b; }
.theme-light header p, .theme-light section p { color: #64748b; }
.theme-light button { color: #475569; background: #eef2f7; }
.theme-light section, .theme-light aside { border-color: #dbe3ee; }
.theme-light aside { background: #f8fafc; }
.theme-light label { color: #475569; }
.theme-light input { color: #1e293b; border-color: #cbd5e1; background: #fff; }
.theme-light small { color: #64748b; }
.theme-light .certificate-note { border-color: #dbe3ee; background: #f8fafc; }
.theme-light aside > div { border-bottom-color: #e2e8f0; }
.theme-light aside strong { color: #334155; }
.theme-light .rollback-note { color: #92400e; border-color: #fcd34d; background: #fffbeb; }
.theme-light .complete-note { color: #166534; border-color: #86efac; background: #f0fdf4; }
.theme-light .deploy { color: #fff; background: #7258ed; }
</style>
