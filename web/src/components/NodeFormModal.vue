<script setup lang="ts">
import { computed, reactive, ref, watch } from "vue";
import { defaultRealityTarget, realityTargets } from "../realityTargets";
import DropdownField from "./DropdownField.vue";

interface NodeRecord {
  id: number;
  name: string;
  protocol: string;
  listen: string;
  port: number;
  enabled: boolean;
  publicHostOverride?: string;
  settings: Record<string, unknown>;
  outboundId?: number;
}

interface ProtocolOption {
  id: string;
  name: string;
  description: string;
  transport: string;
  security: string;
  network: "TCP" | "UDP" | "TCP + UDP";
  defaultPort: number;
  defaultListen: string;
  requiresCertificateDomain?: boolean;
  requiresWebSocketIngress?: boolean;
  requiresCloudflareTunnel?: boolean;
}

const props = defineProps<{
  node: NodeRecord | null;
  error: string;
  submitting: boolean;
  hostName: string;
  publicHost: string;
  nextPort: number;
  usedPorts: number[];
  mockMode: boolean;
  httpsIngressEnabled: boolean;
  httpsIngressDomain: string;
  cloudflareTunnelEnabled: boolean;
  cloudflareTunnelDomain: string;
  cloudflareTunnelOriginPort: number;
  certificateModeDefault: "auto" | "manual";
  certificatePathDefault: string;
  certificateKeyPathDefault: string;
  certificateReady: boolean;
  certificateServerName: string;
  theme: "light" | "dark";
  language: "zh-CN" | "en";
}>();

const emit = defineEmits<{
  close: [];
  submit: [payload: Record<string, unknown>];
}>();
const tr = (chinese: string, english: string) => props.language === "en" ? english : chinese;

const protocols: ProtocolOption[] = [
  {
    id: "vless_reality",
    name: "XTLS+Reality",
    description: "无需域名证书，适合作为 VPS 主节点。",
    transport: "TCP / RAW",
    security: "REALITY",
    network: "TCP",
    defaultPort: 443,
    defaultListen: "0.0.0.0"
  },
  {
    id: "hysteria2", name: "Hysteria2",
    description: "基于 QUIC，适合高延迟或不稳定网络。", transport: "QUIC",
    security: "TLS", network: "UDP", defaultPort: 443, defaultListen: "0.0.0.0",
    requiresCertificateDomain: true
  },
  {
    id: "tuic", name: "TUIC",
    description: "低延迟 QUIC 入站，使用 UUID 与密码认证。", transport: "QUIC / cubic",
    security: "TLS", network: "UDP", defaultPort: 443, defaultListen: "0.0.0.0",
    requiresCertificateDomain: true
  },
  {
    id: "trojan_tls", name: "Trojan",
    description: "使用密码认证的标准 TLS 入站。", transport: "TCP",
    security: "TLS", network: "TCP", defaultPort: 443, defaultListen: "0.0.0.0",
    requiresCertificateDomain: true
  },
  {
    id: "vless_grpc_reality", name: "gRPC+Reality",
    description: "VLESS 经 gRPC 传输并使用 Reality 握手。", transport: "gRPC",
    security: "REALITY", network: "TCP", defaultPort: 443, defaultListen: "0.0.0.0"
  },
  {
    id: "anytls", name: "AnyTLS",
    description: "使用 AnyTLS 多路复用与标准 TLS 证书。", transport: "AnyTLS",
    security: "TLS", network: "TCP", defaultPort: 443, defaultListen: "0.0.0.0",
    requiresCertificateDomain: true
  },
  {
    id: "anytls_reality", name: "AnyTLS+Reality",
    description: "AnyTLS 入站使用 Reality，免配置域名证书。", transport: "AnyTLS",
    security: "REALITY", network: "TCP", defaultPort: 443, defaultListen: "0.0.0.0"
  },
  {
    id: "naive", name: "Naive",
    description: "基于浏览器网络栈特征的 HTTPS 代理。", transport: "HTTPS",
    security: "TLS", network: "TCP", defaultPort: 443, defaultListen: "0.0.0.0",
    requiresCertificateDomain: true
  },
  {
    id: "vless_ws_tls",
    name: "VLESS-WS",
    description: "WebSocket 传输，可配合 HTTPS 反向代理。",
    transport: "WebSocket",
    security: "TLS",
    network: "TCP",
    defaultPort: 443,
    defaultListen: "0.0.0.0",
    requiresCertificateDomain: true,
    requiresWebSocketIngress: true
  },
  {
    id: "vless_argo",
    name: "Argo",
    description: "本机 WebSocket 入站，通过 cloudflared Tunnel 的公开域名连接。",
    transport: "WebSocket",
    security: "Argo Edge TLS",
    network: "TCP",
    defaultPort: 2080,
    defaultListen: "127.0.0.1",
    requiresCloudflareTunnel: true
  }
];

const form = reactive({
  name: props.node?.name ?? "",
  protocol: props.node?.protocol ?? "",
  listen: props.node?.listen ?? "0.0.0.0",
  port: props.node?.port ?? props.nextPort,
  enabled: props.node?.enabled ?? true,
  publicHostOverride: props.node?.publicHostOverride ?? "",
  serverName: String(props.node?.settings.server_name ?? defaultRealityTarget),
  certificateMode: String(props.node?.settings.certificate_mode ?? (
    props.node?.settings.certificate_path ? "manual" : props.certificateModeDefault
  )),
  certificatePath: String(props.node?.settings.certificate_path ?? props.certificatePathDefault),
  keyPath: String(props.node?.settings.key_path ?? props.certificateKeyPathDefault),
  wsPath: String(props.node?.settings.ws_path ?? "/jui"),
  serviceName: String(props.node?.settings.service_name ?? "jui-grpc"),
  handshakeServer: String(props.node?.settings.handshake_server ?? defaultRealityTarget),
  handshakePort: Number(props.node?.settings.handshake_port ?? 443),
  credentialUuid: "",
  credentialUsername: "",
  credentialPassword: "",
  outboundId: props.node?.outboundId ? String(props.node.outboundId) : ""
});

const protocolConfirmed = ref(props.node !== null);
const automaticEditing = ref(false);
const credentialVisible = ref(false);
const nameManuallyEdited = ref(false);
const realitySniAutomatic = ref(
  String(form.serverName).trim() === String(form.handshakeServer).trim()
);

const selectedProtocol = computed(() =>
  protocols.find(protocol => protocol.id === form.protocol) ?? null
);
const protocolDescription = computed(() => {
  const protocol = selectedProtocol.value;
  if (!protocol || props.language !== "en") return protocol?.description ?? "";
  return ({
    vless_reality: "No domain certificate required; ideal as a primary VPS node.",
    hysteria2: "QUIC-based and suitable for high-latency or unstable networks.",
    tuic: "Low-latency QUIC inbound using UUID and password authentication.",
    trojan_tls: "Standard TLS inbound using password authentication.",
    vless_grpc_reality: "VLESS over gRPC with a Reality handshake.",
    anytls: "AnyTLS multiplexing with a standard TLS certificate.",
    anytls_reality: "AnyTLS inbound with Reality and no domain certificate.",
    naive: "HTTPS proxy using browser-like network behavior.",
    vless_ws_tls: "WebSocket transport suitable for HTTPS reverse proxies.",
    vless_argo: "Local WebSocket inbound exposed through a cloudflared Tunnel domain."
  } as Record<string, string>)[protocol.id] ?? protocol.description;
});
const usesReality = computed(() =>
  ["vless_reality", "vless_grpc_reality", "anytls_reality"].includes(form.protocol)
);
const needsCertificate = computed(() =>
  !usesReality.value && form.protocol !== "vless_argo"
);
const usesUuidCredential = computed(() =>
  ["vless_reality", "tuic", "vless_grpc_reality", "vless_ws_tls", "vless_argo"].includes(form.protocol)
);
const usesUsernameCredential = computed(() => form.protocol === "naive");
const usesPasswordCredential = computed(() =>
  ["hysteria2", "tuic", "trojan_tls", "anytls", "anytls_reality", "naive"].includes(form.protocol)
);
const hasServerDomain = computed(() => props.mockMode || props.certificateReady ||
  (props.httpsIngressEnabled && isDomainName(props.httpsIngressDomain)) || isDomainName(props.publicHost));
const certificateExpiresAt = computed(() => {
  const value = props.node?.settings.certificate_not_after;
  if (typeof value !== "string" || !value) return "";
  return new Date(value).toLocaleString();
});
const credentialDescription = computed(() => {
  switch (form.protocol) {
    case "vless_reality":
    case "vless_grpc_reality":
    case "vless_ws_tls":
    case "vless_argo":
      return tr("自动生成 UUID", "UUID generated automatically");
    case "tuic":
      return tr("自动生成 UUID 与密码", "UUID and password generated automatically");
    case "naive":
      return tr("自动生成用户名与密码", "Username and password generated automatically");
    default:
      return tr("自动生成强密码", "Strong password generated automatically");
  }
});
const requiredConfigComplete = computed(() => {
  if (usesReality.value) {
    return form.handshakeServer.trim() !== "" && form.handshakePort >= 1 && form.handshakePort <= 65535;
  }
  if (form.protocol === "vless_argo" || needsCertificate.value) {
    return form.serverName.trim() !== "";
  }
  return false;
});

function isDomainName(value: string): boolean {
  const configured = value.trim().replace(/^\[|\]$/g, "");
  return /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(configured) &&
    !configured.toLowerCase().endsWith(".jui.test");
}

function isIPv4Address(value: string): boolean {
  const octets = value.split(".");
  return octets.length === 4 && octets.every(octet => {
    if (!/^\d{1,3}$/.test(octet)) return false;
    const number = Number(octet);
    return number >= 0 && number <= 255 && String(number) === String(Number(octet));
  });
}

function certificateHost(): string {
  if (form.protocol === "vless_argo" && props.cloudflareTunnelEnabled &&
    (props.mockMode || isDomainName(props.cloudflareTunnelDomain)) && props.cloudflareTunnelDomain.trim()) {
    return props.cloudflareTunnelDomain.trim().toLowerCase();
  }
  const configured = props.publicHost.trim().replace(/^\[|\]$/g, "");
  if (form.protocol === "naive" && configured) {
    return configured;
  }
  if (props.httpsIngressEnabled &&
    (props.mockMode || isDomainName(props.httpsIngressDomain)) && props.httpsIngressDomain.trim()) {
    return props.httpsIngressDomain.trim().toLowerCase();
  }
  if (props.certificateReady && props.certificateServerName.trim()) {
    return props.certificateServerName.trim();
  }
  if (isDomainName(configured)) {
    return configured;
  }
  const host = props.hostName.trim().toLowerCase().replace(/[^a-z0-9-]+/g, "-").replace(/^-|-$/g, "");
  return `${host || "j-ui"}.jui.test`;
}

function protocolUnavailableReason(protocol: ProtocolOption): string {
  if (props.mockMode) {
    return "";
  }
  if (protocol.requiresCloudflareTunnel && (
    !props.cloudflareTunnelEnabled || !isDomainName(props.cloudflareTunnelDomain)
  )) {
    return tr("需要先在系统设置中配置 Cloudflare Tunnel", "Configure Cloudflare Tunnel in System Settings first");
  }
  if (protocol.requiresWebSocketIngress && !props.httpsIngressEnabled) {
    return tr("需要先在系统设置中验证 HTTPS 入口", "Verify HTTPS ingress in System Settings first");
  }
  if (protocol.id === "vless_ws_tls" && !nextWebSocketPort()) {
    return tr("支持的 Cloudflare HTTPS 端口已被占用", "All supported Cloudflare HTTPS ports are already in use");
  }
  if (protocol.requiresCertificateDomain && !hasServerDomain.value) {
    return tr("需要先配置可用于 TLS 证书的服务器域名", "Configure a server domain suitable for a TLS certificate first");
  }
  return "";
}

const orderedProtocols = computed(() => protocols
  .map((protocol, index) => ({
    protocol,
    index,
    unavailable: Boolean(protocolUnavailableReason(protocol))
  }))
  .sort((left, right) => Number(left.unavailable) - Number(right.unavailable) || left.index - right.index)
  .map(item => item.protocol)
);
const protocolDropdownOptions = computed(() => orderedProtocols.value.map(protocol => {
  const reason = protocolUnavailableReason(protocol);
  return {
    value: protocol.id,
    label: `${protocol.name}${reason ? props.language === "en" ? ` (${reason})` : `（${reason}）` : ""}`,
    disabled: Boolean(reason)
  };
}));
const certificateModeOptions = computed(() => [
  { value: "auto", label: tr("自动配置", "Automatic") }, { value: "manual", label: tr("手动指定", "Manual") }
]);

function generatedNodeName(): string {
  return `${props.hostName.trim() || "J-UI"}丨${selectedProtocol.value?.name ?? tr("节点", "Node")}_${form.port}`;
}

function nextWebSocketPort(): number {
  const supported = [8443, 2053, 2083, 2087, 2096, 443];
  return supported.find(port => !props.usedPorts.includes(port) || props.node?.port === port) ?? 0;
}

function randomHex(byteLength: number): string {
  const bytes = crypto.getRandomValues(new Uint8Array(byteLength));
  return [...bytes].map(value => value.toString(16).padStart(2, "0")).join("");
}

function generatedUuid(): string {
  if (typeof crypto.randomUUID === "function") return crypto.randomUUID();
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = [...bytes].map(value => value.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function prepareCredential() {
  form.credentialUuid = usesUuidCredential.value ? generatedUuid() : "";
  form.credentialUsername = usesUsernameCredential.value ? `jui-${randomHex(4)}` : "";
  form.credentialPassword = usesPasswordCredential.value ? randomHex(16) : "";
}

function confirmProtocol() {
  const protocol = selectedProtocol.value;
  if (!protocol || props.node || protocolUnavailableReason(protocol)) return;
  nameManuallyEdited.value = false;
  form.protocol = protocol.id;
  form.port = protocol.id === "vless_argo" && props.cloudflareTunnelOriginPort
    ? props.cloudflareTunnelOriginPort
    : protocol.id === "vless_ws_tls"
      ? nextWebSocketPort()
      : props.nextPort || protocol.defaultPort;
  form.listen = protocol.defaultListen;
  form.name = generatedNodeName();
  form.handshakeServer = defaultRealityTarget;
  form.handshakePort = 443;
  form.wsPath = protocol.id === "vless_argo" ? "/jui-argo" : "/jui";
  form.serviceName = "jui-grpc";
  form.certificateMode = props.certificateModeDefault;
  const naiveIPv4Certificate = protocol.id === "naive" && form.certificateMode === "auto" &&
    isIPv4Address(props.publicHost.trim());
  form.certificatePath = naiveIPv4Certificate
    ? `/etc/letsencrypt/live/${props.publicHost.trim()}/fullchain.pem`
    : props.certificatePathDefault;
  form.keyPath = naiveIPv4Certificate
    ? `/etc/letsencrypt/live/${props.publicHost.trim()}/privkey.pem`
    : props.certificateKeyPathDefault;
  form.serverName = usesReality.value ? defaultRealityTarget : certificateHost();
  form.publicHostOverride = ["vless_ws_tls", "vless_argo"].includes(protocol.id)
    ? form.serverName
    : "";
  realitySniAutomatic.value = usesReality.value;
  prepareCredential();
  automaticEditing.value = false;
  credentialVisible.value = false;
  protocolConfirmed.value = true;
}

function chooseAgain() {
  form.protocol = "";
  automaticEditing.value = false;
  credentialVisible.value = false;
  nameManuallyEdited.value = false;
  protocolConfirmed.value = false;
}

function toggleAutomaticEditing() {
  automaticEditing.value = !automaticEditing.value;
}

function markNameEdited() {
  nameManuallyEdited.value = form.name !== generatedNodeName();
}

function markServerNameEdited() {
  realitySniAutomatic.value = form.serverName.trim() === form.handshakeServer.trim();
}

watch(() => form.port, () => {
  if (protocolConfirmed.value && !props.node && !nameManuallyEdited.value) {
    form.name = generatedNodeName();
  }
});

watch(() => form.handshakeServer, value => {
  if (usesReality.value && realitySniAutomatic.value) form.serverName = value;
});

function submit() {
  if (!protocolConfirmed.value || !selectedProtocol.value) return;
  const settings: Record<string, unknown> = {};
  if (usesReality.value) {
    settings.handshake_server = form.handshakeServer.trim();
    settings.handshake_port = Number(form.handshakePort);
    settings.server_name = form.serverName.trim();
    if (form.protocol === "vless_grpc_reality") settings.service_name = form.serviceName.trim();
  } else if (form.protocol === "vless_argo") {
    settings.server_name = form.serverName.trim();
    settings.ws_path = form.wsPath.trim();
  } else if (needsCertificate.value) {
    settings.server_name = form.serverName.trim();
    settings.certificate_mode = form.certificateMode;
    if (form.certificateMode === "manual") {
      settings.certificate_path = form.certificatePath.trim();
      settings.key_path = form.keyPath.trim();
    }
    if (form.protocol === "vless_ws_tls") settings.ws_path = form.wsPath.trim();
  }

  const payload: Record<string, unknown> = {
    name: form.name.trim(),
    listen: form.listen.trim(),
    port: Number(form.port),
    enabled: form.enabled,
    publicHostOverride: form.protocol === "vless_argo"
      ? form.serverName.trim()
      : form.publicHostOverride.trim(),
    settings,
    outboundId: form.outboundId ? Number(form.outboundId) : null
  };
  if (!props.node) {
    payload.protocol = form.protocol;
    payload.credential = {
      ...(usesUuidCredential.value ? { uuid: form.credentialUuid.trim() } : {}),
      ...(usesUsernameCredential.value ? { username: form.credentialUsername.trim() } : {}),
      ...(usesPasswordCredential.value ? { password: form.credentialPassword } : {})
    };
  }
  emit("submit", payload);
}

</script>

<template>
  <div class="node-form-backdrop" :class="`theme-${theme}`" @click.self="emit('close')">
    <form class="node-form" @submit.prevent="submit">
      <div class="node-form-head">
        <div>
          <h2>{{ node ? tr("编辑节点", "Edit Node") : tr("自定义节点", "Custom Node") }}</h2>
          <p>{{ protocolConfirmed ? tr("系统已生成推荐配置，可在部署前逐项修改。", "Recommended settings have been generated and can be adjusted before deployment.") : tr("选择一个入站协议，系统将自动填写推荐配置。", "Choose an inbound protocol and the system will fill in recommended settings.") }}</p>
        </div>
        <button class="close-button" type="button" :aria-label="tr('关闭', 'Close')" @click="emit('close')">×</button>
      </div>

      <div v-if="!protocolConfirmed" class="node-form-layout selection-only">
        <div class="node-form-main">
          <section class="config-section">
            <div class="section-title"><div><h3>{{ tr("入站协议", "Inbound Protocol") }}</h3><p>{{ tr("选择客户端使用的连接方案", "Choose the connection profile used by clients") }}</p></div></div>
            <label class="protocol-select-label">{{ tr("节点协议", "Node Protocol") }}
              <div class="protocol-selection-control">
                <DropdownField v-model="form.protocol" :options="protocolDropdownOptions" :theme="theme" :language="language" menu-id="node-protocol-menu" :placeholder="tr('请选择入站协议', 'Select an inbound protocol')" required :trigger-label="tr('节点协议', 'node protocol')" />
                <button class="protocol-confirm-button" type="button" :disabled="!selectedProtocol || Boolean(protocolUnavailableReason(selectedProtocol))" @click="confirmProtocol">{{ tr("确定", "Confirm") }}</button>
              </div>
            </label>
            <p v-if="selectedProtocol" class="protocol-description">{{ protocolDescription }}</p>
            <div class="protocol-availability-note">
              <p v-if="mockMode">{{ tr("当前为测试模式，证书协议默认使用自动生成的 .jui.test 假域名和自签名证书。", "Test mode uses generated .jui.test domains and self-signed certificates for certificate-based protocols.") }}</p>
              <p v-else-if="!hasServerDomain">{{ tr("当前没有可用服务器域名，需要 TLS 证书的协议已禁用。", "No server domain is available, so protocols requiring TLS certificates are disabled.") }}</p>
              <template v-if="!mockMode">
                <p>{{ tr("VLESS-WS 使用 Cloudflare 支持的 HTTPS 端口，优先自动分配 8443，不参与普通节点端口顺延。", "VLESS-WS uses a Cloudflare-supported HTTPS port, preferring 8443, and does not follow the regular sequential node ports.") }}</p>
                <p>{{ tr("Argo 需要已验证的 cloudflared Tunnel；请在 VPS 运行 j-ui，并从管理菜单部署或重新配置。", "Argo requires a verified cloudflared Tunnel. Run j-ui on the VPS and deploy or reconfigure it from the management menu.") }}</p>
              </template>
            </div>
          </section>
        </div>
      </div>

      <div v-else class="node-form-layout">
        <div class="node-form-main">
          <section class="config-section advanced-section">
            <div class="section-title advanced-title">
              <div><h3>{{ tr("高级配置", "Advanced Settings") }}</h3><p>{{ tr("系统已按", "Recommended settings for") }} {{ selectedProtocol?.name }} {{ tr("自动填写", "have been filled in automatically") }}</p></div>
              <button v-if="!node" class="change-protocol-button" type="button" @click="chooseAgain">{{ tr("重新选择协议", "Choose Again") }}</button>
            </div>

            <section class="config-group automatic-config-group">
              <div class="config-group-head">
                <div><h4>{{ tr("自动配置项", "Automatic Settings") }}</h4><p>{{ tr("系统已采用推荐值；默认锁定，通常无需修改", "Recommended values are locked by default and usually need no changes") }}</p></div>
                <div class="automatic-actions">
                  <button v-if="!node" class="credential-visibility-button" type="button" @click="credentialVisible = !credentialVisible">
                    {{ credentialVisible ? tr("隐藏凭据", "Hide Credentials") : tr("显示凭据", "Show Credentials") }}
                  </button>
                  <button class="automatic-edit-button" type="button" @click="toggleAutomaticEditing">
                    {{ automaticEditing ? tr("完成修改", "Finish Editing") : tr("修改", "Edit") }}
                  </button>
                </div>
              </div>
              <div class="field-grid">
                <label class="field-wide">{{ tr("节点名称", "Node Name") }}
                  <input v-model="form.name" :disabled="!automaticEditing" required @input="markNameEdited">
                  <small>{{ tr("默认格式：主机名丨协议名称_端口", "Default: Host丨Protocol_Port") }}</small>
                </label>
                <label>{{ tr("监听地址", "Listen Address") }}
                  <input v-model="form.listen" :disabled="!automaticEditing" required>
                  <small>{{ tr("`0.0.0.0` 表示监听全部 IPv4 地址", "`0.0.0.0` listens on all IPv4 addresses") }}</small>
                </label>
                <label>{{ tr("监听端口", "Listen Port") }}
                  <input v-model.number="form.port" :disabled="!automaticEditing" type="number" min="1" max="65535" required>
                  <small>{{ selectedProtocol?.network }} {{ tr("端口自动顺延，修改后同步节点名称", "ports increment automatically; changes also update the node name") }}</small>
                </label>
                <label v-if="usesReality" class="field-wide">Server Name / SNI
                  <input v-model="form.serverName" :disabled="!automaticEditing" required @input="markServerNameEdited">
                  <small>{{ tr("系统默认与 Reality 目标匹配", "Matches the Reality target by default") }}</small>
                </label>
                <template v-if="!node">
                  <label v-if="usesUuidCredential" :class="{ 'field-wide': !usesPasswordCredential }">UUID
                    <input v-model="form.credentialUuid" :disabled="!automaticEditing" :type="credentialVisible ? 'text' : 'password'" required spellcheck="false" autocomplete="off">
                    <small>{{ tr("已在本机安全生成，部署时加密保存", "Generated locally and stored encrypted during deployment") }}</small>
                  </label>
                  <label v-if="usesUsernameCredential">{{ tr("账号", "Username") }}
                    <input v-model="form.credentialUsername" :disabled="!automaticEditing" required autocomplete="off">
                  </label>
                  <label v-if="usesPasswordCredential">{{ tr("密码", "Password") }}
                    <input v-model="form.credentialPassword" :disabled="!automaticEditing" :type="credentialVisible ? 'text' : 'password'" required autocomplete="new-password">
                    <small>{{ tr("默认遮罩显示，不会写入日志或节点响应", "Masked by default and never written to logs or node responses") }}</small>
                  </label>
                </template>
              </div>
              <div class="automatic-values">
                <div><span>{{ tr("传输与安全", "Transport & Security") }}</span><strong>{{ selectedProtocol?.transport }} · {{ selectedProtocol?.security }}</strong></div>
                <div v-if="node"><span>{{ tr("账号凭据", "Credentials") }}</span><strong>{{ credentialDescription }}</strong><small>{{ tr("已加密保存，可通过客户端凭据单独重置", "Stored encrypted and resettable per client") }}</small></div>
                <div v-if="usesReality"><span>{{ tr("Reality 密钥", "Reality Keys") }}</span><strong>{{ tr("自动生成 X25519 与 Short ID", "X25519 and Short ID generated automatically") }}</strong></div>
                <div v-else-if="needsCertificate"><span>{{ tr("TLS 证书", "TLS Certificate") }}</span><strong>{{ form.certificateMode === "auto" ? tr("自动查找或签发", "Find or issue automatically") : tr("使用手动证书", "Use manual certificate") }}</strong></div>
              </div>
            </section>

            <section class="config-group required-config-group">
              <div class="config-group-head">
                <div><h4>{{ tr("必要配置", "Required Settings") }}</h4><p>{{ tr("连接成立所需的目标或域名，请确认后再部署", "Confirm the target or domain required for the connection") }}</p></div>
                <span class="required-badge" :class="{ complete: requiredConfigComplete }">{{ tr("必填", "Required") }}</span>
              </div>
              <div v-if="usesReality" class="field-grid">
                <label>{{ tr("Reality 目标网站", "Reality Target") }}
                  <DropdownField v-model="form.handshakeServer" :options="realityTargets" :theme="theme" :language="language" menu-id="node-reality-target-menu" editable required :menu-note="tr('也可以直接输入其他目标域名', 'You may also enter another target domain')" :trigger-label="tr('常用 Reality 目标', 'common Reality targets')" />
                  <small>{{ tr("用于 Reality 握手伪装，不要包含协议或路径", "Used for the Reality handshake; do not include a scheme or path") }}</small>
                </label>
                <label>{{ tr("目标端口", "Target Port") }}
                  <input v-model.number="form.handshakePort" type="number" min="1" max="65535" required>
                  <small>{{ tr("通常使用目标网站的 HTTPS 端口 443", "Usually the target site's HTTPS port 443") }}</small>
                </label>
              </div>
              <div v-else-if="form.protocol === 'vless_argo'" class="field-grid">
                <label class="field-wide">{{ tr("Cloudflare 域名 / SNI", "Cloudflare Domain / SNI") }}
                  <input v-model="form.serverName" required>
                  <small>{{ tr("测试环境提供假域名；正式环境必须填写已接入 Tunnel 的域名", "Test mode provides a demo domain; production requires a domain connected to the Tunnel") }}</small>
                </label>
              </div>
              <div v-else-if="needsCertificate" class="field-grid">
                <label class="field-wide">{{ tr("证书域名 / SNI", "Certificate Domain / SNI") }}
                  <input v-model="form.serverName" required>
                  <small>{{ tr("默认使用系统公网域名；正式部署时必须与证书匹配", "Uses the system public domain by default and must match the production certificate") }}</small>
                </label>
              </div>
            </section>

            <section class="config-group optional-config-group">
              <div class="config-group-head">
                <div><h4>{{ tr("可选项目", "Optional Settings") }}</h4><p>{{ tr("不填写也能使用，仅在特殊网络或自定义场景下调整", "Adjust only for special networks or custom scenarios") }}</p></div>
                <span class="optional-badge">{{ tr("可选", "Optional") }}</span>
              </div>
              <div class="field-grid optional-fields">
                <label v-if="form.protocol !== 'vless_argo'" class="field-wide">{{ tr("导出连接地址覆盖", "Export Address Override") }}
                  <input v-model="form.publicHostOverride" placeholder="edge.example.com">
                  <small>{{ tr("只替换订阅中的连接域名或 IP，不会自动配置 CDN、隧道或转发", "Only replaces the domain or IP in subscriptions; it does not configure a CDN, tunnel, or forwarding") }}</small>
                </label>
                <label v-if="form.protocol === 'vless_grpc_reality'" class="field-wide">gRPC Service Name
                  <input v-model="form.serviceName" required>
                </label>
                <label v-if="form.protocol === 'vless_argo' || form.protocol === 'vless_ws_tls'" class="field-wide">{{ tr("WebSocket 路径", "WebSocket Path") }}
                  <input v-model="form.wsPath" pattern="/.*" required>
                </label>
                <template v-if="needsCertificate">
                  <label class="field-wide">{{ tr("证书方式", "Certificate Mode") }}
                    <DropdownField v-model="form.certificateMode" :options="certificateModeOptions" :theme="theme" :language="language" menu-id="certificate-mode-menu" :trigger-label="tr('证书方式', 'certificate mode')" />
                    <small>{{ tr("本机测试生成自签名证书；正式环境优先使用当前域名证书", "Local tests use a self-signed certificate; production prefers the current domain certificate") }}</small>
                  </label>
                  <template v-if="form.certificateMode === 'manual'">
                    <label>{{ tr("证书绝对路径", "Absolute Certificate Path") }}
                      <input v-model="form.certificatePath" pattern="/.*" required>
                    </label>
                    <label>{{ tr("私钥绝对路径", "Absolute Private Key Path") }}
                      <input v-model="form.keyPath" pattern="/.*" required>
                    </label>
                  </template>
                  <div class="generated-note field-wide"><b>{{ tr("证书", "Certificate") }}</b><span>{{ form.certificateMode === 'auto' ? tr('部署时自动查找或生成测试证书。', 'A certificate is found automatically, or a test certificate is generated during deployment.') : tr('部署时校验证书域名、有效期与私钥权限。', 'The certificate domain, expiry, and private-key permissions are checked during deployment.') }}{{ certificateExpiresAt ? ` ${tr('当前证书到期', 'Current certificate expires')}：${certificateExpiresAt}` : '' }}</span></div>
                </template>
              </div>

            </section>
          </section>
        </div>
      </div>

      <div class="node-form-foot">
        <p v-if="error" class="form-error">{{ error }}</p>
        <div>
          <button class="cancel-button" type="button" @click="emit('close')">{{ tr("取消", "Cancel") }}</button>
          <button v-if="protocolConfirmed" class="deploy-button" type="submit" :disabled="submitting">
            {{ submitting ? tr("正在验证…", "Validating…") : node ? tr("验证并保存", "Validate & Save") : tr("验证并部署", "Validate & Deploy") }}
          </button>
        </div>
      </div>
    </form>
  </div>
</template>

<style scoped>
.node-form-backdrop {
  position: fixed;
  inset: 0;
  z-index: 30;
  overflow-y: auto;
  padding: 32px;
  background: rgba(2, 8, 16, .88);
  backdrop-filter: blur(10px);
}
.node-form {
  width: min(940px, 100%);
  margin: auto;
  /* Dropdown menus must be able to extend beyond the form when the
     protocol picker is near the bottom edge of the modal. The backdrop
     remains the scroll boundary, so the form itself does not need clipping. */
  overflow: visible;
  color: #dbe7f5;
  border: 1px solid #1e3b53;
  border-radius: 18px;
  background: #081522;
  box-shadow: 0 30px 100px rgba(0, 0, 0, .48);
}
.node-form-head {
  display: flex;
  min-height: 128px;
  align-items: flex-start;
  justify-content: space-between;
  padding: 30px 36px;
  border-bottom: 1px solid #183149;
  background: linear-gradient(120deg, #0d2637, #0a1928);
  border-radius: 17px 17px 0 0;
}
.node-form-head h2 { margin: 7px 0; color: #f8fafc; font-size: 30px; }
.node-form-head > div > p:last-child { margin: 0; color: #7690a5; font-size: 13px; }
.close-button {
  width: 38px;
  height: 38px;
  color: #89a1b6;
  border: 0;
  border-radius: 9px;
  background: #0a1b2a;
  font-size: 24px;
}
.node-form-layout { display: grid; grid-template-columns: 1fr; }
.node-form-layout.selection-only { grid-template-columns: 1fr; }
.selection-only .node-form-main { min-height: 250px; }
.node-form-main { padding: 8px 36px 36px; }
.config-section { padding: 30px 0; border-bottom: 1px solid #173047; }
.config-section:last-child { border-bottom: 0; }
.section-title { display: flex; align-items: flex-start; justify-content: space-between; gap: 18px; margin-bottom: 22px; }
.section-title h3 { margin: 0; color: #eef7ff; font-size: 18px; }
.section-title p { margin: 5px 0 0; color: #668096; font-size: 12px; }
.protocol-select-label { display: grid; gap: 8px; color: #8299ad; font-size: 12px; font-weight: 700; }
.protocol-select-label .dropdown-field { min-height: 46px; font-size: 14px; }
.protocol-selection-control { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 9px; align-items: center; }
.protocol-confirm-button, .change-protocol-button {
  min-width: 72px;
  min-height: 42px;
  padding: 0 14px;
  color: #5eead4;
  border: 0;
  border-radius: 8px;
  background: #0c302f;
  font-size: 12px;
  font-weight: 750;
}
.protocol-confirm-button:disabled { cursor: not-allowed; opacity: .45; }
.change-protocol-button { min-height: 34px; color: #8da4b7; background: transparent; }
.protocol-description { margin: 13px 0 0; color: #6f879a; font-size: 12px; }
.protocol-availability-note {
  display: grid;
  gap: 5px;
  margin-top: 16px;
  padding: 12px 14px;
  color: #7891a6;
  border: 1px solid #234653;
  border-radius: 9px;
  background: #0a252d;
  font-size: 11px;
}
.protocol-availability-note p { margin: 0; }
.field-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0 16px; }
.field-grid label { margin: 8px 0 15px; }
.field-grid label > small {
  color: #577187;
  font-size: 10px;
  line-height: 1.45;
}
.field-grid label em { color: #577187; font-size: 10px; font-style: normal; }
.field-wide { grid-column: 1 / -1; }
.config-group {
  margin-top: 18px;
  padding: 20px;
  border: 1px solid #1d3850;
  border-radius: 13px;
  background: #091827;
}
.config-group + .config-group { margin-top: 16px; }
.config-group-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 18px;
  margin-bottom: 13px;
}
.config-group-head h4 { margin: 0; color: #e5f1f9; font-size: 15px; }
.config-group-head p { margin: 5px 0 0; color: #668096; font-size: 11px; }
.automatic-actions { display: flex; gap: 7px; }
.automatic-edit-button, .credential-visibility-button {
  min-width: 72px;
  padding: 7px 13px;
  color: #5eead4;
  border: 0;
  border-radius: 7px;
  background: #0c302f;
  font-size: 11px;
  font-weight: 750;
}
.credential-visibility-button { color: #93c5fd; background: #102b46; }
.required-badge, .optional-badge {
  padding: 5px 8px;
  border-radius: 999px;
  font-size: 9px;
  font-weight: 800;
  white-space: nowrap;
}
.required-badge { color: #fda4af; background: #3b1721; }
.required-badge.complete { color: #047857; background: #d1fae5; }
.optional-badge { color: #93c5fd; background: #102b46; }
.automatic-config-group input:disabled {
  color: #8ba0b2;
  border-color: #1b3348;
  background: #071522;
  cursor: not-allowed;
  opacity: .82;
}
.automatic-values {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 10px;
  margin-top: 2px;
}
.automatic-values > div {
  display: grid;
  align-content: center;
  gap: 5px;
  min-height: 68px;
  padding: 12px 14px;
  border: 1px solid #1f3a50;
  border-radius: 9px;
  background: #071522;
}
.automatic-values span { color: #60798e; font-size: 9px; text-transform: uppercase; }
.automatic-values strong { color: #dceaf4; font-size: 12px; }
.automatic-values small { color: #577187; font-size: 9px; }
.optional-fields { margin-bottom: 3px; }
.generated-note, .inline-notice {
  padding: 13px 15px;
  color: #7891a6;
  border: 1px solid #234653;
  border-radius: 9px;
  background: #0a252d;
  font-size: 11px;
  line-height: 1.55;
}
.generated-note { display: flex; gap: 10px; }
.generated-note b { color: #5eead4; white-space: nowrap; }
.node-form-foot {
  display: flex;
  min-height: 84px;
  align-items: center;
  justify-content: space-between;
  gap: 20px;
  padding: 18px 30px;
  border-top: 1px solid #183149;
  background: #08131f;
  border-radius: 0 0 17px 17px;
}
.node-form-foot > div { display: flex; gap: 10px; margin-left: auto; }
.cancel-button, .deploy-button { padding: 11px 19px; border-radius: 8px; font-weight: 750; }
.cancel-button { color: #8da4b7; border: 0; background: transparent; }
.deploy-button { min-width: 142px; color: #05221f; border: 0; background: #5eead4; }
.deploy-button:disabled { cursor: wait; opacity: .58; }
.form-error { margin: 0; color: #fecdd3; font-size: 12px; }
@media (max-width: 900px) {
  .node-form-backdrop { padding: 14px; }
}
@media (max-width: 600px) {
  .node-form-head, .node-form-main { padding-right: 20px; padding-left: 20px; }
  .node-form-backdrop { padding: 0; }
  .node-form { border-radius: 0; }
  .node-form-head, .node-form-foot { border-radius: 0; }
  .field-grid { grid-template-columns: 1fr; }
  .automatic-values { grid-template-columns: 1fr; }
  .config-group-head { align-items: stretch; flex-direction: column; }
  .automatic-actions { justify-content: flex-end; }
  .field-wide { grid-column: auto; }
  .node-form-foot { align-items: stretch; flex-direction: column; }
  .node-form-foot > div { width: 100%; margin-left: 0; }
  .cancel-button, .deploy-button { flex: 1; }
}

/* KUI-inspired light glass treatment; layout and protocol behavior stay unchanged. */
.node-form-backdrop { background: rgba(30, 41, 59, .42); }
.node-form {
  color: #475569;
  border-color: rgba(255, 255, 255, .92);
  background: rgba(255, 255, 255, .9);
  box-shadow: 0 30px 100px rgba(71, 85, 105, .25);
  backdrop-filter: blur(22px);
}
.node-form-head {
  border-bottom-color: #e8edf4;
  background: linear-gradient(120deg, rgba(255,255,255,.95), rgba(238,242,255,.9));
}
.node-form-head h2, .section-title h3 { color: #1e293b; }
.node-form-head > div > p:last-child, .section-title p, .protocol-description,
.field-grid label > small, .field-grid label em { color: #94a3b8; }
.close-button, .cancel-button {
  color: #64748b; background: rgba(255,255,255,.72);
}
.config-section { border-bottom-color: #e8edf4; }
.config-group { border-color: #e2e8f0; background: rgba(248,250,252,.7); }
.config-group-head h4 { color: #334155; }
.config-group-head p { color: #94a3b8; }
.automatic-edit-button { color: #4f46e5; background: #eef2ff; }
.credential-visibility-button { color: #2563eb; background: #eff6ff; }
.required-badge { color: #be123c; background: #ffe4e6; }
.required-badge.complete { color: #047857; background: #d1fae5; }
.optional-badge { color: #2563eb; background: #dbeafe; }
.automatic-config-group input:disabled { color: #64748b; border-color: #e2e8f0; background: #f1f5f9; }
.automatic-values > div { border-color: #e2e8f0; background: rgba(255,255,255,.75); }
.automatic-values span, .automatic-values small { color: #94a3b8; }
.automatic-values strong { color: #475569; }
.protocol-confirm-button, .change-protocol-button {
  color: #4f46e5; background: #eef2ff;
}
.protocol-availability-note { color: #64748b; border-color: #c7d2fe; background: #eef2ff; }
.generated-note, .inline-notice {
  color: #64748b; border-color: #c7d2fe; background: #eef2ff;
}
.generated-note b { color: #4f46e5; }
.node-form-foot { border-top-color: #e8edf4; background: rgba(248,250,252,.9); }
.deploy-button {
  color: #fff; background: linear-gradient(90deg, #6366f1, #8b5cf6);
  box-shadow: 0 8px 18px rgba(99,102,241,.2);
}
.form-error { color: #be123c; }
.node-form-backdrop.theme-dark { background: rgba(2, 8, 16, .88); }
.theme-dark .node-form {
  color: #dbe7f5; border-color: #1e3b53; background: #081522;
  box-shadow: 0 30px 100px rgba(0, 0, 0, .48);
}
.theme-dark .node-form-head {
  border-bottom-color: #183149; background: linear-gradient(120deg, #0d2637, #0a1928);
}
.theme-dark .node-form-head h2,
.theme-dark .section-title h3 { color: #f8fafc; }
.theme-dark .node-form-head > div > p:last-child,
.theme-dark .section-title p,
.theme-dark .protocol-description,
.theme-dark .field-grid label > small,
.theme-dark .field-grid label em { color: #668096; }
.theme-dark .close-button,
.theme-dark .cancel-button {
  color: #89a1b6; background: #0a1b2a;
}
.theme-dark .config-section { border-bottom-color: #173047; }
.theme-dark .config-group { border-color: #1d3850; background: #091827; }
.theme-dark .config-group-head h4 { color: #e5f1f9; }
.theme-dark .config-group-head p { color: #668096; }
.theme-dark .automatic-edit-button { color: #5eead4; background: #0c302f; }
.theme-dark .credential-visibility-button { color: #93c5fd; background: #102b46; }
.theme-dark .required-badge { color: #fda4af; background: #3b1721; }
.theme-dark .required-badge.complete { color: #6ee7b7; background: #064e3b; }
.theme-dark .optional-badge { color: #93c5fd; background: #102b46; }
.theme-dark .automatic-config-group input:disabled { color: #8ba0b2; border-color: #1b3348; background: #071522; }
.theme-dark .automatic-values > div { border-color: #1f3a50; background: #071522; }
.theme-dark .automatic-values span,
.theme-dark .automatic-values small { color: #60798e; }
.theme-dark .automatic-values strong { color: #dceaf4; }
.theme-dark .protocol-confirm-button,
.theme-dark .change-protocol-button {
  color: #5eead4; background: #0c3036;
}
.theme-dark .protocol-availability-note { color: #7891a6; border-color: #234653; background: #0a252d; }
.theme-dark .generated-note,
.theme-dark .inline-notice {
  color: #7891a6; border-color: #234653; background: #0a252d;
}
.theme-dark .generated-note b { color: #5eead4; }
.theme-dark .node-form-foot { border-top-color: #183149; background: #08131f; }
.theme-dark .deploy-button {
  color: #05221f; background: #5eead4; box-shadow: none;
}
.theme-dark .form-error { color: #fecdd3; }
</style>
