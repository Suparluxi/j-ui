<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref, watch } from "vue";
import QrcodeVue from "qrcode.vue";
import { download, request, setCSRF, type ApiError } from "./api";
import CommonNodesModal from "./components/CommonNodesModal.vue";
import DropdownField from "./components/DropdownField.vue";
import NodeFormModal from "./components/NodeFormModal.vue";

interface Session { username: string; csrfToken: string; setupRequired: boolean; adminPath: string; defaultCredentials: boolean }
interface NodePortSettings { startPort: number; nextPort: number }
interface ProtocolPrerequisites {
  httpsIngressEnabled: boolean;
  httpsIngressDomain: string;
  httpsIngressVerifiedAt?: string;
  cloudflareTunnelEnabled: boolean;
  cloudflareTunnelDomain: string;
  cloudflareTunnelOriginPort?: number;
  cloudflareTunnelVerifiedAt?: string;
  certificateMode: "auto" | "manual";
  certificatePath?: string;
  certificateKeyPath?: string;
  certificateReady: boolean;
  certificateServerName?: string;
}
interface NodeRecord {
  id: number; name: string; protocol: string; listen: string; port: number;
  enabled: boolean; status: string; publicHostOverride?: string; settings: Record<string, unknown>;
  listenerStatus: string; publicConnectivity: string; externalAddress: string; currentOutbound: string;
  outboundId?: number;
}
interface OutboundRecord {
  id: number; name: string; type: "socks5" | "http"; server: string; port: number;
  enabled: boolean; hasCredential: boolean; status: string; observedIp?: string;
  country?: string; asn?: string; lastError?: string; lastCheckedAt?: string;
  managedKind: "manual" | "vpngate";
}
interface VPNGateExit {
  id: number; outboundId: number; slot: number; name: string; country: string;
  candidateHostName?: string; candidateIp?: string; namespace: string;
  localAddress: string; localPort: number; status: string; observedIp?: string;
  lastError?: string; failurePolicy: "block" | "auto_swap"; permanent: boolean;
  expiresAt?: string; lastCheckedAt?: string;
}
interface VPNGateRegion { code: string; name: string; nameZh?: string; count?: number; availableCount?: number }
interface VPNGateCandidate {
  hostName: string; ip: string; score: number; ping: number; speed: number;
  countryLong: string; countryShort: string; numVpnSessions: number; hasOpenVpn: boolean; fetchedAt?: string;
}
interface VPNGateInspection {
  candidateHostName: string; candidateIp: string; provider: string; checkedAt: string;
  vpngate: { score: number; pingMs: number; speedBitsPerSecond: number; numVpnSessions: number; uptimeSeconds: number; fetchedAt: string };
  lookup: {
    ip: string; country?: string; countryCode?: string; region?: string; city?: string;
    registeredCountry?: string; registeredCountryCode?: string; trustScore?: number;
    isResidential: boolean; isDatacenter: boolean; isPublicService: boolean; isMobile: boolean;
    isVpn: boolean; isProxy: boolean; isTor: boolean; isAbuser: boolean; isCrawler: boolean;
    companyType?: string; asnKind?: string; cidr?: string;
    range: { first?: string; last?: string; count?: number };
    asnIpv4Count?: number; estimatedBandwidth?: string; asnAllocated?: string; rpkiStatus?: string;
    intelligence: { threats?: { label: string; severity?: string }[]; abuserLevel?: string; abuserScoreRaw?: string; httpblThreat?: number };
    connection: { asn?: string; asName?: string; org?: string; isp?: string; companyName?: string };
  };
}
interface ResidentialNodeJob {
  id: string;
  status: "queued" | "running" | "succeeded" | "failed";
  message: string;
  createdAt: string;
  updatedAt: string;
  node?: NodeRecord;
  uri?: string;
  source?: string;
  country?: string;
  exitId?: number;
  reusedExit?: boolean;
  expiresAt?: string;
  error?: ApiError;
}
type SubscriptionFormat = "base64" | "v2rayn" | "shadowrocket" | "clash" | "singbox";
type Language = "zh-CN" | "en";
interface SubscriptionInfo {
  token: string;
  base64Path: string;
  v2rayNPath: string;
  shadowrocketPath: string;
  clashPath: string;
  singBoxPath: string;
}
interface Status {
  cpuPercent: number;
  memory: { usedBytes: number; totalBytes: number; percent: number };
  disk: { usedBytes: number; totalBytes: number; percent: number };
  network: {
    uploadBytesPerSecond: number; downloadBytesPerSecond: number;
    uploadTotalBytes: number; downloadTotalBytes: number;
  };
  uptimeSeconds: number;
  load: number[];
  services: { jui: string; singBox: string; openVPN: string; singBoxVersion: string; configVersion: number };
  nodes: { total: number; enabled: number; faulted: number };
  exits: { total: number; running: number; faulted: number };
}

const loading = ref(true);
const argoGuideUrl = "https://github.com/Suparluxi/j-ui/blob/main/docs/argo-quickstart.zh-CN.md";
const language = ref<Language>("zh-CN");
const session = ref<Session | null>(null);
const error = ref("");
const notice = ref("");
const residentialError = ref("");
const showSystemSettings = ref(false);
const showLogs = ref(false);
const showSubscriptionLinks = ref(false);
const showSubscriptionQR = ref(false);
const qrSubscriptionFormat = ref<SubscriptionFormat>("base64");
const login = reactive({ username: "", password: "" });
const serverName = ref("");
const serverNameDraft = ref("");
const countryCodeDraft = ref("");
const publicHost = ref("");
const nodeStartPort = ref(8881);
const nodeStartPortDraft = ref(8881);
const nextNodePort = ref(8881);
const protocolPrerequisites = reactive<ProtocolPrerequisites>({
  httpsIngressEnabled: false, httpsIngressDomain: "",
  cloudflareTunnelEnabled: false, cloudflareTunnelDomain: "", cloudflareTunnelOriginPort: 0,
  certificateMode: "auto", certificatePath: "", certificateKeyPath: "", certificateReady: false, certificateServerName: ""
});
const protocolPrerequisitesDraft = reactive<ProtocolPrerequisites>({
  httpsIngressEnabled: false, httpsIngressDomain: "",
  cloudflareTunnelEnabled: false, cloudflareTunnelDomain: "", cloudflareTunnelOriginPort: 0,
  certificateMode: "auto", certificatePath: "", certificateKeyPath: "", certificateReady: false, certificateServerName: ""
});
const nodes = ref<NodeRecord[]>([]);
const outbounds = ref<OutboundRecord[]>([]);
const vpnGateRegions = ref<VPNGateRegion[]>([]);
const vpnGateCandidates = ref<VPNGateCandidate[]>([]);
const vpnGateRefreshing = ref(false);
const vpnGateInspecting = ref(false);
const vpnGateInspection = ref<VPNGateInspection | null>(null);
const vpnGateInspectionCollapsed = ref(false);
const residentialCreating = ref(false);
const residentialJob = ref<ResidentialNodeJob | null>(null);
const residentialForm = reactive({
  source: "vpngate" as "vpngate" | "manual", nodeId: 0, country: "JP",
  candidateHostName: "", durationMinutes: 30,
  failurePolicy: "auto_swap" as "block" | "auto_swap",
  type: "socks5" as "socks5" | "http", server: "", port: 1080,
  username: "", password: ""
});
const status = ref<Status | null>(null);
const systemInfo = ref<Record<string, string | boolean>>({});
const subscription = ref<SubscriptionInfo | null>(null);
const copiedSubscriptionFormat = ref<SubscriptionFormat | null>(null);
const showNodeForm = ref(false);
const showCommonNodes = ref(false);
const commonNodesSubmitting = ref(false);
const commonNodesError = ref("");
const editingNodeId = ref<number | null>(null);
const nodeSubmitting = ref(false);
const logs = ref("");
const passwordForm = reactive({ currentPassword: "", newPassword: "" });
const eventsConnected = ref(false);
const eventsHealthKnown = ref(false);
const publicAddressBlurred = ref(readAddressBlurPreference());
const theme = ref<"light" | "dark">(readThemePreference());
const countdownClock = ref(Date.now());
const chineseRegionNames = new Intl.DisplayNames(["zh-CN"], { type: "region" });
const regularNodes = computed(() => nodes.value.filter(node => !temporarySource(node)));
const residentialEligibleNodes = computed(() => regularNodes.value.filter(node => node.protocol !== "vless_argo"));
const temporaryNodes = computed(() => {
  const now = countdownClock.value;
  return nodes.value.filter(node => {
    const source = temporarySource(node);
    if (!source) return false;
    if (source !== "vpngate") return true;
    const expiry = temporaryExpiryMilliseconds(node);
    return expiry === null || !Number.isFinite(expiry) || expiry > now;
  });
});
const residentialNodeOptions = computed(() => residentialEligibleNodes.value.map(node => ({
  value: node.id, label: `${node.name} · ${protocolLabel(node.protocol)} · ${node.port}`
})));
const vpnGateRegionOptions = computed(() => (vpnGateRegions.value.length ? vpnGateRegions.value : [
  { code: "JP", name: "Japan", count: 0, availableCount: 0 }
]).map(region => ({
  value: region.code,
  label: language.value === "en"
    ? `${region.code} · ${region.name} · Total ${region.count ?? 0}`
    : `${region.code} · ${region.name}${regionChineseName(region) ? `（${regionChineseName(region)}）` : ""} · 总计 ${region.count ?? 0}`
})));
const vpnGateCandidateOptions = computed(() => vpnGateCandidates.value.map(candidate => ({
  value: candidate.hostName,
  label: `${candidate.ip} · ${candidate.ping > 0 ? `${candidate.ping} ms` : tr("延迟未知", "Ping unknown")} · ${speedMbps(candidate.speed)}`
})));
const selectedVPNGateCandidate = computed(() => vpnGateCandidates.value.find(
  candidate => candidate.hostName === residentialForm.candidateHostName
));
const activeVPNGateInspection = computed(() => {
  const inspection = vpnGateInspection.value;
  const candidate = selectedVPNGateCandidate.value;
  return inspection && candidate &&
    inspection.candidateHostName === candidate.hostName && inspection.candidateIp === candidate.ip
    ? inspection : null;
});
const residentialDurationOptions = computed(() => [
  { value: 30, label: tr("30 分钟", "30 minutes") }, { value: 60, label: tr("1 小时", "1 hour") },
  { value: 120, label: tr("2 小时", "2 hours") }, { value: 360, label: tr("6 小时", "6 hours") },
  { value: 720, label: tr("12 小时", "12 hours") }, { value: 1440, label: tr("24 小时", "24 hours") },
  { value: 0, label: tr("永久", "Permanent") }
]);
const failurePolicyOptions = computed(() => [
  { value: "auto_swap", label: tr("自动更换同国家候选（推荐）", "Automatically switch within the same country (recommended)") },
  { value: "block", label: tr("故障后立即阻断", "Block on failure") }
]);
const proxyTypeOptions = [
  { value: "socks5", label: "SOCKS5" }, { value: "http", label: "HTTP CONNECT" }
];
const languageOptions = [
  { value: "zh-CN", label: "简体中文" },
  { value: "en", label: "English" }
];
const countryNamesZh: Record<string, string> = {
  AR: "阿根廷", AU: "澳大利亚", AT: "奥地利", BE: "比利时", BR: "巴西", CA: "加拿大",
  CL: "智利", CN: "中国", CO: "哥伦比亚", CZ: "捷克", DK: "丹麦", FI: "芬兰", FR: "法国",
  DE: "德国", GR: "希腊", HK: "中国香港", HU: "匈牙利", IN: "印度", ID: "印度尼西亚",
  IE: "爱尔兰", IL: "以色列", IT: "意大利", JP: "日本", KR: "韩国", MY: "马来西亚",
  MX: "墨西哥", NL: "荷兰", NZ: "新西兰", NO: "挪威", PH: "菲律宾", PL: "波兰", PT: "葡萄牙",
  RO: "罗马尼亚", RU: "俄罗斯", SG: "新加坡", SK: "斯洛伐克", ZA: "南非", ES: "西班牙",
  SE: "瑞典", CH: "瑞士", TW: "中国台湾", TH: "泰国", TR: "土耳其", UA: "乌克兰", AE: "阿联酋",
  GB: "英国", US: "美国", VN: "越南"
};
const isoCountryCodes = `AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW`.split(" ");
function flagEmoji(code: string) {
  return String.fromCodePoint(...Array.from(code, letter => 127397 + letter.charCodeAt(0)));
}

function displayDateTime(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString(language.value);
}

const countryOptions = computed(() => {
  const names = new Intl.DisplayNames([language.value], { type: "region" });
  const namesChinese = new Intl.DisplayNames(["zh-CN"], { type: "region" });
  const namesEnglish = new Intl.DisplayNames(["en"], { type: "region" });
  return isoCountryCodes.map(code => {
    const fullName = names.of(code) || (language.value === "zh-CN" ? countryNamesZh[code] : code) || code;
    return {
      value: code,
      label: `${code} · ${fullName}`,
      iconText: flagEmoji(code),
      iconAlt: flagEmoji(code),
      searchText: `${namesChinese.of(code) || ""} ${namesEnglish.of(code) || ""}`
    };
  });
});

function regionChineseName(region: VPNGateRegion) {
  const generated = chineseRegionNames.of(region.code.toUpperCase());
  return region.nameZh || countryNamesZh[region.code] || (generated !== region.code ? generated : "") || "";
}
const subscriptionProfiles = computed<Array<{
  format: SubscriptionFormat; icon: string; label: string; description: string
}>>(() => [
  { format: "base64", icon: "🔗", label: tr("普通订阅", "Standard"), description: tr("包含所有可导出的节点订阅链接", "Contains all exportable node links") },
  { format: "v2rayn", icon: "🪟", label: "v2rayN", description: tr("适用于 Windows 版 v2rayN", "For v2rayN on Windows") },
  { format: "shadowrocket", icon: "🚀", label: "Shadowrocket", description: tr("适用于 iPhone、iPad 和 macOS", "For iPhone, iPad, and macOS") },
  { format: "clash", icon: "🧷", label: "Clash", description: tr("Mihomo / Clash YAML 配置", "Mihomo / Clash YAML configuration") },
  { format: "singbox", icon: "📦", label: "sing-box", description: tr("sing-box JSON 配置", "sing-box JSON configuration") }
]);
const countryCode = computed(() => String(systemInfo.value.countryCode || "").toUpperCase());
const countryFlag = computed(() => {
  const code = countryCode.value;
  if (!/^[A-Z]{2}$/.test(code)) return "🌐";
  return flagEmoji(code);
});
const publicAddresses = computed(() => {
  const configured = publicHost.value.trim().replace(/^\[|\]$/g, "");
  let ipv4 = String(systemInfo.value.ipv4 || "");
  let ipv6 = String(systemInfo.value.ipv6 || "");
  let hostname = "";
  const ipv4Parts = configured.split(".");
  const configuredIsIPv4 = ipv4Parts.length === 4 &&
    ipv4Parts.every(part => /^\d{1,3}$/.test(part) && Number(part) <= 255);
  if (configuredIsIPv4) ipv4 = configured;
  else if (configured.includes(":")) ipv6 = configured;
  else hostname = configured;
  return [
    hostname ? { label: tr("主机", "Host"), value: hostname } : null,
    ipv4 ? { label: "IPv4", value: ipv4 } : null,
    ipv6 ? { label: "IPv6", value: ipv6 } : null
  ].filter((entry): entry is { label: string; value: string } => entry !== null);
});
let lastEventAt = 0;
let eventSource: EventSource | null = null;
let eventWatchdog: number | null = null;
let countdownTimer: number | null = null;
let noticeTimer: number | null = null;
let subscriptionCopyTimer: number | null = null;

watch(notice, value => {
  if (noticeTimer !== null) window.clearTimeout(noticeTimer);
  noticeTimer = null;
  if (!value) return;
  const currentNotice = value;
  noticeTimer = window.setTimeout(() => {
    if (notice.value === currentNotice) notice.value = "";
    noticeTimer = null;
  }, 3000);
});

applyTheme(theme.value);

function readAddressBlurPreference(): boolean {
  try {
    return window.localStorage.getItem("jui-public-address-visible") !== "true";
  } catch {
    return true;
  }
}

function readThemePreference(): "light" | "dark" {
  try {
    const saved = window.localStorage.getItem("jui-theme");
    if (saved === "light" || saved === "dark") return saved;
    return window.matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  } catch {
    return "light";
  }
}

function tr(chinese: string, english: string) {
  return language.value === "en" ? english : chinese;
}

function applyLanguage(value: Language) {
  language.value = value;
  document.documentElement.lang = value;
}

function applyTheme(mode: "light" | "dark") {
  document.documentElement.dataset.theme = mode;
}

function toggleTheme() {
  theme.value = theme.value === "light" ? "dark" : "light";
  applyTheme(theme.value);
  try {
    window.localStorage.setItem("jui-theme", theme.value);
  } catch {
    // Theme switching remains available when storage is unavailable.
  }
}

function togglePublicAddressVisibility() {
  publicAddressBlurred.value = !publicAddressBlurred.value;
  try {
    window.localStorage.setItem("jui-public-address-visible", String(!publicAddressBlurred.value));
  } catch {
    // Privacy state still works for this session when storage is unavailable.
  }
}

function scrollToTop() {
  const reducedMotion = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
  window.scrollTo({ top: 0, behavior: reducedMotion ? "auto" : "smooth" });
}

onMounted(() => {
  countdownTimer = window.setInterval(() => { countdownClock.value = Date.now(); }, 1000);
  void bootstrap();
});
onBeforeUnmount(() => {
  eventSource?.close();
  if (eventWatchdog !== null) window.clearInterval(eventWatchdog);
  if (countdownTimer !== null) window.clearInterval(countdownTimer);
  if (noticeTimer !== null) window.clearTimeout(noticeTimer);
  if (subscriptionCopyTimer !== null) window.clearTimeout(subscriptionCopyTimer);
});

async function bootstrap() {
  try {
    const result = await request<{ language: Language }>("/api/v1/settings/language");
    applyLanguage(result.language);
  } catch {
    applyLanguage("zh-CN");
  }
  try {
    const current = await request<Session>("/api/v1/auth/session");
    await acceptSession(current);
  } catch {
    session.value = null;
  } finally {
    loading.value = false;
  }
}

async function updateLanguage(value: string | number) {
  await act(async () => {
    const result = await request<{ language: Language }>("/api/v1/settings/language", {
      method: "PUT", body: JSON.stringify({ language: String(value) })
    });
    applyLanguage(result.language);
    notice.value = tr("全局界面语言已更新", "Global interface language updated");
  });
}

async function acceptSession(current: Session) {
  session.value = current;
  setCSRF(current.csrfToken);
  if (!current.setupRequired) {
    try {
      await refreshAll();
    } catch (caught) {
      const apiError = caught as ApiError;
      error.value = apiError.message ?? tr("部分页面数据加载失败，请重试", "Some page data failed to load; please retry");
    }
    connectEvents();
  }
}

async function submitLogin() {
  await act(async () => {
    const current = await request<Session>("/api/v1/auth/login", {
      method: "POST", body: JSON.stringify(login)
    });
    login.password = "";
    await acceptSession(current);
  });
}

async function finishSetup() {
  await act(async () => {
    await request("/api/v1/settings/public-host", {
      method: "PUT", body: JSON.stringify({ publicHost: publicHost.value })
    });
    if (session.value) session.value.setupRequired = false;
    await refreshAll();
    connectEvents();
    notice.value = tr("初始化完成", "Setup complete");
  });
}

async function refreshAll() {
  const results = await Promise.allSettled([
    loadNodes(), loadOutbounds(), loadVPNGate(), loadStatus(), loadSubscription(), loadSystemInfo(),
    loadServerName(), loadPublicHost(), loadNodePortSettings(), loadProtocolPrerequisites()
  ]);
  const failed = results.find(result => result.status === "rejected");
  if (failed?.status === "rejected") throw failed.reason;
}

async function retryRefresh() {
  await act(async () => {
    await refreshAll();
    notice.value = tr("页面数据已刷新", "Page data refreshed");
  });
}

async function loadNodes() {
  nodes.value = await request<NodeRecord[]>("/api/v1/nodes");
  if (!residentialEligibleNodes.value.some(node => node.id === residentialForm.nodeId)) {
    residentialForm.nodeId = residentialEligibleNodes.value[0]?.id ?? 0;
  }
}

async function loadOutbounds() {
  outbounds.value = await request<OutboundRecord[]>("/api/v1/outbounds");
}

async function loadVPNGate() {
  const [regions, candidates] = await Promise.all([
    request<VPNGateRegion[]>('/api/v1/vpngate/regions'),
    request<VPNGateCandidate[]>(`/api/v1/vpngate/nodes?country=${encodeURIComponent(residentialForm.country)}`)
  ]);
  vpnGateRegions.value = regions;
  vpnGateCandidates.value = candidates;
  selectFirstAvailableCandidate();
}

async function loadVPNGateCandidates() {
  vpnGateCandidates.value = await request<VPNGateCandidate[]>(
    `/api/v1/vpngate/nodes?country=${encodeURIComponent(residentialForm.country)}`
  );
  selectFirstAvailableCandidate();
}

function selectFirstAvailableCandidate() {
  if (!vpnGateCandidates.value.some(candidate => candidate.hostName === residentialForm.candidateHostName)) {
    residentialForm.candidateHostName = vpnGateCandidates.value[0]?.hostName ?? "";
  }
}

function changeManualProxyType(value: string | number) {
  residentialForm.type = value === "http" ? "http" : "socks5";
  residentialForm.port = residentialForm.type === "socks5" ? 1080 : 8080;
}

async function changeVPNGateCountry() {
  residentialForm.candidateHostName = "";
  vpnGateInspection.value = null;
  vpnGateInspectionCollapsed.value = false;
  await act(loadVPNGateCandidates);
}

async function refreshVPNGate() {
  vpnGateInspection.value = null;
  vpnGateInspectionCollapsed.value = false;
  vpnGateRefreshing.value = true;
  try {
    await act(async () => {
      const result = await request<{ count: number }>("/api/v1/vpngate/refresh", { method: "POST" });
      await loadVPNGate();
      notice.value = language.value === "en" ? `Refreshed ${result.count} VPNGate candidates` : `已刷新 ${result.count} 个 VPNGate 候选`;
    });
  } finally {
    vpnGateRefreshing.value = false;
    await loadVPNGate().catch(() => undefined);
  }
}

async function inspectVPNGateIP() {
  const candidate = selectedVPNGateCandidate.value;
  if (!candidate) return;
  vpnGateInspecting.value = true;
  try {
    await act(async () => {
      vpnGateInspection.value = await request<VPNGateInspection>(
        "/api/v1/vpngate/inspect",
        { method: "POST", body: JSON.stringify({ hostName: candidate.hostName }) }
      );
      vpnGateInspectionCollapsed.value = false;
      notice.value = tr("IP 信息检测完成", "IP information check completed");
    });
  } finally {
    vpnGateInspecting.value = false;
  }
}

function normalizeManualProxyEndpoint() {
  const value = residentialForm.server.trim();
  const bracketed = value.match(/^\[([^\]]+)\]:(\d+)$/);
  const hostPort = bracketed ?? value.match(/^([^:[\]]+):(\d+)$/);
  if (!hostPort) return;
  const port = Number(hostPort[2]);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return;
  residentialForm.server = hostPort[1].trim();
  residentialForm.port = port;
}

async function waitForResidentialNodeJob(jobId: string): Promise<ResidentialNodeJob> {
  let networkFailures = 0;
  for (let attempt = 0; attempt < 360; attempt += 1) {
    try {
      const job = await request<ResidentialNodeJob>(
        `/api/v1/residential-nodes/jobs/${encodeURIComponent(jobId)}`
      );
      residentialJob.value = job;
      networkFailures = 0;
      if (job.status === "succeeded") return job;
      if (job.status === "failed") {
        throw job.error ?? {
          code: "residential_job_failed",
          message: job.message || tr("住宅节点创建失败", "Failed to create residential node")
        } satisfies ApiError;
      }
    } catch (caught) {
      const apiError = caught as Partial<ApiError>;
      if (apiError.code && apiError.message) throw caught;
      networkFailures += 1;
      if (networkFailures >= 5) throw caught;
    }
    await new Promise<void>(resolve => window.setTimeout(resolve, 1000));
  }
  throw {
    code: "residential_job_timeout",
    message: tr("创建任务等待超时，请刷新页面查看节点状态", "The creation task timed out; refresh to check the node status")
  } satisfies ApiError;
}

async function createResidentialNode() {
  residentialError.value = "";
  error.value = "";
  notice.value = "";
  residentialJob.value = null;
  residentialCreating.value = true;
  try {
    if (residentialForm.source === "manual") normalizeManualProxyEndpoint();
    const vpnGatePayload = {
      nodeId: residentialForm.nodeId, country: residentialForm.country,
      candidateHostName: residentialForm.candidateHostName,
      durationMinutes: residentialForm.durationMinutes,
      permanent: residentialForm.durationMinutes === 0,
      failurePolicy: residentialForm.failurePolicy
    };
    const manualPayload = {
      nodeId: residentialForm.nodeId, type: residentialForm.type,
      server: residentialForm.server, port: residentialForm.port,
      username: residentialForm.username, password: residentialForm.password
    };
    if (residentialForm.source === "vpngate") {
      const queued = await request<ResidentialNodeJob>("/api/v1/residential-nodes/vpngate", {
        method: "POST", body: JSON.stringify(vpnGatePayload)
      });
      residentialJob.value = queued;
      await waitForResidentialNodeJob(queued.id);
    } else {
      await request("/api/v1/residential-nodes/manual", {
        method: "POST", body: JSON.stringify(manualPayload)
      });
    }
    await Promise.all([loadNodes(), loadVPNGate(), loadOutbounds(), loadNodePortSettings()]);
    notice.value = tr("住宅节点已创建；可直接复制节点链接导入客户端", "Residential node created; copy its link directly into your client");
  } catch (caught) {
    const apiError = caught as ApiError;
    residentialError.value = apiError.message ?? tr("住宅节点创建失败", "Failed to create residential node");
  } finally {
    residentialCreating.value = false;
  }
}

async function copyTemporaryNode(node: NodeRecord) {
  await act(async () => {
    const result = await request<{ uri: string }>(`/api/v1/nodes/${node.id}/export`);
    await writeClipboardText(result.uri);
    notice.value = tr("临时节点链接已复制", "Temporary node link copied");
  });
}

async function deleteTemporaryNode(node: NodeRecord) {
  if (!confirm(language.value === "en" ? `Delete residential node “${node.name}” and its dedicated exit?` : `删除住宅节点“${node.name}”并清理其独占出口？`)) return;
  await act(async () => {
    await request(`/api/v1/residential-nodes/${node.id}`, { method: "DELETE" });
    await Promise.all([loadNodes(), loadVPNGate(), loadOutbounds(), loadNodePortSettings()]);
    notice.value = tr("临时节点及独占出口已删除", "Temporary node and dedicated exit deleted");
  });
}

function temporarySource(node: NodeRecord) {
  const source = node.settings.jui_temporary_source;
  return source === "vpngate" || source === "manual" ? source : "";
}

function temporaryCountry(node: NodeRecord) {
  return String(node.settings.jui_temporary_country || "").toUpperCase();
}

function temporaryExpiryMilliseconds(node: NodeRecord): number | null {
  const value = String(node.settings.jui_temporary_expires_at || "").trim();
  return value ? Date.parse(value) : null;
}

function temporaryCountdown(node: NodeRecord) {
  if (temporarySource(node) === "manual") return tr("永久", "Permanent");
  const expiry = temporaryExpiryMilliseconds(node);
  if (expiry === null) return tr("永久", "Permanent");
  if (!Number.isFinite(expiry)) return tr("时间未知", "Unknown");
  const seconds = Math.max(0, Math.floor((expiry - countdownClock.value) / 1000));
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const rest = seconds % 60;
  const clock = [hours, minutes, rest].map(value => String(value).padStart(2, "0")).join(":");
  return days ? `${days}${tr("天", "d")} ${clock}` : clock;
}

function temporaryDurationLabel(node: NodeRecord) {
  return temporaryExpiryMilliseconds(node) === null || temporarySource(node) === "manual"
    ? tr("有效期", "Validity")
    : tr("剩余时间", "Time Remaining");
}

function changeResidentialDuration(value: string | number) {
  const duration = Number(value);
  if (duration !== 0) {
    residentialForm.durationMinutes = duration;
    return;
  }
  const accepted = confirm(tr(
    "永久使用 VPNGate 会持续占用一个隧道和监听端口。VPNGate 由志愿者提供，IP 可能随时失效或变化；发生故障时流量会被阻断，直到你手动删除该节点。确认继续吗？",
    "A permanent VPNGate node keeps one tunnel and listening port active. VPNGate is volunteer-run, so its IP may fail or change at any time. Traffic is blocked on failure until you delete the node manually. Continue?"
  ));
  residentialForm.durationMinutes = accepted ? 0 : 30;
}

async function loadStatus() {
  status.value = normalizeStatus(await request<Status>("/api/v1/system/status"));
}

function normalizeStatus(value: Status): Status {
  return {
    ...value,
    services: { ...value.services, openVPN: value.services.openVPN ?? "inactive" },
    exits: value.exits ?? { total: 0, running: 0, faulted: 0 }
  };
}

async function loadSubscription() {
  subscription.value = await request("/api/v1/subscription");
}

async function loadSystemInfo() {
  systemInfo.value = await request("/api/v1/system/info");
  countryCodeDraft.value = String(systemInfo.value.countryCode || "").toUpperCase();
}

async function loadPublicHost() {
  const result = await request<{ publicHost: string }>("/api/v1/settings/public-host");
  publicHost.value = result.publicHost;
}

async function loadServerName() {
  const result = await request<{ serverName: string }>("/api/v1/settings/server-name");
  serverName.value = result.serverName;
  serverNameDraft.value = result.serverName;
}

async function loadNodePortSettings() {
  const result = await request<NodePortSettings>("/api/v1/settings/node-start-port");
  nodeStartPort.value = result.startPort;
  nodeStartPortDraft.value = result.startPort;
  nextNodePort.value = result.nextPort;
}

async function loadProtocolPrerequisites() {
  const result = await request<ProtocolPrerequisites>("/api/v1/settings/protocol-prerequisites");
  Object.assign(protocolPrerequisites, result);
  Object.assign(protocolPrerequisitesDraft, result);
}

function connectEvents() {
  eventSource?.close();
  lastEventAt = Date.now();
  eventsConnected.value = false;
  eventsHealthKnown.value = false;
  eventSource = new EventSource("/api/v1/events");
  eventSource.addEventListener("status", event => {
    status.value = normalizeStatus(JSON.parse((event as MessageEvent).data) as Status);
    lastEventAt = Date.now();
    eventsConnected.value = true;
    eventsHealthKnown.value = true;
  });
  eventSource.onerror = () => {
    eventsConnected.value = false;
    eventsHealthKnown.value = true;
  };
  if (eventWatchdog !== null) window.clearInterval(eventWatchdog);
  eventWatchdog = window.setInterval(() => {
    if (lastEventAt && Date.now() - lastEventAt >= 5000) {
      eventsConnected.value = false;
      eventsHealthKnown.value = true;
    }
  }, 1000);
}

async function submitNode(payload: Record<string, unknown>) {
  const wasEditing = editingNodeId.value !== null;
  nodeSubmitting.value = true;
  try {
    await act(async () => {
      const path = editingNodeId.value ? `/api/v1/nodes/${editingNodeId.value}` : "/api/v1/nodes";
      await request(path, {
        method: editingNodeId.value ? "PUT" : "POST",
        body: JSON.stringify(payload)
      });
      showNodeForm.value = false;
      editingNodeId.value = null;
      await Promise.all([loadNodes(), loadNodePortSettings()]);
      notice.value = wasEditing ? tr("节点更新成功", "Node updated") : tr("节点创建成功", "Node created");
    });
  } finally {
    nodeSubmitting.value = false;
  }
}

function openCreateNode() {
  error.value = "";
  editingNodeId.value = null;
  showNodeForm.value = true;
}

function openCommonNodes() {
  commonNodesError.value = "";
  showCommonNodes.value = true;
}

async function submitCommonNodes(payloads: Record<string, unknown>[]) {
  commonNodesSubmitting.value = true;
  commonNodesError.value = "";
  const createdIds: number[] = [];
  try {
    const existingProtocols = new Set(nodes.value.map(node => node.protocol));
    const missingPayloads = payloads.filter(payload =>
      typeof payload.protocol === "string" && !existingProtocols.has(payload.protocol)
    );
    if (!missingPayloads.length) {
      showCommonNodes.value = false;
      notice.value = tr("常用节点已齐全，无需重复创建", "All common nodes already exist");
      return;
    }
    for (const payload of missingPayloads) {
      const created = await request<NodeRecord>("/api/v1/nodes", {
        method: "POST", body: JSON.stringify(payload)
      });
      createdIds.push(created.id);
    }
    showCommonNodes.value = false;
    await Promise.all([loadNodes(), loadNodePortSettings()]);
    notice.value = language.value === "en"
      ? `${createdIds.length} missing nodes created and validated`
      : `${createdIds.length} 个缺失节点已补全并通过配置校验`;
  } catch (caught) {
    let rollbackFailed = false;
    for (const id of createdIds.reverse()) {
      try {
        await request(`/api/v1/nodes/${id}`, { method: "DELETE" });
      } catch {
        rollbackFailed = true;
      }
    }
    await Promise.all([loadNodes(), loadNodePortSettings()]).catch(() => undefined);
    const message = (caught as ApiError).message ?? tr("常用节点创建失败", "Failed to create common nodes");
    commonNodesError.value = rollbackFailed
      ? `${message}${tr("；部分节点自动清理失败，请检查节点列表", "; some nodes could not be cleaned up automatically; check the node list")}`
      : `${message}${tr("；本批次已自动回滚", "; this batch was rolled back automatically")}`;
  } finally {
    commonNodesSubmitting.value = false;
  }
}

function editNode(node: NodeRecord) {
  error.value = "";
  editingNodeId.value = node.id;
  showNodeForm.value = true;
}

function closeNodeForm() {
  showNodeForm.value = false;
  editingNodeId.value = null;
  error.value = "";
}

async function toggleNode(node: NodeRecord) {
  await act(async () => {
    await request(`/api/v1/nodes/${node.id}/${node.enabled ? "disable" : "enable"}`, { method: "POST" });
    await loadNodes();
  });
}

function nodeStateLabel(node: NodeRecord) {
  if (!node.enabled) return tr("已停用", "Disabled");
  return node.status === "running" ? tr("运行中", "Running") : node.status === "faulted" ? tr("异常", "Faulted") : tr("已启用", "Enabled");
}

async function cloneNode(node: NodeRecord) {
  await act(async () => {
    await request(`/api/v1/nodes/${node.id}/clone`, { method: "POST" });
    await Promise.all([loadNodes(), loadNodePortSettings()]);
    notice.value = tr("副本已创建并保持停用", "Clone created and left disabled");
  });
}

async function deleteNode(node: NodeRecord) {
  if (!confirm(language.value === "en" ? `Delete “${node.name}”? Related credentials and firewall rules will also be removed.` : `删除“${node.name}”？相关凭据和防火墙规则也会被清理。`)) return;
  await act(async () => {
    await request(`/api/v1/nodes/${node.id}`, { method: "DELETE" });
    await Promise.all([loadNodes(), loadNodePortSettings()]);
  });
}

async function resetToken() {
  if (!confirm(tr("重置后旧订阅链接会立即失效，继续吗？", "Resetting immediately invalidates old subscription links. Continue?"))) return;
  await act(async () => {
    const result = await request<{ token: string }>("/api/v1/subscription/reset", { method: "POST" });
    await loadSubscription();
    notice.value = `${tr("新 Token", "New token")}：${result.token}`;
  });
}

async function changePassword() {
  await act(async () => {
    await request("/api/v1/auth/password", {
      method: "POST", body: JSON.stringify(passwordForm)
    });
    location.reload();
  });
}

async function updatePublicHost() {
  await act(async () => {
    const result = await request<{ publicHost: string }>("/api/v1/settings/public-host", {
      method: "PUT", body: JSON.stringify({ publicHost: publicHost.value })
    });
    publicHost.value = result.publicHost;
    await Promise.all([loadNodes(), loadSubscription()]);
    notice.value = tr("公网地址已更新；新导出链接和订阅已生效", "Public address updated; new export links and subscriptions are active");
  });
}

async function updateServerName() {
  await act(async () => {
    const result = await request<{ serverName: string }>("/api/v1/settings/server-name", {
      method: "PUT", body: JSON.stringify({ serverName: serverNameDraft.value })
    });
    serverName.value = result.serverName;
    serverNameDraft.value = result.serverName;
    notice.value = tr("服务器名称已更新；新建节点将使用该名称", "Server name updated; new nodes will use this name");
  });
}

async function updateCountry(value?: string | number) {
  if (value !== undefined) countryCodeDraft.value = String(value);
  await act(async () => {
    const result = await request<{ countryCode: string }>("/api/v1/settings/country", {
      method: "PUT", body: JSON.stringify({ countryCode: countryCodeDraft.value })
    });
    countryCodeDraft.value = result.countryCode;
    systemInfo.value = { ...systemInfo.value, countryCode: result.countryCode };
    notice.value = tr("国家已更新", "Country updated");
  });
}

async function updateNodeStartPort() {
  await act(async () => {
    const result = await request<NodePortSettings>("/api/v1/settings/node-start-port", {
      method: "PUT", body: JSON.stringify({ startPort: Number(nodeStartPortDraft.value) })
    });
    nodeStartPort.value = result.startPort;
    nodeStartPortDraft.value = result.startPort;
    nextNodePort.value = result.nextPort;
    await Promise.all([loadNodes(), loadSubscription()]);
    notice.value = language.value === "en"
      ? nodes.value.length
        ? `Starting port updated to ${result.startPort}; ${nodes.value.length} nodes remapped`
        : `Starting port updated to ${result.startPort}`
      : nodes.value.length
        ? `起始端口已更新为 ${result.startPort}，${nodes.value.length} 个节点已重新匹配端口`
        : `起始端口已更新为 ${result.startPort}`;
  });
}

function openSystemSettings() {
  Object.assign(protocolPrerequisitesDraft, protocolPrerequisites);
  if (!protocolPrerequisitesDraft.cloudflareTunnelOriginPort) {
    protocolPrerequisitesDraft.cloudflareTunnelOriginPort = 2080;
  }
  if (systemInfo.value.mockMode) {
    if (!protocolPrerequisitesDraft.httpsIngressDomain) {
      protocolPrerequisitesDraft.httpsIngressDomain = "ws.demo.jui.test";
    }
    if (!protocolPrerequisitesDraft.cloudflareTunnelDomain) {
      protocolPrerequisitesDraft.cloudflareTunnelDomain = "argo.demo.jui.test";
    }
  }
  showSystemSettings.value = true;
}

async function verifyProtocolPrerequisite(target: "https" | "cloudflare") {
  await act(async () => {
    const domain = target === "https"
      ? protocolPrerequisitesDraft.httpsIngressDomain
      : protocolPrerequisitesDraft.cloudflareTunnelDomain;
    const result = await request<ProtocolPrerequisites>("/api/v1/settings/protocol-prerequisites", {
      method: "PUT", body: JSON.stringify({
        target, action: "verify", domain,
        originPort: target === "cloudflare" ? protocolPrerequisitesDraft.cloudflareTunnelOriginPort : undefined
      })
    });
    Object.assign(protocolPrerequisites, result);
    Object.assign(protocolPrerequisitesDraft, result);
    const label = target === "https" ? tr("HTTPS 入口", "HTTPS ingress") : "Cloudflare Tunnel";
    notice.value = systemInfo.value.mockMode
      ? `${label}${tr("模拟检测已通过", " simulated verification passed")}`
      : `${label}${tr("检测已通过", " verification passed")}`;
  });
}

async function clearProtocolPrerequisite(target: "https" | "cloudflare") {
  await act(async () => {
    const result = await request<ProtocolPrerequisites>("/api/v1/settings/protocol-prerequisites", {
      method: "PUT", body: JSON.stringify({ target, action: "clear" })
    });
    Object.assign(protocolPrerequisites, result);
    Object.assign(protocolPrerequisitesDraft, result);
    notice.value = `${target === "https" ? tr("HTTPS 入口", "HTTPS ingress") : "Cloudflare Tunnel"}${tr("配置已清除", " configuration cleared")}`;
  });
}

async function logout() {
  await act(async () => {
    await request("/api/v1/auth/logout", { method: "POST" });
    location.reload();
  });
}

async function restartService() {
  if (!confirm(tr("仅重启 J-UI 面板服务，不会重启服务器。当前页面会短暂断开，继续吗？", "This restarts only the J-UI panel, not the server. The page will disconnect briefly. Continue?"))) return;
  await act(async () => {
    await request("/api/v1/system/restart", { method: "POST" });
    notice.value = tr("面板重启命令已提交", "Panel restart requested");
  });
}

async function createBackup() {
  await act(async () => {
    await download("/api/v1/system/backup", "j-ui-backup.tar.gz");
    notice.value = tr("备份已下载", "Backup downloaded");
  });
}

async function startUpdate() {
  if (!confirm(tr("下载并安装最新稳定版 J-UI？更新前会自动备份。", "Download and install the latest stable J-UI? A backup is created first."))) return;
  await act(async () => {
    await request("/api/v1/system/update", { method: "POST" });
    notice.value = tr("更新任务已提交", "Update requested");
  });
}

async function loadLogs() {
  await act(async () => {
    const result = await request<{ logs: string }>("/api/v1/system/logs?limit=200");
    logs.value = result.logs;
    showLogs.value = true;
  });
}

function absoluteURL(value: string) {
  return new URL(value, location.origin).toString();
}

function subscriptionURL(format: SubscriptionFormat) {
  if (!subscription.value) return "";
  const paths: Record<SubscriptionFormat, string> = {
    base64: subscription.value.base64Path,
    v2rayn: subscription.value.v2rayNPath,
    shadowrocket: subscription.value.shadowrocketPath,
    clash: subscription.value.clashPath,
    singbox: subscription.value.singBoxPath
  };
  return absoluteURL(paths[format]);
}

async function writeClipboardText(value: string) {
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(value);
      return;
    } catch {
      // Public HTTP pages cannot normally access the asynchronous Clipboard API.
    }
  }
  const textarea = document.createElement("textarea");
  textarea.value = value;
  textarea.setAttribute("readonly", "");
  textarea.style.position = "fixed";
  textarea.style.left = "-9999px";
  textarea.style.opacity = "0";
  document.body.append(textarea);
  textarea.select();
  try {
    if (!document.execCommand?.("copy")) throw new Error("clipboard copy was rejected");
  } finally {
    textarea.remove();
  }
}

async function copySubscription(format: SubscriptionFormat) {
  if (!subscription.value) return;
  await writeClipboardText(subscriptionURL(format));
  if (subscriptionCopyTimer !== null) window.clearTimeout(subscriptionCopyTimer);
  copiedSubscriptionFormat.value = format;
  subscriptionCopyTimer = window.setTimeout(() => {
    copiedSubscriptionFormat.value = null;
    subscriptionCopyTimer = null;
  }, 1600);
  const profile = subscriptionProfiles.value.find(item => item.format === format);
  notice.value = `${profile?.label ?? tr("订阅", "Subscription")}${tr("链接已复制", " link copied")}`;
}

function openSubscriptionLinks() {
  showSubscriptionLinks.value = true;
}

function openSubscriptionQR() {
  qrSubscriptionFormat.value = "base64";
  showSubscriptionQR.value = true;
}

async function act(action: () => Promise<void>) {
  error.value = "";
  notice.value = "";
  try {
    await action();
  } catch (caught) {
    const apiError = caught as ApiError;
    error.value = apiError.message ?? tr("操作失败", "Operation failed");
  }
}

function bytes(value = 0) {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let index = 0;
  while (value >= 1024 && index < units.length - 1) { value /= 1024; index++; }
  return `${value.toFixed(index ? 1 : 0)} ${units[index]}`;
}

function speedMbps(value = 0) {
  return value > 0 ? `${(value / 1_000_000).toFixed(1)} Mbps` : tr("未知", "Unknown");
}

function clearVPNGateInspection() {
  vpnGateInspection.value = null;
  vpnGateInspectionCollapsed.value = false;
}

function inspectionValue(value?: string | number) {
  return value === undefined || value === "" ? tr("未知", "Unknown") : String(value);
}

function nativeIPLabel(lookup: VPNGateInspection["lookup"]) {
  if (!lookup.registeredCountryCode || !lookup.countryCode) return tr("未知", "Unknown");
  return lookup.registeredCountryCode.toUpperCase() === lookup.countryCode.toUpperCase()
    ? tr("原生 IP", "Native IP") : tr(`广播 IP（${lookup.registeredCountryCode}）`, `Broadcast IP (${lookup.registeredCountryCode})`);
}

function ipMarkerLabel(lookup: VPNGateInspection["lookup"]) {
  if (lookup.isPublicService) return tr("公共服务 / 任播", "Public service / anycast");
  if (lookup.isDatacenter) return tr("机房 IP", "Datacenter IP");
  if (lookup.isResidential) return tr("家庭住宅 IP", "Residential IP");
  return tr("未分类", "Unclassified");
}

function operatorTypeLabel(value?: string) {
  const labels: Record<string, [string, string]> = {
    isp: ["ISP", "ISP"], hosting: ["托管 / 机房", "Hosting"], business: ["商业网络", "Business"],
    mobile: ["移动网络", "Mobile"], education: ["教育网络", "Education"]
  };
  const label = labels[(value || "").toLowerCase()];
  return label ? tr(label[0], label[1]) : inspectionValue(value);
}

function humanTrafficLabel(lookup: VPNGateInspection["lookup"]) {
  if (lookup.isPublicService) return tr("服务器 / 任播 DNS", "Server / anycast DNS");
  if (lookup.isCrawler) return tr("偏爬虫", "Crawler-heavy");
  if (lookup.isDatacenter) return tr("机器偏多", "Machine-heavy");
  return tr("人类偏多", "Human-heavy");
}

function detectedLabel(value: boolean) {
  return value ? tr("已检测到", "Detected") : tr("未检测到", "Not detected");
}

function threatFlagsLabel(lookup: VPNGateInspection["lookup"]) {
  const labels = (lookup.intelligence.threats || []).map(item => item.label).filter(Boolean);
  if (lookup.isAbuser) labels.push(tr("历史滥用", "Historical abuse"));
  return labels.length ? labels.join(" · ") : tr("未发现明显威胁", "No obvious threats found");
}

function abuseLevelLabel(lookup: VPNGateInspection["lookup"]) {
  const rawScore = Number.parseFloat(lookup.intelligence.abuserScoreRaw || "");
  if (Number.isFinite(rawScore) && rawScore <= 0.001) return tr("极度纯净", "Extremely clean");
  const labels: Record<string, [string, string]> = {
    safe: ["纯净", "Clean"], low: ["低风险", "Low risk"], medium: ["中风险", "Medium risk"],
    high: ["高风险", "High risk"], critical: ["极高风险", "Critical risk"]
  };
  const label = labels[(lookup.intelligence.abuserLevel || "").toLowerCase()];
  return label ? tr(label[0], label[1]) : inspectionValue(lookup.intelligence.abuserLevel);
}

function abuseLevelHasRisk(lookup: VPNGateInspection["lookup"]) {
  const rawScore = Number.parseFloat(lookup.intelligence.abuserScoreRaw || "");
  if (Number.isFinite(rawScore) && rawScore <= 0.001) return false;
  const level = (lookup.intelligence.abuserLevel || "").toLowerCase();
  return lookup.isAbuser || ["low", "medium", "high", "critical"].includes(level);
}

function httpBLLabel(value?: number) {
  if (typeof value !== "number" || value <= 0) return tr("纯净", "Clean");
  return `${tr("威胁值", "Threat score")} ${value} / 10`;
}

function rpkiLabel(value?: string) {
  const labels: Record<string, [string, string]> = {
    valid: ["Valid（有效）", "Valid"], invalid: ["Invalid（无效）", "Invalid"],
    notfound: ["NotFound（未声明）", "NotFound"]
  };
  const label = labels[(value || "").toLowerCase()];
  return label ? tr(label[0], label[1]) : inspectionValue(value);
}

function integerLabel(value?: number) {
  return typeof value === "number" && value > 0 ? value.toLocaleString(language.value) : tr("未知", "Unknown");
}

function inspectionTime(value?: string) {
  if (!value) return tr("未知", "Unknown");
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString(language.value === "en" ? "en-US" : "zh-CN");
}

function uptime(value = 0) {
  const days = Math.floor(value / 86400);
  const hours = Math.floor((value % 86400) / 3600);
  return language.value === "en" ? `${days}d ${hours}h` : `${days}天 ${hours}小时`;
}

function protocolLabel(protocol: string) {
  return ({
    vless_reality: "XTLS+Reality",
    vless_grpc_reality: "gRPC+Reality", vless_ws_tls: "VLESS-WS",
    vless_argo: "Argo", trojan_tls: "Trojan TLS",
    hysteria2: "Hysteria2", tuic: "TUIC", anytls: "AnyTLS",
    anytls_reality: "AnyTLS+Reality", socks5: tr("已弃用 SOCKS5", "Deprecated SOCKS5")
  } as Record<string, string>)[protocol] ?? protocol;
}

function outboundForNode(node: NodeRecord): OutboundRecord | undefined {
  return outbounds.value.find(outbound => outbound.id === node.outboundId);
}

function residentialNodeFaulted(node: NodeRecord): boolean {
  return outboundForNode(node)?.status === "unhealthy";
}

</script>

<template>
  <div v-if="loading" class="center-screen"><div class="loader"></div></div>

  <main v-else-if="!session" class="auth-shell">
    <section class="auth-copy" :class="{ 'auth-copy-english': language === 'en' }">
      <div class="brand"><span>J</span> J-UI</div>
      <h1>{{ tr("轻松订阅", "Easy subscription") }}<br><em>{{ tr("简单掌控", "Easy management") }}</em></h1>
    </section>
    <form class="auth-card" @submit.prevent="submitLogin">
      <h2>{{ tr("欢迎回来", "Welcome back") }}</h2>
      <label>{{ tr("用户名", "Username") }}<input v-model="login.username" autocomplete="username" required></label>
      <label>{{ tr("密码", "Password") }}<input v-model="login.password" type="password" autocomplete="current-password" required></label>
      <p v-if="error" class="alert error">{{ error }}</p>
      <button class="primary" type="submit">{{ tr("登录控制台", "Sign in") }}</button>
    </form>
  </main>

  <main v-else-if="session.setupRequired" class="setup-shell">
    <form class="auth-card setup-card" @submit.prevent="finishSetup">
      <h2>{{ tr("设置公网地址", "Set Public Address") }}</h2>
      <p>{{ tr("该地址会写入节点链接与订阅，可填写域名或公网 IP，不要包含协议或端口。", "This address is used in node links and subscriptions. Enter a domain or public IP without a scheme or port.") }}</p>
      <label>{{ tr("域名或 IP", "Domain or IP") }}<input v-model="publicHost" placeholder="node.example.com" required></label>
      <p v-if="error" class="alert error">{{ error }}</p>
      <button class="primary" type="submit">{{ tr("完成初始化", "Finish Setup") }}</button>
    </form>
  </main>

  <div v-else class="app-shell kui-shell">
    <section class="workspace">
      <header class="kui-header">
        <div class="header-module brand-module">
          <div class="header-brand"><div class="brand"><span>J</span> J-UI</div></div>
          <span class="header-divider" aria-hidden="true"></span>
          <a class="top-action fixed-action" href="https://github.com/Suparluxi/j-ui" target="_blank" rel="noreferrer" :aria-label="tr('GitHub 仓库', 'GitHub')"><span class="action-icon" aria-hidden="true">🐙</span><span class="action-label">{{ tr("GitHub 仓库", "GitHub") }}</span></a>
        </div>
        <div class="header-module monitor-module">
          <span class="top-action fixed-action live-chip" :aria-label="eventsConnected ? tr('实时监控中', 'Live') : tr('状态重连中', 'Retrying')"><i class="status-pulse" :class="{ reconnecting: !eventsConnected }" aria-hidden="true"></i><span class="action-label">{{ eventsConnected ? tr("实时监控中", "Live") : tr("状态重连中", "Retrying") }}</span></span>
        </div>
        <div class="header-module header-actions">
          <button class="top-action" type="button" :aria-label="tr('显示订阅链接', 'Show subscription links')" :disabled="!subscription" @click="openSubscriptionLinks"><span class="action-icon" aria-hidden="true">🔗</span><span class="action-label">{{ tr("订阅链接", "Subscriptions") }}</span></button>
          <button class="top-action" type="button" :aria-label="tr('显示订阅二维码', 'Show subscription QR codes')" :disabled="!subscription" @click="openSubscriptionQR"><span class="action-icon" aria-hidden="true">📱</span><span class="action-label">{{ tr("二维码", "QR Codes") }}</span></button>
          <button class="top-action" type="button" :aria-label="theme === 'light' ? tr('切换为夜间模式', 'Switch to dark mode') : tr('切换为日间模式', 'Switch to light mode')" @click="toggleTheme"><span class="action-icon" aria-hidden="true">{{ theme === "light" ? "☀️" : "🌙" }}</span><span class="action-label">{{ theme === "light" ? tr("日间", "Light") : tr("夜间", "Dark") }}</span></button>
          <button class="top-action" type="button" :aria-label="tr('刷新页面数据', 'Refresh page data')" @click="retryRefresh"><span class="action-icon" aria-hidden="true">🔄</span><span class="action-label">{{ tr("刷新", "Refresh") }}</span></button>
          <button class="top-action settings-button" type="button" :aria-label="tr('系统设置', 'System Settings')" @click="openSystemSettings"><span class="action-icon" aria-hidden="true">⚙️</span><span class="action-label">{{ tr("系统设置", "Settings") }}</span></button>
          <button class="top-action logout-button" type="button" :aria-label="tr('退出', 'Sign out')" @click="logout"><span class="action-icon" aria-hidden="true">🚪</span><span class="action-label">{{ tr("退出", "Sign out") }}</span></button>
        </div>
      </header>

      <p v-if="session.defaultCredentials" class="alert warning default-password-warning">{{ tr("当前密码为默认密码，请及时修改！", "The current password is the default password. Change it immediately!") }}</p>
      <p v-if="error && !showSystemSettings" class="alert error">{{ error }} <button class="danger-link" type="button" @click="retryRefresh">{{ tr("重试加载", "Retry") }}</button></p>
      <p v-if="notice && !showSystemSettings" class="alert success">{{ notice }}</p>
      <p v-if="eventsHealthKnown && !eventsConnected" class="alert warning">{{ tr("实时状态连接已中断；当前指标可能已经过期。", "The live status connection was interrupted; displayed metrics may be stale.") }}</p>

      <div v-if="status" id="system-status-section" class="page dashboard-section">
        <div class="section-heading"><div><h2>{{ tr("系统状态", "System Status") }}</h2></div><p>{{ tr("系统资源、流量与服务指标每两秒自动更新。", "System resources, traffic, and services update every two seconds.") }}</p></div>
        <section class="system-status-card">
          <div class="server-status-body">
            <div class="server-identity">
              <div class="server-title">
                <span class="server-dot" :class="{ danger: status.services.singBox !== 'active' }"
                  :title="status.services.singBox === 'active' ? tr('服务运行正常', 'Service is healthy') : tr('服务运行异常', 'Service is unhealthy')"></span>
                <span class="country-flag country-flag-fallback" role="img" :aria-label="countryCode ? `${countryCode} ${tr('国旗', 'flag')}` : tr('国家未知', 'Unknown country')" :title="countryCode || tr('国家未知', 'Unknown country')">{{ countryFlag }}</span>
                <h3>{{ serverName || "J-UI" }}</h3>
              </div>
              <div class="address-block">
                <div data-testid="public-address" class="address-values" :class="{ blurred: publicAddressBlurred }">
                  <strong v-for="address in publicAddresses" :key="address.label">{{ address.label }}: <span>{{ address.value }}</span></strong>
                  <strong v-if="!publicAddresses.length">{{ tr("地址", "Address") }}: <span>{{ tr("未设置", "Not set") }}</span></strong>
                </div>
                <button class="address-visibility" type="button"
                  :aria-label="publicAddressBlurred ? tr('显示 IP 地址', 'Show IP addresses') : tr('模糊 IP 地址', 'Blur IP addresses')"
                  :title="publicAddressBlurred ? tr('显示 IP 地址', 'Show IP addresses') : tr('模糊 IP 地址', 'Blur IP addresses')"
                  @click="togglePublicAddressVisibility">
                  <svg aria-hidden="true" viewBox="0 0 24 24">
                    <path d="M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6Z"/>
                    <circle cx="12" cy="12" r="2.5"/>
                    <path v-if="publicAddressBlurred" d="m4 4 16 16"/>
                  </svg>
                </button>
              </div>
              <dl class="server-facts">
                <div><dt>{{ tr("在线节点", "Online Nodes") }}</dt><dd>{{ status.nodes.enabled }} / {{ status.nodes.total }} · {{ status.nodes.faulted }} {{ tr("个异常", "faulted") }}</dd></div>
                <div><dt>{{ tr("运行时间", "Uptime") }}</dt><dd>{{ uptime(status.uptimeSeconds) }}</dd></div>
                <div><dt>{{ tr("系统负载", "System Load") }}</dt><dd>{{ status.load.map(v => v.toFixed(2)).join(" / ") }}</dd></div>
                <div><dt>{{ tr("系统", "System") }}</dt><dd>{{ systemInfo.os || "Linux" }} · {{ systemInfo.arch || "—" }}</dd></div>
                <div><dt>sing-box</dt><dd>{{ status.services.singBox }} · {{ status.services.singBoxVersion }}</dd></div>
                <div><dt>{{ tr("配置版本", "Config Version") }}</dt><dd>#{{ status.services.configVersion }}</dd></div>
                <div><dt>{{ tr("VPNGate 出口", "VPNGate Exits") }}</dt><dd>{{ status.exits.running }} / {{ status.exits.total }} {{ tr("运行", "running") }}</dd></div>
                <div><dt>OpenVPN</dt><dd>{{ status.services.openVPN }}</dd></div>
              </dl>
            </div>

            <div class="resource-panel">
              <div class="resource-row">
                <div><span>CPU <small>{{ tr("当前系统处理器占用", "Current processor usage") }}</small></span><strong>{{ status.cpuPercent.toFixed(1) }}%</strong></div>
                <progress class="bar" max="100" :value="status.cpuPercent"></progress>
              </div>
              <div class="resource-row">
                <div><span>{{ tr("内存", "Memory") }} <small>{{ bytes(status.memory.usedBytes) }} / {{ bytes(status.memory.totalBytes) }}</small></span><strong>{{ status.memory.percent.toFixed(1) }}%</strong></div>
                <progress class="bar memory-bar" max="100" :value="status.memory.percent"></progress>
              </div>
              <div class="resource-row">
                <div><span>{{ tr("磁盘", "Disk") }} <small>{{ bytes(status.disk.usedBytes) }} / {{ bytes(status.disk.totalBytes) }}</small></span><strong>{{ status.disk.percent.toFixed(1) }}%</strong></div>
                <progress class="bar disk-bar" max="100" :value="status.disk.percent"></progress>
              </div>
              <div class="network-facts">
                <div><span>↓ {{ tr("实时下载", "Download") }}</span><strong class="download-value">{{ bytes(status.network.downloadBytesPerSecond) }}/s</strong></div>
                <div class="total-traffic">
                  <span>{{ tr("总计流量 (入 | 出)", "Total Traffic (In | Out)") }}</span>
                  <strong><b>{{ bytes(status.network.downloadTotalBytes) }}</b><i>|</i><b>{{ bytes(status.network.uploadTotalBytes) }}</b></strong>
                </div>
                <div><span>↑ {{ tr("实时上传", "Upload") }}</span><strong class="upload-value">{{ bytes(status.network.uploadBytesPerSecond) }}/s</strong></div>
              </div>
            </div>
          </div>
        </section>
      </div>

      <div id="nodes-section" class="page">
        <div class="section-heading"><div><h2>{{ tr("节点管理", "Node Management") }}</h2></div><div class="node-create-actions"><button class="primary compact" @click="openCommonNodes">{{ tr("一键创建常用节点", "Create Common Nodes") }}</button><button class="ghost compact" @click="openCreateNode">＋ {{ tr("自定义节点", "Custom Node") }}</button></div></div>
        <section class="panel table-panel">
          <div v-if="!regularNodes.length" class="empty"><strong>{{ tr("还没有节点", "No nodes yet") }}</strong><p>{{ tr("创建第一个节点后，配置会经过验证再安全加载。", "Your first node will be validated before its configuration is loaded safely.") }}</p></div>
          <div v-for="node in regularNodes" :key="node.id" class="node-row">
            <div><strong>{{ node.name }}</strong><small>{{ protocolLabel(node.protocol) }} · {{ node.listen }}:{{ node.port }} · {{ tr("出口", "Exit") }} {{ outbounds.find(item => item.id === node.outboundId)?.name ?? tr("VPS 原生", "Native VPS") }} · {{ node.listenerStatus === "listening" ? tr("端口已监听", "Listening") : tr("端口未监听", "Not listening") }}</small></div>
            <div class="node-enable-control">
              <span class="node-live-state" :class="{ faulted: node.enabled && node.status === 'faulted', muted: !node.enabled }">{{ nodeStateLabel(node) }}</span>
              <button class="node-switch" type="button" role="switch" :aria-checked="node.enabled" :aria-label="`${node.enabled ? tr('停用', 'Disable') : tr('启用', 'Enable')} ${node.name}`" @click="toggleNode(node)"><span aria-hidden="true"></span></button>
            </div>
            <div class="row-actions"><button class="ghost" @click="editNode(node)">{{ tr("编辑", "Edit") }}</button><button class="ghost" @click="cloneNode(node)">{{ tr("复制", "Copy") }}</button><button class="danger-link" @click="deleteNode(node)">{{ tr("删除", "Delete") }}</button></div>
          </div>
        </section>
      </div>

      <div id="outbounds-section" class="page">
        <div class="section-heading"><div><h2>{{ tr("住宅ip代理设置", "Residential IP Proxy") }}</h2></div><p>{{ tr("选择一个现有节点作为协议模板，为住宅出口创建独立端口与临时节点链接。", "Use an existing node as a protocol template and create a dedicated port and temporary link for the residential exit.") }}</p></div>
        <form class="panel residential-builder" @submit.prevent="createResidentialNode">
          <div class="residential-source-switch" :aria-label="tr('住宅代理来源', 'Residential proxy source')">
            <button type="button" :class="{ active: residentialForm.source === 'vpngate' }" @click="residentialForm.source = 'vpngate'">VPNGate IP</button>
            <button type="button" :class="{ active: residentialForm.source === 'manual' }" @click="residentialForm.source = 'manual'">{{ tr("手动上游代理", "Manual Upstream Proxy") }}</button>
          </div>
          <div class="form-grid residential-core-fields" :class="{ 'single-column': residentialForm.source === 'manual' }">
            <label>{{ tr("绑定当前节点", "Bind Existing Node") }}
              <DropdownField v-model="residentialForm.nodeId" :options="residentialNodeOptions" :theme="theme" :language="language" menu-id="residential-node-menu" :placeholder="tr('请选择节点', 'Select a node')" required :trigger-label="tr('节点', 'node')" />
              <small>{{ tr("Argo 使用固定 Tunnel 入口，不能复制为独立端口的临时住宅节点。", "Argo uses a fixed Tunnel ingress and cannot be cloned as a temporary residential node on a dedicated port.") }}</small>
            </label>
            <label v-if="residentialForm.source === 'vpngate'">{{ tr("有效期", "Duration") }}
              <DropdownField v-model="residentialForm.durationMinutes" :options="residentialDurationOptions" :theme="theme" :language="language" menu-id="residential-duration-menu" :trigger-label="tr('有效期', 'duration')" @change="changeResidentialDuration" />
            </label>
          </div>

          <template v-if="residentialForm.source === 'vpngate'">
            <div class="toolbar residential-toolbar">
              <div class="residential-toolbar-copy">
                <div class="residential-toolbar-title">
                  <h3>{{ tr("选择 VPNGate IP", "Select a VPNGate IP") }}</h3>
                  <button class="ghost compact residential-refresh-button" type="button" :disabled="vpnGateRefreshing" @click="refreshVPNGate">{{ vpnGateRefreshing ? tr("刷新中…", "Refreshing…") : tr("刷新 IP", "Refresh IPs") }}</button>
                </div>
                <p>{{ tr("每个不同 VPNGate IP 将运行在独立 netns 与 OpenVPN 隧道中；同一 IP 可供多个协议端口复用，最多同时创建 5 个不同 IP 的隧道。", "Each distinct VPNGate IP runs in its own netns and OpenVPN tunnel. The same IP can be shared by multiple protocol ports, with up to 5 different IP tunnels running at once.") }}</p>
              </div>
            </div>
            <div class="form-grid vpn-gate-selection-grid">
              <label>{{ tr("国家 / 地区", "Country / Region") }}
                <DropdownField v-model="residentialForm.country" :options="vpnGateRegionOptions" :theme="theme" :language="language" menu-id="vpngate-region-menu" required :trigger-label="tr('国家或地区', 'country or region')" @change="changeVPNGateCountry" />
              </label>
              <label>VPNGate IP
                <DropdownField v-model="residentialForm.candidateHostName" :options="vpnGateCandidateOptions" :theme="theme" :language="language" menu-id="vpngate-ip-menu" :placeholder="vpnGateCandidates.length ? tr('请选择 IP', 'Select an IP') : tr('暂无可用 IP，请刷新', 'No available IPs; refresh first')" required trigger-label="VPNGate IP" @change="clearVPNGateInspection" />
                <small v-if="selectedVPNGateCandidate" class="candidate-report">
                  {{ tr("以上延迟和速度由", "The latency and speed above are provided by") }} <strong>VPNGate</strong>{{ tr(" 提供，不代表真实连接速度", " and do not represent actual connection speed") }}
                </small>
              </label>
            </div>
            <label>{{ tr("故障策略", "Failure Policy") }}
              <DropdownField v-model="residentialForm.failurePolicy" :options="failurePolicyOptions" :theme="theme" :language="language" menu-id="vpngate-failure-policy-menu" :trigger-label="tr('故障策略', 'failure policy')" />
            </label>
            <div class="ip-inspection-action">
              <button class="ghost compact ip-inspection-button" type="button" :disabled="!selectedVPNGateCandidate || vpnGateInspecting" @click="inspectVPNGateIP">
                {{ vpnGateInspecting ? tr("检测中…", "Checking…") : tr("IP 信息检测", "IP information check") }}
              </button>
            </div>
            <section v-if="activeVPNGateInspection" class="ip-inspection-card" aria-live="polite">
              <div class="ip-inspection-heading">
                <div class="ip-inspection-title-group">
                  <div class="ip-inspection-title-line">
                    <h3>{{ tr("IP 信息检测结果", "IP Information Result") }}</h3>
                    <span class="inspection-score" :class="{ risk: abuseLevelHasRisk(activeVPNGateInspection.lookup) }">{{ tr("IP 评分", "IP score") }} {{ activeVPNGateInspection.lookup.trustScore ?? tr("未知", "Unknown") }}</span>
                  </div>
                  <small>{{ activeVPNGateInspection.provider }} · {{ inspectionTime(activeVPNGateInspection.checkedAt) }}</small>
                </div>
                <button class="ip-inspection-collapse" :class="{ collapsed: vpnGateInspectionCollapsed }" type="button" :aria-expanded="!vpnGateInspectionCollapsed" :aria-label="vpnGateInspectionCollapsed ? tr('展开 IP 信息检测结果', 'Expand IP information result') : tr('折叠 IP 信息检测结果', 'Collapse IP information result')" @click="vpnGateInspectionCollapsed = !vpnGateInspectionCollapsed">
                  <svg viewBox="0 0 24 24" aria-hidden="true"><path d="m6 15 6-6 6 6" /></svg>
                </button>
              </div>
              <div v-show="!vpnGateInspectionCollapsed" class="ip-inspection-body">
                <div class="ip-inspection-cards">
                <div class="ip-inspection-section">
                  <h4>{{ tr("使用场景 / 类型", "Usage / Type") }}</h4>
                  <div class="ip-inspection-grid">
                    <p><span>{{ tr("检测 IP", "Checked IP") }}</span><strong>{{ activeVPNGateInspection.lookup.ip }}</strong></p>
                    <p><span>{{ tr("位置", "Location") }}</span><strong>{{ [activeVPNGateInspection.lookup.country, activeVPNGateInspection.lookup.region, activeVPNGateInspection.lookup.city].filter(Boolean).join(" · ") || tr("未知", "Unknown") }}</strong></p>
                    <p><span>{{ tr("IP 原生性", "IP nativeness") }}</span><strong>{{ nativeIPLabel(activeVPNGateInspection.lookup) }}</strong></p>
                    <p><span>{{ tr("标记", "Classification") }}</span><strong>{{ ipMarkerLabel(activeVPNGateInspection.lookup) }}</strong></p>
                    <p><span>{{ tr("运营商类型", "Operator type") }}</span><strong>{{ operatorTypeLabel(activeVPNGateInspection.lookup.companyType) }}</strong></p>
                    <p><span>{{ tr("人机流量", "Human / machine traffic") }}</span><strong>{{ humanTrafficLabel(activeVPNGateInspection.lookup) }}</strong></p>
                    <p><span>{{ tr("ASN 归属", "ASN ownership") }}</span><strong>{{ inspectionValue(activeVPNGateInspection.lookup.connection.asName) }}</strong></p>
                    <p><span>{{ tr("企业信息", "Company") }}</span><strong>{{ inspectionValue(activeVPNGateInspection.lookup.connection.companyName || activeVPNGateInspection.lookup.connection.org) }}</strong></p>
                    <p><span>{{ tr("服务商", "Provider") }}</span><strong>{{ inspectionValue(activeVPNGateInspection.lookup.connection.isp) }}</strong></p>
                  </div>
                </div>
                <div class="ip-inspection-section">
                  <h4>{{ tr("ASN / 运营商", "ASN / Operator") }}</h4>
                  <div class="ip-inspection-grid">
                    <p><span>ASN</span><strong>{{ inspectionValue(activeVPNGateInspection.lookup.connection.asn) }}</strong></p>
                    <p><span>CIDR</span><strong>{{ inspectionValue(activeVPNGateInspection.lookup.cidr) }}</strong></p>
                    <p><span>{{ tr("ASN 自报类型", "ASN declared type") }}</span><strong>{{ inspectionValue(activeVPNGateInspection.lookup.asnKind) }}</strong></p>
                    <p><span>{{ tr("IP 范围", "IP range") }}</span><strong>{{ activeVPNGateInspection.lookup.range.first && activeVPNGateInspection.lookup.range.last ? `${activeVPNGateInspection.lookup.range.first} – ${activeVPNGateInspection.lookup.range.last}` : tr("未知", "Unknown") }}</strong></p>
                    <p><span>{{ tr("ASN IPv4 总量", "ASN IPv4 total") }}</span><strong>{{ integerLabel(activeVPNGateInspection.lookup.asnIpv4Count) }}</strong></p>
                    <p><span>{{ tr("预估带宽", "Estimated bandwidth") }}</span><strong>{{ inspectionValue(activeVPNGateInspection.lookup.estimatedBandwidth) }}</strong></p>
                    <p><span>{{ tr("ASN 注册日期", "ASN registration date") }}</span><strong>{{ inspectionValue(activeVPNGateInspection.lookup.asnAllocated) }}</strong></p>
                  </div>
                </div>
                <div class="ip-inspection-section">
                  <h4>{{ tr("IP 情报（威胁指标）", "IP Intelligence") }}</h4>
                  <div class="ip-inspection-grid">
                    <p><span>{{ tr("风险标记", "Risk flags") }}</span><strong>{{ threatFlagsLabel(activeVPNGateInspection.lookup) }}</strong></p>
                    <p><span>{{ tr("滥用等级", "Abuse level") }}</span><strong>{{ abuseLevelLabel(activeVPNGateInspection.lookup) }}</strong></p>
                    <p><span>{{ tr("HTTP 蜜罐黑名单", "HTTP honeypot blacklist") }}</span><strong>{{ httpBLLabel(activeVPNGateInspection.lookup.intelligence.httpblThreat) }}</strong></p>
                    <p><span>{{ tr("RPKI 状态", "RPKI status") }}</span><strong>{{ rpkiLabel(activeVPNGateInspection.lookup.rpkiStatus) }}</strong></p>
                  </div>
                </div>
                <div class="ip-inspection-section">
                  <h4>{{ tr("风险深度检测", "Risk Depth Check") }}</h4>
                  <div class="ip-inspection-grid">
                    <p><span>VPN</span><strong>{{ detectedLabel(activeVPNGateInspection.lookup.isVpn) }}</strong></p>
                    <p><span>{{ tr("代理（Proxy）", "Proxy") }}</span><strong>{{ detectedLabel(activeVPNGateInspection.lookup.isProxy) }}</strong></p>
                    <p><span>Tor</span><strong>{{ detectedLabel(activeVPNGateInspection.lookup.isTor) }}</strong></p>
                    <p><span>{{ tr("爬虫 / 机器人", "Crawler / bot") }}</span><strong>{{ detectedLabel(activeVPNGateInspection.lookup.isCrawler) }}</strong></p>
                  </div>
                </div>
                </div>
                <small class="ip-inspection-note">{{ tr("以上信息均由ip.net.coffee 提供，不保证真实性，请自行判断。", "All information above is provided by ip.net.coffee. Accuracy is not guaranteed; use your own judgment.") }}</small>
              </div>
            </section>
            <p class="security-note">{{ tr("VPNGate 是志愿者提供的临时 VPN，不能保证一定属于住宅网络。隧道异常时流量会被阻断，不会回退到 VPS 原生出口。", "VPNGate is a volunteer-run temporary VPN and is not guaranteed to be residential. Traffic is blocked if the tunnel fails and never falls back to the native VPS exit.") }}</p>
          </template>

          <template v-else>
            <div class="toolbar residential-toolbar"><div><h3>{{ tr("填写手动上游代理", "Enter a Manual Upstream Proxy") }}</h3><p>{{ tr("这里必须填写正在运行的 SOCKS5 或 HTTP CONNECT 代理服务，而不是普通住宅 IP。该模式不创建 OpenVPN 隧道，凭据会使用实例密钥加密。", "Enter a running SOCKS5 or HTTP CONNECT proxy service, not an ordinary residential IP. This mode does not create an OpenVPN tunnel. Credentials are encrypted with the instance key.") }}</p></div></div>
            <div class="form-grid">
              <label>{{ tr("代理类型", "Proxy Type") }}
                <DropdownField :model-value="residentialForm.type" :options="proxyTypeOptions" :theme="theme" :language="language" menu-id="manual-proxy-type-menu" :trigger-label="tr('代理类型', 'proxy type')" @update:model-value="changeManualProxyType" />
              </label>
              <label>{{ tr("代理 IP / 域名", "Proxy IP / Domain") }}<input v-model.trim="residentialForm.server" placeholder="198.51.100.10" required @blur="normalizeManualProxyEndpoint"></label>
              <label>{{ tr("代理端口", "Proxy Port") }}<input v-model.number="residentialForm.port" type="number" min="1" max="65535" required></label>
              <label>{{ tr("用户名", "Username") }}<input v-model="residentialForm.username" autocomplete="off" :placeholder="tr('可选', 'Optional')"></label>
              <label>{{ tr("密码", "Password") }}<input v-model="residentialForm.password" type="password" autocomplete="new-password" :placeholder="tr('可选', 'Optional')"></label>
            </div>
            <p class="security-note">{{ tr("创建前会通过该上游代理访问互联网并核验真实出口 IP；检测失败通常表示代理端口未开放、凭据错误或该地址并非代理服务器。该代理永久绑定新建节点，且绝不回退到 VPS 原生出口。", "Before creation, J-UI reaches the internet through this upstream and verifies its real exit IP. A failed check usually means the proxy port is closed, credentials are wrong, or the address is not a proxy server. The proxy is permanently bound and never falls back to the VPS exit.") }}</p>
          </template>

          <div class="residential-submit-row">
            <button class="primary compact residential-submit" type="submit" :disabled="residentialCreating || !residentialEligibleNodes.length">
              {{ residentialCreating
                ? residentialForm.source === "vpngate"
                  ? tr("正在创建独占隧道与节点…", "Creating isolated tunnel and node…")
                  : tr("正在验证上游代理并创建节点…", "Verifying upstream proxy and creating node…")
                : tr("创建订阅节点", "Create Subscription Node") }}
            </button>
            <p v-if="residentialJob && residentialCreating" class="residential-job-progress" role="status">
              {{ residentialJob.message || tr("正在处理…", "Working…") }}
            </p>
            <p v-if="residentialError" class="residential-form-error" role="alert">{{ residentialError }}</p>
          </div>
        </form>

        <section class="panel table-panel temporary-nodes-panel">
          <div class="temporary-list-heading"><div><h3>{{ tr("新建节点展示", "Residential Nodes") }}</h3></div><span>{{ temporaryNodes.length }} {{ tr("个", "") }}</span></div>
          <div v-if="!temporaryNodes.length" class="empty"><strong>{{ tr("还没有住宅节点", "No residential nodes") }}</strong><p>{{ tr("选择来源和绑定节点后，系统会自动分配新端口并生成单节点链接。", "Choose a source and node; the system will allocate a new port and generate a single-node link.") }}</p></div>
          <div v-for="node in temporaryNodes" :key="node.id" class="temporary-node-row">
            <div class="temporary-node-main">
              <div class="temporary-node-title-line">
                <strong>{{ node.name }}</strong>
                <small>{{ temporarySource(node) === "vpngate" ? `VPNGate ${temporaryCountry(node)}` : tr("手动代理", "Manual proxy") }}</small>
              </div>
            </div>
            <div class="temporary-proxy-ip" :class="{ faulted: residentialNodeFaulted(node) }"><span>{{ tr("代理 IP 地址", "Proxy IP") }}</span><strong>{{ outboundForNode(node)?.observedIp || "—" }}</strong><small v-if="residentialNodeFaulted(node)">{{ outboundForNode(node)?.lastError }}</small></div>
            <div class="temporary-countdown" :class="{ faulted: residentialNodeFaulted(node) }"><span>{{ temporaryDurationLabel(node) }}</span><strong>{{ residentialNodeFaulted(node) ? tr("故障", "Faulted") : temporaryCountdown(node) }}</strong></div>
            <div class="row-actions"><button class="ghost" type="button" @click="copyTemporaryNode(node)">{{ tr("复制", "Copy") }}</button><button class="danger-link" type="button" @click="deleteTemporaryNode(node)">{{ tr("删除", "Delete") }}</button></div>
          </div>
        </section>
      </div>

    </section>
    <button class="back-to-top" type="button" :aria-label="tr('返回顶部', 'Back to top')" :title="tr('返回顶部', 'Back to top')" @click="scrollToTop">
      <svg viewBox="0 0 24 24" aria-hidden="true">
        <path d="M12 19V5M6.5 10.5 12 5l5.5 5.5" />
      </svg>
    </button>
  </div>

  <div v-if="showSubscriptionLinks && subscription" class="modal-backdrop subscription-links-backdrop" @click.self="showSubscriptionLinks = false">
    <section class="modal subscription-links-modal" role="dialog" aria-modal="true" aria-labelledby="subscription-links-title">
      <div class="modal-head">
        <div><h2 id="subscription-links-title">{{ tr("订阅链接", "Subscription Links") }}</h2></div>
        <button class="header-button" type="button" @click="showSubscriptionLinks = false">{{ tr("关闭", "Close") }}</button>
      </div>
      <p>{{ tr("选择对应客户端的链接。所有链接共用当前 Token，重置后旧链接会立即失效。", "Choose the link for your client. All links share the current token; resetting it invalidates every old link immediately.") }}</p>
      <div class="subscription-link-list">
        <article v-for="profile in subscriptionProfiles" :key="profile.format" class="subscription-link-item">
          <div><strong><span aria-hidden="true">{{ profile.icon }}</span>{{ profile.label }}</strong><small>{{ profile.description }}</small></div>
          <div class="copy-field"><code>{{ subscriptionURL(profile.format) }}</code><button type="button" :class="{ copied: copiedSubscriptionFormat === profile.format }" aria-live="polite" @click="copySubscription(profile.format)">{{ copiedSubscriptionFormat === profile.format ? tr("已复制 ✓", "Copied ✓") : tr("复制", "Copy") }}</button></div>
        </article>
      </div>
      <button class="danger-link subscription-reset-button" type="button" @click="resetToken">{{ tr("重置订阅 Token", "Reset Subscription Token") }}</button>
    </section>
  </div>

  <div v-if="showSubscriptionQR && subscription" class="modal-backdrop qr-backdrop" @click.self="showSubscriptionQR = false">
    <section class="modal subscription-qr-modal" role="dialog" aria-modal="true" aria-labelledby="subscription-qr-title">
      <div class="modal-head">
        <div><h2 id="subscription-qr-title">{{ tr("订阅二维码", "Subscription QR Codes") }}</h2></div>
        <button class="header-button" type="button" @click="showSubscriptionQR = false">{{ tr("关闭", "Close") }}</button>
      </div>
      <p>{{ tr("二维码仅在当前浏览器本地生成，不会把订阅 Token 发送给第三方。", "QR codes are generated locally in this browser. Subscription tokens are never sent to third parties.") }}</p>
      <div class="qr-format-tabs" :aria-label="tr('二维码订阅格式', 'QR subscription format')">
        <button v-for="profile in subscriptionProfiles" :key="profile.format" type="button" :class="{ active: qrSubscriptionFormat === profile.format }" @click="qrSubscriptionFormat = profile.format">{{ profile.icon }} {{ profile.label }}</button>
      </div>
      <div class="qr-code-surface">
        <QrcodeVue :value="subscriptionURL(qrSubscriptionFormat)" :size="240" level="M" render-as="svg" background="#ffffff" foreground="#111827"/>
      </div>
    </section>
  </div>

  <div v-if="showSystemSettings" class="modal-backdrop settings-backdrop" @click.self="showSystemSettings = false">
    <section class="modal settings-modal" role="dialog" aria-modal="true" aria-labelledby="system-settings-title">
      <div class="modal-head">
        <div><h2 id="system-settings-title">{{ tr("系统设置", "System Settings") }}</h2></div>
        <button class="header-button" type="button" @click="showSystemSettings = false">{{ tr("关闭", "Close") }}</button>
      </div>
      <p v-if="error" class="alert error">{{ error }}</p>
      <p v-if="notice" class="alert success">{{ notice }}</p>
      <div class="settings-grid">
        <section class="panel settings-actions-panel">
          <div class="settings-actions-copy"><h3>{{ tr("系统操作", "System Operations") }}</h3></div>
          <div class="settings-language">
            <span>{{ tr("语言", "Language") }}</span>
            <DropdownField :model-value="language" :options="languageOptions" :theme="theme" :language="language" menu-id="global-language-menu" :trigger-label="tr('语言', 'language')" @change="updateLanguage" />
          </div>
          <div class="system-actions">
            <button class="ghost" @click="createBackup">{{ tr("下载备份", "Download Backup") }}</button>
            <button class="ghost" @click="loadLogs">{{ tr("读取日志", "View Logs") }}</button>
            <button class="ghost" @click="startUpdate">{{ tr("更新", "Update") }}</button>
            <button class="danger-link" @click="restartService">{{ tr("重启面板", "Restart Panel") }}</button>
          </div>
        </section>
        <section class="panel settings-group">
          <h3>{{ tr("基础配置", "General Settings") }}</h3>
          <div class="settings-subsection account-country-subsection">
            <h4 class="account-id-heading">{{ tr("账号 ID", "Account ID") }}：<strong>{{ session?.username }}</strong></h4>
            <div class="country-setting">
              <label><span>{{ tr("国家", "Country") }}</span><DropdownField v-model="countryCodeDraft" :options="countryOptions" :theme="theme" :language="language" menu-id="country-setting-menu" :trigger-label="tr('国家', 'country')" searchable required @change="updateCountry" /></label>
            </div>
            <p>{{ tr("系统会根据公网 IP 自动识别；也可使用两位 ISO 国家代码覆盖。", "Detected from the public IP; you can override it with a two-letter ISO country code.") }}</p>
          </div>
          <form class="settings-subsection" @submit.prevent="updateServerName">
            <h4>{{ tr("服务器名称", "Server Name") }}</h4>
            <p>{{ tr("用于系统状态标题以及后续新建节点的默认名称；不会重命名已有节点。", "Used for the status title and default names of future nodes. Existing nodes are not renamed.") }}</p>
            <label>{{ tr("服务器名称", "Server Name") }}<input v-model.trim="serverNameDraft" maxlength="64" required></label>
            <button class="primary compact" type="submit">{{ tr("保存服务器名称", "Save Server Name") }}</button>
          </form>
          <form class="settings-subsection" @submit.prevent="updatePublicHost">
            <h4>{{ tr("公网地址", "Public Address") }}</h4>
            <p>{{ tr("用于节点 URI 和订阅，不包含协议、端口或路径。", "Used in node URIs and subscriptions; do not include a scheme, port, or path.") }}</p>
            <label>{{ tr("域名或 IP", "Domain or IP") }}<input v-model="publicHost" required></label>
            <button class="primary compact" type="submit">{{ tr("保存并更新导出", "Save and Update Exports") }}</button>
          </form>
          <form class="settings-subsection" @submit.prevent="updateNodeStartPort">
            <h4>{{ tr("节点起始端口", "Starting Node Port") }}</h4>
            <p>{{ tr("修改后，普通节点会按创建顺序重新分配；VLESS-WS 保持 Cloudflare HTTPS 专用端口，Argo 保持 Tunnel 入口端口。", "Regular nodes are reassigned by creation order. VLESS-WS keeps a Cloudflare HTTPS port, while Argo keeps its Tunnel origin port.") }}</p>
            <label>{{ tr("起始端口", "Starting Port") }}<input v-model.number="nodeStartPortDraft" type="number" min="1" max="65535" required></label>
            <div class="detail-list compact-details">
              <p><span>{{ tr("当前起始端口", "Current Starting Port") }}</span>{{ nodeStartPort }}</p>
              <p><span>{{ tr("下一个可用端口", "Next Available Port") }}</span>{{ nextNodePort }}</p>
            </div>
            <button class="primary compact" type="submit">{{ tr("保存并重新匹配节点", "Save and Remap Nodes") }}</button>
          </form>
        </section>
        <section class="panel settings-group security-settings-group">
          <h3>{{ tr("协议与安全", "Protocols & Security") }}</h3>
          <div class="settings-subsection protocol-prerequisites">
            <h4>{{ tr("协议前置配置", "Protocol Prerequisites") }}</h4>
            <p v-if="systemInfo.mockMode" class="inline-notice">{{ tr("当前为测试模式，所有协议均已解锁：填写假域名后执行模拟检测，不会修改 DNS、申请真实证书或启动 cloudflared。", "Test mode unlocks all protocols. Demo-domain checks are simulated and do not change DNS, issue certificates, or start cloudflared.") }}</p>
            <p v-else>{{ tr("HTTPS 入口可在此检测；Argo 由 VPS 中的 j-ui 管理菜单逐步部署，此处只展示真实状态。", "HTTPS ingress can be verified here. Deploy Argo step by step from the j-ui management menu on the VPS; this page only shows its actual status.") }}</p>
            <p v-if="!systemInfo.mockMode" class="inline-notice">{{ protocolPrerequisites.certificateReady
              ? tr(`节点 SSL 证书可用：${protocolPrerequisites.certificateServerName}`, `Node SSL certificate ready: ${protocolPrerequisites.certificateServerName}`)
              : tr("节点 SSL 证书不可用，请运行 j-ui ssl 重新申请。", "Node SSL certificate unavailable; run j-ui ssl to issue it again.") }}</p>
            <form class="prerequisite-card" @submit.prevent="verifyProtocolPrerequisite('https')">
              <div class="prerequisite-head">
                <div><strong>{{ tr("HTTPS 入口", "HTTPS Ingress") }}</strong><small>{{ tr("用于 VLESS-WS 的域名入口；橙云域名会自动使用 Cloudflare 支持的 HTTPS 端口。", "Domain ingress for VLESS-WS. Proxied domains automatically use a Cloudflare-supported HTTPS port.") }}</small></div>
                <span class="status-pill" :class="{ muted: !protocolPrerequisites.httpsIngressEnabled || protocolPrerequisitesDraft.httpsIngressDomain !== protocolPrerequisites.httpsIngressDomain }">
                  {{ protocolPrerequisites.httpsIngressEnabled
                    ? protocolPrerequisitesDraft.httpsIngressDomain === protocolPrerequisites.httpsIngressDomain ? tr("已验证", "Verified") : tr("待重新检测", "Recheck Required")
                    : tr("未配置", "Not Configured") }}
                </span>
              </div>
              <label>{{ tr("HTTPS 公网域名", "HTTPS Public Domain") }}
                <input v-model.trim="protocolPrerequisitesDraft.httpsIngressDomain" placeholder="ws.example.com" required>
                <small>{{ systemInfo.mockMode ? tr("测试模式可使用假域名。", "A demo domain may be used in test mode.") : tr("请将域名解析到当前 VPS；检测时会自动申请匹配证书，需确保 TCP 80 可访问。", "Point the domain to this VPS. Verification will issue a matching certificate and requires public TCP 80 access.") }}</small>
              </label>
              <div class="prerequisite-actions">
                <button class="primary compact" type="submit">{{ systemInfo.mockMode ? tr("模拟检测并保存", "Simulate, Verify & Save") : tr("检测并保存", "Verify & Save") }}</button>
                <button v-if="protocolPrerequisites.httpsIngressEnabled" class="header-button" type="button" @click="clearProtocolPrerequisite('https')">{{ tr("清除配置", "Clear") }}</button>
              </div>
            </form>
            <form v-if="systemInfo.mockMode" class="prerequisite-card" @submit.prevent="verifyProtocolPrerequisite('cloudflare')">
              <div class="prerequisite-head">
                <div><strong>Cloudflare Tunnel</strong><small>{{ tr("用于 Argo 的固定域名 WebSocket 公网入口。", "Provides a fixed-domain WebSocket ingress for Argo.") }}</small></div>
                <span class="status-pill" :class="{ muted: !protocolPrerequisites.cloudflareTunnelEnabled || protocolPrerequisitesDraft.cloudflareTunnelDomain !== protocolPrerequisites.cloudflareTunnelDomain }">
                  {{ protocolPrerequisites.cloudflareTunnelEnabled
                    ? protocolPrerequisitesDraft.cloudflareTunnelDomain === protocolPrerequisites.cloudflareTunnelDomain ? tr("已验证", "Verified") : tr("待重新检测", "Recheck Required")
                    : tr("未配置", "Not Configured") }}
                </span>
              </div>
              <label>{{ tr("Tunnel 公网域名", "Tunnel Public Domain") }}
                <input v-model.trim="protocolPrerequisitesDraft.cloudflareTunnelDomain" placeholder="argo.example.com" required>
                <small>{{ tr("测试模式仅模拟验证；正式环境请在 VPS 运行 j-ui argo 自动配置。", "Verification is simulated in test mode. Run j-ui argo on the VPS for automatic production setup.") }}</small>
              </label>
              <label>{{ tr("本机入口端口", "Local Origin Port") }}
                <input v-model.number="protocolPrerequisitesDraft.cloudflareTunnelOriginPort" type="number" min="1" max="65535" required>
                <small>{{ tr("正式环境中，J-UI 会自动把固定 Tunnel 回源到该端口，例如 http://127.0.0.1:2080。", "In production, J-UI automatically points the fixed Tunnel to this origin, for example http://127.0.0.1:2080.") }}</small>
              </label>
              <p v-if="protocolPrerequisites.cloudflareTunnelEnabled && protocolPrerequisites.cloudflareTunnelOriginPort" class="detected-origin">
                {{ tr("已检测本机入口", "Detected local ingress") }}：127.0.0.1:{{ protocolPrerequisites.cloudflareTunnelOriginPort }}，{{ tr("新建 Argo 将自动使用该端口。", "New Argo nodes will use this port automatically.") }}
              </p>
              <div class="prerequisite-actions">
                <button class="primary compact" type="submit">{{ systemInfo.mockMode ? tr("模拟检测并保存", "Simulate, Verify & Save") : tr("检测并保存", "Verify & Save") }}</button>
                <button v-if="protocolPrerequisites.cloudflareTunnelEnabled" class="header-button" type="button" @click="clearProtocolPrerequisite('cloudflare')">{{ tr("清除配置", "Clear") }}</button>
                <a class="primary compact argo-guide-link" :href="argoGuideUrl" target="_blank" rel="noopener noreferrer">📖 {{ tr("跳转 GitHub 查看教程", "Open GitHub Tutorial") }}</a>
              </div>
            </form>
            <div v-else class="prerequisite-card">
              <div class="prerequisite-head">
                <div><strong>Cloudflare Tunnel</strong><small>{{ tr("用于 Argo 的固定域名 WebSocket 公网入口。", "Provides a fixed-domain WebSocket ingress for Argo.") }}</small></div>
                <span class="status-pill" :class="{ muted: !protocolPrerequisites.cloudflareTunnelEnabled }">
                  {{ protocolPrerequisites.cloudflareTunnelEnabled ? tr("已验证", "Verified") : tr("未部署", "Not Deployed") }}
                </span>
              </div>
              <div v-if="protocolPrerequisites.cloudflareTunnelEnabled" class="detail-list compact-details argo-status-details">
                <p><span>{{ tr("公网域名", "Public Domain") }}</span>{{ protocolPrerequisites.cloudflareTunnelDomain }}</p>
                <p><span>{{ tr("本机入口", "Local Origin") }}</span>127.0.0.1:{{ protocolPrerequisites.cloudflareTunnelOriginPort }}</p>
                <p><span>{{ tr("上次验证", "Last Verified") }}</span>{{ displayDateTime(protocolPrerequisites.cloudflareTunnelVerifiedAt || "") }}</p>
              </div>
              <p v-else class="inline-notice">{{ tr("请登录 VPS 运行 j-ui argo，输入受限 Cloudflare API Token 和固定子域名；J-UI 会自动创建 Tunnel、DNS 与回源规则。", "Run j-ui argo on the VPS and provide a scoped Cloudflare API token plus a fixed subdomain. J-UI creates the Tunnel, DNS, and origin route automatically.") }}</p>
              <div class="prerequisite-actions">
                <button v-if="protocolPrerequisites.cloudflareTunnelEnabled" class="primary compact" type="button" @click="verifyProtocolPrerequisite('cloudflare')">{{ tr("重新进行端到端检测", "Run End-to-End Check Again") }}</button>
                <a class="primary compact argo-guide-link" :href="argoGuideUrl" target="_blank" rel="noopener noreferrer">📖 {{ tr("跳转 GitHub 查看教程", "Open GitHub Tutorial") }}</a>
              </div>
            </div>
          </div>
          <form class="settings-subsection security-password" @submit.prevent="changePassword">
            <h4>{{ tr("修改密码", "Change Password") }}</h4>
            <div class="security-password-fields">
              <label>{{ tr("当前密码", "Current Password") }}<input v-model="passwordForm.currentPassword" type="password" required></label>
              <label>{{ tr("新密码", "New Password") }}<input v-model="passwordForm.newPassword" type="password" required></label>
            </div>
            <button class="primary compact" type="submit">{{ tr("更新并退出所有会话", "Update and Sign Out All Sessions") }}</button>
          </form>
        </section>
      </div>
    </section>
  </div>

  <div v-if="showLogs" class="modal-backdrop logs-backdrop" @click.self="showLogs = false">
    <section class="modal logs-modal" role="dialog" aria-modal="true" aria-labelledby="system-logs-title">
      <div class="modal-head">
        <div><h2 id="system-logs-title">{{ tr("系统日志", "System Logs") }}</h2></div>
        <div class="modal-head-actions"><button class="ghost" type="button" @click="loadLogs">{{ tr("刷新日志", "Refresh Logs") }}</button><button class="header-button" type="button" @click="showLogs = false">{{ tr("关闭", "Close") }}</button></div>
      </div>
      <pre class="logs">{{ logs || tr("暂无日志", "No logs available") }}</pre>
    </section>
  </div>

  <NodeFormModal
    v-if="showNodeForm"
    :node="nodes.find(node => node.id === editingNodeId) ?? null"
    :error="error"
    :submitting="nodeSubmitting"
    :host-name="String(serverName || 'J-UI')"
    :public-host="publicHost"
    :next-port="nextNodePort"
    :used-ports="nodes.map(node => node.port)"
    :mock-mode="Boolean(systemInfo.mockMode)"
    :https-ingress-enabled="protocolPrerequisites.httpsIngressEnabled"
    :https-ingress-domain="protocolPrerequisites.httpsIngressDomain"
    :cloudflare-tunnel-enabled="protocolPrerequisites.cloudflareTunnelEnabled"
    :cloudflare-tunnel-domain="protocolPrerequisites.cloudflareTunnelDomain"
    :cloudflare-tunnel-origin-port="protocolPrerequisites.cloudflareTunnelOriginPort || 0"
    :certificate-mode-default="protocolPrerequisites.certificateMode"
    :certificate-path-default="protocolPrerequisites.certificatePath || ''"
    :certificate-key-path-default="protocolPrerequisites.certificateKeyPath || ''"
    :certificate-ready="protocolPrerequisites.certificateReady"
    :certificate-server-name="protocolPrerequisites.certificateServerName || ''"
    :theme="theme"
    :language="language"
    @close="closeNodeForm"
    @submit="submitNode"
  />

  <CommonNodesModal
    v-if="showCommonNodes"
    :server-name="String(serverName || 'J-UI')"
    :public-host="publicHost"
    :certificate-server-name="protocolPrerequisites.certificateServerName || ''"
    :certificate-mode="protocolPrerequisites.certificateMode"
    :certificate-path="protocolPrerequisites.certificatePath || ''"
    :certificate-key-path="protocolPrerequisites.certificateKeyPath || ''"
    :existing-protocols="regularNodes.map(node => node.protocol)"
    :next-port="nextNodePort"
    :error="commonNodesError"
    :submitting="commonNodesSubmitting"
    :theme="theme"
    :language="language"
    @close="showCommonNodes = false"
    @submit="submitCommonNodes"
  />

</template>
