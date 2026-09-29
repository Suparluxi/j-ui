// Local-only UI fixture. No J-UI database, credentials, or VPS connection.
import { createServer } from "node:http";
import { readFileSync } from "node:fs";

const script = readFileSync(new URL("../internal/node/landing-setup.sh", import.meta.url), "utf8");

const base = JSON.parse(readFileSync(new URL("../internal/engine/singbox/ai-rule-set.json", import.meta.url), "utf8"));
let landing = { enabled: false, inboundId: 0, configured: false };
let overrides = { include: [], exclude: [] };
let previewSource = "";
let previewBase = base;
const status = {
  cpuPercent: 8, memory: { usedBytes: 1200000000, totalBytes: 4000000000, percent: 30 },
  disk: { usedBytes: 6000000000, totalBytes: 40000000000, percent: 15 },
  network: { uploadBytesPerSecond: 1024, downloadBytesPerSecond: 2048,
    uploadTotalBytes: 102400, downloadTotalBytes: 204800 },
  uptimeSeconds: 3600, load: [0.12, 0.2, 0.1],
  services: { jui: "active", singBox: "active", openVPN: "inactive", singBoxVersion: "1.14.0", configVersion: 1 },
  nodes: { total: 1, enabled: 1, faulted: 0 }, exits: { total: 0, running: 0, faulted: 0 }
};
const node = { id: 1, name: "isvoro-hk · 演示", protocol: "vless_reality", listen: "0.0.0.0",
  port: 8881, enabled: true, status: "active", listenerStatus: "listening",
  publicConnectivity: "available", externalAddress: "203.0.113.10", currentOutbound: "native",
  settings: { server_name: "www.example.test" } };
const get = new Map([
  ["/api/v1/settings/language", { language: "zh-CN" }],
  ["/api/v1/auth/session", { username: "演示会话", csrfToken: "", setupRequired: false, adminPath: "", defaultCredentials: false }],
  ["/api/v1/nodes", [node]], ["/api/v1/outbounds", []],
  ["/api/v1/vpngate/regions", []], ["/api/v1/system/status", status],
  ["/api/v1/subscription", null],
  ["/api/v1/system/info", { countryCode: "HK", ipv4: "203.0.113.10", os: "Linux", arch: "amd64", mockMode: true, demoPreview: true }],
  ["/api/v1/settings/server-name", { serverName: "J-UI 本地演示" }],
  ["/api/v1/settings/public-host", { publicHost: "example.test" }],
  ["/api/v1/settings/node-start-port", { startPort: 8881, nextPort: 8882 }],
  ["/api/v1/settings/protocol-prerequisites", { httpsIngressEnabled: false, httpsIngressDomain: "",
    cloudflareTunnelEnabled: false, cloudflareTunnelDomain: "", certificateMode: "auto", certificateReady: false }]
]);

function reply(response, code, data) {
  response.writeHead(code, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" });
  response.end(JSON.stringify(data));
}

createServer(async (request, response) => {
  const pathname = new URL(request.url, "http://127.0.0.1").pathname;
  if (request.method === "GET" && pathname === "/api/v1/events") {
    response.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache" });
    response.write(`event: status\ndata: ${JSON.stringify(status)}\n\n`);
    const timer = setInterval(() => response.write(`event: status\ndata: ${JSON.stringify(status)}\n\n`), 2000);
    request.on("close", () => clearInterval(timer));
    return;
  }
  if (request.method === "GET") {
    if (pathname === "/api/v1/landing") return reply(response, 200, landing);
    if (pathname === "/api/v1/landing/script") return reply(response, 200, { script });
    if (pathname === "/api/v1/landing/rules") return reply(response, 200, {
      source: previewSource ? "演示规则快照" : "v2fly/domain-list-community category-ai-!cn @ bcea254 (演示)",
      sourceUrl: previewSource, base: previewBase, ...overrides
    });
    if (pathname === "/api/v1/vpngate/nodes") return reply(response, 200, []);
    if (get.has(pathname)) return reply(response, 200, get.get(pathname));
  }
  if (request.method === "PUT" && (pathname === "/api/v1/landing" || pathname === "/api/v1/landing/rules")) {
    let raw = "";
    for await (const part of request) {
      raw += part;
      if (raw.length > 8192) return reply(response, 413, { message: "演示请求过大" });
    }
    let input;
    try { input = JSON.parse(raw); } catch { return reply(response, 400, { message: "请求格式无效" }); }
    if (pathname === "/api/v1/landing") {
      if (Object.hasOwn(input, "uri")) return reply(response, 400, { message: "不再支持 VLESS URI 导入，请使用落地机返回的六行连接信息" });
      if (input.details) return reply(response, 400, { message: "演示模式不接收真实节点信息" });
      if (input.inboundId) return reply(response, 400, { message: "请刷新落地机页面，旧版单入口设置已移除" });
      if (input.enabled && !landing.configured) return reply(response, 400, { message: "演示模式没有配置落地出口" });
      landing = { ...landing, enabled: Boolean(input.enabled), inboundId: 0 };
      return reply(response, 200, landing);
    }
    if (!Array.isArray(input.include) || !Array.isArray(input.exclude)) {
      return reply(response, 400, { message: "规则格式无效" });
    }
    overrides = { include: input.include, exclude: input.exclude };
    return reply(response, 200, { source: "v2fly/domain-list-community category-ai-!cn @ bcea254 (演示)", sourceUrl: previewSource, base: previewBase, ...overrides });
  }
  if (request.method === "POST" && pathname === "/api/v1/landing/rules/refresh") {
    let raw = "";
    for await (const part of request) {
      raw += part;
      if (raw.length > 2048) return reply(response, 413, { message: "演示请求过大" });
    }
    let input;
    try { input = JSON.parse(raw); } catch { return reply(response, 400, { message: "请求格式无效" }); }
    previewSource = String(input.sourceUrl || "");
    previewBase = base;
    return reply(response, 200, { source: previewSource ? "演示规则快照" : "v2fly/domain-list-community category-ai-!cn @ bcea254 (演示)",
      sourceUrl: previewSource, base: previewBase, ...overrides });
  }
  reply(response, 403, { message: "本地演示仅允许查看和模拟落地机配置" });
}).listen(Number(process.env.JUI_PREVIEW_PORT || 8080), "127.0.0.1", () => {
  console.log(`J-UI landing UI preview API: http://127.0.0.1:${process.env.JUI_PREVIEW_PORT || 8080} (local mock only)`);
});
