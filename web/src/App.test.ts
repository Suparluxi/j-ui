import { createApp, nextTick, type App as VueApp } from "vue";
import { afterEach, describe, expect, it, vi } from "vitest";
import App from "./App.vue";

let mountedApp: VueApp<Element> | null = null;

class FakeEventSource {
  onerror: (() => void) | null = null;
  constructor(_url: string) {}
  addEventListener(_name: string, _listener: EventListener): void {}
  close(): void {}
}

afterEach(() => {
  mountedApp?.unmount();
  mountedApp = null;
  document.body.innerHTML = "";
  vi.unstubAllGlobals();
  vi.useRealTimers();
  window.localStorage.clear();
  delete document.documentElement.dataset.theme;
});

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}

async function settle(): Promise<void> {
  for (let index = 0; index < 16; index++) {
    await Promise.resolve();
    await nextTick();
  }
}

describe("App bootstrap", () => {
  it("uses the installed language on the login page and leaves the server-specific account blank", async () => {
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      const path = String(input);
      if (path === "/api/v1/settings/language") return json({ language: "en" });
      if (path === "/api/v1/auth/session") return json({ code: "unauthenticated", message: "Unauthorized" }, 401);
      throw new Error(`unexpected fetch: ${path}`);
    }));
    const root = document.createElement("div");
    document.body.append(root);
    mountedApp = createApp(App);
    mountedApp.mount(root);
    await settle();

    expect(root.querySelector(".auth-copy h1")?.textContent).toContain("Easy subscriptionEasy management");
    expect(root.querySelector(".auth-copy h1")?.textContent).not.toMatch(/[,.，。]/);
    expect(root.querySelector(".auth-copy")?.classList.contains("auth-copy-english")).toBe(true);
    expect(root.querySelector(".auth-copy > p")).toBeNull();
    expect(root.querySelector<HTMLInputElement>('input[autocomplete="username"]')?.value).toBe("");
  });

  it("keeps the shell usable and reports a partial data-load failure", async () => {
    vi.useFakeTimers();
    vi.stubGlobal("EventSource", FakeEventSource);
    const copyCommand = vi.fn(() => true);
    vi.stubGlobal("navigator", { ...window.navigator, clipboard: undefined });
    Object.defineProperty(document, "execCommand", { configurable: true, value: copyCommand });
    const confirmMock = vi.fn(() => false);
    let vpnGateCandidateIP = "198.51.100.40";
    let inspectionRisk = false;
    vi.stubGlobal("confirm", confirmMock);
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      if (path === "/api/v1/vpngate/regions" || path.startsWith("/api/v1/vpngate/regions?")) {
        return json([
          { code: "EE", name: "Estonia", nameZh: "爱沙尼亚", count: 1, availableCount: 1 },
          { code: "JP", name: "Japan", nameZh: "日本", count: 1, availableCount: 1 },
          { code: "US", name: "United States", nameZh: "美国", count: 2, availableCount: 2 }
        ]);
      }
      if (path.startsWith("/api/v1/vpngate/nodes?")) {
        return json([{ hostName: "vpn-test", ip: vpnGateCandidateIP, score: 100, ping: 20, speed: 10000000,
          countryLong: "Japan", countryShort: "JP", numVpnSessions: 1, hasOpenVpn: true }]);
      }
      if (path === "/api/v1/vpngate/inspect") {
        return json({
          candidateHostName: "vpn-test", candidateIp: "198.51.100.40", provider: "ip.net.coffee", checkedAt: "2026-08-02T00:00:00Z",
          vpngate: { score: 100, pingMs: 20, speedBitsPerSecond: 10000000, numVpnSessions: 1, uptimeSeconds: 1000, fetchedAt: "2026-08-02T00:00:00Z" },
          lookup: { ip: "198.51.100.40", country: "United States", countryCode: "US", region: "Virginia", city: "Ashburn",
            registeredCountry: "United States", registeredCountryCode: "US", trustScore: 96,
            isResidential: true, isDatacenter: false, isPublicService: false, isMobile: false,
            isVpn: false, isProxy: false, isTor: false, isAbuser: inspectionRisk, isCrawler: false,
            companyType: "isp", asnKind: "residential", cidr: "198.51.100.0/24",
            range: { first: "198.51.100.0", last: "198.51.100.255", count: 256 },
            asnIpv4Count: 1000000, estimatedBandwidth: "10-20Gbps", asnAllocated: "2001-01-01", rpkiStatus: "valid",
            intelligence: { threats: [], abuserLevel: inspectionRisk ? "high" : "safe", abuserScoreRaw: inspectionRisk ? "0.2" : "0.0001", httpblThreat: 0 },
            connection: { asn: "AS64500", asName: "EXAMPLE-NET", isp: "Example ISP", org: "Example ISP", companyName: "Example ISP Inc." } }
        });
      }
      if (path === "/api/v1/vpngate/refresh") {
        vpnGateCandidateIP = "198.51.100.41";
        return json({ count: 1 });
      }
      switch (path) {
      case "/api/v1/settings/language":
        return json({ language: init?.method === "PUT" ? "en" : "zh-CN" });
      case "/api/v1/auth/session":
        return json({ username: "admin", csrfToken: "csrf", setupRequired: false, adminPath: "manage-test", defaultCredentials: true });
      case "/api/v1/nodes":
        return json({ code: "internal_error", message: "节点加载失败" }, 500);
      case "/api/v1/system/status":
        return json({
          cpuPercent: 1, memory: { usedBytes: 1, totalBytes: 2, percent: 50 },
          disk: { usedBytes: 1, totalBytes: 2, percent: 50 },
          network: {
            uploadBytesPerSecond: 0, downloadBytesPerSecond: 0,
            uploadTotalBytes: 2147483648, downloadTotalBytes: 1073741824
          },
          uptimeSeconds: 1, load: [0, 0, 0],
          services: { jui: "active", singBox: "active", openVPN: "inactive", singBoxVersion: "1.13.16", configVersion: 1 },
          nodes: { total: 0, enabled: 0, faulted: 0 },
          exits: { total: 0, running: 0, faulted: 0 }, events: []
        });
      case "/api/v1/subscription":
        return json({
          token: "token", base64Path: "/sub/token?format=base64",
          v2rayNPath: "/sub/token?format=v2rayn",
          shadowrocketPath: "/sub/token?format=shadowrocket",
          clashPath: "/sub/token?format=clash",
          singBoxPath: "/sub/token?format=singbox"
        });
      case "/api/v1/system/info":
        return json({
          hostname: "test", os: "Linux", kernel: "test", arch: "amd64",
          ipv4: "10.0.0.8", ipv6: "2001:db8::8", countryCode: "CN", mockMode: true
        });
      case "/api/v1/settings/public-host":
        return json({ publicHost: "node.example.com" });
      case "/api/v1/settings/server-name":
        return json({ serverName: "云悠JP" });
      case "/api/v1/settings/country": {
        const body = init?.body ? JSON.parse(String(init.body)) as { countryCode: string } : { countryCode: "CN" };
        return json({ countryCode: body.countryCode.toUpperCase() });
      }
      case "/api/v1/settings/node-start-port":
        return json({ startPort: 8881, nextPort: 8882 });
      case "/api/v1/settings/protocol-prerequisites":
        return json({
          httpsIngressEnabled: false, httpsIngressDomain: "",
          cloudflareTunnelEnabled: false, cloudflareTunnelDomain: ""
        });
      case "/api/v1/system/logs?limit=200":
        return json({ logs: "j-ui test log" });
      default:
        throw new Error(`unexpected fetch: ${path}`);
      }
    }));

    const root = document.createElement("div");
    document.body.append(root);
    mountedApp = createApp(App);
    mountedApp.mount(root);
    await settle();

    expect(root.querySelector(".kui-shell")).not.toBeNull();
    expect(root.querySelector(".back-to-top svg path")).not.toBeNull();
    expect(root.querySelector(".back-to-top span")).toBeNull();
    expect(root.querySelector("aside")).toBeNull();
    expect(root.querySelector(".kui-tab-strip")).toBeNull();
    const headerModules = Array.from(root.querySelectorAll(".kui-header > .header-module"))
      .map(element => element.textContent?.trim());
    expect(headerModules).toHaveLength(3);
    expect(headerModules[0]).toContain("J-UI");
    expect(headerModules[0]).toContain("GitHub 仓库");
    expect(root.querySelector(".brand-module > .header-divider")).not.toBeNull();
    expect(headerModules[1]).toContain("状态重连中");
    expect(headerModules[2]).toContain("订阅链接");
    expect(root.querySelector(".status-pulse")?.classList.contains("reconnecting")).toBe(true);
    expect(root.querySelector(".alert.error")?.textContent).toContain("节点加载失败");
    expect(root.querySelector(".alert.error button")?.textContent).toContain("重试加载");
    expect(root.querySelector(".default-password-warning")?.textContent).toContain("当前密码为默认密码，请及时修改");
    expect(root.textContent).toContain("1.13.16");
    expect(root.querySelector("#system-status-section h2")?.textContent).toBe("系统状态");
    expect(root.textContent).toContain("一键创建常用节点");
    expect(root.textContent).toContain("自定义节点");
    expect(root.querySelector("#outbounds-section h2")?.textContent).toBe("住宅ip代理设置");
    expect(root.querySelector("#outbounds-section")?.textContent).toContain("VPNGate IP");
    expect(root.querySelector("#outbounds-section")?.textContent).toContain("最多同时创建 5 个不同 IP 的隧道");
    expect(root.querySelector("#outbounds-section")?.textContent).toContain("手动上游代理");
    expect(root.querySelector("#outbounds-section")?.textContent).toContain("绑定当前节点");
    expect(root.querySelector("#outbounds-section")?.textContent).toContain("新建节点展示");
    expect(root.querySelector("#outbounds-section")?.textContent).not.toContain("可用出口");
    const vpnGateIPInput = [...root.querySelectorAll("#outbounds-section label")]
      .find(label => label.textContent?.includes("VPNGate IP"))?.querySelector("input");
    expect(vpnGateIPInput?.readOnly).toBe(true);
    (root.querySelector("[aria-label='展开国家或地区']") as HTMLButtonElement).click();
    await nextTick();
    expect(root.querySelector("#outbounds-section")?.textContent)
      .toContain("US · United States（美国） · 总计 2");
    expect(root.querySelector("#outbounds-section")?.textContent)
      .toContain("EE · Estonia（爱沙尼亚） · 总计 1");
    expect(root.querySelector("#outbounds-section")?.textContent).not.toContain("可用 2");
    expect(root.querySelector("#outbounds-section select")).toBeNull();
    const inspectButton = root.querySelector<HTMLButtonElement>(".ip-inspection-button");
    expect(inspectButton?.textContent).toContain("IP 信息检测");
    const failurePolicy = [...root.querySelectorAll("#outbounds-section label")]
      .find(label => label.textContent?.includes("故障策略"));
    expect(failurePolicy).toBeTruthy();
    expect(inspectButton).toBeTruthy();
    expect(failurePolicy!.compareDocumentPosition(inspectButton!) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    inspectButton?.click();
    await settle();
    expect(root.querySelector(".ip-inspection-card")?.textContent).toContain("AS64500");
    expect(vpnGateIPInput?.value).toContain("20 ms");
    expect(vpnGateIPInput?.value).toContain("10.0 Mbps");
    expect(root.querySelector(".candidate-report")?.textContent).toContain("以上延迟和速度由 VPNGate 提供，不代表真实连接速度");
    expect(root.querySelector(".ip-inspection-card")?.textContent).not.toContain("组织域名");
    expect(root.querySelector(".ip-inspection-card")?.textContent).not.toContain("时区");
    expect(root.querySelector(".ip-inspection-card")?.textContent).not.toContain("VPS 实测");
    expect(root.querySelector(".ip-inspection-card")?.textContent).not.toContain("信息一致");
    expect(root.querySelector(".ip-inspection-card")?.textContent).toContain("使用场景 / 类型");
    expect(root.querySelector(".ip-inspection-card")?.textContent).toContain("ASN / 运营商");
    expect(root.querySelector(".ip-inspection-card")?.textContent).toContain("IP 情报（威胁指标）");
    expect(root.querySelector(".ip-inspection-card")?.textContent).toContain("风险深度检测");
    expect(root.querySelector(".ip-inspection-card")?.textContent).not.toContain("技术指标");
    expect(root.querySelector(".ip-inspection-card")?.textContent).toContain("以上信息均由ip.net.coffee 提供，不保证真实性，请自行判断。");
    const titleLine = root.querySelector(".ip-inspection-title-line");
    expect(titleLine?.children[0]?.tagName).toBe("H3");
    expect(titleLine?.children[1]?.classList.contains("inspection-score")).toBe(true);
    expect(root.querySelector(".inspection-score")?.classList.contains("risk")).toBe(false);
    const collapseButton = root.querySelector<HTMLButtonElement>(".ip-inspection-collapse");
    collapseButton?.click();
    await nextTick();
    expect(collapseButton?.getAttribute("aria-expanded")).toBe("false");
    expect((root.querySelector(".ip-inspection-body") as HTMLElement).style.display).toBe("none");
    collapseButton?.click();
    inspectionRisk = true;
    inspectButton?.click();
    await settle();
    expect(root.querySelector(".inspection-score")?.classList.contains("risk")).toBe(true);
    expect(root.querySelector(".ip-inspection-card")?.textContent).toContain("高风险");
    (root.querySelector(".residential-refresh-button") as HTMLButtonElement).click();
    await settle();
    expect(root.querySelector(".ip-inspection-card")).toBeNull();
    (root.querySelector("[aria-label='展开有效期']") as HTMLButtonElement).click();
    await nextTick();
    expect(root.querySelector("#residential-duration-menu")?.textContent).toContain("永久");
    (root.querySelector("#residential-duration-menu [data-value='0']") as HTMLButtonElement).click();
    await nextTick();
    expect(confirmMock).toHaveBeenCalledTimes(1);
    expect(root.querySelector<HTMLInputElement>("#outbounds-section label:nth-child(2) input")?.value).toBe("30 分钟");
    confirmMock.mockReturnValue(true);
    (root.querySelector("[aria-label='展开有效期']") as HTMLButtonElement).click();
    await nextTick();
    (root.querySelector("#residential-duration-menu [data-value='0']") as HTMLButtonElement).click();
    await nextTick();
    expect(root.querySelector<HTMLInputElement>("#outbounds-section label:nth-child(2) input")?.value).toBe("永久");
    const manualSourceButton = Array.from(root.querySelectorAll<HTMLButtonElement>(".residential-source-switch button"))
      .find(button => button.textContent?.includes("手动上游代理"));
    manualSourceButton?.click();
    await nextTick();
    expect(root.querySelector("#residential-duration-menu")).toBeNull();
    expect(root.querySelector(".residential-core-fields")?.classList.contains("single-column")).toBe(true);
    const manualProxyLabels = Array.from(root.querySelectorAll<HTMLLabelElement>("#outbounds-section label"));
    const manualProxyServer = manualProxyLabels.find(label => label.textContent?.includes("代理 IP / 域名"))
      ?.querySelector<HTMLInputElement>("input");
    const manualProxyPort = manualProxyLabels.find(label => label.textContent?.includes("代理端口"))
      ?.querySelector<HTMLInputElement>("input");
    expect(manualProxyServer).toBeTruthy();
    expect(manualProxyPort).toBeTruthy();
    manualProxyServer!.value = "103.11.122.244:443";
    manualProxyServer!.dispatchEvent(new Event("input", { bubbles: true }));
    manualProxyServer!.dispatchEvent(new FocusEvent("blur", { bubbles: true }));
    await nextTick();
    expect(manualProxyServer!.value).toBe("103.11.122.244");
    expect(manualProxyPort!.value).toBe("443");
    expect(root.textContent).not.toContain("运行概览");
    expect(root.textContent).not.toContain("实时监控");
    expect(root.textContent).not.toContain("最近配置事件");
    expect(root.querySelector(".status-summary-grid")).toBeNull();
    expect(root.querySelector(".server-title > h3")?.textContent).toBe("云悠JP");
    expect(root.querySelector(".server-title > .server-dot")).not.toBeNull();
    expect(root.querySelector(".server-title > .country-flag")?.textContent).toBe("🇨🇳");
    expect(root.querySelector(".server-title > .country-flag")?.getAttribute("aria-label")).toBe("CN 国旗");
    expect(root.querySelector(".server-title")?.textContent).not.toContain("当前服务器");
    expect(root.querySelector(".server-facts")?.textContent).toContain("在线节点");
    expect(root.querySelector(".server-facts")?.textContent).toContain("sing-box");
    expect(root.querySelector(".network-facts")?.textContent).toContain("实时下载");
    expect(root.querySelector(".network-facts")?.textContent).toContain("实时上传");
    expect(root.querySelector(".network-facts")?.textContent).toContain("总计流量 (入 | 出)");
    expect(root.querySelector(".total-traffic")?.textContent).toContain("1.0 GB");
    expect(root.querySelector(".total-traffic")?.textContent).toContain("2.0 GB");
    expect(root.querySelector(".total-traffic")?.textContent).not.toContain("3.0 GB");
    expect(root.querySelector(".core-facts")).toBeNull();
    const publicAddress = root.querySelector("[data-testid='public-address']");
    expect(publicAddress?.textContent).toContain("主机: node.example.com");
    expect(publicAddress?.textContent).toContain("IPv4: 10.0.0.8");
    expect(publicAddress?.textContent).toContain("IPv6: 2001:db8::8");
    expect(publicAddress?.classList.contains("blurred")).toBe(true);
    (root.querySelector("[aria-label='显示 IP 地址']") as HTMLButtonElement).click();
    await nextTick();
    expect(publicAddress?.classList.contains("blurred")).toBe(false);
    expect(window.localStorage.getItem("jui-public-address-visible")).toBe("true");
    expect(root.querySelector("#subscription-section")).toBeNull();
    expect(root.textContent).not.toContain("订阅管理");

    (root.querySelector("[aria-label='显示订阅链接']") as HTMLButtonElement).click();
    await nextTick();
    const linkModal = root.querySelector(".subscription-links-modal");
    expect(linkModal?.textContent).toContain("普通订阅");
    expect(linkModal?.textContent).toContain("v2rayN");
    expect(linkModal?.textContent).toContain("Shadowrocket");
    expect(linkModal?.textContent).toContain("Clash");
    expect(linkModal?.textContent).toContain("sing-box");
    const urls = Array.from(linkModal?.querySelectorAll("code") ?? [])
      .map(element => element.textContent);
    expect(urls).toEqual([
      new URL("/sub/token?format=base64", location.origin).toString(),
      new URL("/sub/token?format=v2rayn", location.origin).toString(),
      new URL("/sub/token?format=shadowrocket", location.origin).toString(),
      new URL("/sub/token?format=clash", location.origin).toString(),
      new URL("/sub/token?format=singbox", location.origin).toString()
    ]);
    const copyButton = linkModal?.querySelector<HTMLButtonElement>(".copy-field button");
    copyButton?.click();
    await settle();
    expect(copyCommand).toHaveBeenCalledWith("copy");
    expect(copyButton?.textContent).toContain("已复制");
    expect(copyButton?.classList.contains("copied")).toBe(true);
    (linkModal?.querySelector(".header-button") as HTMLButtonElement).click();
    await nextTick();

    const themeButton = root.querySelector("[aria-label='切换为夜间模式']") as HTMLButtonElement;
    expect(themeButton.textContent).toContain("☀️日间");
    themeButton.click();
    await nextTick();
    expect(document.documentElement.dataset.theme).toBe("dark");
    expect(window.localStorage.getItem("jui-theme")).toBe("dark");
    expect(themeButton.textContent).toContain("🌙夜间");

    (root.querySelector("[aria-label='显示订阅二维码']") as HTMLButtonElement).click();
    await nextTick();
    const qrModal = root.querySelector(".subscription-qr-modal");
    expect(qrModal?.textContent).toContain("订阅二维码");
    expect(qrModal?.querySelectorAll(".qr-format-tabs button")).toHaveLength(5);
    expect(root.querySelector(".qr-code-surface svg")).not.toBeNull();
    const ordinaryQRPath = qrModal?.querySelector(".qr-code-surface svg > path")?.getAttribute("d");
    const shadowrocketQRButton = Array.from(qrModal?.querySelectorAll<HTMLButtonElement>(".qr-format-tabs button") ?? [])
      .find(button => button.textContent?.includes("Shadowrocket"));
    shadowrocketQRButton?.click();
    await nextTick();
    expect(shadowrocketQRButton?.classList.contains("active")).toBe(true);
    expect(qrModal?.querySelector(".qr-code-surface svg > path")?.getAttribute("d")).not.toBe(ordinaryQRPath);
    expect(qrModal?.querySelector(".copy-field")).toBeNull();
    (qrModal?.querySelector(".header-button") as HTMLButtonElement).click();
    await nextTick();

    vi.advanceTimersByTime(5000);
    await nextTick();
    expect(root.querySelector(".alert.warning:not(.default-password-warning)")?.textContent).toContain("当前指标可能已经过期");

    const actions = Array.from(root.querySelectorAll(".header-actions button"))
      .map(button => button.getAttribute("aria-label"));
    expect(actions.indexOf("系统设置")).toBeLessThan(actions.indexOf("退出"));
    (root.querySelector("[aria-label='系统设置']") as HTMLButtonElement).click();
    await nextTick();
    const settingsModal = root.querySelector(".settings-modal");
    expect(settingsModal?.textContent).toContain("系统操作");
    expect(settingsModal?.textContent).not.toContain("备份、日志、更新与服务控制。");
    expect(settingsModal?.textContent).toContain("语言");
    expect(settingsModal?.querySelector<HTMLInputElement>(".settings-language input")?.value).toBe("简体中文");
    expect(settingsModal?.textContent).toContain("重启面板");
    expect(settingsModal?.textContent).toContain("基础配置");
    expect(settingsModal?.textContent).toContain("协议与安全");
    expect(settingsModal?.querySelector(".security-settings-group")).not.toBeNull();
    expect(settingsModal?.querySelectorAll(".security-password-fields input")).toHaveLength(2);
    expect(settingsModal?.textContent).not.toContain("最近配置事件");
    expect(settingsModal?.textContent).toContain("节点起始端口");
    const basicSettingsGroup = settingsModal?.querySelectorAll(".settings-group")[0];
    const basicSettingsHeadings = Array.from(basicSettingsGroup?.querySelectorAll(".settings-subsection h4") ?? [])
      .map(heading => heading.textContent?.trim());
    expect(basicSettingsHeadings).toEqual(["账号 ID：admin", "服务器名称", "公网地址", "节点起始端口"]);
    expect(settingsModal?.querySelector(".account-id-heading strong")?.textContent).toBe("admin");
    const accountCountrySection = settingsModal?.querySelector(".account-country-subsection");
    expect(accountCountrySection?.children[0]?.classList.contains("account-id-heading")).toBe(true);
    expect(accountCountrySection?.children[1]?.classList.contains("country-setting")).toBe(true);
    expect(settingsModal?.querySelector<HTMLInputElement>(".country-setting input")?.value).toBe("CN · 中国");
    expect(settingsModal?.querySelector(".country-setting .dropdown-selected-icon")?.textContent).toBe("🇨🇳");
    (settingsModal?.querySelector(".country-setting .dropdown-trigger") as HTMLButtonElement).click();
    await nextTick();
    expect(settingsModal?.querySelector("#country-setting-menu")?.textContent).toContain("JP · 日本");
    const countryCodes = Array.from(settingsModal?.querySelectorAll<HTMLElement>("#country-setting-menu .dropdown-option") ?? [])
      .slice(0, 3).map(option => option.dataset.value);
    expect(countryCodes).toEqual(["AD", "AE", "AF"]);
    const allCountryCodes = Array.from(settingsModal?.querySelectorAll<HTMLElement>("#country-setting-menu .dropdown-option") ?? [])
      .map(option => option.dataset.value);
    expect(allCountryCodes).toHaveLength(249);
    expect(new Set(allCountryCodes).size).toBe(allCountryCodes.length);
    expect(allCountryCodes).not.toEqual(expect.arrayContaining(["AC", "CQ", "CS", "DD"]));
    const countryInput = settingsModal?.querySelector<HTMLInputElement>(".country-setting input") as HTMLInputElement;
    countryInput.value = "中国";
    countryInput.dispatchEvent(new Event("input", { bubbles: true }));
    await nextTick();
    expect(settingsModal?.querySelectorAll("#country-setting-menu .dropdown-option").length).toBeGreaterThan(0);
    expect(settingsModal?.querySelector("#country-setting-menu .dropdown-option")?.textContent).toContain("CN · 中国");
    expect(settingsModal?.querySelector(".country-setting button.primary")).toBeNull();
    countryInput.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
    await settle();
    expect(countryInput.value).toBe("CN · 中国");
    expect(root.querySelector(".alert.success")?.textContent).toContain("国家已更新");
    vi.advanceTimersByTime(3001);
    await nextTick();
    expect(root.querySelector(".alert.success")).toBeNull();
    expect(settingsModal?.querySelector("input[aria-readonly='true']")).toBeNull();
    expect(settingsModal?.textContent).toContain("下一个可用端口8882");
    expect(settingsModal?.textContent).toContain("协议前置配置");
    expect(settingsModal?.textContent).toContain("所有协议均已解锁");
    expect(settingsModal?.textContent).toContain("HTTPS 公网域名");
    expect(settingsModal?.textContent).toContain("Tunnel 公网域名");
    const argoGuide = settingsModal?.querySelector<HTMLAnchorElement>(".argo-guide-link");
    expect(argoGuide?.textContent).toContain("跳转 GitHub 查看教程");
    expect(argoGuide?.classList.contains("primary")).toBe(true);
    expect(argoGuide?.href).toBe("https://github.com/Suparluxi/j-ui/blob/main/docs/argo-quickstart.zh-CN.md");
    expect(argoGuide?.target).toBe("_blank");
    expect(settingsModal?.querySelectorAll(".protocol-prerequisites input[type='checkbox']")).toHaveLength(0);
    expect(settingsModal?.querySelectorAll(".prerequisite-card")).toHaveLength(2);
    expect(settingsModal?.textContent).not.toContain("Ubuntu");
    expect(settingsModal?.textContent).not.toContain("虚拟化");
    expect(root.querySelector(".eyebrow")).toBeNull();
    const readLogsButton = Array.from(settingsModal?.querySelectorAll<HTMLButtonElement>("button") ?? [])
      .find(button => button.textContent?.includes("读取日志"));
    readLogsButton?.click();
    await settle();
    expect(root.querySelector(".logs-modal")?.textContent).toContain("j-ui test log");
    expect(settingsModal?.querySelector(".logs")).toBeNull();

    (settingsModal?.querySelector(".settings-language .dropdown-trigger") as HTMLButtonElement).click();
    await nextTick();
    (settingsModal?.querySelector(".settings-language [data-value='en']") as HTMLButtonElement).click();
    await settle();
    expect(document.documentElement.lang).toBe("en");
    expect(root.querySelector("#system-settings-title")?.textContent).toBe("System Settings");
    expect(root.querySelector("[aria-label='System Settings']")?.textContent).toContain("Settings");
    expect(root.querySelector("[aria-label='GitHub']")?.textContent).toContain("GitHub");
    expect(root.querySelector(".monitor-module")?.textContent).toContain("Retrying");
    expect(settingsModal?.querySelector<HTMLInputElement>(".country-setting input")?.value).toBe("CN · China");
  });

  it("keeps a VPNGate creation job alive across transient polling fetch failures", async () => {
    vi.useFakeTimers();
    vi.stubGlobal("EventSource", FakeEventSource);
    let jobPolls = 0;
    const candidate = {
      hostName: "vpn-test", ip: "198.51.100.40", score: 100, ping: 20, speed: 10000000,
      countryLong: "Japan", countryShort: "JP", numVpnSessions: 1, hasOpenVpn: true
    };
    const regularNode = {
      id: 1, name: "J-UI丨XTLS-Reality_8881", protocol: "vless_reality", listen: "0.0.0.0", port: 8881,
      enabled: true, status: "running", settings: {}, listenerStatus: "listening", publicConnectivity: "reachable",
      externalAddress: "198.51.100.10:8881", currentOutbound: "native"
    };
    const createdNode = {
      id: 2, name: "J-UI丨S-JP丨XTLS-Reality_8882", protocol: "vless_reality", listen: "0.0.0.0", port: 8882,
      enabled: true, status: "running", settings: {
        jui_temporary_source: "vpngate", jui_temporary_expires_at: "2099-01-01T00:00:00Z"
      }, listenerStatus: "listening", publicConnectivity: "reachable", externalAddress: "198.51.100.10:8882",
      currentOutbound: "vpn-test", outboundId: 1
    };
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      if (path === "/api/v1/settings/language") return json({ language: "zh-CN" });
      if (path === "/api/v1/auth/session") {
        return json({ username: "admin", csrfToken: "csrf", setupRequired: false, adminPath: "manage-test", defaultCredentials: false });
      }
      if (path === "/api/v1/vpngate/regions") return json([{ code: "JP", name: "Japan", nameZh: "日本", count: 1, availableCount: 1 }]);
      if (path.startsWith("/api/v1/vpngate/nodes?")) return json([candidate]);
      if (path === "/api/v1/nodes") return json([regularNode, createdNode]);
      if (path === "/api/v1/outbounds") return json([{ id: 1, name: "vpn-test", type: "socks5", server: "10.254.1.2", port: 1080,
        enabled: true, hasCredential: true, status: "running", observedIp: "198.51.100.40", managedKind: "vpngate" }]);
      if (path === "/api/v1/system/status") return json({
        cpuPercent: 1, memory: { usedBytes: 1, totalBytes: 2, percent: 50 }, disk: { usedBytes: 1, totalBytes: 2, percent: 50 },
        network: { uploadBytesPerSecond: 0, downloadBytesPerSecond: 0, uploadTotalBytes: 1, downloadTotalBytes: 1 },
        uptimeSeconds: 1, load: [0, 0, 0],
        services: { jui: "active", singBox: "active", openVPN: "active", singBoxVersion: "1.13.16", configVersion: 1 },
        nodes: { total: 2, enabled: 2, faulted: 0 }, exits: { total: 1, running: 1, faulted: 0 }, events: []
      });
      if (path === "/api/v1/subscription") return json({ token: "token", base64Path: "/sub/token?format=base64",
        v2rayNPath: "/sub/token?format=v2rayn", shadowrocketPath: "/sub/token?format=shadowrocket",
        clashPath: "/sub/token?format=clash", singBoxPath: "/sub/token?format=singbox" });
      if (path === "/api/v1/system/info") return json({ hostname: "test", os: "Linux", kernel: "test", arch: "amd64", ipv4: "198.51.100.10", ipv6: "", countryCode: "JP", mockMode: true });
      if (path === "/api/v1/settings/public-host") return json({ publicHost: "198.51.100.10" });
      if (path === "/api/v1/settings/server-name") return json({ serverName: "J-UI" });
      if (path === "/api/v1/settings/country") return json({ countryCode: "JP" });
      if (path === "/api/v1/settings/node-start-port") return json({ startPort: 8881, nextPort: 8883 });
      if (path === "/api/v1/settings/protocol-prerequisites") return json({
        httpsIngressEnabled: false, httpsIngressDomain: "", cloudflareTunnelEnabled: false, cloudflareTunnelDomain: "",
        certificateMode: "auto", certificateReady: true
      });
      if (path === "/api/v1/residential-nodes/vpngate" && init?.method === "POST") {
        return json({ id: "job-test", status: "queued", message: "住宅节点创建任务已排队", createdAt: "2026-08-22T00:00:00Z", updatedAt: "2026-08-22T00:00:00Z" }, 202);
      }
      if (path === "/api/v1/residential-nodes/jobs/job-test") {
        jobPolls += 1;
        if (jobPolls <= 5) throw new TypeError("Failed to fetch");
        return json({ id: "job-test", status: "succeeded", message: "住宅节点创建完成", createdAt: "2026-08-22T00:00:00Z", updatedAt: "2026-08-22T00:00:20Z", node: createdNode, uri: "vless://test", source: "vpngate", country: "JP", exitId: 1 });
      }
      throw new Error(`unexpected fetch: ${path}`);
    }));

    const root = document.createElement("div");
    document.body.append(root);
    mountedApp = createApp(App);
    mountedApp.mount(root);
    await settle();

    root.querySelector<HTMLFormElement>(".residential-builder")?.dispatchEvent(new Event("submit", { bubbles: true }));
    await settle();
    await vi.advanceTimersByTimeAsync(4000);
    await nextTick();
    expect(jobPolls).toBe(5);
    expect(root.querySelector(".residential-form-error")).toBeNull();
    expect(root.querySelector(".residential-job-progress")?.textContent).toContain("等待 VPS");

    await vi.advanceTimersByTimeAsync(1000);
    await settle();
    expect(jobPolls).toBe(6);
    expect(root.querySelector(".residential-form-error")).toBeNull();
    expect(root.querySelector(".alert.success")?.textContent).toContain("住宅节点已创建");
  });
});
