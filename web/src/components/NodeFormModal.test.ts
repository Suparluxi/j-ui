import { createApp, h, nextTick, type App } from "vue";
import { afterEach, describe, expect, it } from "vitest";
import NodeFormModal from "./NodeFormModal.vue";

let mountedApp: App<Element> | null = null;

afterEach(() => {
  mountedApp?.unmount();
  mountedApp = null;
  document.body.innerHTML = "";
});

function mountForm(
  onSubmit: (payload: Record<string, unknown>) => void,
  publicHost = "127.0.0.1",
  mockMode = true,
  prerequisites: Partial<{
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
  }> = {},
  theme: "light" | "dark" = "light"
): HTMLElement {
  const root = document.createElement("div");
  document.body.append(root);
  mountedApp = createApp({
    render: () => h(NodeFormModal, {
      node: null,
      error: "",
      submitting: false,
      hostName: "test-host",
      publicHost,
      nextPort: 8881,
      usedPorts: [],
      mockMode,
      httpsIngressEnabled: prerequisites.httpsIngressEnabled ?? false,
      httpsIngressDomain: prerequisites.httpsIngressDomain ?? "",
      cloudflareTunnelEnabled: prerequisites.cloudflareTunnelEnabled ?? false,
      cloudflareTunnelDomain: prerequisites.cloudflareTunnelDomain ?? "",
      cloudflareTunnelOriginPort: prerequisites.cloudflareTunnelOriginPort ?? 0,
      certificateModeDefault: prerequisites.certificateModeDefault ?? "auto",
      certificatePathDefault: prerequisites.certificatePathDefault ?? "",
      certificateKeyPathDefault: prerequisites.certificateKeyPathDefault ?? "",
      certificateReady: prerequisites.certificateReady ?? mockMode,
      certificateServerName: prerequisites.certificateServerName ?? (mockMode ? publicHost : ""),
      theme,
      language: "zh-CN",
      onSubmit
    })
  });
  mountedApp.mount(root);
  return root;
}

function inputFor(root: HTMLElement, labelText: string): HTMLInputElement {
  const label = [...root.querySelectorAll("label")].find(item =>
    item.textContent?.includes(labelText)
  );
  const input = label?.querySelector("input");
  if (!(input instanceof HTMLInputElement)) throw new Error(`missing input: ${labelText}`);
  return input;
}

function setInput(input: HTMLInputElement, value: string): void {
  input.value = value;
  input.dispatchEvent(new Event("input", { bubbles: true }));
}

async function selectProtocol(root: HTMLElement, name: string): Promise<void> {
  if (!root.querySelector("#node-protocol-menu")) {
    root.querySelector<HTMLButtonElement>(".protocol-select-label .dropdown-trigger")?.click();
    await nextTick();
  }
  const option = [...root.querySelectorAll<HTMLButtonElement>("#node-protocol-menu .dropdown-option")]
    .find(item => item.textContent?.includes(name));
  if (!option) throw new Error(`missing protocol: ${name}`);
  option.click();
  await nextTick();
}

async function protocolOptions(root: HTMLElement): Promise<HTMLButtonElement[]> {
  root.querySelector<HTMLButtonElement>(".protocol-select-label .dropdown-trigger")?.click();
  await nextTick();
  return [...root.querySelectorAll<HTMLButtonElement>("#node-protocol-menu .dropdown-option")];
}

describe("NodeFormModal", () => {
  it("applies the theme supplied by the main page", () => {
    const root = mountForm(() => undefined, "127.0.0.1", true, {}, "dark");
    expect(root.querySelector(".node-form-backdrop")?.classList.contains("theme-dark")).toBe(true);
  });

  it("generates a named Reality preset before showing advanced settings", async () => {
    let submitted: Record<string, unknown> | null = null;
    const root = mountForm(payload => { submitted = payload; });
    expect(root.textContent).not.toContain("高级配置");
    const protocolInput = root.querySelector<HTMLInputElement>(".protocol-select-label .dropdown-field input");
    expect(protocolInput?.value).toBe("");
    expect(protocolInput?.readOnly).toBe(true);
    expect(root.querySelector("select")).toBeNull();
    await selectProtocol(root, "XTLS+Reality");
    root.querySelector<HTMLButtonElement>(".protocol-confirm-button")?.click();
    await nextTick();

    expect(root.textContent).toContain("高级配置");
    expect(root.textContent).toContain("自动配置项");
    expect(root.textContent).toContain("必要配置");
    expect(root.textContent).toContain("可选项目");
    expect(inputFor(root, "节点名称").value).toBe("test-host丨XTLS+Reality_8881");
    expect(inputFor(root, "监听端口").disabled).toBe(true);
    expect(inputFor(root, "UUID").value).toMatch(/^[0-9a-f-]{36}$/);
    expect(inputFor(root, "UUID").disabled).toBe(true);
    const visibilityButton = root.querySelector<HTMLButtonElement>(".credential-visibility-button");
    expect(inputFor(root, "UUID").type).toBe("password");
    visibilityButton?.click();
    await nextTick();
    expect(inputFor(root, "UUID").type).toBe("text");
    expect(visibilityButton?.textContent).toContain("隐藏凭据");
    visibilityButton?.click();
    await nextTick();
    expect(inputFor(root, "UUID").type).toBe("password");
    expect(root.textContent).not.toContain("创建后立即启用");
    expect(root.textContent).not.toContain("CONFIG SUMMARY");
    expect(root.querySelector(".node-summary")).toBeNull();
    root.querySelector<HTMLButtonElement>(".automatic-edit-button")?.click();
    await nextTick();
    const portInput = inputFor(root, "监听端口");
    expect(portInput.disabled).toBe(false);
    setInput(portInput, "24443");
    await nextTick();
    expect(root.querySelector("[role='dialog']")).toBeNull();
    expect(inputFor(root, "节点名称").value).toBe("test-host丨XTLS+Reality_24443");
    root.querySelector("form")?.dispatchEvent(new Event("submit", { bubbles: true }));
    await nextTick();

    expect(submitted).toMatchObject({
      name: "test-host丨XTLS+Reality_24443",
      protocol: "vless_reality",
      listen: "0.0.0.0",
      port: 24443,
      enabled: true,
      settings: {
        handshake_server: "www.visa.com.sg",
        handshake_port: 443,
        server_name: "www.visa.com.sg"
      }
    });
    const targetInput = inputFor(root, "Reality 目标网站");
    expect(targetInput.value).toBe("www.visa.com.sg");
    expect(targetInput.readOnly).toBe(false);
    [...root.querySelectorAll("label")].find(item => item.textContent?.includes("Reality 目标网站"))
      ?.querySelector<HTMLButtonElement>(".dropdown-trigger")?.click();
    await nextTick();
    expect(root.querySelector("#node-reality-target-menu")?.previousElementSibling?.classList.contains("open")).toBe(true);
    expect(root.querySelector("#node-reality-target-menu")?.parentElement?.querySelector(".dropdown-trigger svg")).not.toBeNull();
    expect([...root.querySelectorAll<HTMLButtonElement>("#node-reality-target-menu .dropdown-option")]
      .map(option => option.textContent?.trim())).toEqual([
      "www.visa.com.sg", "www.microsoft.com", "www.apple.com", "www.amazon.com", "www.samsung.com",
      "www.cloudflare.com", "www.intel.com", "www.nvidia.com", "www.amd.com", "aws.amazon.com", "www.sony.com"
    ]);
    expect((submitted as { credential: { uuid: string } } | null)?.credential.uuid).toMatch(/^[0-9a-f-]{36}$/);
  });

  it("shows the requested protocols in a dropdown", async () => {
    const root = mountForm(() => undefined, "node.example.com");
    const options = await protocolOptions(root);
    expect(options.map(option => option.dataset.value)).toEqual([
      "vless_reality", "hysteria2", "tuic", "trojan_tls", "vless_grpc_reality",
      "anytls", "anytls_reality", "vless_ws_tls",
      "vless_argo"
    ]);
    expect(options.map(option => option.textContent?.trim().split("（")[0])).toEqual([
      "XTLS+Reality", "Hysteria2", "TUIC", "Trojan", "gRPC+Reality",
      "AnyTLS", "AnyTLS+Reality", "VLESS-WS", "Argo"
    ]);
    expect(options.every(option => option.disabled === false)).toBe(true);
    for (const protocol of ["XTLS", "Hysteria2", "TUIC", "Trojan", "gRPC", "AnyTLS", "AnyTLS+"]) {
      await selectProtocol(root, protocol);
      root.querySelector<HTMLButtonElement>(".protocol-confirm-button")?.click();
      await nextTick();
      if (["Hysteria2", "TUIC", "Trojan", "AnyTLS", "VLESS-WS"].includes(protocol)) {
        const certificateMode = [...root.querySelectorAll("label")]
          .find(item => item.textContent?.includes("证书方式"))?.querySelector<HTMLInputElement>("input");
        expect(certificateMode?.value).toBe("自动配置");
        expect(inputFor(root, "证书域名").value).toBe("node.example.com");
      }
      root.querySelector<HTMLButtonElement>(".change-protocol-button")?.click();
      await nextTick();
    }
  });

  it("disables certificate protocols without a server domain", async () => {
    const root = mountForm(() => undefined, "127.0.0.1", false);
    const options = await protocolOptions(root);
    for (const protocol of ["hysteria2", "tuic", "trojan_tls", "anytls", "vless_ws_tls", "vless_argo"]) {
      expect(options.find(option => option.dataset.value === protocol)?.disabled).toBe(true);
    }
    for (const protocol of ["vless_reality", "vless_grpc_reality", "anytls_reality"]) {
      expect(options.find(option => option.dataset.value === protocol)?.disabled).toBe(false);
    }
    const firstDisabled = options.findIndex(option => option.disabled);
    expect(firstDisabled).toBeGreaterThan(0);
    expect(options.slice(firstDisabled).every(option => option.disabled)).toBe(true);

    options.find(option => option.dataset.value === "hysteria2")?.click();
    await nextTick();
    expect(root.querySelector<HTMLInputElement>(".protocol-select-label input")?.value).toBe("");
    expect(root.querySelector<HTMLButtonElement>(".protocol-confirm-button")?.disabled).toBe(true);
    root.querySelector<HTMLButtonElement>(".protocol-confirm-button")?.click();
    await nextTick();
    expect(root.textContent).not.toContain("高级配置");
  });

  it("unlocks TLS protocols when the installer issued an IPv4 certificate", async () => {
    const root = mountForm(() => undefined, "198.51.100.10", false, {
      certificateReady: true,
      certificateServerName: "198.51.100.10"
    });
    const options = await protocolOptions(root);
    for (const protocol of ["hysteria2", "tuic", "trojan_tls", "anytls"]) {
      expect(options.find(option => option.dataset.value === protocol)?.disabled).toBe(false);
    }
    expect(options.find(option => option.dataset.value === "vless_ws_tls")?.disabled).toBe(true);
    expect(options.find(option => option.dataset.value === "vless_argo")?.disabled).toBe(true);
    await selectProtocol(root, "Hysteria2");
    root.querySelector<HTMLButtonElement>(".protocol-confirm-button")?.click();
    await nextTick();
    expect(inputFor(root, "证书域名").value).toBe("198.51.100.10");
  });

  it("unlocks every protocol in mock mode", async () => {
    const root = mountForm(() => undefined);
    const options = await protocolOptions(root);
    expect(options).toHaveLength(9);
    expect(options.every(option => !option.disabled)).toBe(true);
  });

  it("uses saved ingress prerequisites outside mock mode", async () => {
    const root = mountForm(() => undefined, "203.0.113.10", false, {
      httpsIngressEnabled: true,
      httpsIngressDomain: "ws.example.com",
      cloudflareTunnelEnabled: true,
      cloudflareTunnelDomain: "argo.example.com"
    });
    const options = await protocolOptions(root);
    expect(options.find(option => option.dataset.value === "vless_ws_tls")?.disabled).toBe(false);
    expect(options.find(option => option.dataset.value === "vless_argo")?.disabled).toBe(false);
    options.find(option => option.dataset.value === "vless_ws_tls")?.click();
    await nextTick();
    root.querySelector<HTMLButtonElement>(".protocol-confirm-button")?.click();
    await nextTick();
    expect(inputFor(root, "证书域名 / SNI").value).toBe("ws.example.com");
    expect(inputFor(root, "监听端口").value).toBe("8443");
  });

  it("does not trust stale domains or use Tunnel as an HTTPS prerequisite", async () => {
    const staleRoot = mountForm(() => undefined, "203.0.113.10", false, {
      httpsIngressEnabled: false,
      httpsIngressDomain: "stale.example.com",
      cloudflareTunnelEnabled: false,
      cloudflareTunnelDomain: "stale-argo.example.com"
    });
    let options = await protocolOptions(staleRoot);
    expect(options.find(option => option.dataset.value === "vless_ws_tls")?.disabled).toBe(true);
    expect(options.find(option => option.dataset.value === "vless_argo")?.disabled).toBe(true);
    mountedApp?.unmount();
    mountedApp = null;
    document.body.innerHTML = "";

    const tunnelRoot = mountForm(() => undefined, "node.example.com", false, {
      httpsIngressEnabled: false,
      cloudflareTunnelEnabled: true,
      cloudflareTunnelDomain: "argo.example.com",
      cloudflareTunnelOriginPort: 2080
    });
    options = await protocolOptions(tunnelRoot);
    expect(options.find(option => option.dataset.value === "vless_ws_tls")?.disabled).toBe(true);
    expect(options.find(option => option.dataset.value === "vless_argo")?.disabled).toBe(false);
    options.find(option => option.dataset.value === "vless_argo")?.click();
    await nextTick();
    tunnelRoot.querySelector<HTMLButtonElement>(".protocol-confirm-button")?.click();
    await nextTick();
    expect(inputFor(tunnelRoot, "监听端口").value).toBe("2080");
  });

  it("keeps automatic fields locked and directly follows a Reality target", async () => {
    const root = mountForm(() => undefined);
    await selectProtocol(root, "XTLS+Reality");
    root.querySelector<HTMLButtonElement>(".protocol-confirm-button")?.click();
    await nextTick();

    const serverName = inputFor(root, "Server Name / SNI");
    expect(serverName.disabled).toBe(true);
    const target = inputFor(root, "Reality 目标网站");
    setInput(target, "www.cloudflare.com");
    await nextTick();

    expect(root.querySelector("[role='dialog']")).toBeNull();
    expect(serverName.value).toBe("www.cloudflare.com");
  });

  it("toggles UUID and password credentials together", async () => {
    const root = mountForm(() => undefined);
    await selectProtocol(root, "TUIC");
    root.querySelector<HTMLButtonElement>(".protocol-confirm-button")?.click();
    await nextTick();

    const uuid = inputFor(root, "UUID");
    const password = inputFor(root, "密码");
    expect(uuid.type).toBe("password");
    expect(password.type).toBe("password");

    root.querySelector<HTMLButtonElement>(".credential-visibility-button")?.click();
    await nextTick();
    expect(uuid.type).toBe("text");
    expect(password.type).toBe("text");

    root.querySelector<HTMLButtonElement>(".credential-visibility-button")?.click();
    await nextTick();
    expect(uuid.type).toBe("password");
    expect(password.type).toBe("password");
  });

  it("uses an automatic mock certificate preset for TLS protocols", async () => {
    let submitted: Record<string, unknown> | null = null;
    const root = mountForm(payload => { submitted = payload; });
    expect(root.textContent).toContain("当前为测试模式");
    const hysteriaOption = (await protocolOptions(root))
      .find(option => option.dataset.value === "hysteria2");
    expect(hysteriaOption?.disabled).toBe(false);
    await selectProtocol(root, "Hysteria2");
    root.querySelector<HTMLButtonElement>(".protocol-confirm-button")?.click();
    await nextTick();
    expect(root.querySelector(".required-badge")?.classList.contains("complete")).toBe(true);
    setInput(inputFor(root, "证书域名"), "");
    await nextTick();
    expect(root.querySelector(".required-badge")?.classList.contains("complete")).toBe(false);
    setInput(inputFor(root, "证书域名"), "test-host.jui.test");
    await nextTick();
    root.querySelector("form")?.dispatchEvent(new Event("submit", { bubbles: true }));
    await nextTick();

    expect(submitted).toMatchObject({
      name: "test-host丨Hysteria2_8881",
      protocol: "hysteria2",
      settings: {
        server_name: "test-host.jui.test",
        certificate_mode: "auto"
      }
    });
    expect((submitted as { settings: Record<string, unknown> } | null)?.settings).not.toHaveProperty("certificate_path");
    expect((submitted as { credential: { password: string } } | null)?.credential.password).toHaveLength(32);
  });

  it("uses installer certificate defaults for a new TLS node", async () => {
    const root = mountForm(() => undefined, "node.example.com", true, {
      certificateModeDefault: "manual",
      certificatePathDefault: "/etc/j-ui/example.crt",
      certificateKeyPathDefault: "/etc/j-ui/example.key"
    });
    await selectProtocol(root, "Hysteria2");
    root.querySelector<HTMLButtonElement>(".protocol-confirm-button")?.click();
    await nextTick();

    expect(inputFor(root, "证书方式").value).toBe("手动指定");
    expect(inputFor(root, "证书绝对路径").value).toBe("/etc/j-ui/example.crt");
    expect(inputFor(root, "私钥绝对路径").value).toBe("/etc/j-ui/example.key");
  });
});
