import { afterEach, describe, expect, it, vi } from "vitest";
import { createApp, nextTick } from "vue";
import LandingPanel from "./LandingPanel.vue";

const json = (body: unknown) => new Response(JSON.stringify(body), {
  headers: { "Content-Type": "application/json" }
});

describe("LandingPanel", () => {
  afterEach(() => { vi.unstubAllGlobals(); document.body.innerHTML = ""; });

  it("loads effective rules and saves overrides without displaying landing credentials", async () => {
    const calls: Array<{ path: string; body?: Record<string, unknown> }> = [];
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, options?: RequestInit) => {
      const path = String(input);
      calls.push({ path, body: options?.body ? JSON.parse(String(options.body)) : undefined });
      if (path === "/api/v1/landing") return json({ enabled: true, inboundId: 1, configured: true, server: "jp.example.com", port: 443 });
      if (path === "/api/v1/landing/script") return json({ script: "#!/usr/bin/env bash\necho ADDR=203.0.113.1" });
      if (path === "/api/v1/landing/rules") return json({
        source: "v2fly snapshot", base: { rules: [{ domain: ["ai.google.dev"], domain_suffix: ["chatgpt.com"], domain_regex: [] }] },
        include: [], exclude: []
      });
      throw new Error(`unexpected API path: ${path}`);
    }));
    const root = document.createElement("div"); document.body.append(root);
    const app = createApp(LandingPanel, { language: "en" });
    app.mount(root);
    for (let i = 0; i < 5; i++) { await Promise.resolve(); await nextTick(); }
    expect(root.textContent).toContain("Landing exit: configured");
    expect(root.textContent).not.toContain("jp.example.com:443");
    expect(root.textContent).not.toContain("JP_*");
    expect(root.textContent).toContain("Landing connection details");
    expect(root.querySelector('textarea[placeholder]')?.getAttribute("placeholder")).toContain("ADDR=...");
    expect(root.textContent).not.toContain("vless://");
    expect(root.querySelector(".landing-legacy")).toBeNull();
    expect(root.textContent).toContain("all enabled regular inbounds");
    expect(root.textContent).toContain("Existing routing still applies only to the previous inbound");
    expect(root.querySelector("#landing-listen-port")).not.toBeNull();
    expect(root.querySelector("select")).toBeNull();
    expect(root.querySelector(".landing-script textarea")).toBeNull();
    (Array.from(root.querySelectorAll("button")).find(button => button.textContent?.includes("Generate one-click script")) as HTMLButtonElement).click();
    await nextTick();
    expect((root.querySelector(".landing-script textarea") as HTMLTextAreaElement).value).toContain("export LANDING_LISTEN_PORT='14443'");
    (root.querySelector('button[type="submit"]') as HTMLButtonElement).click();
    for (let i = 0; i < 5; i++) { await Promise.resolve(); await nextTick(); }
    expect(calls.some(call => call.path === "/api/v1/landing" && call.body && !("inboundId" in call.body) && !("uri" in call.body))).toBe(true);
    (root.querySelectorAll('[role="tab"]')[1] as HTMLButtonElement).click();
    await nextTick();
    expect(root.textContent).toContain("chatgpt.com");
    const fields = root.querySelectorAll("textarea");
    fields[0].value = "ai.example.com"; fields[0].dispatchEvent(new Event("input"));
    (root.querySelector('button[type="submit"]') as HTMLButtonElement).click();
    for (let i = 0; i < 5; i++) { await Promise.resolve(); await nextTick(); }
    expect(calls.some(call => call.path === "/api/v1/landing/rules" &&
      Array.isArray(call.body?.include) && call.body.include[0] === "ai.example.com")).toBe(true);
    app.unmount();
  });

  it("generates one complete script for NAT ports and rejects stale or invalid settings", async () => {
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      const path = String(input);
      if (path === "/api/v1/landing") return json({ enabled: false, inboundId: 0, configured: false });
      if (path === "/api/v1/landing/script") return json({ script: "#!/usr/bin/env bash\nset -euo pipefail\necho ready\n" });
      if (path === "/api/v1/landing/rules") return json({
        source: "v2fly snapshot", base: { rules: [{ domain: [], domain_suffix: [], domain_regex: [] }] },
        include: [], exclude: []
      });
      throw new Error(`unexpected API path: ${path}`);
    }));
    const writeText = vi.fn(async () => undefined);
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText } });
    const root = document.createElement("div"); document.body.append(root);
    const app = createApp(LandingPanel, { language: "zh-CN", preview: true });
    app.mount(root);
    for (let i = 0; i < 5; i++) { await Promise.resolve(); await nextTick(); }

    const publicPort = root.querySelector("#landing-public-port") as HTMLInputElement;
    const listenPort = root.querySelector("#landing-listen-port") as HTMLInputElement;
    const publicAddress = root.querySelector("#landing-public-address") as HTMLInputElement;
    publicAddress.value = "203.0.113.10";
    publicAddress.dispatchEvent(new Event("input"));
    publicPort.value = "10086";
    publicPort.dispatchEvent(new Event("input"));
    listenPort.value = "14443";
    listenPort.dispatchEvent(new Event("input"));
    await nextTick();
    const generate = Array.from(root.querySelectorAll("button")).find(button => button.textContent?.includes("生成一键脚本")) as HTMLButtonElement;
    expect(root.querySelector(".landing-script textarea")).toBeNull();
    generate.click();
    await nextTick();
    const script = (root.querySelector(".landing-script textarea") as HTMLTextAreaElement).value;
    expect(script).toBe("#!/usr/bin/env bash\nexport LANDING_ADDR='203.0.113.10'\nexport LANDING_PORT='10086'\nexport LANDING_LISTEN_PORT='14443'\nexport LANDING_SNI='www.microsoft.com'\n\nset -euo pipefail\necho ready\n");
    const copy = Array.from(root.querySelectorAll("button")).find(button => button.textContent?.includes("复制一键脚本")) as HTMLButtonElement;
    copy.click();
    await nextTick();
    expect(writeText).toHaveBeenCalledWith(script);
    publicPort.value = "10087";
    publicPort.dispatchEvent(new Event("input"));
    await nextTick();
    expect(root.querySelector(".landing-script textarea")).toBeNull();
    publicPort.value = "70000";
    publicPort.dispatchEvent(new Event("input"));
    await nextTick();
    expect(generate.disabled).toBe(true);
    publicPort.value = "10087";
    publicPort.dispatchEvent(new Event("input"));
    const sni = root.querySelector("#landing-sni") as HTMLInputElement;
    sni.value = "invalid";
    sni.dispatchEvent(new Event("input"));
    await nextTick();
    expect(generate.disabled).toBe(true);
    sni.value = "www.microsoft.com";
    sni.dispatchEvent(new Event("input"));
    await nextTick();
    generate.click();
    await nextTick();
    expect((root.querySelector(".landing-script textarea") as HTMLTextAreaElement).value).toContain("export LANDING_PORT='10087'");
    publicAddress.value = "203.0.113.10.";
    publicAddress.dispatchEvent(new Event("input"));
    await nextTick();
    expect(generate.disabled).toBe(true);
    expect(root.querySelector(".landing-script textarea")).toBeNull();
    app.unmount();
  });

  it("copies generated scripts in restricted browser contexts", async () => {
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      if (String(input) === "/api/v1/landing") return json({ enabled: false, inboundId: 0, configured: false });
      if (String(input) === "/api/v1/landing/script") return json({ script: "#!/usr/bin/env bash\necho ready\n" });
      return json({ source: "v2fly snapshot", base: { rules: [{ domain: [], domain_suffix: [], domain_regex: [] }] }, include: [], exclude: [] });
    }));
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: vi.fn(async () => { throw new Error("denied"); }) } });
    const copyFallback = vi.fn(() => true);
    Object.defineProperty(document, "execCommand", { configurable: true, value: copyFallback });
    const root = document.createElement("div"); document.body.append(root);
    const app = createApp(LandingPanel, { language: "zh-CN", preview: true });
    app.mount(root);
    for (let i = 0; i < 5; i++) { await Promise.resolve(); await nextTick(); }
    (Array.from(root.querySelectorAll("button")).find(button => button.textContent?.includes("生成一键脚本")) as HTMLButtonElement).click();
    await nextTick();
    (Array.from(root.querySelectorAll("button")).find(button => button.textContent?.includes("复制一键脚本")) as HTMLButtonElement).click();
    for (let i = 0; i < 3; i++) { await Promise.resolve(); await nextTick(); }
    expect(copyFallback).toHaveBeenCalledWith("copy");
    expect(root.textContent).toContain("一键脚本已复制");
    app.unmount();
  });

  it("shows disabled status and updates or restores the rule source", async () => {
    const calls: Array<{ path: string; sourceUrl?: string }> = [];
    const baseline = { rules: [{ domain: [], domain_suffix: ["chatgpt.com"], domain_regex: [] }] };
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, options?: RequestInit) => {
      const path = String(input);
      const sourceUrl = options?.body ? JSON.parse(String(options.body)).sourceUrl : undefined;
      calls.push({ path, sourceUrl });
      if (path === "/api/v1/landing") return json({ enabled: false, inboundId: 0, configured: false });
      if (path === "/api/v1/landing/script") return json({ script: "#!/usr/bin/env bash\necho ready" });
      if (path === "/api/v1/landing/rules/refresh") return json({ source: "sha256", sourceUrl, base: baseline, include: [], exclude: [] });
      return json({ source: "bundled", sourceUrl: "", base: baseline, include: [], exclude: [] });
    }));
    const root = document.createElement("div"); document.body.append(root);
    const app = createApp(LandingPanel, { language: "en" });
    app.mount(root);
    for (let i = 0; i < 5; i++) { await Promise.resolve(); await nextTick(); }
    expect(root.textContent).toContain("AI routing: disabled");
    expect(root.textContent).toContain("Landing exit: not configured");
    (root.querySelectorAll('[role="tab"]')[1] as HTMLButtonElement).click();
    await nextTick();
    const input = root.querySelector("#landing-source-url") as HTMLInputElement;
    expect(input.value).toContain("raw.githubusercontent.com");
    (Array.from(root.querySelectorAll("button")).find(button => button.textContent?.includes("Update rule set")) as HTMLButtonElement).click();
    for (let i = 0; i < 5; i++) { await Promise.resolve(); await nextTick(); }
    expect(calls.some(call => call.path.endsWith("/rules/refresh") && call.sourceUrl === input.value)).toBe(true);
    (Array.from(root.querySelectorAll("button")).find(button => button.textContent?.includes("Restore bundled rules")) as HTMLButtonElement).click();
    for (let i = 0; i < 5; i++) { await Promise.resolve(); await nextTick(); }
    expect(calls.some(call => call.path.endsWith("/rules/refresh") && call.sourceUrl === "")).toBe(true);
    app.unmount();
  });
});
