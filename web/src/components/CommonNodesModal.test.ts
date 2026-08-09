import { createApp, h, nextTick, type App } from "vue";
import { afterEach, describe, expect, it } from "vitest";
import CommonNodesModal from "./CommonNodesModal.vue";

let mountedApp: App<Element> | null = null;

afterEach(() => {
  mountedApp?.unmount();
  mountedApp = null;
  document.body.innerHTML = "";
});

describe("CommonNodesModal", () => {
  it("creates three named protocol payloads with automatic certificates", async () => {
    let submitted: Record<string, unknown>[] = [];
    const root = document.createElement("div");
    document.body.append(root);
    mountedApp = createApp({
      render: () => h(CommonNodesModal, {
        serverName: "云悠JP", publicHost: "198.51.100.10",
        certificateServerName: "node.example.com", certificateMode: "auto",
        certificatePath: "", certificateKeyPath: "", existingProtocols: [],
        nextPort: 8881,
        error: "", submitting: false, theme: "light", language: "zh-CN",
        onSubmit: (payloads: Record<string, unknown>[]) => { submitted = payloads; }
      })
    });
    mountedApp.mount(root);
    expect(root.querySelector(".preset-backdrop")?.classList.contains("theme-light")).toBe(true);
    root.querySelector("form")?.dispatchEvent(new Event("submit", { bubbles: true }));
    await nextTick();

    expect(submitted.map(item => item.protocol)).toEqual([
      "vless_reality", "hysteria2", "tuic"
    ]);
    expect(submitted.map(item => item.name)).toEqual([
      "云悠JP丨XTLS-Reality_8881", "云悠JP丨Hysteria2_8882",
      "云悠JP丨TUIC_8883"
    ]);
    expect(submitted[1]).toMatchObject({
      protocol: "hysteria2",
      settings: { server_name: "node.example.com", certificate_mode: "auto" }
    });
    expect(submitted[0]).toMatchObject({
      protocol: "vless_reality",
      settings: { handshake_server: "www.visa.com.sg", server_name: "www.visa.com.sg" }
    });
    expect(root.querySelector<HTMLInputElement>(".dropdown-field input")?.value)
      .toBe("www.visa.com.sg");
    expect(root.textContent).not.toContain("VLESS-Argo");
  });

  it("only submits protocols missing from the current node list", async () => {
    let submitted: Record<string, unknown>[] = [];
    const root = document.createElement("div");
    document.body.append(root);
    mountedApp = createApp({
      render: () => h(CommonNodesModal, {
        serverName: "云悠JP", publicHost: "198.51.100.10",
        certificateServerName: "node.example.com", certificateMode: "auto",
        certificatePath: "", certificateKeyPath: "",
        existingProtocols: ["vless_reality", "hysteria2"],
        nextPort: 8883,
        error: "", submitting: false, theme: "light", language: "zh-CN",
        onSubmit: (payloads: Record<string, unknown>[]) => { submitted = payloads; }
      })
    });
    mountedApp.mount(root);
    expect(root.textContent).toContain("将创建 1 个节点");
    expect(root.textContent?.match(/已存在，将跳过/g)).toHaveLength(2);

    root.querySelector("form")?.dispatchEvent(new Event("submit", { bubbles: true }));
    await nextTick();

    expect(submitted).toHaveLength(1);
    expect(submitted[0]).toMatchObject({ protocol: "tuic", port: 8883 });
  });
});
