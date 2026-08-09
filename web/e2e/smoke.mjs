import assert from "node:assert/strict";
import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import { chromium } from "playwright";

const baseURL = process.env.JUI_E2E_BASE_URL;
const adminPath = process.env.JUI_E2E_ADMIN_PATH;
const password = process.env.JUI_E2E_PASSWORD;
const nodePort = Number(process.env.JUI_E2E_NODE_PORT || "18082");
const commonPorts = { reality: nodePort + 1, hysteria2: nodePort + 2, tuic: nodePort + 3 };
const artifactDir = process.env.JUI_E2E_ARTIFACT_DIR;
const browserPath = process.env.JUI_E2E_BROWSER_PATH;

if (!baseURL || !adminPath || !password) {
  throw new Error("JUI_E2E_BASE_URL, JUI_E2E_ADMIN_PATH, and JUI_E2E_PASSWORD are required");
}
if (!Number.isInteger(nodePort) || nodePort < 1 || nodePort > 65532) {
  throw new Error("JUI_E2E_NODE_PORT must leave room for three common-node test ports");
}
if (artifactDir) await mkdir(artifactDir, { recursive: true });

const browser = await chromium.launch({
  headless: true,
  ...(browserPath ? { executablePath: browserPath } : {})
});
const context = await browser.newContext({
  viewport: { width: 1440, height: 900 },
  permissions: ["clipboard-read", "clipboard-write"]
});
const page = await context.newPage();
const browserErrors = [];
page.on("pageerror", error => browserErrors.push(error.message));
page.on("console", message => {
  if (message.type() === "error") browserErrors.push(message.text());
});

try {
  await page.goto(`${baseURL}/${adminPath}/`, { waitUntil: "networkidle" });
  await page.getByLabel("用户名").fill("admin");
  await page.getByLabel("密码").fill(password);
  await page.getByRole("button", { name: "登录控制台" }).click();

  await page.getByRole("heading", { name: /^(设置公网地址|系统状态)$/ }).waitFor();
  if (await page.getByRole("heading", { name: "设置公网地址" }).isVisible().catch(() => false)) {
    await page.getByLabel("域名或 IP").fill("127.0.0.1");
    await page.getByRole("button", { name: "完成初始化" }).click();
  }
  await page.getByRole("heading", { name: "系统状态" }).waitFor();
  await page.getByRole("heading", { name: "节点管理" }).waitFor();
  assert.equal(await page.locator(".kui-header").evaluate(element => getComputedStyle(element).position),
    "static", "desktop header still follows the viewport");
  await page.evaluate(() => {
    document.documentElement.style.scrollBehavior = "auto";
    window.scrollTo(0, 700);
  });
  await page.waitForFunction(() => window.scrollY > 480);
  const backToTop = page.getByRole("button", { name: "返回顶部" });
  await backToTop.waitFor();
  const scrolledHeaderBox = await page.locator(".kui-header").boundingBox();
  const backToTopBox = await backToTop.boundingBox();
  assert.ok(scrolledHeaderBox && scrolledHeaderBox.y < 0,
    "header did not scroll away with the document");
  assert.ok(backToTopBox &&
    Math.abs(1440 - backToTopBox.x - backToTopBox.width - 24) < 1 &&
    Math.abs(900 - backToTopBox.y - backToTopBox.height - 24) < 1,
  "back-to-top button is not fixed at the desktop bottom-right corner");
  await backToTop.click();
  await page.waitForFunction(() => window.scrollY < 2);
  assert.equal(await page.locator("aside").count(), 0, "legacy sidebar is still rendered");
  assert.equal(await page.locator(".kui-tab-strip").count(), 0, "legacy section navigation is still rendered");
  assert.equal(await page.getByText("运行概览", { exact: true }).count(), 0,
    "legacy overview section is still rendered");
  assert.equal(await page.getByRole("heading", { name: "实时监控" }).count(), 0,
    "legacy monitor section is still rendered");
  assert.equal(await page.locator(".status-summary-grid").count(), 0,
    "detached status summary is still rendered");
  assert.equal(await page.locator(".server-title > h3").count(), 1,
    "server identity is not presented as a single breathing-dot title");
  assert.equal(await page.locator(".server-title > .country-flag[aria-label='CN 国旗']").count(), 1,
    "server identity does not include the detected country flag");
  assert.ok((await page.locator(".server-title > .country-flag").evaluate(
    element => getComputedStyle(element).fontFamily
  )).includes("Twemoji Country Flags"), "bundled country flag font is not applied");
  assert.equal(await page.locator(".server-title").getByText("当前服务器").count(), 0,
    "server identity still shows the redundant current-server label");
  assert.equal(await page.locator(".network-facts").getByText("实时下载").count(), 1,
    "download telemetry was not merged into the resource card");
  assert.equal(await page.locator(".network-facts").getByText("总计流量 (入 | 出)").count(), 1,
    "directional traffic totals are missing between download and upload");
  assert.equal(await page.locator(".network-facts").getByText("累计", { exact: false }).count(), 0,
    "per-direction cumulative traffic is still rendered");
  assert.equal(await page.locator(".core-facts").count(), 0,
    "service facts were not merged into the server information grid");
  assert.equal(await page.locator(".resource-row > small").count(), 0,
    "resource usage details are still below the progress bars");
  assert.equal(await page.locator(".resource-row > div small").count(), 3,
    "resource usage details are not grouped with their labels");
  const desktopServerFactBoxes = await page.locator(".server-facts > div").evaluateAll(elements =>
    elements.slice(0, 2).map(element => {
      const box = element.getBoundingClientRect();
      return { x: box.x, y: box.y };
    })
  );
  assert.ok(desktopServerFactBoxes.length === 2 &&
    desktopServerFactBoxes[0].x < desktopServerFactBoxes[1].x &&
    Math.abs(desktopServerFactBoxes[0].y - desktopServerFactBoxes[1].y) < 1,
  "server and service facts are not arranged in two columns");
  const desktopNetworkBox = await page.locator(".network-facts").boundingBox();
  const desktopUploadBox = await page.locator(".network-facts > div").last().boundingBox();
  assert.ok(desktopNetworkBox && desktopUploadBox &&
    Math.abs(desktopNetworkBox.x + desktopNetworkBox.width -
      desktopUploadBox.x - desktopUploadBox.width) < 1,
  "upload telemetry is not aligned to the far right");
  const desktopNetworkItems = await page.locator(".network-facts > div").evaluateAll(elements =>
    elements.map(element => {
      const box = element.getBoundingClientRect();
      return { centerY: box.y + box.height / 2 };
    })
  );
  assert.ok(desktopNetworkBox && desktopNetworkItems.every(item =>
    Math.abs(item.centerY - (desktopNetworkBox.y + desktopNetworkBox.height / 2)) < 1
  ), "network telemetry modules are not vertically centered");
  const desktopNetworkAlignment = await page.locator(".network-facts > div").evaluateAll(elements =>
    elements.map(element => getComputedStyle(element).textAlign)
  );
  assert.ok(desktopNetworkAlignment.every(alignment => alignment === "center"),
    "network telemetry module contents are not center-aligned");
  const desktopNetworkLineBoxes = await page.locator(".network-facts > div").evaluateAll(elements =>
    elements.map(element => {
      const label = element.querySelector(":scope > span")?.getBoundingClientRect();
      const value = element.querySelector(":scope > strong")?.getBoundingClientRect();
      return label && value ? { labelY: label.y, valueBottom: value.bottom } : null;
    })
  );
  assert.ok(desktopNetworkLineBoxes.every(box => box &&
    Math.abs(box.labelY - desktopNetworkLineBoxes[0].labelY) < 1 &&
    Math.abs(box.valueBottom - desktopNetworkLineBoxes[0].valueBottom) < 1),
  "network telemetry labels and values do not share row baselines");
  const desktopTitleItems = await page.locator(
    ".server-title > .server-dot, .server-title > .country-flag, .server-title > h3"
  ).evaluateAll(elements =>
    elements.map(element => {
      const box = element.getBoundingClientRect();
      return { centerY: box.y + box.height / 2 };
    })
  );
  assert.ok(desktopTitleItems.length === 3 && desktopTitleItems.every(item =>
    Math.abs(item.centerY - desktopTitleItems[0].centerY) < 1
  ), "status dot, country flag, and server name are not center-aligned");
  const desktopAddressBox = await page.locator(".address-block").boundingBox();
  const desktopAddressButtonBox = await page.locator(".address-visibility").boundingBox();
  assert.ok(desktopAddressBox && desktopAddressButtonBox &&
    desktopAddressBox.x + desktopAddressBox.width -
      desktopAddressButtonBox.x - desktopAddressButtonBox.width <= 20,
  "IP visibility button is not aligned to the right edge");
  const resourceFontSizes = await page.locator(".resource-row").first().evaluate(element => {
    const label = element.querySelector(":scope > div > span");
    const detail = element.querySelector(":scope > div > span small");
    const percent = element.querySelector(":scope > div > strong");
    return {
      label: label ? parseFloat(getComputedStyle(label).fontSize) : 0,
      detail: detail ? parseFloat(getComputedStyle(detail).fontSize) : 0,
      percent: percent ? parseFloat(getComputedStyle(percent).fontSize) : 0
    };
  });
  const networkSpeedFontSize = await page.locator(".network-facts .download-value").evaluate(
    element => parseFloat(getComputedStyle(element).fontSize)
  );
  assert.equal(resourceFontSizes.label, resourceFontSizes.percent,
    "resource title and percentage font sizes do not match");
  assert.equal(resourceFontSizes.label, networkSpeedFontSize,
    "resource metrics do not match the live network speed font size");
  assert.ok(resourceFontSizes.detail >= 12,
    "resource usage detail font is too small");
  const desktopResourceRows = await page.locator(".resource-panel > .resource-row").evaluateAll(elements =>
    elements.map(element => {
      const box = element.getBoundingClientRect();
      return { x: box.x, y: box.y, width: box.width, height: box.height };
    })
  );
  assert.equal(desktopResourceRows.length, 3, "resource metric count changed");
  const desktopResourceGaps = desktopResourceRows.slice(1).map((box, index) =>
    box.y - desktopResourceRows[index].y - desktopResourceRows[index].height
  );
  assert.ok(desktopResourceRows.every(box =>
    Math.abs(box.x - desktopResourceRows[0].x) < 1 &&
    Math.abs(box.width - desktopResourceRows[0].width) < 1
  ) && desktopResourceGaps.every(gap => gap >= 22 && gap <= 30) &&
    Math.abs(desktopResourceGaps[0] - desktopResourceGaps[1]) < 1,
  "resource metrics are not evenly distributed in a KUI-style column");
  const desktopServerTitleBox = await page.locator(".server-title").boundingBox();
  const desktopServerFactsBox = await page.locator(".server-facts").boundingBox();
  assert.ok(desktopServerTitleBox && desktopServerFactsBox && desktopNetworkBox &&
    Math.abs(desktopResourceRows[0].y - desktopServerTitleBox.y) < 1 &&
    Math.abs(desktopNetworkBox.y + desktopNetworkBox.height -
      desktopServerFactsBox.y - desktopServerFactsBox.height) < 1,
  "desktop resource panel is not aligned with the server information bounds");
  const desktopBrandBox = await page.locator(".brand-module .header-brand").boundingBox();
  const desktopDividerBox = await page.locator(".brand-module .header-divider").boundingBox();
  const desktopGitHubBox = await page.locator(".brand-module a[aria-label='GitHub 仓库']").boundingBox();
  const desktopLiveBox = await page.locator(".monitor-module .live-chip").boundingBox();
  const desktopHeaderBox = await page.locator(".kui-header").boundingBox();
  const desktopBrandModuleBox = await page.locator(".brand-module").boundingBox();
  const desktopLastActionBox = await page.locator(".header-actions .top-action").last().boundingBox();
  assert.ok(desktopHeaderBox && desktopHeaderBox.height >= 86,
    "desktop header was not enlarged");
  assert.equal(await page.locator(".kui-header .brand").evaluate(
    element => getComputedStyle(element).fontSize
  ), "24px", "header brand font size changed");
  assert.equal(await page.locator(".header-actions .top-action").first().evaluate(
    element => getComputedStyle(element).fontSize
  ), "14px", "header action font size changed");
  assert.equal(await page.locator(".header-actions .action-icon").first().evaluate(
    element => getComputedStyle(element).fontSize
  ), "18px", "header action icon size changed");
  const desktopActionTypography = await page.locator(".header-actions .top-action").evaluateAll(elements =>
    elements.map(element => {
      const style = getComputedStyle(element);
      return { fontSize: style.fontSize, fontWeight: style.fontWeight, paddingLeft: style.paddingLeft, paddingRight: style.paddingRight };
    })
  );
  assert.ok(desktopActionTypography.every(style =>
    style.fontSize === desktopActionTypography[0].fontSize &&
    style.fontWeight === desktopActionTypography[0].fontWeight &&
    style.paddingLeft === desktopActionTypography[0].paddingLeft &&
    style.paddingRight === desktopActionTypography[0].paddingRight
  ), "header action typography is inconsistent");
  const desktopActionIconBoxes = await page.locator(".header-actions .action-icon").evaluateAll(elements =>
    elements.map(element => {
      const box = element.getBoundingClientRect();
      return { width: box.width, height: box.height, centerY: box.y + box.height / 2 };
    })
  );
  assert.ok(desktopActionIconBoxes.every(box =>
    box.width === 22 && box.height === 22 &&
    Math.abs(box.centerY - desktopActionIconBoxes[0].centerY) < 1
  ), "header action icons do not share one size and baseline");
  assert.ok(desktopBrandBox && desktopDividerBox && desktopLiveBox && desktopGitHubBox &&
    desktopBrandBox.x < desktopDividerBox.x &&
    desktopDividerBox.x < desktopGitHubBox.x && desktopGitHubBox.x < desktopLiveBox.x,
  "header modules are not ordered as brand, monitor, actions");
  assert.ok(desktopHeaderBox && desktopBrandModuleBox && desktopLastActionBox &&
    Math.abs((desktopBrandModuleBox.x - desktopHeaderBox.x) -
      (desktopHeaderBox.x + desktopHeaderBox.width -
        desktopLastActionBox.x - desktopLastActionBox.width)) < 1,
  "desktop header actions do not align with the outer brand inset");
  assert.notEqual(await page.locator(".status-pulse").evaluate(
    element => getComputedStyle(element).animationName
  ), "none", "live monitor indicator is not animated");
  const publicAddress = page.getByTestId("public-address");
  assert.equal(await publicAddress.evaluate(element => element.classList.contains("blurred")), true,
    "public address should be blurred by default");
  const statusCardBox = await page.locator(".system-status-card").boundingBox();
  const nodePanelBox = await page.locator("#nodes-section .table-panel").boundingBox();
  assert.ok(statusCardBox && nodePanelBox &&
    Math.abs(statusCardBox.x - nodePanelBox.x) < 1 &&
    Math.abs(statusCardBox.width - nodePanelBox.width) < 1,
  "system status card must align with the page content width");
  if (artifactDir) {
    await page.screenshot({ path: join(artifactDir, "desktop-system-status.png"), fullPage: true });
  }
  const subscriptionButton = page.getByRole("button", { name: "显示订阅链接" });
  const subscriptionLabel = subscriptionButton.locator(".action-label");
  assert.equal(await subscriptionLabel.isVisible(), true, "desktop subscription label is hidden");
  const lightSubscriptionColor = await subscriptionLabel.evaluate(
    element => getComputedStyle(element).color
  );
  await subscriptionButton.click();
  const linkModal = page.locator(".subscription-links-modal");
  await linkModal.getByRole("heading", { name: "订阅链接" }).waitFor();
  assert.equal(await linkModal.locator(".subscription-link-item").count(), 5,
    "client subscription modal does not contain all five profiles");
  const linkModalBox = await linkModal.boundingBox();
  assert.ok(linkModalBox && linkModalBox.width >= 900,
    "subscription modal was not widened for desktop clients");
  assert.equal(await linkModal.evaluate(element => element.scrollWidth <= element.clientWidth), true,
    "subscription modal has horizontal overflow");
  assert.equal(await linkModal.evaluate(element => getComputedStyle(element).scrollbarWidth), "none",
    "subscription modal still renders scrollbars");
  const standardCopyButton = linkModal.locator(".subscription-link-item").first().getByRole("button", { name: "复制" });
  await standardCopyButton.click();
  await linkModal.getByRole("button", { name: /已复制/ }).waitFor();
  assert.equal(await standardCopyButton.evaluate(element => element.classList.contains("copied")), true,
    "subscription copy action has no visible confirmation state");
  if (artifactDir) {
    await page.screenshot({ path: join(artifactDir, "desktop-subscriptions.png"), fullPage: true });
  }
  await linkModal.getByRole("button", { name: "关闭" }).click();
  await page.getByRole("button", { name: "显示订阅二维码" }).click();
  const qrModal = page.locator(".subscription-qr-modal");
  await qrModal.locator(".qr-code-surface svg").waitFor();
  assert.equal(await qrModal.locator(".qr-format-tabs button").count(), 5,
    "QR modal does not contain all five subscription profiles");
  const ordinaryQRPath = await qrModal.locator(".qr-code-surface svg > path").getAttribute("d");
  await qrModal.getByRole("button", { name: /Shadowrocket/ }).click();
  assert.notEqual(await qrModal.locator(".qr-code-surface svg > path").getAttribute("d"), ordinaryQRPath,
    "QR code did not change with the selected client profile");
  assert.equal(await qrModal.locator(".copy-field").count(), 0,
    "QR modal still renders the subscription copy field");
  assert.equal(await qrModal.getByRole("button", { name: "关闭" }).evaluate(
    element => getComputedStyle(element).borderTopWidth
  ), "0px", "QR close button still has a border");
  await page.locator("html").evaluate(element => { element.dataset.theme = "dark"; });
  assert.equal(await qrModal.locator(".qr-code-surface").evaluate(
    element => getComputedStyle(element).backgroundColor
  ), "rgb(255, 255, 255)", "QR surface is not white in dark mode");
  assert.equal(await qrModal.locator(".qr-code-surface svg > rect").first().evaluate(
    element => getComputedStyle(element).fill
  ), "rgb(255, 255, 255)", "QR SVG background is not white in dark mode");
  await page.locator("html").evaluate(element => { element.dataset.theme = "light"; });
  await qrModal.getByRole("button", { name: "关闭" }).click();
  await page.getByRole("button", { name: "一键创建常用节点" }).click();
  const lightPreset = page.locator(".preset-backdrop.theme-light");
  await lightPreset.getByRole("heading", { name: "一键创建常用节点" }).waitFor();
  assert.equal(await lightPreset.locator(".preset-modal").evaluate(
    element => getComputedStyle(element).backgroundColor
  ), "rgb(255, 255, 255)", "common-node modal does not use its light theme");
  await lightPreset.getByRole("button", { name: "展开常用 Reality 目标" }).click();
  const realityMenuBox = await lightPreset.locator("#common-reality-target-menu").boundingBox();
  const realityInputBox = await lightPreset.getByLabel("Reality 伪装目标").boundingBox();
  assert.ok(realityMenuBox && realityInputBox && realityMenuBox.y >= 0 &&
    realityMenuBox.y + realityMenuBox.height <= 900 &&
    realityMenuBox.y + realityMenuBox.height <= realityInputBox.y,
  "common Reality target menu is clipped instead of opening above its field");
  await lightPreset.getByRole("button", { name: "收起常用 Reality 目标" }).click();
  await lightPreset.getByRole("button", { name: "取消" }).click();
  await page.getByRole("button", { name: "切换为夜间模式" }).click();
  assert.equal(await page.locator("html").getAttribute("data-theme"), "dark",
    "dark theme was not applied");
  await page.waitForTimeout(250);
  const darkSubscriptionColor = await subscriptionLabel.evaluate(
    element => getComputedStyle(element).color
  );
  assert.notEqual(lightSubscriptionColor, darkSubscriptionColor,
    "subscription text does not adapt to the selected theme");
  assert.notEqual(darkSubscriptionColor, "rgba(0, 0, 0, 0)",
    "subscription text is transparent in dark mode");
  if (artifactDir) {
    await page.screenshot({ path: join(artifactDir, "desktop-dark.png"), fullPage: true });
  }
  await page.getByRole("button", { name: "显示 IP 地址" }).click();
  assert.equal(await publicAddress.evaluate(element => element.classList.contains("blurred")), false,
    "public address visibility toggle did not reveal the address");
  assert.equal(await page.getByText("最近配置事件", { exact: true }).count(), 0,
    "recent events are visible on the main page");
  // The unauthenticated bootstrap intentionally receives 401 before login.
  browserErrors.length = 0;

  await page.getByRole("heading", { name: "住宅ip代理设置" }).waitFor();
  assert.equal(await page.getByRole("heading", { name: "可用出口" }).count(), 0,
    "legacy outbound inventory is still visible");

  await page.getByRole("button", { name: "一键创建常用节点" }).click();
  await page.getByRole("heading", { name: "一键创建常用节点" }).waitFor();
  assert.equal(await page.locator(".preset-backdrop.theme-dark").count(), 1,
    "common-node modal does not follow the main dark theme");
  await page.getByLabel("Reality", { exact: true }).fill(String(commonPorts.reality));
  await page.getByLabel("Hysteria2", { exact: true }).fill(String(commonPorts.hysteria2));
  await page.getByLabel("TUIC", { exact: true }).fill(String(commonPorts.tuic));
  assert.equal(await page.locator(".preset-modal").getByText("将创建 3 个节点").count(), 1,
    "common-node preset does not preview three nodes");
  if (artifactDir) {
    await page.screenshot({ path: join(artifactDir, "desktop-common-nodes.png"), fullPage: true });
  }
  await page.locator(".preset-modal").getByRole("button", { name: "创建 3 个缺失节点" }).click();
  await page.getByText("3 个缺失节点已补全并通过配置校验", { exact: true }).waitFor();
  assert.equal(await page.locator("#nodes-section .node-row").count(), 3,
    "automatic-certificate common nodes were not all deployed");
  assert.equal(await page.locator("#nodes-section .protocol-mark").count(), 0,
    "node protocol icons are still rendered");
  const firstCommonRow = page.locator("#nodes-section .node-row").first();
  assert.equal(await firstCommonRow.getByRole("button", { name: /^(凭据|导出|停用)$/ }).count(), 0,
    "removed node actions are still rendered");
  assert.equal(await firstCommonRow.locator(".row-actions .ghost").evaluateAll(buttons =>
    buttons.every(button => getComputedStyle(button).borderTopWidth === "0px")
  ), true, "node edit and clone actions still have borders");
  assert.equal(await page.locator("#nodes-section [role='switch']").count(), 3,
    "node enabled states are not rendered as switches");
  const tuicRow = page.locator("#nodes-section .node-row").filter({ hasText: `TUIC_${commonPorts.tuic}` });
  page.once("dialog", dialog => dialog.accept());
  await tuicRow.getByRole("button", { name: "删除" }).click();
  await tuicRow.waitFor({ state: "detached" });
  await page.getByRole("button", { name: "一键创建常用节点" }).click();
  await page.getByLabel("TUIC", { exact: true }).fill(String(commonPorts.tuic));
  assert.equal(await page.locator(".preset-modal").getByText("将创建 1 个节点").count(), 1,
    "common-node retry does not limit the preview to the missing protocol");
  assert.equal(await page.locator(".preset-modal").getByText(/已存在，将跳过/).count(), 2,
    "existing common protocols are not marked as skipped");
  await page.locator(".preset-modal").getByRole("button", { name: "创建 1 个缺失节点" }).click();
  await page.getByText("1 个缺失节点已补全并通过配置校验", { exact: true }).waitFor();
  assert.equal(await page.locator("#nodes-section .node-row").count(), 3,
    "common-node retry did not restore the deleted protocol");

  await page.getByRole("button", { name: "手动上游代理" }).click();
  const residentialForm = page.locator("form.residential-builder");
  assert.notEqual(await residentialForm.getByLabel("绑定当前节点").inputValue(), "0",
    "residential node did not default to an existing protocol template");
  await residentialForm.getByLabel("代理 IP / 域名").fill("127.0.0.1:bad");
  await residentialForm.getByLabel("代理端口").fill("19080");
  await residentialForm.getByRole("button", { name: "创建订阅节点" }).click();
  const residentialError = residentialForm.locator(".residential-submit-row .residential-form-error");
  await residentialError.waitFor();
  assert.match(await residentialError.textContent(), /代理地址/,
    "residential creation error was not rendered beside the submit button");
  assert.equal(await page.locator(".workspace > .alert.error").count(), 0,
    "residential creation error leaked into the global header alert");
  await residentialForm.getByLabel("代理 IP / 域名").fill("127.0.0.1:19080");
  await residentialForm.getByLabel("代理 IP / 域名").press("Tab");
  assert.equal(await residentialForm.getByLabel("代理 IP / 域名").inputValue(), "127.0.0.1",
    "manual proxy endpoint still contains its recognized port");
  assert.equal(await residentialForm.getByLabel("代理端口").inputValue(), "19080",
    "recognized manual proxy port was not synchronized to the port field");
  await residentialForm.getByRole("button", { name: "创建订阅节点" }).click();
  await page.getByText("住宅节点已创建；可直接复制节点链接导入客户端", { exact: true }).waitFor();
  const temporaryRow = page.locator(".temporary-node-row");
  await temporaryRow.waitFor();
  assert.equal(await temporaryRow.locator(".temporary-node-title-line small").textContent(), "手动代理",
    "temporary node source is not shown below the node name");
  assert.equal(await temporaryRow.locator(".temporary-node-title-line").evaluate((line) => {
    const name = line.querySelector("strong");
    const source = line.querySelector("small");
    return Boolean(name && source && source.getBoundingClientRect().top >= name.getBoundingClientRect().bottom);
  }), true, "temporary node source is not stacked below the node name");
  assert.equal(await temporaryRow.locator(".temporary-node-main > small").count(), 0,
    "legacy protocol and server details remain below the temporary node name");
  assert.equal(await temporaryRow.locator(".temporary-countdown strong").textContent(), "永久",
    "manual residential nodes must remain permanent");
  assert.equal(await temporaryRow.getByRole("switch").count(), 0,
    "temporary node unexpectedly has an enable switch");
  assert.equal(await temporaryRow.getByRole("button", { name: "编辑" }).count(), 0,
    "temporary node unexpectedly has an edit action");
  await temporaryRow.getByRole("button", { name: "复制" }).click();
  await page.getByText("临时节点链接已复制", { exact: true }).waitFor();
  page.once("dialog", dialog => dialog.accept());
  await temporaryRow.getByRole("button", { name: "删除" }).click();
  await temporaryRow.waitFor({ state: "detached" });

  await page.getByRole("button", { name: "自定义节点" }).click();
  await page.getByRole("heading", { name: "自定义节点" }).waitFor();
  await page.getByRole("button", { name: "展开节点协议" }).click();
  assert.deepEqual(await page.locator("#node-protocol-menu .dropdown-option").evaluateAll(options =>
    options.map(option => option.dataset.value)
  ), [
    "vless_reality", "hysteria2", "tuic", "trojan_tls", "vless_grpc_reality",
    "anytls", "anytls_reality", "vless_ws_tls",
    "vless_argo"
  ], "custom inbound protocols are not rendered in the requested dropdown order");
  await page.locator("#node-protocol-menu .dropdown-option[data-value='vless_reality']").click();
  await page.getByRole("button", { name: "确定", exact: true }).click();
  await page.getByRole("heading", { name: "高级配置" }).waitFor();
  const customNodeName = page.locator(".field-grid label").filter({ hasText: "节点名称" }).locator("input").first();
  assert.match(await customNodeName.inputValue(), /丨XTLS\+Reality_8881$/,
    "custom inbound name was not generated from host, protocol and port");
  await page.getByRole("button", { name: "修改", exact: true }).click();
  await customNodeName.fill("E2E Local Reality");
  const customPort = page.getByLabel("监听端口");
  await customPort.fill(String(nodePort));
  assert.equal(await page.locator(".advanced-section").getByRole("button", { name: "确认", exact: true }).count(), 0,
    "legacy per-field confirmation buttons are still rendered");
  await page.getByRole("button", { name: "验证并部署" }).click();
  await page.getByText("节点创建成功").waitFor();
  await page.getByText("E2E Local Reality", { exact: true }).waitFor();

  const nodeRow = page.locator(".node-row").filter({ hasText: "E2E Local Reality" });
  const nodeSwitch = nodeRow.getByRole("switch");
  assert.equal(await nodeSwitch.getAttribute("aria-checked"), "true", "new node switch is not enabled");
  await nodeSwitch.click();
  await page.waitForFunction(() => [...document.querySelectorAll(".node-row")].some(row =>
    row.textContent?.includes("E2E Local Reality") &&
    row.querySelector("[role='switch']")?.getAttribute("aria-checked") === "false"
  ));
  assert.equal(await nodeRow.getByText("已停用", { exact: true }).count(), 1,
    "disabled switch state is not reflected in the node row");
  await nodeRow.getByRole("switch").click();
  await page.waitForFunction(() => [...document.querySelectorAll(".node-row")].some(row =>
    row.textContent?.includes("E2E Local Reality") &&
    row.querySelector("[role='switch']")?.getAttribute("aria-checked") === "true"
  ));

  assert.equal(await page.getByRole("heading", { name: "订阅管理" }).count(), 0,
    "removed subscription management section is still rendered");

  await page.locator(".live-chip").waitFor();

  const headerActions = page.locator(".header-actions");
  const systemButton = headerActions.getByRole("button", { name: "系统设置" });
  const logoutButton = headerActions.getByRole("button", { name: "退出" });
  const systemBox = await systemButton.boundingBox();
  const logoutBox = await logoutButton.boundingBox();
  assert.ok(systemBox && logoutBox && systemBox.x < logoutBox.x,
    "system settings must appear before logout");
  await systemButton.click();
  const settingsModal = page.locator(".settings-modal");
  await settingsModal.getByRole("heading", { name: "系统操作" }).waitFor();
  await settingsModal.getByRole("heading", { name: "基础配置" }).waitFor();
  await settingsModal.getByRole("heading", { name: "协议与安全" }).waitFor();
  await settingsModal.getByRole("heading", { name: "公网地址" }).waitFor();
  await settingsModal.getByRole("heading", { name: "节点起始端口" }).waitFor();
  await settingsModal.getByRole("heading", { name: "修改密码" }).waitFor();
  const settingsScrollbarGutter = await settingsModal.evaluate(element =>
    element.offsetWidth - element.clientWidth
  );
  assert.ok(settingsScrollbarGutter <= 4,
    "system settings still reserves a visible scrollbar gutter");
  assert.equal(await settingsModal.getByText("HOST", { exact: true }).count(), 0,
    "removed host information card is still rendered");
  assert.equal(await settingsModal.getByText("TUN 设备", { exact: true }).count(), 0,
    "removed server details are still rendered");
  const accountHeadingBox = await settingsModal.locator(".account-id-heading").boundingBox();
  const countrySettingBox = await settingsModal.locator(".country-setting").boundingBox();
  const basicSettingsBox = await settingsModal.locator(".settings-group").first().boundingBox();
  const settingsGroupBoxes = await settingsModal.locator(".settings-group").evaluateAll(elements =>
    elements.map(element => {
      const box = element.getBoundingClientRect();
      return { top: box.top, bottom: box.bottom };
    })
  );
  assert.ok(accountHeadingBox && countrySettingBox &&
    countrySettingBox.y >= accountHeadingBox.y + accountHeadingBox.height,
  "country selector is not placed below the account ID");
  assert.ok(basicSettingsBox && countrySettingBox &&
    countrySettingBox.x >= basicSettingsBox.x &&
    countrySettingBox.x + countrySettingBox.width <= basicSettingsBox.x + basicSettingsBox.width,
  "country selector overflows the general settings card");
  assert.equal(settingsGroupBoxes.length, 2, "settings card count changed");
  assert.ok(Math.abs(settingsGroupBoxes[0].top - settingsGroupBoxes[1].top) < 1 &&
    Math.abs(settingsGroupBoxes[0].bottom - settingsGroupBoxes[1].bottom) < 1,
  "general and protocol settings cards are not aligned");
  await settingsModal.getByRole("button", { name: "读取日志" }).click();
  const logsModal = page.locator(".logs-modal");
  await logsModal.getByRole("heading", { name: "系统日志" }).waitFor();
  assert.equal(await settingsModal.locator("pre.logs").count(), 0,
    "logs are still embedded in system settings");
  await logsModal.getByRole("button", { name: "关闭" }).click();
  const reassignedStartPort = nodePort + 10;
  await page.getByLabel("起始端口").fill(String(reassignedStartPort));
  await page.getByRole("button", { name: "保存并重新匹配节点" }).click();
  await page.getByText(`起始端口已更新为 ${reassignedStartPort}，4 个节点已重新匹配端口`, { exact: true }).waitFor();
  await page.locator("#nodes-section .node-row")
    .filter({ hasText: `XTLS-Reality_${reassignedStartPort}` }).waitFor();
  assert.match(await nodeRow.textContent(), new RegExp(`:${reassignedStartPort + 3}\\b`),
    "custom node port was not reassigned with the configured range");
  if (artifactDir) {
    await page.screenshot({ path: join(artifactDir, "desktop-system.png"), fullPage: true });
  }
  await page.getByRole("button", { name: "关闭" }).click();

  const mobile = await context.newPage();
  mobile.on("pageerror", error => browserErrors.push(error.message));
  mobile.on("console", message => {
    if (message.type() === "error") browserErrors.push(message.text());
  });
  await mobile.setViewportSize({ width: 390, height: 844 });
  await mobile.goto(`${baseURL}/${adminPath}/`, { waitUntil: "domcontentloaded" });
  await mobile.getByRole("heading", { name: "住宅ip代理设置" }).waitFor();
  assert.equal(await mobile.locator(".kui-header").evaluate(element => getComputedStyle(element).position),
    "static", "mobile header still follows the viewport");
  assert.equal(await mobile.locator(".brand-module .action-label").isVisible(), true,
    "GitHub label is hidden in compressed header");
  assert.equal(await mobile.locator(".monitor-module .action-label").isVisible(), true,
    "monitor label is hidden in compressed header");
  const mobileBrandModuleBox = await mobile.locator(".brand-module").boundingBox();
  const mobileLiveBox = await mobile.locator(".monitor-module .live-chip").boundingBox();
  const mobileMonitorModuleBox = await mobile.locator(".monitor-module").boundingBox();
  const mobileActionsBox = await mobile.locator(".header-actions").boundingBox();
  const mobileHeaderBox = await mobile.locator(".kui-header").boundingBox();
  assert.equal(await mobile.locator(".brand-module .brand").evaluate(
    element => getComputedStyle(element).whiteSpace
  ), "nowrap", "compressed header wraps the J-UI brand");
  assert.ok(desktopLiveBox && mobileLiveBox &&
    desktopLiveBox.width > mobileLiveBox.width && mobileLiveBox.width >= 116,
  "live monitor module does not adapt its own width");
  const mobileGridPlacement = await mobile.locator(".kui-header").evaluate(element => {
    const brand = element.querySelector(".brand-module");
    const monitor = element.querySelector(".monitor-module");
    const actions = element.querySelector(".header-actions");
    return {
      rows: getComputedStyle(element).gridTemplateRows,
      brandRow: brand ? getComputedStyle(brand).gridRowStart : "",
      monitorRow: monitor ? getComputedStyle(monitor).gridRowStart : "",
      actionsRow: actions ? getComputedStyle(actions).gridRowStart : "",
      brandColumn: brand ? getComputedStyle(brand).gridColumnStart : "",
      monitorColumn: monitor ? getComputedStyle(monitor).gridColumnStart : ""
    };
  });
  assert.equal(mobileGridPlacement.rows.trim().split(/\s+/).length, 2,
    "compressed header does not use two rows");
  assert.deepEqual(
    mobileGridPlacement,
    { ...mobileGridPlacement, brandRow: "1", monitorRow: "1", actionsRow: "2", brandColumn: "1", monitorColumn: "2" },
    "compressed header does not place modules one and two above module three"
  );
  assert.ok(mobileHeaderBox &&
    Math.abs(mobileActionsBox.x - mobileBrandModuleBox.x) < 1 &&
    Math.abs((mobileBrandModuleBox.x - mobileHeaderBox.x) -
      (mobileHeaderBox.x + mobileHeaderBox.width -
        mobileActionsBox.x - mobileActionsBox.width)) < 1,
  "compressed header actions do not align with the brand content inset");
  assert.equal(await mobile.locator(".header-actions .action-label").first().evaluate(
    element => getComputedStyle(element).display
  ), "none", "compressed header still shows action text");
  const mobileActionBoxes = await mobile.locator(".header-actions .top-action").evaluateAll(elements =>
    elements.map(element => {
      const box = element.getBoundingClientRect();
      return { x: box.x, width: box.width };
    })
  );
  assert.equal(mobileActionBoxes.length, 6, "compressed header action count changed");
  for (let index = 0; index < mobileActionBoxes.length; index++) {
    assert.ok(mobileActionBoxes[index].width >= 42,
      "compressed header action has an undersized touch target");
    if (index > 0) {
      const previous = mobileActionBoxes[index - 1];
      assert.ok(mobileActionBoxes[index].x - (previous.x + previous.width) >= 5,
        "compressed header action spacing is too small");
    }
  }
  const exitPageFits = await mobile.evaluate(
    () => document.documentElement.scrollWidth <= window.innerWidth
  );
  assert.equal(exitPageFits, true, "mobile outbound page has horizontal overflow");
  await mobile.getByRole("button", { name: "系统设置" }).click();
  const mobileSettingsModal = mobile.locator(".settings-modal");
  await mobileSettingsModal.getByRole("heading", { name: "基础配置" }).waitFor();
  const mobileAccountBox = await mobileSettingsModal.locator(".account-id-heading").boundingBox();
  const mobileCountryBox = await mobileSettingsModal.locator(".country-setting").boundingBox();
  const mobileBasicBox = await mobileSettingsModal.locator(".settings-group").first().boundingBox();
  assert.ok(mobileAccountBox && mobileCountryBox &&
    mobileCountryBox.y >= mobileAccountBox.y + mobileAccountBox.height,
  "mobile country selector is not below the account ID");
  assert.ok(mobileBasicBox && mobileCountryBox &&
    mobileCountryBox.x >= mobileBasicBox.x &&
    mobileCountryBox.x + mobileCountryBox.width <= mobileBasicBox.x + mobileBasicBox.width,
  "mobile country selector overflows the general settings card");
  await mobileSettingsModal.getByRole("button", { name: "关闭" }).click();
  await mobile.getByRole("button", { name: "自定义节点" }).click();
  await mobile.getByRole("heading", { name: "自定义节点" }).waitFor();
  await mobile.getByRole("button", { name: "展开节点协议" }).click();
  await mobile.locator("#node-protocol-menu .dropdown-option[data-value='vless_reality']").click();
  await mobile.getByRole("button", { name: "确定", exact: true }).click();
  await mobile.getByRole("heading", { name: "高级配置" }).waitFor();
  const fitsViewport = await mobile.evaluate(
    () => document.documentElement.scrollWidth <= window.innerWidth
  );
  assert.equal(fitsViewport, true, "mobile layout has horizontal overflow");
  if (artifactDir) {
    await mobile.screenshot({ path: join(artifactDir, "mobile-node-form.png"), fullPage: true });
  }
  await mobile.close();

  page.once("dialog", dialog => dialog.accept());
  await page.locator(".node-row").filter({ hasText: "E2E Local Reality" })
    .getByRole("button", { name: "删除" }).click();
  await page.getByText("E2E Local Reality", { exact: true }).waitFor({ state: "detached" });

  await page.getByRole("button", { name: "系统设置" }).click();
  await page.locator(".settings-language").getByRole("button", { name: "展开语言" }).click();
  await page.locator("#global-language-menu .dropdown-option[data-value='en']").click();
  await page.locator(".settings-modal").getByRole("button", { name: "Close" }).click();
  await page.getByRole("button", { name: "Sign out" }).click();
  const englishHeading = page.locator(".auth-copy.auth-copy-english h1");
  await englishHeading.waitFor();
  assert.match(await englishHeading.textContent(), /Easy subscription/);
  const englishHeadingFontSize = await englishHeading.evaluate(element => parseFloat(getComputedStyle(element).fontSize));
  assert.ok(englishHeadingFontSize <= 68,
    `English login slogan is still oversized (${englishHeadingFontSize}px)`);
  if (artifactDir) {
    await page.screenshot({ path: join(artifactDir, "desktop-login-english.png"), fullPage: true });
  }
  // The unauthenticated session bootstrap after an intentional logout returns 401.
  browserErrors.length = 0;

  assert.deepEqual(browserErrors, [], `browser errors: ${browserErrors.join(" | ")}`);
  console.log("J-UI desktop and mobile browser smoke passed");
} catch (caught) {
  if (artifactDir) {
    await page.screenshot({ path: join(artifactDir, "failure.png"), fullPage: true });
  }
  console.error(`Browser smoke failed at ${page.url()}`);
  throw caught;
} finally {
  await context.close();
  await browser.close();
}
