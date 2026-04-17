import fs from "node:fs/promises";
import path from "node:path";
import { chromium } from "playwright";

const outputDirArg = process.argv[2];
if (!outputDirArg) {
  console.error("Usage: node capture_ui_screenshots.mjs <output-dir>");
  process.exit(1);
}

const outputDir = path.resolve(outputDirArg);
const baseUrl = (process.env.KEYWARDEN_SCREENSHOT_BASE_URL || "https://localhost").replace(/\/+$/, "");
const username = process.env.KEYWARDEN_ADMIN_USERNAME || "admin";
const adminEmail = process.env.KEYWARDEN_ADMIN_EMAIL || "";
const password = process.env.KEYWARDEN_ADMIN_PASSWORD || "";
const requestedServerId = process.env.KEYWARDEN_SCREENSHOT_SERVER_ID || "";

if (!password) {
  console.error("KEYWARDEN_ADMIN_PASSWORD is required for authenticated screenshots.");
  process.exit(1);
}

await fs.mkdir(outputDir, { recursive: true });

const browser = await chromium.launch({ headless: true });
const context = await browser.newContext({
  ignoreHTTPSErrors: true,
  viewport: { width: 1600, height: 900 },
});
const page = await context.newPage();

const shots = [];

async function screenshot(name, label, gotoUrl = null) {
  const fileName = `${name}.png`;
  const filePath = path.join(outputDir, fileName);
  const item = {
    name,
    label,
    requestedUrl: gotoUrl || page.url(),
    finalUrl: "",
    status: "ok",
    file: fileName,
    error: "",
  };
  try {
    if (gotoUrl) {
      await page.goto(gotoUrl, { waitUntil: "domcontentloaded", timeout: 45000 });
    }
    await page.waitForTimeout(700);
    await page.screenshot({ path: filePath, fullPage: true });
    item.finalUrl = page.url();
  } catch (err) {
    item.status = "error";
    item.error = String(err);
    item.finalUrl = page.url();
  }
  shots.push(item);
}

async function ensureNativeLoginForm() {
  if (await page.locator('input[name="username"]').count()) {
    return;
  }
  const nativeLink = page.getByRole("link", { name: /Log in with Keywarden/i });
  if (await nativeLink.count()) {
    await nativeLink.first().click();
    await page.waitForLoadState("domcontentloaded");
    return;
  }
  await page.goto(`${baseUrl}/accounts/login/?native=1`, { waitUntil: "domcontentloaded", timeout: 45000 });
}

async function login() {
  await screenshot("01-login-entry", "Login entry", `${baseUrl}/accounts/login/`);
  const candidates = [...new Set([username, adminEmail].filter(Boolean))];
  if (!candidates.length) {
    throw new Error("No login identifier candidates available.");
  }

  let loggedIn = false;
  for (const identifier of candidates) {
    await page.goto(`${baseUrl}/accounts/login/?native=1`, { waitUntil: "domcontentloaded", timeout: 45000 });
    await ensureNativeLoginForm();
    await screenshot("02-login-native", "Native login form");

    if (!(await page.locator('input[name="username"]').count())) {
      throw new Error("Could not find native login form.");
    }

    await page.fill('input[name="username"]', identifier);
    await page.fill('input[name="password"]', password);
    await Promise.all([
      page.waitForNavigation({ waitUntil: "domcontentloaded", timeout: 45000 }).catch(() => null),
      page.getByRole("button", { name: /Sign in/i }).click(),
    ]);

    await page.goto(`${baseUrl}/servers/`, { waitUntil: "domcontentloaded", timeout: 45000 });
    if (!page.url().includes("/accounts/login")) {
      loggedIn = true;
      break;
    }
  }

  if (!loggedIn) {
    throw new Error("Login failed for all configured identifiers.");
  }

  await screenshot("03-dashboard", "Dashboard", `${baseUrl}/servers/`);
}

async function detectServerId() {
  if (requestedServerId) {
    return requestedServerId;
  }
  const hrefs = await page.$$eval("a[href]", (nodes) => nodes.map((node) => node.getAttribute("href") || ""));
  for (const href of hrefs) {
    const match = href.match(/^\/servers\/(\d+)\/$/);
    if (match) {
      return match[1];
    }
  }
  return "";
}

try {
  await login();
  await screenshot("04-profile", "Profile/key upload", `${baseUrl}/accounts/profile/`);
  await screenshot("05-server-dashboard", "Server dashboard", `${baseUrl}/servers/`);
  await screenshot("06-admin-dashboard", "Access grant/revocation queue", `${baseUrl}/servers/admin/`);
  await screenshot("07-admin-server-reg", "Server registration (Django admin)", `${baseUrl}/admin/servers/enrollmenttoken/`);

  const serverId = await detectServerId();
  if (serverId) {
    await screenshot("08-server-detail", "Server detail/heartbeat", `${baseUrl}/servers/${serverId}/`);
    await screenshot("09-server-audit", "Server audit logs", `${baseUrl}/servers/${serverId}/audit/`);
    await screenshot("10-server-settings", "Server sync/log settings", `${baseUrl}/servers/${serverId}/settings/`);
    await screenshot("11-server-shell", "Browser shell interface", `${baseUrl}/servers/${serverId}/shell/`);
    await screenshot("12-server-admin", "Server access admin view", `${baseUrl}/servers/${serverId}/admin/`);
  } else {
    shots.push({
      name: "server-detection",
      label: "Server routes skipped",
      requestedUrl: `${baseUrl}/servers/`,
      finalUrl: page.url(),
      status: "error",
      file: "",
      error: "No server id detected from dashboard links.",
    });
  }
} finally {
  await context.close();
  await browser.close();
}

const manifest = {
  generatedAtUtc: new Date().toISOString(),
  baseUrl,
  username,
  shots,
};
await fs.writeFile(path.join(outputDir, "manifest.json"), JSON.stringify(manifest, null, 2));

const mdLines = [
  "# Screenshot Index",
  "",
  `- Base URL: \`${baseUrl}\``,
  `- Generated: \`${manifest.generatedAtUtc}\``,
  "",
  "| File | Label | Status | URL |",
  "|---|---|---|---|",
];
for (const shot of shots) {
  const filePart = shot.file ? `\`${shot.file}\`` : "(none)";
  const urlPart = shot.finalUrl || shot.requestedUrl || "";
  const status = shot.status === "ok" ? "ok" : `error: ${shot.error}`;
  mdLines.push(`| ${filePart} | ${shot.label} | ${status} | \`${urlPart}\` |`);
}
mdLines.push("");
await fs.writeFile(path.join(outputDir, "README.md"), mdLines.join("\n"));

console.log(`Captured ${shots.filter((shot) => shot.status === "ok").length}/${shots.length} screenshots to ${outputDir}`);
