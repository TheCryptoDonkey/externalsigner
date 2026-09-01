const fs = require("node:fs");
const puppeteer = require("puppeteer-core");
const axe = require("axe-core");

const baseUrl = process.env.BROWSER_BASE_URL || "http://127.0.0.1:5011";
const cookieJar = process.env.BROWSER_COOKIE_JAR || ".browser-cookies";
const chromePath =
  process.env.CHROME_PATH ||
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const colorSchemes = (process.env.COLOR_SCHEMES || "light,dark").split(",");

function readCookies() {
  return fs
    .readFileSync(cookieJar, "utf8")
    .split("\n")
    .filter(
      (line) =>
        line && (!line.startsWith("#") || line.startsWith("#HttpOnly_")),
    )
    .map((line) => {
      const fields = line.replace(/^#HttpOnly_/, "").split("\t");
      return {
        name: fields[5],
        value: fields[6],
        domain: fields[0],
        path: fields[2],
        secure: fields[3] === "TRUE",
      };
    });
}

async function axeViolations(page, selector, label) {
  await page.addScriptTag({ content: axe.source });
  const violations = await page.evaluate(async (target) => {
    const result = await axe.run(document.querySelector(target), {
      runOnly: {
        type: "tag",
        values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"],
      },
    });
    return result.violations.map((item) => ({
      id: item.id,
      impact: item.impact,
      help: item.help,
      nodes: item.nodes.map((node) => ({
        target: node.target.join(" "),
        failure: node.failureSummary,
      })),
    }));
  }, selector);
  return violations.map((violation) => ({ scope: label, ...violation }));
}

async function openRouteWithKeyboard(page, buttonText) {
  const focused = await page.evaluate((text) => {
    const button = [...document.querySelectorAll("button")].find(
      (element) =>
        element.innerText.includes(text) &&
        element.getBoundingClientRect().width > 0 &&
        element.getBoundingClientRect().height > 0,
    );
    if (!button) throw new Error(`Route button is missing: ${text}`);
    button.focus();
    return document.activeElement === button;
  }, buttonText);
  if (!focused)
    throw new Error(`Route button cannot receive focus: ${buttonText}`);
  await page.keyboard.press("Enter");
  await page.waitForSelector(".externalsigner-dialog", { visible: true });
}

async function dismissHostNotice(page) {
  const dismissed = await page.evaluate(() => {
    const dialog = [...document.querySelectorAll('[role="dialog"]')].find(
      (element) =>
        element.getBoundingClientRect().height > 0 &&
        element.innerText.includes("Important!"),
    );
    if (!dialog) return false;
    const acknowledge = [...dialog.querySelectorAll("button")].find((element) =>
      element.innerText.includes("I UNDERSTAND"),
    );
    if (!acknowledge)
      throw new Error("LNbits first-login notice cannot be dismissed.");
    acknowledge.click();
    return true;
  });
  if (dismissed) {
    await page.waitForFunction(
      () =>
        ![...document.querySelectorAll('[role="dialog"]')].some(
          (element) =>
            element.getBoundingClientRect().height > 0 &&
            element.innerText.includes("Important!"),
        ),
    );
  }
}

async function closeDialog(page) {
  await page.evaluate(() => {
    const dialog = document.querySelector(".externalsigner-dialog");
    const cancel = [...dialog.querySelectorAll("button")].find((element) =>
      element.innerText.includes("Cancel"),
    );
    if (!cancel) throw new Error("Dialog cancel button is missing.");
    cancel.click();
  });
  await page.waitForSelector(".externalsigner-dialog", { hidden: true });
}

function connectionFixture(overrides = {}) {
  return {
    id: "fixture-connection",
    name: "Acceptance signer",
    mode: "bunker",
    remote_signer_pubkey: "b".repeat(64),
    user_pubkey: "c".repeat(64),
    client_pubkey: "d".repeat(64),
    relays: ["wss://relay.example.invalid"],
    permissions: ["get_public_key", "sign_event:27235"],
    status: "connected",
    last_error: null,
    pairing_expires_at: null,
    proof_verified_at: "2026-09-02T00:00:00Z",
    last_used_at: "2026-09-02T00:00:00Z",
    created_at: "2026-09-02T00:00:00Z",
    updated_at: "2026-09-02T00:00:00Z",
    pairing_uri: null,
    ...overrides,
  };
}

async function installStateFixtures(page) {
  const fixtures = [
    connectionFixture({ id: "connected", name: "Working signer" }),
    connectionFixture({
      id: "expired-qr",
      name: "Expired QR pairing",
      mode: "nostrconnect",
      remote_signer_pubkey: null,
      user_pubkey: null,
      status: "error",
      last_error: "The pairing secret expired before the signer approved it.",
      pairing_expires_at: "2026-09-01T00:00:00Z",
      pairing_uri: `nostrconnect://${"e".repeat(64)}?relay=wss%3A%2F%2Frelay.example.invalid&secret=fixture`,
      proof_verified_at: null,
    }),
    connectionFixture({
      id: "disconnected",
      name: "Disconnected signer",
      status: "error",
      last_error: "The signer did not answer after the relay disconnected.",
      proof_verified_at: null,
    }),
    connectionFixture({
      id: "revoked",
      name: "Revoked signer",
      status: "revoked",
      remote_signer_pubkey: null,
      user_pubkey: null,
      client_pubkey: "",
      proof_verified_at: null,
    }),
  ];
  await page.evaluate((connections) => {
    const root = document.querySelector("#vue")._vnode.component.proxy;
    clearInterval(root.connectionTimer);
    clearInterval(root.operationTimer);
    root.connections = connections;
    root.showRevoked = true;
    root.clockNow = Date.now();
    root.activeOperation = {
      id: "failed-operation",
      connection_id: "disconnected",
      request_id: "fixture-request",
      method: "ping",
      purpose: "user",
      status: "failed",
      result: null,
      error: "Signer request failed after the relay disconnected.",
      auth_url: null,
      response_event_id: null,
      created_at: "2026-09-02T00:00:00Z",
      updated_at: "2026-09-02T00:00:00Z",
    };
    window.__externalSignerAcceptanceActions = [];
    root.retry = (connection) => {
      window.__externalSignerAcceptanceActions.push(`retry:${connection.id}`);
    };
    root.ping = (connection) => {
      window.__externalSignerAcceptanceActions.push(`ping:${connection.id}`);
    };
  }, fixtures);
  await page.waitForFunction(() =>
    document.body.innerText.includes("Expired QR pairing"),
  );
}

async function openConnectionWithKeyboard(page, connectionName) {
  const focused = await page.evaluate((name) => {
    const item = [
      ...document.querySelectorAll(".q-expansion-item .q-item"),
    ].find(
      (element) =>
        element.innerText.includes(name) &&
        element.getBoundingClientRect().height > 0,
    );
    if (!item) throw new Error(`Connection row is missing: ${name}`);
    item.focus();
    return document.activeElement === item;
  }, connectionName);
  if (!focused)
    throw new Error(`Connection row cannot receive focus: ${connectionName}`);
  await page.keyboard.press("Enter");
}

async function activateButtonWithKeyboard(page, buttonText) {
  const focused = await page.evaluate((text) => {
    const button = [...document.querySelectorAll("button")].find(
      (element) =>
        element.innerText.includes(text) &&
        element.getBoundingClientRect().height > 0,
    );
    if (!button) throw new Error(`State action is missing: ${text}`);
    button.focus();
    return document.activeElement === button;
  }, buttonText);
  if (!focused)
    throw new Error(`State action cannot receive focus: ${buttonText}`);
  await page.keyboard.press("Enter");
}

async function stateAcceptance(page, colorScheme, viewport) {
  await page.setViewport({ ...viewport, deviceScaleFactor: 1 });
  await page.reload({ waitUntil: "networkidle0" });
  await page.waitForSelector(".externalsigner-page");
  await page.evaluate((scheme) => {
    window.g.darkChoice = scheme === "dark";
  }, colorScheme);
  await page.waitForFunction(
    (scheme) => document.body.classList.contains(`body--${scheme}`),
    {},
    colorScheme,
  );
  await dismissHostNotice(page);
  await installStateFixtures(page);
  await openConnectionWithKeyboard(page, "Working signer");
  await page.waitForFunction(() =>
    [...document.querySelectorAll("button")].some(
      (element) =>
        element.innerText.includes("Test connection") &&
        element.getBoundingClientRect().height > 0,
    ),
  );

  await activateButtonWithKeyboard(page, "Test connection");
  await activateButtonWithKeyboard(page, "Create fresh pairing");
  await activateButtonWithKeyboard(page, "Retry connection");

  const actions = await page.evaluate(
    () => window.__externalSignerAcceptanceActions,
  );
  const expectedActions = [
    "ping:connected",
    "retry:expired-qr",
    "retry:disconnected",
  ];
  const missingActions = expectedActions.filter(
    (action) => !actions.includes(action),
  );

  await activateButtonWithKeyboard(page, "Revoke");
  await page.waitForFunction(() =>
    [...document.querySelectorAll('[role="dialog"]')].some(
      (element) =>
        element.getBoundingClientRect().height > 0 &&
        element.innerText.includes("erase its local client capability"),
    ),
  );
  // Axe must inspect the settled dialog, not a semi-transparent transition frame.
  await new Promise((resolve) => setTimeout(resolve, 500));
  const revokeViolations = await axeViolations(
    page,
    '[role="dialog"]',
    `${colorScheme} ${viewport.width}px revoke confirmation`,
  );
  const revokeButtonStyles = await page.$$eval(
    '[role="dialog"] button',
    (buttons) =>
      buttons.map((button) => {
        const style = window.getComputedStyle(button);
        return {
          text: button.innerText,
          color: style.color,
          backgroundColor: style.backgroundColor,
          opacity: style.opacity,
          disabled: button.disabled,
        };
      }),
  );
  await page.keyboard.press("Escape");
  await page.waitForFunction(
    () =>
      ![...document.querySelectorAll('[role="dialog"]')].some(
        (element) =>
          element.getBoundingClientRect().height > 0 &&
          element.innerText.includes("erase its local client capability"),
      ),
  );

  const state = await page.evaluate(() => {
    const text = document.querySelector(".externalsigner-page").innerText;
    const requiredCopy = [
      "Working signer",
      "Identity verified. Ready for approved requests.",
      "Expired QR pairing",
      "The pairing secret expired",
      "Create fresh pairing",
      "Disconnected signer",
      "Retry connection",
      "Local client capability erased. Revoke it in the signer too.",
      "Signer request failed after the relay disconnected.",
      "Never paste an nsec into this extension.",
    ];
    const nsecInputs = [...document.querySelectorAll("input, textarea")].filter(
      (element) => {
        const id = element.getAttribute("id");
        const label = id
          ? document.querySelector(`label[for="${CSS.escape(id)}"]`)?.innerText
          : "";
        return `${label || ""} ${element.getAttribute("placeholder") || ""}`
          .toLowerCase()
          .includes("nsec");
      },
    );
    return {
      missingCopy: requiredCopy.filter((item) => !text.includes(item)),
      nsecInputCount: nsecInputs.length,
      clientWidth: document.querySelector(".externalsigner-page").clientWidth,
      scrollWidth: document.querySelector(".externalsigner-page").scrollWidth,
    };
  });
  return {
    viewport: viewport.width,
    missingActions,
    missingCopy: state.missingCopy,
    nsecInputCount: state.nsecInputCount,
    hasHorizontalOverflow: state.scrollWidth > state.clientWidth + 1,
    violations: [
      ...(await axeViolations(
        page,
        ".externalsigner-page",
        `${colorScheme} ${viewport.width}px state journeys`,
      )),
      ...revokeViolations,
    ],
    revokeButtonStyles,
  };
}

async function runScheme(browser, colorScheme) {
  const page = await browser.newPage();
  const browserErrors = [];
  page.on("pageerror", (error) => browserErrors.push(`page: ${error.message}`));
  page.on("console", (message) => {
    if (message.type() === "error")
      browserErrors.push(`console: ${message.text()}`);
  });
  page.on("response", (response) => {
    if (response.url().startsWith(baseUrl) && response.status() >= 400) {
      browserErrors.push(`http ${response.status()}: ${response.url()}`);
    }
  });

  await page.setCookie(...readCookies());
  await page.setViewport({ width: 1440, height: 1000, deviceScaleFactor: 1 });
  await page.goto(`${baseUrl}/externalsigner/`, { waitUntil: "networkidle0" });
  await page.waitForSelector(".externalsigner-page");
  await page.evaluate((scheme) => {
    window.g.darkChoice = scheme === "dark";
  }, colorScheme);
  await page.waitForFunction(
    (scheme) => document.body.classList.contains(`body--${scheme}`),
    {},
    colorScheme,
  );
  await dismissHostNotice(page);
  await page.waitForFunction(() =>
    document.body.innerText.includes(
      "Sign from LNbits. Keep your key elsewhere.",
    ),
  );

  const violations = [];
  violations.push(
    ...(await axeViolations(
      page,
      ".externalsigner-page",
      `${colorScheme} desktop page`,
    )),
  );

  await openRouteWithKeyboard(page, "I have a signer invite");
  violations.push(
    ...(await axeViolations(
      page,
      ".externalsigner-dialog",
      `${colorScheme} invite dialog`,
    )),
  );
  await closeDialog(page);

  await page.setViewport({ width: 390, height: 844, deviceScaleFactor: 1 });
  await page.reload({ waitUntil: "networkidle0" });
  await page.waitForSelector(".externalsigner-page");
  violations.push(
    ...(await axeViolations(
      page,
      ".externalsigner-page",
      `${colorScheme} mobile page`,
    )),
  );

  await openRouteWithKeyboard(page, "My signer scans QR codes");
  violations.push(
    ...(await axeViolations(
      page,
      ".externalsigner-dialog",
      `${colorScheme} QR dialog`,
    )),
  );
  await closeDialog(page);

  await page.addStyleTag({ content: "html { font-size: 200% !important; }" });
  const largeText = await page.evaluate(() => {
    const extension = document.querySelector(".externalsigner-page");
    return {
      extensionClientWidth: extension.clientWidth,
      extensionScrollWidth: extension.scrollWidth,
      documentClientWidth: document.documentElement.clientWidth,
      documentScrollWidth: document.documentElement.scrollWidth,
      routeChoicesVisible:
        document.body.innerText.includes("Your signer gives you a link") &&
        document.body.innerText.includes("Your signer scans a QR"),
    };
  });
  if (process.env.BROWSER_SCREENSHOTS) {
    await page.screenshot({
      path: `.browser-${colorScheme}-large-text.png`,
      fullPage: true,
    });
  }
  const stateJourneys = [];
  for (const viewport of [
    { width: 1440, height: 1000 },
    { width: 390, height: 844 },
  ]) {
    stateJourneys.push(await stateAcceptance(page, colorScheme, viewport));
  }
  await page.close();
  return {
    colorScheme,
    violations,
    browserErrors,
    largeText,
    largeTextHasHorizontalOverflow:
      largeText.extensionScrollWidth > largeText.extensionClientWidth + 1,
    stateJourneys,
  };
}

async function main() {
  const browser = await puppeteer.launch({
    executablePath: chromePath,
    headless: true,
    args: ["--disable-background-networking", "--no-first-run", "--no-sandbox"],
  });
  const evidence = [];
  try {
    for (const colorScheme of colorSchemes) {
      evidence.push(await runScheme(browser, colorScheme));
    }
  } finally {
    await browser.close();
  }

  console.log(JSON.stringify(evidence, null, 2));
  if (
    evidence.some(
      (result) =>
        result.violations.length ||
        result.browserErrors.length ||
        !result.largeText.routeChoicesVisible ||
        result.largeTextHasHorizontalOverflow ||
        result.stateJourneys.some(
          (journey) =>
            journey.violations.length ||
            journey.missingActions.length ||
            journey.missingCopy.length ||
            journey.nsecInputCount ||
            journey.hasHorizontalOverflow,
        ),
    )
  ) {
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error(error.stack || error);
  process.exitCode = 1;
});
