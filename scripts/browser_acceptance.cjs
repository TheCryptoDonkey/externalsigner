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
  await page.close();
  return {
    colorScheme,
    violations,
    browserErrors,
    largeText,
    largeTextHasHorizontalOverflow:
      largeText.extensionScrollWidth > largeText.extensionClientWidth + 1,
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
        result.largeTextHasHorizontalOverflow,
    )
  ) {
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error(error.stack || error);
  process.exitCode = 1;
});
