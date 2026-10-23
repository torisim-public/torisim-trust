// Synthetic publication-boundary regressions. No external HTTP requests.
import test from "node:test";
import assert from "node:assert/strict";
import {execFile} from "node:child_process";
import {promisify} from "node:util";
import {readFile, writeFile, mkdtemp, chmod, rm} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {fileURLToPath} from "node:url";
import {
  validateBaseUrl, runPrivacyChecks, findThirdPartyReferences, parseCSP,
  checkCSPHeader, checkCanaryDates, verifyClearsignedText, dearmorPublicKey,
  computeFingerprintV4, countPrimaryKeyPackets, MAX_RESPONSE_BYTES,
} from "../src/privacy-check.mjs";

const exec = promisify(execFile);
const cli = fileURLToPath(new URL("../src/privacy-check.mjs", import.meta.url));
const publicKey = await readFile(new URL("../public/pgp.txt", import.meta.url), "utf8");
const signedCanary = await readFile(new URL("../public/canary.txt", import.meta.url), "utf8");
const keyring = dearmorPublicKey(publicKey);
const base = "https://fixture.invalid";
const csp = "default-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; object-src 'none'";
const headers = {
  "content-type": "text/html; charset=utf-8", "content-security-policy": csp,
  "permissions-policy": "camera=(), microphone=(), geolocation=()", "referrer-policy": "no-referrer",
  "strict-transport-security": "max-age=31536000; includeSubDomains", "x-content-type-options": "nosniff",
  "cache-control": "private, no-store", "x-robots-tag": "noindex, nofollow",
};

function responseFor(url) {
  const path = new URL(url).pathname;
  if (path === "/pgp.txt") return new Response(publicKey, {headers: {"content-type": "text/plain"}});
  if (path === "/canary.txt" || path === "/mirrors.txt") return new Response(signedCanary, {headers: {"content-type": "text/plain"}});
  if (path === "/.well-known/security.txt") return new Response("Contact: mailto:security@example.invalid\nExpires: 2099-01-01T00:00:00Z\nEncryption: https://fixture.invalid/pgp.txt\n", {headers: {"content-type": "text/plain"}});
  return new Response("<!doctype html><html><body>Fixture</body></html>", {headers});
}
const resultFor = (run, id) => run.results.find((result) => result.id === id);
async function mockRun(replace, options = {}) {
  return runPrivacyChecks(base, {verifySignatures: false, fetchImpl: async (url, init) => replace?.(url, init) ?? responseFor(url), ...options});
}

for (const url of [
  "file:///etc/passwd", "http://example.invalid", "ftp://example.invalid", "https://user:secret@example.invalid",
  "https://example.invalid?secret=a", "https://example.invalid#secret", "https://example.invalid?", "https://example.invalid#",
  "https://example.invalid/orders/secret", "https://example.invalid/.", "https://example.invalid/any/..", " https://example.invalid", "https://example.invalid\\@other.invalid",
]) {
  test(`reject unsafe or ambiguous base: ${url}`, async () => {
    let requests = 0;
    await assert.rejects(runPrivacyChecks(url, {fetchImpl: async () => { requests++; return responseFor(base); }}));
    assert.equal(requests, 0);
  });
}

test("accept only explicit HTTPS origins and literal loopback HTTP fixtures", () => {
  assert.equal(validateBaseUrl("https://example.invalid/"), "https://example.invalid");
  assert.equal(validateBaseUrl("http://127.0.0.1:12345"), "http://127.0.0.1:12345");
  assert.equal(validateBaseUrl("http://[::1]:12345"), "http://[::1]:12345");
  assert.throws(() => validateBaseUrl("http://localhost:12345"));
});

test("invalid timeout values fail before making a request", async () => {
  for (const timeoutMs of [NaN, Infinity, 0, -1, 60001, 1.1, "100"]) {
    let requests = 0;
    await assert.rejects(runPrivacyChecks(base, {timeoutMs, fetchImpl: async () => { requests++; return responseFor(base); }}));
    assert.equal(requests, 0);
  }
});

test("redirects are refused with manual mode, without visiting the destination", async () => {
  const visited = [];
  const run = await mockRun((url, init) => {
    visited.push(url);
    assert.equal(init.redirect, "manual");
    assert.equal(init.credentials, "omit");
    if (new URL(url).pathname === "/") return new Response(null, {status: 302, headers: {location: "http://127.0.0.1:9000/private"}});
  });
  assert.equal(resultFor(run, "headers:/").pass, false);
  assert.match(resultFor(run, "headers:/").reason, /redirect refused/);
  assert.ok(visited.every((url) => new URL(url).origin === base));
});

test("declared and streaming oversized response bodies fail closed", async () => {
  for (const declared of [true, false]) {
    const run = await mockRun((url) => new URL(url).pathname === "/" ? new Response("x".repeat(declared ? 1 : MAX_RESPONSE_BYTES + 1), {headers: {...headers, ...(declared ? {"content-length": String(MAX_RESPONSE_BYTES + 1)} : {})}}) : undefined);
    assert.equal(resultFor(run, "headers:/").pass, false);
    assert.match(resultFor(run, "headers:/").reason, /exceeds/);
  }
});

test("an HTTP error page or non-HTML page cannot pass as a working public page", async () => {
  for (const change of [{status: 500, headers}, {headers: {...headers, "content-type": "application/json"}}]) {
    const run = await mockRun((url) => new URL(url).pathname === "/" ? new Response("{}", change) : undefined);
    assert.equal(resultFor(run, "headers:/").pass, false);
  }
});

test("similar header names cannot satisfy restrictive headers by substring", async () => {
  const run = await mockRun((url) => new URL(url).pathname === "/checkout" ? new Response("<html></html>", {headers: {...headers,
    "permissions-policy": "xcamera=(), xmicrophone=(), xgeolocation=()", "strict-transport-security": "not-max-age=31536000",
    "cache-control": "x-no-store", "x-robots-tag": "not-noindex"}}) : undefined);
  const result = resultFor(run, "headers:/checkout");
  assert.equal(result.pass, false);
  for (const token of ["permissions-policy", "strict-transport-security", "cache-control", "x-robots-tag"]) assert.match(result.reason, new RegExp(token));
});

test("CSP duplicates use browser first-directive semantics", () => {
  assert.deepEqual(parseCSP("default-src *; default-src 'self'").get("default-src"), ["*"]);
  assert.ok(checkCSPHeader(`default-src *; ${csp}`).some((problem) => problem.includes("default-src")));
  assert.ok(checkCSPHeader(`${csp}; script-src-elem *`).some((problem) => problem.includes("script-src-elem")));
});

test("HTML entity-obfuscated external references are caught", () => {
  for (const html of [
    '<img src="&#47;&#47;outside.invalid/pixel">', '<script src="https&colon;&sol;&sol;outside.invalid/a.js"></script>',
    '<img src="https&#58;//outside.invalid/pixel">', '<img src="https:&bsol;&bsol;outside.invalid/pixel">',
  ]) assert.ok(findThirdPartyReferences(html, base).length > 0, html);
});

test("fake attributes inside another attribute do not hide the real reference", () => {
  const html = '<img title="src=\'/safe.png\'" src="https://outside.invalid/pixel">';
  assert.ok(findThirdPartyReferences(html, base).some((value) => value.includes("outside.invalid")));
  assert.deepEqual(findThirdPartyReferences('<img title="src=\'https://outside.invalid/fake\'" src="/safe.png">', base), []);
});

test("unsupported URL entities and CSS URL escapes are reported as unverifiable", () => {
  assert.ok(findThirdPartyReferences('<img src="https&CounterClockwiseContourIntegral;outside.invalid">', base).length > 0);
  assert.ok(findThirdPartyReferences('<style>body {background:url(\\68ttps://outside.invalid/pixel)}</style>', base).length > 0);
  assert.ok(findThirdPartyReferences('<style>body {background:u\\72l(https://outside.invalid/pixel)}</style>', base).length > 0);
});

test("embedded iframe HTML and SVG script references cannot receive a static clean pass", () => {
  assert.ok(findThirdPartyReferences('<iframe srcdoc="&lt;img src=https://outside.invalid/pixel&gt;"></iframe>', base).some((reason) => reason.includes("srcdoc")));
  assert.ok(findThirdPartyReferences('<svg><script href="https://outside.invalid/a.js"></script></svg>', base).some((reason) => reason.includes("outside.invalid")));
  assert.ok(findThirdPartyReferences('<svg><script xlink:href="https://outside.invalid/a.js"></script></svg>', base).some((reason) => reason.includes("outside.invalid")));
});

test("repeated malformed tags exhaust a linear scan budget and fail closed", () => {
  for (const prefix of ["<p", "<style"]) {
    const results = findThirdPartyReferences(prefix.repeat(20000), base);
    assert.ok(results.some((reason) => reason.includes("scan work limit exceeded")));
  }
  assert.ok(findThirdPartyReferences('<style>body{background:url(https://outside.invalid/pixel)}', base).some((reason) => reason.includes("outside.invalid")));
});

test("cookie attributes must be real attributes, and values never enter diagnostics", async () => {
  const secret = "SYNTHETIC_COOKIE_VALUE_DO_NOT_PRINT";
  const run = await mockRun((url, init) => {
    if (new URL(url).search) {
      return new Response("<html></html>", {headers: {...headers, "set-cookie": `tori_ref=${secret}; x-HttpOnly; not-secure; x-SameSite=Lax; x-Max-Age=2592000`}});
    }
    if (new URL(url).pathname === "/") return new Response("<html></html>", {headers: {...headers, "set-cookie": `session=${secret}; HttpOnly; Secure`}});
  }, {allowPartnerCookieCheck: true});
  assert.equal(resultFor(run, "cookies:partner-cookie-shape").pass, false);
  assert.equal(resultFor(run, "cookies:partner-gpc-blocked").pass, false);
  assert.equal(resultFor(run, "cookies:no-cookie:/").pass, false);
  assert.ok(!JSON.stringify(run).includes(secret));
});

test("network diagnostics are bounded and cannot inject terminal control sequences", async () => {
  const run = await mockRun(() => { throw new Error("\x1b[2J\n" + "x".repeat(10000)); });
  assert.ok(run.results.every((result) => result.reason.length <= 2048 && !/[\x00-\x1f\x7f]/.test(result.reason)));
});

test("partner checks require opt-in and skipped verification remains incomplete", async () => {
  const urls = [];
  const run = await mockRun((url) => { urls.push(url); });
  assert.ok(urls.every((url) => !new URL(url).search));
  assert.equal(run.summary.status, "incomplete");
  assert.equal(resultFor(run, "cookies:partner-check").skipped, true);
  assert.equal(resultFor(run, "signed:verification").skipped, true);
});

test("canary dates reject future, reversed and duplicate signed dates", () => {
  const now = new Date("2026-10-18T12:00:00Z");
  for (const text of [
    "Date: 2026-10-19\nNext canary: by 2026-11-19\n",
    "Date: 2026-10-18\nNext canary: by 2026-10-17\n",
    "Date: 2026-10-18\nDate: 2026-10-17\nNext canary: by 2026-11-18\n",
    "Date: 2026-10-18\nNext canary: by 2026-11-18\nNext canary: by 2026-11-19\n",
  ]) assert.equal(checkCanaryDates(text, now)[0].pass, false);
});

test("malformed or concatenated public-key armor cannot silently select the first block", () => {
  assert.throws(() => dearmorPublicKey(publicKey + publicKey));
  assert.throws(() => dearmorPublicKey("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n!!!!\n-----END PGP PUBLIC KEY BLOCK-----\n"));
  assert.throws(() => countPrimaryKeyPackets(Buffer.from([0xc6, 192])));
  assert.throws(() => computeFingerprintV4(Buffer.from([0xc6, 1, 5])));
});

test("multiple clear-signed messages are refused before running GnuPG", async () => {
  const result = await verifyClearsignedText(keyring, signedCanary + signedCanary);
  assert.equal(result.ok, false);
  assert.match(result.detail, /exactly one/);
});

async function withVerifierStub(t, body, run) {
  const dir = await mkdtemp(join(tmpdir(), "trust-verifier-test-"));
  const oldPath = process.env.PATH;
  const script = `#!${process.execPath}\n${body}\n`;
  await writeFile(join(dir, "gpgv"), script);
  await writeFile(join(dir, "gpg"), `#!${process.execPath}\nprocess.exit(1);\n`);
  await chmod(join(dir, "gpgv"), 0o755);
  await chmod(join(dir, "gpg"), 0o755);
  process.env.PATH = dir;
  try { await run(dir); } finally { process.env.PATH = oldPath; await rm(dir, {recursive: true, force: true}); }
}

test("GnuPG version probes and verification both have hard timeouts", async (t) => {
  for (const body of ["setTimeout(() => {}, 10000);", "if (process.argv.includes('--version')) process.exit(0); setTimeout(() => {}, 10000);"]) {
    await withVerifierStub(t, body, async () => {
      const started = Date.now();
      const result = await verifyClearsignedText(keyring, signedCanary, {timeoutMs: 150});
      assert.notEqual(result.ok, true);
      assert.ok(Date.now() - started < 2000);
    });
  }
});

test("excess GnuPG output fails within bounded output storage", async (t) => {
  await withVerifierStub(t, "if (process.argv.includes('--version')) process.exit(0); process.stdout.write('x'.repeat(400000)); setTimeout(() => {}, 10000);", async () => {
    const result = await verifyClearsignedText(keyring, signedCanary, {timeoutMs: 1000});
    assert.equal(result.ok, false);
    assert.match(result.detail, /output limit exceeded/);
  });
});

test("GnuPG verification uses a temporary homedir and requires verified plaintext", async (t) => {
  await withVerifierStub(t, "if (process.argv.includes('--version')) process.exit(0); const fs = require('node:fs'); fs.writeFileSync(process.env.TRUST_TEST_ARGS, JSON.stringify(process.argv)); process.stdout.write('[GNUPG:] VALIDSIG synthetic\\n');", async (dir) => {
    const argsPath = join(dir, "args.json");
    process.env.TRUST_TEST_ARGS = argsPath;
    try {
      const result = await verifyClearsignedText(keyring, signedCanary);
      assert.equal(result.ok, false);
      assert.match(result.detail, /plaintext/);
      const args = JSON.parse(await readFile(argsPath, "utf8"));
      assert.ok(args.includes("--homedir"));
      assert.match(args[args.indexOf("--homedir") + 1], /torisim-privacy-check-/);
      assert.ok(args.includes("--status-fd"));
    } finally { delete process.env.TRUST_TEST_ARGS; }
  });
});

test("CLI rejects unknown, conflicting, missing and invalid arguments", async () => {
  for (const args of [["--unknown"], ["--base"], ["--base", base, "--timeout-ms", "0"], ["--base", base, "--base", base], ["--partner-check", "--no-partner-check"], ["--base", "https://user:secret@fixture.invalid"]]) {
    await assert.rejects(exec(process.execPath, [cli, ...args]), (error) => { assert.equal(error.code, 2); return true; });
  }
});
