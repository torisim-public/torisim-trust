

import {test} from "node:test";
import assert from "node:assert/strict";
import {createServer} from "node:http";
import {execFile, execFileSync} from "node:child_process";
import {promisify} from "node:util";
import {mkdtemp, writeFile, chmod, rm} from "node:fs/promises";
import {tmpdir} from "node:os";
import {fileURLToPath} from "node:url";
import {join, dirname} from "node:path";
import {
  runPrivacyChecks,
  dearmorPublicKey,
  verifyClearsignedText,
  computeFingerprintV4,
  countPrimaryKeyPackets,
  findThirdPartyReferences,
  checkCSPHeader,
  parseCSP,
  checkCanaryDates,
  CANARY_MAX_AGE_DAYS,
  TEST_PARTNER_CODE,
  EXPECTED_KEY_FINGERPRINT,
  ALL_PAGES,
  PUBLIC_PAGES,
  PRIVATE_PAGES,
  SIGNED_FILE_PATHS,
  SECURITY_TXT_PATH,
} from "../src/privacy-check.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const CLI_PATH = join(here, "..", "src", "privacy-check.mjs");

const execFileAsync = promisify(execFile);

const FIXTURE_PUBKEY = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEatVGmxYJKwYBBAHaRw8BAQdAM9eEajGQsh/NTZijKxHuqGOQdpRz+W1G6c+A
nNVQuCm0OFRvcmlzaW0gVHJ1c3QgVGVzdCBGaXh0dXJlIDEgPGZpeHR1cmUtMUBl
eGFtcGxlLmludmFsaWQ+iJMEExYKADsWIQSzgr0v2saL7up5lEheshuJqO4YrAUC
atVGmwIbAwULCQgHAgIiAgYVCgkICwIEFgIDAQIeBwIXgAAKCRBeshuJqO4YrIi4
AP0aZUw0m9m829hZRPfTzXkmDbcyplZRbBhax08/ZIAejQEA1cZODntqsqMzlp+0
xxz6/AOxmGOVftRGoTm5X4HvxwQ=
=yfK7
-----END PGP PUBLIC KEY BLOCK-----
`;

const FIXTURE_KEY_FINGERPRINT = computeFingerprintV4(dearmorPublicKey(FIXTURE_PUBKEY));

const GOOD_FINGERPRINT_OPTION = {allowPartnerCookieCheck: true, expectedFingerprint: FIXTURE_KEY_FINGERPRINT, trustedKeyText: FIXTURE_PUBKEY};

const SECOND_FIXTURE_PUBKEY = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEatVGmxYJKwYBBAHaRw8BAQdALW5rC4+xDe934NSfKalFc40Z95AVKnqCHT7p
bZWraLG0OFRvcmlzaW0gVHJ1c3QgVGVzdCBGaXh0dXJlIDIgPGZpeHR1cmUtMkBl
eGFtcGxlLmludmFsaWQ+iJMEExYKADsWIQQ5BBHcuKqZATU5TXVnkcCcZZjzaAUC
atVGmwIbAwULCQgHAgIiAgYVCgkICwIEFgIDAQIeBwIXgAAKCRBnkcCcZZjzaNsF
AP0S4Jza5tjFmkW27tg+dXRylTMmski6NEj+mGrYYzYWBAD/YnSPYJi666Iqk7wY
EBGd7siOVKG7ydCx0X9E6rSsagc=
=pMMU
-----END PGP PUBLIC KEY BLOCK-----
`;

const SECOND_KEY_SIGNED_CANARY = `-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

Torisim warrant canary (TEST FIXTURE, signed by the smuggled second key)

Date: 2026-09-20
Next canary: by 2026-10-04

This synthetic fixture proves
that a live pgp.txt smuggling in a second key cannot make its signature
verify against the local trusted copy, which holds only the first key. It
is not a real Torisim canary.
-----BEGIN PGP SIGNATURE-----

iHUEARYKAB0WIQQ5BBHcuKqZATU5TXVnkcCcZZjzaAUCatVGmwAKCRBnkcCcZZjz
aEKlAQCXP63XIvvi+R0+xCVhVrank37WyjntkOc7yn+ViNECLwD/QboFAsyjXl9C
vL3r4RRXWoSHMkf9P3SIAmwgEv1dwg4=
=EJPG
-----END PGP SIGNATURE-----
`;

const TWO_KEY_PGP_BLOCK = (() => {
  const combined = Buffer.concat([dearmorPublicKey(FIXTURE_PUBKEY), dearmorPublicKey(SECOND_FIXTURE_PUBKEY)]);
  const base64 = combined.toString("base64");
  const lines = base64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n${lines.join("\n")}\n-----END PGP PUBLIC KEY BLOCK-----\n`;
})();

const FIXTURE_SIGNED_CANARY = `-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

Torisim warrant canary (TEST FIXTURE)

Date: 2026-09-20
Next canary: by 2026-10-04

This synthetic fixture proves
that the gpg-verification code path recognizes a real good signature and
rejects a tampered one. It is not a real Torisim canary.
-----BEGIN PGP SIGNATURE-----

iHUEARYKAB0WIQSzgr0v2saL7up5lEheshuJqO4YrAUCatVGmwAKCRBeshuJqO4Y
rEeoAP41yAP/y03OAM2KQl2y7HJXyXXOJTygRR5SpoDPVFCs2gD/R+cQLL6NBg/Z
IZGfsfAr7+TqQiToJkrsqSA1M1FffAk=
=tKD7
-----END PGP SIGNATURE-----
`;

const FIXTURE_NOW = new Date("2026-09-21T12:00:00Z"); 
const FAR_AFTER_NEXT_CANARY = new Date("2026-10-20T12:00:00Z"); 

function canaryCleartext({date = "2026-09-20", next = "by 2026-10-20"} = {}) {
  const lines = ["Torisim warrant canary (TEST FIXTURE, not signed)", ""];
  if (date !== null) lines.push(`Date: ${date}`);
  if (next !== null) lines.push(`Next canary: ${next}`);
  return `${lines.join("\n")}\n`;
}

function unsignedCanary({date = "2026-09-20", next = "by 2026-10-20", before = "", after = ""} = {}) {
  const lines = ["Torisim warrant canary (TEST FIXTURE, not signed)", ""];
  if (date !== null) lines.push(`Date: ${date}`);
  if (next !== null) lines.push(`Next canary: ${next}`);
  return `${before}-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n${lines.join("\n")}\n-----BEGIN PGP SIGNATURE-----\n\nTk9UIEEgU0lHTkFUVVJF\n=AAAA\n-----END PGP SIGNATURE-----\n${after}`;
}

function currentUnsignedCanary() {
  const today = new Date();
  const day = (offset) => new Date(Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate() + offset)).toISOString().slice(0, 10);
  return unsignedCanary({date: day(-1), next: `by ${day(29)}`});
}

function currentSecurityTxt() {
  const expires = new Date(Date.now() + 365 * 86_400_000).toISOString();
  return GOOD_SECURITY_TXT.replace(/^Expires: .*$/m, `Expires: ${expires}`);
}

const GOOD_SECURITY_TXT = `Contact: mailto:support@torisim.com
Expires: 2027-09-21T00:00:00.000Z
Encryption: https://torisim.com/pgp.txt
Preferred-Languages: en, es, fr, de, ja, ar
Canonical: https://torisim.com/.well-known/security.txt
`;

const GOOD_CSP = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline' https://js.stripe.com",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob: https://*.stripe.com",
  "font-src 'self'",
  "connect-src 'self' https://api.stripe.com https://*.stripe.com",
  "frame-src https://js.stripe.com https://hooks.stripe.com https://checkout.stripe.com",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join("; ");

const GOOD_HEADERS_COMMON = {
  "content-security-policy": GOOD_CSP,
  "referrer-policy": "no-referrer",
  "permissions-policy": "camera=(), microphone=(), geolocation=()",
  "x-content-type-options": "nosniff",
  "strict-transport-security": "max-age=31536000; includeSubDomains",
};
const GOOD_PRIVATE_EXTRA = {
  "cache-control": "private, no-store, max-age=0",
  "x-robots-tag": "noindex, nofollow",
};
const GOOD_PAGE_BODY = '<!doctype html><html><head><link rel="stylesheet" href="/style.css"></head><body><h1>Torisim (test fixture)</h1><script src="/app.js"></script></body></html>';

function createFixtureServer(mode = "good") {
  return createServer((req, res) => {
    const url = new URL(req.url, "http://fixture.invalid");
    const path = url.pathname;
    const cookies = [];

    if (path === "/" && req.method === "GET") {
      const partner = url.searchParams.get("partner");
      if (partner && req.headers["sec-gpc"] !== "1") {
        cookies.push(`tori_ref=${partner}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000; Secure`);
      }
    }
    if (mode === "cookie-on-public" && path === "/" && !url.searchParams.has("partner")) {
      cookies.push("some_tracker=1; Path=/");
    }
    if (cookies.length) res.setHeader("Set-Cookie", cookies);

    if (SIGNED_FILE_PATHS.includes(path)) {
      res.setHeader("content-type", "text/plain; charset=utf-8");
      res.writeHead(200);
      if (mode === "empty-canary" && path === "/canary.txt") return res.end("");
      if (mode === "empty-mirrors" && path === "/mirrors.txt") return res.end("");
      if (mode === "unsigned-canary" && path === "/canary.txt") return res.end("Torisim warrant canary\n\nDate: 2026-09-20\nNext canary: by 2026-10-04\n\nNo PGP markers here.\n");
      if (mode === "good-today" && path === "/canary.txt") return res.end(currentUnsignedCanary());

      if (mode === "two-key-pgp") return res.end(path === "/pgp.txt" ? TWO_KEY_PGP_BLOCK : SECOND_KEY_SIGNED_CANARY);

      return res.end(path === "/pgp.txt" ? FIXTURE_PUBKEY : FIXTURE_SIGNED_CANARY);
    }

    if (path === SECURITY_TXT_PATH) {
      res.setHeader("content-type", "text/plain; charset=utf-8");
      res.writeHead(200);
      return res.end(mode === "good-today" ? currentSecurityTxt() : GOOD_SECURITY_TXT);
    }

    if (ALL_PAGES.includes(path)) {
      const headers = {...GOOD_HEADERS_COMMON, "content-type": "text/html; charset=utf-8"};
      if (PRIVATE_PAGES.includes(path)) Object.assign(headers, GOOD_PRIVATE_EXTRA);
      if (mode === "bad-default-src" && path === "/") headers["content-security-policy"] = GOOD_CSP.replace("default-src 'self'", "default-src 'self' https://evil.example");
      if (mode === "bad-script-src" && path === "/") headers["content-security-policy"] = GOOD_CSP.replace("https://js.stripe.com", "https://js.stripe.com https://evil.example");
      if (mode === "bad-connect-src" && path === "/") headers["content-security-policy"] = GOOD_CSP.replace("https://api.stripe.com https://*.stripe.com", "https://api.stripe.com https://evil.example");
      if (mode === "bad-frame-ancestors" && path === "/") headers["content-security-policy"] = GOOD_CSP.replace("frame-ancestors 'none'", "frame-ancestors 'self'");
      if (mode === "bad-object-src" && path === "/") headers["content-security-policy"] = GOOD_CSP.replace("object-src 'none'", "object-src 'self'");
      if (mode === "short-hsts" && path === "/") headers["strict-transport-security"] = "max-age=3600";
      if (mode === "no-csp" && path === "/") delete headers["content-security-policy"];
      if (mode === "private-cache-public" && path === "/checkout") headers["cache-control"] = "public, max-age=3600";
      for (const [key, value] of Object.entries(headers)) res.setHeader(key, value);
      res.writeHead(200);
      let body = GOOD_PAGE_BODY;
      if (mode === "beacon" && path === "/privacy") {
        body = body.replace(
          "</body>",
          `<script src="https://static.cloudflareinsights.com/beacon.min.js/abc123" data-cf-beacon='{"token":"x"}'></script></body>`,
        );
      }
      return res.end(body);
    }

    res.writeHead(404, {"content-type": "text/plain"});
    res.end("not found");
  });
}

function withServer(mode, run) {
  return new Promise((resolve, reject) => {
    const server = createFixtureServer(mode);
    server.listen(0, "127.0.0.1", async () => {
      const {port} = server.address();
      try {
        await run(`http://127.0.0.1:${port}`);
        resolve();
      } catch (error) {
        reject(error);
      } finally {
        server.close();
      }
    });
  });
}

function failingResults(results) {
  return results.filter((r) => r.pass === false);
}

function assertOnlyCategoryFails(results, category) {
  const failing = failingResults(results);
  assert.ok(failing.length > 0, `expected at least one failing check in category "${category}", got none`);
  for (const r of failing) {
    assert.equal(r.category, category, `expected only "${category}" to fail, but ${r.id} also failed: ${r.reason}`);
  }
}

test("a good site passes every check", async () => {
  await withServer("good", async (base) => {
    const run = await runPrivacyChecks(base, {now: FIXTURE_NOW, ...GOOD_FINGERPRINT_OPTION});
    const failing = failingResults(run.results);
    assert.deepEqual(failing, [], `expected no failures, got:\n${failing.map((r) => `${r.id}: ${r.reason}`).join("\n")}`);
    const ids = run.results.map((r) => r.id);
    
    for (const path of PRIVATE_PAGES) assert.ok(ids.includes(`headers:${path}`), `missing headers:${path}`);
    assert.equal(PRIVATE_PAGES.length, 10);
    assert.ok(ids.includes("signed:pgp:fingerprint"));
    assert.ok(ids.includes("security-txt"));
    assert.ok(ids.includes("server-header"));
  });
});

test('one pass makes 22 requests against a healthy site (16 pages + 2 partner + 3 signed + 1 security.txt + 0 for server-header, which reuses "/")', async () => {
  let count = 0;
  const server = createFixtureServer("good");
  server.on("request", () => {
    count += 1;
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;
  try {
    await runPrivacyChecks(`http://127.0.0.1:${port}`, {now: FIXTURE_NOW, ...GOOD_FINGERPRINT_OPTION});
    assert.equal(count, 22);
  } finally {
    server.close();
  }
});

test("a page with the Cloudflare beacon fails third-party-content, and nothing else", async () => {
  await withServer("beacon", async (base) => {
    const run = await runPrivacyChecks(base, {now: FIXTURE_NOW, ...GOOD_FINGERPRINT_OPTION});
    assertOnlyCategoryFails(run.results, "third-party-content");
    const failure = run.results.find((r) => r.id === "third-party:/privacy");
    assert.equal(failure.pass, false);
    assert.match(failure.reason, /static\.cloudflareinsights\.com/);
    assert.match(failure.reason, /data-cf-beacon/);
  });
});

test("a missing CSP fails security-headers, and nothing else", async () => {
  await withServer("no-csp", async (base) => {
    const run = await runPrivacyChecks(base, {now: FIXTURE_NOW, ...GOOD_FINGERPRINT_OPTION});
    assertOnlyCategoryFails(run.results, "security-headers");
    const failure = run.results.find((r) => r.id === "headers:/");
    assert.equal(failure.pass, false);
    assert.match(failure.reason, /default-src must be exactly/);
  });
});

test("an extra default-src source fails security-headers (default-src must be exactly 'self')", async () => {
  await withServer("bad-default-src", async (base) => {
    const run = await runPrivacyChecks(base, {now: FIXTURE_NOW, ...GOOD_FINGERPRINT_OPTION});
    assertOnlyCategoryFails(run.results, "security-headers");
    assert.match(run.results.find((r) => r.id === "headers:/").reason, /default-src must be exactly 'self'/);
  });
});

test("an unreviewed script-src source fails security-headers", async () => {
  await withServer("bad-script-src", async (base) => {
    const run = await runPrivacyChecks(base, {now: FIXTURE_NOW, ...GOOD_FINGERPRINT_OPTION});
    assertOnlyCategoryFails(run.results, "security-headers");
    assert.match(run.results.find((r) => r.id === "headers:/").reason, /script-src has unexpected source\(s\): https:\/\/evil\.example/);
  });
});

test("an unreviewed connect-src source fails security-headers", async () => {
  await withServer("bad-connect-src", async (base) => {
    const run = await runPrivacyChecks(base, {now: FIXTURE_NOW, ...GOOD_FINGERPRINT_OPTION});
    assertOnlyCategoryFails(run.results, "security-headers");
    assert.match(run.results.find((r) => r.id === "headers:/").reason, /connect-src has unexpected source\(s\): https:\/\/evil\.example/);
  });
});

test("frame-ancestors other than 'none' fails security-headers", async () => {
  await withServer("bad-frame-ancestors", async (base) => {
    const run = await runPrivacyChecks(base, {now: FIXTURE_NOW, ...GOOD_FINGERPRINT_OPTION});
    assertOnlyCategoryFails(run.results, "security-headers");
    assert.match(run.results.find((r) => r.id === "headers:/").reason, /frame-ancestors must be exactly 'none'/);
  });
});

test("object-src other than 'none' fails security-headers", async () => {
  await withServer("bad-object-src", async (base) => {
    const run = await runPrivacyChecks(base, {now: FIXTURE_NOW, ...GOOD_FINGERPRINT_OPTION});
    assertOnlyCategoryFails(run.results, "security-headers");
    assert.match(run.results.find((r) => r.id === "headers:/").reason, /object-src must be exactly 'none'/);
  });
});

test("HSTS max-age under one year fails security-headers", async () => {
  await withServer("short-hsts", async (base) => {
    const run = await runPrivacyChecks(base, {now: FIXTURE_NOW, ...GOOD_FINGERPRINT_OPTION});
    assertOnlyCategoryFails(run.results, "security-headers");
    assert.match(run.results.find((r) => r.id === "headers:/").reason, /max-age is 3600, must be at least 31536000/);
  });
});

test("a private page serving cache-control: public fails security-headers, and nothing else", async () => {
  await withServer("private-cache-public", async (base) => {
    const run = await runPrivacyChecks(base, {now: FIXTURE_NOW, ...GOOD_FINGERPRINT_OPTION});
    assertOnlyCategoryFails(run.results, "security-headers");
    const failure = run.results.find((r) => r.id === "headers:/checkout");
    assert.equal(failure.pass, false);
    assert.match(failure.reason, /cache-control/);
    assert.match(failure.reason, /no-store/);
  });
});

test("a Set-Cookie on a public page fails cookies, and nothing else", async () => {
  await withServer("cookie-on-public", async (base) => {
    const run = await runPrivacyChecks(base, {now: FIXTURE_NOW, ...GOOD_FINGERPRINT_OPTION});
    assertOnlyCategoryFails(run.results, "cookies");
    const failure = run.results.find((r) => r.id === "cookies:no-cookie:/");
    assert.equal(failure.pass, false);
    assert.match(failure.reason, /unexpected Set-Cookie/);
    assert.doesNotMatch(failure.reason, /some_tracker/);
  });
});

test("an old canary fails signed-files, and nothing else", async () => {

  await withServer("good", async (base) => {
    const run = await runPrivacyChecks(base, {now: FAR_AFTER_NEXT_CANARY, ...GOOD_FINGERPRINT_OPTION});
    assertOnlyCategoryFails(run.results, "signed-files");
    assert.equal(run.results.find((r) => r.id === "signed:canary:freshness").pass, false);
    assert.equal(run.results.find((r) => r.id === "signed:canary:next-canary-not-passed").pass, false);
  });
});

const freshnessOf = (results) => results.find((r) => r.id === "signed:canary:freshness");
const nextCanaryOf = (results) => results.find((r) => r.id === "signed:canary:next-canary-not-passed");

test("canary dates: a 20-day-old canary whose next date is ahead passes", () => {
  const results = checkCanaryDates(canaryCleartext({date: "2026-09-20", next: "by 2026-10-20"}), new Date("2026-10-10T12:00:00Z"));
  assert.equal(freshnessOf(results).pass, true, freshnessOf(results).reason);
  assert.match(freshnessOf(results).reason, /20\.5 day\(s\) old \(limit 31\); it is valid to the end of 2026-10-20 \(UTC\)/);
  assert.equal(nextCanaryOf(results).pass, true);
});

test("canary dates: a canary passes to the end of its next date (UTC), and fails after it", () => {
  const canary = canaryCleartext({date: "2026-09-20", next: "by 2026-10-20"});
  const lastMoment = checkCanaryDates(canary, new Date("2026-10-20T23:59:59.999Z"));
  assert.equal(freshnessOf(lastMoment).pass, true, freshnessOf(lastMoment).reason);
  assert.equal(nextCanaryOf(lastMoment).pass, true);
  const after = checkCanaryDates(canary, new Date("2026-10-21T00:00:00.000Z"));
  assert.equal(freshnessOf(after).pass, false);
  assert.match(freshnessOf(after).reason, /"Next canary: by 2026-10-20" has passed/);
  assert.equal(nextCanaryOf(after).pass, false);
});

test("canary dates: a canary with no next-date line fails", () => {
  const results = checkCanaryDates(canaryCleartext({next: null}), new Date("2026-09-21T12:00:00Z"));
  assert.equal(freshnessOf(results).pass, false);
  assert.match(freshnessOf(results).reason, /no "Next canary: by YYYY-MM-DD" line in its signed text/);
  assert.equal(nextCanaryOf(results).pass, false);
});

test('canary dates: a next date that is not "by" and a real YYYY-MM-DD date fails', () => {
  for (const next of ["by 2026-02-30", "by 2026-13-01", "by 4 November 2026", "2026-10-20", "by 2026-10-20 or later", "by", ""]) {
    const results = checkCanaryDates(canaryCleartext({next}), new Date("2026-09-21T12:00:00Z"));
    assert.equal(freshnessOf(results).pass, false, next);
    assert.match(freshnessOf(results).reason, /is not "by" and a real YYYY-MM-DD date/, next);
    assert.equal(nextCanaryOf(results).pass, false, next);
  }
});

test("canary dates: a canary more than 31 days old fails, even when its next date is ahead", () => {
  assert.equal(CANARY_MAX_AGE_DAYS, 31);
  const canary = canaryCleartext({date: "2026-09-01", next: "by 2026-12-31"});
  const day30 = checkCanaryDates(canary, new Date("2026-10-01T23:00:00Z")); 
  assert.equal(freshnessOf(day30).pass, true, freshnessOf(day30).reason);
  const day32 = checkCanaryDates(canary, new Date("2026-10-03T12:00:00Z")); 
  assert.equal(freshnessOf(day32).pass, false);
  assert.match(freshnessOf(day32).reason, /canary dated 2026-09-01 is more than 31 days old \(32\.5 day\(s\)\)/);
  
  assert.equal(nextCanaryOf(day32).pass, true);
});

test("canary dates: exactly 31 days old passes, and 1 ms more fails", () => {
  const canary = canaryCleartext({date: "2026-09-01", next: "by 2026-12-31"});
  const exactly31 = checkCanaryDates(canary, new Date("2026-10-02T00:00:00.000Z"));
  assert.equal(freshnessOf(exactly31).pass, true, freshnessOf(exactly31).reason);
  const justOver = checkCanaryDates(canary, new Date("2026-10-02T00:00:00.001Z"));
  assert.equal(freshnessOf(justOver).pass, false);
  assert.match(freshnessOf(justOver).reason, /is more than 31 days old/);
});

test("canary dates: an invalid clock fails both date checks instead of passing", () => {
  for (const now of [new Date("not a date"), undefined, null]) {
    const results = checkCanaryDates(canaryCleartext(), now);
    assert.equal(freshnessOf(results).pass, false, String(now));
    assert.equal(nextCanaryOf(results).pass, false, String(now));
    assert.match(freshnessOf(results).reason, /no valid current time/);
  }
});

test("canary dates: a Date in the future fails freshness", () => {
  const results = checkCanaryDates(canaryCleartext({date: "2026-09-25", next: "by 2026-10-20"}), new Date("2026-09-21T12:00:00Z"));
  assert.equal(freshnessOf(results).pass, false);
  assert.match(freshnessOf(results).reason, /is in the future/);
});

test("canary dates: a missing or impossible Date line fails freshness", () => {
  const cases = [
    [null, /no "Date: YYYY-MM-DD" line in its signed text/],
    ["2026-02-30", /"Date: 2026-02-30" is not a real YYYY-MM-DD date/],
    ["20 September 2026", /"Date: 20 September 2026" is not a real YYYY-MM-DD date/],
  ];
  for (const [date, pattern] of cases) {
    const results = checkCanaryDates(canaryCleartext({date}), new Date("2026-09-21T12:00:00Z"));
    assert.equal(freshnessOf(results).pass, false, String(date));
    assert.match(freshnessOf(results).reason, pattern);
  }
});

test("canary dates: the signed text's own dates decide", () => {
  const now = new Date("2026-10-10T12:00:00Z");
  
  const old = checkCanaryDates(canaryCleartext({date: "2026-08-01", next: "by 2026-08-31"}), now);
  assert.equal(freshnessOf(old).pass, false);
  assert.match(freshnessOf(old).reason, /"Next canary: by 2026-08-31" has passed/);
  assert.equal(nextCanaryOf(old).pass, false);
  
  const undated = checkCanaryDates(canaryCleartext({date: null, next: null}), now);
  assert.equal(freshnessOf(undated).pass, false);
  assert.match(freshnessOf(undated).reason, /no "Date: YYYY-MM-DD" line in its signed text/);
  assert.match(freshnessOf(undated).reason, /no "Next canary: by YYYY-MM-DD" line in its signed text/);
});

test("canary dates: without a verified signature the dates fail closed (null signed text)", () => {
  for (const signed of [null, undefined]) {
    const results = checkCanaryDates(signed, new Date("2026-10-10T12:00:00Z"));
    assert.equal(freshnessOf(results).pass, false);
    assert.equal(nextCanaryOf(results).pass, false);
    assert.match(freshnessOf(results).reason, /signature was not verified/);
  }
});

test("canary dates: forged unsigned dates around a signed canary never reach the date check (real gpgv/gpg)", async (t) => {
  if (!(await hasGpgOrGpgv())) {
    t.skip("neither gpg nor gpgv is on PATH in this environment");
    return;
  }
  
  const forged = "Date: 2026-10-09\nNext canary: by 2099-01-01\n\n";
  const keyring = dearmorPublicKey(FIXTURE_PUBKEY);
  const outcome = await verifyClearsignedText(keyring, `${forged}${FIXTURE_SIGNED_CANARY}${forged}`);

  assert.equal(outcome.ok, true, outcome.detail);
  assert.match(outcome.plaintext, /^Date: 2026-09-20$/m);
  assert.doesNotMatch(outcome.plaintext, /2099/);
  
  const results = checkCanaryDates(outcome.plaintext, new Date("2026-10-10T12:00:00Z"));
  assert.equal(freshnessOf(results).pass, false, "the genuine next date 2026-10-04 has passed");
  assert.match(freshnessOf(results).reason, /"Next canary: by 2026-10-04" has passed/);
});

test("canary dates: CRLF line ends read the same as LF", () => {
  const results = checkCanaryDates(canaryCleartext().replace(/\n/g, "\r\n"), new Date("2026-10-10T12:00:00Z"));
  assert.equal(freshnessOf(results).pass, true, freshnessOf(results).reason);
  assert.equal(nextCanaryOf(results).pass, true);
});

test("canary dates: the signed fixture canary passes every check after day 14 to the end of its next date, and fails only signed-files after it", async () => {

  await withServer("good", async (base) => {
    const lastMoment = await runPrivacyChecks(base, {now: new Date("2026-10-04T23:59:59.999Z"), ...GOOD_FINGERPRINT_OPTION});
    const failing = failingResults(lastMoment.results);
    assert.deepEqual(failing, [], `expected no failures, got:\n${failing.map((r) => `${r.id}: ${r.reason}`).join("\n")}`);
    assert.match(freshnessOf(lastMoment.results).reason, /15\.0 day\(s\) old \(limit 31\)/);

    const dayAfter = await runPrivacyChecks(base, {now: new Date("2026-10-05T00:00:00.000Z"), ...GOOD_FINGERPRINT_OPTION});
    assertOnlyCategoryFails(dayAfter.results, "signed-files");
    assert.deepEqual(failingResults(dayAfter.results).map((r) => r.id).sort(), ["signed:canary:freshness", "signed:canary:next-canary-not-passed"]);
  });
});

test("an empty canary.txt (200, text/plain) fails signed-files instead of passing", async () => {
  await withServer("empty-canary", async (base) => {
    const run = await runPrivacyChecks(base, {now: FIXTURE_NOW, ...GOOD_FINGERPRINT_OPTION});
    const failure = run.results.find((r) => r.id === "signed:/canary.txt");
    assert.equal(failure.pass, false);
    assert.match(failure.reason, /empty body/);
  });
});

test("an empty mirrors.txt (200, text/plain) fails signed-files instead of passing", async () => {
  await withServer("empty-mirrors", async (base) => {
    const run = await runPrivacyChecks(base, {now: FIXTURE_NOW, ...GOOD_FINGERPRINT_OPTION});
    const failure = run.results.find((r) => r.id === "signed:/mirrors.txt");
    assert.equal(failure.pass, false);
    assert.match(failure.reason, /empty body/);
  });
});

test("a non-empty canary.txt with no PGP signed-message markers fails signed-files", async () => {
  await withServer("unsigned-canary", async (base) => {
    const run = await runPrivacyChecks(base, {now: FIXTURE_NOW, ...GOOD_FINGERPRINT_OPTION});
    const failure = run.results.find((r) => r.id === "signed:/canary.txt");
    assert.equal(failure.pass, false);
    assert.match(failure.reason, /missing PGP signed-message markers/);
    
    assert.equal(run.results.find((r) => r.id === "signed:canary:freshness").pass, false);
  });
});

test("computeFingerprintV4 matches gpg --show-keys on the real public/pgp.txt", async () => {
  const {readFile} = await import("node:fs/promises");
  const real = await readFile(join(here, "..", "public", "pgp.txt"), "utf8");
  const keyring = dearmorPublicKey(real);
  assert.equal(computeFingerprintV4(keyring), EXPECTED_KEY_FINGERPRINT);
});

test("countPrimaryKeyPackets: the real public/pgp.txt carries exactly one primary key", async () => {
  const {readFile} = await import("node:fs/promises");
  const real = await readFile(join(here, "..", "public", "pgp.txt"), "utf8");
  assert.equal(countPrimaryKeyPackets(dearmorPublicKey(real)), 1);
});

test("a live pgp.txt that does not match the local trusted copy fails signed:pgp:matches-local-copy, and its signature no longer verifies -- even though it is a real, validly signed, single key", async () => {

  await withServer("good", async (base) => {
    const run = await runPrivacyChecks(base, {now: FIXTURE_NOW});
    const fingerprint = run.results.find((r) => r.id === "signed:pgp:fingerprint");
    assert.equal(fingerprint.pass, true, "the LOCAL copy (the real key) still matches the pinned fingerprint");

    const matchesLocal = run.results.find((r) => r.id === "signed:pgp:matches-local-copy");
    assert.equal(matchesLocal.pass, false);
    assert.match(matchesLocal.reason, /does not match the local trusted copy/);

    const singleKey = run.results.find((r) => r.id === "signed:pgp:single-key");
    assert.equal(singleKey.pass, true, "FIXTURE_PUBKEY alone is still a well-formed single-key block");

    assert.equal(run.results.find((r) => r.id === "signed:canary:signature").pass, false);
    assert.equal(run.results.find((r) => r.id === "signed:mirrors:signature").pass, false);
  });
});

test("key pin bypass: a live pgp.txt with a smuggled second key, signed with THAT key, fails matches-local-copy, fails single-key, and its signature does not verify", async () => {
  await withServer("two-key-pgp", async (base) => {
    const run = await runPrivacyChecks(base, {now: FIXTURE_NOW, ...GOOD_FINGERPRINT_OPTION});

    const fingerprint = run.results.find((r) => r.id === "signed:pgp:fingerprint");
    assert.equal(fingerprint.pass, true, "the pin describes the local copy, which is unaffected by what the live site serves");

    const matchesLocal = run.results.find((r) => r.id === "signed:pgp:matches-local-copy");
    assert.equal(matchesLocal.pass, false, "a live pgp.txt with an extra key can never match a single-key local copy");

    const singleKey = run.results.find((r) => r.id === "signed:pgp:single-key");
    assert.equal(singleKey.pass, false);
    assert.match(singleKey.reason, /carries 2 primary keys, expected exactly 1/);

    const canarySig = run.results.find((r) => r.id === "signed:canary:signature");
    assert.equal(canarySig.pass, false, "gpgv must not accept a signature from a key that is not in the local trusted copy");
    const mirrorsSig = run.results.find((r) => r.id === "signed:mirrors:signature");
    assert.equal(mirrorsSig.pass, false);
  });
});

test("key pin bypass: a missing local trusted copy fails the fingerprint pin and every signature check, never falls back to trusting the live body", async () => {
  await withServer("good", async (base) => {
    const run = await runPrivacyChecks(base, {
      now: FIXTURE_NOW,
      expectedFingerprint: FIXTURE_KEY_FINGERPRINT,
      trustedKeyPath: join(tmpdir(), `torisim-privacy-check-test-missing-key-${process.pid}.txt`), 
    });
    const fingerprint = run.results.find((r) => r.id === "signed:pgp:fingerprint");
    assert.equal(fingerprint.pass, false);
    assert.match(fingerprint.reason, /could not read the local trusted copy/);
    assert.equal(run.results.find((r) => r.id === "signed:canary:signature").pass, false);
    assert.equal(run.results.find((r) => r.id === "signed:mirrors:signature").pass, false);
  });
});

test("key pin bypass: a local trusted copy that itself has two primary keys is refused, not silently trusted for whichever key gpgv happens to pick", async () => {
  await withServer("good", async (base) => {
    const run = await runPrivacyChecks(base, {
      now: FIXTURE_NOW,
      expectedFingerprint: FIXTURE_KEY_FINGERPRINT,
      trustedKeyText: TWO_KEY_PGP_BLOCK,
    });
    const fingerprint = run.results.find((r) => r.id === "signed:pgp:fingerprint");
    assert.equal(fingerprint.pass, false);
    assert.match(fingerprint.reason, /local trusted copy has 2 primary keys, expected exactly 1/);
    assert.equal(run.results.find((r) => r.id === "signed:canary:signature").pass, false);
    assert.equal(run.results.find((r) => r.id === "signed:mirrors:signature").pass, false);
  });
});

test("dearmorPublicKey + verifyClearsignedText: a good signature verifies, a tampered one does not", async (t) => {
  if (!(await hasGpgOrGpgv())) {
    t.skip("neither gpg nor gpgv is on PATH in this environment");
    return;
  }
  const keyring = dearmorPublicKey(FIXTURE_PUBKEY);
  const good = await verifyClearsignedText(keyring, FIXTURE_SIGNED_CANARY);
  assert.equal(good.checked, true);
  assert.equal(good.ok, true);
  
  assert.match(good.plaintext, /^Date: 2026-09-20$/m);
  assert.match(good.plaintext, /^Next canary: by 2026-10-04$/m);

  const tampered = FIXTURE_SIGNED_CANARY.replace("TEST FIXTURE", "TEST FIXTURE, TAMPERED");
  const bad = await verifyClearsignedText(keyring, tampered);
  assert.equal(bad.checked, true);
  assert.equal(bad.ok, false);
  assert.equal(bad.plaintext, null, "no plaintext is returned for a bad signature");
});

test("verifyClearsignedText (gpg fallback, gpgv shadowed): an unsigned message does not verify", async (t) => {

  let gpgOk = true;
  try { execFileSync("gpg", ["--version"], {stdio: "ignore"}); } catch { gpgOk = false; }
  if (!gpgOk) { t.skip("gpg is not on PATH"); return; }

  const home = await mkdtemp(join(tmpdir(), "torisim-gpg-store-"));
  t.after(() => rm(home, {recursive: true, force: true}));
  const armored = execFileSync(
    "gpg",
    ["--batch", "--no-tty", "--no-autostart", "--homedir", home, "--armor", "--store"],
    {input: "Date: 2099-01-01\nNext canary: by 2099-01-31\n", encoding: "utf8"},
  );
  assert.match(armored, /-----BEGIN PGP MESSAGE-----/);

  const binDir = await mkdtemp(join(tmpdir(), "torisim-gpgv-stub-"));
  t.after(() => rm(binDir, {recursive: true, force: true}));
  await writeFile(join(binDir, "gpgv"), "#!/bin/sh\nexit 1\n");
  await chmod(join(binDir, "gpgv"), 0o755);
  const originalPath = process.env.PATH;
  process.env.PATH = `${binDir}:${originalPath}`;
  t.after(() => { process.env.PATH = originalPath; });

  const keyring = dearmorPublicKey(FIXTURE_PUBKEY);
  const unsigned = await verifyClearsignedText(keyring, armored);
  assert.equal(unsigned.ok, false, "an unsigned literal message must not verify on the gpg path");
  assert.equal(unsigned.plaintext, null);
  
  const good = await verifyClearsignedText(keyring, FIXTURE_SIGNED_CANARY);
  assert.equal(good.ok, true, good.detail);
  assert.match(good.plaintext ?? "", /^Date: 2026-09-20$/m);
});

test("dearmorPublicKey rejects text that is not an armored public key", () => {
  assert.throws(() => dearmorPublicKey("not a key"));
});

test("the public referral test code has the expected format", () => {
  assert.match(TEST_PARTNER_CODE, /^[A-Z0-9_-]{3,32}$/);
});

test("allowPartnerCookieCheck: false skips the partner check instead of calling it", async () => {
  await withServer("good", async (base) => {
    const run = await runPrivacyChecks(base, {now: FIXTURE_NOW, ...GOOD_FINGERPRINT_OPTION, allowPartnerCookieCheck: false});
    const skipped = run.results.find((r) => r.id === "cookies:partner-check");
    assert.equal(skipped.skipped, true);
    assert.equal(skipped.pass, null);
    assert.equal(run.results.some((r) => r.id === "cookies:partner-gpc-blocked"), false);
  });
});

test("verifySignatures: false skips the gpg step without failing the run", async () => {
  await withServer("good", async (base) => {
    const run = await runPrivacyChecks(base, {now: FIXTURE_NOW, verifySignatures: false});
    assert.equal(run.results.some((r) => r.id === "signed:canary:signature"), false);
    assert.deepEqual(failingResults(run.results), []);
  });
});

test("when neither gpg nor gpgv is on PATH, the signature checks FAIL, not warn (independent review, 28 September 2026)", async (t) => {
  const stubDir = await mkdtemp(join(tmpdir(), "torisim-privacy-check-nogpg-"));
  t.after(() => rm(stubDir, {recursive: true, force: true}));
  
  const originalPath = process.env.PATH;
  process.env.PATH = stubDir;
  t.after(() => { process.env.PATH = originalPath; });
  await withServer("good", async (base) => {
    const run = await runPrivacyChecks(base, {now: FIXTURE_NOW, ...GOOD_FINGERPRINT_OPTION});
    const canarySig = run.results.find((r) => r.id === "signed:canary:signature");
    const mirrorsSig = run.results.find((r) => r.id === "signed:mirrors:signature");
    assert.equal(canarySig.pass, false, "must fail, not warn, when gpg/gpgv are unavailable");
    assert.equal(canarySig.warning, undefined);
    assert.equal(mirrorsSig.pass, false);
    assert.match(canarySig.reason, /gpg\/gpgv not found on PATH/);
  });
});

function hasGpgOrGpgv() {
  return (async () => {
    for (const command of ["gpgv", "gpg"]) {
      try {
        execFileSync(command, ["--version"], {stdio: "ignore"});
        return true;
      } catch {
        
      }
    }
    return false;
  })();
}

test("a request that fails once then succeeds is retried, and the check passes with no networkError", async () => {
  let attempts = 0;
  const server = createServer((req, res) => {
    attempts += 1;
    if (attempts === 1) {
      req.socket.destroy(); 
      return;
    }
    res.writeHead(200, {...GOOD_HEADERS_COMMON, "content-type": "text/html"});
    res.end(GOOD_PAGE_BODY);
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;
  try {
    const run = await runPrivacyChecks(`http://127.0.0.1:${port}`, {
      now: FIXTURE_NOW,
      allowPartnerCookieCheck: false,
      verifySignatures: false,
      timeoutMs: 1000,
    });
    const home = run.results.find((r) => r.id === "headers:/");
    assert.equal(home.pass, true);
    assert.equal(home.networkError, undefined);
    assert.ok(attempts >= 2, "expected at least one retry");
  } finally {
    server.close();
  }
});

test("a request that always fails is reported as a network error, not a promise failure", async () => {
  
  const deadServer = createServer(() => {});
  await new Promise((resolve) => deadServer.listen(0, "127.0.0.1", resolve));
  const deadPort = deadServer.address().port;
  await new Promise((resolve) => deadServer.close(resolve));
  const run = await runPrivacyChecks(`http://127.0.0.1:${deadPort}`, {
    now: FIXTURE_NOW,

    verifySignatures: false, 
    timeoutMs: 300,
  });
  assert.ok(run.results.length > 0);
  for (const result of run.results.filter((result) => !result.skipped)) {
    assert.equal(result.pass, false, `${result.id} should fail when the site is unreachable`);
    assert.equal(result.networkError, true, `${result.id} should be flagged as a network error, not a promise failure`);
  }
});

const ORIGIN = "https://torisim.com";

const THIRD_PARTY_CASES = [
  ["script[src]", '<script src="https://evil.example/a.js"></script>', "https://evil.example"],
  ["script[data-src] (lazy-loaded, no src)", '<script data-src="https://evil.example/a.js"></script>', "https://evil.example"],
  ["img[src]", '<img src="https://evil.example/a.png">', "https://evil.example"],
  ["img/src (a bare / as the attribute separator, e.g. <img/src=...>)", '<img/src="https://evil.example/slash.png">', "https://evil.example"],
  ["img[data-src], no src present", '<img data-src="https://evil.example/a.png">', "https://evil.example"],
  ["img[srcset], one of several candidates", '<img src="/a.png" srcset="/a.png 1x, https://evil.example/b.png 2x">', "https://evil.example"],
  ["img[data-srcset]", '<img data-srcset="https://evil.example/b.png 2x">', "https://evil.example"],
  ["source[src]", '<source src="https://evil.example/a.mp4">', "https://evil.example"],
  ["source[srcset]", '<source srcset="https://evil.example/a.webp 1x">', "https://evil.example"],
  ["iframe[src]", '<iframe src="https://evil.example/embed"></iframe>', "https://evil.example"],
  ["iframe[data-src]", '<iframe data-src="https://evil.example/embed"></iframe>', "https://evil.example"],
  ["link[rel=stylesheet]", '<link rel="stylesheet" href="https://evil.example/s.css">', "https://evil.example"],
  ["link[rel=preload]", '<link rel="preload" href="https://evil.example/f.woff2">', "https://evil.example"],
  ["link[rel=modulepreload]", '<link rel="modulepreload" href="https://evil.example/m.js">', "https://evil.example"],
  ["link[rel=icon]", '<link rel="icon" href="https://evil.example/f.ico">', "https://evil.example"],
  ['link[rel="shortcut icon"] (legacy two-token rel)', '<link rel="shortcut icon" href="https://evil.example/f.ico">', "https://evil.example"],
  ["link[rel=preconnect]", '<link rel="preconnect" href="https://evil.example">', "https://evil.example"],
  ["link[rel=dns-prefetch]", '<link rel="dns-prefetch" href="https://evil.example">', "https://evil.example"],
  ["link[rel=prefetch]", '<link rel="prefetch" href="https://evil.example/next.html">', "https://evil.example"],
  ["link[rel=manifest]", '<link rel="manifest" href="https://evil.example/app.webmanifest">', "https://evil.example"],
  ["link[rel=apple-touch-icon]", '<link rel="apple-touch-icon" href="https://evil.example/apple.png">', "https://evil.example"],
  ["link[rel=apple-touch-icon-precomposed]", '<link rel="apple-touch-icon-precomposed" href="https://evil.example/apple2.png">', "https://evil.example"],
  ["CSS url() inside a <style> block", '<style>.a{background:url(https://evil.example/x.png)}</style>', "https://evil.example"],
  ['CSS @import "..." inside a <style> block', '<style>@import "https://evil.example/x.css";</style>', "https://evil.example"],
  ["CSS @import url(...) inside a <style> block", '<style>@import url(https://evil.example/x.css);</style>', "https://evil.example"],
  ["CSS @font-face src:url() inside a <style> block", '<style>@font-face{font-family:"x";src:url(https://evil.example/f.woff2)}</style>', "https://evil.example"],
  ["CSS url() inside a style=\"\" attribute", '<div style="background:url(https://evil.example/y.png)"></div>', "https://evil.example"],
  ["CSS image-set() with a url() candidate, inside a <style> block", '<style>.a{background-image:image-set(url(https://evil.example/x1.png) 1x)}</style>', "https://evil.example"],
  ["CSS image-set() with a bare quoted-string candidate", '<style>.a{background-image:image-set("https://evil.example/x2.png" 1x, "/local.png" 2x)}</style>', "https://evil.example"],
  ["CSS -webkit-image-set() inside a style=\"\" attribute", '<div style="background-image:-webkit-image-set(url(https://evil.example/x3.png) 1x)"></div>', "https://evil.example"],
  ['meta[http-equiv=refresh]', '<meta http-equiv="refresh" content="0;url=https://evil.example/">', "https://evil.example"],
  ["base[href] itself, when foreign", '<base href="https://evil.example/">', "https://evil.example"],
  ["base[href] changes resolution for a later relative reference", '<base href="https://evil.example/"><img src="a.png">', "https://evil.example"],
  ["video[src]", '<video src="https://evil.example/v.mp4"></video>', "https://evil.example"],
  ["video[poster]", '<video poster="https://evil.example/p.png"></video>', "https://evil.example"],
  ["audio[src]", '<audio src="https://evil.example/a.mp3"></audio>', "https://evil.example"],
  ["track[src]", '<track src="https://evil.example/t.vtt">', "https://evil.example"],
  ["embed[src]", '<embed src="https://evil.example/e.swf">', "https://evil.example"],
  ["object[data]", '<object data="https://evil.example/o.pdf"></object>', "https://evil.example"],
  ["input[type=image][src]", '<input type="image" src="https://evil.example/i.png">', "https://evil.example"],
  ["svg image[href]", '<svg><image href="https://evil.example/s.png"></image></svg>', "https://evil.example"],
  ["svg image[xlink:href]", '<svg><image xlink:href="https://evil.example/s2.png"></image></svg>', "https://evil.example"],
  ["svg use[href]", '<svg><use href="https://evil.example/sprite.svg#icon"></use></svg>', "https://evil.example"],
  ["svg use[xlink:href]", '<svg><use xlink:href="https://evil.example/sprite.svg#icon"></use></svg>', "https://evil.example"],
  ["a[ping], a single URL", '<a href="/" ping="https://evil.example/beacon">go</a>', "https://evil.example"],
  ["a[ping], one foreign among two space-separated URLs", '<a href="/" ping="/local-ping https://evil.example/beacon">go</a>', "https://evil.example"],
  ["button[formaction]", '<button formaction="https://evil.example/submit">go</button>', "https://evil.example"],
  ["input[formaction]", '<input formaction="https://evil.example/submit">', "https://evil.example"],
  ["form[action]", '<form action="https://evil.example/submit"></form>', "https://evil.example"],
];

for (const [name, html, expectedOrigin] of THIRD_PARTY_CASES) {
  test(`third-party detection: ${name}`, () => {
    const violations = findThirdPartyReferences(html, ORIGIN);
    assert.ok(violations.length > 0, `expected a violation for: ${html}`);
    assert.ok(violations.some((v) => v.startsWith(expectedOrigin)), `expected an origin of ${expectedOrigin}, got: ${JSON.stringify(violations)}`);
  });
}

test("third-party detection: a `>` inside a quoted attribute value does not end the tag early (regression)", () => {
  const html = '<a title="a &gt; b" href="/ok.html" data-x="y"></a><script src="https://evil.example/inside.js"></script>';
  const violations = findThirdPartyReferences(html, ORIGIN);
  assert.ok(violations.some((v) => v.includes("https://evil.example") && v.includes("script[src]")));
});

test("third-party detection: a literal, unescaped `>` inside a quoted attribute does not truncate the tag", () => {

  const html = '<script data-note="a > b" src="https://evil.example/after-gt.js"></script>';
  const violations = findThirdPartyReferences(html, ORIGIN);
  assert.ok(violations.some((v) => v.includes("https://evil.example/after-gt.js")), `expected the src after the quoted ">" to be found, got: ${JSON.stringify(violations)}`);
});

test("third-party detection: input[type=text][src] is not flagged (src is only meaningful on type=image)", () => {
  const html = '<input type="text" src="https://evil.example/ignored.png">';
  assert.deepEqual(findThirdPartyReferences(html, ORIGIN), []);
});

test("third-party detection: data:, blob:, mailto:, tel:, javascript: and a bare #fragment are never flagged", () => {
  const html = [
    '<img src="data:image/png;base64,aGVsbG8=">',
    '<a href="mailto:support@torisim.com">mail</a>',
    '<a href="tel:+15550000000">call</a>',
    '<a href="javascript:void(0)">js</a>',
    '<a href="#section">jump</a>',
    '<iframe src="blob:https://torisim.com/abc"></iframe>',
  ].join("");
  assert.deepEqual(findThirdPartyReferences(html, ORIGIN), []);
});

test("third-party detection: a same-origin base href does not change same-origin resolution", () => {
  const html = '<base href="https://torisim.com/sub/"><img src="a.png">';
  assert.deepEqual(findThirdPartyReferences(html, ORIGIN), []);
});

test("third-party detection: the known-negative page (many of the new selectors, all same-origin) still passes with zero violations", () => {
  const html = `<!doctype html><html><head>
    <link rel="stylesheet" href="/s.css">
    <link rel="preconnect" href="/">
    <link rel="icon" href="/favicon.ico">
    <link rel="apple-touch-icon" href="/apple.png">
    <style>.a{background:url(/img.png)} @font-face{font-family:"x";src:url(/f.woff2)} .b{background-image:image-set(url(/x1.png) 1x, "/x2.png" 2x)}</style>
  </head><body>
    <img src="/a.png" data-src="/a.png" srcset="/a.png 1x, /a-2x.png 2x">
    <img/src="/slash.png">
    <video src="/v.mp4" poster="/p.png"></video>
    <svg><use href="/sprite.svg#icon"></use></svg>
    <a href="/" ping="/local-ping">home</a>
    <form action="/submit"><button formaction="/submit">go</button></form>
    <div style="background:url(/y.png);background-image:image-set(url(/x3.png) 1x)"></div>
  </body></html>`;
  assert.deepEqual(findThirdPartyReferences(html, ORIGIN), []);
});

test("third-party detection: a stray tag with an unterminated quote does not hide a real third-party tag that follows it, and is itself reported as too long to check", () => {

  const junkFollowedByRealTag = `<x foo="unterminated and no more quote characters anywhere in this string, ` + "x".repeat(5000) + `><script src="https://evil.example/after-junk.js"></script>`;
  const violations = findThirdPartyReferences(junkFollowedByRealTag, ORIGIN);
  assert.ok(
    violations.some((v) => v.includes("https://evil.example/after-junk.js")),
    `expected the script tag after the broken quote to still be found, got: ${JSON.stringify(violations)}`,
  );
  assert.ok(
    violations.some((v) => v.includes("tag too long to check")),
    `expected the broken <x> tag itself to be reported as too long to check, got: ${JSON.stringify(violations)}`,
  );
});

test("third-party detection: a tag whose only attribute is one huge quoted value is reported as too long to check, not silently skipped", () => {

  const html = `<script data-config="` + "y".repeat(5000) + `" src="https://evil.example/big-attr.js"></script>`;
  const violations = findThirdPartyReferences(html, ORIGIN);
  assert.ok(
    violations.some((v) => v.includes("tag too long to check") && v.includes("<script>")),
    `expected the oversized <script> tag to be reported as too long to check, got: ${JSON.stringify(violations)}`,
  );
});

test("third-party detection: a short stray unclosed-quote tag can still swallow a normal tag right after it, when the two tags' quotes happen to balance out (a known, narrow limit -- contrast with the long-junk case above, which this checker does recover from)", () => {

  const html = '<x foo="short junk, no closing quote here either><script src="https://evil.example/short-junk.js"></script>';
  const violations = findThirdPartyReferences(html, ORIGIN);
  assert.deepEqual(violations, [], "documents today's behavior for this narrow shape; revisit only alongside a real attribute-state tokenizer");
});

test('third-party detection: an apostrophe inside an unquoted attribute value (e.g. <p title=it\'s>) does not open a fake quote that hides a later third-party tag', () => {
  const html = `<p title=it's>ignore</p><script src="https://evil.example/apostrophe.js"></script><p>Don't miss this > arrow</p>`;
  const violations = findThirdPartyReferences(html, ORIGIN);
  assert.ok(
    violations.some((v) => v.includes("https://evil.example/apostrophe.js")),
    `expected the script tag after the unquoted apostrophe to be found, got: ${JSON.stringify(violations)}`,
  );
});

test("third-party detection: a quote character that is not the first non-space character after \"=\" does not open a quote (a second, closer-together case)", () => {

  const html = `<div data-x=b'a"r title="ok"></div><script src="https://evil.example/mid-value.js"></script>`;
  const violations = findThirdPartyReferences(html, ORIGIN);
  assert.ok(
    violations.some((v) => v.includes("https://evil.example/mid-value.js")),
    `expected the script tag to be found, got: ${JSON.stringify(violations)}`,
  );
});

test("third-party detection: a 60 KB unterminated-quote junk prefix does not hide a real third-party tag that follows it", () => {
  const junk = `<x data-junk="unterminated, ` + "z".repeat(60_000) + `>`;
  const html = junk + `<script src="https://evil.example/after-60kb-junk.js"></script>`;
  const violations = findThirdPartyReferences(html, ORIGIN);
  assert.ok(
    violations.some((v) => v.includes("https://evil.example/after-60kb-junk.js")),
    `expected the script tag after 60 KB of junk to still be found, got a violations array of length ${violations.length}`,
  );
  assert.ok(violations.some((v) => v.includes("tag too long to check")));
});

test("third-party detection: a 60 KB well-formed inline JSON attribute does not hide a real third-party tag that follows it", () => {
  const bigJson = JSON.stringify({items: Array.from({length: 3000}, (_, i) => ({id: i, name: `item-${i}`}))});
  assert.ok(bigJson.length > 60_000, "fixture sanity: the inline JSON must actually be over 60 KB");
  const html = `<script type="application/json" data-config="${bigJson.replace(/"/g, "&quot;")}"></script><script src="https://evil.example/after-60kb-json.js"></script>`;
  const violations = findThirdPartyReferences(html, ORIGIN);
  assert.ok(
    violations.some((v) => v.includes("https://evil.example/after-60kb-json.js")),
    `expected the script tag after the 60 KB JSON attribute to still be found, got a violations array of length ${violations.length}`,
  );
  assert.ok(violations.some((v) => v.includes("tag too long to check")));
});

test("checkCSPHeader: the real live CSP passes with no problems", () => {
  assert.deepEqual(checkCSPHeader(GOOD_CSP), []);
});

test("checkCSPHeader: default-src with an extra source is rejected even though 'self' is present", () => {
  const bad = GOOD_CSP.replace("default-src 'self'", "default-src 'self' https://evil.example");
  assert.ok(checkCSPHeader(bad).some((p) => p.includes("default-src must be exactly 'self'")));
});

test("checkCSPHeader: a missing script-src is a problem", () => {
  const bad = GOOD_CSP.split("; ").filter((d) => !d.startsWith("script-src")).join("; ");
  assert.ok(checkCSPHeader(bad).some((p) => p.includes("script-src is missing")));
});

test("parseCSP: splits directives and sources correctly", () => {
  const parsed = parseCSP("default-src 'self'; object-src 'none'");
  assert.deepEqual(parsed.get("default-src"), ["'self'"]);
  assert.deepEqual(parsed.get("object-src"), ["'none'"]);
});

test("CLI: exits 3 and marks a signature-skipping run incomplete", async () => {
  await withServer("good-today", async (base) => {
    await assert.rejects(execFileAsync(process.execPath, [CLI_PATH, "--base", base, "--no-verify-signatures"], {encoding: "utf8"}), (error) => {
      assert.equal(error.code, 3);
      assert.match(error.stdout, /\[PASS\] server-header/);
      assert.match(error.stdout, /\[SKIP\] signed:verification/);
      assert.match(error.stdout, /Result: INCOMPLETE/);
      return true;
    });
  });
});

test("CLI: exits 1 and prints a FAIL line for a bad site", async () => {
  await withServer("no-csp", async (base) => {
    await assert.rejects(execFileAsync(process.execPath, [CLI_PATH, "--base", base], {encoding: "utf8"}), (error) => {
      assert.equal(error.code, 1);
      assert.match(error.stdout, /\[FAIL\] headers:\//);
      return true;
    });
  });
});

test("CLI --json: reports skipped signature checks as incomplete", async () => {
  await withServer("good-today", async (base) => {
    await assert.rejects(execFileAsync(process.execPath, [CLI_PATH, "--base", base, "--json", "--no-verify-signatures"], {encoding: "utf8"}), (error) => {
      assert.equal(error.code, 3);
      const parsed = JSON.parse(error.stdout);
      assert.equal(parsed.baseUrl, base);
      assert.equal(parsed.summary.status, "incomplete");
      assert.ok(Array.isArray(parsed.results));
      assert.ok(parsed.results.length > 20);
      assert.ok(parsed.results.every((r) => r.pass !== false));
      return true;
    });
  });
});

test("CLI: --base is required", async () => {
  await assert.rejects(execFileAsync(process.execPath, [CLI_PATH], {encoding: "utf8"}), (error) => {
    assert.equal(error.code, 2);
    return true;
  });
});

test("verifyClearsignedText does not block the event loop while a slow gpgv-like process runs", async (t) => {
  const stubDir = await mkdtemp(join(tmpdir(), "torisim-privacy-check-slowgpgv-"));
  t.after(() => rm(stubDir, {recursive: true, force: true}));
  const stubPath = join(stubDir, "gpgv");

  await writeFile(
    stubPath,
    "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo stub 1.0; exit 0; fi\nsleep 3\nexit 0\n",
  );
  await chmod(stubPath, 0o755);
  const originalPath = process.env.PATH;
  process.env.PATH = `${stubDir}:${originalPath}`;
  t.after(() => { process.env.PATH = originalPath; });

  const server = createServer((req, res) => res.end("ok"));
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => server.close());
  const port = server.address().port;

  const keyring = dearmorPublicKey(FIXTURE_PUBKEY);
  const verifyPromise = verifyClearsignedText(keyring, FIXTURE_SIGNED_CANARY);
  const started = Date.now();
  await fetch(`http://127.0.0.1:${port}/`);
  const elapsed = Date.now() - started;
  await verifyPromise; 
  assert.ok(elapsed < 1500, `a concurrent HTTP request should resolve quickly if verification does not block the event loop; took ${elapsed}ms`);
});

test("analytics loader text is not an injected beacon attribute", () => {
  assert.deepEqual(findThirdPartyReferences(`<script id="cloudflare-web-analytics">script.setAttribute('data-cf-beacon', '{}');</script>`, 'https://torisim.com'), []);
  assert.ok(findThirdPartyReferences(`<script data-cf-beacon='{}'></script>`, 'https://torisim.com').length > 0);
});
