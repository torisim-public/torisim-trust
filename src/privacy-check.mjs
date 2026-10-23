

import {spawn} from "node:child_process";
import {AsyncLocalStorage} from "node:async_hooks";
const fetchScope = new AsyncLocalStorage();
import {mkdtempSync, writeFileSync, rmSync, realpathSync, readFileSync, statSync} from "node:fs";
import {createHash} from "node:crypto";
import {tmpdir} from "node:os";
import {join, dirname} from "node:path";
import {fileURLToPath} from "node:url";

export const PUBLIC_PAGES = ["/", "/plans", "/privacy", "/privacy-facts", "/bitcoin-esim", "/help/tor-browser"];
export const PRIVATE_PAGES = [
  "/checkout",
  "/my-esim",
  "/recover",
  "/recover-access",
  "/contact",
  "/support",
  "/payment/status",
  "/cases/example",
  "/orders/example",
  "/partners/statements/example",
];
export const ALL_PAGES = [...PUBLIC_PAGES, ...PRIVATE_PAGES];

export const SIGNED_FILE_PATHS = ["/pgp.txt", "/canary.txt", "/mirrors.txt"];
const PGP_PATH = "/pgp.txt";
const CANARY_PATH = "/canary.txt";
const MIRRORS_PATH = "/mirrors.txt";
export const SECURITY_TXT_PATH = "/.well-known/security.txt";

export const CANARY_MAX_AGE_DAYS = 31;

export const EXPECTED_KEY_FINGERPRINT = "4F8F4622F3A1AB6B82E961AEC9CACCC42226BA86";

export const DEFAULT_TRUSTED_KEY_PATH = join(dirname(fileURLToPath(import.meta.url)), "..", "public", "pgp.txt");

export const TEST_PARTNER_CODE = "PRIVACYCHECKTEST";

const USER_AGENT = "TorisimPrivacyCheck/1 (+https://torisim.com/.well-known/security.txt)";
const DEFAULT_TIMEOUT_MS = 8_000;
export const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const MAX_REASON_LENGTH = 2048;
const MAX_PROCESS_OUTPUT_BYTES = 256 * 1024;

function validateTimeout(value) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 60_000) throw new Error("timeoutMs must be an integer from 1 to 60000");
  return value;
}

// This is a command-line checker, not an untrusted-URL proxy. Never deploy it
// behind a service that accepts URLs from strangers. Only explicit local
// fixtures may use HTTP; real targets require HTTPS and redirects are refused.
export function validateBaseUrl(value) {
  if (typeof value !== "string" || value !== value.trim() || /[\u0000-\u0020\u007f\\]/.test(value)) throw new Error("base URL must be a clean absolute origin");
  let url;
  try { url = new URL(value); } catch { throw new Error("base URL must be a valid absolute origin"); }
  if (url.username || url.password || url.search || url.hash || !/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^/?#]+\/?$/.test(value) || url.pathname !== "/") throw new Error("base URL must contain only an origin, without credentials, path, query or fragment");
  const loopback = url.hostname === "127.0.0.1" || url.hostname === "[::1]";
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) throw new Error("base URL requires HTTPS; HTTP is allowed only for literal loopback fixtures");
  return url.origin;
}

function safeReason(value) {
  return String(value).replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g, "?").slice(0, MAX_REASON_LENGTH);
}

function pass(id, category, ok, reason, extra = {}) {
  return {id, category, pass: ok, reason: safeReason(reason), ...extra};
}
function skip(id, category, reason) {
  return {id, category, pass: null, skipped: true, reason: safeReason(reason)};
}
function networkErrorResult(id, category, reason) {
  return pass(id, category, false, reason, {networkError: true});
}

const BROWSER_LIKE_ACCEPT = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";

async function fetchOnce(url, {timeoutMs = DEFAULT_TIMEOUT_MS, headers = {}} = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await (fetchScope.getStore() ?? globalThis.fetch)(url, {
      method: "GET",
      redirect: "manual",
      credentials: "omit",
      signal: controller.signal,
      headers: {"User-Agent": USER_AGENT, "Accept": BROWSER_LIKE_ACCEPT, ...headers},
    });
    if (response.status >= 300 && response.status < 400) {
      await response.body?.cancel();
      throw new Error("redirect refused: no redirected destination was requested");
    }
    if (response.url && new URL(response.url).href !== new URL(url).href) {
      await response.body?.cancel();
      throw new Error("transport returned a different URL");
    }
    const length = response.headers.get("content-length");
    if (length && /^\d+$/.test(length) && Number(length) > MAX_RESPONSE_BYTES) {
      await response.body?.cancel();
      throw new Error(`response exceeds ${MAX_RESPONSE_BYTES} bytes`);
    }
    const chunks = [];
    let bytes = 0;
    if (response.body) {
      const reader = response.body.getReader();
      try {
        while (true) {
          const {done, value} = await reader.read();
          if (done) break;
          bytes += value.byteLength;
          if (bytes > MAX_RESPONSE_BYTES) {
            await reader.cancel();
            throw new Error(`response exceeds ${MAX_RESPONSE_BYTES} bytes`);
          }
          chunks.push(Buffer.from(value));
        }
      } finally {
        reader.releaseLock();
      }
    }
    const body = Buffer.concat(chunks, bytes).toString("utf8");
    return {response, body};
  } finally {
    clearTimeout(timer);
  }
}

async function fetchWithRetry(url, options = {}) {
  try {
    return await fetchOnce(url, options);
  } catch {
    try {
      return await fetchOnce(url, options);
    } catch (secondError) {
      const error = new Error(`request failed twice: ${secondError.message}`);
      error.isNetworkError = true;
      throw error;
    }
  }
}

function setCookieLines(response) {
  if (typeof response.headers.getSetCookie === "function") {
    const lines = response.headers.getSetCookie();
    if (Array.isArray(lines)) return lines;
  }
  const raw = response.headers.get("set-cookie");
  return raw ? [raw] : [];
}

function findCookie(cookieLines, name) {
  for (const line of cookieLines) {
    const first = line.split(";")[0];
    const eq = first.indexOf("=");
    if (eq !== -1 && first.slice(0, eq).trim() === name) return line;
  }
  return null;
}

export function parseCSP(header) {
  const directives = new Map();
  for (const part of (header || "").split(";")) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    if (tokens.length === 0) continue;
    const [name, ...sources] = tokens;
    // Browsers honor the first occurrence of a directive, not the last.
    if (!directives.has(name.toLowerCase())) directives.set(name.toLowerCase(), sources);
  }
  return directives;
}

const SCRIPT_SRC_ALLOWED = new Set(["'self'", "'unsafe-inline'", "https://js.stripe.com", "https://static.cloudflareinsights.com"]);
const CONNECT_SRC_ALLOWED = new Set(["'self'", "https://api.stripe.com", "https://*.stripe.com", "https://cloudflareinsights.com"]);

export function checkCSPHeader(header) {
  const problems = [];
  const directives = parseCSP(header);

  const defaultSrc = directives.get("default-src") || [];
  if (!(defaultSrc.length === 1 && defaultSrc[0] === "'self'")) {
    problems.push(`default-src must be exactly 'self' (got: ${defaultSrc.join(" ") || "(missing)"})`);
  }

  const scriptSrc = directives.get("script-src");
  if (!scriptSrc || scriptSrc.length === 0) {
    problems.push("script-src is missing");
  } else {
    const extra = scriptSrc.filter((source) => !SCRIPT_SRC_ALLOWED.has(source));
    if (extra.length) problems.push(`script-src has unexpected source(s): ${extra.join(", ")}`);
  }
  const scriptElem = directives.get("script-src-elem");
  if (scriptElem) {
    const extra = scriptElem.filter((source) => !SCRIPT_SRC_ALLOWED.has(source));
    if (extra.length) problems.push(`script-src-elem has unexpected source(s): ${extra.join(", ")}`);
  }

  const connectSrc = directives.get("connect-src");
  if (!connectSrc || connectSrc.length === 0) {
    problems.push("connect-src is missing");
  } else {
    const extra = connectSrc.filter((source) => !CONNECT_SRC_ALLOWED.has(source));
    if (extra.length) problems.push(`connect-src has unexpected source(s): ${extra.join(", ")}`);
  }

  const frameAncestors = directives.get("frame-ancestors") || [];
  if (!(frameAncestors.length === 1 && frameAncestors[0] === "'none'")) {
    problems.push(`frame-ancestors must be exactly 'none' (got: ${frameAncestors.join(" ") || "(missing)"})`);
  }

  const objectSrc = directives.get("object-src") || [];
  if (!(objectSrc.length === 1 && objectSrc[0] === "'none'")) {
    problems.push(`object-src must be exactly 'none' (got: ${objectSrc.join(" ") || "(missing)"})`);
  }

  return problems;
}

const MIN_HSTS_MAX_AGE = 31_536_000; 

function checkHeaders(path, response, isPrivate) {
  const h = response.headers;
  const problems = [...checkCSPHeader(h.get("content-security-policy") || "")];
  // Placeholder private routes may correctly answer 404; an error page is
  // never accepted as a working public page.
  if (response.status !== 200 && !(isPrivate && response.status === 404)) problems.push(`unexpected HTTP status ${response.status}`);
  const type = (h.get("content-type") || "").split(";", 1)[0].trim().toLowerCase();
  if (type !== "text/html") problems.push("page content-type is not text/html");

  const referrerPolicy = (h.get("referrer-policy") || "").trim().toLowerCase();
  if (referrerPolicy !== "no-referrer") problems.push(`referrer-policy is "${h.get("referrer-policy") || ""}", not "no-referrer"`);

  const permissionsPolicy = (h.get("permissions-policy") || "").split(",").map((part) => part.trim());
  for (const name of ["camera", "microphone", "geolocation"]) {
    const matching = permissionsPolicy.filter((part) => new RegExp(`^${name}\\s*=`).test(part));
    if (matching.length !== 1 || !new RegExp(`^${name}\\s*=\\s*\\(\\s*\\)$`).test(matching[0])) problems.push(`permissions-policy missing or ambiguous "${name}=()"`);
  }

  const xcto = (h.get("x-content-type-options") || "").trim().toLowerCase();
  if (xcto !== "nosniff") problems.push(`x-content-type-options is "${h.get("x-content-type-options") || ""}", not "nosniff"`);

  const hsts = h.get("strict-transport-security") || "";
  const maxAgeMatch = /(?:^|;)\s*max-age=(\d+)\s*(?:;|$)/i.exec(hsts);
  const maxAge = maxAgeMatch ? Number(maxAgeMatch[1]) : 0;
  if (maxAge < MIN_HSTS_MAX_AGE) problems.push(`strict-transport-security max-age is ${maxAgeMatch ? maxAge : "missing"}, must be at least ${MIN_HSTS_MAX_AGE}`);

  if (isPrivate) {
    const cacheControl = (h.get("cache-control") || "").toLowerCase();
    if (!cacheControl.split(",").some((part) => part.trim() === "no-store")) problems.push(`cache-control is "${h.get("cache-control") || ""}", missing "no-store"`);
    const robotsTag = (h.get("x-robots-tag") || "").toLowerCase();
    if (!robotsTag.split(",").some((part) => part.trim() === "noindex")) problems.push(`x-robots-tag is "${h.get("x-robots-tag") || ""}", missing "noindex"`);
  }

  const ok = problems.length === 0;
  return pass(`headers:${path}`, "security-headers", ok, ok ? "all required headers are present" : problems.join("; "));
}

const MAX_TAG_SCAN = 4096;

export function* iterateOpenTags(html) {
  let i = 0;
  const n = html.length;
  let scanned = 0;
  const scanBudget = 8 * n + MAX_TAG_SCAN;
  while (i < n) {
    const lt = html.indexOf("<", i);
    if (lt === -1) return;
    if (html.startsWith("<!--", lt)) {
      const end = html.indexOf("-->", lt + 4);
      i = end === -1 ? n : end + 3;
      continue;
    }
    const nameMatch = /^<([a-zA-Z][a-zA-Z0-9:-]*)/.exec(html.slice(lt, lt + 64));
    if (!nameMatch) {
      i = lt + 1;
      continue;
    }
    const tagName = nameMatch[1].toLowerCase();
    let j = lt + 1 + nameMatch[1].length;
    let quote = null;
    let afterEquals = false; 
    const scanLimit = Math.min(n, lt + MAX_TAG_SCAN);
    while (j < scanLimit) {
      // Bound recovery work when a response repeats malformed tag prefixes.
      if (++scanned > scanBudget) {
        yield {tagName, tagText: null, tooLong: true, budgetExceeded: true};
        return;
      }
      const ch = html[j];
      if (quote) {
        if (ch === quote) quote = null;
      } else if (ch === ">") {
        break;
      } else if (ch === "=") {
        afterEquals = true;
      } else if (afterEquals) {
        if (ch === '"' || ch === "'") {
          quote = ch;
          afterEquals = false;
        } else if (!/\s/.test(ch)) {
          afterEquals = false; 
        }
      }
      j++;
    }
    const closed = j < scanLimit && html[j] === ">";
    if (!closed) {
      yield {tagName, tagText: null, tooLong: true};
      i = lt + 1;
      continue;
    }
    yield {tagName, tagText: html.slice(lt, j + 1), tooLong: false, start: lt, end: j + 1};
    i = j + 1;
  }
}

const ATTRIBUTE_ENTITIES = {amp: "&", quot: '"', apos: "'", lt: "<", gt: ">", colon: ":", sol: "/", bsol: "\\", Tab: "\t", NewLine: "\n"};

function decodeAttribute(value) {
  return value.replace(/&#(?:x([0-9a-f]+)|([0-9]+));?|&([A-Za-z][A-Za-z0-9]+);/gi, (whole, hex, decimal, name) => {
    if (name) return ATTRIBUTE_ENTITIES[name] ?? whole;
    const point = Number.parseInt(hex ?? decimal, hex ? 16 : 10);
    return point > 0 && point <= 0x10ffff && !(point >= 0xd800 && point <= 0xdfff) ? String.fromCodePoint(point) : "\ufffd";
  });
}

// Scan attribute boundaries rather than looking for src= inside arbitrary
// quoted text. HTML uses the first instance of a repeated attribute.
function attributeValue(tagText, wanted) {
  const prefix = /^<[a-zA-Z][a-zA-Z0-9:-]*/.exec(tagText);
  if (!prefix) return null;
  let i = prefix[0].length;
  while (i < tagText.length) {
    while (i < tagText.length && /[\t\n\f\r /]/.test(tagText[i])) i++;
    if (i >= tagText.length || tagText[i] === ">") break;
    const nameStart = i;
    while (i < tagText.length && !/[\t\n\f\r />=]/.test(tagText[i])) i++;
    const name = tagText.slice(nameStart, i).toLowerCase();
    if (!name) { i++; continue; }
    while (i < tagText.length && /[\t\n\f\r ]/.test(tagText[i])) i++;
    let value = "";
    if (tagText[i] === "=") {
      i++;
      while (i < tagText.length && /[\t\n\f\r ]/.test(tagText[i])) i++;
      const quote = tagText[i] === '"' || tagText[i] === "'" ? tagText[i++] : null;
      const start = i;
      while (i < tagText.length && (quote ? tagText[i] !== quote : !/[\t\n\f\r >]/.test(tagText[i]))) i++;
      value = tagText.slice(start, i);
      if (quote && tagText[i] === quote) i++;
    }
    if (name === wanted.toLowerCase()) return decodeAttribute(value);
  }
  return null;
}

function extractElementText(html, tagName) {
  const texts = [];
  const closing = new RegExp(`</${tagName}\\s*>`, "gi");
  let consumedUntil = 0;
  for (const tag of iterateOpenTags(html)) {
    if (tag.tooLong || tag.tagName !== tagName || tag.start < consumedUntil) continue;
    closing.lastIndex = tag.end;
    const match = closing.exec(html);
    if (!match) {
      texts.push(html.slice(tag.end));
      break;
    }
    texts.push(html.slice(tag.end, match.index));
    consumedUntil = closing.lastIndex;
  }
  return texts;
}

const ALLOWED_LINK_REL_TOKENS = new Set([
  "stylesheet",
  "preload",
  "modulepreload",
  "icon",
  "preconnect",
  "dns-prefetch",
  "prefetch",
  "manifest",
  "apple-touch-icon",
  "apple-touch-icon-precomposed",
]);
const NON_NETWORK_SCHEMES = new Set(["data:", "blob:", "mailto:", "tel:", "javascript:", "about:"]);

function isNonNetworkReference(value) {
  const trimmed = value.trim();
  if (!trimmed || trimmed.startsWith("#")) return true;
  const schemeMatch = /^([a-zA-Z][a-zA-Z0-9+.-]*:)/.exec(trimmed);
  return Boolean(schemeMatch && NON_NETWORK_SCHEMES.has(schemeMatch[1].toLowerCase()));
}

function resolveAgainst(value, base) {
  try {
    return new URL(value, base);
  } catch {
    return null;
  }
}

function parseSrcset(value) {
  return value.split(",").map((candidate) => candidate.trim().split(/\s+/)[0]).filter(Boolean);
}

function pushAttr(found, tagText, selector, attrName) {
  const value = attributeValue(tagText, attrName);
  if (value) found.push({selector, value});
}
function pushSrcset(found, tagText, selector, attrName) {
  const value = attributeValue(tagText, attrName);
  if (!value) return;
  for (const candidate of parseSrcset(value)) found.push({selector, value: candidate});
}

function pushSpaceList(found, tagText, selector, attrName) {
  const value = attributeValue(tagText, attrName);
  if (!value) return;
  for (const token of value.split(/\s+/).filter(Boolean)) found.push({selector, value: token});
}
const CSS_URL_RE = /url\(\s*(['"]?)([^'")]+)\1\s*\)/gi;
const CSS_IMPORT_RE = /@import\s+(?:url\(\s*(['"]?)([^'")]+)\1\s*\)|(['"])([^'"]+)\3)/gi;

const CSS_IMAGE_SET_RE = /(?:-webkit-)?image-set\(([^)]*)\)/gi;
function pushCssUrls(found, css, selector) {
  CSS_URL_RE.lastIndex = 0;
  let match;
  while ((match = CSS_URL_RE.exec(css))) found.push({selector: `${selector} url()`, value: match[2]});
}
function pushCssImports(found, css, selector) {
  CSS_IMPORT_RE.lastIndex = 0;
  let match;
  while ((match = CSS_IMPORT_RE.exec(css))) found.push({selector: `${selector} @import`, value: match[2] ?? match[4]});
}
function pushCssImageSet(found, css, selector) {
  CSS_IMAGE_SET_RE.lastIndex = 0;
  let match;
  while ((match = CSS_IMAGE_SET_RE.exec(css))) {
    for (const candidate of match[1].split(",")) {
      const trimmed = candidate.trim();
      const urlMatch = /^url\(\s*(['"]?)([^'")]+)\1\s*\)/i.exec(trimmed);
      const quotedMatch = /^(['"])([^'"]+)\1/.exec(trimmed);
      const value = urlMatch ? urlMatch[2] : quotedMatch ? quotedMatch[2] : null;
      if (value) found.push({selector: `${selector} image-set()`, value});
    }
  }
}

export function findThirdPartyReferences(html, siteOrigin) {
  const found = [];
  const tooLongViolations = [];
  let injectedBeacon = false;

  let resolutionBase = siteOrigin;
  for (const {tagName, tagText, tooLong} of iterateOpenTags(html)) {
    if (tooLong || tagName !== "base") continue; 
    const href = attributeValue(tagText, "href");
    if (href) {
      found.push({selector: "base[href]", value: href});
      if (!isNonNetworkReference(href)) {
        const resolved = resolveAgainst(href, siteOrigin);
        if (resolved) resolutionBase = resolved.href;
      }
    }
    break; 
  }

  for (const {tagName, tagText, tooLong, budgetExceeded} of iterateOpenTags(html)) {
    if (tooLong) {
      tooLongViolations.push(budgetExceeded ? "HTML scan work limit exceeded; remaining references cannot be verified" : `tag too long to check (over ${MAX_TAG_SCAN} characters; starts with <${tagName}>)`);
      continue;
    }
    switch (tagName) {
      case "script":
        if (/\bdata-cf-beacon\b/i.test(tagText)) injectedBeacon = true;
        pushAttr(found, tagText, "script[src]", "src");
        pushAttr(found, tagText, "script[data-src]", "data-src");
        pushAttr(found, tagText, "script[href]", "href");
        pushAttr(found, tagText, "script[xlink:href]", "xlink:href");
        break;
      case "img":
        pushAttr(found, tagText, "img[data-src]", "data-src"); 
        pushAttr(found, tagText, "img[src]", "src");
        pushSrcset(found, tagText, "img[srcset]", "srcset");
        pushSrcset(found, tagText, "img[data-srcset]", "data-srcset");
        break;
      case "source":
        pushAttr(found, tagText, "source[src]", "src");
        pushSrcset(found, tagText, "source[srcset]", "srcset");
        break;
      case "iframe":
        pushAttr(found, tagText, "iframe[data-src]", "data-src");
        pushAttr(found, tagText, "iframe[src]", "src");
        if (attributeValue(tagText, "srcdoc")) tooLongViolations.push("iframe[srcdoc] contains embedded HTML; its references cannot be verified");
        break;
      case "video":
        pushAttr(found, tagText, "video[src]", "src");
        pushAttr(found, tagText, "video[poster]", "poster");
        break;
      case "audio":
        pushAttr(found, tagText, "audio[src]", "src");
        break;
      case "track":
        pushAttr(found, tagText, "track[src]", "src");
        break;
      case "embed":
        pushAttr(found, tagText, "embed[src]", "src");
        break;
      case "object":
        pushAttr(found, tagText, "object[data]", "data");
        break;
      case "image": 
        pushAttr(found, tagText, "image[href]", "href");
        pushAttr(found, tagText, "image[xlink:href]", "xlink:href");
        break;
      case "use": 
        pushAttr(found, tagText, "use[href]", "href");
        pushAttr(found, tagText, "use[xlink:href]", "xlink:href");
        break;
      case "a":
        pushSpaceList(found, tagText, "a[ping]", "ping");
        break;
      case "button":
        pushAttr(found, tagText, "button[formaction]", "formaction");
        break;
      case "input": {
        const type = (attributeValue(tagText, "type") || "").toLowerCase();
        if (type === "image") pushAttr(found, tagText, "input[type=image][src]", "src");
        pushAttr(found, tagText, "input[formaction]", "formaction");
        break;
      }
      case "form":
        pushAttr(found, tagText, "form[action]", "action");
        break;
      case "link": {
        const rel = (attributeValue(tagText, "rel") || "").toLowerCase();
        const tokens = rel.split(/\s+/).filter(Boolean);
        if (tokens.some((token) => ALLOWED_LINK_REL_TOKENS.has(token))) pushAttr(found, tagText, `link[rel=${rel}]`, "href");
        break;
      }
      case "meta": {
        const httpEquiv = (attributeValue(tagText, "http-equiv") || "").toLowerCase();
        if (httpEquiv !== "refresh") break;
        const content = attributeValue(tagText, "content") || "";
        const urlMatch = /url\s*=\s*(['"]?)([^'";]+)\1?/i.exec(content);
        if (urlMatch) found.push({selector: "meta[http-equiv=refresh]", value: urlMatch[2]});
        break;
      }
      default:
        break;
    }
    const styleAttr = attributeValue(tagText, "style");
    if (styleAttr) {
      if (styleAttr.includes("\\")) tooLongViolations.push("CSS escape in style attribute; CSS references cannot be fully verified");
      pushCssUrls(found, styleAttr, "[style]");
      pushCssImageSet(found, styleAttr, "[style]");
    }
  }

  for (const styleText of extractElementText(html, "style")) {
    if (styleText.includes("\\")) tooLongViolations.push("CSS escape in style element; CSS references cannot be fully verified");
    pushCssUrls(found, styleText, "style");
    pushCssImports(found, styleText, "style");
    pushCssImageSet(found, styleText, "style");
  }

  const violations = [...tooLongViolations];
  for (const {selector, value} of found) {
    if (/&[A-Za-z][A-Za-z0-9]+;/.test(value)) {
      violations.push(`unresolved HTML entity in ${selector}; reference cannot be verified`);
      continue;
    }
    if ((selector.includes("url()") || selector.includes("@import") || selector.includes("image-set()")) && value.includes("\\")) {
      violations.push(`CSS escape in ${selector}; reference cannot be verified`);
      continue;
    }
    if (isNonNetworkReference(value)) continue;
    const resolved = resolveAgainst(value, resolutionBase);
    if (!resolved) continue;
    if (resolved.origin !== siteOrigin) violations.push(`${resolved.origin} (${selector}="${value}")`);
  }

  if (injectedBeacon) violations.push("inline data-cf-beacon attribute is present");

  return [...new Set(violations)];
}

function checkThirdPartyContent(path, html, siteOrigin) {
  const violations = findThirdPartyReferences(html, siteOrigin);
  const ok = violations.length === 0;
  return pass(`third-party:${path}`, "third-party-content", ok, ok ? "no third-party origin found in inspected HTML references" : violations.join("; "));
}

function checkNoCookieOnPublicPage(path, response) {
  const cookies = setCookieLines(response);
  const ok = cookies.length === 0;
  return pass(`cookies:no-cookie:${path}`, "cookies", ok, ok ? "no Set-Cookie on a plain GET" : `unexpected Set-Cookie (${cookies.length} header(s); values omitted)`);
}

async function checkPartnerCookie(origin, timeoutMs) {
  const results = [];
  const url = new URL("/", origin);
  url.searchParams.set("partner", TEST_PARTNER_CODE);

  try {
    const {response} = await fetchWithRetry(url.toString(), {timeoutMs, headers: {"Sec-GPC": "1"}});
    const cookie = findCookie(setCookieLines(response), "tori_ref");
    results.push(
      pass("cookies:partner-gpc-blocked", "cookies", !cookie, !cookie ? "Sec-GPC: 1 correctly blocked tori_ref" : "tori_ref was set despite Sec-GPC: 1 (value omitted)"),
    );
  } catch (error) {
    results.push(networkErrorResult("cookies:partner-gpc-blocked", "cookies", `request failed (after retry): ${error.message}`));
  }

  try {
    const {response} = await fetchWithRetry(url.toString(), {timeoutMs});
    const cookie = findCookie(setCookieLines(response), "tori_ref");
    if (!cookie) {
      results.push(pass("cookies:partner-cookie-shape", "cookies", false, "tori_ref was not set on a plain partner-link visit"));
    } else {
      const attributes = new Map();
      const duplicate = new Set();
      for (const item of cookie.split(";").slice(1)) {
        const eq = item.indexOf("=");
        const name = (eq < 0 ? item : item.slice(0, eq)).trim().toLowerCase();
        const value = eq < 0 ? null : item.slice(eq + 1).trim().toLowerCase();
        if (attributes.has(name)) duplicate.add(name);
        attributes.set(name, value);
      }
      const missing = [];
      if (attributes.get("httponly") !== null || duplicate.has("httponly")) missing.push("HttpOnly");
      if (attributes.get("secure") !== null || duplicate.has("secure")) missing.push("Secure");
      if (attributes.get("samesite") !== "lax" || duplicate.has("samesite")) missing.push("SameSite=Lax");
      if (attributes.get("max-age") !== "2592000" || duplicate.has("max-age")) missing.push("Max-Age=2592000");
      const ok = missing.length === 0;
      results.push(
        pass("cookies:partner-cookie-shape", "cookies", ok, ok ? "tori_ref has HttpOnly, Secure, SameSite=Lax, Max-Age=2592000" : `tori_ref is missing or has ambiguous attributes: ${missing.join(", ")} (value omitted)`),
      );
    }
  } catch (error) {
    results.push(networkErrorResult("cookies:partner-cookie-shape", "cookies", `request failed (after retry): ${error.message}`));
  }

  return results;
}

// The verifier is a local executable; HTTP bodies never become command names
// or shell arguments. Bound its runtime and output, including --version probes.
function spawnAsync(command, args, {timeout = DEFAULT_TIMEOUT_MS} = {}) {
  return new Promise((resolve) => {
    let child;
    let timer;
    let finished = false;
    let outputBytes = 0;
    const stdoutChunks = [];
    const stderrChunks = [];
    const finish = (status, error = null) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      resolve({status, error, stdout: Buffer.concat(stdoutChunks), stderr: Buffer.concat(stderrChunks)});
    };
    const stop = (message) => {
      child?.kill("SIGKILL");
      child?.stdout?.destroy();
      child?.stderr?.destroy();
      finish(null, new Error(message));
    };
    try {
      child = spawn(command, args, {stdio: ["ignore", "pipe", "pipe"]});
    } catch (error) {
      finish(null, error);
      return;
    }
    const append = (chunks, chunk) => {
      if (finished) return;
      outputBytes += chunk.length;
      if (outputBytes > MAX_PROCESS_OUTPUT_BYTES) { stop("verifier output limit exceeded"); return; }
      chunks.push(chunk);
    };
    child.stdout?.on("data", (chunk) => append(stdoutChunks, chunk));
    child.stderr?.on("data", (chunk) => append(stderrChunks, chunk));
    child.on("error", (error) => finish(null, error));
    child.on("close", (status) => finish(status));
    timer = setTimeout(() => stop("verifier timed out"), timeout);
  });
}

async function hasCommand(command, timeoutMs, homedir) {
  const args = ["--version", "--homedir", homedir, ...(command === "gpg" ? ["--no-options"] : [])];
  const result = await spawnAsync(command, args, {timeout: timeoutMs});
  return !result.error && result.status === 0;
}

export function dearmorPublicKey(armored) {
  if (typeof armored !== "string" || Buffer.byteLength(armored) > MAX_RESPONSE_BYTES) throw new Error("public-key text exceeds limits or is not a string");
  if (armored.split("-----BEGIN PGP PUBLIC KEY BLOCK-----").length !== 2 || armored.split("-----END PGP PUBLIC KEY BLOCK-----").length !== 2) throw new Error("expected exactly one armored PGP public key block");
  const lines = armored.split(/\r?\n/);
  const start = lines.findIndex((line) => line.startsWith("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
  const end = lines.findIndex((line) => line.startsWith("-----END PGP PUBLIC KEY BLOCK-----"));
  if (start === -1 || end === -1 || end <= start) throw new Error("not an armored PGP public key block");
  let body = lines.slice(start + 1, end);
  const blank = body.findIndex((line) => line.trim() === "");
  if (blank !== -1) body = body.slice(blank + 1); 
  body = body.filter((line) => line.trim() !== "");
  if (body.length && /^=[A-Za-z0-9+/]{4}$/.test(body[body.length - 1])) body = body.slice(0, -1); 
  const encoded = body.join("");
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(encoded) || encoded.length % 4 !== 0) throw new Error("invalid public-key base64");
  return Buffer.from(encoded, "base64");
}

function readPacketHeader(buffer, offset) {
  if (buffer.length < offset + 2) throw new Error("packet header runs past the end of the buffer");
  const first = buffer[offset];
  if ((first & 0x80) === 0) throw new Error("not a valid OpenPGP packet (high bit unset)");
  const isOldFormat = (first & 0x40) === 0;
  let tag, bodyStart, bodyLength;
  if (isOldFormat) {
    tag = (first >> 2) & 0x0f;
    const lengthType = first & 0x03;
    if (lengthType === 0) {
      bodyLength = buffer[offset + 1];
      bodyStart = offset + 2;
    } else if (lengthType === 1) {
      bodyLength = buffer.readUInt16BE(offset + 1);
      bodyStart = offset + 3;
    } else if (lengthType === 2) {
      bodyLength = buffer.readUInt32BE(offset + 1);
      bodyStart = offset + 5;
    } else {
      throw new Error("indeterminate-length OpenPGP packet is not supported");
    }
  } else {
    tag = first & 0x3f;
    const len1 = buffer[offset + 1];
    if (len1 < 192) {
      bodyLength = len1;
      bodyStart = offset + 2;
    } else if (len1 < 224) {
      bodyLength = ((len1 - 192) << 8) + buffer[offset + 2] + 192;
      bodyStart = offset + 3;
    } else if (len1 === 255) {
      bodyLength = buffer.readUInt32BE(offset + 2);
      bodyStart = offset + 6;
    } else {
      throw new Error("partial-length OpenPGP packet is not supported");
    }
  }
  if (!Number.isSafeInteger(bodyLength) || bodyLength < 0 || buffer.length < bodyStart + bodyLength) throw new Error("packet body runs past the end of the buffer");
  return {tag, bodyStart, bodyLength};
}

export function computeFingerprintV4(keyringBuffer) {
  if (keyringBuffer.length < 2) throw new Error("keyring buffer is too short to hold a packet header");
  const {tag, bodyStart, bodyLength} = readPacketHeader(keyringBuffer, 0);
  if (tag !== 6) throw new Error(`expected a public-key packet (tag 6) first, got tag ${tag}`);
  const body = keyringBuffer.subarray(bodyStart, bodyStart + bodyLength);
  if (body[0] !== 4 || body.length > 65535) throw new Error("expected a version-4 public-key packet within fingerprint limits");
  const lengthPrefix = Buffer.alloc(2);
  lengthPrefix.writeUInt16BE(body.length, 0);
  return createHash("sha1").update(Buffer.concat([Buffer.from([0x99]), lengthPrefix, body])).digest("hex").toUpperCase();
}

export function countPrimaryKeyPackets(keyringBuffer) {
  let offset = 0;
  let count = 0;
  while (offset < keyringBuffer.length) {
    const {tag, bodyStart, bodyLength} = readPacketHeader(keyringBuffer, offset);
    if (tag === 6) count += 1;
    offset = bodyStart + bodyLength;
  }
  return count;
}

function lastLine(buffer) {
  const text = buffer ? buffer.toString("utf8").trim() : "";
  const lines = text.split("\n").filter(Boolean);
  return lines[lines.length - 1] || "";
}

export async function verifyClearsignedText(keyringBuffer, signedText, {timeoutMs = 8000} = {}) {
  validateTimeout(timeoutMs);
  const failure = (detail) => ({checked: true, ok: false, detail: safeReason(detail), plaintext: null});
  if (!Buffer.isBuffer(keyringBuffer) || keyringBuffer.length > MAX_RESPONSE_BYTES || typeof signedText !== "string" || Buffer.byteLength(signedText) > MAX_RESPONSE_BYTES) return failure("verification input exceeds limits or has an invalid type");
  try {
    if (countPrimaryKeyPackets(keyringBuffer) !== 1) return failure("verification requires exactly one primary public key");
    computeFingerprintV4(keyringBuffer);
  } catch (error) { return failure(`invalid public key: ${error.message}`); }
  // Limit this API to a single clear-signed message. Unsigned prefix/suffix
  // lines are never interpreted: dates come only from GnuPG's verified output.
  for (const marker of ["-----BEGIN PGP SIGNED MESSAGE-----", "-----BEGIN PGP SIGNATURE-----", "-----END PGP SIGNATURE-----"]) {
    if (signedText.split(marker).length !== 2) return failure("expected exactly one clear-signed message");
  }
  const dir = mkdtempSync(join(tmpdir(), "torisim-privacy-check-"));
  try {
    const keyringPath = join(dir, "keyring.gpg");
    const signedPath = join(dir, "signed.asc");
    const plainPath = join(dir, "plain.txt");
    writeFileSync(keyringPath, keyringBuffer, {mode: 0o600});
    writeFileSync(signedPath, signedText, {encoding: "utf8", mode: 0o600});
    const readPlain = () => {
      try {
        if (statSync(plainPath).size > MAX_RESPONSE_BYTES) return null;
        return readFileSync(plainPath, "utf8");
      } catch { return null; }
    };
    const verified = (run) => {
      const status = run.stdout.toString("utf8");
      return !run.error && run.status === 0 && (status.match(/^\[GNUPG:\] VALIDSIG /gm) ?? []).length === 1 &&
        !/^\[GNUPG:\] (?:BADSIG|ERRSIG|EXPSIG|EXPKEYSIG|REVKEYSIG|KEYEXPIRED|SIGEXPIRED|FAILURE|ERROR)\b/m.test(status);
    };
    const detail = (command, run) => `${command}: ${run.error?.message || lastLine(run.stderr) || "verification failed"}`;
    if (await hasCommand("gpgv", timeoutMs, dir)) {
      const run = await spawnAsync("gpgv", ["--homedir", dir, "--keyring", keyringPath, "--status-fd", "1", "--output", plainPath, signedPath], {timeout: timeoutMs});
      if (!verified(run)) return failure(detail("gpgv", run));
      const plaintext = readPlain();
      return plaintext === null ? failure("gpgv: verified plaintext was not produced within limits") : {checked: true, ok: true, detail: "gpgv: good signature", plaintext};
    }
    if (await hasCommand("gpg", timeoutMs, dir)) {
      // No default configuration, keyring, agent or network key retrieval.
      const base = ["--no-options", "--batch", "--no-tty", "--no-autostart", "--homedir", dir, "--no-default-keyring", "--keyring", keyringPath, "--no-auto-key-retrieve", "--status-fd", "1"];
      const run = await spawnAsync("gpg", [...base, "--verify", signedPath], {timeout: timeoutMs});
      if (!verified(run)) return failure(detail("gpg", run));
      const extraction = await spawnAsync("gpg", [...base, "--output", plainPath, "--decrypt", signedPath], {timeout: timeoutMs});
      if (!verified(extraction)) return failure(detail("gpg plaintext extraction", extraction));
      const plaintext = readPlain();
      return plaintext === null ? failure("gpg: verified plaintext was not produced within limits") : {checked: true, ok: true, detail: "gpg: good signature", plaintext};
    }
    return {checked: false, ok: null, detail: "gpg/gpgv not found on PATH or version probe failed", plaintext: null};
  } finally {
    rmSync(dir, {recursive: true, force: true});
  }
}

const DAY_MS = 86_400_000;

function parseCanaryDay(text) {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(text);
  if (!match) return null;
  const [year, month, day] = match.slice(1).map(Number);
  const start = Date.UTC(year, month - 1, day);
  const check = new Date(start);
  if (check.getUTCFullYear() !== year || check.getUTCMonth() !== month - 1 || check.getUTCDate() !== day) return null;
  return start;
}

function canaryField(signedText, label) {
  const lines = signedText.split("\n").filter((candidate) => candidate.startsWith(`${label}:`));
  if (lines.length > 1) return "(duplicate fields)";
  const line = lines[0];
  return line === undefined ? null : line.slice(label.length + 1).trim();
}

function preview(text) {
  const printable = text.replace(/[^\x20-\x7e]/g, "?");
  return printable.length > 40 ? `${printable.slice(0, 40)}...` : printable;
}

export function checkCanaryDates(signedText, now) {
  const failBoth = (reason) => [pass("signed:canary:freshness", "signed-files", false, reason), pass("signed:canary:next-canary-not-passed", "signed-files", false, reason)];

  if (typeof signedText !== "string") return failBoth("the canary's signature was not verified, so its signed dates are not read");
  
  const nowMs = typeof now?.getTime === "function" ? now.getTime() : NaN;
  if (!Number.isFinite(nowMs)) return failBoth("the check has no valid current time, so the canary dates cannot be checked");
  const problems = [];

  const dateText = canaryField(signedText, "Date");
  const issued = dateText === null ? null : parseCanaryDay(dateText);
  if (dateText === null) problems.push('canary.txt has no "Date: YYYY-MM-DD" line in its signed text');
  else if (issued === null) problems.push(`canary.txt "Date: ${preview(dateText)}" is not a real YYYY-MM-DD date`);

  const nextText = canaryField(signedText, "Next canary");
  const nextMatch = nextText === null ? null : /^by\s+(\S+)$/.exec(nextText);
  const nextStart = nextMatch ? parseCanaryDay(nextMatch[1]) : null;
  let nextProblem = null;
  if (nextText === null) nextProblem = 'canary.txt has no "Next canary: by YYYY-MM-DD" line in its signed text';
  else if (nextStart === null) nextProblem = `canary.txt "Next canary: ${preview(nextText)}" is not "by" and a real YYYY-MM-DD date`;
  else if (issued !== null && nextStart < issued) nextProblem = '"Next canary" is earlier than the signed issue date';
  else if (nowMs >= nextStart + DAY_MS) nextProblem = `"Next canary: by ${nextMatch[1]}" has passed (the canary was valid to the end of that day, UTC)`;
  if (nextProblem) problems.push(nextProblem);

  const ageDays = issued === null ? null : (nowMs - issued) / DAY_MS;
  if (ageDays !== null && ageDays < 0) problems.push(`canary dated ${dateText} is in the future (UTC)`);
  if (ageDays !== null && ageDays > CANARY_MAX_AGE_DAYS) problems.push(`canary dated ${dateText} is more than ${CANARY_MAX_AGE_DAYS} days old (${ageDays.toFixed(1)} day(s))`);

  const fresh = problems.length === 0;
  
  const age = ageDays !== null && ageDays < 0 ? `has a date ${(-ageDays).toFixed(1)} day(s) in the future` : `is ${ageDays?.toFixed(1)} day(s) old`;
  return [
    pass(
      "signed:canary:freshness",
      "signed-files",
      fresh,
      fresh ? `canary dated ${dateText} ${age} (limit ${CANARY_MAX_AGE_DAYS}); it is valid to the end of ${nextMatch[1]} (UTC), its "Next canary" date` : problems.join("; "),
    ),
    pass("signed:canary:next-canary-not-passed", "signed-files", nextProblem === null, nextProblem ?? `next canary due by ${nextMatch[1]}`),
  ];
}

const PGP_SIGNED_MESSAGE_MARKERS = [/-----BEGIN PGP SIGNED MESSAGE-----/, /-----BEGIN PGP SIGNATURE-----/];

async function checkSignedFiles(origin, {timeoutMs, now, verifySignatures, expectedFingerprint, trustedKeyPath, trustedKeyText}) {
  const results = [];
  const bodies = {};

  for (const path of SIGNED_FILE_PATHS) {
    try {
      const {response, body} = await fetchWithRetry(new URL(path, origin).toString(), {timeoutMs});
      const contentType = (response.headers.get("content-type") || "").toLowerCase();
      const nonEmpty = body.trim().length > 0;
      const looksSigned = path === PGP_PATH
        ? /-----BEGIN PGP PUBLIC KEY BLOCK-----/.test(body)
        : PGP_SIGNED_MESSAGE_MARKERS.every((marker) => marker.test(body));
      const problems = [];
      if (response.status !== 200) problems.push(`status ${response.status}`);
      if (!contentType.includes("text/plain")) problems.push(`content-type "${contentType}"`);
      if (!nonEmpty) problems.push("empty body");
      else if (!looksSigned) problems.push(path === PGP_PATH ? "missing PGP public-key-block markers" : "missing PGP signed-message markers");
      const ok = problems.length === 0;
      results.push(pass(`signed:${path}`, "signed-files", ok, ok ? "200 text/plain, signed" : problems.join("; ")));
      bodies[path] = body;
    } catch (error) {
      results.push(networkErrorResult(`signed:${path}`, "signed-files", `could not fetch (after retry): ${error.message}`));
      bodies[path] = null;
    }
  }

  if (verifySignatures) {
    const pgpBody = bodies[PGP_PATH];

    let localKeyText = trustedKeyText ?? null;
    let localKeyError = null;
    if (localKeyText === null) {
      try {
        const keyFile = statSync(trustedKeyPath);
        if (!keyFile.isFile() || keyFile.size > MAX_RESPONSE_BYTES) throw new Error("trusted key must be a regular file within size limits");
        localKeyText = readFileSync(trustedKeyPath, "utf8");
      } catch (error) {
        localKeyError = `could not read the local trusted copy at ${trustedKeyPath}: ${error.message}`;
      }
    }
    let localKeyring = null;
    if (localKeyText !== null && !localKeyError) {
      try {
        localKeyring = dearmorPublicKey(localKeyText);
        const localKeyCount = countPrimaryKeyPackets(localKeyring);
        if (localKeyCount !== 1) localKeyError = `the local trusted copy has ${localKeyCount} primary keys, expected exactly 1`;
      } catch (error) {
        localKeyError = `the local trusted copy could not be read as an armored key (${error.message})`;
      }
    }

    if (localKeyError) {
      results.push(pass("signed:pgp:fingerprint", "signed-files", false, localKeyError));
    } else {
      let fingerprint = null;
      let fingerprintError = null;
      try {
        fingerprint = computeFingerprintV4(localKeyring);
      } catch (error) {
        fingerprintError = error.message;
      }
      const ok = fingerprint === expectedFingerprint;
      results.push(
        pass(
          "signed:pgp:fingerprint",
          "signed-files",
          ok,
          ok ? "key fingerprint matches the pinned value" : `the local trusted copy's key fingerprint is ${fingerprint ?? `unreadable (${fingerprintError})`}, expected ${expectedFingerprint}`,
        ),
      );
    }

    if (!pgpBody) {
      results.push(pass("signed:pgp:matches-local-copy", "signed-files", false, "pgp.txt is unavailable; it cannot be compared to the local trusted copy"));
      results.push(pass("signed:pgp:single-key", "signed-files", false, "pgp.txt is unavailable; its key count cannot be checked"));
    } else {
      let liveKeyring = null;
      let liveKeyError = null;
      try {
        liveKeyring = dearmorPublicKey(pgpBody);
      } catch (error) {
        liveKeyError = error.message;
      }

      if (liveKeyError) {
        const reason = `pgp.txt could not be read as an armored key (${liveKeyError})`;
        results.push(pass("signed:pgp:matches-local-copy", "signed-files", false, reason));
        results.push(pass("signed:pgp:single-key", "signed-files", false, reason));
      } else {
        const matches = !localKeyError && Buffer.isBuffer(localKeyring) && liveKeyring.equals(localKeyring);
        results.push(
          pass(
            "signed:pgp:matches-local-copy",
            "signed-files",
            matches,
            matches
              ? "pgp.txt matches the local trusted copy exactly"
              : localKeyError
                ? `pgp.txt cannot be compared: ${localKeyError}`
                : "pgp.txt does not match the local trusted copy -- not trusted for signature verification",
          ),
        );

        let liveKeyCount = null;
        let liveKeyCountError = null;
        try {
          liveKeyCount = countPrimaryKeyPackets(liveKeyring);
        } catch (error) {
          liveKeyCountError = error.message;
        }
        const singleKeyOk = liveKeyCount === 1;
        results.push(
          pass(
            "signed:pgp:single-key",
            "signed-files",
            singleKeyOk,
            liveKeyCountError
              ? `pgp.txt's key packets could not be counted: ${liveKeyCountError}`
              : singleKeyOk
                ? "pgp.txt carries exactly one primary key"
                : `pgp.txt carries ${liveKeyCount} primary keys, expected exactly 1`,
          ),
        );
      }
    }

    let canarySignedText = null;
    for (const [path, id] of [
      [CANARY_PATH, "signed:canary:signature"],
      [MIRRORS_PATH, "signed:mirrors:signature"],
    ]) {
      const body = bodies[path];
      if (localKeyError) {
        results.push(pass(id, "signed-files", false, `the local trusted copy is unusable; the signature cannot be verified (${localKeyError})`));
      } else if (!body) {
        results.push(pass(id, "signed-files", false, `${path} is unavailable; the signature cannot be verified`));
      } else {
        const outcome = await verifyClearsignedText(localKeyring, body, {timeoutMs});

        if (!outcome.checked) results.push(pass(id, "signed-files", false, outcome.detail));
        else results.push(pass(id, "signed-files", outcome.ok, outcome.detail));

        if (path === CANARY_PATH && outcome.ok) canarySignedText = outcome.plaintext;
      }
    }

    results.push(...checkCanaryDates(canarySignedText, now));
  } else {
    results.push(skip("signed:verification", "signed-files", "signature, key identity and canary freshness checks were not performed"));
  }

  return results;
}

async function checkSecurityTxt(origin, timeoutMs, now) {
  const id = "security-txt";
  try {
    const {response, body} = await fetchWithRetry(new URL(SECURITY_TXT_PATH, origin).toString(), {timeoutMs});
    if (response.status !== 200) return pass(id, "security-txt", false, `status ${response.status}`);

    const problems = [];
    const contentType = (response.headers.get("content-type") || "").toLowerCase();
    if (!contentType.includes("text/plain")) problems.push(`content-type "${contentType}" is not text/plain`);

    if (!/^Contact:\s*\S/m.test(body)) problems.push("no Contact: field");

    const expires = /^Expires:\s*(\S+)/m.exec(body);
    if (!expires) {
      problems.push("no Expires: field");
    } else {
      const expiresMs = Date.parse(expires[1]);
      if (Number.isNaN(expiresMs)) problems.push(`Expires: "${expires[1]}" is not a date this check can parse`);
      else if (expiresMs <= now.getTime()) problems.push(`Expires: ${expires[1]} is not in the future`);
    }

    const encryption = /^Encryption:\s*(\S+)/m.exec(body);
    if (!encryption) problems.push("no Encryption: field");
    else if (!/^https:\/\/.+\/pgp\.txt$/.test(encryption[1])) problems.push(`Encryption: "${encryption[1]}" does not point at a pgp.txt key`);

    const ok = problems.length === 0;
    return pass(id, "security-txt", ok, ok ? "200 text/plain with Contact, a future Expires and Encryption" : problems.join("; "));
  } catch (error) {
    return networkErrorResult(id, "security-txt", `could not fetch (after retry): ${error.message}`);
  }
}

function checkServerHeader(response) {
  const id = "server-header";
  const server = response.headers.get("server");
  const ok = !server || server.trim().toLowerCase() === "cloudflare";
  return pass(id, "server-header", ok, ok ? (server ? `server: ${server}` : "no server header") : `server header reveals "${server}"`);
}

export async function runPrivacyChecks(baseUrl, options = {}) {
  if (options.fetchImpl !== undefined && typeof options.fetchImpl !== 'function') throw new Error('invalid privacy transport');
  validateBaseUrl(baseUrl);
  validateTimeout(options.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  for (const name of ["allowPartnerCookieCheck", "verifySignatures"]) {
    if (options[name] !== undefined && typeof options[name] !== "boolean") throw new Error(`${name} must be a boolean`);
  }
  if (options.now !== undefined && (!(options.now instanceof Date) || !Number.isFinite(options.now.getTime()))) throw new Error("now must be a valid Date");
  return fetchScope.run(options.fetchImpl ?? globalThis.fetch, () => runPrivacyChecksScoped(baseUrl, options));
}
async function runPrivacyChecksScoped(baseUrl, options = {}) {
  const {
    timeoutMs = DEFAULT_TIMEOUT_MS,
    allowPartnerCookieCheck = false,
    verifySignatures = true,
    now = new Date(),
    expectedFingerprint = EXPECTED_KEY_FINGERPRINT,
    trustedKeyPath = DEFAULT_TRUSTED_KEY_PATH,
    trustedKeyText = null,
  } = options;
  const origin = validateBaseUrl(baseUrl);
  const results = [];
  let rootResponse = null;

  for (const path of ALL_PAGES) {
    let fetched;
    try {
      fetched = await fetchWithRetry(new URL(path, origin).toString(), {timeoutMs});
    } catch (error) {
      const reason = `could not fetch (after retry): ${error.message}`;
      results.push(networkErrorResult(`headers:${path}`, "security-headers", reason));
      results.push(networkErrorResult(`third-party:${path}`, "third-party-content", reason));
      continue;
    }
    const {response, body} = fetched;
    if (path === "/") rootResponse = response;
    const isPrivate = PRIVATE_PAGES.includes(path);
    results.push(checkHeaders(path, response, isPrivate));
    results.push(checkThirdPartyContent(path, body, origin));
    if (!isPrivate) results.push(checkNoCookieOnPublicPage(path, response));
  }

  if (allowPartnerCookieCheck) {
    results.push(...(await checkPartnerCookie(origin, timeoutMs)));
  } else {
    results.push(skip("cookies:partner-check", "cookies", "opt-in referral-cookie probe was not requested"));
  }

  results.push(...(await checkSignedFiles(origin, {timeoutMs, now, verifySignatures, expectedFingerprint, trustedKeyPath, trustedKeyText})));
  results.push(await checkSecurityTxt(origin, timeoutMs, now));

  if (rootResponse) {
    results.push(checkServerHeader(rootResponse));
  } else {
    results.push(networkErrorResult("server-header", "server-header", "the \"/\" page could not be fetched, so its server header could not be read"));
  }

  return {generatedAt: new Date().toISOString(), baseUrl: origin, summary: summarizeResults(results), results};
}

export function summarizeResults(results) {
  const failed = results.filter((result) => result.pass === false).length;
  const incomplete = results.filter((result) => result.pass === null).length;
  return {status: failed ? "fail" : incomplete ? "incomplete" : "pass", passed: results.filter((result) => result.pass === true).length, failed, incomplete};
}

function parseArgs(argv) {
  const args = {base: null, json: false, allowPartnerCookieCheck: false, verifySignatures: true, timeoutMs: undefined, trustedKeyPath: undefined};
  const seen = new Set();
  const valueFor = (i) => {
    if (!argv[i + 1] || argv[i + 1].startsWith("--")) throw new Error(`missing value for ${argv[i]}`);
    return argv[i + 1];
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (seen.has(arg)) throw new Error(`duplicate option: ${arg}`);
    seen.add(arg);
    if (arg === "--base") { args.base = valueFor(i); i++; }
    else if (arg === "--json") args.json = true;
    else if (arg === "--partner-check") args.allowPartnerCookieCheck = true;
    else if (arg === "--no-partner-check") args.allowPartnerCookieCheck = false;
    else if (arg === "--no-verify-signatures") args.verifySignatures = false;
    else if (arg === "--timeout-ms") { args.timeoutMs = validateTimeout(Number(valueFor(i))); i++; }
    else if (arg === "--trusted-key-path") { args.trustedKeyPath = valueFor(i); i++; }
    else if (arg === "--help" || arg === "-h") args.help = true;
    else throw new Error(`unknown option: ${safeReason(arg)}`);
  }
  if (seen.has("--partner-check") && seen.has("--no-partner-check")) throw new Error("conflicting partner-check flags");
  return args;
}

function statusWord(result) {
  if (result.skipped) return "SKIP";
  if (result.warning) return "WARN";
  if (result.pass === false && result.networkError) return "NETERR";
  return result.pass ? "PASS" : "FAIL";
}

function printText(run) {
  for (const result of run.results) console.log(`[${statusWord(result)}] ${result.id} - ${result.reason}`);
  const counts = {PASS: 0, FAIL: 0, WARN: 0, SKIP: 0, NETERR: 0};
  for (const result of run.results) counts[statusWord(result)] += 1;
  console.log("");
  console.log(`${counts.PASS} passed, ${counts.FAIL} failed, ${counts.NETERR} network errors, ${counts.WARN} warned, ${counts.SKIP} skipped. Base: ${run.baseUrl}`);
  console.log(`Result: ${run.summary.status.toUpperCase()}`);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help || !args.base) {
    console.log(
      "Usage: node src/privacy-check.mjs --base <origin> [--json] [--partner-check] [--no-verify-signatures] [--timeout-ms <1..60000>] [--trusted-key-path <path>]\nExit: 0 full pass; 1 failed checks; 2 invalid input; 3 incomplete (skipped checks).",
    );
    process.exit(args.help ? 0 : 2);
  }
  const run = await runPrivacyChecks(args.base, {
    allowPartnerCookieCheck: args.allowPartnerCookieCheck,
    verifySignatures: args.verifySignatures,
    ...(args.timeoutMs ? {timeoutMs: args.timeoutMs} : {}),
    ...(args.trustedKeyPath ? {trustedKeyPath: args.trustedKeyPath} : {}),
  });
  if (args.json) console.log(JSON.stringify(run, null, 2));
  else printText(run);
  process.exit(run.summary.status === "fail" ? 1 : run.summary.status === "incomplete" ? 3 : 0);
}

let isMain = false;
try {
  isMain = Boolean(process.argv[1]) && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
} catch {
  isMain = false;
}

if (isMain) {
  main().catch((error) => {
    console.error(`privacy-check failed: ${safeReason(error.message)}`);
    process.exit(2);
  });
}
