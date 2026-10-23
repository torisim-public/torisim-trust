import {constants, openSync, closeSync, fstatSync, readSync, lstatSync, readdirSync, realpathSync} from "node:fs";
import {createHash} from "node:crypto";
import {dirname, join} from "node:path";
import {fileURLToPath} from "node:url";
import {
  EXPECTED_KEY_FINGERPRINT, dearmorPublicKey, computeFingerprintV4,
  countPrimaryKeyPackets, verifyClearsignedText, checkCanaryDates,
} from "./privacy-check.mjs";

const DEFAULT_DIRECTORY = join(dirname(fileURLToPath(import.meta.url)), "..", "public");
const MAX_FILE_BYTES = 128 * 1024;
const SOURCES = Object.freeze({
  "pgp.txt": "https://torisim.com/pgp.txt",
  "canary.txt": "https://torisim.com/canary.txt",
  "mirrors.txt": "https://torisim.com/mirrors.txt",
  "security.txt": "https://torisim.com/.well-known/security.txt",
});
const NAMES = Object.keys(SOURCES);

function boundedRead(path) {
  if (!lstatSync(path).isFile()) throw new Error("expected a regular file, without symbolic links");
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.size > MAX_FILE_BYTES) throw new Error("file exceeds the regular-file size limit");
    // Bound allocation even if a local file grows after fstat.
    const buffer = Buffer.alloc(MAX_FILE_BYTES + 1);
    let length = 0;
    while (length < buffer.length) {
      const count = readSync(fd, buffer, length, buffer.length - length, null);
      if (count === 0) break;
      length += count;
    }
    if (length > MAX_FILE_BYTES) throw new Error("file exceeds the size limit");
    return buffer.subarray(0, length);
  } finally { closeSync(fd); }
}

function isoTime(value) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(value)) return NaN;
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) return NaN;
  const normalized = value.replace(/(?:\.(\d{1,3}))?Z$/, (_, fraction = "") => `.${fraction.padEnd(3, "0")}Z`);
  return new Date(parsed).toISOString() === normalized ? parsed : NaN;
}

function oneField(text, name) {
  const matches = text.split(/\r?\n/).filter((line) => line.startsWith(`${name}:`));
  return matches.length === 1 ? matches[0].slice(name.length + 1).trim() : null;
}

export async function verifyPublicFiles({directory = DEFAULT_DIRECTORY, now = new Date()} = {}) {
  const results = [];
  const add = (id, pass, detail) => results.push({id, pass, detail});
  const nowMs = now instanceof Date ? now.getTime() : NaN;
  const report = () => ({checkedAt: Number.isFinite(nowMs) ? now.toISOString() : null, ok: results.every((r) => r.pass), results});
  if (!Number.isFinite(nowMs)) { add("clock", false, "A valid current clock is required."); return report(); }

  let manifest, files;
  try {
    if (!lstatSync(directory).isDirectory()) throw new Error("invalid directory");
    const inventory = readdirSync(directory).sort();
    const expected = [...NAMES, "manifest.json"].sort();
    if (JSON.stringify(inventory) !== JSON.stringify(expected)) throw new Error("unexpected inventory");
    manifest = JSON.parse(boundedRead(join(directory, "manifest.json")).toString("utf8"));
    files = Object.fromEntries(NAMES.map((name) => [name, boundedRead(join(directory, name))]));
  } catch {
    add("inventory", false, "Expected exactly four regular public files and manifest.json, each at most 128 KiB; a read, size or JSON check failed.");
    return report();
  }
  add("inventory", true, "Only the four expected public files and their manifest are present.");

  if (!manifest || typeof manifest !== "object" || manifest.schemaVersion !== 1 || !Array.isArray(manifest.files) || manifest.files.length !== NAMES.length) {
    add("manifest", false, "Unsupported manifest schema or file count."); return report();
  }
  const seen = new Set();
  for (const row of manifest.files) {
    const name = typeof row?.path === "string" && row.path.startsWith("public/") ? row.path.slice(7) : "";
    if (!NAMES.includes(name) || seen.has(name)) {
      add("manifest", false, "Manifest paths must name each expected file exactly once."); return report();
    }
    seen.add(name);
    const captured = isoTime(row.capturedAt);
    const metadataOK = row.source === SOURCES[name] && Number.isFinite(captured) && captured <= nowMs;
    const hash = createHash("sha256").update(files[name]).digest("hex");
    const integrityOK = Number.isSafeInteger(row.bytes) && row.bytes === files[name].length &&
      typeof row.sha256 === "string" && /^[a-f0-9]{64}$/.test(row.sha256) && row.sha256 === hash;
    add(`manifest:${name}`, metadataOK && integrityOK, metadataOK && integrityOK ?
      "Size and SHA-256 match the unsigned inventory; source and capture metadata are valid." :
      "File integrity or source/capture metadata does not match the expected inventory.");
  }
  if (results.some((r) => !r.pass)) return report();

  let key;
  try {
    key = dearmorPublicKey(files["pgp.txt"].toString("utf8"));
    if (countPrimaryKeyPackets(key) !== 1 || computeFingerprintV4(key) !== EXPECTED_KEY_FINGERPRINT) throw new Error("key mismatch");
    add("key", true, `One primary public key matches ${EXPECTED_KEY_FINGERPRINT}.`);
  } catch {
    add("key", false, "The public key does not match the pinned single-key trust anchor."); return report();
  }

  for (const name of ["canary.txt", "mirrors.txt"]) {
    const signature = await verifyClearsignedText(key, files[name].toString("utf8"));
    add(`signature:${name}`, signature.checked && signature.ok === true, signature.detail);
    if (name === "canary.txt" && signature.checked && signature.ok === true) {
      for (const result of checkCanaryDates(signature.plaintext, now)) add(result.id, result.pass === true, result.reason);
    }
  }
  const security = files["security.txt"].toString("utf8");
  const expiry = isoTime(oneField(security, "Expires"));
  const contactOK = oneField(security, "Contact") === "mailto:support@torisim.com" &&
    oneField(security, "Encryption") === SOURCES["pgp.txt"] &&
    oneField(security, "Canonical") === SOURCES["security.txt"] &&
    Boolean(oneField(security, "Preferred-Languages"));
  add("security:fields", contactOK, contactOK ? "Expected fields are present in the unsigned contact file." : "Unexpected, missing or duplicate contact fields.");
  add("security:expiry", Number.isFinite(expiry) && expiry > nowMs, Number.isFinite(expiry) && expiry > nowMs ?
    "The unsigned contact file has a valid future expiry." : "The unsigned contact file has expired or has an invalid expiry.");
  return report();
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length === 1 && args[0] === "--help") {
    console.log("Usage: node src/verify-public-files.mjs [--json]\nVerify bundled files offline. Exit 0: verified; 1: failed or unavailable; 2: invalid input.");
    return;
  }
  if (args.length > 1 || (args.length === 1 && args[0] !== "--json")) {
    console.error("Invalid arguments. Use --help."); process.exitCode = 2; return;
  }
  try {
    const result = await verifyPublicFiles();
    if (args[0] === "--json") console.log(JSON.stringify(result, null, 2));
    else {
      for (const row of result.results) console.log(`${row.pass ? "PASS" : "FAIL"} ${row.id}: ${row.detail}`);
      console.log(result.ok ? "Bundled files verified. Read docs/verification.md for the limits." : "Bundled files did not pass verification.");
    }
    process.exitCode = result.ok ? 0 : 1;
  } catch {
    console.error("Verification could not complete. Check local file and GnuPG availability.");
    process.exitCode = 1;
  }
}

let isMain = false;
try {
  isMain = Boolean(process.argv[1]) && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
} catch { isMain = false; }
if (isMain) await main();
