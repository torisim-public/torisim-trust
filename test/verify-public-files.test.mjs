import test from "node:test";
import assert from "node:assert/strict";
import {mkdtempSync, cpSync, rmSync, readFileSync, writeFileSync, symlinkSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {fileURLToPath} from "node:url";
import {createHash} from "node:crypto";
import {spawnSync} from "node:child_process";
import {verifyPublicFiles} from "../src/verify-public-files.mjs";

const source = fileURLToPath(new URL("../public/", import.meta.url));
const now = new Date("2026-10-18T23:00:00Z");
const hasGpg = ["gpgv", "gpg"].some((command) => spawnSync(command, ["--version"], {timeout: 2000}).status === 0);

function fixture(t) {
  const directory = mkdtempSync(join(tmpdir(), "torisim-public-files-test-"));
  cpSync(source, directory, {recursive: true});
  t.after(() => rmSync(directory, {recursive: true, force: true}));
  return directory;
}
function editManifest(directory, edit) {
  const path = join(directory, "manifest.json");
  const manifest = JSON.parse(readFileSync(path, "utf8"));
  edit(manifest);
  writeFileSync(path, JSON.stringify(manifest));
}
function rewrite(directory, name, content, rehash = true) {
  const bytes = Buffer.from(content);
  writeFileSync(join(directory, name), bytes);
  if (rehash) editManifest(directory, (m) => {
    const row = m.files.find((r) => r.path === `public/${name}`);
    row.bytes = bytes.length;
    row.sha256 = createHash("sha256").update(bytes).digest("hex");
  });
}

test("bundled historical snapshots verify offline at the review date", {skip: !hasGpg}, async () => {
  const result = await verifyPublicFiles({now});
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.ok(result.results.some((r) => r.id === "signature:canary.txt" && r.pass));
  assert.ok(result.results.some((r) => r.id === "signature:mirrors.txt" && r.pass));
});
test("a changed snapshot fails its hash check", async (t) => {
  const directory = fixture(t);
  rewrite(directory, "canary.txt", "changed", false);
  const result = await verifyPublicFiles({directory, now});
  assert.equal(result.ok, false);
  assert.ok(result.results.some((r) => r.id === "manifest:canary.txt" && !r.pass));
});
test("rewriting the unsigned manifest cannot authenticate a changed canary", {skip: !hasGpg}, async (t) => {
  const directory = fixture(t);
  const original = readFileSync(join(directory, "canary.txt"), "utf8");
  rewrite(directory, "canary.txt", original.replace("Date: 2026-10-05", "Date: 2026-10-06"));
  const result = await verifyPublicFiles({directory, now});
  assert.equal(result.ok, false);
  assert.ok(result.results.some((r) => r.id === "signature:canary.txt" && !r.pass));
});
test("a second public key is rejected even after rehashing", async (t) => {
  const directory = fixture(t);
  const key = readFileSync(join(directory, "pgp.txt"), "utf8");
  rewrite(directory, "pgp.txt", key + key);
  const result = await verifyPublicFiles({directory, now});
  assert.equal(result.ok, false);
  assert.ok(result.results.some((r) => r.id === "key" && !r.pass));
});
test("manifest paths cannot escape the fixed public file inventory", async (t) => {
  const directory = fixture(t);
  editManifest(directory, (m) => { m.files[0].path = "public/../../private.txt"; });
  assert.equal((await verifyPublicFiles({directory, now})).ok, false);
});
test("duplicate manifest entries cannot replace a missing entry", async (t) => {
  const directory = fixture(t);
  editManifest(directory, (m) => { m.files[1] = m.files[0]; });
  assert.equal((await verifyPublicFiles({directory, now})).ok, false);
});
test("a null manifest returns a failed report", async (t) => {
  const directory = fixture(t);
  writeFileSync(join(directory, "manifest.json"), "null");
  assert.equal((await verifyPublicFiles({directory, now})).ok, false);
});
test("a renamed source URL is rejected", async (t) => {
  const directory = fixture(t);
  editManifest(directory, (m) => { m.files[0].source = "https://untrusted.invalid/pgp.txt"; });
  assert.equal((await verifyPublicFiles({directory, now})).ok, false);
});
test("extra files fail the public inventory check", async (t) => {
  const directory = fixture(t);
  writeFileSync(join(directory, "unexpected.txt"), "synthetic");
  assert.equal((await verifyPublicFiles({directory, now})).ok, false);
});
test("a public file cannot be a symlink", {skip: process.platform === "win32"}, async (t) => {
  const directory = fixture(t);
  rmSync(join(directory, "pgp.txt"));
  symlinkSync(join(source, "pgp.txt"), join(directory, "pgp.txt"));
  assert.equal((await verifyPublicFiles({directory, now})).ok, false);
});
test("oversized local files are rejected before signature parsing", async (t) => {
  const directory = fixture(t);
  rewrite(directory, "canary.txt", Buffer.alloc(128 * 1024 + 1));
  assert.equal((await verifyPublicFiles({directory, now})).ok, false);
});
test("expired historical canary fails even with valid signatures", {skip: !hasGpg}, async () => {
  const result = await verifyPublicFiles({now: new Date("2026-11-05T00:00:00Z")});
  assert.equal(result.ok, false);
  assert.ok(result.results.some((r) => r.id === "signature:canary.txt" && r.pass));
  assert.ok(result.results.some((r) => r.id === "signed:canary:next-canary-not-passed" && !r.pass));
});
test("missing or invalid clock cannot produce a verified result", async () => {
  assert.equal((await verifyPublicFiles({now: new Date("invalid")})).ok, false);
  assert.equal((await verifyPublicFiles({now: new Date("2026-10-17T00:00:00Z")})).ok, false);
});
test("expired unsigned contact file is reported independently", {skip: !hasGpg}, async (t) => {
  const directory = fixture(t);
  const text = readFileSync(join(directory, "security.txt"), "utf8");
  rewrite(directory, "security.txt", text.replace("2027-09-28T00:00:00Z", "2026-10-17T00:00:00Z"));
  const result = await verifyPublicFiles({directory, now});
  assert.equal(result.ok, false);
  assert.ok(result.results.some((r) => r.id === "security:expiry" && !r.pass));
});
test("invoking the CLI through a symlink runs verification instead of silently succeeding", {skip: process.platform === "win32"}, (t) => {
  const directory = mkdtempSync(join(tmpdir(), "torisim-verifier-cli-test-"));
  t.after(() => rmSync(directory, {recursive: true, force: true}));
  const cli = join(directory, "verify.mjs");
  symlinkSync(fileURLToPath(new URL("../src/verify-public-files.mjs", import.meta.url)), cli);
  const run = spawnSync(process.execPath, [cli, "--json"], {encoding: "utf8", timeout: 10000});
  assert.equal(run.error, undefined);
  assert.ok([0, 1].includes(run.status));
  const result = JSON.parse(run.stdout);
  assert.ok(result.results.length > 0);
  assert.equal(run.status === 0, result.ok);
});
