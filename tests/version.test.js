// The version is defined once, in manifest.json (Settings and the side
// panel header read it at runtime). Everything else that states it must
// agree, so a release can't ship with a stale number anywhere.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const root = new URL("../", import.meta.url);
const read = (path) => readFile(new URL(path, root), "utf8");

test("manifest.json has a semantic version", async () => {
  const { version } = JSON.parse(await read("manifest.json"));
  assert.match(version, /^\d+\.\d+\.\d+$/);
});

test("package.json, the README, and the newest CHANGELOG entry all match manifest.json", async () => {
  const { version } = JSON.parse(await read("manifest.json"));
  assert.equal(JSON.parse(await read("package.json")).version, version, "package.json");
  assert.match(await read("README.md"), new RegExp(`\\*\\*Version ${version.replace(/\./g, "\\.")}\\*\\*`), "README.md version line");
  const newest = (await read("CHANGELOG.md")).match(/^## (\d+\.\d+\.\d+)/m)?.[1];
  assert.equal(newest, version, "CHANGELOG.md newest entry");
});
