// Regression guard for the core security invariant in docs/SECURITY.md:
// captured (untrusted) traffic must never be routed through an HTML/JS
// execution sink. This can't be a runtime/DOM test (no browser here), so
// instead it statically scans every shipped source file for the sinks that
// would defeat the sandboxed-iframe/textContent-only rendering approach.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SRC_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "src");

// Matched as plain substrings (not regex) so this can't itself become an
// injection vector, and so `.innerHTML =` and `.innerHTML=` are both caught.
const FORBIDDEN_SINKS = ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write(", "eval(", "new Function("];

async function listJsFiles(dir) {
  const entries = await readdir(dir, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) files.push(...(await listJsFiles(full)));
    else if (entry.name.endsWith(".js")) files.push(full);
  }
  return files;
}

function stripLineComments(source) {
  return source
    .split("\n")
    .map((line) => {
      const idx = line.indexOf("//");
      return idx === -1 ? line : line.slice(0, idx);
    })
    .join("\n");
}

test("no shipped source file contains an HTML/JS execution sink outside of comments", async () => {
  const files = await listJsFiles(SRC_DIR);
  assert.ok(files.length > 10, "sanity check: expected to find the source tree");

  const offenders = [];
  for (const file of files) {
    const code = stripLineComments(await readFile(file, "utf8"));
    for (const sink of FORBIDDEN_SINKS) {
      if (code.includes(sink)) offenders.push(`${path.relative(SRC_DIR, file)} contains "${sink}"`);
    }
  }
  assert.deepEqual(offenders, []);
});
