import { test } from "node:test";
import assert from "node:assert/strict";

const store = {};
globalThis.chrome = {
  storage: {
    local: {
      get: async (key) => (key in store ? { [key]: store[key] } : {}),
      set: async (items) => Object.assign(store, items),
      remove: async (key) => delete store[key],
    },
  },
};

const { getSettings, updateSettings, resetSettings, SETTINGS_DEFAULTS } = await import("../src/storage/settings.js");

test("resetSettings restores the defaults by removing the stored copy, and reports what changed", async () => {
  await updateSettings({ interceptStage: "both", excludedResourceTypes: [], maxHistoryEntries: 5 });
  assert.equal("settings" in store, true);

  const { previous, next } = await resetSettings();
  assert.equal(previous.interceptStage, "both");
  assert.equal(next.interceptStage, SETTINGS_DEFAULTS.interceptStage);
  assert.deepEqual(next.excludedResourceTypes, SETTINGS_DEFAULTS.excludedResourceTypes);
  assert.equal(next.maxHistoryEntries, SETTINGS_DEFAULTS.maxHistoryEntries);
  // Removed, not overwritten with the defaults — so future default changes still apply.
  assert.equal("settings" in store, false);
  assert.deepEqual(await getSettings(), next);
});

test("the settings returned by a reset can be mutated without corrupting SETTINGS_DEFAULTS", async () => {
  const { next } = await resetSettings();
  next.excludedResourceTypes.push("Document");
  next.shortcuts.forward = "Ctrl+X";
  assert.equal(SETTINGS_DEFAULTS.excludedResourceTypes.includes("Document"), false);
  assert.equal(SETTINGS_DEFAULTS.shortcuts.forward, "Ctrl+Enter");
});
