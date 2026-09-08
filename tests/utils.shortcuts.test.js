import { test } from "node:test";
import assert from "node:assert/strict";
import { parseShortcut, matchesShortcut } from "../src/utils/shortcuts.js";

test("parseShortcut returns null for empty or modifier-only strings", () => {
  assert.equal(parseShortcut(""), null);
  assert.equal(parseShortcut(undefined), null);
  assert.equal(parseShortcut("Ctrl+Shift"), null);
});

test("parseShortcut extracts modifiers and a lowercased key, order-independent", () => {
  assert.deepEqual(parseShortcut("Ctrl+Shift+F"), { ctrl: true, shift: true, alt: false, key: "f" });
  assert.deepEqual(parseShortcut("F"), { ctrl: false, shift: false, alt: false, key: "f" });
  assert.deepEqual(parseShortcut("Shift+Alt+Ctrl+K"), { ctrl: true, shift: true, alt: true, key: "k" });
});

test("parseShortcut treats Cmd/Command/Meta as Ctrl", () => {
  assert.deepEqual(parseShortcut("Cmd+K"), { ctrl: true, shift: false, alt: false, key: "k" });
});

test("matchesShortcut matches a real KeyboardEvent-shaped object exactly (modifiers and key)", () => {
  const event = { ctrlKey: true, shiftKey: false, altKey: false, key: "i" };
  assert.equal(matchesShortcut(event, "Ctrl+I"), true);
  assert.equal(matchesShortcut(event, "Ctrl+Shift+I"), false);
  assert.equal(matchesShortcut(event, "Ctrl+K"), false);
});

test("matchesShortcut treats metaKey (Cmd on macOS) as satisfying a Ctrl requirement", () => {
  const event = { ctrlKey: false, metaKey: true, shiftKey: false, altKey: false, key: "r" };
  assert.equal(matchesShortcut(event, "Ctrl+R"), true);
});

test("matchesShortcut requires no extra modifiers beyond what's configured", () => {
  const event = { ctrlKey: true, shiftKey: true, altKey: false, key: "f" };
  assert.equal(matchesShortcut(event, "Ctrl+F"), false);
});

test("matchesShortcut returns false for an unconfigured (empty) shortcut string", () => {
  assert.equal(matchesShortcut({ ctrlKey: true, key: "f" }, ""), false);
});
