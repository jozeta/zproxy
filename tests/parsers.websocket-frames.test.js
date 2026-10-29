import { test } from "node:test";
import assert from "node:assert/strict";
import { opcodeName, describeFrame, filterFrames } from "../src/parsers/websocket-frames.js";

test("opcodeName names the standard opcodes and degrades gracefully", () => {
  assert.equal(opcodeName(1), "text");
  assert.equal(opcodeName(2), "binary");
  assert.equal(opcodeName(9), "ping");
  assert.equal(opcodeName(7), "opcode 7");
  assert.equal(opcodeName(undefined), "unknown");
});

test("describeFrame collapses whitespace, caps the preview, and detects JSON text frames", () => {
  const d = describeFrame({ opcode: 1, data: '{\n  "type": "chat",\n  "msg": "hi"\n}' });
  assert.equal(d.preview, '{ "type": "chat", "msg": "hi" }');
  assert.equal(d.isJson, true);
  assert.equal(describeFrame({ opcode: 1, data: "x".repeat(300) }, 10).preview, `${"x".repeat(10)}…`);
  assert.equal(describeFrame({ opcode: 1, data: "not json" }).isJson, false);
});

test("describeFrame never renders a binary frame's base64 as if it were text", () => {
  const d = describeFrame({ opcode: 2, data: "AAEC" });
  assert.equal(d.preview, "[binary, 4 base64 chars]");
  assert.equal(d.isJson, false);
});

test("filterFrames filters by direction and case-insensitive payload substring", () => {
  const frames = [
    { direction: "sent", opcode: 1, data: "PING" },
    { direction: "received", opcode: 1, data: "pong" },
    { direction: "received", opcode: 1, data: "balance=100" },
  ];
  assert.equal(filterFrames(frames).length, 3);
  assert.deepEqual(filterFrames(frames, { direction: "received" }).map((f) => f.data), ["pong", "balance=100"]);
  assert.deepEqual(filterFrames(frames, { query: "  ping " }).map((f) => f.data), ["PING"]);
  assert.deepEqual(filterFrames(frames, { direction: "sent", query: "pong" }), []);
});
