// Pure helpers for the WebSockets view: what a captured frame looks like
// in a list, and which frames a filter keeps. Frames come from
// interception/websocket-interceptor.js ({direction, time, opcode, data}),
// where CDP reports a text frame's payload as-is and a binary frame's
// (opcode 2) as base64.
import { tryParseJson } from "./json.js";

const OPCODES = { 0: "continuation", 1: "text", 2: "binary", 8: "close", 9: "ping", 10: "pong" };

export function opcodeName(opcode) {
  return OPCODES[opcode] || (opcode == null ? "unknown" : `opcode ${opcode}`);
}

/** {kind, preview, isJson} for one frame — preview is one line, capped at `max` chars. */
export function describeFrame(frame, max = 160) {
  const kind = opcodeName(frame.opcode);
  const data = frame.data ?? "";
  if (frame.opcode === 2) return { kind, preview: `[binary, ${data.length} base64 chars]`, isJson: false };
  const oneLine = data.replace(/\s+/g, " ").trim();
  return {
    kind,
    preview: oneLine.length > max ? `${oneLine.slice(0, max)}…` : oneLine,
    isJson: frame.opcode === 1 && tryParseJson(data).ok,
  };
}

/** Frames matching `direction` ("all" | "sent" | "received") and a case-insensitive substring `query`. */
export function filterFrames(frames, { direction = "all", query = "" } = {}) {
  const q = query.trim().toLowerCase();
  return frames.filter((f) => (direction === "all" || f.direction === direction) && (!q || (f.data ?? "").toLowerCase().includes(q)));
}
