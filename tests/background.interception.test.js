import { test } from "node:test";
import assert from "node:assert/strict";
import { buildFetchPatterns } from "../src/background/interception.js";

test("buildFetchPatterns registers both stages for 'both'", () => {
  assert.deepEqual(buildFetchPatterns("both"), [
    { urlPattern: "*", requestStage: "Request" },
    { urlPattern: "*", requestStage: "Response" },
  ]);
});

test("buildFetchPatterns registers only the Request stage for 'request'", () => {
  assert.deepEqual(buildFetchPatterns("request"), [{ urlPattern: "*", requestStage: "Request" }]);
});

test("buildFetchPatterns registers only the Response stage for 'response'", () => {
  assert.deepEqual(buildFetchPatterns("response"), [{ urlPattern: "*", requestStage: "Response" }]);
});

test("buildFetchPatterns defaults to both stages for an unrecognized value", () => {
  // Fail open to the existing/documented default rather than silently
  // pausing nothing if settings storage ever holds a stale/invalid value.
  assert.deepEqual(buildFetchPatterns(undefined), [
    { urlPattern: "*", requestStage: "Request" },
    { urlPattern: "*", requestStage: "Response" },
  ]);
});

test("buildFetchPatterns with no excluded types still uses the single catch-all pattern per stage", () => {
  assert.deepEqual(buildFetchPatterns("both", []), [
    { urlPattern: "*", requestStage: "Request" },
    { urlPattern: "*", requestStage: "Response" },
  ]);
});

test("buildFetchPatterns excludes CSS/images by enumerating every other resource type explicitly", () => {
  // Fetch.enable's patterns are an allow-list, not a block-list — there is
  // no way to say "everything except Stylesheet/Image" other than listing
  // every remaining type.
  const patterns = buildFetchPatterns("request", ["Stylesheet", "Image"]);
  const types = patterns.map((p) => p.resourceType);
  assert.ok(types.includes("Document"));
  assert.ok(types.includes("Script"));
  assert.ok(types.includes("XHR"));
  assert.ok(!types.includes("Stylesheet"));
  assert.ok(!types.includes("Image"));
  assert.ok(patterns.every((p) => p.requestStage === "Request" && p.urlPattern === "*"));
});

test("buildFetchPatterns combines stage and resource-type exclusion — one pattern per (stage, included type)", () => {
  const patterns = buildFetchPatterns("both", ["Font"]);
  const requestPatterns = patterns.filter((p) => p.requestStage === "Request");
  const responsePatterns = patterns.filter((p) => p.requestStage === "Response");
  assert.equal(requestPatterns.length, responsePatterns.length);
  assert.ok(!patterns.some((p) => p.resourceType === "Font"));
  assert.ok(patterns.some((p) => p.resourceType === "Document" && p.requestStage === "Request"));
  assert.ok(patterns.some((p) => p.resourceType === "Document" && p.requestStage === "Response"));
});

test("buildFetchPatterns excludes every resource type it knows about and still returns a valid (empty) patterns array, never throwing", () => {
  // Regression: Fetch.RequestPattern.resourceType only recognizes 12
  // strings, confirmed at runtime ({"code":-32602,"message":"Unknown
  // resource type in fetch filter: 'TextTrack'"}) — NOT the full
  // Network.ResourceType enum from the protocol docs. This list must never
  // grow back to include TextTrack/Preflight/WebSocket/Manifest/
  // SignedExchange/FedCM, which Chrome's Fetch domain rejects outright.
  const patterns = buildFetchPatterns("both", [
    "Document",
    "Stylesheet",
    "Image",
    "Media",
    "Font",
    "Script",
    "XHR",
    "Fetch",
    "EventSource",
    "CSPViolationReport",
    "Ping",
    "Other",
  ]);
  assert.deepEqual(patterns, []);
});

test("buildFetchPatterns never includes a resource type Chrome's Fetch domain rejects", () => {
  const rejected = ["TextTrack", "Preflight", "WebSocket", "Manifest", "SignedExchange", "FedCM"];
  // Any single exclusion forces the "enumerate every other known type"
  // path (the no-exclusion case uses a plain "*" pattern with no
  // resourceType field at all, so it wouldn't exercise this).
  const patterns = buildFetchPatterns("both", ["Other"]);
  for (const bad of rejected) {
    assert.ok(!patterns.some((p) => p.resourceType === bad));
  }
});
