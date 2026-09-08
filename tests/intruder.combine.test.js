import { test } from "node:test";
import assert from "node:assert/strict";
import { combine, totalRequestCount, ATTACK_TYPES } from "../src/intruder/combine.js";

function collect(iter) {
  return [...iter];
}

test("ATTACK_TYPES exposes exactly the four Burp Intruder attack types", () => {
  assert.deepEqual(
    ATTACK_TYPES.map((t) => t.id),
    ["sniper", "batteringRam", "pitchfork", "clusterBomb"]
  );
  for (const t of ATTACK_TYPES) assert.ok(t.label && t.description);
});

test("sniper: attacks each position in turn, leaving the others null (original value)", () => {
  const tuples = collect(combine("sniper", [["A", "B"]], 2));
  assert.deepEqual(tuples, [
    ["A", null],
    ["B", null],
    [null, "A"],
    [null, "B"],
  ]);
  assert.equal(totalRequestCount("sniper", 2, [2]), 4);
});

test("battering ram: the same payload lands in every position at once", () => {
  const tuples = collect(combine("batteringRam", [["A", "B"]], 3));
  assert.deepEqual(tuples, [
    ["A", "A", "A"],
    ["B", "B", "B"],
  ]);
  assert.equal(totalRequestCount("batteringRam", 3, [2]), 2);
});

test("pitchfork: sets are stepped through in lockstep, stopping at the shortest set", () => {
  const tuples = collect(combine("pitchfork", [["u1", "u2", "u3"], ["p1", "p2"]], 2));
  assert.deepEqual(tuples, [
    ["u1", "p1"],
    ["u2", "p2"],
  ]);
  assert.equal(totalRequestCount("pitchfork", 2, [3, 2]), 2);
});

test("cluster bomb: every combination across all sets (Cartesian product)", () => {
  const tuples = collect(combine("clusterBomb", [["u1", "u2"], ["p1", "p2", "p3"]], 2));
  assert.deepEqual(tuples, [
    ["u1", "p1"],
    ["u1", "p2"],
    ["u1", "p3"],
    ["u2", "p1"],
    ["u2", "p2"],
    ["u2", "p3"],
  ]);
  assert.equal(totalRequestCount("clusterBomb", 2, [2, 3]), 6);
});

test("cluster bomb yields nothing if any position's set is empty", () => {
  assert.deepEqual(collect(combine("clusterBomb", [["u1"], []], 2)), []);
});

test("pitchfork with three positions steps all three sets together", () => {
  const tuples = collect(combine("pitchfork", [["a1", "a2"], ["b1", "b2"], ["c1", "c2"]], 3));
  assert.deepEqual(tuples, [
    ["a1", "b1", "c1"],
    ["a2", "b2", "c2"],
  ]);
});

test("totalRequestCount returns 0 for an unknown attack type instead of throwing", () => {
  assert.equal(totalRequestCount("bogus", 2, [2, 2]), 0);
});
