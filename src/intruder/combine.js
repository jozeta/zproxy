// Pure, DOM-free implementation of Burp Intruder's four attack types. Each
// combine*() is a generator yielding one "tuple" per attack request — an
// array the same length as the position count, tuple[i] being the payload
// string to substitute at position i (or null, meaning "leave this position
// at its original/base value" — only ever produced by Sniper). Generators,
// not materialized arrays, so Cluster bomb's Cartesian product never has to
// hold more than one tuple in memory at a time regardless of how large the
// attack is.
export const ATTACK_TYPES = [
  {
    id: "sniper",
    label: "Sniper",
    description:
      "One payload set. Attacks each position in turn, one at a time, while every other position stays at its original value. Total requests = positions × payloads.",
  },
  {
    id: "batteringRam",
    label: "Battering ram",
    description:
      "One payload set. Puts the SAME payload into every position at once, each iteration. Useful when the same value (e.g. a username) appears more than once in a request. Total requests = payloads.",
  },
  {
    id: "pitchfork",
    label: "Pitchfork",
    description:
      "One payload set per position, stepped through in lockstep (position 1 gets set 1's Nth payload, position 2 gets set 2's Nth payload, ...). Useful for testing known username/password pairs. Total requests = length of the shortest set.",
  },
  {
    id: "clusterBomb",
    label: "Cluster bomb",
    description:
      "One payload set per position, every combination of all sets (Cartesian product). Useful for an unknown username × password combination. Total requests = product of every set's length — can get very large.",
  },
];

export function* combineSniper(payloads, positionCount) {
  for (let posIdx = 0; posIdx < positionCount; posIdx++) {
    for (const payload of payloads) {
      const tuple = new Array(positionCount).fill(null);
      tuple[posIdx] = payload;
      yield tuple;
    }
  }
}

export function* combineBatteringRam(payloads, positionCount) {
  for (const payload of payloads) {
    yield new Array(positionCount).fill(payload);
  }
}

export function* combinePitchfork(payloadSets) {
  if (payloadSets.length === 0) return;
  const n = Math.min(...payloadSets.map((s) => s.length));
  for (let i = 0; i < n; i++) yield payloadSets.map((s) => s[i]);
}

export function* combineClusterBomb(payloadSets) {
  if (payloadSets.length === 0) return;
  const lengths = payloadSets.map((s) => s.length);
  if (lengths.some((l) => l === 0)) return;
  const total = lengths.reduce((a, b) => a * b, 1);
  const idx = new Array(payloadSets.length).fill(0);
  for (let n = 0; n < total; n++) {
    yield payloadSets.map((s, i) => s[idx[i]]);
    for (let i = payloadSets.length - 1; i >= 0; i--) {
      idx[i]++;
      if (idx[i] < lengths[i]) break;
      idx[i] = 0;
    }
  }
}

/** Uniform entry point: `payloadSets` is always an array of arrays, one per position — Sniper/Battering ram only ever read payloadSets[0] (Burp's UI only ever shows one payload-set tab for those two types, regardless of how many positions exist). */
export function combine(attackType, payloadSets, positionCount) {
  switch (attackType) {
    case "sniper":
      return combineSniper(payloadSets[0] || [], positionCount);
    case "batteringRam":
      return combineBatteringRam(payloadSets[0] || [], positionCount);
    case "pitchfork":
      return combinePitchfork(payloadSets.slice(0, positionCount));
    case "clusterBomb":
      return combineClusterBomb(payloadSets.slice(0, positionCount));
    default:
      return [][Symbol.iterator]();
  }
}

/** Cheap total-request-count calculation, matching combine()'s semantics, without running the generator — used for the pre-attack "this will send N requests" warning. */
export function totalRequestCount(attackType, positionCount, payloadSetLengths) {
  const lengths = payloadSetLengths.slice(0, positionCount);
  switch (attackType) {
    case "sniper":
      return positionCount * (lengths[0] || 0);
    case "batteringRam":
      return lengths[0] || 0;
    case "pitchfork":
      return lengths.length === 0 ? 0 : Math.min(...lengths);
    case "clusterBomb":
      return lengths.length === 0 ? 0 : lengths.reduce((a, b) => a * b, 1);
    default:
      return 0;
  }
}
