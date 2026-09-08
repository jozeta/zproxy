// Word-level diff behind the Comparer view. Classic LCS dynamic programming
// over whitespace-delimited tokens (whitespace runs are kept as their own
// tokens, so highlighting reads naturally for HTTP text — headers, JSON,
// raw request/response text). The DP table is O(n*m) in both time and
// space, so a large-enough input falls back to a plain two-block
// removed/added result instead of either hanging the UI thread or crashing
// on an out-of-memory typed array — see MAX_DIFF_TOKENS.
export const MAX_DIFF_TOKENS = 3000;

export function tokenize(text) {
  return (text || "").match(/\s+|\S+/g) || [];
}

/**
 * Returns {segments, truncated}. `segments` is an ordered list of
 * {type: "equal" | "removed" | "added", text} runs — "removed" is text only
 * in `a`, "added" only in `b`, reconstructing `a` from equal+removed and `b`
 * from equal+added. `truncated` is true when either side exceeds
 * MAX_DIFF_TOKENS tokens, in which case `segments` is just [{removed: all
 * of a}, {added: all of b}] rather than a real per-word diff.
 */
export function diffText(a, b) {
  const tokensA = tokenize(a);
  const tokensB = tokenize(b);
  if (tokensA.length > MAX_DIFF_TOKENS || tokensB.length > MAX_DIFF_TOKENS) {
    const segments = [];
    if (tokensA.length) segments.push({ type: "removed", text: tokensA.join("") });
    if (tokensB.length) segments.push({ type: "added", text: tokensB.join("") });
    return { segments, truncated: true };
  }

  const n = tokensA.length;
  const m = tokensB.length;
  const dp = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      dp[i][j] = tokensA[i] === tokensB[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }

  const segments = [];
  function push(type, text) {
    const last = segments[segments.length - 1];
    if (last && last.type === type) last.text += text;
    else segments.push({ type, text });
  }
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (tokensA[i] === tokensB[j]) {
      push("equal", tokensA[i]);
      i++;
      j++;
    } else if (dp[i + 1][j] >= dp[i][j + 1]) {
      push("removed", tokensA[i]);
      i++;
    } else {
      push("added", tokensB[j]);
      j++;
    }
  }
  while (i < n) {
    push("removed", tokensA[i]);
    i++;
  }
  while (j < m) {
    push("added", tokensB[j]);
    j++;
  }
  return { segments, truncated: false };
}
