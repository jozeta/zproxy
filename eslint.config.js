// ESLint flat config (app standards QA-LINT-1). no-unsanitized flags innerHTML/outerHTML/
// insertAdjacentHTML/document.write with unsanitized data (SEC-DOM-2); no-eval and friends back up
// SEC-EVAL-1.
import js from "@eslint/js";
import globals from "globals";
import nounsanitized from "eslint-plugin-no-unsanitized";

export default [
  { ignores: ["vendor/**", "node_modules/**", "dist/**", "build/**", "coverage/**", "**/*.min.js"] },
  js.configs.recommended,
  nounsanitized.configs.recommended,
  {
    languageOptions: {
      ecmaVersion: 2024,
      sourceType: "module",
      globals: { ...globals.browser, ...globals.webextensions },
    },
    rules: {
      "no-eval": "error", "no-implied-eval": "error", "no-new-func": "error",
      "no-unused-vars": ["error", { argsIgnorePattern: "^_", varsIgnorePattern: "^_", caughtErrors: "none" }],
    },
  },
  {
    // Parsers match binary content on purpose.
    files: ["src/parsers/**"],
    rules: { "no-control-regex": "off" },
  },
  {
    files: ["**/*.mjs", "eslint.config.js"],
    languageOptions: { sourceType: "module" },
  },
  {
    files: ["**/*.test.*", "tests/**", "test/**", "examples/**", "scripts/**", "**/*.cjs", "*.config.*"],
    languageOptions: { globals: { ...globals.node } },
  },
];
