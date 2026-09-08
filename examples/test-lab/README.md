# ZProxy test lab

A tiny, dependency-free local app for practicing the ZProxy workflow (Scope → Intercept → browse → edit → forward) without pointing ZProxy at a real site. Requires Node.js (18+) to run — this is the only place in the project that does, since the extension itself has no build step or dependencies.

## Run it

```
node examples/test-lab/server.js
```

Then open http://localhost:8787/ in Chrome.

## Set up ZProxy

1. Open the ZProxy side panel, go to **Scope**, enable it, and add `localhost` (and/or `127.0.0.1`) to Include.
2. Click **Intercept** in the header to attach it to the tab you have the test lab open in (this requests the `debugger` and host-access permissions the first time).
3. Browse the test lab and use each of its four buttons — see what shows up in **History** and, with pausing on, in **Intercept**.

## Things to try

- **Log in**, then inspect the `Set-Cookie` response header in History/Intercept, and check it against the **Cookies** view.
- **Get profile** sends `Authorization: Bearer <token>` — open the request in the inspector's **JWT** tab to see it decoded (never verified — the lab issues intentionally unsigned tokens for exactly this reason).
- **Feature flags** returns `{"featureXEnabled": false, ...}`. Import `examples/match-replace-rules/toggle-feature-flag.content.json` in **Match & Replace**, re-fetch with Intercept attached, and watch the response body change before it reaches the page.
- **Echo headers**: with a paused request in **Intercept**, edit/add a header and Forward — the response will echo back exactly what the server received, so you can confirm your edit actually reached the wire.
- Send any of these requests to **Repeater** and resend with tweaks without re-clicking through the page.

Everything here runs on `localhost` and does no real authentication — it exists purely so you have a safe, local, authorized target.
