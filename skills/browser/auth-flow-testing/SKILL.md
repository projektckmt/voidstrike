---
name: auth-flow-testing
description: Testing login/registration/2FA flows with Playwright. Catches business-logic flaws that fuzzers miss.
allowed-tools: [browser__goto, browser__fill_form, browser__submit, browser__get_cookies, browser__eval_js]
---

# Auth flow testing

This is what the browser MCP server is *for* — multi-step flows with cookies,
CSRF tokens, and conditional UI. `curl` is painful here; Playwright is trivial.

## The flow

1. `browser__goto(engagement_id, login_url)` — let JS render.
2. `browser__fill_form({"#email": "admin@example.com", "#password": "..."})`.
3. `browser__submit("#login-button")` — captures the navigation.
4. `browser__get_cookies(engagement_id)` — check what session cookies got set.

## Business-logic flaws to probe

| Probe | What you're checking |
|---|---|
| Submit login twice in parallel | race conditions on session creation |
| Tamper with the user-id in a post-login GET | IDOR — change `?user=1` to `?user=2` |
| Change password without sending current password | broken auth |
| Reset password to a known token then log in | poor token randomness, IDOR-on-reset |
| 2FA: submit step-1 success, skip step-2 by going directly to step-3 | broken state machine |
| Session-fixation: set a cookie before login, see if it persists | yes = fixation flaw |

## Capture evidence

Always `browser__screenshot` after each suspicious step. PNG goes into the
engagement working directory, gets attached to the eventual `Finding`.

## What to record

A confirmed auth flaw becomes a `Finding` with:

- The exact request sequence (in the description)
- The cookies/headers that show the flaw (in evidence)
- Severity: critical (auth bypass), high (account takeover), medium (info leak)
