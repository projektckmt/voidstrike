---
name: injection-probing
description: How to probe for SQLi, command-injection, SSRF, and template injection at *signal* level (not exploitation).
allowed-tools: [browser__goto, browser__fill_form, browser__submit, browser__read_dom]
---

# Injection probing — signal, not exploitation

Surface's job is to characterize. You probe for injection at signal-level —
"this parameter behaves weirdly when I send a quote" — and pass the candidate
to Exploit. You do **not** dump databases here.

## SQL injection signal probes

For each form field / GET parameter on the target, submit:

1. `'` — break the quote. Watch for SQL errors, 500 status, or odd content shift.
2. `' OR 1=1 -- ` — observe whether the response changes shape.
3. `<param>--` (numeric variant for numeric params).

Record in `WebSurface.suspected_vulns` as:
`SQLi candidate: param=<name> at <url> — error on single quote`

## Command injection signal probes

For forms that look like they shell out (lookup tools, ping utilities, etc.):

1. `; sleep 5`
2. `| whoami`
3. ``` `id` ``` (backticks)

Time-based is the cleanest signal — a 5s delay vs. <1s is unambiguous.

## SSRF signal probes

For any field that takes a URL:

1. `http://localhost/`
2. `http://169.254.169.254/` (cloud metadata)
3. `file:///etc/passwd`

Look for *anything* coming back that wasn't the original target.

## Template injection

Submit `{{7*7}}` and `${7*7}`. If the response contains `49`, that's confirmed
template injection. Note which template syntax — different engines, different
exploit shapes.

## What you do not do

- Do not run sqlmap. That's an exploitation step.
- Do not chain probes into a full exfil. Note the signal and move on.
- Do not submit destructive payloads (`DROP`, `RM`, `DELETE`) even in CTF mode.
  Use read-only probes.
