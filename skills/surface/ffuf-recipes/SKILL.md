---
name: ffuf-recipes
description: Common ffuf invocations for directory busting, parameter discovery, and Host-header fuzzing.
allowed-tools: [surface__ffuf]
---

# ffuf recipes

## Directory busting

```
ffuf -u http://target/FUZZ -w common.txt -e .php,.html,.txt -mc 200,204,301,302,307,401,403
```

Match more statuses than 200 — `401` and `403` often hide auth-walled juice.

## Parameter discovery

```
ffuf -u http://target/page?FUZZ=test -w params.txt -fc 404 -fs 0
```

Find hidden GET params on a page that already exists. Use `-fc` to filter the
typical 404, and `-fs 0` to drop empty responses.

## Faster on local labs, slower on real engagements

- CTF mode: `-t 40` is fine
- Engagement mode: `-t 5 -p 0.5` (5 threads, 0.5s pause) to be quiet-ish

## When ffuf misses things

- Stop after two sensible ffuf attempts per web root. Repeating larger or
  near-duplicate wordlists after empty results is usually wasted time.
- Heavy WAF → switch to slow + jitter, or browser-driven enumeration
- SPA → the routes are JS, not paths. Use `browser__read_dom` + a JS-aware
  parse to find route registrations
- If a wordlist is missing, use the installed fallback (`dirb/common.txt`) once
  or pivot. Do not keep guessing wordlist paths.
