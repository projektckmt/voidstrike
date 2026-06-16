---
name: web-tech-fingerprinting
description: Identifying the framework, server, and CMS behind a web service. When to follow up with vhost-enum or directory fuzzing.
allowed-tools: [surface__httpx_fingerprint, browser__goto, browser__read_dom, surface__ffuf]
---

# Web tech fingerprinting

## First pass: `httpx_fingerprint`

Pass the full list of `http://host:port/` candidates you have. Returns
status, title, server, detected tech stack, and TLS info per target.

Read carefully:

- `tech` list — Wappalyzer-style detection. `Drupal`, `WordPress`, `Tomcat` are
  highly actionable; `Bootstrap` is not.
- `title` — sometimes contains the app name and version (`phpMyAdmin 4.9.0`).
- `server` — Apache version, IIS version, nginx version. Same precision rule as nmap.

## Second pass: browser

If httpx returned a 200 with little detail, or the page is JS-heavy:

1. `browser__goto(engagement_id, url)` — let JS render
2. `browser__read_dom(engagement_id)` — grab the post-render HTML
3. Look for: `<meta name="generator">`, `<link>` to known CDN paths, footer
   "Powered by", login form action paths.

## Triggers for follow-up

- Multiple Host headers respond differently → `vhost-enum`
- Default-looking site → `ffuf` against common dictionary
- Generic CMS detected → search for that CMS in `exploit/searchsploit_lookup`

## Pitfalls

- WAFs lie about server headers. If the response says `cloudflare` ignore the
  server claim and fingerprint via behavior.
- `Server: nginx` with no version is usually nginx-as-reverse-proxy. The real
  backend is behind it — keep digging.
