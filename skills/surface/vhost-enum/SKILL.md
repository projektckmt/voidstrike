---
name: vhost-enum
description: When and how to enumerate virtual hosts (Host-header fuzzing), tell vhost_enum apart from ffuf, and make a discovered vhost resolve via /etc/hosts.
allowed-tools: surface__vhost_enum surface__ffuf surface__add_hosts_entry surface__curl surface__httpx_fingerprint
---

# vhost enumeration

## ffuf vs vhost_enum — different tools, don't confuse them

- **`surface__ffuf`** fuzzes the URL *path* — its `url` MUST contain a `FUZZ`
  placeholder (`http://host/FUZZ`). Use a Web-Content wordlist. Directory/file
  discovery, NOT subdomain enumeration.
- **`surface__vhost_enum(base_url=...)`** fuzzes the *Host header* — no `FUZZ`
  in the URL (it sets `Host: FUZZ.<target>` for you). Use a DNS/subdomains
  wordlist. This is what finds name-based virtual hosts / subdomains.

Passing a subdomains wordlist to `ffuf` is the classic mistake — that's
`vhost_enum`'s job.

## When to run vhost enumeration

- The IP responds to HTTP but content seems generic
- nmap revealed an HTTP service but `httpx_fingerprint` showed nothing interesting
- The box hint or domain suggests multi-tenant hosting, or a redirect / page
  content references a hostname (e.g. `silentium.htb`)

## How

`surface__vhost_enum(base_url, wordlist, filter_size)`. Use a sensible
subdomain wordlist (default: SecLists top-1m-5000). It auto-calibrates against
the wildcard response; pass `filter_size` to filter the default response's
content-length explicitly if you still see noise.

## Make the vhost resolve (/etc/hosts) — required before browsing by name

A discovered name like `silentium.htb` will NOT resolve until it's mapped to the
target IP. The moment you find a vhost — from `vhost_enum`, a redirect, a
`Host:`-based 200, or page content — map it once:

```
surface__add_hosts_entry(ip="<target IP>", hostnames=["silentium.htb"])
```

Then fuzz / `curl` / `httpx_fingerprint` it by name normally. Notes:

- Add **every** vhost you find (apex and subs, e.g. `silentium.htb` and
  `staging.silentium.htb`) — the box often routes differently per name.
- The mapping applies to this recon sandbox (httpx/ffuf/curl). The browser and
  shell containers keep their own `/etc/hosts`.

## Reading the output

Each result is a vhost name whose response *differed* from the default. Visit
each one. The interesting ones often have:

- Admin panels
- Internal-only apps left exposed
- Development versions of the main site (older, more vulnerable)

## After enumeration

Add each discovered vhost to `WebSurface.interesting_paths` with a note about
what makes it distinct. Pass on to Exploit if any look exploitable.
