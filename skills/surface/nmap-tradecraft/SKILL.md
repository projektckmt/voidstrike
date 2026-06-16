---
name: nmap-tradecraft
description: When to use nmap_quick vs nmap_full, how to read service-version banners, when to escalate to UDP/-sC --script vuln.
allowed-tools: [surface__nmap_quick, surface__nmap_full]
---

# Nmap tradecraft

## The two-stage approach

Always start with `nmap_quick` (top-1000, -sV -sC, default scripts). This gets you
80% of useful surface in ~60s. Only escalate to `nmap_full` (-p- all ports) when:

- `nmap_quick` returned almost no services (firewall? non-default ports?)
- The box hint mentions an unusual port
- You're stuck and need to broaden — let the stuck detector escalate first

## Reading what comes back

The banner is the value. `Apache 2.4.49 ((Ubuntu))` is a different beast from
`Apache 2.4.41 ((Ubuntu))` — one has a one-line RCE (CVE-2021-41773). Always
record the *exact* version string in `SurfaceFindings.services[*].version` and
the verbatim banner in `banner`. Do not paraphrase.

## When to add `--script vuln`

Adds 5-15min to a scan. Use it when:

- A web port shows up and HTTP fingerprinting was inconclusive
- An SMB/RPC service appears — vuln scripts catch easy MS-* CVEs
- You've enumerated everything and need to dig

Avoid it as the *first* scan — it's noisy and slow.

## UDP

Almost never worth it in CTF mode. In lab/engagement, run `nmap -sU --top-ports 100`
against hosts where you suspect SNMP/NTP/IKE/DNS specifically.

## What you do not do

- Don't run `-T5`. Faster than `-T4` is detection bait and missed services.
- Don't run `-A` everywhere. It's a convenience flag that hides what you ran.
- Don't trust the service column over the banner. nmap guesses on port number;
  the banner is ground truth.
