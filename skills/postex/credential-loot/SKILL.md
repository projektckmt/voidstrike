---
name: credential-loot
description: Targeted credential collection on a landed host. Lab/engagement mode only.
allowed-tools: [postex__loot_credentials, shell__tmux_send, shell__tmux_read]
---

# Credential loot

## When to run

- You have a stable shell.
- The engagement mode is lab or engagement (CTF mode rarely benefits — single-box).
- The orchestrator's next planned objective is *lateral movement* — credentials
  are what unlock that.

## Linux targets

`postex__loot_credentials(session_name, os_kind="linux")` covers:

- `/root/.ssh/*` and `/home/*/.ssh/*` — SSH keys (often unencrypted on CTFs)
- `.aws/credentials`, `.docker/config.json` — cloud + container registry creds
- `grep -ri password /etc` — config files with hardcoded creds
- `/etc/shadow` — if readable, exfil + crack locally (see `hash-cracking` skill —
  cracking on the target's reverse shell is the wrong machine)

## Windows targets

`postex__loot_credentials(session_name, os_kind="windows")`:

- `cmdkey /list` — stored Windows credentials
- PuTTY saved sessions — registry-based, often have hostnames + sometimes keys
- Browser-stored passwords (varies by browser; phase 3+ has dedicated tool)
- KeePass `.kdbx` files — collect + crack via `hash-cracking` skill

## What you do not do

- Do not exfiltrate to outside the sandbox. Loot stays in `/engagement/loot/`.
- Do not dump LSASS without HITL approval in engagement mode — extremely noisy
  and a strong incident-response signal.
- Do not re-use a domain credential to scan beyond the current host without
  the orchestrator's explicit lateral-movement step.

## Output

Each cred becomes a `Credential` record with:

- `source` — where it was found (`/root/.ssh/id_rsa`, `cmdkey /list`)
- `service` — best guess at what it's for (`ssh`, `aws`, `domain`)
- `domain` — for AD creds

The orchestrator uses `source` to triage which creds are worth trying next.
