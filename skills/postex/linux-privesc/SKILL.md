---
name: linux-privesc
description: Linux privilege escalation enumeration and the most common paths to root.
allowed-tools: [postex__linux_basic_enum, postex__linpeas, shell__tmux_send, shell__tmux_read]
---

# Linux privilege escalation

## Order of operations

1. **Basic enum first** — `postex__linux_basic_enum(session_name)` runs the
   small set of checks that cover 60% of easy boxes:
   - `id`, `sudo -n -l`, `find / -perm -4000 -type f`, `ss -ltnp`
2. **If basic enum gives nothing useful**, escalate to `postex__linpeas` (fast mode).
3. **Read carefully** — linpeas highlights yellow/red findings; those are
   prioritized for you, but verify each.

## Common paths (rough priority)

| Signal | Path | Notes |
|---|---|---|
| `sudo -n -l` shows `(ALL) NOPASSWD: <something>` | abuse via GTFOBins | check `gtfobins.github.io/gtfobins/<binary>` |
| World-writable cron in `/etc/cron.*` | overwrite + wait | be patient — the cron's frequency matters |
| SUID binary not in `/usr/bin` | check version + GTFOBins | almost always vulnerable on CTFs |
| Capabilities on a binary | `getcap` output, GTFOBins capability table | python with `cap_setuid` = root |
| Kernel version + arch from `uname -a` | check exploit-DB | last resort — noisy and unstable |
| Group `docker` or `lxd` | well-known root paths | trivial — see GTFOBins |
| Writable `/etc/passwd` or `/etc/shadow` | inject root entry | rare but instant root |

## Don't lose your shell

When trying a kernel exploit or anything destabilizing, **open a second
session first**. The `shell` MCP server lets you `tmux_new_session` with a
fresh listener so a crashed shell doesn't wipe state.

## Credential collection

In lab/engagement modes, before escalating run `postex__loot_credentials` —
quick win if the box has SSH keys, AWS creds, or password files in
predictable locations. Adds those to `Credential`s for the orchestrator to
chain to other hosts.
