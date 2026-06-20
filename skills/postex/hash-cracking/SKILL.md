---
name: hash-cracking
description: Crack captured hashes offline in the Kali sandbox with john (NOT hashcat — the sandbox is GPU-less and hashcat errors out), and on Kali, NOT the target.
allowed-tools: [shell__tmux_new_session, shell__tmux_send, shell__tmux_read]
---

# Hash cracking

## Use `john`, NOT `hashcat`

**The sandbox has no GPU / OpenCL runtime.** `hashcat` enumerates compute
devices at startup and aborts when it finds none:

```
clGetDeviceIDs(): CL_DEVICE_NOT_FOUND
No devices found/left.
```

(Sometimes phrased "No OpenCL devices available" / "No CUDA-capable device".)
This is the environment, not a fixable setup problem — **do not** try to install
OpenCL/CUDA drivers, pass `--backend-devices`, or `--force` your way past it
(`--force` on a no-device host still cracks nothing). If you typed `hashcat` and
saw that error, that's your cue to switch tools, not to debug it.

**`john` (John the Ripper, jumbo) is the cracker here** — it's CPU-native,
preinstalled, needs no GPU, auto-detects most formats, and writes to a pot file
you can re-read with `--show`. Everything below uses `john`. If a writeup or POC
gives a `hashcat -m <mode>` command, translate it to `john --format=<name>`
(see the format table below); the wordlists are the same.

## The rule

**Cracking runs on Kali, not on the target.** If you have a tmux session
pointing at a landed reverse shell (`session_name="shell-foo"`), running
`john` or `hashcat` in that session executes the cracker on the *target*
machine. That is almost always wrong:

- The target probably has no `john` / `hashcat` installed → command fails.
- Even if it does, target CPUs are typically tiny → cracks that finish in
  seconds on Kali grind for hours there.
- It's loud — heavy CPU on a compromised host is a strong incident-response
  signal.
- The target's wordlists (if any) are sparse; Kali ships `rockyou.txt`,
  `seclists`, and `dirbuster` lists.

The target session is for *capturing* the hash. The Kali sandbox is for
*cracking* it.

## The workflow

1. **Capture in the target session.** Read the hash out of the reverse-shell
   session:
   ```
   shell__tmux_send(session_name="shell-foo", command="cat /etc/shadow")
   shell__tmux_read(session_name="shell-foo")
   ```
   Or `cat /etc/security/passwd`, `find / -name "*.kdbx" 2>/dev/null`, etc.

2. **Spawn a Kali-local cracking session.** This is a fresh shell *in the
   sandbox*, not on the target:
   ```
   shell__tmux_new_session(name="cracker", kind="generic")
   ```

3. **Write the hash to a file in the sandbox.** Use the cracker session, not
   the target session. A single-quoted heredoc avoids shell expansion eating
   `$` characters in MD5/SHA crypt hashes:
   ```
   shell__tmux_send("cracker", "cat > /tmp/hashes.txt << 'EOF'")
   shell__tmux_send("cracker", "<paste the captured hash line(s) verbatim>")
   shell__tmux_send("cracker", "EOF")
   ```

4. **Run the cracker on Kali.** `john` is preinstalled and
   `/usr/share/wordlists/rockyou.txt` is decompressed in the Kali image:
   ```
   shell__tmux_send("cracker", "john --wordlist=/usr/share/wordlists/rockyou.txt /tmp/hashes.txt")
   shell__tmux_read("cracker", timeout_s=120)
   ```

5. **Re-read with `--show` if the cracker exits before you read.** John
   writes results to a pot file:
   ```
   shell__tmux_send("cracker", "john --show /tmp/hashes.txt")
   shell__tmux_read("cracker", timeout_s=5)
   ```

## Hash-format quick reference

`john` auto-detects in most cases, but explicit `--format=` is safer:

| Source / shape | john `--format=` |
|---|---|
| `/etc/shadow` line starting `$1$` | `md5crypt` |
| `/etc/shadow` line starting `$5$` | `sha256crypt` |
| `/etc/shadow` line starting `$6$` | `sha512crypt` |
| `/etc/shadow` line starting `$y$` | `crypt` (newer yescrypt — john ≥ 1.9.0-jumbo-1) |
| 32-char hex from MySQL `mysql.user.authentication_string` (no `$`) | `mysql-sha1` |
| 32-char hex, no salt | `Raw-MD5` |
| 40-char hex, no salt | `Raw-SHA1` |
| `$apr1$...` from `.htpasswd` | `md5crypt-long` |
| NTLM dumped via `secretsdump.py` | `NT` |
| Kerberos TGS-REP from `kerberoast` | `krb5tgs` |
| Kerberos AS-REP from `as-rep roast` | `krb5asrep` |

For `/etc/shadow` lines, paste the whole `user:$6$salt$hash:...` line —
john parses the `:`-delimited format directly. Do not strip the username.

## Fallback wordlists

`rockyou.txt` covers ~80% of CTF passwords. If it doesn't crack:

- `/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt`
- `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt` (yes, dir
  fuzz lists occasionally crack — sysadmin-style passwords)
- `--rules=Jumbo` adds standard mutations (`Password` → `Password1!`)
- For long brute-force runs, time-box. Don't sit on a hash > 15 minutes
  unless the box clearly hinges on it. Note it in `notes` and move on.

## What this skill does not cover

- **Online password spraying.** That belongs in the `exploit` subagent.
- **Pass-the-hash / overpass.** AD primitives are in
  `skills/ad/ad-attack-paths/` — those don't crack the hash, they *use* it
  directly.
- **Hashcat.** Not usable here — the sandbox is GPU-less and hashcat aborts with
  `CL_DEVICE_NOT_FOUND` / "No devices found". Use `john` (see the top of this
  skill).

## Output

When a crack succeeds, emit a `Credential` finding with:

- `source` — where the hash came from (`/etc/shadow:root`, `mysql.user:admin`)
- `service` — best guess for what it unlocks (`ssh`, `mysql`, `domain`)
- `secret` — the cracked plaintext
- `domain` — for AD creds only
