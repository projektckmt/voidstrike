---
name: privesc-verify
description: Confirm a privesc actually produced root before claiming it. How to verify async/root-triggered vectors (cron, incron, signed hooks, services), prove uid=0 instead of guessing, and avoid wedging the shell while you wait.
allowed-tools: [shell__tmux_exec, shell__tmux_read, shell__tmux_send]
---

# Verify the privesc — don't assume it worked

The most expensive privesc failure is not "no vector" — it's **declaring
victory on a vector you never confirmed**. You set up a root-run trigger, the
artifact you expected isn't there, and you spend the rest of the run guessing
whether the mechanism fired, whether the box reverted, or whether your read was
stale. This skill is the verification loop that closes that gap.

The rule everything follows from: **"ran" is not "rooted."** A trigger firing,
a file being written, a hook executing — none of those is root until you have
*directly observed `uid=0`*.

## What counts as proof of root

Rank your evidence. Only the first two are proof:

| Evidence | Proof? | Why |
|---|---|---|
| A file **owned by root** that you caused to be created | ✅ | Ownership can't be faked by your low-priv user |
| `id` / `cat /proc/self/status` showing **uid=0** from the escalated context | ✅ | Direct |
| The **root flag** (`/root/root.txt`) readable | ✅ | Only root can read it |
| "The cron/hook should run as root" | ❌ | A plan, not a result |
| A file exists at the expected path | ❌ | **You** may have created it during a manual test (see below) |
| The trigger file was consumed / the command returned `ok` | ❌ | The mechanism started, not that it succeeded as root |

**Always check the owner, not just existence:**

```sh
# nonce so a stale scrollback read can't masquerade as a fresh result
N=$RANDOM; rm -f /tmp/p.$N
# ... fire your root-run vector, pointing its payload at /tmp/p.$N ...
stat -c '%n %U:%G %a' /tmp/p.$N 2>/dev/null   # want owner root:root
```

If `stat` shows `root root`, you have root code execution. If it shows your
own user (e.g. `asterisk asterisk`), your payload ran **as you**, not as root —
the privilege boundary was never crossed.

## The contamination trap

When you test a root-run hook, **do not run the hook's payload manually first**
"to see if it works." A manual run executes as your low-priv user and leaves a
**user-owned** artifact at the exact path the root run would use. On the next
check you see the file, assume the root path worked, and report a privesc that
never happened. Either use a fresh nonce path per attempt, or `rm` the artifact
and confirm it's gone *before* triggering the real (root) path.

## Async / root-triggered vectors (cron, incron, signed hooks, services)

These are the hard ones — the code runs as root in a context you can't see, and
your only feedback is whether a root-owned artifact appears. Two things kill
them silently:

1. **Backgrounded payloads get reaped.** If the root-run wrapper launches your
   payload with `&` (e.g. `php hook.php $1 &`), the trigger daemon (incrond,
   some service managers) can tear down the whole process tree when the wrapper
   returns — your payload dies mid-write. **Make the payload synchronous and
   self-detaching** so it survives and finishes:

   ```sh
   # in your payload: detach from the reaped process group, do the work fast
   setsid sh -c 'id > /tmp/p.$N; cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash' &
   ```

   `setsid`/`nohup` is the first thing to try when a root trigger "fires but
   leaves nothing." It is cheap and it is the most common reason these vectors
   no-op.

2. **The wrapper fatals before your code runs.** Run the wrapper's own
   prerequisites by hand and read the *error*: a missing interpreter module
   (`Class 'DB' not found`, missing PEAR/include path), a failed signature
   check, a stripped environment. If the wrapper dies on line 11 every time,
   the vector is genuinely dead on this box — record that and move on; don't
   re-trigger it ten times.

### The wait — never `sleep` in the foreground

To wait for a cron/incron cycle, **do not** run `sleep 70` in the target shell.
It blocks the pane; `tmux_read` then returns a half-drawn prompt that looks
*wedged*, and the reflex to "clear" it with Ctrl-C will kill the reverse shell
(Ctrl-C to the listener pane tears down `nc`). Instead, **return control after
firing the trigger and poll** with short, separate checks:

```sh
# fire-and-return (no foreground sleep):
echo go > /var/spool/.../trigger
# then, in SEPARATE tmux_exec calls spaced out, poll for the ROOT-owned artifact:
stat -c '%U' /tmp/p.$N 2>/dev/null
```

Each poll is its own `shell__tmux_exec` (or a `shell__tmux_read` with a
`timeout_s`) — the pane stays responsive, and you can read a clean result every
time. A per-minute cron needs at most ~2 polls a minute apart; if three polls
show nothing root-owned, the chain is broken — diagnose the wrapper (point 2),
don't keep waiting.

## Behavioral check beats the version string

Before you commit to an exploit — *especially* before any brute-force or
long-running attempt — confirm the target is actually vulnerable, not just that
its version is in the vulnerable *range*. Distros backport security fixes
without bumping the version string, so `sudo 1.8.23` can be either vulnerable or
patched.

| Vector | Behavioral check | Patched looks like |
|---|---|---|
| Baron Samedit (CVE-2021-3156) | `sudoedit -s /` | prints `usage:` (vulnerable: `sudoedit: /: not a regular file` or a crash) |
| PwnKit (CVE-2021-4034) | check the polkit package build (`-26.el7_9.1` etc. are patched) | patched backport build string |

If the behavioral check says patched, it's patched — the version string does
not overturn it. Do not start an ASLR brute-force on a vector you haven't
confirmed live; that is how a run ends with hundreds of timed-out iterations
and no root.

## Before you report "solved"

Gate your handback on proof, not mechanism:

- You have **directly observed uid=0** (root-owned artifact you created, `id`=0,
  or `root.txt` in hand) → write the `Finding` with that evidence and stop.
- The mechanism is "set up" but you have **not** seen root → it is **not**
  solved. Either close the loop with one clean verification poll, or hand back
  honestly: "vector identified, root not yet confirmed; blocker is X." Do not
  claim a privesc you can't prove — a false "solved" sends the next subagent
  down a path that doesn't exist.

Cross-reference: `skills/postex/linux-privesc` for choosing the vector;
`skills/postex/binary-fetch-and-drop` for staging a needed binary. This skill
is specifically about *confirming the vector worked* once you've picked one.
