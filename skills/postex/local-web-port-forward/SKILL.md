---
name: local-web-port-forward
description: Expose localhost-only target web services to Kali/browser tooling during post-exploitation.
allowed-tools: [shell__tmux_new_session, shell__tmux_exec, shell__tmux_send, shell__tmux_read]
---

# Local Web Port Forward

Use this when PostEx finds a web service that only listens on the target host
itself, such as `127.0.0.1:3001`, `localhost:8080`, or an internal-only bind.
This is especially important for apps with cookies, CSRF, registration, upload
flows, JavaScript, or captcha. Raw `curl` is fine for fingerprinting; it is the
wrong primary tool for multi-step browser state.

## Trigger Conditions

Port-forward before grinding if any of these are true:

- `ss -ltnp`, `netstat`, process output, config files, or nginx/apache proxy
  config shows a service bound to `127.0.0.1`, `localhost`, or an internal-only
  interface.
- The local service is HTTP-ish: Gogs/Gitea, Jenkins, Grafana, Adminer, CUPS,
  dev servers, dashboards, framework debug consoles, or any app with forms.
- The next step needs browser behavior: CSRF cookies, redirects, hidden fields,
  registration, SSO, upload widgets, JavaScript-rendered state, or visual input.
- You are about to manually replay more than two form requests with `curl`.

## Standard SSH Tunnel

If you have SSH creds to the target host, create a separate Kali-local tmux
session and keep it running:

```bash
sshpass -p '<password>' ssh -N \
  -L 0.0.0.0:<local_port>:127.0.0.1:<remote_port> \
  -o ExitOnForwardFailure=yes \
  -o StrictHostKeyChecking=no \
  <user>@<target_ip>
```

Use `0.0.0.0` deliberately. The tunnel lives in the shell MCP container, and
binding all interfaces lets other MCP containers reach it over Docker networking.

Pick a local port that is unlikely to collide. A simple convention is:

- Remote `3001` -> local `13001`
- Remote `8080` -> local `18080`
- Remote `5000` -> local `15000`

## Verify

From a second shell call, verify the tunnel before returning it:

```bash
curl -sS -i http://127.0.0.1:<local_port>/ --max-time 5 | head -20
```

If the app requires a vhost, verify with the Host header too:

```bash
curl -sS -i -H 'Host: <vhost>' http://127.0.0.1:<local_port>/ --max-time 5 | head -20
```

The browser-capable follow-up can usually access the tunnel as:

```text
http://shell-mcp:<local_port>/
```

If a vhost is required, include `target_vhost` in `forwarded_services` and say
that browser tooling may need a hosts entry or a browser-side host mapping.

## When SSH Is Not Available

If you only have a reverse shell, try a userland relay only if a suitable tool is
already present or trivially stageable from Kali:

- `socat TCP-LISTEN:<local_port>,fork,reuseaddr TCP:127.0.0.1:<remote_port>`
- `chisel` or `ligolo-ng`, staged from Kali, if already in your normal playbook.

Do not install packages from the target. If no relay path exists, return a
specific blocker in `summary`.

## Return Shape

When the tunnel works, include a `forwarded_services` entry in the PostEx result:

```json
{
  "remote_host": "127.0.0.1",
  "remote_port": 3001,
  "local_port": 13001,
  "access_url": "http://shell-mcp:13001/",
  "tunnel_session": "fwd-gogs-3001",
  "target_vhost": "staging-v2-code.dev.silentium.htb",
  "verified": true,
  "reason": "Gogs is localhost-only and needs browser/session handling",
  "next_step": "Hand access_url and target_vhost to a browser-capable agent for signup/login/exploit"
}
```

Keep the tunnel tmux session alive. Do not `exit` it after verification.
