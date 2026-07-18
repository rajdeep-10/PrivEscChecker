# PrivEscChecker

![Python](https://img.shields.io/badge/python-2.5%2B%20%7C%203.x-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)
![Status](https://img.shields.io/badge/status-active-brightgreen)

A Linux privilege escalation checker built from scratch to find real,
exploitable misconfigurations on a target you already have a foothold on —
SUID/SGID binaries, sudo misconfigurations, and writable root-run cron jobs —
and report them in one severity-tiered, evidence-backed summary.

Project 3 of a 4-part cybersecurity portfolio. Built and tested against a
real, live target (Metasploitable2) over an isolated VirtualBox lab network,
with every finding confirmed by actually exploiting it, not just detected on
paper.

---

## Why This Exists

Tools like [LinPEAS](https://github.com/carlospolop/PEASS-ng) already do this,
and do it more exhaustively. The point here wasn't to replace them — it was to
understand, at a code level, exactly *why* these misconfigurations are
exploitable, by building the detection logic myself: what makes a SUID binary
dangerous, what a sudoers wildcard actually permits, why a writable cron
script is a root-code-execution primitive. That's a stronger interview
answer than "I ran LinPEAS" — and this project produced real findings that
were then actually exploited on a real target, not just flagged.

---

## Architecture

```
                    ┌─────────────────────────┐
                    │   privesc_check.py       │   <- run this
                    │   (combined tool)        │
                    └────────────┬─────────────┘
                                 │
          ┌──────────────────────┼──────────────────────┐
          │                      │                      │
  ┌───────▼────────┐   ┌─────────▼─────────┐   ┌─────────▼─────────┐
  │  SUID/SGID      │   │  Sudo             │   │  Cron Job          │
  │  Check          │   │  Misconfig Check  │   │  Check             │
  │                 │   │                   │   │                    │
  │  os.walk('/')   │   │  sudo -l          │   │  /etc/crontab       │
  │  + stat bits    │   │  (stdin from      │   │  /etc/cron.d/*      │
  │  + GTFOBins     │   │   /dev/null)      │   │  + writable-path    │
  │    binary list  │   │  + GTFOBins list  │   │    walk             │
  └─────────────────┘   └───────────────────┘   └────────────────────┘
          │                      │                      │
          └──────────────────────┼──────────────────────┘
                                 │
                    ┌────────────▼─────────────┐
                    │  Unified finding model:   │
                    │  CRITICAL / HIGH / INFO   │
                    │  + evidence + exploit cmd │
                    │  + remediation            │
                    └────────────┬─────────────┘
                                 │
                    ┌────────────▼─────────────┐
                    │   report.md (markdown)    │
                    └───────────────────────────┘
```

The three checks were built and tested **individually first** (they still
exist standalone in `modules/`), then merged into one combined tool sharing a
single finding format — this incremental order meant each check could be
verified against a real target before adding the next.

---

## Usage

```bash
# Run all three checks, print results to the terminal
python privesc_check.py

# Also save a full markdown report
python privesc_check.py --output report.md
```

No installation, no dependencies — see [Design Decisions](#design-decisions)
for why. Works with either `python` or `python3`, on anything from Python
2.5.2 up through modern Python 3.

Individual checks can also be run standalone from `modules/` if you only need
one:
```bash
python modules/suid_check.py --output suid_report.md
python modules/sudo_check.py --output sudo_report.md
python modules/cron_check.py --output cron_report.md
```

---

## Proof of Concept

Tested against [Metasploitable2](https://sourceforge.net/projects/metasploitable/),
run as the low-privileged `msfadmin` user (a real foothold, not root):

```
$ python privesc_check.py --output combined_report.md
[*] PrivEscChecker - Combined Privilege Escalation Scan
[*] Running SUID/SGID, sudo, and cron checks...

[*] Running as: msfadmin
[*] id: uid=1000(msfadmin) gid=1000(msfadmin) groups=4(adm),20(dialout),24(cdrom),...

[*] Scan complete. 51 total findings.
[!!] 2 CRITICAL findings.
[!] 1 HIGH findings.
[i] 48 INFO findings.

[CRITICAL] SUID/SGID Binary: /usr/bin/nmap
        -> Older versions support --interactive mode, allowing shell execution when SUID.
        exploit: nmap --interactive  (then: !sh)

[CRITICAL] Sudo Misconfiguration: sudo ALL commands allowed
        -> This user can run any command as the target user via sudo - full compromise.
        exploit: sudo su  (password required)

[HIGH] Cron Job: [ -x /usr/lib/php5/maxlifetime ] && [ -d /var/lib/php5 ] && find /var/lib/php5/ ...
        -> This job runs as root and its script path (or a parent directory) is writable: /var/lib/php5/ (world-writable)
        exploit: Modify or replace the writable path with attacker-controlled content, then wait for the cron job to fire.

[*] Full report saved to: combined_report.md
```

**The `nmap` finding was actually exploited, not just flagged:**

```
msfadmin@metasploitable:~$ nmap --interactive
nmap> !sh
# whoami
root
```

Full root shell obtained from a low-privilege foothold, purely through a
misconfiguration this tool detected on its own.

---

## Design Decisions

| Decision | Reasoning |
|---|---|
| Zero external dependencies | Meant to run on a freshly-obtained shell where `pip install` may not be possible, may require internet access the target doesn't have, or may get noticed by defenders. Standard library only. |
| No `argparse`, `str.format()`, `with`, or the `bytes` builtin | All four are missing or behave differently on Python < 2.6/2.7. Confirmed the hard way against Metasploitable2's Python 2.5.2 — see Bugs Found & Fixed below. |
| Curated GTFOBins list instead of an exhaustive one | Depth over breadth: every entry in the list has a specific, explainable exploitation technique, rather than a long list of binaries flagged with no context. |
| `sudo -l` run with stdin redirected from `/dev/null`, not `sudo -n -l` | The `-n` flag doesn't exist on older sudo versions (rejected outright on Metasploitable2). Redirecting stdin achieves the same "never hang on a password prompt" goal without relying on a flag that isn't universally supported. |
| Cron check walks up parent directories, not just the target file | A writable *parent directory* of a root-run script is just as exploitable as a writable script itself (you can replace the file entirely), so both are checked. |
| SUID/sudo/cron built as standalone modules first | Let each check be tested and debugged against a real target independently, isolating bugs to one component at a time rather than debugging three interacting systems at once. |
| NOPASSWD detection reflects the literal sudoers entry, not session caching | `sudo`'s credential timestamp cache can make a password-protected account *feel* passwordless within a session. The tool reports what's actually configured, not runtime caching behavior, since that's what actually determines the underlying misconfiguration. |

---

## Bugs Found & Fixed

Every one of these was hit against a real target, not anticipated in advance.
Metasploitable2 turned out to be a genuinely difficult compatibility target —
its Python (2.5.2), sudo, and OpenSSH versions are all old enough to break
assumptions that hold on virtually any modern system.

1. **Non-ASCII characters broke Python 2 parsing entirely.**
   An em dash in a docstring caused `SyntaxError: Non-ASCII character... but no
   encoding declared` on the target's Python 2. Fixed by removing all non-ASCII
   characters and standardizing on `# -*- coding: utf-8 -*-`.

2. **`str.format()`, the `with` statement, and `argparse` don't exist on
   Python 2.5.2.** Discovered one at a time, each surfacing only after the
   previous was fixed. `str.format()` was added in 2.6, `with` in 2.6,
   `argparse` in 2.7 — Metasploitable2 predates all three. Rewrote all string
   formatting to `%`-style, replaced `with open(...)` with explicit
   `try/finally`, and wrote a ~30-line manual argument parser in place of
   `argparse`.

3. **A defensive `except Exception` clause silently swallowed a real bug.**
   After the above fixes, `whoami`/`id` output kept coming back blank with no
   visible error. Root cause: `isinstance(out, bytes)` was raising
   `NameError: global name 'bytes' is not defined`, because the `bytes`
   builtin doesn't exist at all before Python 2.6 — and a broad
   `except Exception: pass` was catching that error invisibly. Only found by
   adding temporary debug prints directly on the target and reproducing the
   exact failure. Fixed by checking `not isinstance(out, str)` instead, which
   is only ever true on Python 3.

4. **SSH host key negotiation failed against Metasploitable2's ancient
   OpenSSH.** Modern OpenSSH on Kali refuses the old `ssh-rsa`/`ssh-dss` host
   key types by default. Fixed per-connection with
   `-oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedAlgorithms=+ssh-rsa`.

5. **`sudo -n -l` failed with "illegal option -n" on old sudo.** The `-n`
   (non-interactive) flag doesn't exist on Metasploitable2's sudo version at
   all. Rewrote the check to instead redirect `sudo -l`'s stdin from
   `/dev/null` — achieving the same "never hang on a password prompt"
   guarantee without depending on a flag that isn't universally supported.

6. **A regression during the merge into the combined tool.** While combining
   the three standalone modules, adding `"|"` (pipe) as a command separator
   in the cron path-extraction logic seemed like a reasonable generalization —
   but it actually discarded the real `find /var/lib/php5/ ...` command in
   favor of the trailing `xargs -r -0 rm`, losing a real finding entirely.
   Caught by comparing the combined tool's output against the already-verified
   standalone version's result on the same target, and fixed by only treating
   `&&`, `||`, and `;` as "the real command follows this" separators.

---

## Skills Demonstrated

| Skill | Where |
|---|---|
| Linux privilege escalation techniques (SUID/SGID, sudo misconfig, cron) | Core detection logic across all three checks |
| Python cross-version compatibility (2.5.2 → 3.x) | Every module, extensively — see Bugs Found & Fixed |
| Live exploitation, not just detection | `nmap --interactive` root shell obtained from a flagged finding |
| Debugging via direct target instrumentation | Adding temporary debug prints on the live target to isolate the `bytes` NameError |
| Regression testing | Caught the pipe-splitting regression by diffing combined-tool output against the standalone module's already-verified result |
| Structured security reporting | Severity tiers, evidence, suggested exploitation, and remediation per finding |

---

## Legal & Ethical Use

This tool is built strictly for authorized security testing and educational
use: your own lab virtual machines, deliberately vulnerable practice targets
(Metasploitable2, VulnHub, TryHackMe, HackTheBox), or systems you have
explicit written authorization to test.

**Do not run this against any system you do not own or do not have explicit
permission to test.** Unauthorized access to computer systems is illegal
under laws including the U.S. Computer Fraud and Abuse Act and equivalent
legislation in most countries, regardless of whether a vulnerability is
successfully exploited.

All testing for this project was performed against Metasploitable2, a
deliberately vulnerable machine designed for security practice, running on an
isolated host-only VirtualBox network with no internet exposure and no
connection to any third-party system.

---

## License

MIT — see [LICENSE](LICENSE).

## Author

**Rajdeep Goswami** — [github.com/rajdeep-10](https://github.com/rajdeep-10)
CEH / CEH Practical / CEH Master. Built as project 3 of a 4-part
cybersecurity portfolio (see also: [ThreatMapper](https://github.com/rajdeep-10/ThreatMapper),
[PacketHound](https://github.com/rajdeep-10/PacketHound)).
