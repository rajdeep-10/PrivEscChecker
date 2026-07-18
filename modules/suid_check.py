#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
suid_check.py - SUID/SGID Privilege Escalation Checker (standalone module)
Part of the PrivEscChecker project.

NOTE: This is one of three standalone checks that were built and tested
individually before being combined into ../privesc_check.py, which is
the primary tool for this project (runs all three checks together with
a unified, severity-tiered report). This file is kept in the repo to
show the incremental development process and because it's still useful
on its own if you only want the SUID/SGID check specifically.

Scans the local filesystem for SUID/SGID binaries and flags any that are
known to be exploitable for privilege escalation, based on a curated list
of common GTFOBins-style abuse vectors.

Written to run on very old Python 2 as well as Python 3, since real-world
targets (older lab VMs, CTF boxes) can ship Python versions that predate
features like str.format() (2.6+), the 'with' statement (2.6+), and
argparse (2.7+). This script avoids all of those and sticks to syntax
that has worked since early Python 2.x.

USAGE:
    python suid_check.py
    python suid_check.py --output report.md

Intended for use on Linux systems you are authorized to test
(e.g. your own lab VMs, CTF machines you have legitimate access to).
"""

import os
import sys
import stat
import subprocess
from datetime import datetime

# Known binaries that can be abused for privilege escalation when SUID,
# based on common GTFOBins-documented techniques. This list is intentionally
# curated (not exhaustive) - focus on quality of explanation over quantity.
KNOWN_EXPLOITABLE = {
    "find":    "Can spawn a shell via 'find . -exec /bin/sh \\; -quit' when SUID.",
    "vim":     "Can spawn a shell via ':!sh' or read/write arbitrary files when SUID.",
    "vi":      "Can spawn a shell via ':!sh' when SUID.",
    "nano":    "Can read/write arbitrary files as owner when SUID.",
    "less":    "Can spawn a shell via '!sh' when SUID.",
    "more":    "Can spawn a shell via '!sh' when SUID (older versions).",
    "nmap":    "Older versions support --interactive mode, allowing shell execution when SUID.",
    "python":  "Can spawn a shell via 'os.system(\"/bin/sh\")' when SUID.",
    "python3": "Can spawn a shell via 'os.system(\"/bin/sh\")' when SUID.",
    "perl":    "Can spawn a shell via 'exec \"/bin/sh\";' when SUID.",
    "awk":     "Can spawn a shell via 'awk BEGIN {system(\"/bin/sh\")}' when SUID.",
    "cp":      "Can overwrite sensitive files (e.g. /etc/passwd) as owner when SUID.",
    "tar":     "Can spawn a shell via '--checkpoint-action' tricks when SUID.",
    "env":     "Can spawn a shell via 'env /bin/sh -p' when SUID.",
    "bash":    "If SUID, spawns a root shell directly via 'bash -p'.",
    "sh":      "If SUID, spawns a root shell directly via 'sh -p'.",
}


def find_suid_sgid_files():
    """
    Walk the filesystem looking for files with the SUID or SGID bit set.
    Equivalent in purpose to: find / -perm -4000 -o -perm -2000 2>/dev/null
    """
    findings = []
    skip_dirs = set(["/proc", "/sys", "/run"])

    for root, dirs, files in os.walk("/", topdown=True):
        # Don't descend into virtual/pseudo filesystems - wastes time and
        # produces noise, not real findings.
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


def score_finding(finding):
    """
    Assign a risk level based on whether the binary name matches a known
    exploitable pattern. Returns (risk_level, note).
    """
    basename = os.path.basename(finding["path"])

    if basename in KNOWN_EXPLOITABLE:
        return "HIGH", KNOWN_EXPLOITABLE[basename]

    return "INFO", "SUID/SGID set, but not a recognized high-risk binary. Manually review if unexpected."


def run_cmd(cmd_list):
    """
    Run a command and return its stdout, stripped.
    Uses subprocess.Popen (not subprocess.run, which is Python 3.5+ only).

    Does NOT check isinstance(out, bytes) - the 'bytes' builtin does not
    exist at all on Python < 2.6 (confirmed: raises NameError on Python
    2.5.2 on Metasploitable2, silently caught by the except clause here,
    which made whoami/id context detection silently fail every time).
    """
    try:
        proc = subprocess.Popen(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, _ = proc.communicate()
        if not isinstance(out, str):
            # Only true on Python 3, where out is a real bytes object.
            out = out.decode("utf-8", "replace")
        return out.strip()
    except Exception:
        return "unknown"


def get_current_user_context():
    """Grab basic context: current user, id output, for the report header."""
    whoami = run_cmd(["whoami"])
    id_out = run_cmd(["id"])
    return whoami, id_out


def build_report(findings, scored, whoami, id_out):
    """Build a markdown-formatted report string."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    high_count = 0
    info_count = 0
    for f in scored:
        if f["risk"] == "HIGH":
            high_count = high_count + 1
        else:
            info_count = info_count + 1

    lines = []
    lines.append("# PrivEscChecker - SUID/SGID Scan Report")
    lines.append("")
    lines.append("**Scan time:** %s" % timestamp)
    lines.append("**Run as:** %s" % whoami)
    lines.append("**id output:** `%s`" % id_out)
    lines.append("")
    lines.append("**Total SUID/SGID files found:** %d" % len(findings))
    lines.append("**HIGH risk findings:** %d" % high_count)
    lines.append("**INFO findings:** %d" % info_count)
    lines.append("")
    lines.append("---")
    lines.append("")

    if high_count > 0:
        lines.append("## HIGH Risk Findings (likely exploitable)")
        lines.append("")
        for f in scored:
            if f["risk"] == "HIGH":
                bits = []
                if f["suid"]:
                    bits.append("SUID")
                if f["sgid"]:
                    bits.append("SGID")
                lines.append("### `%s`" % f["path"])
                lines.append("- **Bits set:** %s" % ", ".join(bits))
                lines.append("- **Owner UID:** %s" % f["owner_uid"])
                lines.append("- **Why this matters:** %s" % f["note"])
                lines.append("")

    if info_count > 0:
        lines.append("## INFO - SUID/SGID Set, Not Flagged as High-Risk")
        lines.append("")
        lines.append("| Path | SUID | SGID | Owner UID |")
        lines.append("|---|---|---|---|")
        for f in scored:
            if f["risk"] == "INFO":
                lines.append("| `%s` | %s | %s | %s |" % (
                    f["path"], f["suid"], f["sgid"], f["owner_uid"]))
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("**Note:** This tool only checks SUID/SGID binaries. It does not yet check ")
    lines.append("sudo misconfigurations, cron jobs, file permissions, or kernel exploits - ")
    lines.append("those checks are planned as separate modules.")
    lines.append("")
    lines.append("**Scope reminder:** Run this only on systems you are authorized to test ")
    lines.append("(your own lab VMs, CTF machines you have legitimate access to).")

    return "\n".join(lines)


def parse_args(argv):
    """
    Minimal manual argument parser.
    Not using argparse here, since argparse is Python 2.7+ only and
    this target's Python predates it.

    Supports: --output/-o <path>  (also accepts --output=<path>)
    Returns an object with an .output attribute, to match the rest of
    the script's usage (args.output).
    """
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
            print("Usage: python suid_check.py [--output report.md]")
            sys.exit(0)
        else:
            print("[!] Unrecognized argument: %s" % arg)
            sys.exit(1)
        i = i + 1

    return result


def main():
    args = parse_args(sys.argv[1:])

    print("[*] PrivEscChecker - SUID/SGID Scan")
    print("[*] Scanning filesystem, this may take a minute...")
    print("")

    whoami, id_out = get_current_user_context()
    print("[*] Running as: %s" % whoami)
    print("[*] id: %s" % id_out)
    print("")

    findings = find_suid_sgid_files()
    scored = []
    for f in findings:
        risk, note = score_finding(f)
        f["risk"] = risk
        f["note"] = note
        scored.append(f)

    high = []
    info = []
    for f in scored:
        if f["risk"] == "HIGH":
            high.append(f)
        else:
            info.append(f)

    print("[*] Scan complete. %d SUID/SGID files found." % len(findings))
    print("[!] %d HIGH risk findings." % len(high))
    print("[i] %d INFO findings." % len(info))
    print("")

    if high:
        print("=" * 60)
        print("HIGH RISK FINDINGS")
        print("=" * 60)
        for f in high:
            print("")
            print("[HIGH] %s" % f["path"])
            print("        SUID=%s SGID=%s Owner_UID=%s" % (
                f["suid"], f["sgid"], f["owner_uid"]))
            print("        -> %s" % f["note"])
        print("")

    if args.output:
        report = build_report(findings, scored, whoami, id_out)
        # Using explicit try/finally instead of 'with' here, since 'with' is
        # not valid syntax on very old Python 2 (this target's Python fails
        # outright on 'with', not just with a deprecation warning).
        fh = open(args.output, "w")
        try:
            fh.write(report)
        finally:
            fh.close()
        print("[*] Full report saved to: %s" % args.output)


if __name__ == "__main__":
    main()
