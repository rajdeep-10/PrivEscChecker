#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
sudo_check.py - Sudo Misconfiguration Privilege Escalation Checker (standalone module)
Part of the PrivEscChecker project.

NOTE: This is one of three standalone checks that were built and tested
individually before being combined into ../privesc_check.py, which is
the primary tool for this project (runs all three checks together with
a unified, severity-tiered report). This file is kept in the repo to
show the incremental development process and because it's still useful
on its own if you only want the sudo check specifically.

Runs 'sudo -l' (with stdin redirected from /dev/null, so it can never
hang on a password prompt) to see what the current user is allowed to
run as another user (usually root), and flags entries that are
exploitable:
  - NOPASSWD entries (no password required to run as root)
  - Binaries known to be abusable via sudo (GTFOBins-style)
  - Wildcard entries (e.g. '/usr/bin/vim *') which are still abusable

Written in the same Python 2.5.2-safe style as suid_check.py: no
str.format(), no 'with' statement, no argparse - all of these are
missing or broken on very old Python 2 (confirmed against Python 2.5.2
on Metasploitable2).

USAGE:
    python sudo_check.py
    python sudo_check.py --output report.md

Intended for use on Linux systems you are authorized to test
(e.g. your own lab VMs, CTF machines you have legitimate access to).
"""

import sys
import subprocess
from datetime import datetime

# Binaries known to be abusable when run via sudo, based on common
# GTFOBins-documented techniques. Same curated approach as the SUID
# checker - depth over breadth.
KNOWN_EXPLOITABLE = {
    "find":    "Can spawn a root shell via 'sudo find . -exec /bin/sh \\; -quit'.",
    "vim":     "Can spawn a root shell via 'sudo vim -c \":!sh\"'.",
    "vi":      "Can spawn a root shell via 'sudo vi -c \":!sh\"'.",
    "nano":    "Can read/write arbitrary files as root via sudo.",
    "less":    "Can spawn a root shell via 'sudo less /etc/profile' then '!sh'.",
    "more":    "Can spawn a root shell via 'sudo more /etc/profile' then '!sh'.",
    "nmap":    "Older versions support --interactive mode, spawning a root shell via sudo.",
    "python":  "Can spawn a root shell via 'sudo python -c \"import os; os.system(chr(47)+chr(98)+chr(105)+chr(110)+chr(47)+chr(115)+chr(104))\"'.",
    "python3": "Can spawn a root shell via 'sudo python3 -c \"import os; os.system(chr(47)+chr(98)+chr(105)+chr(110)+chr(47)+chr(115)+chr(104))\"'.",
    "perl":    "Can spawn a root shell via 'sudo perl -e \"exec chr(47).chr(98).chr(105).chr(110).chr(47).chr(115).chr(104);\"'.",
    "awk":     "Can spawn a root shell via 'sudo awk BEGIN {system(\"/bin/sh\")}'.",
    "cp":      "Can overwrite root-owned files (e.g. /etc/passwd, /etc/sudoers) via sudo.",
    "tar":     "Can spawn a root shell via 'sudo tar --checkpoint=1 --checkpoint-action=exec=/bin/sh'.",
    "env":     "Can spawn a root shell directly via 'sudo env /bin/sh'.",
    "bash":    "Direct root shell via 'sudo bash'.",
    "sh":      "Direct root shell via 'sudo sh'.",
    "su":      "Can be used to become root directly via 'sudo su'.",
    "apt":     "Can spawn a root shell via 'sudo apt update -o APT::Update::Pre-Invoke::=/bin/sh'.",
    "apt-get": "Can spawn a root shell via 'sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh'.",
}


def run_cmd(cmd_list):
    """
    Run a command and return (stdout, returncode).
    Uses subprocess.Popen (not subprocess.run, which is Python 3.5+ only).

    Falls back to common full paths (/usr/bin, /bin) if the bare command
    name fails to resolve, since some minimal shell environments (seen on
    Metasploitable2 over SSH) don't pass through PATH the way an
    interactive login shell does.

    Does NOT use isinstance(out, bytes) - the 'bytes' builtin does not
    exist at all on Python < 2.6 (confirmed: raises NameError on Python
    2.5.2, which was silently swallowed by a broad except clause and
    caused every subprocess call to appear to fail). Decoding is only
    ever needed on Python 3, where subprocess output is real bytes; we
    detect that case with a duck-typed check instead (hasattr decode
    only matters if it's not already a plain str).
    """
    try:
        proc = subprocess.Popen(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate()
        if not isinstance(out, str):
            # Only true on Python 3, where out is a bytes object.
            out = out.decode("utf-8", "replace")
        if proc.returncode == 0 and out.strip():
            return out, proc.returncode
    except Exception:
        pass

    # Fallback: try common full paths for the binary
    fallback_dirs = ["/usr/bin/", "/bin/", "/usr/sbin/", "/sbin/"]
    original_cmd = cmd_list[0]
    for prefix in fallback_dirs:
        try:
            full_path = prefix + original_cmd
            new_cmd_list = [full_path] + cmd_list[1:]
            proc = subprocess.Popen(new_cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, err = proc.communicate()
            if not isinstance(out, str):
                out = out.decode("utf-8", "replace")
            if out.strip():
                return out, proc.returncode
        except Exception:
            continue

    return "", -1


def get_current_user_context():
    """Grab basic context: current user, id output, for the report header."""
    whoami_out, _ = run_cmd(["whoami"])
    id_out, _ = run_cmd(["id"])
    return whoami_out.strip(), id_out.strip()


def get_sudo_l_output():
    """
    Run 'sudo -l' safely, without ever risking a hang on a password
    prompt. Returns (raw_output, could_run, needs_password).

    Originally this used 'sudo -n -l' (-n = non-interactive), but that
    flag does not exist on older sudo versions - confirmed on
    Metasploitable2's sudo, which rejects -n outright with
    "illegal option -n". Instead, we redirect sudo's stdin from
    /dev/null: if a password were required, sudo would read EOF
    immediately and fail fast rather than block waiting on a real
    terminal - this works the same way across old and new sudo alike.
    """
    devnull = None
    try:
        devnull = open("/dev/null", "r")
        proc = subprocess.Popen(["sudo", "-l"], stdin=devnull,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate()
        if not isinstance(out, str):
            out = out.decode("utf-8", "replace")
        if not isinstance(err, str):
            err = err.decode("utf-8", "replace")
    except Exception:
        out, err = "", ""
        proc = None
    finally:
        if devnull is not None:
            devnull.close()

    could_run = (proc is not None and proc.returncode == 0 and out.strip() != "")

    needs_password = False
    if not could_run:
        err_lower = err.lower()
        if "password" in err_lower:
            needs_password = True

    return out, could_run, needs_password


def parse_sudo_entries(raw_output):
    """
    Parse 'sudo -l' output into a list of individual allowed-command
    entries. This is intentionally simple pattern matching rather than a
    full grammar parser, since sudoers output formatting is fairly
    consistent across distros for the common cases we care about.

    Returns a list of dicts: {"raw": line, "nopasswd": bool, "commands": [...]}
    """
    entries = []
    lines = raw_output.split("\n")

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        # Lines describing actual allowed commands typically look like:
        #   (root) /usr/bin/find
        #   (root) NOPASSWD: /usr/bin/vim, /usr/bin/less
        #   (ALL : ALL) ALL
        if "(" in stripped and ")" in stripped:
            nopasswd = "NOPASSWD" in stripped

            # Pull everything after the closing paren of the user spec,
            # e.g. "(root) NOPASSWD: /usr/bin/find" -> "NOPASSWD: /usr/bin/find"
            after_paren = stripped.split(")", 1)
            if len(after_paren) > 1:
                cmd_part = after_paren[1].strip()
            else:
                cmd_part = stripped

            if cmd_part.upper().startswith("NOPASSWD:"):
                cmd_part = cmd_part[len("NOPASSWD:"):].strip()

            # Split on commas for multi-command entries
            commands = [c.strip() for c in cmd_part.split(",") if c.strip()]

            entries.append({
                "raw": stripped,
                "nopasswd": nopasswd,
                "commands": commands,
            })

    return entries


def score_entry(entry):
    """
    Score a parsed sudo entry. Returns a list of finding dicts, since a
    single entry can contain multiple commands, each scored separately.
    """
    findings = []

    for cmd in entry["commands"]:
        risk = "INFO"
        note = "Allowed via sudo, but not matched against a known high-risk pattern. Manually review."

        if cmd == "ALL":
            risk = "HIGH"
            note = "ALL commands allowed via sudo - full command execution as the target user."
        else:
            # Extract just the binary name for matching, ignoring any
            # arguments or wildcards that follow (e.g. "/usr/bin/vim *"
            # -> "vim").
            cmd_path = cmd.split(" ")[0]
            basename = cmd_path.split("/")[-1]

            if basename in KNOWN_EXPLOITABLE:
                risk = "HIGH"
                note = KNOWN_EXPLOITABLE[basename]
            elif "*" in cmd:
                risk = "HIGH"
                note = "Wildcard argument allowed - may permit passing unintended flags or arguments as root."

        if entry["nopasswd"] and risk == "HIGH":
            note = note + " No password required (NOPASSWD), making this immediately usable."

        findings.append({
            "command": cmd,
            "risk": risk,
            "note": note,
            "nopasswd": entry["nopasswd"],
            "raw_entry": entry["raw"],
        })

    return findings


def build_report(raw_sudo_output, could_run, needs_password, all_findings, whoami, id_out):
    """Build a markdown-formatted report string."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    high_findings = []
    info_findings = []
    for f in all_findings:
        if f["risk"] == "HIGH":
            high_findings.append(f)
        else:
            info_findings.append(f)

    lines = []
    lines.append("# PrivEscChecker - Sudo Misconfiguration Report")
    lines.append("")
    lines.append("**Scan time:** %s" % timestamp)
    lines.append("**Run as:** %s" % whoami)
    lines.append("**id output:** `%s`" % id_out)
    lines.append("")

    if not could_run:
        if needs_password:
            lines.append("**Result:** This user appears to have sudo access, but a ")
            lines.append("password is required and none was supplied (this scanner ")
            lines.append("never attempts an interactive password prompt). Run 'sudo -l' ")
            lines.append("manually with the account's password to see the actual allowed ")
            lines.append("commands, then re-run this scan interpreting that output by hand.")
        else:
            lines.append("**Result:** 'sudo -l' could not be run non-interactively. ")
            lines.append("This usually means no sudo entry exists for this user at all.")
        lines.append("")
        lines.append("---")
        return "\n".join(lines)

    lines.append("**Raw 'sudo -l' output:**")
    lines.append("```")
    lines.append(raw_sudo_output.strip())
    lines.append("```")
    lines.append("")
    lines.append("**HIGH risk findings:** %d" % len(high_findings))
    lines.append("**INFO findings:** %d" % len(info_findings))
    lines.append("")
    lines.append("---")
    lines.append("")

    if high_findings:
        lines.append("## HIGH Risk Findings (likely exploitable)")
        lines.append("")
        for f in high_findings:
            lines.append("### `%s`" % f["command"])
            lines.append("- **NOPASSWD:** %s" % f["nopasswd"])
            lines.append("- **Why this matters:** %s" % f["note"])
            lines.append("- **Sudoers entry:** `%s`" % f["raw_entry"])
            lines.append("")

    if info_findings:
        lines.append("## INFO - Allowed via Sudo, Not Flagged as High-Risk")
        lines.append("")
        lines.append("| Command | NOPASSWD | Sudoers Entry |")
        lines.append("|---|---|---|")
        for f in info_findings:
            lines.append("| `%s` | %s | `%s` |" % (
                f["command"], f["nopasswd"], f["raw_entry"]))
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("**Note:** This check only covers 'sudo -l' output for the current ")
    lines.append("user. It cannot see sudo rules that apply to other users or groups ")
    lines.append("the current user isn't a member of.")
    lines.append("")
    lines.append("**Scope reminder:** Run this only on systems you are authorized to ")
    lines.append("test (your own lab VMs, CTF machines you have legitimate access to).")

    return "\n".join(lines)


def parse_args(argv):
    """
    Minimal manual argument parser (no argparse - see suid_check.py for
    why). Supports: --output/-o <path> (also --output=<path>)
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
            print("Usage: python sudo_check.py [--output report.md]")
            sys.exit(0)
        else:
            print("[!] Unrecognized argument: %s" % arg)
            sys.exit(1)
        i = i + 1

    return result


def main():
    args = parse_args(sys.argv[1:])

    print("[*] PrivEscChecker - Sudo Misconfiguration Scan")
    print("[*] Running 'sudo -l' (non-interactive)...")
    print("")

    whoami, id_out = get_current_user_context()
    print("[*] Running as: %s" % whoami)
    print("[*] id: %s" % id_out)
    print("")

    raw_output, could_run, needs_password = get_sudo_l_output()

    if not could_run:
        if needs_password:
            print("[!] This user appears to have sudo access, but it requires a password.")
            print("[!] This scanner never attempts an interactive password prompt.")
            print("[!] Run 'sudo -l' manually with the password to see the real entry.")
        else:
            print("[!] Could not run 'sudo -l' non-interactively.")
            print("[!] This user likely has no sudo entry at all.")
        print("")
        if args.output:
            report = build_report(raw_output, could_run, needs_password, [], whoami, id_out)
            fh = open(args.output, "w")
            try:
                fh.write(report)
            finally:
                fh.close()
            print("[*] Report saved to: %s" % args.output)
        return

    print("[*] Raw sudo -l output:")
    print(raw_output)

    entries = parse_sudo_entries(raw_output)
    all_findings = []
    for entry in entries:
        all_findings.extend(score_entry(entry))

    high = [f for f in all_findings if f["risk"] == "HIGH"]
    info = [f for f in all_findings if f["risk"] == "INFO"]

    print("[*] Scan complete. %d sudo entries parsed." % len(all_findings))
    print("[!] %d HIGH risk findings." % len(high))
    print("[i] %d INFO findings." % len(info))
    print("")

    if high:
        print("=" * 60)
        print("HIGH RISK FINDINGS")
        print("=" * 60)
        for f in high:
            print("")
            print("[HIGH] %s" % f["command"])
            print("        NOPASSWD=%s" % f["nopasswd"])
            print("        -> %s" % f["note"])
        print("")

    if args.output:
        report = build_report(raw_output, could_run, needs_password, all_findings, whoami, id_out)
        fh = open(args.output, "w")
        try:
            fh.write(report)
        finally:
            fh.close()
        print("[*] Full report saved to: %s" % args.output)


if __name__ == "__main__":
    main()
