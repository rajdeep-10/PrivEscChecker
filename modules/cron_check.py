#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
cron_check.py - Cron Job Privilege Escalation Checker (standalone module)
Part of the PrivEscChecker project.

NOTE: This is one of three standalone checks that were built and tested
individually before being combined into ../privesc_check.py, which is
the primary tool for this project (runs all three checks together with
a unified, severity-tiered report). This file is kept in the repo to
show the incremental development process and because it's still useful
on its own if you only want the cron check specifically.

Reads system-wide cron job definitions (/etc/crontab and /etc/cron.d/*)
and flags any job whose target script (or a directory in its path) is
writable by the current user or world-writable. If a root-run cron job
executes a script you can modify, root will run your code the next time
the job fires.

Written in the same Python 2.5.2-safe style as suid_check.py and
sudo_check.py: no str.format(), no 'with' statement, no argparse, no
'bytes' builtin usage - all of these are missing or broken on very old
Python 2 (confirmed against Python 2.5.2 on Metasploitable2).

USAGE:
    python cron_check.py
    python cron_check.py --output report.md

Intended for use on Linux systems you are authorized to test
(e.g. your own lab VMs, CTF machines you have legitimate access to).
"""

import os
import sys
import stat
import subprocess
from datetime import datetime

CRON_LOCATIONS = [
    "/etc/crontab",
]

CRON_D_DIR = "/etc/cron.d"


def run_cmd(cmd_list):
    """
    Run a command and return (stdout, returncode).
    Same Python 2.5.2-safe pattern as the other modules - no 'bytes'
    builtin usage, since it doesn't exist before Python 2.6.
    """
    try:
        proc = subprocess.Popen(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate()
        if not isinstance(out, str):
            out = out.decode("utf-8", "replace")
        return out, proc.returncode
    except Exception:
        return "", -1


def get_current_user_context():
    """Grab basic context: current user, id output, for the report header."""
    whoami_out, _ = run_cmd(["whoami"])
    id_out, _ = run_cmd(["id"])
    return whoami_out.strip(), id_out.strip()


def get_current_uid_and_groups():
    """
    Return (uid, list_of_gids) for the current process, using os.getuid
    and os.getgroups - both available since very early Python 2.
    """
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


def list_cron_d_files():
    """List full paths of files inside /etc/cron.d, if it exists and is readable."""
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
    """
    Parse a single crontab-style line into (user, command), or return
    None if the line isn't a real job entry (comment, blank, env var
    assignment like PATH=... or SHELL=...).

    /etc/crontab and /etc/cron.d files have this format:
        minute hour day month weekday user command
    (unlike a per-user crontab, which omits the 'user' field.)
    """
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    if "=" in stripped.split(" ")[0]:
        # Looks like an environment variable assignment, e.g. PATH=...
        return None

    parts = stripped.split(None, 6)
    # Expect at least: minute hour day month weekday user command...
    if len(parts) < 7:
        return None

    user = parts[5]
    command = parts[6]
    return user, command


def extract_script_path(command):
    """
    Try to extract the actual executed script/binary path from a cron
    command string.

    Naively taking the first token starting with "/" is wrong for
    commands with shell conditionals, e.g.:
        test -e /run/systemd/system || SERVICE_MODE=1 /path/to/real_script
    The first "/"-prefixed token here is part of a test/existence check,
    not the command that actually runs. This function instead looks
    for command separators (&&, ||, ;) and takes the path-like token
    from the LAST segment, which is where cron.d's systemd-guard
    pattern (test -e ... || real_command) places the real command.

    This is still a best-effort heuristic, not a full shell parser -
    complex pipelines or multiple real commands may need manual review,
    which is why anything ambiguous should fall through to INFO rather
    than a confident HIGH/INFO call either way.
    """
    # Split on common shell command separators, keep the last segment,
    # since that's where the real command lives after a guard clause.
    segment = command
    for separator in ["||", "&&", ";"]:
        if separator in segment:
            segment = segment.split(separator)[-1]

    tokens = segment.split()
    for token in tokens:
        if token.startswith("/"):
            return token
        # Skip over VAR=value assignments (e.g. SERVICE_MODE=1) that
        # commonly precede the real command in cron.d entries.
        if "=" in token and not token.startswith("/"):
            continue

    return None


def check_path_writable(path, current_uid, current_gids):
    """
    Check whether the given path (or any parent directory of it) is
    writable by the current user - either because they own it and have
    owner-write permission, are in the owning group with group-write
    permission, or it's world-writable.

    Returns a list of (checked_path, reason) tuples describing any
    writable component found. An empty list means nothing writable was
    found (at least not by permission bits alone).
    """
    writable_findings = []

    # Check the target file itself, then walk up each parent directory,
    # since a writable parent directory would let you delete/replace
    # the file entirely, which is just as exploitable.
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
        owner_uid = st.st_uid
        owner_gid = st.st_gid

        world_writable = bool(mode & stat.S_IWOTH)
        group_writable = bool(mode & stat.S_IWGRP)
        owner_writable = bool(mode & stat.S_IWUSR)

        if world_writable:
            writable_findings.append((check_path, "world-writable"))
        elif owner_writable and owner_uid == current_uid:
            writable_findings.append((check_path, "owned and writable by current user"))
        elif group_writable and owner_gid in current_gids:
            writable_findings.append((check_path, "group-writable, current user is in that group"))

    return writable_findings


def gather_cron_jobs():
    """
    Read all system cron job sources and return a list of dicts:
    {"source": file_path, "user": cron_user, "command": raw_command}
    """
    jobs = []
    sources = list(CRON_LOCATIONS)
    sources.extend(list_cron_d_files())

    for source in sources:
        content = read_file_safely(source)
        if content is None:
            continue
        for line in content.split("\n"):
            parsed = parse_crontab_line(line)
            if parsed is not None:
                user, command = parsed
                jobs.append({
                    "source": source,
                    "user": user,
                    "command": command,
                })

    return jobs


def score_job(job, current_uid, current_gids):
    """
    Score a single cron job entry. Returns a finding dict.
    """
    script_path = extract_script_path(job["command"])

    if script_path is None:
        return {
            "source": job["source"],
            "cron_user": job["user"],
            "command": job["command"],
            "risk": "INFO",
            "note": "Could not identify a specific script path in this command; manual review recommended.",
            "writable_paths": [],
        }

    writable = check_path_writable(script_path, current_uid, current_gids)

    if writable and job["user"] in ("root",):
        reasons = "; ".join(["%s (%s)" % (p, r) for p, r in writable])
        return {
            "source": job["source"],
            "cron_user": job["user"],
            "command": job["command"],
            "risk": "HIGH",
            "note": "This job runs as root and its script path (or a parent directory) is writable: %s" % reasons,
            "writable_paths": writable,
        }
    elif writable:
        reasons = "; ".join(["%s (%s)" % (p, r) for p, r in writable])
        return {
            "source": job["source"],
            "cron_user": job["user"],
            "command": job["command"],
            "risk": "INFO",
            "note": "Script path is writable, but job does not run as root: %s" % reasons,
            "writable_paths": writable,
        }
    else:
        return {
            "source": job["source"],
            "cron_user": job["user"],
            "command": job["command"],
            "risk": "INFO",
            "note": "No writable path found for this job's script.",
            "writable_paths": [],
        }


def build_report(jobs_found, all_findings, could_read_crontab, whoami, id_out):
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
    lines.append("# PrivEscChecker - Cron Job Scan Report")
    lines.append("")
    lines.append("**Scan time:** %s" % timestamp)
    lines.append("**Run as:** %s" % whoami)
    lines.append("**id output:** `%s`" % id_out)
    lines.append("")

    if not could_read_crontab:
        lines.append("**Result:** /etc/crontab and /etc/cron.d could not be read. ")
        lines.append("This user may not have permission to view system cron jobs.")
        lines.append("")
        lines.append("---")
        return "\n".join(lines)

    lines.append("**Total cron jobs found:** %d" % len(jobs_found))
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
            lines.append("- **Source:** `%s`" % f["source"])
            lines.append("- **Runs as:** %s" % f["cron_user"])
            lines.append("- **Why this matters:** %s" % f["note"])
            lines.append("")

    if info_findings:
        lines.append("## INFO - Cron Jobs Found, Not Flagged as High-Risk")
        lines.append("")
        lines.append("| Command | Source | Runs As | Note |")
        lines.append("|---|---|---|---|")
        for f in info_findings:
            lines.append("| `%s` | `%s` | %s | %s |" % (
                f["command"], f["source"], f["cron_user"], f["note"]))
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("**Note:** This check only covers system-wide cron jobs in /etc/crontab ")
    lines.append("and /etc/cron.d. It does not check per-user crontabs (crontab -l for ")
    lines.append("other users), which typically require elevated privileges to read anyway.")
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
            print("Usage: python cron_check.py [--output report.md]")
            sys.exit(0)
        else:
            print("[!] Unrecognized argument: %s" % arg)
            sys.exit(1)
        i = i + 1

    return result


def main():
    args = parse_args(sys.argv[1:])

    print("[*] PrivEscChecker - Cron Job Scan")
    print("[*] Reading /etc/crontab and /etc/cron.d...")
    print("")

    whoami, id_out = get_current_user_context()
    print("[*] Running as: %s" % whoami)
    print("[*] id: %s" % id_out)
    print("")

    current_uid, current_gids = get_current_uid_and_groups()

    jobs = gather_cron_jobs()
    could_read = (read_file_safely("/etc/crontab") is not None) or (len(list_cron_d_files()) > 0)

    if not could_read:
        print("[!] Could not read /etc/crontab or /etc/cron.d.")
        print("[!] This user may not have permission to view system cron jobs.")
        print("")
        if args.output:
            report = build_report([], [], could_read, whoami, id_out)
            fh = open(args.output, "w")
            try:
                fh.write(report)
            finally:
                fh.close()
            print("[*] Report saved to: %s" % args.output)
        return

    all_findings = []
    for job in jobs:
        all_findings.append(score_job(job, current_uid, current_gids))

    high = [f for f in all_findings if f["risk"] == "HIGH"]
    info = [f for f in all_findings if f["risk"] == "INFO"]

    print("[*] Scan complete. %d cron jobs found." % len(jobs))
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
            print("        Source: %s" % f["source"])
            print("        Runs as: %s" % f["cron_user"])
            print("        -> %s" % f["note"])
        print("")

    if args.output:
        report = build_report(jobs, all_findings, could_read, whoami, id_out)
        fh = open(args.output, "w")
        try:
            fh.write(report)
        finally:
            fh.close()
        print("[*] Full report saved to: %s" % args.output)


if __name__ == "__main__":
    main()
