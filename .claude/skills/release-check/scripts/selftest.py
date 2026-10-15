#!/usr/bin/env python3
"""Self-test for release-check: it must catch planted problems and accept clean input.

Builds throwaway git repos in a temp folder. Fake secrets are assembled at run time,
so this file does not contain anything the scanner would flag.

Usage: python3 selftest.py
"""
import os
import plistlib
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
CHECK = HERE / "check.py"
HOOKS = ROOT / "scripts" / "hooks"
NOREPLY = "1+tester@users.noreply.github.com"

FAKE_KEY = "s" + "k-" + "A1b2C3d4" * 4
FAKE_EMAIL = "someone" + "@" + "example.org"
FAKE_PHONE = "+972" + " 50" + " 123" + " 4567"
FAKE_NAME = "Testname"

results = []


def sh(cwd, *cmd, env=None):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, env=env)


def new_repo(tmp, name):
    repo = Path(tmp) / name
    repo.mkdir()
    sh(repo, "git", "init", "-q")
    sh(repo, "git", "config", "user.email", NOREPLY)
    sh(repo, "git", "config", "user.name", "Tester")
    sh(repo, "git", "config", "commit.gpgsign", "false")
    (repo / ".gitignore").write_text((ROOT / ".gitignore").read_text())
    (repo / "README.md").write_text("A harmless readme.\n")
    sh(repo, "git", "add", ".gitignore", "README.md")
    return repo


def run_check(repo, denylist):
    env = dict(os.environ, RELEASE_CHECK_DENYLIST=str(denylist))
    return sh(repo, sys.executable, str(CHECK), "pre-commit", "--staged-only", "--root", str(repo), env=env)


def expect(name, repo, denylist, want_fail, needle=""):
    r = run_check(repo, denylist)
    out = r.stdout + r.stderr
    ok = (r.returncode == 1) == want_fail and (needle in out if needle else True)
    results.append(ok)
    print(f"{'PASS' if ok else 'FAIL'}  {name}  (exit {r.returncode}{', saw: ' + needle if needle and ok else ''})")
    if not ok:
        print(out)


def main():
    with tempfile.TemporaryDirectory() as tmp:
        deny = Path(tmp) / "deny.txt"
        deny.write_text(f"{FAKE_NAME}\n")

        repo = new_repo(tmp, "clean")
        (repo / "notes.txt").write_text(f"Contact {NOREPLY} on 2026-10-20 10:00, id 760CC2D0-3045-421E-BE26-D0DB3B7181A6\n")
        sh(repo, "git", "add", "notes.txt")
        expect("clean files are accepted (no-reply email, dates, UUIDs allowed)", repo, deny, False)

        cases = [
            ("API key is caught", "config.txt", f"value = {FAKE_KEY}\n", "API key"),
            ("credential assignment is caught", "app.cfg", "pass" + "word = " + "hunter2hunter2\n", "credential assignment"),
            ("personal denylist term is caught", "msg.txt", f"Dinner with {FAKE_NAME} tonight\n", "denylist term"),
            ("real email address is caught", "mail.txt", f"write to {FAKE_EMAIL}\n", "email address"),
            ("phone number is caught", "tel.txt", f"call {FAKE_PHONE}\n", "phone-like"),
            ("private key block is caught", "k.txt", "-----BEGIN " + "RSA PRIVATE KEY-----\n", "private key"),
        ]
        for name, fname, content, needle in cases:
            repo = new_repo(tmp, fname.replace(".", "_"))
            (repo / fname).write_text(content)
            sh(repo, "git", "add", fname)
            expect(name, repo, deny, True, needle)

        for name, fname in [("staged .shortcut file is blocked", "x.shortcut"), ("staged .env file is blocked", ".env"),
                            ("staged private-key file is blocked", "id.pem")]:
            repo = new_repo(tmp, "f_" + fname.replace(".", "_"))
            (repo / fname).write_text("data\n")
            sh(repo, "git", "add", "-f", fname)
            expect(name, repo, deny, True, "forbidden file")

        repo = new_repo(tmp, "cal")
        (repo / "IphoneShortcuts").mkdir()
        (repo / "IphoneShortcuts" / "x.plist").write_bytes(plistlib.dumps(
            {"WFWorkflowActions": [{"WFWorkflowActionParameters": {"WFCalendarDescriptor": {"Identifier": "abc"}}}]}))
        sh(repo, "git", "add", "IphoneShortcuts/x.plist")
        expect("device-specific calendar in plist is caught", repo, deny, True, "WFCalendarDescriptor")

        # the real git hook: a bad commit is refused, a good one goes through
        env = dict(os.environ, RELEASE_CHECK_DENYLIST=str(deny))
        repo = new_repo(tmp, "hook")
        sh(repo, "git", "config", "core.hooksPath", str(HOOKS))
        (repo / "secret.txt").write_text(f"token value {FAKE_KEY}\n")
        sh(repo, "git", "add", "secret.txt")
        r = sh(repo, "git", "commit", "-q", "-m", "bad", env=env)
        refused = r.returncode != 0 and sh(repo, "git", "rev-parse", "-q", "--verify", "HEAD").returncode != 0
        results.append(refused)
        print(f"{'PASS' if refused else 'FAIL'}  git hook refuses a commit that contains a secret")
        sh(repo, "git", "rm", "-q", "--cached", "secret.txt")
        r = sh(repo, "git", "commit", "-q", "-m", "good", env=env)
        accepted = r.returncode == 0
        results.append(accepted)
        print(f"{'PASS' if accepted else 'FAIL'}  git hook accepts a clean commit")
        if not accepted:
            print(r.stdout, r.stderr)

    print()
    print("SELFTEST:", "ALL PASSED" if all(results) else "FAILED", f"({sum(results)}/{len(results)})")
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
