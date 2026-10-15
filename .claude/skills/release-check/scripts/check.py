#!/usr/bin/env python3
"""release-check: security and privacy checks for this repo.

Modes:
  pre-commit [--staged-only]   scan what is about to be committed
  pre-release X.Y.Z            check the built shortcut, the git history and the source archive before publishing
  post-publish X.Y.Z           check what GitHub actually serves after publishing

Exit code 1 if any check FAILS. Warnings do not fail.
Personal terms (family names etc.) are read from denylist.local.txt, which git ignores.
"""
import argparse
import hashlib
import io
import json
import os
import plistlib
import re
import subprocess
import shutil
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import verify_shortcut  # noqa: E402

REPO = "DinaKleiman/productivity_tools"
NOREPLY = "62329901+DinaKleiman@users.noreply.github.com"
ALLOWED_EMAIL = re.compile(r"(@users\.noreply\.github\.com|^noreply@anthropic\.com|^noreply@github\.com)$", re.I)
PLIST_GLOB = "IphoneShortcuts/*.plist"
SOURCE_PLIST = "IphoneShortcuts/iphone_create_calendar_event.plist"
MAX_SCAN_BYTES = 5_000_000

SECRET_PATTERNS = [
    ("API key (sk-...)", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}")),
    ("GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})")),
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}")),
    ("private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{5,}")),
    ("credential assignment", re.compile(
        r"""(?i)\b(?:api[_-]?key|secret|access[_-]?token|auth[_-]?token|password|passwd|bearer)\b["']?\s*[:=]\s*["']?[A-Za-z0-9/+_.=-]{8,}""")),
]
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
PHONE_RE = re.compile(r"(?<![\w.])\+?\d[\d ()-]{7,}\d(?![\w.])")
UUID_RE = re.compile(r"\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b")
HEX_RE = re.compile(r"\b[0-9a-fA-F]{32,}\b")
DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}(?::\d{2})?)?")
FORBIDDEN_RE = re.compile(
    r"(?i)(\.shortcut$|(^|/)\.env(\..*)?$|\.(pem|key|p12|pfx|crt|cer|jks)$|(^|/)id_(rsa|dsa|ecdsa|ed25519)"
    r"|(^|/)credentials(\.\w+)?$|denylist\.local\.txt$|(^|/)\.DS_Store$)")
SHOULD_BE_IGNORED = ["x.shortcut", ".DS_Store", ".env", "x.pem", "x.key",
                     ".claude/skills/release-check/denylist.local.txt"]


def mask(s):
    return f"{s[:2]}... ({len(s)} chars)"


class Report:
    def __init__(self):
        self.fails = self.warns = self.passes = 0

    def add(self, name, passed, detail=""):
        self.passes += 1 if passed else 0
        self.fails += 0 if passed else 1
        print(f"{'PASS' if passed else 'FAIL'}  {name}{'  - ' + detail if detail else ''}")

    def warn(self, name, detail=""):
        self.warns += 1
        print(f"WARN  {name}{'  - ' + detail if detail else ''}")

    def findings(self, name, items):
        """One check that fails if any item was found; print each item."""
        items = sorted(set(items))
        self.add(name, not items, f"{len(items)} finding(s)" if items else "")
        for item in items[:25]:
            print(f"        {item}")
        if len(items) > 25:
            print(f"        ... and {len(items) - 25} more")

    def finish(self):
        print()
        if self.fails:
            print(f"RESULT: FAILED ({self.fails} failed, {self.warns} warning(s), {self.passes} passed). Do not commit/publish.")
            return 1
        print(f"RESULT: ALL CHECKS PASSED ({self.warns} warning(s), {self.passes} passed).")
        return 0


class Scanner:
    def __init__(self, denylist_path):
        self.deny = []
        self.denylist_path = Path(denylist_path) if denylist_path else None
        if self.denylist_path and self.denylist_path.exists():
            for raw in self.denylist_path.read_text(encoding="utf-8").splitlines():
                term = raw.strip()
                if not term or term.startswith("#"):
                    continue
                pat = re.escape(term)
                if term.isascii() and term.isalpha():  # plain words match whole words only
                    pat = rf"(?<!\w){pat}(?!\w)"
                self.deny.append((term, re.compile(pat, re.I)))

    def scan_text(self, text, where):
        found = []
        for n, line in enumerate(text.splitlines(), 1):
            for term, rx in self.deny:
                if rx.search(line):
                    found.append(f"{where}:{n}: denylist term {mask(term)}")
            for kind, rx in SECRET_PATTERNS:
                m = rx.search(line)
                if m:
                    found.append(f"{where}:{n}: {kind} {mask(m.group(0))}")
            clean = DATE_RE.sub(" ", HEX_RE.sub(" ", UUID_RE.sub(" ", line)))
            for m in EMAIL_RE.finditer(clean):
                if not ALLOWED_EMAIL.search(m.group(0)):
                    found.append(f"{where}:{n}: email address {mask(m.group(0))}")
            for m in PHONE_RE.finditer(clean):
                if sum(c.isdigit() for c in m.group(0)) >= 9:
                    found.append(f"{where}:{n}: phone-like number {mask(m.group(0))}")
        return found

    def scan_files(self, files, report, label):
        """files: {path: bytes}. Reports forbidden file names and findings in text content."""
        forbidden = [p for p in files if FORBIDDEN_RE.search(p)]
        report.findings(f"{label}: no forbidden files (shortcut, .env, keys, denylist)", [f"forbidden file: {p}" for p in forbidden])
        found, skipped = [], []
        for path, data in files.items():
            if len(data) > MAX_SCAN_BYTES or b"\0" in data[:8192]:
                skipped.append(path)
                continue
            found += self.scan_text(data.decode("utf-8", errors="replace"), path)
        report.findings(f"{label}: no secrets, personal terms, emails or phone numbers", found)
        if skipped:
            report.warn(f"{label}: binary/large files not scanned", ", ".join(sorted(skipped)[:10]))


class Ctx:
    def __init__(self, root, scanner):
        self.root, self.scanner = Path(root), scanner

    def git(self, *args, check=True):
        r = subprocess.run(["git", "-C", str(self.root), *args], capture_output=True)
        if check and r.returncode != 0:
            raise RuntimeError(f"git {' '.join(args)} failed: {r.stderr.decode(errors='replace').strip()}")
        return r

    def git_names(self, *args):
        out = self.git(*args).stdout
        return [p.decode("utf-8", errors="replace") for p in out.split(b"\0") if p]


# ---------------------------------------------------------------- shared checks
def check_gitignore(ctx, rep):
    missing = [p for p in SHOULD_BE_IGNORED
               if ctx.git("check-ignore", "-q", "--no-index", p, check=False).returncode != 0]
    rep.add(".gitignore protects shortcut files, .env, keys, denylist", not missing,
            f"not ignored: {missing}" if missing else "")


def walk_keys(node, key):
    if isinstance(node, dict):
        for k, v in node.items():
            if k == key:
                yield v
            yield from walk_keys(v, key)
    elif isinstance(node, list):
        for v in node:
            yield from walk_keys(v, key)


def check_plists(ctx, rep):
    plists = sorted(ctx.root.glob(PLIST_GLOB))
    for p in plists:
        rel = p.relative_to(ctx.root)
        r = subprocess.run(["plutil", "-lint", str(p)], capture_output=True, text=True) if shutil.which("plutil") else None
        if r is None:
            rep.warn(f"{rel}: plutil not available, lint skipped")
        else:
            rep.add(f"{rel}: valid plist (plutil -lint)", r.returncode == 0, r.stdout.strip() if r.returncode else "")
        try:
            data = plistlib.loads(p.read_bytes())
        except Exception as e:
            rep.add(f"{rel}: readable plist", False, str(e))
            continue
        rep.add(f"{rel}: no device-specific calendar (WFCalendarDescriptor)", not list(walk_keys(data, "WFCalendarDescriptor")))


def check_identity(ctx, rep):
    email = ctx.git("config", "user.email", check=False).stdout.decode().strip()
    if email == NOREPLY or ALLOWED_EMAIL.search(email):
        rep.add("git identity uses the GitHub no-reply address", True)
    else:
        rep.warn("git identity is not the no-reply address", f"user.email = {email or '(unset)'}; use {NOREPLY}")


# ---------------------------------------------------------------- modes
def pre_commit(ctx, rep, staged_only):
    files = {}
    for p in ctx.git_names("diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"):
        files[p] = ctx.git("show", f":{p}").stdout
    n_staged = len(files)
    if not staged_only:
        extra = ctx.git_names("diff", "--name-only", "--diff-filter=ACMR", "-z") + \
            ctx.git_names("ls-files", "--others", "--exclude-standard", "-z")
        for p in extra:
            f = ctx.root / p
            if p not in files and f.is_file():
                files[p] = f.read_bytes()
    label = "staged files" if staged_only else f"staged + modified + new files ({n_staged} staged)"
    print(f"scanning {len(files)} file(s): {label}")
    ctx.scanner.scan_files(files, rep, "files")
    check_gitignore(ctx, rep)
    check_plists(ctx, rep)
    check_identity(ctx, rep)
    if ctx.scanner.denylist_path is None or not ctx.scanner.deny:
        rep.warn("no personal denylist loaded", "copy denylist.example.txt to denylist.local.txt and add real names")


def scan_archive_bytes(ctx, rep, data, kind, label):
    files = {}
    try:
        if kind == "zip":
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                for i in z.infolist():
                    if not i.is_dir():
                        files[i.filename] = z.read(i)
        else:
            with tarfile.open(fileobj=io.BytesIO(data)) as t:
                for m in t.getmembers():
                    if m.isfile():
                        files[m.name] = t.extractfile(m).read()
    except Exception as e:
        rep.add(f"{label}: archive readable", False, str(e))
        return
    ctx.scanner.scan_files(files, rep, label)


def scan_shortcut_contents(ctx, rep, inner, label):
    text = plistlib.dumps(inner).decode("utf-8", errors="replace")
    rep.findings(f"{label}: contents have no secrets, personal terms, emails or phone numbers",
                 ctx.scanner.scan_text(text, "shortcut"))


def pre_release(ctx, rep, ver):
    pre_commit(ctx, rep, staged_only=False)
    name = f"iphone_create_calendar_event.public.v{ver}.shortcut"
    path = ctx.root / "IphoneShortcuts" / name
    if not path.exists():
        rep.add(f"signed shortcut exists: {name}", False, "build and sign it first")
    else:
        rep.add(f"signed shortcut exists: {name}", True)
        with tempfile.TemporaryDirectory() as work:
            checks, inner = verify_shortcut.inspect(path, ctx.root / SOURCE_PLIST, work)
        for n, ok, d in checks:
            rep.add(f"shortcut: {n}", ok, d)
        if inner is not None:
            scan_shortcut_contents(ctx, rep, inner, "shortcut")

    commits = ctx.git("rev-list", "--all").stdout.decode().split()
    found = []
    for sha in commits:
        text = ctx.git("show", "--format=%B", "--no-color", sha).stdout.decode("utf-8", errors="replace")
        found += ctx.scanner.scan_text(text, f"commit {sha[:7]}")
    rep.findings(f"git history ({len(commits)} commits): no secrets, personal terms, emails or phone numbers", found)
    files_ever = set(ctx.git("log", "--all", "--name-only", "--format=").stdout.decode().splitlines()) - {""}
    rep.findings("git history: no forbidden file was ever committed",
                 [f"forbidden file in history: {p}" for p in files_ever if FORBIDDEN_RE.search(p)])
    authors = set(ctx.git("log", "--all", "--format=%ae%n%ce").stdout.decode().split())
    bad = sorted(a for a in authors if not ALLOWED_EMAIL.search(a))
    if bad:
        rep.warn("git history has non-no-reply author/committer emails (accepted, history not rewritten)", ", ".join(bad))
    else:
        rep.add("git history: all author/committer emails are no-reply addresses", True)

    tag = f"v{ver}"
    ref = tag if ctx.git("rev-parse", "-q", "--verify", f"refs/tags/{tag}", check=False).returncode == 0 else "HEAD"
    archive = ctx.git("archive", "--format=tar", ref).stdout
    scan_archive_bytes(ctx, rep, archive, "tar", f"source archive of {ref}")
    if ctx.git("status", "--porcelain").stdout.strip():
        rep.warn("working tree has uncommitted changes", "commit them before tagging a release")


def post_publish(ctx, rep, ver):
    tag, name = f"v{ver}", f"iphone_create_calendar_event.public.v{ver}.shortcut"
    r = subprocess.run(["gh", "release", "view", tag, "-R", REPO, "--json", "tagName,isDraft,isPrerelease,assets,body"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        rep.add(f"release {tag} exists on GitHub", False, r.stderr.strip())
        return
    rel = json.loads(r.stdout)
    rep.add(f"release {tag} exists and is published (not a draft)", not rel["isDraft"])
    names = [a["name"] for a in rel["assets"]]
    rep.add("release has exactly one uploaded file, with the versioned name", names == [name], f"assets: {names}")

    with tempfile.TemporaryDirectory() as work:
        work = Path(work)
        dl = work / name
        r = subprocess.run(["gh", "release", "download", tag, "-R", REPO, "-D", str(work), "-p", name], capture_output=True, text=True)
        if r.returncode != 0 or not dl.exists():
            rep.add("downloaded the release file", False, r.stderr.strip())
        else:
            sha = hashlib.sha256(dl.read_bytes()).hexdigest()
            digest = next((a.get("digest") for a in rel["assets"] if a["name"] == name), None)
            rep.add("downloaded file matches GitHub's digest", digest == f"sha256:{sha}", f"sha256 {sha[:12]}...")
            local = ctx.root / "IphoneShortcuts" / name
            if local.exists():
                rep.add("downloaded file is identical to the local build", hashlib.sha256(local.read_bytes()).hexdigest() == sha)
            else:
                rep.warn("local copy not found, identical-to-local check skipped")
            checks, inner = verify_shortcut.inspect(dl, ctx.root / SOURCE_PLIST, work / "v")
            for n, ok, d in checks:
                rep.add(f"downloaded shortcut: {n}", ok, d)
            if inner is not None:
                scan_shortcut_contents(ctx, rep, inner, "downloaded shortcut")

    body = rel["body"] or ""
    rep.findings("release notes: no secrets, personal terms, emails or phone numbers", ctx.scanner.scan_text(body, "release notes"))
    if name in body:
        rep.add("release notes name the current file", True)
    else:
        rep.warn("release notes do not mention the current file name", name)

    for kind, endpoint in (("zip", "zipball"), ("tar", "tarball")):
        r = subprocess.run(["gh", "api", f"repos/{REPO}/{endpoint}/{tag}"], capture_output=True)
        label = f"GitHub source {'zip' if kind == 'zip' else 'tar.gz'}"
        if r.returncode != 0:
            rep.add(f"{label} downloaded", False, r.stderr.decode(errors="replace").strip())
        else:
            scan_archive_bytes(ctx, rep, r.stdout, kind, label)

    for label, url in (("latest release page", f"https://github.com/{REPO}/releases/latest"),
                       ("release file link", f"https://github.com/{REPO}/releases/download/{tag}/{name}")):
        out = subprocess.run(["curl", "-sIL", "-o", os.devnull, "-w", "%{http_code}", url], capture_output=True, text=True).stdout.strip()
        rep.add(f"link works: {label}", out == "200", f"HTTP {out}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", choices=["pre-commit", "pre-release", "post-publish"])
    ap.add_argument("version", nargs="?", help="X.Y.Z for pre-release / post-publish")
    ap.add_argument("--staged-only", action="store_true", help="pre-commit: scan only staged files (used by the git hook)")
    ap.add_argument("--root", default=str(HERE.parents[3]), help="repository root")
    ap.add_argument("--denylist", default=os.environ.get("RELEASE_CHECK_DENYLIST", str(HERE.parent / "denylist.local.txt")))
    a = ap.parse_args()
    if a.mode != "pre-commit" and not (a.version and re.fullmatch(r"\d+\.\d+\.\d+", a.version)):
        ap.error(f"{a.mode} needs a version like 0.0.1")

    ctx, rep = Ctx(a.root, Scanner(a.denylist)), Report()
    print(f"release-check {a.mode}{' ' + a.version if a.version else ''}\n")
    if a.mode == "pre-commit":
        pre_commit(ctx, rep, a.staged_only)
    elif a.mode == "pre-release":
        pre_release(ctx, rep, a.version)
    else:
        post_publish(ctx, rep, a.version)
    sys.exit(rep.finish())


if __name__ == "__main__":
    main()
