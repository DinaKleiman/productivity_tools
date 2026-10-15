#!/usr/bin/env python3
"""Verify a signed .shortcut file: "anyone" mode, valid Apple signature, contents match the source plist.

Usage: verify_shortcut.py <file.shortcut> <source.plist>
Needs macOS tools: aea, aa, openssl.
"""
import plistlib
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

# The Mac stamps this key with its own Shortcuts version when it signs; it is metadata, not content.
IGNORED_KEYS = {"WFWorkflowClientVersion"}


def inspect(shortcut, source, work):
    """Return ([(name, passed, detail), ...], inner_plist_or_None)."""
    checks = []

    def check(name, passed, detail=""):
        checks.append((name, bool(passed), detail))

    work = Path(work)
    work.mkdir(parents=True, exist_ok=True)
    try:
        data = Path(shortcut).read_bytes()
    except OSError as e:
        check("shortcut file readable", False, str(e))
        return checks, None

    if data[:4] != b"AEA1":
        check("signed container (AEA1)", False, f"starts with {data[:4]!r}; not a signed shortcut")
        return checks, None
    check("signed container (AEA1)", True)

    try:
        n = struct.unpack("<I", data[8:12])[0]
        auth = plistlib.loads(data[12:12 + n])
        chain = auth["SigningCertificateChain"]
    except Exception as e:  # malformed header
        check("signature header readable", False, str(e))
        return checks, None

    check("signature section has only SigningCertificateChain",
          sorted(auth) == ["SigningCertificateChain"], str(sorted(auth)))
    check("no AppleIDValidationRecord (anyone mode, not contacts mode)", "AppleIDValidationRecord" not in auth)

    try:
        info = subprocess.run(["openssl", "x509", "-inform", "DER", "-noout", "-subject", "-issuer"],
                              input=chain[0], capture_output=True, check=True).stdout.decode()
        pub = subprocess.run(["openssl", "x509", "-inform", "DER", "-pubkey", "-noout"],
                             input=chain[0], capture_output=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError) as e:
        check("certificate readable (openssl)", False, str(e))
        return checks, None

    check("certificate issued by Apple System Integration CA", "issuer=CN=Apple System Integration CA" in info)
    cn = re.search(r"subject=CN=([^,\n]+)", info)
    check("certificate name is an opaque hash, not a person",
          bool(cn) and re.fullmatch(r"[0-9a-f]{32}", cn.group(1)) is not None, cn.group(1) if cn else "no CN")

    pub_path, aar, out = work / "pub.pem", work / "out.aar", work / "out"
    pub_path.write_bytes(pub)
    out.mkdir(exist_ok=True)
    try:
        r = subprocess.run(["aea", "decrypt", "-i", str(shortcut), "-o", str(aar), "-sign-pub", str(pub_path)],
                           capture_output=True)
        check("signature valid (aea decrypt)", r.returncode == 0, r.stderr.decode().strip())
        if r.returncode != 0:
            return checks, None
        subprocess.run(["aa", "extract", "-i", str(aar), "-d", str(out)], check=True, capture_output=True)
        inner = plistlib.loads((out / "Shortcut.wflow").read_bytes())
    except (OSError, subprocess.CalledProcessError) as e:
        check("shortcut unpacked (aa extract)", False, str(e))
        return checks, None

    try:
        src = plistlib.loads(Path(source).read_bytes())
    except OSError as e:
        check("source plist readable", False, str(e))
        return checks, inner
    differs = sorted(k for k in set(inner) | set(src) if inner.get(k) != src.get(k) and k not in IGNORED_KEYS)
    check("contents match the source plist", not differs, f"differs in: {differs}" if differs else "")
    return checks, inner


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    with tempfile.TemporaryDirectory() as work:
        checks, _ = inspect(sys.argv[1], sys.argv[2], work)
    for name, passed, detail in checks:
        print(f"{'PASS' if passed else 'FAIL'}  {name}{'  - ' + detail if detail else ''}")
    sys.exit(0 if all(p for _, p, _ in checks) else 1)


if __name__ == "__main__":
    main()
