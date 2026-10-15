---
name: release-check
description: Security and privacy checks for the productivity_tools repo (secrets, personal data, emails, shortcut signature mode, release file, source zips, release notes). Run pre-commit before every git commit or push, pre-release X.Y.Z before publishing a release, and post-publish X.Y.Z after publishing. Use whenever committing, pushing, tagging, releasing or publishing in this repo.
---

# release-check

One script runs every security check this repo needs. A **FAIL stops the work**: fix it first, never commit or publish around it. Warnings are informational.

```bash
python3 .claude/skills/release-check/scripts/check.py pre-commit            # before every commit/push
python3 .claude/skills/release-check/scripts/check.py pre-release 0.0.1     # before publishing a release
python3 .claude/skills/release-check/scripts/check.py post-publish 0.0.1    # after publishing
python3 .claude/skills/release-check/scripts/selftest.py                    # proves the checks catch problems
```

Show the commands to the user before running them, as for any git command. `post-publish` uses the network (`gh`, `curl`).

## When to run what

| Mode | When | What it checks |
|---|---|---|
| `pre-commit` | Before **every** commit and push. The git hook also runs it on staged files. | Secrets (keys, tokens, private keys, JWT, `password=`), personal terms from the denylist, email addresses, phone numbers, forbidden files (`*.shortcut`, `.env`, keys, the denylist), `.gitignore` protections, valid plist with no device-specific calendar, git identity |
| `pre-release X.Y.Z` | After building the signed shortcut, before creating or editing the release | Everything above, plus: the signed shortcut `IphoneShortcuts/iphone_create_calendar_event.public.vX.Y.Z.shortcut` is in **anyone** mode, its signature is valid, its contents equal the committed plist and hold no personal data; the full git history; the source archive of the tag |
| `post-publish X.Y.Z` | **Always after publishing.** The uploaded file, the release notes (editable on GitHub) and the two zips GitHub generates only exist after publishing. | The release is published with exactly one correctly named file; the **downloaded** file matches GitHub's checksum and the local build and passes the shortcut checks; release notes; the real source zip and tar.gz; links return 200 |

## Personal terms (denylist)

Real names, the family calendar name and calendar IDs live only in `denylist.local.txt` in this folder. Git ignores it and the check refuses to commit it. In a new clone, copy `denylist.example.txt` to `denylist.local.txt` and add your own terms. Never write a real name into any committed file, including this one.

## Setup

```bash
scripts/install-hooks.sh      # once per clone: turns on the pre-commit hook
```

Needs macOS tools `plutil`, `aea`, `aa`, `openssl`, plus `git`, `gh` and `curl`.

## Known accepted warning

The first three commits are authored with a non-no-reply email. History was deliberately not rewritten, so `pre-release` shows a warning for it. New commits use the GitHub no-reply address.

## Maintaining

Add a new pattern or file rule in `scripts/check.py`, then add a matching case to `scripts/selftest.py` and run it.
