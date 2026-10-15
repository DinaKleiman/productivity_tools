#!/bin/sh
# Git does not share hooks, so each clone runs this once to turn the pre-commit security scan on.
set -e
cd "$(git rev-parse --show-toplevel)"
chmod +x scripts/hooks/pre-commit
git config core.hooksPath scripts/hooks
echo "pre-commit hook installed (core.hooksPath=scripts/hooks)"
