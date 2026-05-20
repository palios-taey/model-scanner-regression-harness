#!/usr/bin/env bash
# Fetch the Hide-and-Seek public PoC artifact at a pinned commit SHA into
# corpora/PickleCloak. No execution; just git clone + checkout.
#
# Source repo: https://github.com/Lyutoon/PickleCloak
# Authors: Liu et al., USENIX Security '26, arXiv:2508.19774
# Disclosure: GHSA-9gvj-pp9x-gcfr (credited to @Lyutoon)
#
# We pin a commit SHA so the corpus does not silently shift between runs.
# If the upstream rebases / renames / deletes, you will get an explicit
# error here rather than a silent diff in your scanner verdicts.

set -euo pipefail

REPO_URL="https://github.com/Lyutoon/PickleCloak.git"
PINNED_SHA="909fff715f065d690c3d5475f324a931d97349fc"   # 2026-01-16
DEST="corpora/PickleCloak"

if [ -d "$DEST" ]; then
    echo "Existing checkout at $DEST — verifying commit..."
    cd "$DEST"
    current=$(git rev-parse HEAD)
    if [ "$current" = "$PINNED_SHA" ]; then
        echo "OK: $DEST is at pinned commit $PINNED_SHA"
        exit 0
    fi
    echo "Existing checkout is at $current; expected $PINNED_SHA"
    echo "Remove $DEST and re-run to fetch the pinned commit, or"
    echo "investigate the difference before re-scanning."
    exit 1
fi

mkdir -p corpora
git clone "$REPO_URL" "$DEST"
cd "$DEST"
git -c advice.detachedHead=false checkout "$PINNED_SHA"

echo
echo "Fetched $REPO_URL at $PINNED_SHA into $DEST"
echo "Corpus path for harness:  $DEST/gadget/aeg/container/pickles"
