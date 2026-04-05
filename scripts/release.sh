#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════
# VulnScan Platform — Release Script
# Automatically bumps version in ALL files, commits, tags, and pushes.
#
# Usage:
#   ./scripts/release.sh patch    # bump patch version
#   ./scripts/release.sh minor    # bump minor version
#   ./scripts/release.sh major    # bump major version
#   ./scripts/release.sh X.Y.Z   # set exact version
# ═══════════════════════════════════════════════════════════════════════

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT"

# Source of truth for current version
CONFIG_PY="backend/app/core/config.py"

# All files that contain the version string
VERSION_FILES=(
    "backend/app/core/config.py"
    "backend/app/main.py"
    "frontend/index.html"
    "frontend/package.json"
    "frontend/src/components/Sidebar.jsx"
    "frontend/src/pages/Dashboard.jsx"
)

# ── Read current version ────────────────────────────────────────────
CURRENT=$(grep 'PLATFORM_VERSION.*=' "$CONFIG_PY" | grep -oP '\d+\.\d+\.\d+' | head -1)
if [ -z "$CURRENT" ]; then
    echo "ERROR: Could not read current version from $CONFIG_PY"
    exit 1
fi

IFS='.' read -r MAJOR MINOR PATCH <<< "$CURRENT"

# ── Calculate new version ───────────────────────────────────────────
BUMP="${1:-patch}"

case "$BUMP" in
    patch)
        PATCH=$((PATCH + 1))
        NEW="$MAJOR.$MINOR.$PATCH"
        ;;
    minor)
        MINOR=$((MINOR + 1))
        PATCH=0
        NEW="$MAJOR.$MINOR.$PATCH"
        ;;
    major)
        MAJOR=$((MAJOR + 1))
        MINOR=0
        PATCH=0
        NEW="$MAJOR.$MINOR.$PATCH"
        ;;
    *)
        if echo "$BUMP" | grep -qP '^\d+\.\d+\.\d+$'; then
            NEW="$BUMP"
        else
            echo "Usage: $0 [patch|minor|major|X.Y.Z]"
            echo ""
            echo "  patch  — $CURRENT → $MAJOR.$MINOR.$((PATCH + 1))"
            echo "  minor  — $CURRENT → $MAJOR.$((MINOR + 1)).0"
            echo "  major  — $CURRENT → $((MAJOR + 1)).0.0"
            echo "  X.Y.Z  — set exact version"
            exit 1
        fi
        ;;
esac

echo ""
echo "╔═══════════════════════════════════════════════╗"
echo "║  VulnScan Platform — Release                  ║"
echo "╚═══════════════════════════════════════════════╝"
echo ""
echo "  Current version: v$CURRENT"
echo "  New version:     v$NEW"
echo ""
echo "  Files to update:"
for f in "${VERSION_FILES[@]}"; do
    if [ -f "$f" ]; then
        COUNT=$(grep -c "$CURRENT" "$f" 2>/dev/null || echo "0")
        echo "    $f ($COUNT occurrences)"
    else
        echo "    $f (NOT FOUND — skipping)"
    fi
done
echo ""

# ── Confirm ─────────────────────────────────────────────────────────
read -p "  Proceed? (y/N) " CONFIRM
if [ "$CONFIRM" != "y" ] && [ "$CONFIRM" != "Y" ]; then
    echo "  Aborted."
    exit 0
fi
echo ""

# ── Replace version in all files ────────────────────────────────────
UPDATED=0
for f in "${VERSION_FILES[@]}"; do
    if [ -f "$f" ]; then
        BEFORE=$(grep -c "$CURRENT" "$f" 2>/dev/null || echo "0")
        if [ "$BEFORE" -gt 0 ]; then
            sed -i "s/$CURRENT/$NEW/g" "$f"
            AFTER=$(grep -c "$NEW" "$f" 2>/dev/null || echo "0")
            echo "  ✓ $f — replaced $BEFORE occurrence(s)"
            UPDATED=$((UPDATED + 1))
        else
            echo "  - $f — no occurrences found, skipping"
        fi
    fi
done

if [ "$UPDATED" -eq 0 ]; then
    echo ""
    echo "  ERROR: No files were updated. Is the current version correct?"
    exit 1
fi

# ── Verify key files ────────────────────────────────────────────────
echo ""
echo "  Verifying..."
ERRORS=0

# config.py must have new version
if ! grep -q "PLATFORM_VERSION.*$NEW" "$CONFIG_PY"; then
    echo "  ✗ config.py — PLATFORM_VERSION not updated"
    ERRORS=$((ERRORS + 1))
else
    echo "  ✓ config.py"
fi

# main.py must have new version in FastAPI and healthz
if ! grep -q "version=\"$NEW\"" "backend/app/main.py"; then
    echo "  ✗ main.py — FastAPI version not updated"
    ERRORS=$((ERRORS + 1))
else
    echo "  ✓ main.py (FastAPI)"
fi

if ! grep -q "\"version\": \"$NEW\"" "backend/app/main.py"; then
    echo "  ✗ main.py — healthz version not updated"
    ERRORS=$((ERRORS + 1))
else
    echo "  ✓ main.py (healthz)"
fi

# index.html
if ! grep -q "v$NEW" "frontend/index.html"; then
    echo "  ✗ index.html — version not found"
    ERRORS=$((ERRORS + 1))
else
    echo "  ✓ index.html"
fi

# package.json
if ! grep -q "\"version\": \"$NEW\"" "frontend/package.json"; then
    echo "  ✗ package.json — version not updated"
    ERRORS=$((ERRORS + 1))
else
    echo "  ✓ package.json"
fi

if [ "$ERRORS" -gt 0 ]; then
    echo ""
    echo "  WARNING: $ERRORS verification(s) failed. Review changes before committing."
    read -p "  Continue anyway? (y/N) " FORCE
    if [ "$FORCE" != "y" ] && [ "$FORCE" != "Y" ]; then
        echo "  Aborted. Revert with: git checkout -- ."
        exit 1
    fi
fi

# ── Git commit + tag ────────────────────────────────────────────────
echo ""
echo "  Committing..."
git add "${VERSION_FILES[@]}"
git commit -m "release: v$NEW"

echo "  Tagging v$NEW..."
git tag -a "v$NEW" -m "Release v$NEW"

echo ""
echo "═══════════════════════════════════════════════"
echo "  ✓ Version bumped: v$CURRENT → v$NEW"
echo "  ✓ $UPDATED file(s) updated"
echo "  ✓ Git commit + tag created"
echo ""
echo "  To publish:"
echo "    git push origin main --tags"
echo ""
echo "  Then create a GitHub Release:"
echo "    https://github.com/Gondrong/VulnScan-Platform/releases/new?tag=v$NEW"
echo "═══════════════════════════════════════════════"
