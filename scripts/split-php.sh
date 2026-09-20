#!/usr/bin/env bash
# Publishes packages/php to the read-only mirror Packagist watches.
#
# Packagist indexes a repository whose composer.json sits at the root, and ours
# lives in a monorepo — so the package is split into its own repository. Run this
# after every PHP release commit.
#
#   scripts/split-php.sh v0.2.0
set -euo pipefail

VERSION="${1:-}"
MIRROR="git@github.com:catalisaio/catalisa-biometrics-php.git"
BRANCH="php-split-$(date +%s)"

cd "$(dirname "$0")/.."
git subtree split --prefix=packages/php -b "$BRANCH" -q
git push "$MIRROR" "$BRANCH:main"
if [ -n "$VERSION" ]; then
  git push "$MIRROR" "$BRANCH:refs/tags/$VERSION"
  echo "mirror updated and tagged $VERSION"
else
  echo "mirror updated (no tag — pass a version to tag a release)"
fi
git branch -D "$BRANCH" >/dev/null
