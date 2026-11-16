#!/usr/bin/env bash
set -euo pipefail

version='(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?'
if [[ ! "$GITHUB_REF_NAME" =~ ^$1$version$ ]]; then
  printf 'Expected %sMAJOR.MINOR.PATCH or %sMAJOR.MINOR.PATCH-SUFFIX\n' "$1" "$1" >&2
  exit 1
fi

git fetch --no-tags origin master:refs/remotes/origin/master
if [ "$(git rev-parse --is-shallow-repository)" = true ]; then
  git fetch --unshallow --no-tags origin
fi
git merge-base --is-ancestor "$GITHUB_SHA" refs/remotes/origin/master
