#!/usr/bin/env bash
set -euo pipefail

tag="$VERSION_TAG"
version="${tag#helper-}"
prerelease=false
if [[ "$version" == *-* ]]; then prerelease=true; fi

# Both workflows verify the archives and their checksum sidecars before calling
# this script. Keep each release's manifest and draft inventory scoped to its files.
case "$1:$tag" in
  standalone:v*)
    dist=binary-dist
    archives=(wgslirp-"$GITHUB_SHA"-linux-{amd64,arm64}.tar.gz
              wgslirp-"$GITHUB_SHA"-windows-amd64.zip)
    {
      printf 'Source: `%s`\n\nTested image: `%s`\n\n' "$GITHUB_SHA" "$TESTED_IMAGE"
      printf '%s\n' 'Linux amd64/arm64 executables extracted from tested images. Windows amd64 executable validated natively with ICMP_ECHO=false. Verify downloads with SHA256SUMS.'
    } > release-notes.txt
    ;;
  helper:helper-v*)
    dist=helper-dist
    archives=(wgslirp-helper-"$version"-linux-{amd64,arm64}.tar.gz)
    {
      printf 'Source: `%s`\n\n' "$GITHUB_SHA"
      printf '%s\n' 'Linux amd64 and arm64 helper archives passed native pipe and encrypted forwarding acceptance. See SOURCE.json for helper compatibility and SHA256SUMS for checksums.'
    } > release-notes.txt
    ;;
  *)
    echo 'Release profile does not match the tag namespace' >&2
    exit 1
    ;;
esac
sidecars=("${archives[@]/%/.sha256}")
(cd "$dist" && cat "${sidecars[@]}" > SHA256SUMS)
assets=("${archives[@]/#/$dist/}" "$dist/SHA256SUMS")

verify_remote_tag() {
  local ref="refs/tags/$tag" refs commit
  refs=$(GIT_TERMINAL_PROMPT=0 git -c credential.helper= -c 'credential.helper=!gh auth git-credential' \
    ls-remote --exit-code origin "$ref" "$ref^{}")
  commit=$(awk -v ref="$ref" '$2 == ref {target=$1} $2 == ref "^{}" {peeled=$1} END {print (peeled ? peeled : target)}' <<< "$refs")
  if [[ "$commit" != "$GITHUB_SHA" ]]; then
    echo 'Remote release tag differs from the tested commit' >&2
    return 1
  fi
}
read_draft_id() {
  python3 - <<'PY'
import json
import sys
with open('draft.json') as file:
    release = json.load(file)
if release['draft'] is not True:
    sys.exit('version is already published; refusing to replace assets')
release_id = release['id']
if type(release_id) is not int or release_id <= 0:
    sys.exit('invalid draft release ID')
print(release_id)
PY
}
verify_draft_assets() {
  local release_id="$1"
  shift
  gh api --paginate --slurp "repos/$GH_REPO/releases/$release_id/assets?per_page=100" > draft-assets.json
  python3 - "$@" <<'PY'
import hashlib
import itertools
import json
import sys
from pathlib import Path
mode, *paths = sys.argv[1:]
expected = {Path(path).name: Path(path) for path in paths}
assets = list(itertools.chain.from_iterable(json.loads(Path('draft-assets.json').read_bytes())))
names = {asset['name'] for asset in assets}
if len(names) != len(assets) or names - expected.keys():
    sys.exit('draft contains unexpected or duplicate assets')
if mode == 'partial':
    for asset in assets:
        asset_id = asset['id']
        if type(asset_id) is not int or asset_id <= 0:
            sys.exit('invalid draft asset ID')
        sys.stdout.buffer.write(f'{asset_id}\n'.encode('ascii'))
else:
    if names != expected.keys():
        sys.exit('draft is missing expected assets')
    for asset in assets:
        path = expected[asset['name']]
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if (asset['state'] != 'uploaded' or asset['size'] != path.stat().st_size
                or asset['digest'] != f'sha256:{digest}'):
            sys.exit(f'draft asset does not match verified file: {path.name}')
PY
}
verify_checked_draft() {
  gh api "repos/$GH_REPO/releases/$draft_id" > checked-draft.json
  python3 - "$draft_id" "$tag" <<'PY'
import json
import sys
with open('checked-draft.json') as file:
    release = json.load(file)
if release['id'] != int(sys.argv[1]) or release['tag_name'] != sys.argv[2] or release['draft'] is not True:
    sys.exit('checked draft is no longer available for this tag')
PY
}
verify_remote_tag
if ! gh release view "$tag" --json isDraft,databaseId \
  --jq '{draft: .isDraft, id: .databaseId}' > draft.json 2>/dev/null; then
  gh api --method POST "repos/$GH_REPO/releases" \
    -f tag_name="$tag" -f target_commitish="$GITHUB_SHA" -f name="$tag" \
    -F draft=true -F prerelease="$prerelease" -F body=@release-notes.txt > draft.json
fi
draft_id=$(read_draft_id)
verify_draft_assets "$draft_id" partial "${assets[@]}" > draft-asset-ids.txt
verify_checked_draft
while IFS= read -r asset_id; do
  gh api --method DELETE "repos/$GH_REPO/releases/assets/$asset_id" --silent
done < draft-asset-ids.txt
for path in "${assets[@]}"; do
  name="${path##*/}"
  printf 'Authorization: Bearer %s\n' "$GH_TOKEN" | curl --fail-with-body --silent --show-error \
    --header @- --header 'Content-Type: application/octet-stream' --data-binary "@$path" \
    --output /dev/null "https://uploads.github.com/repos/$GH_REPO/releases/$draft_id/assets?name=$name"
done
verify_checked_draft
verify_draft_assets "$draft_id" complete "${assets[@]}"
verify_remote_tag
gh api --method PATCH "repos/$GH_REPO/releases/$draft_id" --silent \
  -f tag_name="$tag" -f target_commitish="$GITHUB_SHA" -F draft=false \
  -F prerelease="$prerelease" -f make_latest=false -F body=@release-notes.txt
printf '### Binary release\n\nhttps://github.com/%s/releases/tag/%s\n' "$GITHUB_REPOSITORY" "$tag" >> "$GITHUB_STEP_SUMMARY"
