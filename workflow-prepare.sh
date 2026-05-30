#!/usr/bin/env bash
#
# workflow-prepare.sh — stamp the release version into version.go at build time.
#
# The shared go-release workflow (lukaszraczylo/shared-actions go-release.yaml)
# runs this script, if present, from the repository root BEFORE GoReleaser
# builds and tags. Traefik runs this plugin under Yaegi, where the version
# cannot be resolved from build info at runtime, so the released semver must be
# baked into source here.
#
# Version source — first non-empty wins:
#   $VERSION  $VERSION_TAG  $SEMVER  $NEW_VERSION  $RELEASE_VERSION
# A leading "v"/"V" is stripped.
#
# NOTE: go-release.yaml @main does not yet pass the computed version into this
# step's environment. Add it to the "Run workflow prepare script" step, e.g.:
#   env:
#     VERSION: ${{ needs.version.outputs.version }}   # bare, no leading v
#
# The shared workflow runs this script in its test, version AND release jobs,
# but only the release job has a computed version. So a missing version is a
# no-op (leave the dev sentinel) — NOT a hard failure, otherwise the test/version
# jobs would break. A malformed version that IS provided is a hard error. Wire
# the env only on the release job's prepare step (see header note above).
set -euo pipefail

FILE="version.go"
CONST="traefikoidcPluginVersion"

VER="${VERSION:-${VERSION_TAG:-${SEMVER:-${NEW_VERSION:-${RELEASE_VERSION:-}}}}}"
VER="${VER#v}"
VER="${VER#V}"

if [ -z "$VER" ]; then
  if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
    echo "workflow-prepare: WARNING no version provided; leaving ${FILE} at the dev placeholder. If this is the release build, set 'env: VERSION: \${{ needs.version.outputs.version }}' on the release job's prepare step — otherwise the release ships 0.0.0-dev and emits no telemetry." >&2
  else
    echo "workflow-prepare: no version provided; leaving dev placeholder in ${FILE} (local build)"
  fi
  exit 0
fi

# Accept MAJOR[.MINOR[.PATCH]] with optional -prerelease / +build (semver-ish,
# matching the oss-telemetry receiver's validator).
if ! printf '%s' "$VER" | grep -Eq '^[0-9]+(\.[0-9]+){0,2}(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$'; then
  echo "workflow-prepare: ERROR version '${VER}' is not semver-shaped" >&2
  exit 1
fi

if [ ! -f "$FILE" ]; then
  echo "workflow-prepare: ERROR ${FILE} not found (run from repository root)" >&2
  exit 1
fi

# Rewrite only the value of ${CONST}, anchored on the constant name so the
# sibling devPluginVersion sentinel is left untouched.
tmp="$(mktemp)"
sed -E "s/(${CONST}[[:space:]]*=[[:space:]]*\")[^\"]*(\")/\1${VER}\2/" "$FILE" > "$tmp"
mv "$tmp" "$FILE"

if ! grep -Eq "${CONST}[[:space:]]*=[[:space:]]*\"${VER}\"" "$FILE"; then
  echo "workflow-prepare: ERROR failed to stamp version into ${FILE}" >&2
  exit 1
fi

command -v gofmt >/dev/null 2>&1 && gofmt -w "$FILE"
echo "workflow-prepare: stamped ${CONST} = \"${VER}\" in ${FILE}"
