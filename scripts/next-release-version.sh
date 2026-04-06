#!/usr/bin/env bash
# Compute the next release tag from conventional commits since the latest v*.*.* tag.
# Rubric: docs/breaking-changes.md
#
# Usage:
#   scripts/next-release-version.sh              # human-readable summary to stdout
#   scripts/next-release-version.sh --github-out # append KEY=value lines to GITHUB_OUTPUT
#
set -euo pipefail

GITHUB_OUT=false
if [[ "${1:-}" == "--github-out" ]]; then
	GITHUB_OUT=true
fi

LAST_TAG="$(git describe --tags --abbrev=0 --match='v[0-9]*.[0-9]*.[0-9]*' 2>/dev/null || true)"
if [[ -z "${LAST_TAG}" ]]; then
	LAST_TAG="v0.0.0"
fi

VER="${LAST_TAG#v}"
IFS=. read -r MA MI PA <<<"${VER}"
MA="${MA:-0}"
MI="${MI:-0}"
PA="${PA:-0}"

RANGE="${LAST_TAG}..HEAD"
if [[ -z "$(git rev-list "${RANGE}" 2>/dev/null)" ]]; then
	if [[ "$GITHUB_OUT" == true ]]; then
		{
			echo "should_release=false"
			echo "reason=no_commits_since_tag"
		} >>"${GITHUB_OUTPUT:?}"
	else
		echo "No commits since ${LAST_TAG}; nothing to release."
	fi
	exit 0
fi

# 0 = patch, 1 = minor, 2 = major
LEVEL=0

set_level() {
	local n="$1"
	if [[ "${n}" -gt "${LEVEL}" ]]; then
		LEVEL="${n}"
	fi
}

is_breaking_body() {
	local body="$1"
	echo "${body}" | grep -qiE '^BREAKING[[:space:]]CHANGE' || echo "${body}" | grep -qiE '^BREAKING-CHANGE'
}

while IFS= read -r rev; do
	subj="$(git log -1 --pretty=format:%s "${rev}")"
	body="$(git log -1 --pretty=format:%b "${rev}")"

	if [[ "${subj}" == Merge\ pull\ request* ]] || [[ "${subj}" == Merge\ branch* ]]; then
		continue
	fi

	if is_breaking_body "${body}"; then
		set_level 2
		continue
	fi

	# Conventional: type(scope)!: or type!: (breaking); grep -E for bash 3.2 / macOS
	if echo "${subj}" | grep -qE '^[a-zA-Z]+(\([^)]+\))?!:'; then
		set_level 2
		continue
	fi

	if echo "${subj}" | grep -qE '^[a-zA-Z]+(\([^)]+\))?:'; then
		t="$(echo "${subj}" | sed -E 's/^([a-zA-Z]+)(\([^)]+\))?:.*/\1/' | tr '[:upper:]' '[:lower:]')"
		case "${t}" in
		feat) set_level 2 ;;
		fix | refactor | perf) set_level 1 ;;
		style | test | docs | build | ops | chore) set_level 0 ;;
		*) set_level 0 ;;
		esac
	else
		set_level 0
	fi
done < <(git rev-list --no-merges --reverse "${RANGE}")

case "${LEVEL}" in
0)
	PA=$((PA + 1))
	BUMP_KIND="patch"
	;;
1)
	MI=$((MI + 1))
	PA=0
	BUMP_KIND="minor"
	;;
2)
	MA=$((MA + 1))
	MI=0
	PA=0
	BUMP_KIND="major"
	;;
esac

NEXT_VERSION="${MA}.${MI}.${PA}"
TAG="v${NEXT_VERSION}"

if [[ "$GITHUB_OUT" == true ]]; then
	{
		echo "should_release=true"
		echo "bump=${BUMP_KIND}"
		echo "version=${NEXT_VERSION}"
		echo "tag=${TAG}"
		echo "last_tag=${LAST_TAG}"
	} >>"${GITHUB_OUTPUT:?}"
else
	printf 'Last tag:    %s\n' "${LAST_TAG}"
	printf 'Bump:        %s (%s)\n' "${BUMP_KIND}" "${LEVEL}"
	printf 'Next tag:    %s\n' "${TAG}"
fi
