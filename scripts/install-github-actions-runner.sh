#!/usr/bin/env bash
# Install the official GitHub Actions self-hosted runner (Linux x64) on this machine.
# Intended for a dedicated user on a homelab host (e.g. Beelink + k3s node).
#
# Prerequisites: curl, tar; for jq-less systems we parse the latest release tag via the GitHub API.
#
# Usage:
#   export RUNNER_CFG_URL="https://github.com/iota-corp"              # org, or full repo URL
#   export RUNNER_CFG_TOKEN="********"                                 # Settings → Actions → Runners → New
#   ./scripts/install-github-actions-runner.sh
#
# Optional environment:
#   RUNNER_DIR       install directory (default: ~/actions-runner)
#   RUNNER_LABELS    comma-separated labels (default: beelink)
#   RUNNER_REPLACE=1 re-register if a runner is already configured in RUNNER_DIR
#
# Org runner groups: after registration, move the runner to the right group in
# Organization → Settings → Actions → Runner groups (CLI defaults to Default).

set -euo pipefail

RUNNER_DIR="${RUNNER_DIR:-$HOME/actions-runner}"
RUNNER_LABELS="${RUNNER_LABELS:-beelink}"

if [[ -z "${RUNNER_CFG_URL:-}" || -z "${RUNNER_CFG_TOKEN:-}" ]]; then
	echo "install-github-actions-runner: set RUNNER_CFG_URL and RUNNER_CFG_TOKEN" >&2
	exit 1
fi

need() {
	command -v "$1" >/dev/null 2>&1 || {
		echo "install-github-actions-runner: missing required command: $1" >&2
		exit 1
	}
}

need curl
need tar

TAG="$(curl -fsSL https://api.github.com/repos/actions/runner/releases/latest | sed -n 's/.*"tag_name": *"v\([^"]*\)".*/\1/p' | head -1)"
if [[ -z "$TAG" ]]; then
	echo "install-github-actions-runner: could not resolve latest actions/runner version" >&2
	exit 1
fi

TARBALL="actions-runner-linux-x64-${TAG}.tar.gz"
URL="https://github.com/actions/runner/releases/download/v${TAG}/${TARBALL}"

mkdir -p "$RUNNER_DIR"
cd "$RUNNER_DIR"

echo "install-github-actions-runner: installing to $RUNNER_DIR (actions/runner v${TAG})..."
curl -fL -o "$TARBALL" "$URL"
tar xzf "$TARBALL"

CONFIG_ARGS=(
	./config.sh
	--url "$RUNNER_CFG_URL"
	--token "$RUNNER_CFG_TOKEN"
	--labels "$RUNNER_LABELS"
	--unattended
)
if [[ -n "${RUNNER_REPLACE:-}" ]]; then
	CONFIG_ARGS+=(--replace)
fi

"${CONFIG_ARGS[@]}"

echo ""
echo "install-github-actions-runner: config finished."
echo "Next (run from $RUNNER_DIR):"
echo "  sudo ./svc.sh install"
echo "  sudo ./svc.sh start"
echo "  sudo ./svc.sh status"
echo ""
echo "In GitHub: confirm the runner is Online, then run workflow \"Self-hosted runner smoke\" (workflow_dispatch)."
