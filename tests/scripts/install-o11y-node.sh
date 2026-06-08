#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
O11Y_NODE_DIR="${1:?o11y-node source dir required}"

cd "$O11Y_NODE_DIR"
echo "Packing @hatraa/otel-ts from $O11Y_NODE_DIR..."
npm pack

tarball="$(ls -1t *.tgz | head -n 1)"
if [[ -z "$tarball" ]]; then
  echo "No .tgz package found after npm pack" >&2
  exit 1
fi

vendor_dir="$REPO_ROOT/libraries/authz-nestjs/vendor"
mkdir -p "$vendor_dir"
cp -f "$O11Y_NODE_DIR/$tarball" "$vendor_dir/"
echo "Copied $tarball to $vendor_dir"
echo "Done. Run 'npm install' from libraries/authz-nestjs to refresh the dependency."