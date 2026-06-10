#!/usr/bin/env bash
#
# Full end-to-end run with a GUARANTEED-FRESH build of both libraries.
#
# Why this script exists
# ----------------------
# The two demos bundle PREBUILT artifacts into their Docker images:
#   * spring-demo  — a Spring Boot fat jar (target/spring-demo-0.1.0.jar) is
#                    COPY'd in by its Dockerfile.
#   * nestjs-demo  — the library's compiled dist/ is COPY'd in by its Dockerfile.
#
# `docker compose up --build` rebuilds the IMAGES but NOT those artifacts. So
# after any change to a library, a plain compose-up silently ships the OLD code.
# The classic symptom: every Spring user request returns 403 while NestJS returns
# 200 — the stale jar still reads the pre-rename `role` claim instead of `roleId`,
# resolves an unknown role to empty permissions, and DENIES. (The NestJS side has
# the mirror trap: a stale dist/ can crash the demo at startup.)
#
# This script rebuilds the artifacts first, IN ORDER, then runs the suite and
# always tears the stack down — even on failure.
#
# Usage:  tests/e2e/run-e2e.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "==> [1/5] Build the NestJS library dist/ (feeds the nestjs-demo image)"
pushd "$REPO_ROOT/libraries/authz-nestjs" >/dev/null
[ -d node_modules ] || npm install --no-audit --no-fund
npm run build
popd >/dev/null

echo "==> [2/5] Install authz-spring-boot into the shared Maven repo (Docker JDK)"
"$REPO_ROOT/tests/scripts/mvn.sh" libraries/authz-spring-boot -DskipTests install

echo "==> [3/5] Package the spring-demo fat jar (re-bundles the fresh library)"
"$REPO_ROOT/tests/scripts/mvn.sh" tests/demo-services/spring-demo -DskipTests package

echo "==> [4/5] Build images and start the stack"
cd "$SCRIPT_DIR"
cleanup() { echo "==> Tearing down (docker compose down -v)"; docker compose down -v >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker compose up --build -d

echo "==> [5/5] Run the cross-language parity suite"
rc=0
node run.mjs || rc=$?
exit "$rc"
