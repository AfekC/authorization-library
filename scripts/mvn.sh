#!/usr/bin/env bash
# Run Maven for the Java modules inside a JDK-21 container (no host JDK needed).
# Usage: scripts/mvn.sh <maven-module-dir> <maven args...>
# Example: scripts/mvn.sh libraries/authz-spring-boot test
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODULE_DIR="${1:?module dir required}"
shift

docker run --rm \
  -v "${REPO_ROOT}:/work" \
  -v authz-m2:/root/.m2 \
  -w "/work/${MODULE_DIR}" \
  maven:3-eclipse-temurin-21 \
  mvn -B -ntp "$@"
