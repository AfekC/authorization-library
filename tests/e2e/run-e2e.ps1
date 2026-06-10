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
# Usage:  tests\e2e\run-e2e.ps1
#
# NOTE: ErrorActionPreference is "Continue", not "Stop". Windows PowerShell 5.1
# wraps a native command's stderr in an ErrorRecord; under "Stop" the progress
# `docker compose` writes to stderr would abort the script even on success. We
# rely on explicit $LASTEXITCODE checks (Assert-LastExit) for real failures.
$ErrorActionPreference = "Continue"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path

# Throws (terminating) on a non-zero native exit. `throw` runs regardless of
# ErrorActionPreference, and inside the try/finally it lets teardown still run.
function Assert-LastExit($what) {
    if ($LASTEXITCODE -ne 0) { throw "$what failed (exit $LASTEXITCODE)" }
}

Write-Host "==> [1/5] Build the NestJS library dist/ (feeds the nestjs-demo image)"
Push-Location (Join-Path $RepoRoot "libraries/authz-nestjs")
try {
    if (-not (Test-Path node_modules)) { npm install --no-audit --no-fund; Assert-LastExit "npm install" }
    npm run build; Assert-LastExit "npm run build"
} finally { Pop-Location }

Write-Host "==> [2/5] Install authz-spring-boot into the shared Maven repo (Docker JDK)"
& (Join-Path $RepoRoot "tests/scripts/mvn.ps1") -ModuleDir "libraries/authz-spring-boot" "-DskipTests" install
Assert-LastExit "mvn install authz-spring-boot"

Write-Host "==> [3/5] Package the spring-demo fat jar (re-bundles the fresh library)"
& (Join-Path $RepoRoot "tests/scripts/mvn.ps1") -ModuleDir "tests/demo-services/spring-demo" "-DskipTests" package
Assert-LastExit "mvn package spring-demo"

Write-Host "==> [4/5] Build images and start the stack"
Set-Location $PSScriptRoot
$rc = 1
try {
    docker compose up --build -d; Assert-LastExit "docker compose up"
    Write-Host "==> [5/5] Run the cross-language parity suite"
    node run.mjs
    $rc = $LASTEXITCODE
} finally {
    Write-Host "==> Tearing down (docker compose down -v)"
    docker compose down -v | Out-Null
}
exit $rc
