# One-time: build and install the in-house Spring Boot observability library
# (idf.hatraa:o11y parent + idf.hatraa:o11y-lib) into the SAME local Maven
# repository (the `authz-m2` Docker volume) that tests\scripts\mvn.ps1 uses.
#
# o11y-springboot lives outside this repo, so we run the same Maven image with
# its source tree mounted and the shared m2 volume attached. After this runs,
# `mvn.ps1 libraries/authz-spring-boot ...` resolves o11y-lib from the volume.
#
# Usage: tests\scripts\install-o11y.ps1 -O11ySpringDir <path-to-o11y-springboot>
param(
    [Parameter(Mandatory = $true)][string]$O11ySpringDir
)
$ErrorActionPreference = "Stop"

$src = (Resolve-Path $O11ySpringDir).Path
if (-not (Test-Path (Join-Path $src "pom.xml"))) {
    throw "No pom.xml found at $src - pass -O11ySpringDir <path-to-o11y-springboot>"
}

Write-Host "Installing o11y-lib from $src into the authz-m2 volume..."
docker run --rm `
  -v "${src}:/o11y" `
  -v authz-m2:/root/.m2 `
  -w "/o11y" `
  maven:3-eclipse-temurin-21 `
  mvn -B -ntp -DskipTests install

if ($LASTEXITCODE -ne 0) { throw "o11y-lib install failed (exit $LASTEXITCODE)" }
Write-Host "Done: idf.hatraa:o11y-lib:1.0.1 is now in the authz-m2 repo."
