# Run Maven for the Java modules inside a JDK-21 container (no host JDK needed).
# Usage: tests\scripts\mvn.ps1 <maven-module-dir> <maven args...>
# Example: tests\scripts\mvn.ps1 libraries/authz-spring-boot test
param(
    [Parameter(Mandatory = $true)][string]$ModuleDir,
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$MvnArgs
)
$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path

docker run --rm `
  -v "${RepoRoot}:/work" `
  -v authz-m2:/root/.m2 `
  -w "/work/$ModuleDir" `
  maven:3-eclipse-temurin-21 `
  mvn -B -ntp @MvnArgs
