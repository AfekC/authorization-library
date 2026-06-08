param(
    [Parameter(Mandatory = $true)][string]$O11yNodeDir
)

$ErrorActionPreference = "Stop"

$src = (Resolve-Path $O11yNodeDir).Path
if (-not (Test-Path (Join-Path $src "package.json"))) {
    throw "No package.json found at $src - pass -O11yNodeDir <path-to-o11y-node>"
}

$vendorDir = (Resolve-Path "$PSScriptRoot\..\..\libraries\authz-nestjs\vendor").Path
if (-not (Test-Path $vendorDir)) {
    New-Item -ItemType Directory -Path $vendorDir | Out-Null
}

Write-Host "Packing @hatraa/otel-ts from $src..."
Push-Location $src
try {
    npm pack | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "npm pack failed with exit code $LASTEXITCODE"
    }

    $tarball = Get-ChildItem -Path $src -Filter "*.tgz" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $tarball) {
        throw "Could not find generated tarball after npm pack"
    }

    $destination = Join-Path $vendorDir $tarball.Name
    Copy-Item -Path $tarball.FullName -Destination $destination -Force
    Write-Host "Copied $($tarball.Name) to $vendorDir"
} finally {
    Pop-Location
}

Write-Host "Done. Run 'npm install' from libraries/authz-nestjs to refresh the dependency."