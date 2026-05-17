# Full project build script
Write-Host "=== Building 赛审卫士 ===" -ForegroundColor Magenta

# 1. Build native modules
Write-Host "`n[1/3] Building native modules..." -ForegroundColor Cyan
& "$PSScriptRoot\build-native.ps1"

# 2. Install dependencies and build client
Write-Host "`n[2/3] Building Electron client..." -ForegroundColor Cyan
Push-Location (Join-Path $PSScriptRoot "..\client")
npm install
npm run build
Pop-Location

# 3. Install dependencies for audit panel
Write-Host "`n[3/3] Setting up audit panel..." -ForegroundColor Cyan
Push-Location (Join-Path $PSScriptRoot "..\audit-panel")
if (Test-Path "package.json") {
    npm install
    npm run build
}
Pop-Location

Write-Host "`n=== Build complete ===" -ForegroundColor Green
