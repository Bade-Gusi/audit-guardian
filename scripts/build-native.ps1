# Build all native collector modules
# Run from project root: ./scripts/build-native.ps1

$ProjectRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$NativeDir = Join-Path $ProjectRoot "client\native"
$OutputDir = Join-Path $ProjectRoot "client\native\bin"

# Create output directory
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

Write-Host "=== Building HardwareCollector ===" -ForegroundColor Cyan
dotnet publish (Join-Path $NativeDir "HardwareCollector\HardwareCollector.csproj") `
    --configuration Release `
    --output (Join-Path $OutputDir "HardwareCollector") `
    --self-contained false

Write-Host "=== Building EventLogCollector ===" -ForegroundColor Cyan
dotnet publish (Join-Path $NativeDir "EventLogCollector\EventLogCollector.csproj") `
    --configuration Release `
    --output (Join-Path $OutputDir "EventLogCollector") `
    --self-contained false

Write-Host "=== Building FileActivityReader ===" -ForegroundColor Cyan
dotnet publish (Join-Path $NativeDir "FileActivityReader\FileActivityReader.csproj") `
    --configuration Release `
    --output (Join-Path $OutputDir "FileActivityReader") `
    --self-contained false

Write-Host "=== Native modules built successfully ===" -ForegroundColor Green
Write-Host "Output: $OutputDir"
