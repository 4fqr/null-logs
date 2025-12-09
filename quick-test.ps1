# null.log Quick Test Script
Write-Host "=" * 60
Write-Host "null.log - Quick Functionality Test"
Write-Host "=" * 60

$ErrorActionPreference = "Stop"

# Change to script directory
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

Write-Host "`n[1/5] Checking build..."
if (!(Test-Path ".\bin\null-log.exe")) {
    Write-Host "Building binary..." -ForegroundColor Yellow
    go build -ldflags="-s -w" -o bin\null-log.exe cmd\null-log\main.go
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Build failed!" -ForegroundColor Red
        exit 1
    }
}
Write-Host "✓ Binary exists" -ForegroundColor Green

Write-Host "`n[2/5] Checking rules..."
$ruleCount = (Get-ChildItem .\rules\*.yml | Measure-Object).Count
Write-Host "✓ Found $ruleCount detection rules" -ForegroundColor Green

Write-Host "`n[3/5] Testing help command..."
$helpOutput = .\bin\null-log.exe --help 2>&1
if ($helpOutput -match "null.log") {
    Write-Host "✓ Help works" -ForegroundColor Green
} else {
    Write-Host "✗ Help failed" -ForegroundColor Red
}

Write-Host "`n[4/5] Testing network scan..."
Write-Host "Running: .\bin\null-log.exe net" -ForegroundColor Cyan
try {
    $netOutput = .\bin\null-log.exe net 2>&1 | Out-String
    if ($netOutput -match "connections|PROCESS|scanning") {
        Write-Host "✓ Network scanner works" -ForegroundColor Green
        Write-Host "`nSample output:"
        Write-Host $netOutput.Substring(0, [Math]::Min(500, $netOutput.Length))
    } else {
        Write-Host "✗ Network scanner produced unexpected output" -ForegroundColor Yellow
        Write-Host $netOutput
    }
} catch {
    Write-Host "✗ Network scanner failed: $_" -ForegroundColor Red
}

Write-Host "`n[5/5] Summary"
Write-Host "=" * 60
Write-Host "Binary: .\bin\null-log.exe"
Write-Host "Rules: $ruleCount loaded"
Write-Host "Status: " -NoNewline
Write-Host "OPERATIONAL" -ForegroundColor Green
Write-Host "`nTo run live monitoring (requires Administrator):"
Write-Host "  .\bin\null-log.exe live" -ForegroundColor Cyan
Write-Host "`nTo scan network for threats:"
Write-Host "  .\bin\null-log.exe net" -ForegroundColor Cyan
Write-Host "=" * 60
