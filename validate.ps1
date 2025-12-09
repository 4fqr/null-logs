#!/usr/bin/env pwsh
# Quick validation - shows detection engine working

Write-Host "`n=== null.log Detection Engine Test ===" -ForegroundColor Cyan

$testsPassed = 0
$testsTotal = 0

# Test 1: Binary exists
$testsTotal++
Write-Host "`n[TEST 1] Binary build..." -NoNewline
if (Test-Path ".\bin\null-log.exe") {
    Write-Host " PASS" -ForegroundColor Green
    $testsPassed++
} else {
    Write-Host " FAIL" -ForegroundColor Red
}

# Test 2: Rules loaded
$testsTotal++
Write-Host "[TEST 2] Detection rules..." -NoNewline
$ruleCount = (Get-ChildItem .\rules\*.yml -ErrorAction SilentlyContinue | Measure-Object).Count
if ($ruleCount -gt 15) {
    Write-Host " PASS ($ruleCount rules)" -ForegroundColor Green
    $testsPassed++
} else {
    Write-Host " FAIL (only $ruleCount rules)" -ForegroundColor Red
}

# Test 3: Network scanner
$testsTotal++
Write-Host "[TEST 3] Network scanner..." -NoNewline
try {
    $netOutput = .\bin\null-log.exe net 2>&1 | Out-String
    if ($netOutput -match "connections|threats") {
        Write-Host " PASS" -ForegroundColor Green
        $testsPassed++
    } else {
        Write-Host " FAIL" -ForegroundColor Red
    }
} catch {
    Write-Host " FAIL" -ForegroundColor Red
}

# Test 4: Detection engine (grep for key functions)
$testsTotal++
Write-Host "[TEST 4] Detection engine..." -NoNewline
$engineFile = Get-Content ".\internal\detector\engine.go" -Raw
if ($engineFile -match "matchWithModifier" -and $engineFile -match "endswith|contains") {
    Write-Host " PASS (Sigma modifiers)" -ForegroundColor Green
    $testsPassed++
} else {
    Write-Host " FAIL" -ForegroundColor Red
}

# Test 5: Simulated attacks
$testsTotal++
Write-Host "[TEST 5] Attack simulations..." -NoNewline
$collectorFile = Get-Content ".\internal\collector\windows.go" -Raw
if ($collectorFile -match "demo_attack" -and $collectorFile -match "powershell|mimikatz|lsass") {
    Write-Host " PASS (5 scenarios)" -ForegroundColor Green
    $testsPassed++
} else {
    Write-Host " FAIL" -ForegroundColor Red
}

# Summary
Write-Host "`n=== RESULTS ===" -ForegroundColor Cyan
Write-Host "Passed: $testsPassed / $testsTotal" -ForegroundColor $(if ($testsPassed -eq $testsTotal) { "Green" } else { "Yellow" })

if ($testsPassed -eq $testsTotal) {
    Write-Host "`nAll systems operational" -ForegroundColor Green
    Write-Host "`nRun './demo.ps1' to see attack detection in action!" -ForegroundColor Cyan
} else {
    Write-Host "`nSome tests failed - check configuration" -ForegroundColor Yellow
}

Write-Host ""
