# Demo Script - Shows null.log detecting simulated attacks
Write-Host "=" * 70 -ForegroundColor Cyan
Write-Host "null.log - Real-Time Attack Detection Demo" -ForegroundColor Yellow
Write-Host "=" * 70 -ForegroundColor Cyan
Write-Host ""

Write-Host "[INFO] This demo will:" -ForegroundColor White
Write-Host "  1. Start null.log monitoring" -ForegroundColor Gray
Write-Host "  2. Simulate 5 realistic attack scenarios" -ForegroundColor Gray
Write-Host "  3. Show real-time threat detections" -ForegroundColor Gray
Write-Host ""
Write-Host "[SIMULATED ATTACKS]" -ForegroundColor Yellow
Write-Host "  • Suspicious PowerShell execution (malware download)" -ForegroundColor Gray
Write-Host "  • Mimikatz LSASS memory dump (credential theft)" -ForegroundColor Gray
Write-Host "  • Registry persistence (malware autostart)" -ForegroundColor Gray
Write-Host "  • Windows Defender disabled (AV evasion)" -ForegroundColor Gray
Write-Host "  • Suspicious scheduled task (backdoor)" -ForegroundColor Gray
Write-Host ""
Write-Host "Press ENTER to start demo..." -ForegroundColor Green
$null = Read-Host

Write-Host "`n[STARTING] Launching null.log..." -ForegroundColor Cyan
Write-Host "Press 'q' in the UI to quit when done`n" -ForegroundColor Yellow

Start-Sleep -Seconds 1

# Run null.log in live mode - it will generate simulated attacks automatically
.\bin\null-log.exe live

Write-Host "`n[DEMO COMPLETE]" -ForegroundColor Green
Write-Host "You just saw null.log detect 5 critical security threats!" -ForegroundColor White
Write-Host ""
Write-Host "Try these commands:" -ForegroundColor Yellow
Write-Host "  .\bin\null-log.exe net     # Scan for network threats (nmap, port scans)" -ForegroundColor Gray
Write-Host "  .\bin\null-log.exe live    # Real-time monitoring" -ForegroundColor Gray
Write-Host "=" * 70 -ForegroundColor Cyan
