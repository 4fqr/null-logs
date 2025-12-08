# null.log installation script for Windows PowerShell
$ErrorActionPreference = "Stop"

Write-Host "Installing null.log..." -ForegroundColor Cyan
Write-Host ""

# Detect architecture
$arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }
$binary = "null-log-windows-$arch.exe"

# Installation directory
$installDir = "$env:LOCALAPPDATA\null-log"
New-Item -ItemType Directory -Force -Path $installDir | Out-Null

# Download URL (in production, this would be a real URL)
$downloadUrl = "https://github.com/nullsector/null-log/releases/latest/download/$binary"
$exePath = Join-Path $installDir "null.log.exe"

Write-Host "Downloading null.log for Windows ($arch)..." -ForegroundColor Yellow

try {
    Invoke-WebRequest -Uri $downloadUrl -OutFile $exePath -UseBasicParsing
} catch {
    Write-Host "Download failed. Checking for local build..." -ForegroundColor Yellow
    
    # Fallback for local development
    if (Test-Path ".\null-log.exe") {
        Copy-Item ".\null-log.exe" $exePath
    } else {
        Write-Host "ERROR: Binary not found" -ForegroundColor Red
        exit 1
    }
}

# Create config directory
$configDir = Join-Path $env:USERPROFILE ".null.log"
New-Item -ItemType Directory -Force -Path (Join-Path $configDir "rules") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $configDir "intel") | Out-Null

# Copy bundled rules if available
if (Test-Path ".\rules") {
    Copy-Item -Path ".\rules\*" -Destination (Join-Path $configDir "rules") -Recurse -Force
}

Write-Host ""
Write-Host "✓ Installation complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Installation location: $exePath" -ForegroundColor Cyan
Write-Host ""

# Check if directory is in PATH
$currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($currentPath -notlike "*$installDir*") {
    Write-Host "Adding to PATH..." -ForegroundColor Yellow
    [Environment]::SetEnvironmentVariable(
        "Path",
        "$currentPath;$installDir",
        "User"
    )
    $env:Path = "$env:Path;$installDir"
    Write-Host "✓ Added to PATH" -ForegroundColor Green
}

Write-Host ""
Write-Host "You can now run: null.log --help" -ForegroundColor Cyan
Write-Host ""
Write-Host "Get started with: null.log live" -ForegroundColor Green
Write-Host ""
Write-Host "Note: You may need to restart your terminal for PATH changes to take effect." -ForegroundColor Yellow
