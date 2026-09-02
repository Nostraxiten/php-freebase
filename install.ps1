# ==============================================================================
# PHP FreeBase — Windows Lab Launcher & Setup Script
# ==============================================================================
# Allows Windows operators to run the lab via WSL (Debian/Ubuntu) or Docker Desktop.
# ==============================================================================

Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "      PHP FreeBase — Security Training Lab (Windows Launcher)    " -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "[!] Educational and Cybersecurity Training Laboratory" -ForegroundColor Yellow
Write-Host ""

$wslAvailable = Get-Command wsl -ErrorAction SilentlyContinue
$dockerAvailable = Get-Command docker -ErrorAction SilentlyContinue

Write-Host "Select deployment method for Windows:" -ForegroundColor White
Write-Host "1) Run automated Debian installer inside WSL (Recommended for native Debian feel)"
Write-Host "2) Launch containerized lab via Docker Compose (Ports 80, 443, 3306, 2222)"
Write-Host "3) Prepare local .env for manual Windows testing (XAMPP / native PHP & MySQL)"
Write-Host "4) Exit"
Write-Host ""

$choice = Read-Host "Enter option [1-4]"

switch ($choice) {
    "1" {
        if (-not $wslAvailable) {
            Write-Host "[!] WSL is not enabled on this system. Please enable WSL or use Docker." -ForegroundColor Red
            return
        }
        Write-Host "[+] Launching install.sh inside WSL (Debian)..." -ForegroundColor Green
        wsl -d Debian bash -c "cd '$(wslpath $PSScriptRoot)' && sudo bash install.sh"
    }
    "2" {
        if (-not $dockerAvailable) {
            Write-Host "[!] Docker was not found on PATH. Please ensure Docker Desktop is running." -ForegroundColor Red
            return
        }
        Write-Host "[+] Starting containerized lab with Docker Compose..." -ForegroundColor Green
        docker compose up -d --build
        Write-Host "[+] Lab running! Access https://localhost (Web), localhost:3306 (MySQL), localhost:2222 (SSH)" -ForegroundColor Green
    }
    "3" {
        Write-Host "[+] Creating local .env for Windows development..." -ForegroundColor Green
        if (-not (Test-Path "$PSScriptRoot\.env")) {
            Copy-Item "$PSScriptRoot\.env.example" "$PSScriptRoot\.env"
            Write-Host "[+] Copied .env.example -> .env. Adjust DB credentials as needed." -ForegroundColor Green
        } else {
            Write-Host "[*] .env already exists." -ForegroundColor Yellow
        }
    }
    default {
        Write-Host "Exiting." -ForegroundColor Gray
    }
}
