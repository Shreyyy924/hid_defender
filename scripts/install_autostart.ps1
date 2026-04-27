# =============================================================
#  HID Defender — Windows Auto-Start Setup
#  Run ONCE as Administrator to register the defender in
#  Windows Task Scheduler so it starts at every logon.
#
#  Usage (from project root, elevated PowerShell):
#      .\scripts\install_autostart.ps1
#
#  To remove:
#      Unregister-ScheduledTask -TaskName "HIDDefender" -Confirm:$false
# =============================================================

param(
    [string]$ProjectRoot = (Resolve-Path "$PSScriptRoot\..").Path,
    [string]$TaskName    = "HIDDefender"
)

# ── Resolve Python interpreter inside .venv ──────────────────────────────────
$Python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $Python)) {
    Write-Error "Python not found at: $Python`nMake sure you have created the .venv first."
    exit 1
}

$RunScript = Join-Path $ProjectRoot "run.py"
if (-not (Test-Path $RunScript)) {
    Write-Error "run.py not found at: $RunScript"
    exit 1
}

# ── Build the scheduled task ─────────────────────────────────────────────────
$Action  = New-ScheduledTaskAction `
    -Execute  $Python `
    -Argument "`"$RunScript`" --monitor" `
    -WorkingDirectory $ProjectRoot

# Trigger: at every user logon
$Trigger = New-ScheduledTaskTrigger -AtLogOn

# Run with highest privileges so pnputil /disable-device works
$Settings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit (New-TimeSpan -Hours 0) `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -StartWhenAvailable `
    -MultipleInstances IgnoreNew

$Principal = New-ScheduledTaskPrincipal `
    -UserId ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) `
    -RunLevel Highest `
    -LogonType Interactive

# ── Register (or overwrite if exists) ────────────────────────────────────────
try {
    Register-ScheduledTask `
        -TaskName  $TaskName `
        -Action    $Action `
        -Trigger   $Trigger `
        -Settings  $Settings `
        -Principal $Principal `
        -Force `
        -ErrorAction Stop | Out-Null

    Write-Host ""
    Write-Host "  ✅  HID Defender registered in Task Scheduler." -ForegroundColor Green
    Write-Host "      Task name : $TaskName"
    Write-Host "      Python    : $Python"
    Write-Host "      Script    : $RunScript"
    Write-Host ""
    Write-Host "  The defender will now start automatically at every Windows logon." -ForegroundColor Cyan
    Write-Host "  To run it right now:"
    Write-Host "    Start-ScheduledTask -TaskName '$TaskName'"
    Write-Host ""
} catch {
    Write-Error "Failed to register task: $_`nTry running this script as Administrator."
    exit 1
}
