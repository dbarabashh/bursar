#Requires -Version 5.1
# From a terminal opened with "Run as administrator":
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\uninstall-windows.ps1 [-Purge]
param([switch]$Purge)
$ErrorActionPreference = 'Stop'

$Name = 'bursar'
$Prefix = Join-Path $env:ProgramFiles $Name
$State = Join-Path $env:ProgramData $Name

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  [Console]::Error.WriteLine('run from a terminal opened with "Run as administrator"')
  exit 1
}

$svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
if ($null -ne $svc) {
  if ($svc.Status -ne 'Stopped') {
    Stop-Service -Name $Name -Force
    $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
  }
  & sc.exe delete $Name | Out-Null
}
$cliDir = Join-Path $Prefix 'cli'
$machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
$kept = ($machinePath -split ';') | Where-Object { $_ -ne '' -and $_ -ne $cliDir }
[Environment]::SetEnvironmentVariable('Path', ($kept -join ';'), 'Machine')
if (Test-Path $Prefix) { Remove-Item -Recurse -Force $Prefix }
Write-Host 'daemon stopped and code removed'

if ($Purge) {
  Write-Host "this deletes $State, including the wallet key. Move the funds out first."
  $answer = Read-Host 'type DELETE to continue'
  if ($answer -ne 'DELETE') { Write-Host 'kept'; exit 0 }
  Remove-Item -Recurse -Force $State
  Write-Host 'state and key removed'
} else {
  Write-Host "kept $State (key, policy, ledger, audit). Pass -Purge to delete it."
}
