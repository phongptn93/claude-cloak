<#
.SYNOPSIS
  Install Claude Cloak as a Windows scheduled task running under SYSTEM.

.DESCRIPTION
  Resolves the locked dependency set once with uv, then registers a task that
  runs the resulting venv entry point directly. Nothing resolves at boot, so
  a network hiccup or an upstream index outage cannot stop the proxy starting.

  Run from an elevated PowerShell:
    .\deploy\windows\install-service.ps1 -DataDir C:\ProgramData\claude-cloak
#>
[CmdletBinding()]
param(
    [string]$AppDir  = 'C:\Program Files\claude-cloak',
    [string]$DataDir = 'C:\ProgramData\claude-cloak',
    [string]$TaskName = 'ClaudeCloakServer'
)

$ErrorActionPreference = 'Stop'
$repo = Resolve-Path (Join-Path $PSScriptRoot '..\..')

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this from an elevated PowerShell.'
}

if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    Write-Host 'Installing uv...'
    Invoke-RestMethod https://astral.sh/uv/install.ps1 | Invoke-Expression
    $env:PATH = "$env:USERPROFILE\.local\bin;$env:PATH"
}

New-Item -ItemType Directory -Force -Path $AppDir, $DataDir | Out-Null
Copy-Item -Force (Join-Path $repo 'pyproject.toml'), (Join-Path $repo 'uv.lock'), (Join-Path $repo 'README.md') $AppDir
Copy-Item -Recurse -Force (Join-Path $repo 'src') $AppDir

# --locked fails rather than silently resolving something other than uv.lock.
$env:UV_COMPILE_BYTECODE = '1'
& uv sync --project $AppDir --locked --no-dev --no-editable
if ($LASTEXITCODE -ne 0) { throw "uv sync failed ($LASTEXITCODE)" }

$envFile = Join-Path $DataDir '.env'
if (-not (Test-Path $envFile)) {
    Copy-Item (Join-Path $repo 'client\.env.example') $envFile
    Write-Host "Created $envFile from the template - edit it before starting."
}

# SYSTEM needs to read the data dir; keep everyone else out of the secrets.
$acl = Get-Acl $DataDir
$acl.SetAccessRuleProtection($true, $false)
foreach ($who in 'SYSTEM', 'Administrators') {
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        $who, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
}
Set-Acl $DataDir $acl

$exe = Join-Path $AppDir '.venv\Scripts\claude-cloak.exe'
if (-not (Test-Path $exe)) { throw "entry point missing: $exe" }

$action = New-ScheduledTaskAction -Execute $exe -WorkingDirectory $DataDir
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Force | Out-Null

[Environment]::SetEnvironmentVariable('CLAUDE_CLOAK_ENV', $envFile, 'Machine')

Write-Host ''
Write-Host "Installed task '$TaskName'."
Write-Host "  settings : $envFile"
Write-Host "  entry    : $exe"
Write-Host '  start    : schtasks /run /tn ' $TaskName
Write-Host '  TLS      : see deploy/README.md (win-acme)'
