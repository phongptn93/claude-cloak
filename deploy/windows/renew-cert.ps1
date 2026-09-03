<#
.SYNOPSIS
  win-acme deploy hook: restart the proxy after a certificate renewal.

.DESCRIPTION
  uvicorn reads the certificate once at startup, so a renewed certificate only
  takes effect on restart. Register this as win-acme's post-request script:

    wacs.exe --target manual --host <fqdn> --store pemfiles `
             --pemfilespath C:\ProgramData\claude-cloak\tls `
             --installation script `
             --script "powershell.exe" `
             --scriptparameters "-File C:\Program Files\claude-cloak\renew-cert.ps1"
#>
param([string]$TaskName = 'ClaudeCloakServer')
$ErrorActionPreference = 'Stop'
schtasks /end /tn $TaskName 2>$null | Out-Null
Start-Sleep -Seconds 3
schtasks /run /tn $TaskName | Out-Null
Write-Host "restarted $TaskName after certificate renewal"
