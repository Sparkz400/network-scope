# Smoke test of the Windows installer (roadmap I58), used by ci.yml and release.yml:
# installs it silently per user (no administrator rights) into a temporary folder, checks that
# both installed binaries print `network-scope <version>`, uninstalls it silently and checks that
# the folder and the uninstall registry entry are gone.
#
#   pwsh scripts/installer_smoke.ps1 dist\NetworkScope-0.6.0-setup.exe 0.6.0
param(
    [Parameter(Mandatory)][string]$Setup,
    [Parameter(Mandatory)][string]$Version
)
$ErrorActionPreference = 'Stop'

$dir = Join-Path ([IO.Path]::GetTempPath()) 'network-scope-installer-smoke'
$log = Join-Path ([IO.Path]::GetTempPath()) 'network-scope-installer-smoke.log'
# AppId of installer/network-scope.iss; a per-user install registers under HKCU.
$key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{6F0B8C0E-6A0D-4E9B-8E52-3C1B1F6B7A41}_is1'
if (Test-Path $dir) { throw "$dir exists already; remove it first" }

$p = Start-Process -FilePath $Setup -Wait -PassThru -ArgumentList @(
    '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/SP-', '/CURRENTUSER', "/DIR=`"$dir`"", "/LOG=`"$log`"")
if ($p.ExitCode -ne 0) { Get-Content $log -ErrorAction SilentlyContinue; throw "setup exited with $($p.ExitCode)" }
if (-not (Test-Path $key)) { throw "no uninstall entry at $key" }

# Start-Process with redirected output also waits for the GUI-subsystem binary and reads its exit code.
foreach ($exe in 'network-scope-cli.exe', 'network-scope.exe') {
    $path = Join-Path $dir $exe
    $out = Join-Path ([IO.Path]::GetTempPath()) "$exe.out"
    $run = Start-Process -FilePath $path -ArgumentList '--version' -Wait -PassThru -NoNewWindow -RedirectStandardOutput $out
    $text = (Get-Content $out -Raw).Trim()
    if ($run.ExitCode -ne 0 -or $text -ne "network-scope $Version") {
        throw "$exe --version: exit $($run.ExitCode), output '$text', expected 'network-scope $Version'"
    }
    Write-Host "$exe --version: $text"
}

$uninstaller = (Get-ItemProperty $key).UninstallString.Trim('"')
Start-Process -FilePath $uninstaller -Wait -ArgumentList '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART' | Out-Null
# The uninstaller runs a copy of itself from TEMP and may return before that copy has finished.
$deadline = (Get-Date).AddSeconds(60)
while ((Test-Path $key) -or (Test-Path $dir)) {
    if ((Get-Date) -gt $deadline) {
        if (Test-Path $dir) { Get-ChildItem -Recurse $dir | Select-Object -ExpandProperty FullName }
        throw 'uninstall left the install folder or the uninstall registry entry behind'
    }
    Start-Sleep -Seconds 1
}
Write-Host 'Installed, ran both binaries and uninstalled cleanly.'
