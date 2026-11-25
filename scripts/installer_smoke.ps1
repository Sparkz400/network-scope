# SPDX-FileCopyrightText: Copyright the Network Scope contributors
# SPDX-License-Identifier: MIT
# Smoke test of the Windows installer (roadmap I58), used by ci.yml and release.yml:
# installs it silently per user (no administrator rights) into a temporary folder with the
# "add to PATH" task, installs it a second time over the first (an upgrade in place), checks that
# both installed binaries print `network-scope <version>` and that the folder is in the user's
# PATH once, uninstalls it silently and checks that the folder, the uninstall registry entry and
# the PATH entry are gone. The user's PATH is restored at the end in any case.
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

# The user's PATH as stored (unexpanded), and how often the install folder is in it. The folder
# is matched by its unique name: Inno Setup and GetTempPath may spell the TEMP part differently
# (short or long names).
$leaf = Split-Path $dir -Leaf
function Get-UserPath { (Get-Item 'HKCU:\Environment').GetValue('Path', $null, 'DoNotExpandEnvironmentNames') }
function Get-PathCount {
    # Empty entries (";;" or a trailing ";") are skipped; Split-Path rejects an empty string.
    @("$(Get-UserPath)" -split ';' | Where-Object { $_ -and [IO.Path]::GetFileName($_.TrimEnd('\')) -ieq $leaf }).Count
}
$savedPath = Get-UserPath

try {
    # Installed twice: the second run is an upgrade in place and must not add PATH again.
    foreach ($round in 1, 2) {
        $p = Start-Process -FilePath $Setup -Wait -PassThru -ArgumentList @(
            '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/SP-', '/CURRENTUSER', '/TASKS="addtopath"',
            "/DIR=`"$dir`"", "/LOG=`"$log`"")
        if ($p.ExitCode -ne 0) { Get-Content $log -ErrorAction SilentlyContinue; throw "setup (round $round) exited with $($p.ExitCode)" }
        if (-not (Test-Path $key)) { throw "no uninstall entry at $key" }
        $count = Get-PathCount
        if ($count -ne 1) { throw "after install round $round the folder is $count times in the user PATH, expected once" }
    }
    Write-Host 'Installed twice; the folder is in the user PATH once.'

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
    while ((Test-Path $key) -or (Test-Path $dir) -or (Get-PathCount) -ne 0) {
        if ((Get-Date) -gt $deadline) {
            if (Test-Path $dir) { Get-ChildItem -Recurse $dir | Select-Object -ExpandProperty FullName }
            throw "uninstall left the install folder, the uninstall registry entry or the PATH entry ($(Get-PathCount)) behind"
        }
        Start-Sleep -Seconds 1
    }
    Write-Host 'Installed, upgraded in place, ran both binaries and uninstalled cleanly (PATH entry removed).'
} finally {
    # Whatever happened, the user's PATH is as before.
    if ($null -eq $savedPath) {
        Remove-ItemProperty -Path 'HKCU:\Environment' -Name 'Path' -ErrorAction SilentlyContinue
    } else {
        Set-ItemProperty -Path 'HKCU:\Environment' -Name 'Path' -Value $savedPath -Type ExpandString
    }
}
