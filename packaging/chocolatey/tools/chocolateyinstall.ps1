$ErrorActionPreference = 'Stop'

# The official installer from the GitHub release, checked against its SHA-256 from SHA256SUMS.
# Uninstalling goes through Chocolatey's automatic uninstaller (the installer's registry entry).
$packageArgs = @{
  packageName    = $env:ChocolateyPackageName
  fileType       = 'exe'
  url64bit       = 'https://github.com/Sparkz400/network-scope/releases/download/v@VERSION@/NetworkScope-@VERSION@-setup.exe'
  checksum64     = '@SHA256_WINDOWS_SETUP@'
  checksumType64 = 'sha256'
  silentArgs     = '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP- /ALLUSERS'
  validExitCodes = @(0)
  softwareName   = 'Network Scope'
}
Install-ChocolateyPackage @packageArgs
