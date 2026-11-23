; Inno Setup script. Build: iscc /DAppVersion=0.6.0 /DExePath=..\target\release\network-scope.exe /DCliExePath=..\target\release\network-scope-cli.exe network-scope.iss
#ifndef AppVersion
  #define AppVersion "0.6.0"
#endif
#ifndef ExePath
  #define ExePath "..\target\release\network-scope.exe"
#endif
; Console-subsystem build for scripts: shells wait for it and see its exit code.
#ifndef CliExePath
  #define CliExePath "..\target\release\network-scope-cli.exe"
#endif
; The version block of setup.exe takes numbers only: "0.7.0-rc.1" -> "0.7.0".
#if Pos("-", AppVersion) > 0
  #define NumericVersion Copy(AppVersion, 1, Pos("-", AppVersion) - 1)
#else
  #define NumericVersion AppVersion
#endif

[Setup]
AppId={{6F0B8C0E-6A0D-4E9B-8E52-3C1B1F6B7A41}
AppName=Network Scope
AppVersion={#AppVersion}
AppPublisher=Network Scope
AppPublisherURL=https://github.com/Sparkz400/network-scope
AppSupportURL=https://github.com/Sparkz400/network-scope/issues
AppUpdatesURL=https://github.com/Sparkz400/network-scope/releases
VersionInfoVersion={#NumericVersion}
VersionInfoProductName=Network Scope
VersionInfoProductTextVersion={#AppVersion}
VersionInfoDescription=Network Scope Setup
VersionInfoCompany=Network Scope
VersionInfoCopyright=MIT License
SetupIconFile=..\assets\icon\network-scope.ico
; The icon of the entry in Settings > Apps > Installed apps.
UninstallDisplayIcon={app}\network-scope.exe
DefaultDirName={autopf}\Network Scope
DefaultGroupName=Network Scope
OutputDir=..\dist
OutputBaseFilename=NetworkScope-{#AppVersion}-setup
Compression=lzma2
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
WizardStyle=modern
UninstallDisplayName=Network Scope
LicenseFile=..\LICENSE.txt

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; Flags: unchecked
Name: "addtopath"; Description: "Add the command-line tool (network-scope-cli) to PATH"; Flags: unchecked

[Files]
Source: "{#ExePath}"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#CliExePath}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\THIRD-PARTY-NOTICES.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\LICENSE.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\data\README.md"; DestDir: "{app}"; DestName: "DATA-SOURCES.md"; Flags: ignoreversion
Source: "..\scripts\*"; DestDir: "{app}\scripts"; Flags: ignoreversion recursesubdirs
Source: "..\lab\*"; DestDir: "{app}\lab"; Flags: ignoreversion recursesubdirs

[Icons]
; AppUserModelID: the one the window sets (APP_USER_MODEL_ID in src/gui/desktop.rs), so a pinned
; shortcut and the running window share one taskbar button.
Name: "{group}\Network Scope"; Filename: "{app}\network-scope.exe"; AppUserModelID: "Sparkz400.NetworkScope"
Name: "{group}\Uninstall Network Scope"; Filename: "{uninstallexe}"
Name: "{autodesktop}\Network Scope"; Filename: "{app}\network-scope.exe"; AppUserModelID: "Sparkz400.NetworkScope"; Tasks: desktopicon

[Registry]
Root: HKCU; Subkey: "Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; Tasks: addtopath; Check: NeedsPath(ExpandConstant('{app}'))

[Run]
Filename: "{app}\network-scope.exe"; Description: "Start Network Scope"; Flags: nowait postinstall skipifsilent

[Code]
function NeedsPath(Dir: string): Boolean;
var
  Paths: string;
begin
  if not RegQueryStringValue(HKCU, 'Environment', 'Path', Paths) then
    Paths := '';
  Result := Pos(';' + Lowercase(Dir) + ';', ';' + Lowercase(Paths) + ';') = 0;
end;
