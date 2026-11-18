; Inno Setup script. Build: iscc /DAppVersion=0.5.0 /DExePath=..\target\release\network-scope.exe /DCliExePath=..\target\release\network-scope-cli.exe network-scope.iss
#ifndef AppVersion
  #define AppVersion "0.5.0"
#endif
#ifndef ExePath
  #define ExePath "..\target\release\network-scope.exe"
#endif
; Console-subsystem build for scripts: shells wait for it and see its exit code.
#ifndef CliExePath
  #define CliExePath "..\target\release\network-scope-cli.exe"
#endif

[Setup]
AppId={{6F0B8C0E-6A0D-4E9B-8E52-3C1B1F6B7A41}
AppName=Network Scope
AppVersion={#AppVersion}
AppPublisher=Network Scope
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
Source: "..\CREDITS.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\scripts\*"; DestDir: "{app}\scripts"; Flags: ignoreversion recursesubdirs
Source: "..\lab\*"; DestDir: "{app}\lab"; Flags: ignoreversion recursesubdirs

[Icons]
Name: "{group}\Network Scope"; Filename: "{app}\network-scope.exe"
Name: "{group}\Uninstall Network Scope"; Filename: "{uninstallexe}"
Name: "{autodesktop}\Network Scope"; Filename: "{app}\network-scope.exe"; Tasks: desktopicon

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
