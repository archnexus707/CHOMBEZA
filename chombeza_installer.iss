; CHOMBEZA Bug Bounty Pro - Professional Installer
; Created by archnexus707
; For compiled EXE - WORKS OUT OF THE BOX!

[Setup]
; Basic setup information
AppName=CHOMBEZA Bug Bounty Pro
AppVersion=2.0
AppPublisher=archnexus707
AppPublisherURL=https://github.com/archnexus707/chombeza
AppSupportURL=https://github.com/archnexus707/chombeza/issues
AppUpdatesURL=https://github.com/archnexus707/chombeza/releases

; Installation directory
DefaultDirName={autopf}\CHOMBEZA
DefaultGroupName=CHOMBEZA Bug Bounty Pro
UninstallDisplayIcon={app}\CHOMBEZA.exe
UninstallDisplayName=CHOMBEZA Bug Bounty Pro

; Compression and output
Compression=lzma2/ultra64
SolidCompression=yes
OutputDir=installer
OutputBaseFilename=CHOMBEZA_Setup_v2.0
SetupIconFile=favicon2.ico

; Modern wizard style
WizardStyle=modern
DisableWelcomePage=no
DisableDirPage=no
DisableProgramGroupPage=no
DisableReadyPage=no

; Privileges
PrivilegesRequired=admin
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64

; Version info
VersionInfoVersion=2.0.0.0
VersionInfoCompany=archnexus707
VersionInfoDescription=CHOMBEZA Bug Bounty Pro - Advanced Security Scanner
VersionInfoProductName=CHOMBEZA
VersionInfoProductVersion=2.0
VersionInfoCopyright=Copyright (c) 2026 archnexus707

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional icons:"; Flags: checkablealone
Name: "quicklaunchicon"; Description: "Create a &Quick Launch icon"; GroupDescription: "Additional icons:"; Flags: checkablealone; OnlyBelowVersion: 6.01

[Files]
; Main executable (compiled with PyInstaller)
Source: "dist\CHOMBEZA.exe"; DestDir: "{app}"; Flags: ignoreversion

; Configuration and data files
Source: "config.json"; DestDir: "{app}"; Flags: ignoreversion
Source: "core\payloads.json"; DestDir: "{app}\core"; Flags: ignoreversion
Source: "favicon2.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "b450cbf1-f020-4104-990e-2111e8c9e69e.jpg"; DestDir: "{app}"; DestName: "splash.jpg"; Flags: ignoreversion

; Core modules (for data files only)
Source: "core\*"; DestDir: "{app}\core"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "templates\*"; DestDir: "{app}\templates"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "ui\*"; DestDir: "{app}\ui"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "api\*"; DestDir: "{app}\api"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "plugins\*"; DestDir: "{app}\plugins"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "examples\*"; DestDir: "{app}\examples"; Flags: ignoreversion recursesubdirs createallsubdirs

; Documentation
Source: "README.md"; DestDir: "{app}"; Flags: ignoreversion isreadme
Source: "LICENSE.txt"; DestDir: "{app}"; Flags: ignoreversion

; Create runtime directories
[Dirs]
Name: "{app}\reports"; Flags: uninsalwaysuninstall
Name: "{app}\reports\screenshots"; Flags: uninsalwaysuninstall
Name: "{app}\scans"; Flags: uninsalwaysuninstall
Name: "{app}\ml_models"; Flags: uninsalwaysuninstall
Name: "{app}\logs"; Flags: uninsalwaysuninstall

[Icons]
; Start Menu shortcuts
Name: "{group}\CHOMBEZA Bug Bounty Pro"; Filename: "{app}\CHOMBEZA.exe"; IconFilename: "{app}\CHOMBEZA.exe"; WorkingDir: "{app}"; Comment: "Launch CHOMBEZA Bug Bounty Pro"
Name: "{group}\CHOMBEZA (Debug Mode)"; Filename: "{app}\CHOMBEZA.exe"; Parameters: "--debug"; IconFilename: "{app}\CHOMBEZA.exe"; WorkingDir: "{app}"; Comment: "Launch with debug console"
Name: "{group}\Reports Folder"; Filename: "{app}\reports"; IconFilename: "{sys}\shell32.dll,3"; Comment: "Open reports folder"
Name: "{group}\Uninstall CHOMBEZA"; Filename: "{uninstallexe}"; IconFilename: "{app}\CHOMBEZA.exe"

; Desktop shortcut
Name: "{autodesktop}\CHOMBEZA Bug Bounty Pro"; Filename: "{app}\CHOMBEZA.exe"; IconFilename: "{app}\CHOMBEZA.exe"; WorkingDir: "{app}"; Tasks: desktopicon; Comment: "Launch CHOMBEZA Bug Bounty Pro"

; Quick Launch shortcut
Name: "{userappdata}\Microsoft\Internet Explorer\Quick Launch\CHOMBEZA.lnk"; Filename: "{app}\CHOMBEZA.exe"; Tasks: quicklaunchicon; IconFilename: "{app}\CHOMBEZA.exe"

[Run]
; Launch after installation
Filename: "{app}\CHOMBEZA.exe"; Description: "Launch CHOMBEZA Bug Bounty Pro"; Flags: postinstall nowait skipifsilent unchecked

[UninstallDelete]
; Remove all files (but ask to keep reports)
Type: filesandordirs; Name: "{app}\core"
Type: filesandordirs; Name: "{app}\ui"
Type: filesandordirs; Name: "{app}\api"
Type: filesandordirs; Name: "{app}\templates"
Type: filesandordirs; Name: "{app}\plugins"
Type: filesandordirs; Name: "{app}\examples"
Type: filesandordirs; Name: "{app}\ml_models"
Type: filesandordirs; Name: "{app}\logs"
Type: files; Name: "{app}\CHOMBEZA.exe"
Type: files; Name: "{app}\config.json"
Type: files; Name: "{app}\favicon2.ico"
Type: files; Name: "{app}\splash.jpg"
Type: files; Name: "{app}\README.md"
Type: files; Name: "{app}\LICENSE.txt"
Type: filesandordirs; Name: "{app}\reports"; Tasks: 
Type: dirifempty; Name: "{app}"

[Registry]
; Add to Add/Remove Programs with proper info
Root: HKA; Subkey: "Software\Microsoft\Windows\CurrentVersion\Uninstall\{#emit SetupSetting("AppName")}_is1"; ValueType: string; ValueName: "DisplayIcon"; ValueData: "{app}\CHOMBEZA.exe"; Flags: uninsdeletevalue
Root: HKA; Subkey: "Software\Microsoft\Windows\CurrentVersion\Uninstall\{#emit SetupSetting("AppName")}_is1"; ValueType: string; ValueName: "DisplayVersion"; ValueData: "2.0"; Flags: uninsdeletevalue
Root: HKA; Subkey: "Software\Microsoft\Windows\CurrentVersion\Uninstall\{#emit SetupSetting("AppName")}_is1"; ValueType: string; ValueName: "Publisher"; ValueData: "archnexus707"; Flags: uninsdeletevalue
Root: HKA; Subkey: "Software\Microsoft\Windows\CurrentVersion\Uninstall\{#emit SetupSetting("AppName")}_is1"; ValueType: string; ValueName: "HelpLink"; ValueData: "https://github.com/archnexus707/chombeza"; Flags: uninsdeletevalue
Root: HKA; Subkey: "Software\Microsoft\Windows\CurrentVersion\Uninstall\{#emit SetupSetting("AppName")}_is1"; ValueType: string; ValueName: "URLInfoAbout"; ValueData: "https://github.com/archnexus707"; Flags: uninsdeletevalue
Root: HKA; Subkey: "Software\Microsoft\Windows\CurrentVersion\Uninstall\{#emit SetupSetting("AppName")}_is1"; ValueType: string; ValueName: "Comments"; ValueData: "Professional Bug Bounty Hunting Tool"; Flags: uninsdeletevalue

; File association for .chombeza files
Root: HKA; Subkey: "Software\Classes\.chombeza"; ValueType: string; ValueName: ""; ValueData: "CHOMBEZA.Report"; Flags: uninsdeletevalue
Root: HKA; Subkey: "Software\Classes\CHOMBEZA.Report"; ValueType: string; ValueName: ""; ValueData: "CHOMBEZA Report File"; Flags: uninsdeletevalue
Root: HKA; Subkey: "Software\Classes\CHOMBEZA.Report\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: "{app}\CHOMBEZA.exe,0"; Flags: uninsdeletevalue
Root: HKA; Subkey: "Software\Classes\CHOMBEZA.Report\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\CHOMBEZA.exe"" ""%1"""; Flags: uninsdeletevalue

[Code]
// Custom welcome message
procedure InitializeWizard();
begin
  WizardForm.WelcomeLabel2.Caption := 'CHOMBEZA Bug Bounty Pro v2.0' + #13#10 + 
    'Created by archnexus707' + #13#10 + #13#10 +
    'This professional security testing tool will be installed on your computer.' + #13#10 +
    '⚠️  IMPORTANT: Use only on authorized systems! ⚠️' + #13#10 + #13#10 +
    'FEATURES:' + #13#10 +
    '• 50+ Vulnerability Types (XSS, SQLi, SSRF, etc.)' + #13#10 +
    '• Live Traffic Monitoring Window' + #13#10 +
    '• Blind XSS Callback Server' + #13#10 +
    '• Professional Reports (HTML/PDF/JSON/CSV)' + #13#10 +
    '• Multi-threaded Scanning Engine' + #13#10 +
    '• ML-Powered False Positive Reduction' + #13#10 +
    '• Screenshot Evidence Capture';
end;

// Create necessary folders after installation
procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    CreateDir(ExpandConstant('{app}\reports'));
    CreateDir(ExpandConstant('{app}\reports\screenshots'));
    CreateDir(ExpandConstant('{app}\scans'));
    CreateDir(ExpandConstant('{app}\ml_models'));
    CreateDir(ExpandConstant('{app}\logs'));
  end;
end;

// Ask about keeping reports during uninstall
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ResultCode: Integer;
begin
  if CurUninstallStep = usPostUninstall then
  begin
    if MsgBox('Do you want to KEEP your scan reports and data?' + #13#10 + #13#10 +
              '• Click YES to keep them (recommended)' + #13#10 +
              '• Click NO to delete everything', 
      mbConfirmation, MB_YESNO or MB_DEFBUTTON1) = IDNO then
    begin
      DelTree(ExpandConstant('{app}\reports'), True, True, True);
      DelTree(ExpandConstant('{app}\scans'), True, True, True);
      DelTree(ExpandConstant('{app}\ml_models'), True, True, True);
      DelTree(ExpandConstant('{app}\logs'), True, True, True);
    end;
  end;
end;

[Messages]
SetupAppTitle=CHOMBEZA Bug Bounty Pro Installer
SetupWindowTitle=CHOMBEZA Bug Bounty Pro Setup
BeveledLabel=CHOMBEZA
WelcomeLabel1=Welcome to the CHOMBEZA Bug Bounty Pro installer
WelcomeLabel2=This will install CHOMBEZA Bug Bounty Pro on your computer.%n%nIt is recommended that you close all other applications before continuing.
FinishedLabel=Setup has finished installing CHOMBEZA Bug Bounty Pro on your computer.%n%nYou can launch the application from the Start Menu or desktop shortcut.