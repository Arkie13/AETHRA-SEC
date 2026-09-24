; ===========================================================================
;  AETHRA-SEC Windows installer  (Inno Setup 6)
;
;  Produces AETHRA-SEC-Setup.exe. Compile it with packaging\build.ps1, which
;  runs PyInstaller first and passes the version in.
;
;  What this installer does and, as importantly, does not do
;  ---------------------------------------------------------
;  It installs the AETHRA-SEC application: the two executables PyInstaller
;  produced, the Python runtime and libraries they need, the packaged assets,
;  the reference SQL schema and the documentation. Shortcuts point at the real
;  executable, and the first launch runs the setup wizard.
;
;  It does NOT bundle Nmap, Wireshark/TShark, Npcap, Snort or MySQL. Every one
;  of those is a separately licensed product with its own installer and its own
;  redistribution terms, and shipping a copy inside this file would be both a
;  licensing problem and a maintenance one - a bundled Npcap that is older than
;  the one already on the machine is worse than none at all. So the installer
;  DETECTS them, reports honestly what is present and what is missing, and
;  gives the operator the official download location for anything absent. The
;  application then reports each missing tool as unavailable rather than
;  pretending the feature works.
;
;  Data is never destroyed silently. An upgrade leaves the configuration, the
;  database and the logs exactly where they are; the uninstaller asks, once and
;  explicitly, before removing anything that is security evidence, and defaults
;  to keeping it.
; ===========================================================================

#ifndef AppVersion
  #define AppVersion "1.0.0"
#endif
#ifndef SourceDir
  #define SourceDir "..\build\dist\AETHRA-SEC"
#endif
#ifndef OutputDir
  #define OutputDir "..\build\installer"
#endif

#define AppName        "AETHRA-SEC"
#define AppPublisher   "AETHRA-SEC"
#define AppExeName     "AETHRA-SEC.exe"
#define AppCliName     "aethra-sec-cli.exe"
#define AppDataDirName "AETHRA-SEC"

[Setup]
; The AppId is what makes upgrade, repair and uninstall work: Windows and Inno
; both key the installed-product record on it. It must never change between
; releases, or an upgrade becomes a second, parallel installation.
AppId={{7E2A1C64-5B3D-4A19-9E77-2F8C41D6B0A3}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
VersionInfoVersion={#AppVersion}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
OutputDir={#OutputDir}
OutputBaseFilename=AETHRA-SEC-Setup
SetupIconFile=..\assets\aethra-sec.ico
UninstallDisplayIcon={app}\{#AppExeName}
UninstallDisplayName={#AppName} {#AppVersion}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
; Writing to Program Files and setting the ACL on the configuration file both
; need an elevated install. Live packet capture needs elevation at run time
; too, so an operator who cannot elevate cannot use the product anyway.
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; Offer to close a running AETHRA-SEC rather than failing on a locked file, and
; restart it afterwards. Without this an upgrade over a running console fails
; halfway with a file-in-use error.
CloseApplications=yes
RestartApplications=yes
CloseApplicationsFilter=*.exe,*.dll,*.pyd
MinVersion=10.0
LicenseFile=..\packaging\LICENSE-NOTICE.txt
InfoBeforeFile=..\packaging\PREREQUISITES.txt

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Shortcuts:"
Name: "startmenuicon"; Description: "Create a &Start Menu entry"; GroupDescription: "Shortcuts:"

[Files]
; The whole PyInstaller output directory. recursesubdirs picks up _internal,
; which holds the Python runtime, the libraries and the packaged assets.
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Dirs]
; The application-data tree, created at install time so the first run does not
; have to and so the permissions below are in place before anything is written.
;
; Users get modify rather than full control: an operator must be able to run
; the console, write logs, captures and reports without elevating, but must not
; be able to rewrite the directory's own access control. The configuration file
; inside it is tightened further by the application when setup writes it,
; because that file holds the database and SMTP passwords.
Name: "{commonappdata}\{#AppDataDirName}"; Permissions: users-modify
Name: "{commonappdata}\{#AppDataDirName}\logs"; Permissions: users-modify
Name: "{commonappdata}\{#AppDataDirName}\captures"; Permissions: users-modify
Name: "{commonappdata}\{#AppDataDirName}\reports_output"; Permissions: users-modify

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExeName}"; IconFilename: "{app}\_internal\assets\aethra-sec.ico"; Comment: "AETHRA-SEC Security Operations Console"; Tasks: startmenuicon
Name: "{group}\{#AppName} diagnostics"; Filename: "{app}\{#AppCliName}"; Parameters: "--check"; IconFilename: "{app}\_internal\assets\aethra-sec.ico"; Comment: "Run the AETHRA-SEC system health check"; Tasks: startmenuicon
Name: "{group}\{#AppName} setup"; Filename: "{app}\{#AppExeName}"; Parameters: "--setup"; IconFilename: "{app}\_internal\assets\aethra-sec.ico"; Comment: "Re-run the AETHRA-SEC setup wizard"; Tasks: startmenuicon
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"; Tasks: startmenuicon
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; IconFilename: "{app}\_internal\assets\aethra-sec.ico"; Comment: "AETHRA-SEC Security Operations Console"; Tasks: desktopicon

[Run]
; Live capture needs the packet driver, which needs an elevated process. The
; shortcut inherits that from the manifest; launching from here keeps the same
; token the installer already has.
Filename: "{app}\{#AppExeName}"; Description: "Start {#AppName} and run first-time setup"; Flags: postinstall nowait skipifsilent

[UninstallDelete]
; Only what the application itself creates inside its own install directory.
; Everything under {commonappdata} is the operator's data and is dealt with by
; the confirmation prompt in CurUninstallStepChanged, never by a blanket rule.
Type: filesandordirs; Name: "{app}\_internal\__pycache__"

[Code]
var
  PrereqPage: TOutputMsgMemoWizardPage;
  DetectionText: String;

{ --------------------------------------------------------------------------
  Prerequisite detection.

  Each tool is looked for where its own installer puts it and on PATH. The
  result is reported to the operator before anything is copied, so a machine
  that is missing Npcap is known to be missing it at install time rather than
  at the first attempt to capture.

  Nothing here blocks the installation. AETHRA-SEC runs with any subset of
  these present - each absent tool simply disables its own feature and says so.
  -------------------------------------------------------------------------- }

function FileOnPath(const Exe: String): String;
var
  FoundPath: String;
begin
  Result := '';
  { Inno resolves a bare name against PATH the same way ShellExecute would. }
  if FileSearch(Exe, GetEnv('PATH')) <> '' then
    Result := FileSearch(Exe, GetEnv('PATH'))
  else
  begin
    FoundPath := ExpandConstant('{sys}') + '\' + Exe;
    if FileExists(FoundPath) then
      Result := FoundPath;
  end;
end;

function FirstExisting(const Candidates: array of String): String;
var
  I: Integer;
begin
  Result := '';
  for I := 0 to GetArrayLength(Candidates) - 1 do
  begin
    if (Candidates[I] <> '') and FileExists(Candidates[I]) then
    begin
      Result := Candidates[I];
      Exit;
    end;
  end;
end;

function DetectNmap(): String;
var
  Candidates: array[0..2] of String;
  Found: String;
begin
  Candidates[0] := ExpandConstant('{commonpf32}') + '\Nmap\nmap.exe';
  Candidates[1] := ExpandConstant('{commonpf64}') + '\Nmap\nmap.exe';
  Candidates[2] := FileOnPath('nmap.exe');
  Found := FirstExisting(Candidates);
  if Found <> '' then
    Result := 'FOUND    ' + Found
  else
    Result := 'MISSING  install from https://nmap.org/download.html';
end;

function DetectTShark(): String;
var
  Candidates: array[0..2] of String;
  Found: String;
begin
  Candidates[0] := ExpandConstant('{commonpf64}') + '\Wireshark\tshark.exe';
  Candidates[1] := ExpandConstant('{commonpf32}') + '\Wireshark\tshark.exe';
  Candidates[2] := FileOnPath('tshark.exe');
  Found := FirstExisting(Candidates);
  if Found <> '' then
    Result := 'FOUND    ' + Found
  else
    Result := 'MISSING  install Wireshark from https://www.wireshark.org/download.html';
end;

function DetectNpcap(): String;
var
  Candidates: array[0..2] of String;
  Found: String;
begin
  Candidates[0] := ExpandConstant('{sys}') + '\Npcap\wpcap.dll';
  Candidates[1] := ExpandConstant('{sys}') + '\wpcap.dll';
  Candidates[2] := ExpandConstant('{syswow64}') + '\Npcap\wpcap.dll';
  Found := FirstExisting(Candidates);
  if Found <> '' then
    Result := 'FOUND    ' + Found
  else
    Result := 'MISSING  install Npcap from https://npcap.com/#download (bundled with Wireshark)';
end;

function DetectSnort(): String;
var
  Candidates: array[0..2] of String;
  Found: String;
begin
  Candidates[0] := 'C:\Snort\bin\snort.exe';
  Candidates[1] := ExpandConstant('{commonpf64}') + '\Snort\bin\snort.exe';
  Candidates[2] := FileOnPath('snort.exe');
  Found := FirstExisting(Candidates);
  if Found <> '' then
    Result := 'FOUND    ' + Found
  else
    Result := 'OPTIONAL not found - AETHRA-SEC''s own detection rules still work';
end;

function DetectMySQL(): String;
var
  Candidates: array[0..3] of String;
  Found: String;
begin
  Candidates[0] := 'C:\xampp\mysql\bin\mysqld.exe';
  Candidates[1] := ExpandConstant('{commonpf64}') + '\MySQL\MySQL Server 8.0\bin\mysqld.exe';
  Candidates[2] := ExpandConstant('{commonpf64}') + '\MariaDB 11.4\bin\mysqld.exe';
  Candidates[3] := FileOnPath('mysqld.exe');
  Found := FirstExisting(Candidates);
  if Found <> '' then
    Result := 'FOUND    ' + Found
  else
    Result := 'MISSING  install MySQL 8.0+, MariaDB 10.6+, or XAMPP';
end;

function BuildDetectionReport(): String;
var
  S: String;
begin
  S := 'AETHRA-SEC checked this machine for the tools it integrates with.' + #13#10;
  S := S + 'None of them is installed by this installer, and none of them is' + #13#10;
  S := S + 'required for AETHRA-SEC to install and start.' + #13#10 + #13#10;
  S := S + 'MySQL / MariaDB' + #13#10 + '  ' + DetectMySQL() + #13#10;
  S := S + '  Required. AETHRA-SEC stores every host, alert and incident here.' + #13#10 + #13#10;
  S := S + 'Npcap packet driver' + #13#10 + '  ' + DetectNpcap() + #13#10;
  S := S + '  Required for live capture. Without it TShark cannot open an interface.' + #13#10 + #13#10;
  S := S + 'Wireshark / TShark' + #13#10 + '  ' + DetectTShark() + #13#10;
  S := S + '  Required for traffic analysis. PyShark drives TShark.' + #13#10 + #13#10;
  S := S + 'Nmap' + #13#10 + '  ' + DetectNmap() + #13#10;
  S := S + '  Required for vulnerability assessment and host discovery.' + #13#10 + #13#10;
  S := S + 'Snort' + #13#10 + '  ' + DetectSnort() + #13#10;
  S := S + '  Optional. AETHRA-SEC reads alerts a Snort sensor produced; it' + #13#10;
  S := S + '  never starts Snort itself.' + #13#10 + #13#10;
  S := S + 'Anything marked MISSING can be installed later. The setup wizard and' + #13#10;
  S := S + 'the System Health screen re-check all of them and report what is' + #13#10;
  S := S + 'genuinely available - a feature whose tool is absent reports itself' + #13#10;
  S := S + 'unavailable rather than showing invented data.' + #13#10;
  Result := S;
end;

{ --------------------------------------------------------------------------
  Existing installation detection.
  -------------------------------------------------------------------------- }

function GetUninstallRegKey(): String;
begin
  Result := 'Software\Microsoft\Windows\CurrentVersion\Uninstall\' +
            '{7E2A1C64-5B3D-4A19-9E77-2F8C41D6B0A3}_is1';
end;

function InstalledVersion(): String;
begin
  Result := '';
  if not RegQueryStringValue(HKLM, GetUninstallRegKey(), 'DisplayVersion', Result) then
    if not RegQueryStringValue(HKCU, GetUninstallRegKey(), 'DisplayVersion', Result) then
      Result := '';
end;

function IsUpgrade(): Boolean;
begin
  Result := InstalledVersion() <> '';
end;

function InitializeSetup(): Boolean;
var
  Existing: String;
begin
  Result := True;
  Existing := InstalledVersion();
  if Existing <> '' then
  begin
    { An upgrade is allowed to proceed without ceremony, but the operator is
      told what is about to happen to their data, because the one thing they
      will want to know is whether the history survives. It does. }
    if MsgBox('AETHRA-SEC ' + Existing + ' is already installed.' + #13#10 + #13#10 +
              'Continuing will upgrade it to ' + '{#AppVersion}' + '.' + #13#10 + #13#10 +
              'Your configuration, database, security history, reports and logs' + #13#10 +
              'are kept. Database migrations run on the next start.' + #13#10 + #13#10 +
              'Continue?',
              mbConfirmation, MB_YESNO) = IDNO then
      Result := False;
  end;
end;

procedure InitializeWizard();
begin
  DetectionText := BuildDetectionReport();
  PrereqPage := CreateOutputMsgMemoPage(
    wpSelectTasks,
    'Third-party components',
    'What AETHRA-SEC integrates with, and what is on this machine',
    'The components below are installed and licensed separately. This ' +
    'installer detects them; it does not install or redistribute them.',
    DetectionText);
end;

{ --------------------------------------------------------------------------
  Uninstall.

  The install directory goes without asking - it holds only the application.
  The data directory is a different matter: it holds the configuration, the
  logs and, in a default deployment, nothing else, but the database it points
  at holds hosts, alerts, incidents, vulnerabilities and the audit trail. Those
  are security evidence, and destroying them because someone uninstalled an
  application would be indefensible.

  So the question is asked once, plainly, and defaults to keeping everything.
  The database itself is never dropped by the uninstaller under any answer -
  removing a MySQL schema is the database administrator's decision, and the
  message says where it is so it can be made deliberately.
  -------------------------------------------------------------------------- }

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  DataDir: String;
  Response: Integer;
begin
  if CurUninstallStep = usPostUninstall then
  begin
    DataDir := ExpandConstant('{commonappdata}\{#AppDataDirName}');
    if not DirExists(DataDir) then
      Exit;

    Response := MsgBox(
      'AETHRA-SEC has been removed.' + #13#10 + #13#10 +
      'Its data directory is still on this machine:' + #13#10 +
      '    ' + DataDir + #13#10 + #13#10 +
      'It contains the configuration file, the application logs, saved ' +
      'reports and capture files.' + #13#10 + #13#10 +
      'Do you want to DELETE it?' + #13#10 + #13#10 +
      'Choose No to keep everything. This is the safe answer, and it is what ' +
      'you want if you are reinstalling or if these files are evidence.',
      mbConfirmation, MB_YESNO or MB_DEFBUTTON2);

    if Response = IDYES then
    begin
      if MsgBox(
        'This permanently deletes the AETHRA-SEC configuration, logs, ' +
        'reports and capture files.' + #13#10 + #13#10 +
        'This cannot be undone. Delete them?',
        mbError, MB_YESNO or MB_DEFBUTTON2) = IDYES then
      begin
        DelTree(DataDir, True, True, True);
      end;
    end;

    MsgBox(
      'The AETHRA-SEC database was NOT removed.' + #13#10 + #13#10 +
      'Hosts, alerts, incidents, vulnerability findings and the audit trail ' +
      { A continuation line must not BEGIN with '#': the preprocessor reads
        that as a directive and aborts. Every newline constant below therefore
        follows something else on its line. }
      'live in MySQL, and an uninstaller must not destroy security ' +
      'evidence.' + #13#10 + #13#10 +
      'To remove it deliberately, drop the schema named in the configuration ' +
      'file (AETHRA_DB_NAME) using your database administration tool.',
      mbInformation, MB_OK);
  end;
end;
