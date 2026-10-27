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
;  DETECTS them and reports honestly what is present and what is missing, and,
;  for anything missing, OFFERS to download that product's own official
;  installer from its vendor's website and start it. The operator follows that
;  vendor installer as usual. Nothing is installed without a ticked box, and
;  anything left unticked can be installed later; the application then reports
;  each missing tool as unavailable rather than pretending the feature works.
;
;  It can also register the XAMPP MySQL/MariaDB server as a Windows service
;  that starts automatically, so the database is running when AETHRA-SEC
;  starts instead of having to be started from the XAMPP Control Panel first.
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
const
  { Official download locations, checked on 24 Oct 2026. Each is the vendor's
    own installer; the operator runs it interactively. }
  UrlXampp     = 'https://sourceforge.net/projects/xampp/files/XAMPP%20Windows/8.2.12/xampp-windows-x64-8.2.12-0-VS16-installer.exe/download';
  UrlWireshark = 'https://www.wireshark.org/download/win64/Wireshark-latest-x64.exe';
  UrlNmap      = 'https://nmap.org/dist/nmap-7.992-setup.exe';
  XamppMysqld  = 'C:\xampp\mysql\bin\mysqld.exe';
  XamppMyIni   = 'C:\xampp\mysql\bin\my.ini';
  MysqlService = 'SYSTEM\CurrentControlSet\Services\mysql';

var
  PrereqPage: TOutputMsgMemoWizardPage;
  InstallPage: TInputOptionWizardPage;
  DownloadPage: TDownloadWizardPage;
  DetectionText: String;
  IdxDB, IdxCapture, IdxNmap, IdxService: Integer;

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
  S := S + 'None of them is required for AETHRA-SEC to install and start. For' + #13#10;
  S := S + 'anything MISSING, the next page can download its official installer.' + #13#10 + #13#10;
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

{ --------------------------------------------------------------------------
  Installing missing components.

  For each missing tool the operator may tick a box; the vendor's official
  installer is then downloaded to a temporary folder and started, and this
  wizard waits for it to finish. Nothing is installed silently and nothing is
  redistributed: the files come straight from each vendor's own site.
  -------------------------------------------------------------------------- }

function IsMissing(const Report: String): Boolean;
begin
  Result := Pos('MISSING', Report) = 1;
end;

function OnDownloadProgress(const Url, FileName: String; const Progress, ProgressMax: Int64): Boolean;
begin
  if (ProgressMax > 0) and (Progress = ProgressMax) then
    Log('Downloaded ' + FileName);
  Result := True;
end;

procedure RunDownloaded(const FileName, Title: String);
var
  Path: String;
  ResultCode: Integer;
begin
  Path := ExpandConstant('{tmp}\') + FileName;
  if not FileExists(Path) then
    Exit;
  MsgBox('The ' + Title + ' installer will now open.' + #13#10 + #13#10 +
         'Follow its steps and finish it. This AETHRA-SEC setup waits and ' +
         'continues when it closes.', mbInformation, MB_OK);
  if not Exec(Path, '', '', SW_SHOW, ewWaitUntilTerminated, ResultCode) then
    MsgBox('The ' + Title + ' installer could not be started: ' +
           SysErrorMessage(ResultCode) + #13#10 + 'You can install it later.',
           mbError, MB_OK)
  else if ResultCode <> 0 then
    Log(Title + ' installer exited with code ' + IntToStr(ResultCode));
end;

function Ticked(const Index: Integer): Boolean;
begin
  Result := (Index >= 0) and InstallPage.Values[Index];
end;

procedure InitializeWizard();
var
  NeedDB, NeedCapture, NeedNmap, OfferService: Boolean;
begin
  DetectionText := BuildDetectionReport();
  PrereqPage := CreateOutputMsgMemoPage(
    wpSelectTasks,
    'Third-party components',
    'What AETHRA-SEC integrates with, and what is on this machine',
    'The components below are installed and licensed separately. They are ' +
    'not bundled; the next page can download the official installer of ' +
    'anything that is missing.',
    DetectionText);

  NeedDB := IsMissing(DetectMySQL());
  NeedCapture := IsMissing(DetectTShark()) or IsMissing(DetectNpcap());
  NeedNmap := IsMissing(DetectNmap());
  OfferService := (NeedDB or FileExists(XamppMysqld)) and
                  (not RegKeyExists(HKLM, MysqlService));

  InstallPage := CreateInputOptionPage(
    PrereqPage.ID,
    'Install missing components',
    'Let this setup fetch the tools AETHRA-SEC needs',
    'Each ticked item is downloaded from its official website and its own ' +
    'installer is started. Untick anything you prefer to install yourself.',
    False, False);

  IdxDB := -1; IdxCapture := -1; IdxNmap := -1; IdxService := -1;
  if NeedDB then
  begin
    IdxDB := InstallPage.Add('XAMPP with the MySQL/MariaDB database (about 150 MB, from SourceForge)');
    InstallPage.Values[IdxDB] := True;
  end;
  if NeedCapture then
  begin
    IdxCapture := InstallPage.Add('Wireshark with TShark and the Npcap capture driver (about 90 MB, from wireshark.org) - keep "Npcap" ticked in its installer');
    InstallPage.Values[IdxCapture] := True;
  end;
  if NeedNmap then
  begin
    IdxNmap := InstallPage.Add('Nmap network scanner (about 30 MB, from nmap.org)');
    InstallPage.Values[IdxNmap] := True;
  end;
  if OfferService then
  begin
    IdxService := InstallPage.Add('Start the XAMPP database automatically with Windows (so you do not have to start MySQL in the XAMPP Control Panel each time)');
    { Ticked for a fresh XAMPP; left for the operator to decide when XAMPP was
      already here, because an existing setup may start MySQL another way. }
    InstallPage.Values[IdxService] := NeedDB;
  end;

  DownloadPage := CreateDownloadPage(SetupMessage(msgWizardPreparing),
    SetupMessage(msgPreparingDesc), @OnDownloadProgress);
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := (PageID = InstallPage.ID) and
            (IdxDB < 0) and (IdxCapture < 0) and (IdxNmap < 0) and (IdxService < 0);
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  Any: Boolean;
begin
  Result := True;
  if CurPageID <> InstallPage.ID then
    Exit;

  DownloadPage.Clear;
  Any := False;
  if Ticked(IdxDB) then
  begin
    DownloadPage.Add(UrlXampp, 'xampp-setup.exe', '');
    Any := True;
  end;
  if Ticked(IdxCapture) then
  begin
    DownloadPage.Add(UrlWireshark, 'wireshark-setup.exe', '');
    Any := True;
  end;
  if Ticked(IdxNmap) then
  begin
    DownloadPage.Add(UrlNmap, 'nmap-setup.exe', '');
    Any := True;
  end;
  if not Any then
    Exit;

  DownloadPage.Show;
  try
    try
      DownloadPage.Download;
    except
      if DownloadPage.AbortedByUser then
        Log('Component download cancelled by the operator.')
      else
        MsgBox('A download did not complete: ' + GetExceptionMessage + #13#10 + #13#10 +
               'AETHRA-SEC will still be installed. Anything that was not ' +
               'downloaded can be installed later from:' + #13#10 +
               '  XAMPP      https://www.apachefriends.org/download.html' + #13#10 +
               '  Wireshark  https://www.wireshark.org/download.html' + #13#10 +
               '  Nmap       https://nmap.org/download.html',
               mbError, MB_OK);
    end;
  finally
    DownloadPage.Hide;
  end;

  { The database first, so it is in place before anything else needs it. }
  if Ticked(IdxDB) then RunDownloaded('xampp-setup.exe', 'XAMPP');
  if Ticked(IdxCapture) then RunDownloaded('wireshark-setup.exe', 'Wireshark');
  if Ticked(IdxNmap) then RunDownloaded('nmap-setup.exe', 'Nmap');
end;

{ Register the XAMPP database as an automatic Windows service and start it. }
procedure InstallDatabaseService();
var
  ResultCode: Integer;
begin
  if not FileExists(XamppMysqld) then
  begin
    MsgBox('The XAMPP database was not found at ' + XamppMysqld + ', so it ' +
           'could not be set to start with Windows. Start MySQL from the XAMPP ' +
           'Control Panel before running AETHRA-SEC.', mbInformation, MB_OK);
    Exit;
  end;
  if RegKeyExists(HKLM, MysqlService) then
    Exit;
  if Exec(XamppMysqld, '--install mysql --defaults-file="' + XamppMyIni + '"', '',
          SW_HIDE, ewWaitUntilTerminated, ResultCode) and (ResultCode = 0) then
  begin
    Exec(ExpandConstant('{sys}\net.exe'), 'start mysql', '', SW_HIDE,
         ewWaitUntilTerminated, ResultCode);
    if ResultCode <> 0 then
      MsgBox('The database service was created but did not start now (it ' +
             'may already be running from the XAMPP Control Panel). It will ' +
             'start automatically the next time Windows starts.',
             mbInformation, MB_OK);
  end
  else
    MsgBox('The database could not be registered as a Windows service. Start ' +
           'MySQL from the XAMPP Control Panel before running AETHRA-SEC.',
           mbInformation, MB_OK);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if (CurStep = ssPostInstall) and Ticked(IdxService) then
    InstallDatabaseService();
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
