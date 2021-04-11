#define MyAppName "Tactical RMM Agent"
#define MyAppVersion "1.4.14"
#define MyAppPublisher "Tactical Techs"
#define MyAppURL "https://github.com/wh1te909"
#define MyAppExeName "tacticalrmm.exe"
#define NSSM "nssm.exe"
#define MESHEXE "meshagent.exe"
#define SALTUNINSTALL "{sd}\salt\uninst.exe"
#define SALTDIR "{sd}\salt"
#define MESHDIR "{sd}\Program Files\Mesh Agent"

[Setup]
AppId={{0D34D278-5FAF-4159-A4A0-4E2D2C08139D}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName="{sd}\Program Files\TacticalAgent"
DisableDirPage=yes
SetupLogging=yes
DisableProgramGroupPage=yes
OutputBaseFilename=winagent-v{#MyAppVersion}
SetupIconFile=C:\Users\Public\Documents\rmmagent\build\onit.ico
WizardSmallImageFile=C:\Users\Public\Documents\rmmagent\build\onit.bmp
UninstallDisplayIcon={app}\{#MyAppExeName}
Compression=lzma
SolidCompression=yes
WizardStyle=modern
RestartApplications=no
CloseApplications=no
MinVersion=6.0

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "C:\Users\Public\Documents\rmmagent\tacticalrmm.exe"; DestDir: "{app}"; Flags: ignoreversion;
Source: "C:\Users\Public\Documents\rmmagent\build\nssm.exe"; DestDir: "{app}"

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent runascurrentuser

[UninstallRun]
Filename: "{app}\{#NSSM}"; Parameters: "stop tacticalagent"; RunOnceId: "stoptacagent";
Filename: "{app}\{#NSSM}"; Parameters: "remove tacticalagent confirm"; RunOnceId: "removetacagent";
Filename: "{app}\{#NSSM}"; Parameters: "stop tacticalrpc"; RunOnceId: "stoptacrpc";
Filename: "{app}\{#NSSM}"; Parameters: "remove tacticalrpc confirm"; RunOnceId: "removetacrpc";
Filename: "{app}\{#MyAppExeName}"; Parameters: "-m cleanup"; RunOnceId: "cleanuprm";
Filename: "{cmd}"; Parameters: "/c taskkill /F /IM tacticalrmm.exe"; RunOnceId: "killtacrmm";
Filename: "{#SALTUNINSTALL}"; Parameters: "/S"; RunOnceId: "saltrm"; Check: FileExists(ExpandConstant('{sd}\salt\uninst.exe'));
Filename: "{app}\{#MESHEXE}"; Parameters: "-fulluninstall"; RunOnceId: "meshrm";

[UninstallDelete]
Type: filesandordirs; Name: "{app}";
Type: filesandordirs; Name: "{#SALTDIR}"; Check: DirExists(ExpandConstant('{sd}\salt'));
Type: filesandordirs; Name: "{#MESHDIR}";

[Code]
function InitializeSetup(): boolean;
var
  ResultCode: Integer;
begin
  Exec('cmd.exe', '/c net stop tacticalagent', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Log('Stop tacticalagent: ' + IntToStr(ResultCode));
  Exec('cmd.exe', '/c net stop checkrunner', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec('cmd.exe', '/c net stop tacticalrpc', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Log('Stop tacticalrpc: ' + IntToStr(ResultCode));
  Exec('cmd.exe', '/c taskkill /F /IM tacticalrmm.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Log('taskkill: ' + IntToStr(ResultCode));

  Result := True;
end;

procedure DeinitializeSetup();
var
  ResultCode: Integer;
begin
  Exec('cmd.exe', '/c net start tacticalagent && ping 127.0.0.1 -n 2', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Log('Start tacticalagent: ' + IntToStr(ResultCode));
  Exec('cmd.exe', '/c net start tacticalrpc', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Log('Start tacticalrpc: ' + IntToStr(ResultCode));
end;

