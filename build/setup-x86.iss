#define MyAppName "Tactical RMM Agent"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "Tactical Techs"
#define MyAppURL "https://github.com/wh1te909"
#define MyAppExeName "tacticalrmm.exe"
#define NSSM "nssm-x86.exe"
#define MESHEXE "meshagent-x86.exe"
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
DisableProgramGroupPage=yes
OutputBaseFilename=winagent-v{#MyAppVersion}-x86
SetupIconFile=C:\Users\Public\Documents\rmmagent\build\onit.ico
WizardSmallImageFile=C:\Users\Public\Documents\rmmagent\build\onit.bmp
UninstallDisplayIcon={app}\{#MyAppExeName}
Compression=lzma
SolidCompression=yes
WizardStyle=modern

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "C:\Users\Public\Documents\rmmagent\tacticalrmm.exe"; DestDir: "{app}"; Flags: ignoreversion; BeforeInstall: StopServices;
Source: "C:\Users\Public\Documents\rmmagent\build\nssm-x86.exe"; DestDir: "{app}"; Flags: ignoreversion;
Source: "C:\Users\Public\Documents\rmmagent\build\saltcustom"; DestDir: "{app}"; Flags: ignoreversion; AfterInstall: StartServices;

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent runascurrentuser

[UninstallRun]
Filename: "{app}\{#NSSM}"; Parameters: "stop tacticalagent"; RunOnceId: "stoptacagent";
Filename: "{app}\{#NSSM}"; Parameters: "remove tacticalagent confirm"; RunOnceId: "removetacagent";
Filename: "{app}\{#NSSM}"; Parameters: "stop checkrunner"; RunOnceId: "stopcheckrun";
Filename: "{app}\{#NSSM}"; Parameters: "remove checkrunner confirm"; RunOnceId: "removecheckrun";
;Filename: "{app}\{#MyAppExeName}"; Parameters: "-m cleanup"; RunOnceId: "cleanuprm";
Filename: "{#SALTUNINSTALL}"; Parameters: "/S"; RunOnceId: "saltrm";
Filename: "{app}\{#MESHEXE}"; Parameters: "-fulluninstall"; RunOnceId: "meshrm";

[UninstallDelete]
Type: filesandordirs; Name: "{app}";
Type: filesandordirs; Name: "{#SALTDIR}";
Type: filesandordirs; Name: "{#MESHDIR}";

[Code]
procedure StopServices();
var
  ResultCode: Integer;
  StopTactical: string;
  StopCheckrunner: string;
begin
  StopTactical := ExpandConstant(' /c "{app}\{#NSSM}"' + ' stop tacticalagent && ping 127.0.0.1 -n 5');
  StopCheckrunner := ExpandConstant(' /c "{app}\{#NSSM}"' + ' stop checkrunner && ping 127.0.0.1 -n 5');
  Exec('cmd.exe', StopTactical, '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec('cmd.exe', StopCheckrunner, '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

procedure StartServices();
var
  ResultCode: Integer;
  StartTactical: string;
  StartCheckrunner: string;
begin
  StartTactical := ExpandConstant(' /c "{app}\{#NSSM}"' + ' start tacticalagent && ping 127.0.0.1 -n 7');
  StartCheckrunner := ExpandConstant(' /c "{app}\{#NSSM}"' + ' start checkrunner && ping 127.0.0.1 -n 3');
  Exec('cmd.exe', StartTactical, '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec('cmd.exe', StartCheckrunner, '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

