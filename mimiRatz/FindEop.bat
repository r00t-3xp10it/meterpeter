@echo off
:: Version: v1.1.7
:: Author: @r00t-3xp10it (ssa red team @2022)
:: Helper: Auxiliary module of @Meterpeter v2.10.11 - FindEop module
:: Methodology: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#windows---privilege-escalation
:: ----
TITLE @FindEop v1.1.7


:: List system info
echo SYSTEM INFORMATION
echo ------------------
systeminfo > systeminfo.txt
type systeminfo.txt|findstr "Host OS Registered Owner: Locale:"|findstr /V /C:"Registered Organization:"|findstr /V /C:"BIOS Version:"|findstr /V /C:"OS Build Type:"|findstr /V /C:"Input Locale:"
del /f systeminfo.txt
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

:: Environement Paths
echo ENVIRONEMENT PATHS
echo ------------------
powershell -C "($Env:Path) -split ';'"
echo.

:: Check icacls
where /q icacls
IF ERRORLEVEL 1 (
    echo icacls is missing, performing checks using cacls for older versions of Windows
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

:: Program Files and User Directorys with full or modify permisions
echo DIRECTORYS WITH FULL OR MODIFY PERMISSIONS
echo ------------------------------------------
:: Get system default language installed to build variables
FOR /F "tokens=*" %%a in ('powershell -C "([CultureInfo]::InstalledUICulture).Name"') do SET OUTPUT=%%a
:: This function supports 'pt-PT' or 'en-ENG' languages, change vars 'token=' and 'viriato=' for diferent lang
if %OUTPUT%==pt-PT (set token=Utilizadores&&set viriato=Todos) ELSE (set token=Users&&set viriato=Everyone)

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

:: List programs running under system privs
echo PROGRAMS RUNNING UNDER SYSTEM PRIVILEGES
echo ----------------------------------------
powershell -C "tasklist /fi 'username eq system'|Format-Table|Out-String -Stream|Select-Object -Skip 1"
echo.
echo.

:: Link running processes to started services
echo LINK RUNNING PROCESSES TO STARTED SERVICES
echo ------------------------------------------
powershell -C "tasklist /SVC|Format-Table|Out-String -Stream|Select-Object -Skip 1"
echo.
echo.

:: List unattend.xml files
echo LIST UNATTEND.XML FILES EXISTENCE
echo Creds are stored in base64 and can be decoded manually.
echo -------------------------------------------------------
powershell -C "(Get-ChildItem $Env:WINDIR\unattend.xml -EA SilentlyContinue|Select-Object *).FullName"
powershell -C "(Get-ChildItem $Env:WINDIR\Panther\Unattend.xml -EA SilentlyContinue|Select-Object *).FullName"
powershell -C "(Get-ChildItem $Env:WINDIR\system32\sysprep.inf -EA SilentlyContinue|Select-Object *).FullName"
powershell -C "(Get-ChildItem $Env:WINDIR\Panther\Unattend\Unattend.xml -EA SilentlyContinue|Select-Object *).FullName"
powershell -C "(Get-ChildItem $Env:WINDIR\system32\sysprep\sysprep.xml -EA SilentlyContinue|Select-Object *).FullName"
echo.
echo.

:: List AlwaysInstallElevated
echo REGISTRY ALWAYSINSTALLELEVATED
echo ------------------------------
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
echo.
echo.

:: Registry raw credentials search
echo REGISTRY RAW CREDENTIALS SEARCH
echo -------------------------------
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"|findstr "LastUsedUsername DefaultUserName DefaultDomainName DefaultPassword"
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SOFTWARE\RealVNC\WinVNC4 /v password"
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"
echo.
echo.

:: Get Domain Controllers
echo GET DOMAIN CONTROLLERS
echo ----------------------
powershell -C "$DomainControler = $Env:USERDOMAIN;echo ::DCName::[$DomainControler];nltest /DCNAME:$DomainControler|Out-Null;nltest /DSGETDC:$DomainControler|Out-Null;nltest /DCLIST:$DomainControler|Out-Null"
echo.
echo.


:: DEBUG FUNCTION
:: Change directory to %tmp% to run sherlock.ps1
::cd %tmp%
::exit