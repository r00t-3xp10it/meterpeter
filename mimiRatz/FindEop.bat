@echo off
:: Version: v1.1.5
:: Author: @r00t-3xp10it (ssa red team)
:: Auxiliary module of @Meterpeter v2.10.11 - FindEop module
:: Credits: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#windows---privilege-escalation
:: ----
TITLE @FindEop v1.1.5


:: List system info
echo SYSTEM INFORMATION
echo ------------------
systeminfo > systeminfo.txt
type systeminfo.txt|findstr "Host OS Registered Owner: Locale:"|findstr /V /C:"Registered Organization:"|findstr /V /C:"BIOS Version:"|findstr /V /C:"OS Build Type:"|findstr /V /C:"Input Locale:"
del /f systeminfo.txt
echo.

:: List UserPrivs
whoami /user
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

:: List Privileges
powershell -C "whoami /priv|Format-Table -AutoSize"
echo.
echo.

:: List Environement Paths
echo LIST ENVIRONEMENT PATHS
echo -----------------------
powershell -C "($Env:Path) -split ';'"
echo.

:: Program Files and User Directorys with full or modify permisions
echo DIRECTORYS WITH FULL OR MODIFY PERMISSIONS
echo ------------------------------------------
:: Get system default language installed to build variables
FOR /F "tokens=*" %%a in ('powershell -C "([CultureInfo]::InstalledUICulture).Name"') do SET OUTPUT=%%a
:: This function supports 'pt-PT' or 'en-ENG' languages, change vars 'token=' and 'viriato=' for diferent lang
if %OUTPUT%==pt-PT (set token=Utilizadores&&set viriato=Todos) ELSE (set token=Users&&set viriato=Everyone)

where /q icacls
IF ERRORLEVEL 1 (
    echo icacls is missing, performing checks using cacls for older versions of Windows
    FOR /F "tokens=* USEBACKQ" %%F IN (`where cacls`) DO (SET cacls_exe=%%F)
) ELSE (
    FOR /F "tokens=* USEBACKQ" %%F IN (`where icacls`) DO (SET cacls_exe=%%F)
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
::powershell -C "gwmi -class Win32_Service -Property Name,DisplayName,PathName,StartMode,StartName|Where-Object {$_.StartMode -eq 'Auto' -and $_.StartName -eq 'LocalSystem' -and $_.PathName -NotLike 'C:\Windows*' -and $_.PathName -NotMatch '""' -and $_.Name -iNotMatch '^(SAService)'}|Select-Object PathName,Name|Format-table -AutoSize"
sc query state= all > scoutput.txt
findstr "SERVICE_NAME:" scoutput.txt > Servicenames.txt
FOR /F "tokens=2 delims= " %%i in (Servicenames.txt) DO @echo %%i >> services.txt
FOR /F %%i in (services.txt) DO @sc qc %%i | findstr "BINARY_PATH_NAME" >> path.txt
find /v """" path.txt > unquotedpaths.txt
sort unquotedpaths.txt|findstr /i /v C:\WINDOWS|findstr /V /C:"---------- PATH.TXT"
del /f Servicenames.txt
del /f services.txt
del /f path.txt
del /f scoutput.txt
del /f unquotedpaths.txt
echo.
echo.

:: List Programs that run at startup
echo PROGRAMS THAT RUN AT STARTUP
echo ----------------------------
powershell -C "Get-CimInstance Win32_StartupCommand|Select-Object Name,command,Location,User|Format-List"

:: List programs running under system privs
echo PROGRAMS RUNNING UNDER SYSTEM PRIVILEGES
echo ----------------------------------------
powershell -C "tasklist /fi 'username eq system'|Format-Table|Out-String -Stream|Select-Object -Skip 1"
echo.
echo.
echo.

:: Link running processes to started services
echo LINK RUNNING PROCESSES TO STARTED SERVICES
echo ------------------------------------------
tasklist /SVC
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
