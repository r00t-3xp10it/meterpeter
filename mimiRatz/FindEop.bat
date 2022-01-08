@echo off
:: Version: v1.0.3
:: Author: @r00t-3xp10it (ssa red team)
:: Auxiliary module of @Meterpeter v2.10.11 - FindEop module
:: Credits: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#windows---privilege-escalation
:: ----


:: List system info
echo LIST SYSTEM INFORMATION
echo -----------------------
systeminfo > systeminfo.txt
type systeminfo.txt|findstr "Host OS Registered Owner:"|findstr /V /C:"Registered Organization:"|findstr /V /C:"BIOS Version:"|findstr /V /C:"OS Build Type:"
del /f systeminfo.txt
echo.

:: List UserPrivs
whoami /user
echo.
echo.

:: List HotFixes
powershell -C "Get-HotFix|Select-Object Description,HotFixID,InstalledBy,InstalledOn|Format-table -AutoSize|Out-String -Stream|Select-Object -Skip 1|Select-Object -SkipLast 1"

:: List Privileges
whoami /priv
echo.
echo.

:: List Administrators Groups
echo LIST ADMINISTRATORS GROUPS
echo --------------------------
powershell -C "$lang = ([CultureInfo]::InstalledUICulture).Name;If($lang -iMatch '^(pt-PT)$'){net localgroup administradores|findstr /V 'Nome de alias     administradores'|findstr /V 'O comando foi'|findstr /V 'Membros --'|?{$_ -ne ''}}Else{net localgroup administrators|findstr /V 'Command'|?{$_ -ne ''}}"
echo.
echo.

:: List Stored cmdkey creds
echo STORED CMDKEY CREDENTIALS (runas)
echo ---------------------------------
cmdkey /list
echo.

:: List Environement Paths
echo LIST ENVIRONEMENT PATHS
echo -----------------------
powershell -C "$Env:Path"
echo.
echo.

cd %tmp%
:: List Unquoted Service Paths
echo UNQUOTED SERVICE PATHS
echo ----------------------
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
::echo PROGRAMS RUNNING UNDER SYSTEM PRIVILEGES
::echo ----------------------------------------
::tasklist /v /fi "username eq system"
::echo.
::echo.

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


:: DEBUG FUNCTION
::cd "C:\Users\pedro\OneDrive\Ambiente de Trabalho"
::exit
