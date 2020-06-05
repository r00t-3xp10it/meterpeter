<#
.SYNOPSIS
  Standalone Powershell script that will dump Local-Host browser(s) information.

.Author r00t-3xp10it (SSA RedTeam @2020)
  Required Dependencies: Local Web Browser (Installed)
  Optional Dependencies: None

.DESCRIPTION
   Standalone Powershell script to dump Local-host browser information sutch as: Home Page, Browser Version
   Language Used, Download Directory, URL History, Bookmarks, etc.. The dumps will be created in $env:tmp

.EXAMPLE
   PS C:\> ./GetBrowser.ps1 -ALL
   Enumerates Internet Explorer, FireFox and Chrome Browsers info.

.PARAMETERS
   PS C:\> ./GetBrowser.ps1 -HELP
   Displays GetBrowser.ps1 help discription.

.PARAMETERS
   PS C:\> ./GetBrowser.ps1 -FIREFOX
   Enumerates FireFox Browser information Only.

.LINK 
    https://github.com/r00t-3xp10it/meterpeter
    https://github.com/r00t-3xp10it/meterpeter\mimRatz\GetBrowser.ps1
    https://github.com/rvrsh3ll/Misc-Powershell-Scripts/blob/master/Get-BrowserData.ps1 (flagged by AV)
#>

$RFP = $null
$Path = $null
$JsPrefs = $null
$RegPrefs = $null
$param1 = $args[0]
$ParsingData = $null


## Help Menu (parameter)
function HELP_MENU {
  If($param1 -eq "-help"){
    write-host "`n"
    write-host ".Author r00t-3xp10it (SSA RedTeam @2020)" -ForegroundColor Green
    write-host "  Required Dependencies: Local Web Browser (Installed)"
    write-host "  Optional Dependencies: None"
    write-host "`n"
    write-host ".DESCRIPTION" -ForegroundColor Green
    write-host "  Standalone Powershell script to dump Local-host browser information sutch as:"
    write-host "  Home Page, Browser Version, ContryCode, Download Dir, URL History, Bookmarks,"
    write-host "  etc.. The dumps will be Saved in `$env:tmp folder for later review."
    write-host "`n"
    write-host ".EXAMPLE" -ForegroundColor Green
    write-host "  PS C:\> ./GetBrowser.ps1 -ALL"
    write-host "  Enumerates Internet Explorer, FireFox and Chrome Browsers info."
    write-host "`n"
    write-host ".PARAMETERS" -ForegroundColor Green
    write-host "  PS C:\> ./GetBrowser.ps1 -FIREFOX"
    write-host "  Enumerates FireFox Browser information Only."
    write-host "`n"
    write-host ".LINK" -ForegroundColor Green
    write-host "  https://github.com/r00t-3xp10it/meterpeter"
    write-host "  https://github.com/r00t-3xp10it/meterpeter\mimRatz\GetBrowser.ps1"
    exit
  }
}


## GetBrowser PS Script Banner
Write-Host "GetBrowser - Dump Local-Host Browsers Information." -ForeGroundColor Green
Write-Host "[i] Dumping Data To: `$env:tmp\BrowserEnum.log" -ForeGroundColor yellow -BackgroundColor Black
Start-sleep -Seconds 2

## Get Default WebBrowser
$Registry = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $Env:ComputerName)
$RegistryKey = $Registry.OpenSubKey("SOFTWARE\\Classes\\http\\shell\\open\\command")
$Value = $RegistryKey.GetValue("") -replace '%1','' -replace '"',''
echo "`n`nDefault Browser" > $env:tmp\BrowserEnum.log
echo "---------------" >> $env:tmp\BrowserEnum.log
echo "$Value" >> $env:tmp\BrowserEnum.log


## Retrieve IE Browser Information
function IE_Dump {
$IEVersion = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer" -Name 'Version' -ErrorAction SilentlyContinue|Select-Object 'Version'
If(-not($IEVersion) -or $IEVersion -eq $null){
    echo "`n`nIE Browser" >> $env:tmp\BrowserEnum.log
    echo "----------" >> $env:tmp\BrowserEnum.log
    echo "Could not find any IE Browser Info .." >> $env:tmp\BrowserEnum.log
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
    ## Build Remote LogFile
    echo "`n`nIE Browser" >> $env:tmp\BrowserEnum.log
    echo "----------" >> $env:tmp\BrowserEnum.log
    echo "$KBData" >> $env:tmp\BrowserEnum.log
    echo "$IEData" >> $env:tmp\BrowserEnum.log
    echo "$ParsingIntSet" >> $env:tmp\BrowserEnum.log 
    echo "$ParsingData" >> $env:tmp\BrowserEnum.log
    echo "$ParsingLocal" >> $env:tmp\BrowserEnum.log
}

## Retrieve IE history URLs
$IEHistory = Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Internet Explorer\TypedURLs" -ErrorAction SilentlyContinue|findstr /B /I "url"
If(-not($IEHistory) -or $IEHistory -eq $null){
    echo "`nIE Browser History" >> $env:tmp\BrowserEnum.log
    echo "------------------" >> $env:tmp\BrowserEnum.log
    echo "Could not find any IE History Info .." >> $env:tmp\BrowserEnum.log
}else{
    echo "`nIE Browser History" >> $env:tmp\BrowserEnum.log
    echo "------------------" >> $env:tmp\BrowserEnum.log
    Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Internet Explorer\TypedURLs"|findstr /B /I "url" >> $env:tmp\BrowserEnum.log
}

## Retrieve Internet Explorer Bookmarks
echo "`nIE Bookmarks" >> $env:tmp\BrowserEnum.log
echo "------------" >> $env:tmp\BrowserEnum.log
$URLs = Get-ChildItem -Path "$Env:systemdrive\Users\" -Filter "*.url" -Recurse -ErrorAction SilentlyContinue
ForEach ($URL in $URLs) {
    if ($URL.FullName -match 'Favorites') {
        $User = $URL.FullName.split('\')[2]
        Get-Content -Path $URL.FullName | ForEach-Object {
            try {
                if ($_.StartsWith('URL')) {
                    # parse the .url body to extract the actual bookmark location
                    $URL = $_.Substring($_.IndexOf('=') + 1)
                        if($URL -match $Search) {
                            echo "$URL" >> $env:tmp\BrowserEnum.log
                        }
                }
            }
            catch {
                echo "Error parsing url: $_" >> $env:tmp\BrowserEnum.log
            }
        }
    }
}
}


## Retrieve FireFox Browser Information
function FIREFOX {
$Path = Test-Path "$env:APPDATA\Mozilla\Firefox\Profiles";
If($Path -eq $True){
    ## change to the correct directory structure
    cd $env:APPDATA\Mozilla\Firefox\Profiles\*.default
    echo "`n`nFireFox Browser" >> $env:tmp\BrowserEnum.log
    echo "---------------" >> $env:tmp\BrowserEnum.log

    ## get browser countryCode
    $JsPrefs = Get-content prefs.js|Select-String "browser.search.countryCode";
    $ParsingData = $JsPrefs[0] -replace 'user_pref\(','' -replace '\"','' -replace ',',':' -replace '\);','' -replace 'browser.search.countryCode','countryCode  '
    echo "$ParsingData" >> $env:tmp\BrowserEnum.log

    ## get PlatformVersion
    $JsPrefs = Get-content prefs.js|Select-String "extensions.lastPlatformVersion"
    $ParsingData = $JsPrefs[0] -replace 'user_pref\(','' -replace '\"','' -replace ',',':' -replace '\);','' -replace 'extensions.lastPlatformVersion','Version      '
    echo "$ParsingData" >> $env:tmp\BrowserEnum.log

    ## get browser plugin.flash.version
    $JsPrefs = Get-content prefs.js|Select-String "plugin.flash.version";
    $ParsingData = $JsPrefs[0] -replace 'user_pref\(','' -replace '\"','' -replace ',',':' -replace '\);','' -replace 'plugin.flash.version','flash        '
    echo "$ParsingData" >> $env:tmp\BrowserEnum.log

    ## get brownser startup page
    $JsPrefs = Get-content prefs.js|Select-String "browser.startup.homepage"
    $ParsingData = $JsPrefs[0] -replace 'user_pref\(','' -replace '\"','' -replace ',',':' -replace '\);','' -replace 'browser.startup.homepage','HomePage     '
    echo "$ParsingData" >> $env:tmp\BrowserEnum.log

    ## get browser DownloadDir
    $JsPrefs = Get-content prefs.js|Select-String "browser.download.lastDir";
    $ParsingData = $JsPrefs[0] -replace 'user_pref\(','' -replace '\"','' -replace ',',':' -replace '\);','' -replace 'browser.download.lastDir','Downloads    '
    echo "$ParsingData" >> $env:tmp\BrowserEnum.log
}else{
    echo "`n`nFireFox Browser" >> $env:tmp\BrowserEnum.log
    echo "---------------" >> $env:tmp\BrowserEnum.log
    echo "Could not find any FireFox Info .." >> $env:tmp\BrowserEnum.log
}

## Dump FIREFOX HISTORY URLs
If($Path -eq $False) {
    echo "`nFireFox History" >> $env:tmp\BrowserEnum.log
    echo "---------------" >> $env:tmp\BrowserEnum.log
    echo "Could not find any FireFox History URLs .." >> $env:tmp\BrowserEnum.log
}else{
    $Profiles = Get-ChildItem "$env:AppData\Mozilla\Firefox\Profiles\*.default\"
    $Regex = '([a-zA-Z]{3,})://([\w-]+\.)+[\w-]+(/[\w- ./?%&=]*)*?'
    echo "`nFireFox History" >> $env:tmp\BrowserEnum.log
    echo "---------------" >> $env:tmp\BrowserEnum.log
    Get-Content $Profiles\places.sqlite | Select-String -Pattern $Regex -AllMatches | % { $_.Matches } | % { $_.Value } | Sort-Object -Unique | % {
        $Value = New-Object -TypeName PSObject -Property @{
            FireFoxHistoryURL = $_
        }
        if ($Value -match $Search) {
            $ParsingData = $Value -replace '@{FireFoxHistoryURL=','' -replace '}',''
            echo "$ParsingData" >> $env:tmp\BrowserEnum.log
        }
    }
}
}


## Get Google Chrome Version
function CHROME {
$Path = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Window\CurrentVersion\App Paths\chrome.exe' -ErrorAction SilentlyContinue
If(-not($Path) -or $Path -eq $null){
    echo "`n`nChrome Browser" >> $env:tmp\BrowserEnum.log
    echo "--------------" >> $env:tmp\BrowserEnum.log
    echo "Could not find any Chrome Info .." >> $env:tmp\BrowserEnum.log
}else{
    $GCVersionInfo = (Get-Item (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Window\CurrentVersion\App Paths\chrome.exe').'(Default)').VersionInfo
    $GCVersion = $GCVersionInfo.ProductVersion
    echo "`n`nChrome Browser" >> $env:tmp\BrowserEnum.log
    echo "--------------" >> $env:tmp\BrowserEnum.log
    echo "Version      : $GCVersion" >> $env:tmp\BrowserEnum.log
}
}


### ----

## Jump Links (Functions)
If(-not($param1)){HELP_MENU}
If($param1 -eq "-IE"){IE_Dump}
If($param1 -eq "-HELP"){HELP_MENU}
If($param1 -eq "-FIREFOX"){FIREFOX}
If($param1 -eq "-CHROME"){CHROME}
If($param1 -eq "-ALL"){IE_Dump;FIREFOX;CHROME}


## Retrieve Remote Info from LogFile
Get-Content $env:tmp\BrowserEnum.log;# Remove-Item $env:tmp\BrowserEnum.log -Force
Write-Host "`n`n";Write-Host "[i] DumpLogFile: `$env:tmp\BrowserEnum.log" -ForeGroundColor yellow -BackGroundColor Black
Start-sleep -Seconds 4
exit
