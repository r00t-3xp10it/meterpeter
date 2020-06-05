<#
.SYNOPSIS
  Standalone Powershell script that will dump Local-Host browser(s) information.

.Author r00t-3xp10it (SSA RedTeam @2020)
  Required Dependencies: Local Web Browser (Installed)
  Optional Dependencies: None

.DESCRIPTION
   Standalone Powershell script to dump Local-host browser information sutch as: HomePage, Browser Version
   Language Used, Download Directory, URL History, etc.. The dumps will be created in Local-host $env:tmp

.EXAMPLE
   PS C:\> ./GetBrowser.ps1
   Enumerates Internet Explorer, FireFox and Chrome Browsers info.

.LINK 
    https://github.com/r00t-3xp10it/meterpeter
    https://github.com/rvrsh3ll/Misc-Powershell-Scripts/blob/master/Get-BrowserData.ps1 (flagged by AV)
#>


$RFP = $null
$Path = $null
$JsPrefs = $null
$RegPrefs = $null
$ParsingData = $null
## GetBrowser PS Script Banner
Write-Host "GetBrowser - Dump Remote-Host Browser(s) Information." -ForeGroundColor Green
Write-Host "[i] Dumping Data To: `$env:tmp\BrowserEnum.log" -ForeGroundColor yellow -BackgroundColor Black
Start-sleep -Seconds 2


## Retrieve IE Browser Information
$IEVersion = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer" -Name 'Version' -ErrorAction SilentlyContinue|Select-Object 'Version'
If(-not($IEVersion) -or $IEVersion -eq $null){
    echo "`n`nIE Browser" > $env:tmp\BrowserEnum.log
    echo "----------" >> $env:tmp\BrowserEnum.log
    echo "Could not find any IE Browser Info .." >> $env:tmp\BrowserEnum.log
}else{
    $IEData = $IEVersion -replace '@{Version=','Version      : ' -replace '}',''
    $KBNumber = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer" -Name 'svcKBNumber'|Select-Object 'svcKBNumber'
    $KBData = $KBNumber -replace '@{svcKBNumber=','KBUpdate     : ' -replace '}',''
    $RegPrefs = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Internet Explorer\Main\" -Name 'start page'|Select-Object 'Start Page'
    $ParsingData = $RegPrefs -replace '@{Start Page=','HomePage     : ' -replace '}',''
    ## Build Remote LogFile
    echo "`n`nIE Browser" > $env:tmp\BrowserEnum.log
    echo "----------" >> $env:tmp\BrowserEnum.log
    echo "$KBData" >> $env:tmp\BrowserEnum.log
    echo "$IEData" >> $env:tmp\BrowserEnum.log
    echo "$ParsingData" >> $env:tmp\BrowserEnum.log
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



## function Get-InternetExplorerBookmarks
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
                        Write-Verbose "Error parsing url: $_"
                    }
                }
            }
        }



## Retrieve FireFox Browser Information
$Path = Test-Path "$env:APPDATA\Mozilla\Firefox\Profiles";
If($Path -eq $True){
    ## change to the correct directory structure
    cd $env:APPDATA\Mozilla\Firefox\Profiles\*.default

    ## get PlatformVersion
    $JsPrefs = Get-content prefs.js|Select-String "extensions.lastPlatformVersion"
    $ParsingData = $JsPrefs[0] -replace 'user_pref\(','' -replace '\"','' -replace ',',':' -replace '\);','' -replace 'extensions.lastPlatformVersion','Version      '
    echo "`n`nFireFox Browser" >> $env:tmp\BrowserEnum.log
    echo "---------------" >> $env:tmp\BrowserEnum.log
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


## Get Google Chrome Version
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


### ----


## Retrieve Remote Info from LogFile
Get-Content $env:tmp\BrowserEnum.log;# Remove-Item $env:tmp\BrowserEnum.log -Force
Write-Host "`n`n";Write-Host "[i] DumpLogFile: `$env:tmp\BrowserEnum.log" -ForeGroundColor yellow -BackGroundColor Black
Start-sleep -Seconds 4
exit
