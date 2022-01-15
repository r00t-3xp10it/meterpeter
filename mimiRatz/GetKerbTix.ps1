#************************************************
# GetKerbTix.ps1
# Version 1.0
# Date: 6-11-2014
# Author: Tim Springston [MSFT]
# Description: On a specific computer the script is ran on, 
#  this script finds all logon sessions which have Kerberos
# 	tickets cached and enumerates the tickets and any ticket granting tickets.
# The tickets may be from remote or interactive users and may be 
#  any logon type session (network, batch, interactive, remote interactive...).
# This script will run on Windows Server 2008/Vista and later.
#************************************************

$FormatEnumerationLimit = -1
$ComputerName = $env:COMPUTERNAME
$UserName = [Security.Principal.WindowsIdentity]::GetCurrent().name
try{#Supress Domain not foud outputs
$ComputerDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().name
}catch{}
$Date = Get-Date


#Prepare an output file to place info into.
$ExportFile = "C:\windows\temp\" + $ComputerName + "_CachedKerberosTickets.txt"
"Cached Kerberos Tickets" | Out-File $ExportFile -Encoding utf8
"Logged on User:$UserName" | Out-File $ExportFile -Append -Encoding utf8
"Computer name: $ComputerName" | Out-File $ExportFile -Append -Encoding utf8
"Computer Domain: $ComputerDomain" | Out-File $ExportFile -Append -Encoding utf8
"Date: $Date" | Out-File $ExportFile -Append -Encoding utf8
"************************************" | Out-File $ExportFile -Append -Encoding utf8

function GetKerbSessions
	{
	$Sessions = @()
	$WMILogonSessions = gwmi win32_LogonSession
	foreach ($WMILogonSession in $WMILogonSessions)
		{
		$LUID = [Convert]::ToString($WMILogonSession.LogonID, 16)
		$LUID = '0x' + $LUID
		$Sessions += $LUID
		}
	return $sessions
	}
	
function GetKerbSessionInfo
	{
	$OS = gwmi win32_operatingsystem
	$sessions = New-Object PSObject
	if ($OS.Buildnumber -ge 9200)
		{
		$KlistSessions = klist sessions
		$Counter = 0

		foreach ($item in $KlistSessions)
			{
			if ($item -match "^\[.*\]")
				{
				$LogonId = $item.split(' ')[3]
				$LogonId = $LogonId.Replace('0:','')
				$Identity = $item.split(' ')[4]
				$Token5 = $item.Split(' ')[5]
				$AuthnMethod = $Token5.Split(':')[0]
				$LogonType = $Token5.Split(':')[1]
				$Session = New-Object PSObject
				Add-Member -InputObject $Session -MemberType NoteProperty -Name "SessionID" -Value $LogonId
				Add-Member -InputObject $Session -MemberType NoteProperty -Name "Identity" -Value $Identity
				Add-Member -InputObject $Session -MemberType NoteProperty -Name "Authentication Method" -Value $AuthnMethod			
				Add-Member -InputObject $Session -MemberType NoteProperty -Name "Logon Type" -Value $LogonType
				
				Add-Member -InputObject $sessions -MemberType NoteProperty -Name $LogonId -Value $Session
				$Session = $null
				}
			}
		}
	if ($OS.Buildnumber -lt 9200)
		{
		$WMILogonSessions = gwmi win32_LogonSession
		foreach ($WMILogonSession in $WMILogonSessions)
			{
			$LUID = [Convert]::ToString($WMILogonSession.LogonID, 16)
			$LUID = '0x' + $LUID
			$Session = New-Object PSObject
			Add-Member -InputObject $Session -MemberType NoteProperty -Name "SessionID" -Value $LUID
			Add-Member -InputObject $Session -MemberType NoteProperty -Name "Identity" -Value "Not available"
			Add-Member -InputObject $Session -MemberType NoteProperty -Name "Authentication Method" -Value $WMILogonSession.AuthenticationPackage		
			Add-Member -InputObject $Session -MemberType NoteProperty -Name "Logon Type" -Value $WMILogonSession.LogonType
				
			Add-Member -InputObject $sessions -MemberType NoteProperty -Name $LUID -Value $Session
			$Session = $null
			}
		}
	return $sessions
	}

function ReturnSessionTGTs
	{
	param ($SessionID = $null)
	if ($SessionID -eq $null)
		{
		$RawTGT =  klist.exe tgt
		}
		else
			{
			$RawTGT =  klist.exe tgt -li $sessionID
			}
	$TGT = @()
	foreach ($Line in $RawTGT)
		{
		if ($Line.length -ge 1)
			{
			$TGT += $Line
			}
		}
	if ($TGT -contains 'Error calling API LsaCallAuthenticationPackage (Ticket Granting Ticket substatus): 1312')
		{$TGT = 'No ticket granting ticket cached in session.'}
	return $TGT
	}	

function ReturnSessionTickets 
	{
	param ($SessionID = $null)
	$OS = gwmi win32_operatingsystem
	if ($SessionID -eq $null)
		{
		$TicketsArray =  klist.exe tickets
		}
		else
			{
			$TicketsArray =  klist.exe tickets -li $sessionID
			}
	$Counter = 0
	$TicketsObject = New-Object PSObject
	foreach ($line in $TicketsArray)
		{
		if ($line -match "^#\d")
			{
			$Ticket = New-Object PSObject
			$Number = $Line.Split('>')[0]
			$Line1 = $Line.Split('>')[1]
			$TicketNumber = "Ticket " + $Number
			$Client = $Line1 ;	$Client = $Client.Replace('Client:','') ; $Client = $Client.Substring(2)
			$Server = $TicketsArray[$Counter+1]; $Server = $Server.Replace('Server:','') ;$Server = $Server.substring(2)
			$KerbTicketEType = $TicketsArray[$Counter+2];$KerbTicketEType = $KerbTicketEType.Replace('KerbTicket Encryption Type:','');$KerbTicketEType = $KerbTicketEType.substring(2)
			$TickFlags = $TicketsArray[$Counter+3];$TickFlags = $TickFlags.Replace('Ticket Flags','');$TickFlags = $TickFlags.substring(2)
			$StartTime =  $TicketsArray[$Counter+4];$StartTime = $StartTime.Replace('Start Time:','');$StartTime = $StartTime.substring(2)
			$EndTime = $TicketsArray[$Counter+5];$EndTime = $EndTime.Replace('End Time:','');$EndTime = $EndTime.substring(4)
			$RenewTime = $TicketsArray[$Counter+6];$RenewTime = $RenewTime.Replace('Renew Time:','');$RenewTime = $RenewTime.substring(2)
			$SessionKey = $TicketsArray[$Counter+7];$SessionKey = $SessionKey.Replace('Session Key Type:','');$SessionKey = $SessionKey.substring(2)

			Add-Member -InputObject $Ticket -MemberType NoteProperty -Name "Client" -Value $Client
			Add-Member -InputObject $Ticket -MemberType NoteProperty -Name "Server" -Value $Server
			Add-Member -InputObject $Ticket -MemberType NoteProperty -Name "KerbTicket Encryption Type" -Value $KerbTicketEType
			Add-Member -InputObject $Ticket -MemberType NoteProperty -Name "Ticket Flags" -Value $TickFlags
			Add-Member -InputObject $Ticket -MemberType NoteProperty -Name "Start Time" -Value $StartTime
			Add-Member -InputObject $Ticket -MemberType NoteProperty -Name "End Time" -Value $EndTime
			Add-Member -InputObject $Ticket -MemberType NoteProperty -Name "Renew Time" -Value $RenewTime
			Add-Member -InputObject $Ticket -MemberType NoteProperty -Name "Session Key Type" -Value $SessionKey

			if ($OS.BuildNumber -ge 9200)
				{
				$CacheFlags =  $TicketsArray[$Counter+8];$CacheFlags = $CacheFlags.Replace('Cache Flags:','');$CacheFlags = $CacheFlags.substring(2)
				$KDCCalled = $TicketsArray[$Counter+9];$KDCCalled = $KDCCalled.Replace('Kdc Called:','');$KDCCalled = $KDCCalled.substring(2)
				Add-Member -InputObject $Ticket -MemberType NoteProperty -Name "Cache Flags" -Value $CacheFlags
				Add-Member -InputObject $Ticket -MemberType NoteProperty -Name "KDC Called" -Value $KDCCalled
				}
			Add-Member -InputObject $TicketsObject -MemberType NoteProperty -Name $TicketNumber -Value $Ticket
			$Ticket = $null
			}
		$Counter++
		

		}
	return $TicketsObject
	}	

$OS = gwmi win32_operatingsystem
$sessions = getkerbsessions
$sessioninfo = GetKerbSessionInfo
foreach ($Session in $sessions)
{	
	#Get Session details as well
	$currentsessioninfo = $sessioninfo.$session
	$ID = $currentsessioninfo.identity
	$SessionID = $currentsessioninfo.SessionID
	$LogonType = $currentsessioninfo.'Logon Type'
	$AuthMethod = $currentsessioninfo.'Authentication Method'
	if ($OS.Buildnumber -lt 9200)
		{
		Write-Host "Kerberos Tickets for LogonID $SessionID"
		"Kerberos Tickets for LogonID $SessionID" | Out-File $ExportFile -Append -Encoding utf8
		}
		else
		{
		Write-Host "Kerberos Tickets for $ID"
		"Kerberos Tickets for $ID" | Out-File $ExportFile -Append -Encoding utf8
		}
	Write-Host "*****************************"
	 "*****************************" | Out-File $ExportFile -Append -Encoding utf8
	Write-Host "Logon Type: $LogonType"
	"Logon Type: $LogonType" | Out-File $ExportFile -Append -Encoding utf8
	Write-host "Session ID: $SessionID"
	"Session ID: $SessionID" | Out-File $ExportFile -Append -Encoding utf8
	Write-host "Auth Method: $AuthMethod"
	"Auth Method: $AuthMethod" | Out-File $ExportFile -Append -Encoding utf8
	$SessionTickets = ReturnSessionTickets $Session

	
	$TGT = ReturnSessionTGTs $SessionID
	$TGT | FL *
	$TGT | Out-File $ExportFile -Append -Encoding utf8
	
	if ($SessionTickets -notmatch 'Ticket')
		{
		Write-Host "Session TGT: No tickets for this session in cache."
		"Session TGT: No tickets for this session in cache." | Out-File $ExportFile -Append -Encoding utf8
		}
		else
		{
		$SessionTickets | FL *
		$SessionTickets	| FL * | Out-File $ExportFile -Append -Encoding utf8 
		}
	Write-Host "`n"
	 "`n" | Out-File $ExportFile -Append -Encoding utf8

}

#Clean artifacts left behind
Remove-Item -Path "$ExportFile" -Force
