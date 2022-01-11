<#
.SYNOPSIS
   MITRE ATT&CK - T1574

   Author: @r00t-3xp10it
   Tested Under: Windows 10 (19043) x64 bits
   Required Dependencies: Get-Acl {native}
   Optional Dependencies: none
   PS cmdlet Dev version: v1.0.3

.DESCRIPTION
   Cmdlet to search for weak directory permissions (F) (M) that
   allow attackers to EscalatePrivileges on target system [local]

.NOTES
   This cmdlet its a module of @Meterpeter C2 v2.10.11 release.
   It scans recursive $Env:PROGRAMFILES, ${Env:PROGRAMFILES(x86)}
   $Env:LOCALAPPDATA\Programs dirs for 'FullControl' or 'Modify'
   FileSystemRigths permissions, with 'Everyone:' as GroupName.

   RemarK: Parameter -usergroup 'string' can be used to change
   cmdlet default Group Name from Everyone: to SKYNET\\pedro:

.Parameter UserGroup
   The GroupName IdentityReference (default: Everyone)

.EXAMPLE
   PS C:\> .\ACLMitreT1574.ps1
   Scan recursive in pre-defined directorys for UserGroup
   'Everyone' with 'FullControl' or 'Modify' permissions.

.EXAMPLE
   PS C:\> .\ACLMitreT1574.ps1 -usergroup "SKYNET\\pedro"
   Scan recursive in pre-defined directorys for UserGroup
   'SKYNET\pedro' with 'FullControl' or 'Modify' permissions.

.INPUTS
   None. You cannot pipe objects into ACLMitreT1574.ps1

.OUTPUTS
   VulnId            : 1::ACL (Mitre T1574)
   FolderPath        : C:\Program Files (x86)\Resource Hacker
   FileSystemRights  : FullControl
   IdentityReference : Everyone
   IsInherited       : False

   VulnId            : 2::ACL (Mitre T1574)
   FolderPath        : C:\Program Files (x86)\Resource Hacker\help
   FileSystemRights  : FullControl
   IdentityReference : Everyone
   IsInherited       : True

   VulnId            : 3::ACL (Mitre T1574)
   FolderPath        : C:\Program Files (x86)\Resource Hacker\samples
   FileSystemRights  : FullControl
   IdentityReference : Everyone
   IsInherited       : True

   VulnId            : 4::ACL (Mitre T1574)
   FolderPath        : C:\Program Files (x86)\Starcraft2\OobehgtrDoncFjp
   FileSystemRights  : Modify
   IdentityReference : Everyone
   IsInherited       : False
   
.LINK
   https://attack.mitre.org/techniques/T1574/010
   https://github.com/r00t-3xp10it/meterpeter/blob/master/mimiRatz/ACLMitreT1574.ps1
#>


 [CmdletBinding(PositionalBinding=$false)] param(
   [string]$UserGroup="false"
)

$Count = 0
#Disable Powershell Command Logging for current session.
Set-PSReadlineOption –HistorySaveStyle SaveNothing|Out-Null
#Define GroupName based on language pack installed!
$LangSetting = ([CultureInfo]::InstalledUICulture).Name
If($LangSetting -iMatch '^(pt-PT)$')
{
   #SKYNET\pedro
   #SKYNET\Utilizadores
   If($UserGroup -ieq "false")
   {
      $UserGroup = "Todos"   
   }
}
Else
{
   #SKYNET\pedro
   #SKYNET\Users
   If($UserGroup -ieq "false")
   {
      $UserGroup = "Everyone"   
   }
}
#ACL Permissions
$PrivsGroups = @(
   "FullControl","Modify"
)


#Directorys to search recursive: $Env:PROGRAMFILES, ${Env:PROGRAMFILES(x86)}, $Env:LOCALAPPDATA\Programs\
$dAtAbAsEList = Get-ChildItem  -Path "$Env:PROGRAMFILES", "${Env:PROGRAMFILES(x86)}", "$Env:LOCALAPPDATA\Programs\" -Recurse -ErrorAction SilentlyContinue -Force|Where {
   $_.PSIsContainer
}|Select -ExpandProperty FullName
#Loop trough all catched paths
ForEach($Token in $dAtAbAsEList)
{
   #Exclude 'WindowsApps' from scans
   If(-not($Token -Match 'WindowsApps'))
   {
      #Loop trough folder permissions
      ForEach($Permission in $PrivsGroups)
      {
         #Get directory ACL
         $IsInHerit = (Get-Acl "$Token").Access.IsInherited | Select-Object -First 1
         (Get-Acl "$Token").Access | Where-Object {#Search for Everyone:(F) \ Everyone:(M) directory permissions (default)
            $CleanOutput = $_.FileSystemRights -Match "$Permission" -and $_.IdentityReference -Match "$UserGroup" ## pt-PT = Todos
            If($CleanOutput)
            {
               $Count++ #Write the Table 'IF' found any vulnerable permissions
               Write-Host "VulnId            : ${Count}::ACL (Mitre T1574)"
               Write-Host "FolderPath        : $Token" -ForegroundColor Green -BackgroundColor Black
               Write-Host "FileSystemRights  : $Permission" -ForegroundColor yellow
               Write-Host "IdentityReference : $UserGroup"
               Write-Host "IsInherited       : $IsInHerit`n"
            }##End of Table
         }## End of Get-Acl loop
      }##End of 2º ForEach loop
   }## End of Exclude WindowsApps
}## End of ForEach loop

