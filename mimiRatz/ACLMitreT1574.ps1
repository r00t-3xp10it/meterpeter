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
#Define the GroupName based on the language pack installed!
$LanguageSetting = ([CultureInfo]::InstalledUICulture).Name
If($LanguageSetting -iMatch '^(pt-PT)$')
{
   If($UserGroup -ieq "false")
   {
      #Todos
      #SKYNET\pedro
      #$Env:USERDOMAIN\Utilizadores
      $UserGroup = "Todos"   
   }
}
Else
{
   If($UserGroup -ieq "false")
   {
      #Everyone
      #SKYNET\pedro
      #$Env:USERDOMAIN\Users
      $UserGroup = "Everyone"   
   }
}
#ACL Permissions
$DirectoryPermission = @(
   "FullControl","Modify"
)


#Directorys to search recursive: $Env:PROGRAMFILES, ${Env:PROGRAMFILES(x86)}, $Env:LOCALAPPDATA\Programs\
$RawDataBaseList = Get-ChildItem  -Path "$Env:PROGRAMFILES", "${Env:PROGRAMFILES(x86)}", "$Env:LOCALAPPDATA\Programs\" -Recurse -ErrorAction SilentlyContinue -Force | Where-Object {
   $_.PSIsContainer
}|Select -ExpandProperty FullName
#Loop trough all catched paths
ForEach($TokenPath in $RawDataBaseList)
{
   #Exclude 'WindowsApps' from scans
   If(-not($TokenPath -Match 'WindowsApps'))
   {
      #Loop trough folder permissions
      ForEach($ACLPermission in $DirectoryPermission)
      {
         #Get directory ACL
         $IsInHerit = (Get-Acl "$TokenPath").Access.IsInherited | Select-Object -First 1
         (Get-Acl "$TokenPath").Access | Where-Object {#Search for Everyone:(F) \ Everyone:(M) directory permissions (default)
            $CleanOutput = $_.FileSystemRights -Match "$ACLPermission" -and $_.IdentityReference -Match "$UserGroup" ## pt-PT = Todos
            If($CleanOutput)
            {
               $Count++ #Write the Table 'IF' found any vulnerable permissions
               Write-Host "VulnId            : ${Count}::ACL (Mitre T1574)"
               Write-Host "FolderPath        : $TokenPath" -ForegroundColor Green -BackgroundColor Black
               Write-Host "FileSystemRights  : $ACLPermission" -ForegroundColor yellow
               Write-Host "IdentityReference : $UserGroup"
               Write-Host "IsInherited       : $IsInHerit`n"
            }##End of Table
         }## End of Get-Acl loop
      }##End of 2º ForEach loop
   }## End of Exclude WindowsApps
}## End of ForEach loop

