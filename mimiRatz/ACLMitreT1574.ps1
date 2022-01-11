<#
.SYNOPSIS
   MITRE ATT&CK - T1574

   Author: @r00t-3xp10it
   Tested Under: Windows 10 (19043) x64 bits
   Required Dependencies: Get-Acl {native}
   Optional Dependencies: none
   PS cmdlet Dev version: v1.0.5

.DESCRIPTION
   Cmdlet to search for weak directory permissions (F) (M) (W) that
   allow attackers to Escalate Privileges on target system [ local ]

.NOTES
   This cmdlet its a module of @Meterpeter C2 v2.10.11 release.

   If invoked -action 'path' then cmdlet scans all environement paths for
   FileSystemRigths 'FullControl, Modify, Write' with GroupName 'Everyone,Users'.

   If invoked -action 'dir' then cmdlet scans recursive $Env:PROGRAMFILES
   ${Env:PROGRAMFILES(x86)},$Env:LOCALAPPDATA\Programs default directrorys
   for FileSystemRigths 'FullControl, Modify, Write' with 'Everyone:,Users:'

.Parameter Action
   Accepts arguments: dir or path (default: dir)

.Parameter Agressive
   Add 'ReadAndExecute' to permissions_list? (default: false)

.EXAMPLE
   PS C:\> .\ACLMitreT1574.ps1
   Scan recursive in pre-defined directorys for pre-defined
   UserGroups 'Everyone,Users' with 'FullControl,Modify,Write'
   ACL directory permissions.

.EXAMPLE
   PS C:\> .\ACLMitreT1574.ps1 -action path
   Scans all environement paths for FileSystemRigths
   'FullControl, Modify, Write' with GroupName 'Everyone,Users'

.EXAMPLE
   PS C:\> .\ACLMitreT1574.ps1 -agressive true
   Scans all environement paths for FileSystemRigths
   'FullControl, Modify, Write, ReadAndExecute' with
   GroupName 'Everyone,Users'

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
   [string]$Agressive="false",
   [string]$Action="dir"
)


$Count = 0
#Disable Powershell Command Logging for current session.
Set-PSReadlineOption –HistorySaveStyle SaveNothing|Out-Null
#Define the GroupName based on the language pack installed!
$LanguageSetting = ([CultureInfo]::InstalledUICulture).Name
If($LanguageSetting -iMatch '^(pt-PT)$')
{
      $UserGroup = "Todos"
      $UtilGroup = "$Env:USERDOMAIN\\Utilizadores"
}
Else
{
      $UserGroup = "Everyone"
      $UtilGroup = "$Env:USERDOMAIN\\Users"
}
#ACL Permissions List
$DirectoryPermission = @(
   "FullControl","Modify","Write"
)
If($Agressive -ieq "True")
{
   #If '-agressive true' add extra permission
   $DirectoryPermission += "ReadAndExecute"
}


If($Action -ieq "path")
{

   <#
   .SYNOPSIS
      author: @r00t-3xp10it
      Helper - Search in environement paths for dirs with weak permissions!
   #>

   #Get Environement Paths and split each path
   $GroupFdx = "$Env:USERDOMAIN\\$Env:USERNAME"
   $EnvironementPaths = ($Env:Path).Split(';') | ? {$_ -ne ''}

   #Loop trough all Environement catched paths
   ForEach($TokenPath in $EnvironementPaths)
   {
      ForEach($ACLPermission in $DirectoryPermission)
      {
         #Get directory ACL
         $IsInHerit = (Get-Acl "$TokenPath").Access.IsInherited | Select-Object -First 1
         (Get-Acl "$TokenPath").Access | Where-Object {#Search for Everyone:(F) \ Everyone:(M) directory permissions (default)
            $CleanOutput = $_.FileSystemRights -Match "$ACLPermission" -and $_.IdentityReference -iMatch "^($UserGroup|$UtilGroup|$GroupFdx)$" ## pt-PT = Todos
            If($CleanOutput)
            {
               $Count++ #Write the Table 'IF' found any vulnerable permissions
               Write-Host "VulnId            : ${Count}::ACL (Mitre T1574)"
               Write-Host "FolderPath        : $TokenPath" -ForegroundColor Green -BackgroundColor Black
               Write-Host "FileSystemRights  : $ACLPermission" -ForegroundColor yellow
               Write-Host "IdentityReference :"$_.IdentityReference.ToString()
               Write-Host "IsInherited       : $IsInHerit`n"
            }##End of Table
         }## End of Get-Acl loop
      }

   }

}


If($Action -ieq "dir")
{

   <#
   .SYNOPSIS
      author: @r00t-3xp10it
      Helper - Search in Pre-Defined paths (recursive) for dirs with weak permissions!
   #>

   #ACL Permissions List
   $DirectoryPermission = @(
      "FullControl","Modify"
   )
   If($Agressive -ieq "True")
   {
      #If '-agressive true' add extra permission
      $DirectoryPermission += "ReadAndExecute"
   }

   #Directorys to search recursive: $Env:PROGRAMFILES, ${Env:PROGRAMFILES(x86)}, $Env:LOCALAPPDATA\Programs\
   $RawDataBaseList = Get-ChildItem  -Path "$Env:PROGRAMFILES", "${Env:PROGRAMFILES(x86)}", "$Env:LOCALAPPDATA\Programs\" -Recurse -ErrorAction SilentlyContinue -Force | Where-Object {
      $_.PSIsContainer
   }|Select-Object -ExpandProperty FullName
   #Loop trough all ChildItem catched paths
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
            (Get-Acl "$TokenPath").Access | Where-Object {#Search for Everyone:(F) \ Everyone:(M) \ Everyone:(W) directory permissions (default)
               $CleanOutput = $_.FileSystemRights -Match "$ACLPermission" -and $_.IdentityReference -iMatch "^($UserGroup|$UtilGroup)$" ## pt-PT = Todos
               If($CleanOutput)
               {
                  $Count++ #Write the Table 'IF' found any vulnerable permissions
                  Write-Host "VulnId            : ${Count}::ACL (Mitre T1574)"
                  Write-Host "FolderPath        : $TokenPath" -ForegroundColor Green -BackgroundColor Black
                  Write-Host "FileSystemRights  : $ACLPermission" -ForegroundColor yellow
                  Write-Host "IdentityReference :"$_.IdentityReference.ToString()
                  Write-Host "IsInherited       : $IsInHerit`n"
               }##End of Table
            }## End of Get-Acl loop
         }##End of 2º ForEach loop
      }## End of Exclude WindowsApps
   }## End of ForEach loop

}