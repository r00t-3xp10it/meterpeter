<#
.SYNOPSIS
   MITRE ATT&CK - T1574

   Author: @r00t-3xp10it
   Tested Under: Windows 10 (19043) x64 bits
   Required Dependencies: Get-Acl {native}
   Optional Dependencies: none
   PS cmdlet Dev version: v2.4.10

.DESCRIPTION
   Cmdlet to search for weak directory permissions (F) (M) (W) that
   allow attackers to Escalate Privileges on target system [ local ]

.NOTES
   This cmdlet its a auxiliary module of @Meterpeter C2 v2.10.11 release.
   If invoked -action 'path' then cmdlet scans all environement paths for
   FileSystemRigths 'FullControl, Modify' with 'Everyone,Users,UserName'

   If invoked -action 'dir' then cmdlet scans recursive $Env:PROGRAMFILES
   ${Env:PROGRAMFILES(x86)},$Env:LOCALAPPDATA\Programs default directrorys
   for FileSystemRigths 'FullControl,Modify' with GroupName 'Everyone,Users'

   If invoked -extraperm 'true' @argument then cmdlet adds extra
   permission to the 'ACL_Permissions_List' (permisssion: Write)
   Remark: extraperm parameter takes a long time to finish if invoked
   together with -action 'dir' @arg (Scan recursive pre-defined paths)

   If invoked -extraGroup 'true' @argument then cmdlet adds extra Group
   Name to the 'Groups_To_Scan_List' (NT AUTHORITY\Authenticated Users)

   Remark: Parameter -scanpath 'string' only works if invoked together
   with -action 'dir' @argument ( Scan recursive pre-defined paths ) and
   it will scan recursive the inputed directory ( excluding pre-defined )

.Parameter Action
   Accepts arguments: dir, path, reg (default: dir)

.Parameter extraperm
   Add extra permission to permissions_list? (default: false)

.Parameter scanpath
   The directory absoluct path to scan recursive (default: false)

.Parameter extraGroup
   Add extra group name to groups_to_scan_list? (default: false)

.Parameter Verb
   Display the paths beeing scanned in realtime? (default: false)
  
.EXAMPLE
   PS C:\> .\ACLMitreT1574.ps1
   Scan recursive in pre-defined directorys for 'Everyone,
   BUILTIN\Users' GroupNames with 'FullControl,Modify' ACL

.EXAMPLE
   PS C:\> .\ACLMitreT1574.ps1 -action path
   Scans all environement paths for 'Everyone,BUILTIN\Users,
   DOMAIN\UserName' GroupNames with 'FullControl,Modify' ACL

.EXAMPLE
   PS C:\> .\ACLMitreT1574.ps1 -action dir -extraperm true
   Scan recursive in pre-defined directorys for 'Everyone,
   BUILTIN\Users' GroupNames with 'FullControl,Modify,Write'

.EXAMPLE
   PS C:\> .\ACLMitreT1574.ps1 -action dir -scanpath "C:\Users\pedro\Coding"
   Scan recursive -scanpath 'C:\Users\pedro\Coding' for 'Everyone, BUILTIN\Users'
   GroupNames with 'FullControl,Modify' ACL permissions settings.

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
   IdentityReference : SKYNET\pedro
   IsInherited       : False

   VulnId            : 5::ACL (Mitre T1574)
   FolderPath        : C:\Program Files (x86)\Starcraft2\OobehgtrDoncFjp\games
   FileSystemRights  : Write
   IdentityReference : BUILTIN\Users
   IsInherited       : True
   
.LINK
   https://attack.mitre.org/techniques/T1574/010
   https://github.com/r00t-3xp10it/meterpeter/blob/master/mimiRatz/FindEop.bat
   https://github.com/r00t-3xp10it/meterpeter/blob/master/mimiRatz/ACLMitreT1574.ps1
#>


 [CmdletBinding(PositionalBinding=$false)] param(
   [string]$extraGroup="false",
   [string]$extraperm="false",
   [string]$Scanpath="false",
   [string]$Action="dir",
   [string]$Verb="false"
)


$Count = 0 #VulnId Counter
$ScanStartTimer = (Get-Date)
$CmdletVersion = "v2.4.10" #CmdLet version
#Disable Powershell Command Logging for current session.
Set-PSReadlineOption –HistorySaveStyle SaveNothing|Out-Null
$host.UI.RawUI.WindowTitle = "@ACLMitreT1574 $CmdletVersion {SSA@RedTeam}"

#Define the GroupName based on the language pack installed!
$LanguageSetting = ([CultureInfo]::InstalledUICulture).Name
If($LanguageSetting -iMatch '^(pt-PT)$')
{
      $UserGroup = "Todos"                                     #Default scan
      $UtilGroup = "BUILTIN\\Utilizadores"                     #Default scan
      $GroupFdx = "$Env:USERDOMAIN\\$Env:USERNAME"             #Default scan     - Only available with -action 'path'
      $OneMorek = "NT AUTHORITY\\Utilizadores Autenticados"    #extra Group Name - Only available with -extragroup 'true'
}
ElseIf($LanguageSetting -iMatch '^(fr-FR)$')
{
      $UserGroup = "Tout"                                      #Default scan
      $UtilGroup = "BUILTIN\\Utilisateurs"                     #Default scan
      $GroupFdx = "$Env:USERDOMAIN\\$Env:USERNAME"             #Default scan     - Only available with -action 'path'
      $OneMorek = "NT AUTHORITY\\Utilisateurs authentifiés"    #extra Group Name - Only available with -extragroup 'true'

}
ElseIf($LanguageSetting -iMatch '^(pl)')
{
      $UserGroup = "Wszystkie"                                 #Default scan
      $UtilGroup = "BUILTIN\\użytkownicy"                      #Default scan
      $GroupFdx = "$Env:USERDOMAIN\\$Env:USERNAME"             #Default scan     - Only available with -action 'path'
      $OneMorek = "NT AUTHORITY\\Uwierzytelnieni użytkownicy"  #extra Group Name - Only available with -extragroup 'true'

}
ElseIf($LanguageSetting -iMatch '^(in)')
{
      $UserGroup = "Semua"                                     #Default scan
      $UtilGroup = "BUILTIN\\Pengguna"                         #Default scan
      $GroupFdx = "$Env:USERDOMAIN\\$Env:USERNAME"             #Default scan     - Only available with -action 'path'
      $OneMorek = "NT AUTHORITY\\Pengguna yang Diautentikasi"  #extra Group Name - Only available with -extragroup 'true'

}
ElseIf($LanguageSetting -iMatch '^(ro)')
{
      $UserGroup = "Toate"                                     #Default scan
      $UtilGroup = "BUILTIN\\utilizatorii"                     #Default scan
      $GroupFdx = "$Env:USERDOMAIN\\$Env:USERNAME"             #Default scan     - Only available with -action 'path'
      $OneMorek = "NT AUTHORITY\\Utilizatori autentificați"    #extra Group Name - Only available with -extragroup 'true'

}
Else
{
      $UserGroup = "Everyone"                                  #Default scan
      $UtilGroup = "BUILTIN\\Users"                            #Default scan
      $GroupFdx = "$Env:USERDOMAIN\\$Env:USERNAME"             #Default scan     - Only available with -action 'path'
      $OneMorek = "NT AUTHORITY\\Authenticated Users"          #extra Group Name - Only available with -extragroup 'true'
}


If($Action -ieq "path")
{

   <#
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Search in environement paths for dirs with weak permissions!

   .NOTES
     If invoked -verb 'true' @argument then cmdlet displays all
     the directory paths beeing scanned in realtime (more_slow)

     If invoked -extraperm 'true' @argument then cmdlet adds extra
     permissions to the 'ACL_Permissions_List' (permission: Write)

     If invoked -extraGroup 'true' @argument then cmdlet adds one
     extra Group Name to the 'Group_Names_To_Scan_List' : 'Everyone,
     BUILTIN\Users, DOMAIN\UserName, NT AUTHORITY\Authenticated Users'
   #>

   #ACL Permissions List
   $DirectoryPermission = @(
      "FullControl","Modify"
   )
   If($extraperm -ieq "True")
   {
      #-extraperm 'true' add 'Write' permission
      $DirectoryPermission += "Write"
   }
   If($extraGroup -ieq "True")
   {
      #Add extra Group Name if invoked -extragroup 'string' param
      $FinalGroupList = "$UserGroup|$UtilGroup|$GroupFdx|$OneMorek"
   }
   Else
   {
      $FinalGroupList = "$UserGroup|$UtilGroup|$GroupFdx"         
   }

   #Get Environement Paths and split(';') each catched path.
   $EnvironementPaths = ($Env:Path).Split(';') | ? {$_ -ne ''}

   $NewCounter = 0 #Group Name Id
   #Loop trough all '$Environement' catched paths.
   ForEach($TokenPath in $EnvironementPaths)
   {
      #Loop trough all 'ACL Permissions List' Items
      ForEach($ACLPermission in $DirectoryPermission)
      {
         If($Verb -ieq "True")
         {
            $NewCounter++
            #Display OnScreen directory paths beeing scanned in realtime
            Write-Host "[VERBOSE] Scanning: " -ForegroundColor Blue -BackgroundColor Black -NoNewLine;
            Write-Host "$TokenPath" -ForegroundColor Green -BackgroundColor Black;
            write-host "[VERBOSE] Identity: " -ForegroundColor Blue -BackgroundColor Black -NoNewLine;
            write-host "[$NewCounter] $FinalGroupList" -ForegroundColor DarkGray -BackgroundColor Black -NoNewLine;
            Write-Host " - Permission " -ForegroundColor Blue -BackgroundColor Black -NoNewLine;
            Write-Host "$ACLPermission" -ForegroundColor DarkGray -BackgroundColor Black -NoNewLine;
            Write-Host "." -ForegroundColor Blue -BackgroundColor Black;
            Start-Sleep -Milliseconds 100
         }

         #Get directory ACL settings
         $IsInHerit = (Get-Acl "$TokenPath").Access.IsInherited | Select-Object -First 1
         (Get-Acl "$TokenPath").Access | Where-Object {#Search for Everyone:(F) \ Everyone:(M) directory permissions (default)
            $CleanOutput = $_.FileSystemRights -Match "$ACLPermission" -and $_.IdentityReference -iMatch "^($FinalGroupList)$" ## pt-PT = Todos
            If($CleanOutput)
            {
               If($Verb -ieq "True"){Write-Host ""}
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
      Author: @r00t-3xp10it
      Helper - Search in Pre-Defined paths (recursive) for dirs with weak permissions!

   .NOTES
     If invoked -verb 'true' @argument then cmdlet displays all
     the directory paths beeing scanned in realtime (more_slow)

     If invoked -extraperm 'true' @argument then cmdlet adds extra
     permissions to the 'ACL_Permissions_List' (permission: Write)
     Remark: extraperm parameter takes a long time to finish ..

     If invoked -extraGroup 'true' @argument then cmdlet adds one
     extra Group Name to the 'Group_Names_To_Scan_List' : 'Everyone,
     BUILTIN\Users, NT AUTHORITY\Authenticated Users' Group Names

     Parameter -scanpath 'string' scans recursive the inputed
     directory, excluding all pre-defined 'Directorys_To_Scan_List'
   #>

   #ACL Permissions List
   $DirectoryPermission = @(
      "FullControl","Modify"
   )
   If($extraperm -ieq "True")
   {
      #-extraperm 'true' add 'Write' permission
      $DirectoryPermission += "Write"
   }
   If($extraGroup -ieq "True")
   {
      #Add extra Group Name if invoked -extragroup 'string' param
      $FinalGroupList = "$UserGroup|$UtilGroup|$OneMorek"
   }
   Else
   {
      $FinalGroupList = "$UserGroup|$UtilGroup"         
   }

   If($scanpath -ne "false")
   {
      #Make sure User directory input exists
      If(-not(Test-Path -Path "$scanpath" -EA SilentlyContinue))
      {
         Write-Host "* ERROR: not found '$scanpath'" -ForegroundColor Red -BackgroundColor Black
         Write-Host "  => HELP: Try to use absoluct path declarations .." -ForegroundColor Red -BackgroundColor Black
         Start-Sleep -Seconds 1;exit #Exit @ACLMitreT1574
      }
      Else
      {
         #Inputed directory path found [ -scanpath 'string' ] ..
         #Directorys to search recursive: The directory tree inputed by user!
         $RawDataBaseList = Get-ChildItem  -Path "$scanpath" -Recurse -ErrorAction SilentlyContinue -Force | Where-Object {
            $_.PSIsContainer -and $_.FullName -iNotMatch '(.DLL|.EXE)$' } | Select-Object -ExpandProperty FullName
      }   
   }
   Else
   {
      #Default directory scans
      #Directorys to search recursive: $Env:PROGRAMFILES, ${Env:PROGRAMFILES(x86)}, $Env:LOCALAPPDATA\Programs
      $RawDataBaseList = Get-ChildItem  -Path "$Env:PROGRAMFILES", "${Env:PROGRAMFILES(x86)}", "$Env:LOCALAPPDATA\Programs" -Recurse -ErrorAction SilentlyContinue -Force | Where-Object {
         $_.PSIsContainer -and $_.FullName -iNotMatch '(.DLL|.EXE)$' } | Select-Object -ExpandProperty FullName
   }

   $NewCounter = 0 #Group Name Id
   #Loop trough all ChildItem catched paths
   ForEach($TokenPath in $RawDataBaseList)
   {
      #Exclude 'WindowsApps' from scans
      If(-not($TokenPath -Match 'WindowsApps'))
      {
         #Loop trough all 'ACL Permissions List' Items
         ForEach($ACLPermission in $DirectoryPermission)
         {
            If($Verb -ieq "True")
            {
               $NewCounter++
               #Display OnScreen directory paths beeing scanned in realtime
               Write-Host "[VERBOSE] Scanning: " -ForegroundColor Blue -BackgroundColor Black -NoNewLine;
               Write-Host "$TokenPath" -ForegroundColor Green -BackgroundColor Black;
               write-host "[VERBOSE] Identity: " -ForegroundColor Blue -BackgroundColor Black -NoNewLine;
               write-host "[$NewCounter] $FinalGroupList" -ForegroundColor DarkGray -BackgroundColor Black -NoNewLine;
               Write-Host " - Permission " -ForegroundColor Blue -BackgroundColor Black -NoNewLine;
               Write-Host "$ACLPermission" -ForegroundColor DarkGray -BackgroundColor Black -NoNewLine;
               Write-Host "." -ForegroundColor Blue -BackgroundColor Black;
               Start-Sleep -Milliseconds 100
            }

            #Get directory ACL settings
            $IsInHerit = (Get-Acl "$TokenPath").Access.IsInherited | Select-Object -First 1
            (Get-Acl "$TokenPath").Access | Where-Object {#Search for Everyone:(F) \ Everyone:(M) directory permissions (default)
               $CleanOutput = $_.FileSystemRights -Match "$ACLPermission" -and $_.IdentityReference -iMatch "^($FinalGroupList)$" ## pt-PT = Todos
               If($CleanOutput)
               {
                  If($Verb -ieq "True"){Write-Host ""}
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


If($Action -ieq "reg")
{

   <#
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Search in registry for services with weak permissions!

   .NOTES
     If invoked -verb 'true' @argument then cmdlet displays all
     the directory paths beeing scanned in realtime (more_slow)

     If invoked -extraGroup 'true' @argument then cmdlet adds one
     extra Group Name to the 'Group_Names_To_Scan_List' : 'Everyone,
     BUILTIN\Users, NT AUTHORITY\Authenticated Users, Domain\UserName'
   #>

   #ACL Group Names List
   $Count = 0 #RegKeysCounter
   $NewCounter = 0 #Group Name Id
   $WeakPerm = "FullControl" #Perm to scan
   If($extraGroup -ieq "False")
   {
      #Defaul Group Name List
      $FinalGroupList = "$UserGroup"  
   }
   Else
   {
      #"BUILTIN\\Administradores"
      $FinalGroupList = @(#Add two extra Group Names to List
         "$UserGroup","$UtilGroup","$OneMorek","$GroupFdx"
      )    
   }

   ## Get ALL services under HKLM hive key
   $GetPath = (Get-Acl -Path "HKLM:\SYSTEM\CurrentControlSet\services\*" -EA SilentlyContinue).PSPath
   $ParseData = $GetPath -replace 'Microsoft.PowerShell.Core\\Registry::HKEY_LOCAL_MACHINE\\','HKLM:\'
   ForEach($Token in $ParseData)
   {
      #Loop trough all 'Group Names List' Items
      ForEach($GroupServiceName in $FinalGroupList)
      {
         ## Loop trough $FinalGroupList services database
         $IsInHerit = (Get-Acl -Path "$Token").Access.IsInherited | Select -First 1
         $CleanOutput = (Get-Acl -Path "$Token").Access | Select-Object * | Where-Object {## Search for Everyone:(F) registry service permissions (default)
            $_.IdentityReference -Match "^($GroupServiceName)" -and $_.RegistryRights -Match "^($WeakPerm)"
         }

         If($Verb -ieq "True")
         {
            $NewCounter++
            #Display OnScreen registry keys beeing scanned in realtime
            Write-Host "[VERBOSE] Scanning: " -ForegroundColor Blue -BackgroundColor Black -NoNewLine;
            Write-Host "$Token" -ForegroundColor Green -BackgroundColor Black;
            write-host "[VERBOSE] Identity: " -ForegroundColor Blue -BackgroundColor Black -NoNewLine;
            write-host "[$NewCounter] $GroupServiceName" -ForegroundColor DarkGray -BackgroundColor Black -NoNewLine;
            Write-Host " - Permission " -ForegroundColor Blue -BackgroundColor Black -NoNewLine;
            Write-Host "$WeakPerm" -ForegroundColor DarkGray -BackgroundColor Black -NoNewLine;
            Write-Host "." -ForegroundColor Blue -BackgroundColor Black;
            Start-Sleep -Milliseconds 100
         }

         If($CleanOutput)
         {
            If($Verb -ieq "True"){Write-Host ""}
            $Count++ ##  Write the Table 'IF' found any vulnerable permissions
            Write-Host "`nVulnId            : ${Count}::SRV"
            Write-Host "RegistryPath      : $Token" -ForegroundColor Yellow
            Write-Host "IdentityReference : $GroupServiceName"
            Write-Host "RegistryRights    : $WeakPerm"
            Write-Host "AccessControlType : Allow"
            Write-Host "IsInherited       : $IsInHerit"
         }
      }
   }

   #Report that we have fail to find any permissions.
   If(-not($Count -gt 0) -or $Count -ieq $null)
   {
      ## Weak directorys permissions report banner
      Write-Host "[REG] none services found with ${FinalGroupList}:(F)"
   }
}


If($Verb -ieq "True")
{
   Write-Host ""
   #Internal clock Timmer
   $ElapsTime = $(Get-Date) - $ScanStartTimer
   $TotalTime = "{0:HH:mm:ss}" -f ([datetime]$ElapsTime.Ticks) #Count the diferense between 'start|end' scan duration!
   Write-Host "`* ElapsedTime:" -ForegroundColor Blue -BackgroundColor Black -NoNewline;
   Write-Host "$TotalTime" -ForegroundColor Green -BackgroundColor Black -NoNewline;
   Write-Host " - scantype:" -ForegroundColor Blue -BackgroundColor Black -NoNewline;
   Write-Host "$Action" -ForegroundColor Green -BackgroundColor Black -NoNewline;
}