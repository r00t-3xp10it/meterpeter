<#
.SYNOPSIS
   Query\Create\Delete super hidden system folders

   Author: @r00t-3xp10it
   Tested Under: Windows 10 (19043) x64 bits
   Required Dependencies: attrib {native}
   Optional Dependencies: none
   PS cmdlet Dev version: v1.2.18

.DESCRIPTION
   This cmdlet allow users to Query\Create\Delete super hidden folders.
   Super hidden folders contains 'Hidden, System' attributes set and it
   does not show-up in explorer even if 'show hidden files' are activated.

.NOTES
   This cmdlet allow users to search for 'hidden' or 'super hidden' directorys
   in input location (recursive, non-recursive), creates 'super hidden' folder,
   'hidde folder', 'un-hidde folder' and 'delete' super hidden directorys ..
   Remark: Admin privileges required to create folders outside %userprofile%.
   Remark: The -Recursive 'true' arg requires of an -Directory input by user.

.Parameter Action
   Accepts arguments: query, hidden, visible, delete (default: query)

.Parameter Directory
   The query\create\delete folder directory path (default: false)

.Parameter FolderName
   The folder name to query\create\delete (default: false)

.Parameter Recursive
   Search super hidden folders recursive? (default: false)

.Parameter Attributes
   The directory attributes (default: Hidden, System)

.EXAMPLE
   PS C:\> .\SuperHidden.ps1 -Action Query
   Search for 'Hidden, System' folders on predefined locations

.EXAMPLE
   PS C:\> .\SuperHidden.ps1 -Action Query -Directory $Env:TMP
   Search for 'Hidden, System' folders on %TMP% location

.EXAMPLE
   PS C:\> .\SuperHidden.ps1 -Action Query -Directory $Env:TMP -Recursive true
   Search for 'Hidden, System' folders on %TMP% location 'recursive' (sub-folders)

.EXAMPLE
   PS C:\> .\SuperHidden.ps1 -Action Query -Directory $Env:TMP -attributes Hidden
   Search for folders with 'Hidden' attribute (not super Hidden, System) on %TMP%
   
.EXAMPLE
   PS C:\> .\SuperHidden.ps1 -Action Query -Directory $Env:TMP -FolderName vault
   Search for 'Hidden, System' folders on %TMP% location with the name of 'vault'

.EXAMPLE
   PS C:\> .\SuperHidden.ps1 -Action Hidden -Directory $Env:TMP -FolderName vault
   Create\Modify 'Hidden, System' folder on %TMP% location with the name of 'vault'   

.EXAMPLE
   PS C:\> .\SuperHidden.ps1 -Action Visible -Directory $Env:TMP -FolderName vault
   Create\modify 'VISIBLE, System' folder on %TMP% location with the name of 'vault'    

.EXAMPLE
   PS C:\> .\SuperHidden.ps1 -Action Delete -Directory $Env:TMP -FolderName vault
   Delete the super hidden 'Hidden, System' folder of %TMP% with the name of 'vault'

.EXAMPLE
   PS C:\> .\SuperHidden.ps1 -Action Query -Directory $Env:TMP -Attributes "(Hidden|System)" -Recursive true
   Search for 'Hidden' OR 'System' directorys on %TMP% location in 'recursive' mode (scan sub-folders) 

.INPUTS
   None. You cannot pipe objects into SuperHidden.ps1

.OUTPUTS
   FullName                                CreationTime        LastAccessTime                      Attributes
   --------                                ------------        --------------                      ----------
   C:\Users\pedro\AppData\Local\Temp\vault 15/11/2021 07:17:42 15/11/2021 07:20:44  Hidden, System, Directory

.LINK
   https://github.com/r00t-3xp10it/meterpeter/releases/tag/v2.10.10
#>


#CmdLet Global variable declarations!
[CmdletBinding(PositionalBinding=$false)] param(
   [string]$Attributes="Hidden, System",
   [string]$FolderName="false",
   [string]$Directory="false",
   [string]$Recursive="false",
   [string]$Action="Query"
)


$ErrorActionPreference = "SilentlyContinue"
#Disable Powershell Command Logging for current session.
Set-PSReadlineOption –HistorySaveStyle SaveNothing|Out-Null
$IsClientAdmin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -Match "S-1-5-32-544")
If($Action -ieq "Query" -and $Directory -ieq "false")
{
   If($Attributes -iMatch '^(Hidden)$')
   {
      Write-Host "Searching hidden folders in common locations .." -ForegroundColor Blue 
   }
   ElseIf($Attributes -iMatch '^(Hidden, System)$')
   {
      Write-Host "Searching super hidden folders in common locations .." -ForegroundColor Blue
   }
   Else
   {
      Write-Host "Searching '$Attributes' folders in common locations .." -ForegroundColor Blue    
   }
}


Write-Host "`n"
#Build ramdom search output DataTable!
$supertable = New-Object System.Data.DataTable
$supertable.Columns.Add("Attributes     ")|Out-Null
$supertable.Columns.Add("Length")|Out-Null
$supertable.Columns.Add("FullName")|Out-Null
$supertable.Columns.Add("LastAccessTime")|Out-Null


If($Action -ieq "Query")
{

   <#
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Query for hidden folders with 'hidden, system' attributes set.
      
   .NOTES
      This function allow users to search for hidden folders on predefined locations
      or accepts the absoluct path of the directory to query (not recursive), it also
      accepts the '-FolderName' parameter to search for sellected directory existence.
      Remark: The -Recursive 'true' argument requires of an -Directory input by user.

   .OUTPUTS
      Attributes      Length  FullName                                 LastAccessTime                         
      --------------- ------  --------                                 --------------
      Hidden, System  0       C:\Program Files\Windows Sidebar         11/18/2021 09:32:55
      Hidden, System  2       C:\Program Files (x86)\Windows Sidebar   11/18/2021 03:13:06
      Hidden, System  61      C:\Users\pedro\AppData\Local\Temp\vault  11/18/2021 09:34:10
   #>

   If($Directory -ieq "false")
   {

      $CommonLocations = @(
         "$Env:TMP",
         "$Env:APPDATA",
         "$Env:USERPROFILE",         
         "$Env:LOCALAPPDATA",
         "$Env:PROGRAMFILES",
         "${Env:PROGRAMFILES(X86)}",
         "$Env:USERPROFILE\Desktop",
         "$Env:USERPROFILE\Documents"
      )

      ForEach($Item in $CommonLocations)
      {
         #Search for hidden,system folders on predefined locations (random search)
         $RawList = (Get-ChildItem -Path "$Item" -Force | Select-Object * | Where-Object { 
            $_.PSIsContainer -eq 'True' -and $_.Attributes -iMatch "$Attributes"
         }).FullName

         If($RawList)
         {
            ForEach($Entry in $RawList)
            {

               #Add each indevidual entry to database now.
               $DirLength = (Get-ChildItem -Path "$Entry").Length
               $LastAccessTime = (Get-ChildItem -Path "$Entry").LastAccessTime | Select-Object -Last 1
               $supertable.Rows.Add("$Attributes","$DirLength","$Entry","$LastAccessTime")|Out-Null
            }
         }
      }

      #Display DataTable contents onscreen
      $supertable | Format-Table -AutoSize | Out-String -Stream | Select-Object -Skip 1 | ForEach-Object {
         $stringformat = If($_ -Match '^(Attributes)')
         {
            @{ 'ForegroundColor' = 'Green' }
         }
         Else
         {
            @{ 'ForegroundColor' = 'White' }
         }
         Write-Host @stringformat $_
      }

   }
   ElseIf($Directory -ne "false")
   {

      If(-not(Test-Path -Path "$Directory" -EA SilentlyContinue))
      {
         #Making sure that the directory input exists before go any further..
         Write-Host "error: not found: '$Directory'`n" -ForegroundColor Red -BackgroundColor Black
         exit #Exit SuperHidden
      }
   
      If($FolderName -ne "false")
      {
          If($Recursive -ieq "true")
         {
            #FolderName parameter user input recursive search function
            $SHdb = Get-ChildItem -Path "$Directory" -Recurse -Force| Select-Object * |
               Where-Object { $_.PSIsContainer -eq 'True' -and $_.Name -iMatch "$FolderName" -and
               $_.Attributes -iMatch "$Attributes" -and $_.FullName -iNotMatch 'Packages'
            } | Select-Object FullName,CreationTime,LastAccessTime,Attributes | Format-Table -AutoSize
         }
         Else
         {
            #FolderName parameter user input search function
            $SHdb = Get-ChildItem -Path "$Directory" -Force| Select-Object * |
               Where-Object { $_.PSIsContainer -eq 'True' -and $_.Name -iMatch "$FolderName" -and $_.Attributes -iMatch "$Attributes"
            } | Select-Object FullName,CreationTime,LastAccessTime,Attributes | Format-Table -AutoSize         
         }

         If(-not($SHdb))
         {
            Write-Host "Error: fail to match the search criteria.`n" -ForegroundColor Red -BackgroundColor Black
         }
         Else
         {
            echo $SHdb
         }

      }
      Else
      {

         If($Recursive -ieq "true")
         {
            #Query for hidden,system folders in -Directory argument location
            $SHdb = Get-ChildItem -Path "$Directory" -Recurse -Force | Select-Object * |
               Where-Object { $_.PSIsContainer -eq 'True' -and $_.Attributes -Match "$Attributes" -and $_.FullName -iNotMatch 'Packages'
            } | Select-Object FullName,CreationTime,LastAccessTime,Attributes | Format-Table -AutoSize
         }
         Else
         {
            #Query for hidden,system folders in -Directory argument location
            $SHdb = Get-ChildItem -Path "$Directory" -Force | Select-Object * |
               Where-Object { $_.PSIsContainer -eq 'True' -and $_.Attributes -iMatch "$Attributes"
            } | Select-Object FullName,CreationTime,LastAccessTime,Attributes | Format-Table -AutoSize         
         }

         If(-not($SHdb))
         {
            Write-Host "Error: fail to match the search criteria.`n" -ForegroundColor Red -BackgroundColor Black
         }
         Else
         {
            echo $SHdb
         }

      }
   }

}


If($Action -ieq "Hidden")
{

   <#
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Create one hidden,system folder on sellected location!

   .NOTES
      This function creates or modify the sellected folder attributes.
      Admin privileges required to create folders outside userprofile tree.
   #>

   If($Directory -ieq "false")
   {
      $Directory = "$Env:TMP"
   }

   If($Directory -iMatch '^C:\\Windows' -or $Directory -iMatch '^C:\\Program Files')
   {
      If($IsClientAdmin -iMatch 'False')
      {
         #Making sure that the directory structure does not start with C:\Windows if we have UserLand privs!
         Write-Host "Error: Admin privileges required to manipulate sellected directory.`n" -ForegroundColor Red -BackgroundColor Black
         exit #Exit @SuperHidden
      }
   }

   If($FolderName -ieq "false"){$FolderName = "vault"}
   If(-not(Test-Path -Path "$Directory\$FolderName" -EA SilentlyContinue))
   {
      #Make sure that the directory\folder exists
      mkdir $Directory\$FolderName -Force|Out-Null
   }

   try{#hidde sellected folder
      attrib +s +h $Directory\$FolderName
   }catch{#Fail to modify sellected directory attributes
      Write-Host "Error: fail to change directory attributes.`n" -ForegroundColor Red -BackgroundColor Black
      exit #Exit SuperHidden
   }

   #Search for hidden,system folder created\modified..
   $SHdb = Get-ChildItem -Path "$Directory" -Force | Select-Object * |
      Where-Object { $_.PSIsContainer -eq 'True' -and $_.Name -iMatch "$FolderName" -and $_.Attributes -iMatch 'Hidden, System'
   } | Select-Object FullName,CreationTime,LastAccessTime,Attributes | Format-Table -AutoSize

   If(-not($SHdb))
   {
      Write-Host "Error: fail to match the search criteria.`n" -ForegroundColor Red -BackgroundColor Black
   }
   Else
   {
      echo $SHdb
   }

}


If($Action -ieq "Visible")
{

   <#
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Create one VISIBLE,system folder on sellected location!

   .NOTES
      This function creates or modify the sellected folder attributes.
      Admin privileges required to create folders outside userprofile tree.
   #>

   If($Directory -ieq "false")
   {
      $Directory = "$Env:TMP"
   }

   If($Directory -iMatch '^C:\\Windows' -or $Directory -iMatch '^C:\\Program Files')
   {
      If($IsClientAdmin -iMatch 'False')
      {
         #Making sure that the directory structure does not start with C:\Windows if we have UserLand privs!
         Write-Host "Error: Admin privileges required to manipulate sellected directory.`n" -ForegroundColor Red -BackgroundColor Black
         exit #Exit @SuperHidden
      }
   }

   If($FolderName -ieq "false"){$FolderName = "vault"}
   If(-not(Test-Path -Path "$Directory\$FolderName" -EA SilentlyContinue))
   {
      #Make sure that the directory\folder exists
      mkdir $Directory\$FolderName -Force|Out-Null
   }

   try{#UnHidde sellected folder
      attrib -s -h $Directory\$FolderName
   }catch{#Fail to modify sellected directory attributes
      Write-Host "Error: fail to change directory attributes.`n" -ForegroundColor Red -BackgroundColor Black
      exit #Exit SuperHidden
   }

   #Search for VISIBLE,system folder created\modified..
   $SHdb = Get-ChildItem -Path "$Directory" -Force | Select-Object * |
      Where-Object { $_.PSIsContainer -eq 'True' -and $_.Name -iMatch "$FolderName"
   } | Select-Object FullName,CreationTime,LastAccessTime,Attributes | Format-Table -AutoSize

   If(-not($SHdb))
   {
      Write-Host "Error: fail to match the search criteria.`n" -ForegroundColor Red -BackgroundColor Black
   }
   Else
   {
      echo $SHdb
   }

}


If($Action -ieq "Delete")
{

   <#
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Delete one hidden,system folder on sellected location!

   .NOTES
      Admin privileges required to delete folders outside userprofile tree.
   #>

   If($FolderName -ieq "false")
   {
      #Make sure that the folder to delete exists
      Write-Host "Error: The 'delete' function requires -FolderName input ..`n" -ForegroundColor Red -BackgroundColor Black
      exit #Exit SuperHidden
   }

   If($Directory -ieq "false")
   {
      #Make sure that the directory tree to delete exists
      Write-Host "Error: The 'delete' function requires -Directory input ..`n" -ForegroundColor Red -BackgroundColor Black
      exit #Exit SuperHidden
   }

   If($Directory -iMatch '^C:\\Windows' -or $Directory -iMatch '^C:\\Program Files')
   {
      If($IsClientAdmin -iMatch 'False')
      {
         #Making sure that the directory structure does not start with C:\Windows if we have UserLand privs!
         Write-Host "Error: Admin privileges required to manipulate sellected directory.`n" -ForegroundColor Red -BackgroundColor Black
         exit #Exit @SuperHidden
      }
   }

   If(-not(Test-Path -Path "$Directory\$FolderName" -EA SilentlyContinue))
   {
      #Make sure that the directory\folder to delete exists
      Write-Host "Error: not found '$Directory\$FolderName'`n" -ForegroundColor Red -BackgroundColor Black
      exit #Exit SuperHidden
   }

   try{#delete sellected folder
      attrib -s -h $Directory\$FolderName
   }catch{#Fail to change directory attributes
      Write-Host "Error: fail to change directory attributes.`n" -ForegroundColor Red -BackgroundColor Black
      exit #Exit SuperHidden
   }

   #Remove directory
   Remove-Item -Path "$Directory\$FolderName" -Recurse -Force
   If(-not(Test-Path -Path "$Directory\$FolderName" -EA SilentlyContinue))
   {
      Write-Host "Super hidden '$FolderName' folder deleted .."
   }
   Else
   {
      Write-Host "Error: fail to delete '$Directory\$FolderName' folder .."   
   }

   #Display directory contents now
   $SHdb = Get-ChildItem -Path "$Directory" -Force | Select-Object * |
      Where-Object { $_.PSIsContainer -eq 'True' } |
   Select-Object Length,Name,LastWriteTime | Format-Table -AutoSize

   If(-not($SHdb))
   {
      Write-Host "none contents found inside current directory.`n" -ForegroundColor Yellow
   }
   Else
   {
      echo $SHdb
   }

}