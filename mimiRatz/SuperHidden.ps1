<#
.SYNOPSIS
   Query\Create\Delete super hidden system folders

   Author: @r00t-3xp10it
   Tested Under: Windows 10 (19043) x64 bits
   Required Dependencies: attrib {native}
   Optional Dependencies: none
   PS cmdlet Dev version: v1.1.8

.DESCRIPTION
   This cmdlet allow users to Query\Create\Delete super hidden folders.
   Super hidden folders contains 'hidden, system' attributes set and does
   not show-up in explorer even if 'show hidden files' its activated ...

.NOTES
   This cmdlet allows users to hidde or un-hidde system directorys.
   If none 'Directory' path its inputed, them cmlet scans a list of
   predefined locations for folders with 'hidden, system' attributes.
   Remark: -Recursive 'true' only works if a -Directory its inputed.

.Parameter Action
   Accepts arguments: query, hidden, visible, delete (default: query)

.Parameter Directory
   The folder to query\create\delete directory path (default: false)

.Parameter FolderName
   The folder name to query\create\delete (default: false)

.Parameter Recursive
   Search super hidden folders recursive? (default: false)

.EXAMPLE
   PS C:\> .\SuperHidden.ps1 -Action Query
   Search for hidden,system folders on predefined locations

.EXAMPLE
   PS C:\> .\SuperHidden.ps1 -Action Query -Directory $Env:TMP
   Search for hidden,system folders on %TMP% location

.EXAMPLE
   PS C:\> .\SuperHidden.ps1 -Action Query -Directory $Env:TMP -Recursive true
   Search for hidden,system folders on %TMP% location 'recursive' (sub-folders)
   
.EXAMPLE
   PS C:\> .\SuperHidden.ps1 -Action Query -Directory $Env:TMP -FolderName testing
   Search for hidden,system folder on %TMP% location with the name 'testing'  

.EXAMPLE
   PS C:\> .\SuperHidden.ps1 -Action Hidden -Directory $Env:TMP -FolderName testing
   Create\modify hidden,system folder on %TMP% location with the name 'testing'   

.EXAMPLE
   PS C:\> .\SuperHidden.ps1 -Action Visible -Directory $Env:TMP -FolderName testing
   Create\modify VISIBLE,system folder on %TMP% location with the name 'testing'    

.EXAMPLE
   PS C:\> .\SuperHidden.ps1 -Action Delete -Directory $Env:TMP -FolderName testing
   Delete the super hidden folder on %TMP% location with the name 'testing'    

.INPUTS
   None. You cannot pipe objects into SuperHidden.ps1

.OUTPUTS
   FullName                                  CreationTime        LastAccessTime                      Attributes
   --------                                  ------------        --------------                      ----------
   C:\Users\pedro\AppData\Local\Temp\testing 15/11/2021 07:17:42 15/11/2021 07:20:44  Hidden, System, Directory
#>


#CmdLet Global variable declarations!
[CmdletBinding(PositionalBinding=$false)] param(
   [string]$FolderName="false",
   [string]$Directory="false",
   [string]$Recursive="false",
   [string]$Action="Query"
)


Write-Host ""
$ErrorActionPreference = "SilentlyContinue"
#Disable Powershell Command Logging for current session.
Set-PSReadlineOption –HistorySaveStyle SaveNothing|Out-Null


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

   .NOTES
      The -Recursive 'true' argument only works if a -Directory its inputed by user.
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
         "$Env:USERPROFILE\Documents"
      )

      ForEach($Item in $CommonLocations)
      {
         #Search for hidden,system folders on predefined locations
         Get-ChildItem -Path "$Item" -Force | Select-Object * |
            Where-Object { $_.PSIsContainer -eq 'True' -and $_.Attributes -iMatch 'Hidden, System'
         } | Select-Object FullName,CreationTime,LastAccessTime,Attributes | Format-Table -AutoSize
      }

   }
   ElseIf($Directory -ne "false")
   {
   
      If(-not(Test-Path -Path "$Directory" -EA SilentlyContinue))
      {
         #Making sure that the directory inputed exists before go any further..
         Write-Host "error: directory not found: '$Directory'" -ForegroundColor Red -BackgroundColor Black
         exit #Exit SuperHidden
      }
   
      If($FolderName -ne "false")
      {
          If($Recursive -ieq "true")
         {
            #FolderName parameter user input search function
            $SHdb = Get-ChildItem -Path "$Directory" -Recurse -Force| Select-Object * |
               Where-Object { $_.PSIsContainer -eq 'True' -and $_.Name -iMatch "$FolderName" -and $_.Attributes -iMatch 'Hidden, System'
            } | Select-Object FullName,CreationTime,LastAccessTime,Attributes | Format-Table -AutoSize
         }
         Else
         {
            #FolderName parameter user input search function
            $SHdb = Get-ChildItem -Path "$Directory" -Force| Select-Object * |
               Where-Object { $_.PSIsContainer -eq 'True' -and $_.Name -iMatch "$FolderName" -and $_.Attributes -iMatch 'Hidden, System'
            } | Select-Object FullName,CreationTime,LastAccessTime,Attributes | Format-Table -AutoSize         
         }

         If(-not($SHdb))
         {
            Write-Host "Error: fail to match the search criteria." -ForegroundColor Red -BackgroundColor Black
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
               Where-Object { $_.PSIsContainer -eq 'True' -and $_.Attributes -iMatch 'Hidden, System'
            } | Select-Object FullName,CreationTime,LastAccessTime,Attributes | Format-Table -AutoSize
         }
         Else
         {
            #Query for hidden,system folders in -Directory argument location
            $SHdb = Get-ChildItem -Path "$Directory" -Force | Select-Object * |
               Where-Object { $_.PSIsContainer -eq 'True' -and $_.Attributes -iMatch 'Hidden, System'
            } | Select-Object FullName,CreationTime,LastAccessTime,Attributes | Format-Table -AutoSize         
         }

         If(-not($SHdb))
         {
            Write-Host "Error: fail to match the search criteria." -ForegroundColor Red -BackgroundColor Black
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
   #>

   If($Directory -ieq "false"){$Directory = "$Env:TMP"}
   If($FolderName -ieq "false"){$FolderName = "testing"}
   If(-not(Test-Path -Path "$Directory\$FolderName" -EA SilentlyContinue))
   {
      #Make sure that the directory\folder exists
      mkdir $Directory\$FolderName -Force|Out-Null
   }

   try{#hidde sellected folder
      attrib +s +h $Directory\$FolderName
   }catch{#Fail to modify sellected directory attributes
      Write-Host "Error: fail to change directory attributes." -ForegroundColor Red -BackgroundColor Black
      exit #Exit SuperHidden
   }

   #Search for hidden,system folder created\modified..
   $SHdb = Get-ChildItem -Path "$Directory" -Force | Select-Object * |
      Where-Object { $_.PSIsContainer -eq 'True' -and $_.Name -iMatch "$FolderName" -and $_.Attributes -iMatch 'Hidden, System'
   } | Select-Object FullName,CreationTime,LastAccessTime,Attributes | Format-Table -AutoSize

   If(-not($SHdb))
   {
      Write-Host "Error: fail to match the search criteria." -ForegroundColor Red -BackgroundColor Black
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
   #>

   If($Directory -ieq "false"){$Directory = "$Env:TMP"}
   If($FolderName -ieq "false"){$FolderName = "testing"}
   If(-not(Test-Path -Path "$Directory\$FolderName" -EA SilentlyContinue))
   {
      #Make sure that the directory\folder exists
      mkdir $Directory\$FolderName -Force|Out-Null
   }

   try{#UnHidde sellected folder
      attrib -s -h $Directory\$FolderName
   }catch{#Fail to modify sellected directory attributes
      Write-Host "Error: fail to change directory attributes." -ForegroundColor Red -BackgroundColor Black
      exit #Exit SuperHidden
   }

   #Search for VISIBLE,system folder created\modified..
   $SHdb = Get-ChildItem -Path "$Directory" -Force | Select-Object * |
      Where-Object { $_.PSIsContainer -eq 'True' -and $_.Name -iMatch "$FolderName"
   } | Select-Object FullName,CreationTime,LastAccessTime,Attributes | Format-Table -AutoSize

   If(-not($SHdb))
   {
      Write-Host "Error: fail to match the search criteria." -ForegroundColor Red -BackgroundColor Black
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
   #>

   If($FolderName -ieq "false")
   {
      #Make sure that the folder to delete exists
      Write-Host "Error: The 'delete' function requires -FolderName input .." -ForegroundColor Red -BackgroundColor Black
      Write-Host "";exit #Exit SuperHidden
   }
   If($Directory -ieq "false"){$Directory = "$Env:TMP"}
   If(-not(Test-Path -Path "$Directory\$FolderName" -EA SilentlyContinue))
   {
      #Make sure that the directory\folder to delete exists
      Write-Host "Error: directory '$Directory\$FolderName' not found." -ForegroundColor Red -BackgroundColor Black
      exit #Exit SuperHidden
   }

   try{#delete sellected folder
      attrib -s -h $Directory\$FolderName
   }catch{#Fail to change directory attributes
      Write-Host "Error: fail to change directory attributes." -ForegroundColor Red -BackgroundColor Black
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
      Write-Host "none contents found inside current directory." -ForegroundColor Yellow
   }
   Else
   {
      echo $SHdb
   }

}
Write-Host ""