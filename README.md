Author: <b><i>@r00t-3xp10it</i></b><br />
Version release: <b><i>v2.10.11</i></b><br />
Distros Supported: <b><i>Windows (x86|x64), Linux</i></b><br />
Inspired in the work of: ['@ZHacker13 - ReverseTCPShell'](https://github.com/ZHacker13/ReverseTCPShell)<br /><br />
![meterbanner](https://user-images.githubusercontent.com/23490060/134608569-ca194b98-8a6b-4da6-9848-326101ec3652.png)<br />

[![Version](https://img.shields.io/badge/meterpeter-v2.10.11-brightgreen.svg?maxAge=259200)]()
[![Stage](https://img.shields.io/badge/Release-Stable-brightgreen.svg)]()
[![Build](https://img.shields.io/badge/OS-Windows,Linux-orange.svg)]()
![licence](https://img.shields.io/badge/license-GPLv3-brightgreen.svg)
![Last Commit](https://img.shields.io/github/last-commit/r00t-3xp10it/meterpeter)
![isues](https://img.shields.io/github/issues/r00t-3xp10it/meterpeter)
![Repo Size](https://img.shields.io/github/repo-size/r00t-3xp10it/meterpeter)

<br />

## :octocat: Quick Jump List<br />
- **[Project Description](https://github.com/r00t-3xp10it/meterpeter/blob/master/README.md#octocat-project-description)**<br />
- **[Meterpeter C2 Latest Release](https://github.com/r00t-3xp10it/meterpeter/releases/tag/untagged-a861dc932323ee9dd280)**<br />
- **[List Of Available Modules](https://github.com/r00t-3xp10it/meterpeter/blob/master/README.md#meterpeter-server-available-modules)**<br />
- **[How To - Under Linux Distributions](https://github.com/r00t-3xp10it/meterpeter/blob/master/README.md#attacker-machine-linux-kali)**<br />
- **[How To - Under Windows Distributions](https://github.com/r00t-3xp10it/meterpeter/blob/master/README.md#attacker-machiner-windows-pc)**<br />
- **[Windows Defender (Target Related)](https://github.com/r00t-3xp10it/meterpeter/blob/master/README.md#remark-about-windows-defender)**<br />
- **[Special Thanks|Contributions|Videos](https://github.com/r00t-3xp10it/meterpeter/blob/master/README.md#video-tutorials)**<br />
- **[Please Read my 'WIKI' page for detailed information about each Module](https://github.com/r00t-3xp10it/meterpeter/wiki)**<br />

<br />

## :octocat: Project Description
This PS1 starts a listener Server on a Windows|Linux attacker machine and generates oneliner PS reverse shell payloads obfuscated in BXOR with a random secret key and another layer of Characters/Variables Obfuscation to be executed on the victim machine (The payload will also execute AMSI reflection bypass in current session to evade AMSI detection while working). You can also recive the generated oneliner reverse shell connection via netcat. (in this case you will lose the C2 functionalities like screenshot, upload, download files, Keylogger, AdvInfo, PostExploit, etc)<br /><br />meterpeter payloads/droppers can be executed using User or Administrator Privileges depending of the cenario (executing the Client as Administrator will unlock ALL Server Modules, amsi bypasses, etc.). Droppers mimic a fake KB Security Update while in background download\exec Client in '<b><i>$Env:TMP</i></b>' trusted location, with the intent of evading  Windows Defender Exploit Guard. meterpeter payloads|droppers are FUD (please dont test samples on VirusTotal).<br />

Under Linux users required to install **powershell** and **apache2** webserver, Under Windows its optional the install of **python3** http.server to deliver payloads under LAN networks. If this requirements are **NOT** met, then the Client ( <b><i>Update-KB4524147.ps1</i></b> ) will be written in meterpeter working directory for manual deliver.
![oki1](https://user-images.githubusercontent.com/23490060/135849854-575d3dcd-21c5-44a1-96fe-3684d586c128.png)<br />

<br />

### meterpeter (Server) available modules<br />
![bob](https://user-images.githubusercontent.com/23490060/135769098-839712de-87ef-4c0e-a74a-190b3d2c7ad3.png)<br />

<details>

<summary>Full List of meterpeter (Server) available modules</summary>

- **Info**       : Quick Retrieve of Target PC Information
- **AdvInfo**    : Advanced Gather Information Modules (Sub-Menu)
  - **ListAdm**  : Retrieve Client Shell Path|Privileges
  - **ListAcc**  : Retrieve Remote-Host Accounts List
  - **ListSmb**  : Retrieve Remote-Host SMB shares List
  - **ListDns**  : Retrieve Remote-Host DNS Entrys List
  - **ListApp**  : Retrieve Remote-Host Installed Applications List
  - **ListTask** : Remote-Host Schedule Tasks Module (Sub-Menu)
    - **Check**    : Retrieve Schedule Tasks List
    - **Query**    : Schedule Taks Verbose Information
    - **Create**   : Create Remote-Host New Tasks
    - **Delete**   : Delete Remote-Host Tasks
  - **ListRece** : Retrieve Remote-Host Recent Folder Contents
  - **ListPriv** : Remote-Host Weak Service|Folders permissions (Sub-Menu)
    - **Check**   : Retrieve Folder Permissions
    - **WeakDir** : Search for Folders weak Permissions recursive
    - **Service** : Search for Unquoted Service Paths vulnerability
    - **RottenP** : Search for Rotten Potato Privilege Vulnerability
    - **RegACL**  : Search for weak permissions on registry
  - **StartUp**  : Retrieve Remote-Host StartUp Folder Contents
  - **ListDriv** : Retrieve Remote-Host Drives Available List
  - **ListRun**  : Retrieve Remote-Host Startup Run Entrys
  - **ListProc** : Remote-Host Processe(s) (Sub-Menu)
    - **Check**    : Retrieve Remote Processe(s) Running
    - **KillProc** : Kill Remote Process By DisplayName
  - **ListConn** : Retrieve Remote-Host Active TCP Connections List
  - **ListIpv4** : Retrieve Remote-Host IPv4 Network Statistics List
  - **ListWifi** : Remote-Host Profiles/SSID/Passwords (Sub-Menu)
    - **ListProf**  : Retrieve Remote-Host wifi Profile
    - **ListNetw**  : Retrieve wifi Available networks List
    - **SSIDPass**  : Retrieve Stored SSID passwords
- **Session**    : Retrieve C2 Server Connection Status.
- **Upload**     : Upload File from Local-Host to Remote-Host.
- **Download**   : Download File from Remote-Host to Local-Host.
- **Screenshot** : Save Screenshot from Remote-Host to Local-Host.
- **keylogger**  : Remote-Host Keylogger (Sub-Menu)
  - **Mouse**       : start mouse looger
  - **Start**       : Start remote keylogger
  - **Stop**        : Stop keylogger Process(s)
- **FRManager**  : Manage remote-host Firewall rules
  - **Query**       : Query for all active firewall rules
  - **Create**      : Create a new Block firewall rule
  - **Delete**      : Delete an existing firewall rule
- **PostExploit**: Post-Exploitation Modules (Sub-Menu)
  - **Escalate** : Client Privilege Escalation (Sub-Menu)
    - **GetAdmin**  : Escalate Client Privileges (UserLand -> Admin)
  - **Stream**   : stream live target desktop (Sub-Menu)
    - **Start**     : Start streamming target desktop
  - **Artifacts**: Clean target system tracks (Sub-Menu)
    - **Query**     : Print major eventvwr categories
    - **Clean**     : Delete .tmp,.ps1,eventvwr logfiles
    - **Paranoid**  : Delete all artifacts paranoid mode
  - **CamSnap**  : Manipulate remote webcam (sub-menu)
    - **Device**    : List Remote-Host webcams available
    - **Snap**      : Take Remote-Host screenshot (Default webcam)
    - **Manual**    : Manual sellect webcam device to use (device name)
  - **HideUser** : Hidden accounts manager (sub-menu)
    - **Query**     : Query all accounts existence
    - **Create**    : create hidden account with admin privs
    - **Delete**    : delete hidden account name
  - **OpenUrl**  : Open URL in default browser
  - **Persist**  : Remote Persist Client (Sub-Menu)
    - **Beacon**    : Persiste Client Using startup Folder (beacon home from xx to xx sec)
    - **RUNONCE**   : Persiste Client using REGISTRY:RunOnce Key
    - **REGRUN**    : Persiste Client using REGISTRY:Run Key
    - **Schtasks**  : Make Client Beacon Home with xx minuts of Interval
    - **WinLogon**  : Persiste Client using WinLogon REGISTRY:Userinit Key
  - **BruteAcc** : Brute-Force User Account Password (dicionary)
    - **Start**     : Start brute-forcing user account password
  - **Restart**  : Restart in xx seconds
  - **SetMace**  : Change files date/time TimeStomp
  - **ListPas**  : Search for passwords in txt Files
  - **Hidden**   : Query\Create\Delete super hidden folders
    - **Search**    : Search for regular hidden folders
    - **Super**     : Search for super hidden folders
    - **Create**    : Create super hidden folder
    - **Delete**    : Delete super hidden folder
  - **GoogleX**  : Open Remote Browser in google sphere (prank)
  - **LockPC**   : Lock Remote workstation (prank|refresh explorer)
  - **SpeakPC**  : Make Remote-Host Speak your sentence (prank)
  - **AMSIset**  : Enable/Disable AMSI Module (Sub-Menu)
    - **Disable**   : Disable AMSI in REGISTRY:hklm|hkcu
    - **Enable**    : Enable  AMSI in REGISTRY:hklm|hkcu
  - **ListCred** : Retrieve Remote-Host cmdkey stored Creds
  - **UACSet**   : Enable/Disable remote UAC Module (Sub-Menu)
    - **Disable**   : Disable UAC in REGISTRY:hklm
    - **Enable**    : Enable  UAC in REGISTRY:hklm
  - **ASLRSet**  : Enable/Disable ASLR Module (Sub-Menu)
    - **Disable**   : Disable ASLR in REGISTRY:hklm
    - **Enable**    : Enable  ASLR in REGISTRY:hklm
  - **TaskMan**  : Enable/Disable TaskManager Module (Sub-Menu)
    - **Disable**   : Disable TaskManager in REGISTRY:hklm
    - **Enable**    : Enable  TaskManager in REGISTRY:hklm
  - **Firewall** : Enable/Disable Remote Firewall Module (Sub-Menu)
    - **Check**     : Review Remote-Host Firewall Settings
    - **Disable**   : Disable Remote-Host Firewall
    - **Enable**    : Enable  Remote-Host Firewall
  - **DumpSAM**  : Dump LSASS/SAM/SYSTEM Creds to a remote location
  - **Dnspoof**  : Hijack Entrys in hosts file Module (Sub-Menu)
    - **Check**     : Review Remote-Host hosts File
    - **Spoof**     : Add Entrys to Remote-Host hosts File
    - **Default**   : Defaults Remote-Host hosts File
  - **NoDrive**  : Hide Drives from Explorer Module (Sub-Menu)
    - **Disable**   : Hide Drives from explorer in REGISTRY:hklm
    - **Enable**    : Enable Drives from explorer in REGISTRY:hklm
  - **CredPhi**  : Phishing for remote logon credentials
    - **Start**     : Trigger Remote Phishing PS Script (Windows 7 or less)
  - **Browser**   : Enumerate Installed Browsers (IE,FIREFOX,CHROME)
- **exit**       : Exit Reverse TCP Shell (Server + Client).

- **[Please Read my WIKI for Detailed information about each Module](https://github.com/r00t-3xp10it/meterpeter/wiki)**<br />
  
  </details>
  
**[Quick Jump List](https://github.com/r00t-3xp10it/meterpeter/blob/master/README.md#octocat-quick-jump-list)**<br />


---

<br /><br />

### ATTACKER MACHINE: [Linux Kali]
      Warning: powershell under linux distributions its only available for x64 bits archs ..
![linux](https://user-images.githubusercontent.com/23490060/74575258-26951700-4f7e-11ea-832c-512dce1c97cc.png)

<br />

#### Install Powershell (Linux x64 bits)
```
apt-get update && apt-get install -y powershell
```

#### Install Apache2
```
apt-get install Apache2
```

#### Start Apache2 WebServer
```
service apache2 start
```

#### Start C2 Server (Local)
```
cd meterpeter
pwsh -File meterpeter.ps1
```

#### Deliver Dropper/Payload To Target Machine (apache2)
```
USE THE 'Attack Vector URL' TO DELIVER 'Update-KB4524147.zip' (dropper) TO TARGET ..
UNZIP (IN DESKTOP) AND EXECUTE 'Update-KB4524147.bat' (Run As Administrator)..
```

#### Remark:

     IF dropper.bat its executed: Then the Client will use $env:tmp has its working directory ('recomended')..
     IF Attacker decided to manualy execute Client: Then Client remote location (pwd) will be used has working dir .


**[Quick Jump List](https://github.com/r00t-3xp10it/meterpeter/blob/master/README.md#octocat-quick-jump-list)**<br />

---

<br /><br />

### ATTACKER MACHINER: [Windows PC]
![frd](https://user-images.githubusercontent.com/23490060/74575907-b76cf200-4f80-11ea-8f44-ddd79fbd812f.png)

<br />

#### Install Python3 (optional)
Install Python3 (http.Server) to deliver payloads under LAN networks ..<br />
```
https://www.python.org/downloads/release/python-381/
```

#### Start C2 Server (Local)
```
cd meterpeter
powershell Set-ExecutionPolicy Unrestricted -Scope CurrentUser
powershell -File meterpeter.ps1
```

**Remark**
- meterpeter.ps1 delivers Dropper/Payload using python3 http.server. IF attacker has python3 installed.<br />
  **'If NOT then the payload (Client) its written in Server Local [Working Directory](https://github.com/r00t-3xp10it/meterpeter/wiki/How-To-Display%7CChange-'Client'-Working-Directory) to be Manualy Deliver'** ..

- Remmnenber to close the http.server terminal after the target have recived the two files (Dropper & Client)<br />
  **'And we have recived the connection in our meterpeter Server { to prevent Server|Client connection errors }'**<br /><br />

#### Deliver Dropper/Payload To Target Machine (manual OR python3)
```
DELIVER 'Update-KB4524147' (.ps1=manual) OR (.zip=automated|silentExec) TO TARGET ..
```

#### Remark:

     IF dropper.bat its executed: Then the Client will use $env:tmp has its working directory ('recomended')..
     IF Attacker decided to manualy execute Client: Then Client remote location (pwd) will be used has working dir .

**[Quick Jump List](https://github.com/r00t-3xp10it/meterpeter/blob/master/README.md#octocat-quick-jump-list)**<br />

---

<br />

### Remark About Windows Defender:
Using **keylogger** Module without the **Client** been executed as administrator, will trigger this kind of warnings by Windows Defender **AMSI** mechanism. IF the **Client** is executed as administrator and target machine as powershell **version 2** installed, then the keylogger execution its achieved using PSv2 (**bypassing Windows Defender AMSI|DEP|ASLR defenses**). The same method its also valid for **persistence** Module, executing our client using powershell version 2 (PS downgrade Attack).<br /><br />
**Payloads|Droppers are FUD (Fully UnDetected) by AntiVirus (Please dont test samples on VirusTotal)**<br />
![AV](https://user-images.githubusercontent.com/23490060/74576599-6f030380-4f83-11ea-8e10-bdeefeb0b547.png)<br />
**[Quick Jump List](https://github.com/r00t-3xp10it/meterpeter/blob/master/README.md#octocat-quick-jump-list)**<br />

---

<br />

### Video Tutorials:
meterpeter Under Windows Distros: https://www.youtube.com/watch?v=d2npuCXsMvE<br />
meterpeter Under Linux Distros: https://www.youtube.com/watch?v=CmMbWmN246E<br /><br />

### Special Thanks:
**@ZHacker13** (Original Rev Shell) | **@tedburke** (CommandCam.exe binary)<br />
**@codings9** (debugging project uWindows|Linux) | @ShantyDamayanti (debugging Windows)<br /><br />
- **[meterpeter WIKI pages (Oficial Documentation)](https://github.com/r00t-3xp10it/meterpeter/wiki)**<br />
- **[Jump To Top of this readme File](https://github.com/r00t-3xp10it/meterpeter/blob/master/README.md#octocat-quick-jump-list)**<br />
---

<br />
