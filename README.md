Author: <b><i>@r00t-3xp10it</i></b><br />
Version release: <b><i>v2.10.12</i></b><br />
Distros Supported: <b><i>Windows (x86|x64), Linux</i></b><br />
Inspired in the work of: ['@ZHacker13 - ReverseTCPShell'](https://github.com/ZHacker13/ReverseTCPShell)<br /><br />
![meterbanner](https://user-images.githubusercontent.com/23490060/134608569-ca194b98-8a6b-4da6-9848-326101ec3652.png)<br />

[![Version](https://img.shields.io/badge/meterpeter-v2.10.12-brightgreen.svg?maxAge=259200)]()
[![Stage](https://img.shields.io/badge/Release-Stable-brightgreen.svg)]()
[![Build](https://img.shields.io/badge/OS-Windows,Linux-orange.svg)]()
![licence](https://img.shields.io/badge/license-GPLv3-brightgreen.svg)
![Last Commit](https://img.shields.io/github/last-commit/r00t-3xp10it/meterpeter)
![isues](https://img.shields.io/github/issues/r00t-3xp10it/meterpeter)
![Repo Size](https://img.shields.io/github/repo-size/r00t-3xp10it/meterpeter)

<br />

## :octocat: Quick Jump List<br />
- **[Project Description](https://github.com/r00t-3xp10it/meterpeter/blob/master/README.md#octocat-project-description)**<br />
- **[List Of Available Modules](https://gist.github.com/r00t-3xp10it/4b066797ddc99a3fc41195ddfaf4af9b?permalink_comment_id=4133582#gistcomment-4133582)**<br />
- **[Meterpeter C2 Latest Release](https://github.com/r00t-3xp10it/meterpeter/releases/tag/v2.10.12)**<br />
- **[How To - Under Linux Distributions](https://github.com/r00t-3xp10it/meterpeter/blob/master/README.md#attacker-machine-linux-kali)**<br />
- **[How To - Under Windows Distributions](https://github.com/r00t-3xp10it/meterpeter/blob/master/README.md#attacker-machiner-windows-pc)**<br />
- **[Special Thanks|Contributions|Videos](https://github.com/r00t-3xp10it/meterpeter/blob/master/README.md#video-tutorials)**<br />
- **[Please Read my 'WIKI' page for detailed information about each Module](https://github.com/r00t-3xp10it/meterpeter/wiki)**<br />

<br />

## :octocat: Project Description
This PS1 starts a listener Server on a Windows|Linux attacker machine and generates oneliner PS reverse shell payloads obfuscated in BXOR with a random secret key and another layer of Characters/Variables Obfuscation to be executed on the victim machine (The payload will also execute AMSI reflection bypass in current session to evade AMSI detection while working). You can also recive the generated oneliner reverse shell connection via netcat. (in this case you will lose the C2 functionalities like screenshot, upload, download files, Keylogger, AdvInfo, PostExploit, etc)<br /><br />meterpeter payloads/droppers can be executed using User or Administrator Privileges depending of the cenario (executing the Client as Administrator will unlock ALL Server Modules, amsi bypasses, etc.). Droppers mimic a fake KB Security Update while in background download\exec Client in '<b><i>$Env:TMP</i></b>' trusted location, with the intent of evading  Windows Defender Exploit Guard. meterpeter payloads|droppers are FUD (please dont test samples on VirusTotal).<br />

Under Linux users required to install **powershell** and **apache2** webserver, Under Windows its optional the install of **python3** http.server to deliver payloads under LAN networks. If this requirements are **NOT** met, then the Client ( <b><i>Update-KB4524147.ps1</i></b> ) will be written in meterpeter working directory for manual deliver.
![oki1](https://user-images.githubusercontent.com/23490060/135849854-575d3dcd-21c5-44a1-96fe-3684d586c128.png)<br />

<br />

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

### Video Tutorials:
meterpeter Under Windows Distros: https://www.youtube.com/watch?v=d2npuCXsMvE<br />
meterpeter Under Linux Distros: https://www.youtube.com/watch?v=CmMbWmN246E<br /><br />

### Special Thanks:
**@ZHacker13** (Original Rev Shell) | **@tedburke** (CommandCam.exe binary)<br />
**@codings9** (debugging modules) | @ShantyDamayanti (debugging Modules)<br />
**@AHLASaad** (debugging Modules) | **@gtworek** (EnableAllParentPrivileges)<br /><br />
- **[meterpeter WIKI pages (Oficial Documentation)](https://github.com/r00t-3xp10it/meterpeter/wiki)**<br />
- **[Jump To Top of this readme File](https://github.com/r00t-3xp10it/meterpeter/blob/master/README.md#octocat-quick-jump-list)**<br />
---

<br />
