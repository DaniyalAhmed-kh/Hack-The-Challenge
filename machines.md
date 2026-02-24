
#  **🎯 THE ULTIMATE FREE PENTESTING MACHINES CATALOG**



**1000+ Free Vulnerable Machines to Own in One Year**

**VulnHub  •  HackMyVM  •  VulNyx  •  DockerLabs  •  GitHub Vulnerable Projects**

From Beginner to Advanced  |  Boot2Root  |  Web Exploitation  |  Binary Exploitation  |  Active Directory  |  Cloud Security

2025 Edition

## PLATFORM OVERVIEW

| **Platform**    | **Type**                    | **Machine Count** | **Cost**  | **URL**       |
| --------------- | --------------------------- | ----------------- | --------- | ------------- |
| VulnHub         | Downloadable VMs (OVA/VMDK) | 700+ machines     | 100% Free | vulnhub.com   |
| HackMyVM        | Downloadable VMs (OVA)      | 300+ machines     | 100% Free | hackmyvm.eu   |
| VulNyx          | Downloadable VMs (OVA)      | 150+ machines     | 100% Free | vulnyx.com    |
| DockerLabs      | Docker containers           | 200+ machines     | 100% Free | dockerlabs.es |
| GitHub Projects | Docker/VM/source            | 500+ apps         | 100% Free | github.com    |

  

# 📅 12-MONTH PWNING ROADMAP

This roadmap organizes 1000+ machines into a progressive 12-month plan. Each month builds on the previous, progressively introducing harder techniques. Start with beginner boxes to build confidence, then systematically advance through intermediate and expert-level exploitation.

|**Month**|**Theme**|**Machines/Month**|**Primary Platform**|**Key Skills**|
|---|---|---|---|---|
|Month 1|Linux Fundamentals & Basic Enum|20-25|VulnHub|Nmap, Gobuster, Basic SQLi, SSH brute|
|Month 2|Web Application Attacks|20-25|VulnHub + DockerLabs|SQLi, LFI, RFI, File Upload, XSS|
|Month 3|Privilege Escalation Mastery|20-25|VulnHub + VulNyx|SUID, Sudo, Cron, PATH hijacking|
|Month 4|CMS & Web Framework Exploitation|20-25|VulnHub + HackMyVM|WordPress, Joomla, Drupal, Laravel|
|Month 5|Buffer Overflow & Binary Basics|15-20|VulnHub + VulNyx|x86 BOF, Shellcode, GDB, Pwndbg|
|Month 6|Network Services & Pivoting|20-25|HackMyVM + VulnHub|SMB, NFS, SSH tunneling, Chisel|
|Month 7|Active Directory & Windows|15-20|VulNyx + GitHub|BloodHound, Kerberoasting, DCSync|
|Month 8|Advanced Binary Exploitation|10-15|VulNyx|ROP chains, ASLR bypass, format string|
|Month 9|Container & Cloud Basics|15-20|GitHub + DockerLabs|Docker escape, K8s, AWS IAM|
|Month 10|Advanced Web & API Security|20-25|HackMyVM + VulNyx|SSTI, XXE, Deserialization, OAuth|
|Month 11|Multi-Machine Networks|10-15|VulnHub|Network pivot, multi-hop, AD chains|
|Month 12|CTF Challenges & Exam Prep|20-25|All Platforms|Full attack chain, report writing|

## 🛠️ ESSENTIAL TOOLS REFERENCE

|**Category**|**Tools**|**Purpose**|
|---|---|---|
|Reconnaissance|Nmap, Masscan, Rustscan, Netdiscover, arp-scan|Port scanning, service detection, OS fingerprinting|
|Web Enumeration|Gobuster, Feroxbuster, Dirsearch, ffuf, Nikto|Directory/file fuzzing, web vulnerability scanning|
|Web Exploitation|SQLmap, Burp Suite, OWASP ZAP, XSSer, Commix|SQL injection, proxy, XSS, command injection|
|Password Attacks|Hydra, Medusa, Hashcat, John, CrackStation|Brute forcing, hash cracking, password recovery|
|Privilege Escalation|LinPEAS, WinPEAS, PSPY, GTFOBins, PrivescCheck|Linux/Windows privesc enum, SUID, sudo abuse|
|Exploitation|Metasploit, Searchsploit, pwntools, GDB, pwndbg|Exploit frameworks, binary exploitation, debugging|
|Active Directory|BloodHound, SharpHound, Impacket, CrackMapExec, Evil-WinRM|AD enumeration, Kerberoasting, lateral movement|
|Network|Wireshark, tcpdump, Chisel, Ligolo-ng, Proxychains|Packet analysis, tunneling, pivoting|
|Containers|Docker CLI, kubectl, Trivy, Falco|Container enumeration, escape, K8s attacks|
|Steganography|Steghide, Binwalk, Stegsolve, ExifTool|Hidden data extraction, file analysis|

  

# 🔴 SECTION 1: VULNHUB MACHINES

VulnHub provides downloadable vulnerable virtual machines. Download OVA/VMDK files and import into VirtualBox or VMware. All machines are 100% free. Website: vulnhub.com

## TIER 1 — BEGINNER (Machines #1–100)

Start here. Focus on enumeration fundamentals, basic web exploitation, simple privilege escalation. Complete these before moving on.

|**#**|**Machine Name**|**OS**|**Skills / Focus Areas**|**Difficulty**|
|---|---|---|---|---|
|**1**|Kioptrix: Level 1|Linux|SMB exploitation, Samba version vuln, Metasploit basics|**Easy**|
|**2**|Kioptrix: Level 1.1|Linux|SQL injection, OS command injection, privilege escalation|**Easy**|
|**3**|Kioptrix: Level 1.2|Linux|Web CMS exploit, LFI, local privesc via SUID|**Easy**|
|**4**|Kioptrix: Level 1.3|Linux|SMB enumeration, MySQL credentials, config file reading|**Easy**|
|**5**|Kioptrix: 2014|FreeBSD|FreeBSD enumeration, Apache config exploit, kernel privesc|**Easy**|
|**6**|pWnOS 2.0|Linux|WordPress exploitation, SimplePress plugin RCE, sudo abuse|**Easy**|
|**7**|FristiLeaks 1.3|Linux|PHP file upload bypass, image shell upload, SUID privesc|**Easy**|
|**8**|Basic Pentesting: 1|Linux|Samba recon, FTP enumeration, SSH brute force, sudo misconfiguration|**Easy**|
|**9**|Lin.Security|Linux|Linux local priv esc, sudo misconfiguration, SUID binaries|**Easy**|
|**10**|Metasploitable 2|Linux|Multiple services, FTP, SSH, Telnet, VSFTPD, Samba, Java RMI|**Easy**|
|**11**|Metasploitable 3|Windows/Linux|Full service exploitation, web apps, multiple attack vectors|**Easy**|
|**12**|DVWA|Linux|OWASP Top 10, SQLi, XSS, CSRF, file inclusion, command exec|**Easy**|
|**13**|SickOs 1.1|Linux|HTTP proxy enumeration, shellshock, cron job abuse|**Easy**|
|**14**|SickOs 1.2|Linux|FTP, HTTP, SSH, vulnerability chaining, Linux privesc|**Easy**|
|**15**|/dev/random: Scream|Linux|Buffer overflow, shellcode, basic exploits, GDB usage|**Easy**|
|**16**|pWnOS 1.0|Linux|Webmin exploit, Perl CGI exploitation, privilege escalation|**Easy**|
|**17**|Tr0ll 1|Linux|FTP anonymous, Wireshark analysis, SSH brute force, kernel exploit|**Easy**|
|**18**|Tr0ll 2|Linux|Base64 encoding, SSH key extraction, binary reverse engineering|**Easy**|
|**19**|Tr0ll 3|Linux|Multi-stage, web enum, crypto, binary analysis|**Medium**|
|**20**|DC: 1|Linux|Drupal CME exploit, SUID find binary, privilege escalation|**Easy**|
|**21**|DC: 2|Linux|WordPress CTF mode, WPScan, Git privesc, rbash escape|**Easy**|
|**22**|DC: 3|Linux|Joomla exploitation, sqlmap, John cracking, kernel exploit|**Medium**|
|**23**|DC: 4|Linux|WordPress RCE, Teehee sudo escape, cron job hijack|**Easy**|
|**24**|DC: 5|Linux|Nginx LFI, log poisoning, RCE, screen privesc|**Medium**|
|**25**|DC: 6|Linux|WordPress admin exploitation, WPScan, Nmap sudo, Exim exploit|**Medium**|
|**26**|DC: 7|Linux|WordPress, OpenCart, database credentials, config file analysis|**Medium**|
|**27**|DC: 8|Linux|Drupal SQLi, exim4 privesc, SUID exploitation|**Medium**|
|**28**|DC: 9|Linux|SQLi, WordPress, Knockd port knocking, SSH privesc|**Medium**|
|**29**|Mr. Robot: 1|Linux|WordPress enumeration, dictionary attack, privilege escalation|**Medium**|
|**30**|Stapler: 1|Linux|SMB enumeration, multiple web ports, SSH user enumeration, priv esc|**Medium**|
|**31**|VulnOS: 2|Linux|OpenDocMan SQLi, metasploit, Drupal, post exploitation|**Medium**|
|**32**|SkyTower: 1|Linux|SQLi, SSH tunneling, RBash escape, privilege escalation|**Medium**|
|**33**|HackLAB: Vulnix|Linux|NFS shares, SMTP finger, SSH key injection, privilege escalation|**Medium**|
|**34**|PwnLab: Init|Linux|PHP code injection, LFI, file upload, privilege escalation|**Medium**|
|**35**|Temple of Doom|Linux|Node.js deserialization, SUID privilege escalation|**Medium**|
|**36**|billu: b0x|Linux|PHP file inclusion, SQLi, wget SUID abuse|**Medium**|
|**37**|IMF: 1|Linux|HTTP steganography, SQLi, Metasploit, buffer overflow|**Hard**|
|**38**|Empire: LupinOne|Linux|SSH key cracking, Python sudo, pip install abuse|**Easy**|
|**39**|Empire: Breakout|Linux|Webmin exploit, BreakOut CTF, capability privesc|**Medium**|
|**40**|Empire: Vanquish|Linux|Multi-stage, Docker pivot, SSH agent forwarding|**Hard**|
|**41**|Pinky's Palace v1|Linux|SQLi, Nginx config bypass, buffer overflow stack smashing|**Hard**|
|**42**|Pinky's Palace v2|Linux|PHP web shell, SSH key bruteforce, BOF x86|**Hard**|
|**43**|Pinky's Palace v3|Linux|Multi-stage network pivot, SSH tunneling, ROP chain|**Hard**|
|**44**|Pinky's Palace v4|Linux|ARM exploitation, glibc heap overflow, ASLR bypass|**Insane**|
|**45**|Brainpan: 1|Linux|Buffer overflow, OSCP prep, Wine, manual payload crafting|**Medium**|
|**46**|Brainpan: 2|Linux|Restricted shell escape, Docker, Python BOF|**Hard**|
|**47**|Brainpan: 3|Linux|Format string exploit, Ret2libc, ASLR bypass|**Hard**|
|**48**|HackMe: 1|Linux|Web app hacking, manual SQLi, password cracking|**Easy**|
|**49**|Symfonos: 1|Linux|SMTP log poisoning, LFI, Helios WordPress privesc|**Easy**|
|**50**|Symfonos: 2|Linux|FTP SMB credentials, LibreNMS RCE, sudo exploit chain|**Medium**|
|**51**|Symfonos: 3|Linux|Proftpd SQL injection, tcpdump SUID, Python reverse shell|**Medium**|
|**52**|Symfonos: 4|Linux|SQLI, Flask SSTI, custom Python RCE, motd privesc|**Medium**|
|**53**|Symfonos: 5|Linux|OpenLDAP, LDAP injection, sudo ldapmodify, privilege escalation|**Hard**|
|**54**|Symfonos: 6|Linux|Gitea RCE, network pivot, Golang reverse engineering|**Hard**|
|**55**|Zico2|Linux|WordPress, ZipArchive PHP vuln, sudo zip privesc|**Medium**|
|**56**|Wintermute|Linux|Multi-machine, Postfix, Dovecot, network lateral movement|**Hard**|
|**57**|SolidState|Linux|James Mail server RCE, rsync privesc, cron abuse|**Medium**|
|**58**|Lord of the Root 1.0.1|Linux|Port knocking, SQLi, BOF kernel exploit|**Hard**|
|**59**|VulnUni|Linux|LFI, SQL injection, PHP web shell, file upload|**Easy**|
|**60**|Web Developer: 1|Linux|WordPress plugin vuln, Wireshark packet analysis, MySQL priv esc|**Medium**|
|**61**|HackInOS: 1|Linux|Docker container escape, reverse engineering, privesc|**Medium**|
|**62**|Toppo: 1|Linux|Web enumeration, credentials in files, sudo privesc|**Easy**|
|**63**|BSides Vancouver 2018|Linux|WordPress enum, user enumeration, password reuse, CRON abuse|**Easy**|
|**64**|Wallaby's Nightmare v2|Linux|IRC bot exploitation, Ansible playbook abuse|**Medium**|
|**65**|Lazysysadmin|Linux|SMB, WordPress, SSH credentials reuse, sudo ALL|**Easy**|
|**66**|Sar: 1|Linux|Sar2HTML RCE, cron job injection, command injection|**Easy**|
|**67**|Vikings: 1|Linux|FTP, Wireshark, custom port, SUID perl|**Medium**|
|**68**|Hacksudo: FOG|Linux|FTP, RCE, Python privesc, lateral movement|**Medium**|
|**69**|Hacksudo: Thor|Linux|Multi-stage, SSH tunneling, binary reverse engineering|**Hard**|
|**70**|Hacksudo: IsRo0t|Linux|Docker container escape, CVE exploitation|**Hard**|
|**71**|doubletrouble: 1|Linux|SquirrelMail RCE, steganography, sudoedit privesc|**Medium**|
|**72**|GoldenEye: 1|Linux|POP3 service, Moodle RCE, cron privesc|**Medium**|
|**73**|Photographer: 1|Linux|Koken CMS upload, arbitrary file upload RCE, SUID privesc|**Easy**|
|**74**|NullByte: 1|Linux|SQLi, image metadata, Hydra SSH, env PATH hijack|**Medium**|
|**75**|Jangow: 01|Linux|Command injection, PHP web shell, kernel exploit|**Easy**|
|**76**|Sunset: Midnight|Linux|WordPress, SQLI, STATUS privesc|**Easy**|
|**77**|Sunset: Twilight|Linux|WordPress credential re-use, sudo ALL access|**Easy**|
|**78**|Sunset: Dawn|Linux|Samba credentials, CRON execution, SSH privesc|**Easy**|
|**79**|Sunset: Decoy|Linux|Python jail break, restricted shell escape|**Medium**|
|**80**|Sunset: Noontide|Linux|Hexchat, IRC bot command injection|**Easy**|
|**81**|Ragnar-Lothbrok|Linux|Hidden directories, encrypted files, steg, PHP RCE|**Medium**|
|**82**|PwnOS: 1.0|Linux|Webmin exploit, PHP injection, local privesc|**Easy**|
|**83**|Lampiao|Linux|Drupal 7 SQLi, Dirty Cow exploit (CVE-2016-5195)|**Easy**|
|**84**|The Planets: Earth|Linux|DNS enumeration, Certutil RCE, SUID binary exploitation|**Easy**|
|**85**|The Planets: Mercury|Linux|Python SQLi, Django debug, sudo vim privesc|**Easy**|
|**86**|The Planets: Venus|Linux|SSH user enum, reverse engineering binary, SUID abuse|**Medium**|
|**87**|Misdirection|Linux|Apache .htpasswd, port redirect, PHP shell, privesc via su|**Medium**|
|**88**|HA: Narak|Linux|WordPress, tftp, Gandalf shell escape|**Easy**|
|**89**|HA: Infinity Stones|Linux|Multi-step, LFI, SQLi, RCE, Docker escape|**Hard**|
|**90**|HA: Joker|Linux|WordPress admin, writable cron, SH injection|**Easy**|
|**91**|HA: Pandavas|Linux|Apache, git repo exposed, sudo nmap|**Easy**|
|**92**|HA: HaraKiri|Linux|Tomcat WAR deploy, SUID find, privesc chain|**Medium**|
|**93**|HA: Dhanush|Linux|Shellshock, SUID, kernel exploit|**Medium**|
|**94**|HA: Chanakya|Linux|CMS exploit, password reuse, sudo abuse|**Easy**|
|**95**|HA: Sherlock|Linux|Joomla RCE, privilege escalation via sudo python|**Medium**|
|**96**|HA: Detective|Linux|LFI, PHP session poisoning, SUID binary|**Medium**|
|**97**|HA: Avengers|Linux|Multi-stage, Docker, network enum|**Hard**|
|**98**|HA: Lord Of The Ring|Linux|Multi-machine network pentest|**Hard**|
|**99**|HA: Chakravyuh|Linux|Complex multi-stage, lateral movement|**Hard**|
|**100**|HA: Armour|Linux|Complex priv chain, custom binary exploitation|**Hard**|

## TIER 2 — INTERMEDIATE (Machines #101–200)

Intermediate boxes require chaining multiple vulnerabilities together. Expect more complex privilege escalation, web exploitation depth, and lateral movement.

|**#**|**Machine Name**|**OS**|**Skills / Focus Areas**|**Difficulty**|
|---|---|---|---|---|
|**101**|ColddBox: Easy|Linux|WordPress hidden creds, PHP reverse shell, SUID privesc|**Easy**|
|**102**|ColddBox: Medium|Linux|WordPress plugin exploit, mysql credentials, lxd privesc|**Medium**|
|**103**|ColddBox: Hard|Linux|Multi-stage wordpress, kernel CVE exploitation|**Hard**|
|**104**|Tiki: 1|Linux|TikiWiki CMS, SQLi, LDAP injection, sudo abuse|**Medium**|
|**105**|Gaara|Linux|Genie binary privesc, hidden files, Hydra SSH|**Easy**|
|**106**|Gemini Inc: 1|Linux|Web directory traversal, LDAP injection, SSH privesc|**Medium**|
|**107**|Gemini Inc: 2|Linux|Multi-stage, pivoting, LDAP, custom binary|**Hard**|
|**108**|unknowndevice64: 1|Linux|Linux password cracking, steganography, binary RE|**Hard**|
|**109**|W1R3S: 1.0.1|Linux|Cuppa CMS LFI, passwd readable, custom user privesc|**Easy**|
|**110**|Escalate_Linux: 1|Linux|Linux privilege escalation, multi-vector PrivEsc lab|**Easy**|
|**111**|InfoSecWarrior CTF: 1|Linux|Web enum, SSH key cracking, sudo abuse|**Easy**|
|**112**|Covfefe: 1|Linux|SSH, hidden secret files, binary SUID|**Easy**|
|**113**|HarryPotter: Aragog|Linux|WordPress, SQLi, LXD container escape|**Medium**|
|**114**|HarryPotter: Nagini|Linux|SSRF, Joomla CMS, curl sudo exploitation|**Medium**|
|**115**|HarryPotter: Fawkes|Linux|BOF x64, ret2libc, ROP chain stack canary|**Hard**|
|**116**|MinU: 1|Linux|Restricted shell escape, command injection, privesc|**Hard**|
|**117**|MinU: 2|Linux|Multi-stage, webapp + binary exploitation|**Hard**|
|**118**|KB-VULN: 1|Linux|SMB enumeration, WordPress, Metasploit privesc|**Easy**|
|**119**|KB-VULN: 2|Linux|WordPress, phpMyAdmin, sudo bash|**Easy**|
|**120**|KB-VULN: 3|Linux|SMTP, FTP, SSH, WebAdmin exploit chain|**Medium**|
|**121**|Ckanel: 1|Linux|phpMyAdmin, SQL, sudo awk privesc|**Easy**|
|**122**|Djinn: 1|Linux|FTP, Game server, template injection, restricted shell escape|**Medium**|
|**123**|Djinn: 2|Linux|SSRF, Redis, python subprocess, docker escape|**Hard**|
|**124**|Djinn: 3|Linux|Multi-stage, crypto, LFI, reverse engineering|**Hard**|
|**125**|CengBox: 1|Linux|Cengaver CMS exploit, sudo privesc|**Easy**|
|**126**|CengBox: 2|Linux|Web enum, python sudo, privilege escalation|**Medium**|
|**127**|CengBox: 3|Linux|Multi-stage, kernel CVE, network pivot|**Hard**|
|**128**|Hackfest2016: Sedna|Linux|Brainpan-style BOF, restricted shell escape|**Hard**|
|**129**|Hackfest2016: Quaoar|Linux|WordPress, SMB, password spray|**Easy**|
|**130**|Hackfest2016: Orcus|Linux|SQLi, LFI, log poisoning, privilege escalation|**Medium**|
|**131**|Kioprix: 2014 VMware|FreeBSD|FreeBSD kernel privesc, Apache misconfig, exploit db|**Medium**|
|**132**|CloakAndDagger|Linux|clang SUID, overlay FS, capabilities exploitation|**Hard**|
|**133**|Raven: 1|Linux|WordPress, PHPMailer RCE, MySQL creds, udf privesc|**Medium**|
|**134**|Raven: 2|Linux|WordPress, PHPMailer, MySQL UDF exploit root|**Medium**|
|**135**|Dawn: 1|Linux|SMB anonymous, FTP, cron script injection, pivesc|**Easy**|
|**136**|Dawn: 2|Linux|Sudo exploitation, SUID, kernel exploit chain|**Medium**|
|**137**|Dawn: 3|Linux|Docker escape, network pivot, kernel exploitation|**Hard**|
|**138**|Matrix: 1|Linux|Custom binary, Ctrl+U source, BOF|**Medium**|
|**139**|Matrix: 2|Linux|Multi-stage, reverse engineering, custom services|**Hard**|
|**140**|Matrix: 3|Linux|Complex multi-stage BOF exploitation|**Hard**|
|**141**|AI: Web: 1|Linux|AI-themed, SQLi, reverse shell, Docker escape|**Medium**|
|**142**|AI: Web: 2|Linux|SSRF, XML injection, docker breakout|**Hard**|
|**143**|Sleepy|Linux|Tomcat, Zookeeper, Hadoop YARN RCE, privesc|**Hard**|
|**144**|CyberSploit: 1|Linux|GitHub leaked info, ROT, kernel exploit|**Easy**|
|**145**|CyberSploit: 2|Linux|Docker container, CMS exploit, sudo chain|**Medium**|
|**146**|CyberSploit: 3|Linux|Multi-stage exploit chain, kernel 0-day sim|**Hard**|
|**147**|RootThis: 1|Linux|PHP webapp LFI, cron, password in history file|**Easy**|
|**148**|BrainFuck|Linux|WPA cracking sim, custom binary RE|**Hard**|
|**149**|Serenity|Linux|Tomcat deploy, SUID bash, custom script|**Medium**|
|**150**|Laziness|Linux|PHP file upload, SUID find, sudo privesc|**Easy**|
|**151**|Healthcare: 1|Linux|OpenEMR SQLi, Metasploit, privilege escalation|**Medium**|
|**152**|ReconwithMe|Linux|FTP, SMB, HTTP enum, sudo privesc chain|**Easy**|
|**153**|Alfa|Linux|WordPress credential reuse, command injection|**Easy**|
|**154**|Whitebox|Linux|Source code review, race condition exploit|**Hard**|
|**155**|DarkHole: 1|Linux|File upload, password reuse, SUID bash|**Easy**|
|**156**|DarkHole: 2|Linux|GitFoundation, SQL time-based blind, ssh agent|**Medium**|
|**157**|Sunset: Dusk|Linux|Custom CMS SQLi, credential reuse, sudo abuse|**Medium**|
|**158**|Gravity|Linux|LFI, sudo env privesc, binary analysis|**Medium**|
|**159**|Fawkes|Linux|Stack BOF, ret2plt, ASLR bypass, ROP|**Hard**|
|**160**|Nully Cybersecurity|Linux|Multi-machine pivot, FTP, SMTP, WordPress|**Hard**|
|**161**|Tempus Fugit|Linux|Complex multi-stage network pentest|**Hard**|
|**162**|Mercy|Linux|Knockd port knocking, Samba, Tomcat, SUID|**Hard**|
|**163**|Prime: 1|Linux|WordPress, LFI, Diffie-Hellman, sudo privesc|**Medium**|
|**164**|Pylington|Linux|Python CGI RCE, restricted shell jail escape|**Medium**|
|**165**|PwnOS: 2.0|Linux|WordPress, SimplePress plugin, sudo all|**Easy**|
|**166**|SoberSecTF: 1|Linux|Web CTF, hidden dirs, SSH key, sudo|**Easy**|
|**167**|Morpheus: 1|Linux|Multi-stage, PHP injection, reverse shell|**Medium**|
|**168**|Ew_Skuzzy|Linux|NFS, SNMP, sticky bit abuse|**Medium**|
|**169**|Monitoring|Linux|Nagios RCE, sudo exploitation chain|**Medium**|
|**170**|EVM: 1|Linux|WordPress, SMB, sudo tee privesc|**Easy**|
|**171**|HackDay Albania|Linux|Multi-stage, web + binary exploitation|**Medium**|
|**172**|Pebbles|Linux|SeedDMS SQLi, file upload, docker escape|**Medium**|
|**173**|DevGuru: 1|Linux|Gitea, October CMS, Gitea post hooks RCE|**Hard**|
|**174**|Shuriken: 1|Linux|NodeBB, SSRF, LFI, command injection|**Hard**|
|**175**|Shuriken: Node|Linux|NodeJS deserialization, prototype pollution|**Hard**|
|**176**|Katana|Linux|Multi-stage, Apache, Python sudo, file perms|**Medium**|
|**177**|Hogwarts: Bellatrix|Linux|HP-themed, LFI, privesc via capabilities|**Easy**|
|**178**|Hogwarts: Dumbledore|Linux|SSH, binary RE, custom privesc chain|**Medium**|
|**179**|Hogwarts: Dobby|Linux|Docker, NFS, kernel exploit sim|**Hard**|
|**180**|XDXD: 1|Linux|Custom web, bypass filters, shell injection|**Medium**|
|**181**|Funbox: 1|Linux|FTP, WordPress, zip SUID privesc|**Easy**|
|**182**|Funbox: 2|Linux|Restricted bash (rbash) escape, command injection|**Easy**|
|**183**|Funbox: 3|Linux|Cron, SMB, password cracking, sudo chain|**Easy**|
|**184**|Funbox: 4|Linux|Web enum, PHP upload, env PATH hijack|**Medium**|
|**185**|Funbox: 5|Linux|Multi-stage Docker + SSH pivoting|**Medium**|
|**186**|Funbox: 6|Linux|Kernel exploit, binary analysis, advanced privesc|**Hard**|
|**187**|Funbox: 7|Linux|Complete network pentest simulation|**Hard**|
|**188**|Funbox: Easy|Linux|FTP anonymous, WordPress, rbash, nano privesc|**Easy**|
|**189**|Funbox: TryHarder|Linux|Multi-stage enumeration, password spray|**Medium**|
|**190**|Funbox: Scriptkiddie|Linux|Script injection, SMB, cron job abuse|**Easy**|
|**191**|Funbox: GaoKao|Linux|Advanced binary exploitation, heap overflow|**Hard**|
|**192**|Funbox: Lunchbreaker|Linux|Quick web CTF, SQLi, sudo privesc|**Easy**|
|**193**|Pluck|Linux|Pluck CMS RCE, tar SUID, capabilities|**Easy**|
|**194**|Bluemoon: 2021|Linux|Web enum, SUID binary RE, kernel exploit|**Medium**|
|**195**|Insomnia|Linux|Node.js JWT bypass, SSRF, sudo node|**Medium**|
|**196**|Sumo|Linux|Shellshock, Dirty Cow kernel privesc|**Easy**|
|**197**|Connect-The-Dots|Linux|Stego, binary analysis, kernel ROP|**Hard**|
|**198**|OSCP: 1|Linux|OSCP style, BOF, multi-service|**Hard**|
|**199**|Tre: 1|Linux|Mantis BT SQLi, Adminer RCE, sudo chmod|**Medium**|
|**200**|Relevant|Windows|SMB exploit, PrintSpoofer, token impersonation|**Medium**|

## TIER 3 — ADVANCED (Machines #201–250)

Advanced VulnHub machines involve exploit development, kernel exploits, multi-machine networks, or complex binary exploitation. Expect to spend significantly more time per machine.

|**#**|**Machine Name**|**OS**|**Skills / Focus Areas**|**Difficulty**|
|---|---|---|---|---|
|**201**|VulnNet: 1|Linux|SSRF, NFS, cron priv esc, lateral movement|**Medium**|
|**202**|VulnNet: Internal|Linux|Redis SSRF, NFS shares, Docker privesc|**Medium**|
|**203**|VulnNet: Node|Linux|NodeJS deserialization, npm SUID|**Easy**|
|**204**|VulnNet: Endgame|Linux|Multi-machine, redis, SMB, kernel pivot|**Hard**|
|**205**|VulnNet: Roasted|Windows|AD Kerberoasting, ASREProasting, DCSync|**Hard**|
|**206**|Persistence|Linux|Custom web, cron injection, docker escape|**Hard**|
|**207**|Gauntlet|Linux|Multi-stage, network pivoting, kernel 0-day|**Insane**|
|**208**|SolidState 2|Linux|James server RCE, Rsync, complex privesc|**Hard**|
|**209**|Seppuku|Linux|FTP, HTTPD, Stick note privesc, sudo chain|**Medium**|
|**210**|Wreath (standalone)|Windows|Multi-machine network, WinRM, Evil-WinRM|**Hard**|
|**211**|Empire: Breakout 2|Linux|Webmin, python capability, kernel exploit|**Hard**|
|**212**|Glasgowsmile|Linux|Joker-themed, SMB, zip cracking, sudo vim|**Easy**|
|**213**|NoName: 1|Linux|SQL injection, file upload, sudo awk|**Easy**|
|**214**|Darknet|Linux|Web PHP injection, Antak shell, kernel exploit|**Hard**|
|**215**|Aragog (HP)|Linux|WordPress SQLi, LXD group escape|**Medium**|
|**216**|DragonCTF|Linux|Complex CTF-style challenge, advanced exploitation|**Insane**|
|**217**|pWnOS: 1.0 v2|Linux|Perl CGI, Webmin, local privilege escalation|**Medium**|
|**218**|Ica: 1|Linux|ICA CMS, SQL injection, SUID privesc|**Easy**|
|**219**|Pinkys Palace v1 Redux|Linux|SQL injection, BOF, stack smashing protection bypass|**Hard**|
|**220**|Kioptrix Level 2 (4 update)|Linux|SQL injection, command injection, OS-level privesc|**Easy**|
|**221**|Rickdiculouslyeasy: 1|Linux|Rick & Morty themed, multi-service, steganography|**Easy**|
|**222**|Fristileaks 2|Linux|PHP web shell, sudo env, binary RE|**Medium**|
|**223**|Pandora's Box|Linux|Multi-stage, format string, ROP chain|**Hard**|
|**224**|Tophat: 1|Linux|Web CTF, PHP, password cracking, privesc|**Medium**|
|**225**|Prime: 2|Linux|Advanced SQLi, SSRF, Hashcat, kernel exploit|**Hard**|
|**226**|SkyDog: 1|Linux|Nmap CTF, web enum, binary analysis|**Medium**|
|**227**|GoldenEye: 2|Linux|Moodle, kernel exploit, multi-stage|**Hard**|
|**228**|Boredhackerblog|Linux|Custom web, JSON injection, kernel privilege escalation|**Hard**|
|**229**|TokyoWesterns CTF Offline|Linux|CTF binary exploitation, advanced heap|**Insane**|
|**230**|Crossroads: 1|Linux|Multi-hop pivot, tunneling, complex network|**Hard**|
|**231**|HackDay Quebec|Linux|Multi-stage boot2root with complex binary exploit|**Hard**|
|**232**|SecTalks: BNE0x03 - Simple|Linux|Simple Linux priv esc, web app misconfig|**Easy**|
|**233**|Jarbas: 1|Linux|Jenkins RCE, Cron injection, privilege escalation|**Easy**|
|**234**|The Ether: EvilScience|Linux|LFI log poison, command injection, wildcard sudo|**Medium**|
|**235**|Zico: 2|Linux|ZicoJWT LFI, exec RCE, zip priv chain|**Medium**|
|**236**|VulnVPN|Linux|OpenVPN configuration misconfig, client cert auth bypass|**Hard**|
|**237**|OpenBSD (misc)|OpenBSD|OpenBSD kernel privesc, setuid misuse|**Hard**|
|**238**|Bulldog: 1|Linux|Django web, reverse shell, sudo chain|**Easy**|
|**239**|Bulldog: 2|Linux|Django RCE, custom binary, kernel|**Medium**|
|**240**|Clamp|Linux|NFS, FTP, multi-stage, binary exploitation|**Hard**|
|**241**|TechSupport: 1|Linux|WordPress, irc, SMB, sudo privesc|**Easy**|
|**242**|Amaterasu: 1|Linux|REST API IDOR, file upload, SUID python|**Easy**|
|**243**|Containment|Linux|Docker container breakout, network pivot|**Hard**|
|**244**|Xtreme|Linux|Custom binary, heap exploitation, kernel ROP chain|**Insane**|
|**245**|Corrosion: 1|Linux|Tomcat, LFI, password spray, tar injection|**Medium**|
|**246**|Corrosion: 2|Linux|Tomcat WAR, crack .zip, docker, capabilities|**Hard**|
|**247**|Noob|Linux|Very basic web enum, sudo vim privesc|**Easy**|
|**248**|Alfa: 2|Linux|SSH, WordPress, kernel exploit chain|**Medium**|
|**249**|Badstore|Linux|SQL injection, command injection, password cracking|**Easy**|
|**250**|PWNAGOTCHI|Linux|Custom pwnagotchi app, BLE exploitation|**Insane**|

## TIER 4 — EXTENDED SERIES (Machines #251–300)

Extended VulnHub collection including CTF-style machines, recent CVE recreations, and OSCP-prep style boxes.

|**#**|**Machine Name**|**OS**|**Skills / Focus Areas**|**Difficulty**|
|---|---|---|---|---|
|**251**|Kioptrix 2014 Revisited|FreeBSD|FreeBSD userland exploit, web server chain|**Medium**|
|**252**|BoredHackerBlog: Social Network|Linux|Elasticsearch, Docker escape, network pivot|**Hard**|
|**253**|BoredHackerBlog: Cloud AV|Linux|HTTP API, command injection, docker escape|**Hard**|
|**254**|SecureCode: 1|Linux|PHP code review, RCE, privesc|**Medium**|
|**255**|SecureCode: 2|Linux|Advanced PHP, binary analysis, kernel|**Hard**|
|**256**|NullByte: 2|Linux|SQLi sequel, steganography, binary analysis|**Hard**|
|**257**|Sedna (Hackfest)|Linux|Buffer overflow, NX bypass, ROP chain|**Hard**|
|**258**|Plecost|Linux|Plecost WordPress scanner, RCE, privesc|**Easy**|
|**259**|PumpkinFestival|Linux|Pumpkin series finale, hardest stage|**Hard**|
|**260**|PumpkinGarden|Linux|Easy pumpkin, web, SSH key, privesc|**Easy**|
|**261**|PumpkinRaising|Linux|Medium pumpkin, Morse code, sudo|**Medium**|
|**262**|Typhoon|Linux|Multi-service, Heartbleed, Shellshock, Stego|**Hard**|
|**263**|VulnOS: 1|Linux|OpenDocMan, SQLi, kernel exploit|**Medium**|
|**264**|Kvasir|Linux|Norse themed, multi-stage, complex priv|**Hard**|
|**265**|Derpnstink|Linux|WordPress, FTP, MySQL creds, SUID binary|**Easy**|
|**266**|Fowsniff|Linux|Fowsniff, POP3, ssh exploit, motd script|**Easy**|
|**267**|GreenOptic|Linux|Optics company sim, web, SQLi, privesc|**Hard**|
|**268**|Blacklight|Linux|Blacklight CTF, binary analysis, ROP|**Hard**|
|**269**|Hack the Planet CTF|Linux|HtP CTF, multi-stage, complex binary|**Hard**|
|**270**|Tophat: 2|Linux|PHP RCE, password spray, docker escape|**Hard**|
|**271**|SoberSec CTF 1|Linux|Simple web CTF, sudo, privesc|**Easy**|
|**272**|Typhoon VM|Linux|Multiple vulnerability types, full lab|**Hard**|
|**273**|Kioptrix Level 3 v2|Linux|CMS LFI, SQL, SUID, PHP shell|**Easy**|
|**274**|PentesterLab: Web 1|Linux|Web security basics, SQLi, XSS|**Easy**|
|**275**|PentesterLab: PCAP|Linux|Packet capture analysis, credential recovery|**Easy**|
|**276**|PentesterLab: PlayVM|Linux|Exploit writing, buffer overflow basics|**Medium**|
|**277**|PentesterLab: CVE-2014-6271|Linux|Shellshock CVE exploitation|**Easy**|
|**278**|PentesterLab: S2-045|Linux|Apache Struts CVE, OGNL injection|**Medium**|
|**279**|Troll: 1|Linux|Trolling machine, misleading hints, exploit|**Easy**|
|**280**|Troll: 2|Linux|Hard trolling, binary RE, custom service|**Hard**|
|**281**|Wireless (OffSec style)|Linux|WPA cracking, WPS attack, post-exploit|**Medium**|
|**282**|Armageddon|Linux|Drupal RCE, snap privesc|**Easy**|
|**283**|Doctor|Linux|Werkzeug debug, SSTI, Splunk privesc|**Easy**|
|**284**|Ready|Linux|GitLab RCE, Docker escape|**Medium**|
|**285**|Knife|Linux|PHP 8.1 backdoor, knife sudo privesc|**Easy**|
|**286**|Explore|Android|Android ES File Manager, ADB exploitation|**Easy**|
|**287**|Pikaboo|Linux|Nginx location bypass, FTP LFI, Perl priv|**Hard**|
|**288**|Interface|Linux|Math API, metafile XSS, crontab exploit|**Medium**|
|**289**|Carpediem|Linux|Docker container pivot, MongoDB, privesc|**Hard**|
|**290**|Stocker|Linux|NoSQLi, SSRF to PDF LFI, sudo app|**Medium**|
|**291**|Soccer|Linux|Tiny File Manager, WebSocket SQLi, doas priv|**Easy**|
|**292**|Shoppy|Linux|Shopify-style, NoSQLi, Docker privesc|**Easy**|
|**293**|Precious|Linux|PDFKit CVE-2022-25765, rbenv sudo|**Easy**|
|**294**|Topology|Linux|LaTeX injection, gnuplot privesc|**Easy**|
|**295**|Analytics|Linux|Metabase RCE CVE-2023-38646, env var priv|**Easy**|
|**296**|Codify|Linux|vm2 sandbox escape, script comparison privesc|**Easy**|
|**297**|Headless|Linux|XSS cookie theft, blind XSS, cmd injection|**Easy**|
|**298**|Monitored|Linux|Nagios XI API, config file, privesc|**Medium**|
|**299**|Ouija|Linux|Node.js, PHP, X-Password filter bypass|**Hard**|
|**300**|Compiled|Windows|.NET, Git commit injection, VS Build privesc|**Hard**|

  

# 🟠 SECTION 2: HACKMYVM MACHINES

HackMyVM.eu provides community-created boot2root VMs. 300+ machines available, all free. Download OVA files and import into VirtualBox/VMware. No account required to download. Website: hackmyvm.eu

## HackMyVM — BEGINNER TO INTERMEDIATE (Machines #1–150)

HackMyVM community-created machines. Focus on diverse Linux exploitation techniques. Many machines are thematic and creative.

|**#**|**Machine Name**|**OS**|**Skills / Focus Areas**|**Difficulty**|
|---|---|---|---|---|
|**1**|Apaches|Linux|Apache misconfig, hidden dirs, SUID privesc|**Easy**|
|**2**|Animetronic|Linux|Web fuzzing, wordlist creation, SUID exploit|**Easy**|
|**3**|Atom|Linux|IPMI vulnerability, UDP enumeration, hash cracking|**Medium**|
|**4**|Ball|Linux|Web app, command injection, sudo binary|**Easy**|
|**5**|Banana|Linux|PHP RFI, SUID binary, password reuse|**Easy**|
|**6**|Canto|Linux|Nginx, PHP upload, env PATH abuse|**Easy**|
|**7**|Canto II|Linux|CMS exploit, sudo chain, Docker escape|**Medium**|
|**8**|Chill|Linux|Web enum, credentials file, sudo privesc|**Easy**|
|**9**|Comingsoon|Linux|Apache, command injection, kernel exploit|**Easy**|
|**10**|Connection|Linux|SSH user enum, brute force, sudo ALL|**Easy**|
|**11**|Crossbow|Linux|Multi-service, SMB, sudo chain|**Medium**|
|**12**|DC416 Basement|Linux|Multi-stage, binary analysis, kernel priv|**Medium**|
|**13**|Deathnote|Linux|Death Note themed, stego, binary RE|**Medium**|
|**14**|Decode|Linux|Base64, ROT13, crypto decode chain|**Easy**|
|**15**|Deity|Linux|PHP injection, LFI, custom priv chain|**Medium**|
|**16**|Dooku|Linux|Star Wars themed, web, binary exploitation|**Medium**|
|**17**|Download|Linux|FTP, wget script, cron injection|**Easy**|
|**18**|Eighteen|Linux|Web CTF, PHP shell, sudo privesc|**Easy**|
|**19**|Expression|Linux|Expression language injection, Java RCE|**Medium**|
|**20**|Eye|Linux|Eyewitness, screenshot recon, web pivoting|**Easy**|
|**21**|Flowers|Linux|PHP upload, SUID find privesc|**Easy**|
|**22**|Friendly|Linux|FTP anonymous, Samba, PHP RCE|**Easy**|
|**23**|Friendly2|Linux|WordPress, WPScan, SUID binary exploitation|**Easy**|
|**24**|Friendly3|Linux|Multi-stage, SSH tunneling, credential spray|**Medium**|
|**25**|Galaxy|Linux|Web CTF, hidden messages, SUID nano|**Easy**|
|**26**|Geometry|Linux|Math-themed CTF, binary exploitation, ROT|**Medium**|
|**27**|GoldenCage|Linux|Custom CMS, SQLi, container escape|**Hard**|
|**28**|Gorgon|Linux|Python web, SSTI, sudo python3|**Medium**|
|**29**|Greasy|Linux|SUID greasy binary, env PATH abuse|**Easy**|
|**30**|Hacking Station|Linux|CTF-style, binary RE, reverse engineering|**Medium**|
|**31**|Haiku|Linux|PHP, poetry, file upload bypass|**Easy**|
|**32**|Hardware|Linux|Hardware simulation, I2C, GPIO exploitation|**Hard**|
|**33**|Hellbound|Linux|Multi-stage, buffer overflow, heap exploit|**Hard**|
|**34**|Hundreds|Linux|Multiple vectors, 100 services sim|**Medium**|
|**35**|Hurney|Linux|Web fuzzing, SSH key extraction, sudo|**Easy**|
|**36**|Icecap|Linux|IPMI, NFS, passwd poisoning|**Medium**|
|**37**|Infinity|Linux|HA: Infinity Stones inspired, multi-vector|**Hard**|
|**38**|Infestation|Linux|Malware analysis, reverse engineering|**Hard**|
|**39**|Ingot|Linux|Ruby web app, SSTI, sudo gem|**Medium**|
|**40**|JO2024|Linux|Olympics themed, Apache, hidden paths, privesc|**Easy**|
|**41**|Joker|Linux|Joker themed, UDP, TFTP, Squid proxy bypass|**Hard**|
|**42**|Kaiju|Linux|Japanese CTF, multi-service, binary analysis|**Hard**|
|**43**|Kangaroo|Linux|PHP web app, SQLi, sudo binary|**Easy**|
|**44**|Kepler|Linux|Science themed, web, binary exploitation|**Medium**|
|**45**|Kingpin|Linux|Criminal themed, multi-stage pivoting|**Hard**|
|**46**|Klister|Linux|Custom service, rootkit detection evasion|**Insane**|
|**47**|Kraken|Linux|Multi-stage, tentacle network pivot|**Hard**|
|**48**|Labyrinth|Linux|PHP maze, LFI, command injection|**Medium**|
|**49**|Leet|Linux|CTF puns, binary exploitation, ROP chain|**Hard**|
|**50**|Light|Linux|Minimalist web, SSH, sudo privesc|**Easy**|
|**51**|Logger|Linux|Keylogger exploitation, credential theft|**Medium**|
|**52**|Logforge|Linux|Log4Shell simulation, Java deserialization|**Hard**|
|**53**|Lucky|Linux|Random number gen, PHP, SUID|**Easy**|
|**54**|Lusca|Linux|Laravel web, SSRF, env abuse|**Medium**|
|**55**|Mango|Linux|Web enum, JavaScript injection, privesc|**Easy**|
|**56**|Mechanic|Linux|Binary analysis, ret2libc, format string|**Hard**|
|**57**|Milk|Linux|PHP injection, cow privesc (Dirty Cow)|**Easy**|
|**58**|Mirror|Linux|Custom web, PHP reverse shell, SUID|**Easy**|
|**59**|Music|Linux|Orfeo NG, command injection, sudo find|**Medium**|
|**60**|Napping|Linux|Git hooks, cron execution, Python priv|**Medium**|
|**61**|Newcomer|Linux|Beginner box, web enum, SSH, sudo|**Easy**|
|**62**|Nineteen|Linux|Python web, SQLi, sudo python|**Easy**|
|**63**|NMap|Linux|Nmap sudo privesc classic|**Easy**|
|**64**|Oldschool|Linux|Retro services, Telnet, FTP, RCE|**Medium**|
|**65**|Orion|Linux|Space themed, Python, GTFOBins chain|**Medium**|
|**66**|Overflow|Linux|Buffer overflow, DEP/ASLR, shellcode|**Hard**|
|**67**|Pebble|Linux|Web admin panel, credential reuse|**Easy**|
|**68**|Piccolo|Linux|PHP web, SQL, SUID bash|**Easy**|
|**69**|Piranesi|Linux|Art-themed, web, file upload, privesc|**Medium**|
|**70**|Pivoting|Linux|Classic network pivot practice box|**Medium**|
|**71**|Pixy|Linux|PHP, SQLi, password crack, docker escape|**Medium**|
|**72**|Pluto|Linux|Space themed, web, binary exploitation|**Medium**|
|**73**|Potato|Linux|Web CTF, PHP injection, SUID|**Easy**|
|**74**|Pumpkin|Linux|Halloween themed, web enum, privesc|**Easy**|
|**75**|Quantum|Linux|Quantum-themed, binary RE, crypto|**Hard**|
|**76**|Quick3|Linux|Speed challenge, SQLi, sudo privesc|**Easy**|
|**77**|Rattle|Linux|Custom snake game, buffer overflow|**Medium**|
|**78**|Reality|Linux|Multi-stage, web + binary|**Hard**|
|**79**|Reaper|Linux|Reaper CTF, custom service exploit|**Hard**|
|**80**|Redcross|Linux|Multi-machine, network pivot, RCE|**Hard**|
|**81**|Relax|Linux|Easy web, file disclosure, sudo binary|**Easy**|
|**82**|Retro|Linux|Retro gaming, web, reverse shell|**Medium**|
|**83**|Revenge|Linux|Exploit revenge chain, re-use credentials|**Medium**|
|**84**|Ring|Linux|Ring themed CTF, binary analysis|**Hard**|
|**85**|Robot|Linux|Robot themed, multi-service|**Medium**|
|**86**|Rookie|Linux|Absolute beginner, web, sudo privesc|**Easy**|
|**87**|Rpg|Linux|RPG game themed, PHP, SQL|**Medium**|
|**88**|Run|Linux|Gitea RCE, port forwarding, privesc|**Medium**|
|**89**|Sauna|Windows|AD enumeration, Kerberoasting, DCSync|**Hard**|
|**90**|Secret|Linux|API token, JWT manipulation, RCE|**Medium**|
|**91**|Seventeen|Linux|Web CTF, file inclusion, binary priv|**Medium**|
|**92**|Shell|Linux|Shellshock, custom service, privesc|**Medium**|
|**93**|Sixteen|Linux|PHP injection, binary RE, sudo chain|**Medium**|
|**94**|Skar|Linux|Scar-themed CTF, multi-stage|**Medium**|
|**95**|Sky|Linux|Multi-service, network scan, binary analysis|**Medium**|
|**96**|Slide|Linux|Slides themed, LFI, PHP, privesc|**Easy**|
|**97**|Slip|Linux|PHP, file upload, pivot|**Medium**|
|**98**|Small|Linux|Minimal attack surface, web + SUID|**Easy**|
|**99**|Smol|Linux|Very beginner friendly, web, sudo|**Easy**|
|**100**|Sokar|Linux|Advanced multi-stage CTF, kernel level|**Insane**|
|**101**|Some|Linux|Random service enum, credentials, privesc|**Easy**|
|**102**|Sorrow|Linux|Shellshock, custom web, priv chain|**Medium**|
|**103**|Speed|Linux|Fast CTF, web enum, sudo|**Easy**|
|**104**|Spider|Linux|Web crawl, hidden files, SSH privesc|**Easy**|
|**105**|Spring|Linux|Spring Boot, SSRF, Actuator RCE|**Hard**|
|**106**|Ssa|Linux|SSA themed, multi-vector|**Medium**|
|**107**|Status|Linux|HTTP status exploitation, web misconfig|**Easy**|
|**108**|Stocker|Linux|NoSQL injection, SSRF PDF, privesc|**Medium**|
|**109**|Strapi|Linux|Strapi CMS RCE, node privesc|**Medium**|
|**110**|Taco|Linux|Food themed, SQLi, PHP, SUID|**Easy**|
|**111**|Teacher|Linux|Moodle RCE, MySQL creds, cron privesc|**Medium**|
|**112**|Think|Linux|Logic puzzles, custom binary RE|**Hard**|
|**113**|Tiny|Linux|Minimal footprint, web, binary|**Easy**|
|**114**|Toc|Linux|TokyoCabinet DB, config file, privesc|**Medium**|
|**115**|Tools|Linux|Security tools exploitation, sudo chain|**Medium**|
|**116**|Trender|Linux|WordPress, XSS, cookie stealing, privesc|**Medium**|
|**117**|Trick|Linux|DNS enum, SSRF, LFI, privesc|**Medium**|
|**118**|Trusted|Linux|Trust exploitation, web, NFS, priv esc|**Medium**|
|**119**|Twill|Linux|Twill testing framework, RCE, privesc|**Medium**|
|**120**|Twitbook|Linux|Social network app, IDOR, XSS, privesc|**Medium**|
|**121**|Typo|Linux|CMS typo, PHP injection, sudo privesc|**Easy**|
|**122**|Unbalanced|Linux|EncFS, Squid proxy, Pi-hole, Rsync|**Hard**|
|**123**|Union|Linux|SQLi, filter bypass, file write, SUID|**Medium**|
|**124**|Upgrade|Linux|Upgrade shell techniques, restricted jail escape|**Medium**|
|**125**|Upload|Linux|File upload bypass, MIME tricks, priv esc|**Easy**|
|**126**|Vanguard|Linux|Multi-stage network pentest lab|**Hard**|
|**127**|Veteran|Linux|Complex priv chain, advanced binary|**Hard**|
|**128**|Vigor|Linux|Apache, PHP, sudo chain, kernel bypass|**Medium**|
|**129**|Viper|Linux|Python viper framework, RCE, privesc|**Medium**|
|**130**|Void|Linux|Empty-looking, hidden services, binary exploitation|**Hard**|
|**131**|Voyage|Linux|Travel themed, PHP, SQLi, SUID|**Easy**|
|**132**|Vulnerable|Linux|Multi-vector lab, OWASP style|**Easy**|
|**133**|Waffle|Linux|Waffle app, SQLi, LFI, command injection|**Medium**|
|**134**|Walkthroo|Linux|Tutorial box, step by step exploitation|**Easy**|
|**135**|Warzone|Linux|War-themed, multi-stage, binary RE|**Hard**|
|**136**|Web|Linux|Web application hacking, various web vulns|**Easy**|
|**137**|Wee|Linux|Minimal box, quick exploitation chain|**Easy**|
|**138**|Wicca|Linux|Magic themed, custom binary, privesc|**Medium**|
|**139**|Wifi|Linux|Wireless security simulation, WPA cracking|**Hard**|
|**140**|Wilderness|Linux|Multi-stage, outdoors themed, binary|**Medium**|
|**141**|Wilson|Linux|Custom web app, injection, sudo privesc|**Easy**|
|**142**|Win|Linux|Winning CTF chain, web + binary|**Medium**|
|**143**|Winter|Linux|Cold themed, PHP, cron, kernel|**Medium**|
|**144**|Witch|Linux|Halloween themed, LFI, RCE, privesc|**Easy**|
|**145**|Wizard|Linux|Magic app, SSTI, sudo chain|**Medium**|
|**146**|Wolf|Linux|Apache, PHP, sudo wolf binary|**Medium**|
|**147**|Wonder|Linux|Themed CTF, web + binary exploitation|**Medium**|
|**148**|Wonderful|Linux|Full chain web + binary + kernel|**Hard**|
|**149**|Wordy|Linux|WordPress themed, WPScan, privesc|**Easy**|
|**150**|Xpositor|Linux|Exposed services, credential reuse, privesc|**Medium**|

## HackMyVM — INTERMEDIATE TO ADVANCED (Machines #151–200)

Advanced HackMyVM machines including Windows AD boxes, hardcore binary exploitation, and multi-machine networks.

|**#**|**Machine Name**|**OS**|**Skills / Focus Areas**|**Difficulty**|
|---|---|---|---|---|
|**151**|Warzone2|Linux|War zone sequel, advanced exploitation|**Hard**|
|**152**|Wayfarer|Linux|Travel themed, complex multi-stage|**Hard**|
|**153**|Weakbox|Linux|Multiple weak points, beginner practice|**Easy**|
|**154**|Website|Linux|Simple web, file upload, SUID|**Easy**|
|**155**|Whynotsecurity|Linux|Why not security? multi-vector lab|**Easy**|
|**156**|Wificap|Linux|WiFi capture analysis, WPA cracking|**Hard**|
|**157**|Wild|Linux|Wild west themed, multi-stage|**Medium**|
|**158**|Windmill|Linux|Windmill themed, network enum, priv|**Medium**|
|**159**|Worder|Linux|WordPress themed, WPScan, priv|**Easy**|
|**160**|Xposed|Linux|Exposed services, credential spray|**Easy**|
|**161**|Yearbook|Linux|School yearbook, web, SQLi, SUID|**Easy**|
|**162**|Zday|Linux|Zero day simulation, complex exploit|**Hard**|
|**163**|Zeug|Linux|German themed, binary RE, kernel|**Insane**|
|**164**|Zerba|Linux|Zebra themed, web enum, priv|**Easy**|
|**165**|Zimba|Linux|Zimbra email, CVE exploitation|**Hard**|
|**166**|Zino|Linux|Zino themed, web, SQL, privesc|**Easy**|
|**167**|Zombie|Linux|Zombie process, SUID, privesc|**Easy**|
|**168**|Zoom|Linux|Zoom themed, web, binary exploitation|**Medium**|
|**169**|Zulu|Linux|Zulu themed, multi-vector pentest|**Medium**|
|**170**|Zundert|Linux|Zundert CTF, complex multi-stage|**Hard**|
|**171**|Aero|Windows|Driver exploitation, kernel vuln, privesc|**Insane**|
|**172**|Analytics|Linux|Metabase CVE, env var privesc|**Easy**|
|**173**|Ariadne|Linux|Mythological themed, web, binary RE|**Hard**|
|**174**|Armour|Linux|Heavy armor, advanced multi-stage|**Hard**|
|**175**|Art|Linux|Art themed, web, injection, privesc|**Easy**|
|**176**|Astat|Linux|Statistics web app, SQLi, privesc|**Easy**|
|**177**|Astro|Linux|Astronomy themed, binary, kernel|**Hard**|
|**178**|Ato|Linux|Japanese themed, web enum, SUID|**Easy**|
|**179**|Atlas|Linux|Atlas holding the world, multi-vector|**Hard**|
|**180**|Aum|Linux|AUM themed, web, binary, kernel|**Hard**|
|**181**|Aux|Linux|Auxiliary channels, side-channel attack|**Hard**|
|**182**|Ava|Linux|Ava themed, web, LFI, privesc|**Easy**|
|**183**|Avengers|Linux|Marvel themed, multi-service, privesc|**Medium**|
|**184**|Avocado|Linux|Food themed, simple web, privesc|**Easy**|
|**185**|Axe|Linux|Axe themed, web, binary exploitation|**Medium**|
|**186**|Aztec|Linux|Aztec themed, multi-stage, crypto|**Hard**|
|**187**|Babosco|Linux|Baby themed, absolute beginner|**Very Easy**|
|**188**|Backtrack|Linux|Backtrack OS sim, retro, multi-vector|**Medium**|
|**189**|Bahia|Linux|Brazilian themed, web, injection|**Easy**|
|**190**|Balidari|Linux|Indonesian themed, web, privesc|**Easy**|
|**191**|Ballistic|Linux|Ballistics sim, binary, ROP chain|**Hard**|
|**192**|Bamboo|Linux|Nature themed, web, SUID chain|**Easy**|
|**193**|Banana2|Linux|Banana sequel, harder privesc|**Medium**|
|**194**|Bandit-style|Linux|Bandit inspired, web, SSH brute|**Easy**|
|**195**|Barby|Linux|Barby themed, web, injection, priv|**Easy**|
|**196**|Baron|Linux|Baron themed, web, binary RE|**Medium**|
|**197**|Bash|Linux|Bash scripting exploitation, eval injection|**Medium**|
|**198**|Bat|Linux|Bat (Windows) style, web, binary|**Hard**|
|**199**|Batcat|Linux|Cat-bat hybrid, web, SUID chain|**Easy**|
|**200**|Beekeeper|Linux|Bee themed, web, PHP, privesc|**Easy**|

  

# 🔵 SECTION 3: VULNYX MACHINES

VulNyx is a free cybersecurity training platform launched in 2023 by d4t4s3c. Features 150+ intentionally vulnerable VMs for ethical hackers. Machines are Unix-based (mostly Linux, some Windows). Download OVA format for VirtualBox. Website: vulnyx.com

VulNyx specializes in skill-specific machines — each box often targets one or two specific vulnerability classes, making it perfect for focused practice. Excellent for OSCP, eJPT, eWPT preparation.

## VULNYX — ALL MACHINES (#1–166)

VulNyx machines are categorized by the specific exploitation skill tested. Perfect for targeted skill building.

|**#**|**Machine Name**|**OS**|**Skills / Focus Areas**|**Difficulty**|
|---|---|---|---|---|
|1|Ready|Linux|SSH enum, web recon, basic privesc|Easy|
|2|Hat|Linux|Web exploitation, credential reuse, sudo|Easy|
|3|Serve|Linux|Service enumeration, file permissions, privesc|Easy|
|4|Brain|Linux|Web app, SUID binary, privilege escalation|Easy|
|5|Responder|Linux|SMB/NTLMv2 capture, responder, hash crack|Easy|
|6|Wrapp|Linux|Wrapper scripts, PATH hijack, privesc|Easy|
|7|Doctor|Linux|SSTI, Flask, template injection, privesc|Easy|
|8|Secrets|Linux|Hidden credentials, file enumeration, privesc|Easy|
|9|Fing|Linux|Fingerprinting, web recon, privilege escalation|Easy|
|10|Blog|Linux|CMS exploitation, web shell, privesc|Easy|
|11|Backdoor|Linux|Backdoor detection, network analysis, privesc|Easy|
|12|Tom|Linux|Tomcat-style service, default creds, privesc|Easy|
|13|Shock|Linux|Shellshock CVE, bash exploitation, root|Medium|
|14|Developer|Linux|Dev tools exposed, code review, privesc|Easy|
|15|Hidden|Linux|Hidden services, directory traversal, privesc|Easy|
|16|Real|Linux|Real-world CVE sim, web exploitation, privesc|Easy|
|17|Ceres|Linux|Service enum, weak creds, priv chain|Easy|
|18|Printer|Linux|CUPS/printing service exploit, privesc|Medium|
|19|Zero|Linux|Zero-day simulation, web app, escalation|Medium|
|20|Zone|Linux|DNS zone transfer, recon, privesc|Easy|
|21|Internal|Linux|Internal network simulation, pivoting, privesc|Medium|
|22|Deploy|Linux|CI/CD exploitation, credentials, privesc|Easy|
|23|Mail|Linux|Email service exploitation, IMAP, privesc|Easy|
|24|External|Linux|External recon, web app, privilege escalation|Easy|
|25|Node|Linux|Node.js exploitation, deserialization, privesc|Medium|
|26|Key|Linux|SSH key management, weak keys, privesc|Easy|
|27|Noob|Linux|Beginner-friendly, basic web, simple privesc|Low|
|28|Transfer|Linux|File transfer services, FTP/SCP abuse, privesc|Easy|
|29|Bund|Linux|Bundling/packaging vulns, code execution|Medium|
|30|Encode|Linux|Encoding bypass, web filter evasion, privesc|Easy|
|31|Flash|Linux|Fast exploitation chain, web app, privesc|Easy|
|32|Listen|Linux|Open ports, service enum, privesc|Easy|
|33|Trace|Linux|Process tracing, ptrace, SUID privesc|Medium|
|34|Look|Linux|File read abuse, SUID look binary, privesc|Easy|
|35|Chain|Linux|Chained vulnerabilities, multi-step privesc|Medium|
|36|Shop|Linux|E-commerce app, SQL injection, privesc|Easy|
|37|Discover|Linux|Service discovery, hidden endpoints, privesc|Easy|
|38|Belial|Linux|Daemon exploitation, service misconfig, root|Medium|
|39|Jenk|Linux|Jenkins exploitation, Groovy script, privesc|Medium|
|40|Beginner|Linux|Introductory box, basic recon, simple priv|Low|
|41|Share|Linux|SMB/NFS shares, credential exposure, privesc|Easy|
|42|Dark|Linux|Dark web-themed, Tor-style service, privesc|Medium|
|43|Plot|Linux|Script injection, cron jobs, privesc|Easy|
|44|Cap|Linux|Linux capabilities abuse, privesc|Easy|
|45|Remote|Linux|RCE via remote service, exploit chain|Medium|
|46|Goetia|Linux|Advanced web exploitation, privesc chain|Medium|
|47|Slash|Linux|Path traversal, directory traversal, privesc|Medium|
|48|Travel|Linux|FTP/web combo, credential reuse, privesc|Easy|
|49|Annunciation|Linux|Web app vulnerability, info disclosure, priv|Easy|
|50|Play|Linux|Playful CTF-style, web app, privilege escalation|Easy|
|51|Baal|Linux|Advanced service exploitation, root escalation|Hard|
|52|Wicca|Linux|PHP web app, file inclusion, privilege escalation|Medium|
|53|Fire|Linux|Web exploitation, command injection, sudo abuse|Medium|
|54|Robot|Linux|Robots.txt recon, web app, SUID escalation|Easy|
|55|Access|Linux|Access control bypass, web exploitation, privesc|Easy|
|56|Basic|Linux|Fundamental web skills, basic privesc chain|Low|
|57|Monitor|Linux|Monitoring service exploitation, RCE, root|Easy|
|58|First|Linux|First machine on platform, basics, web+SSH|Low|
|59|Air|Linux|Lightweight service, web enum, privesc|Easy|
|60|Bind|Linux|DNS BIND exploitation, zone data, privesc|Easy|
|61|Code|Linux|Source code review, RCE, privilege escalation|Easy|
|62|Unit|Linux|Systemd unit files, service exploit, privesc|Medium|
|63|Raw|Linux|Raw socket/binary exploitation, privesc|Hard|
|64|Mux|Linux|Multiplexer abuse, tmux/screen, privesc|Hard|
|65|Infected|Linux|Malware analysis-themed, rootkit detection|Medium|
|66|Agent|Linux|Agent/C2 simulation, cron exploitation, privesc|Medium|
|67|Hunter|Linux|Hunting hidden services, web, privesc|Medium|
|68|Load|Linux|Load balancer bypass, web exploitation, privesc|Hard|
|69|Cache|Linux|Cache poisoning, web cache exploit, privesc|Easy|
|70|Experience|Windows|Windows service enum, credential abuse, privesc|Hard|
|71|Shared|Linux|Shared memory exploitation, privesc chain|Medium|
|72|Eternal|Windows|EternalBlue SMB exploit simulation, privesc|Hard|
|73|Druid|Linux|Custom CMS exploitation, web shell, privesc|Medium|
|74|Dump|Linux|Memory dump analysis, credential extraction, root|Medium|
|75|Gen|Linux|Code generation, template injection, SUID|Easy|
|76|Friends|Linux|Multi-user pivoting, lateral movement, root|Medium|
|77|Lost|Linux|Hidden services, binary RE, privilege escalation|Medium|
|78|Leak|Linux|Data leak, credentials exposure, privesc|Medium|
|79|Plex|Linux|Plex Media Server exploit, RCE, root|Hard|
|80|Jerry|Linux|Tomcat manager, WAR file deploy, privesc|Easy|
|81|Future|Linux|Future-themed, advanced web, privesc chain|Medium|
|82|HackingStation|Linux|Multi-service hacking lab, full chain|Hard|
|83|Diff3r3ntS3c|Linux|Unique security challenges, multi-vector exploit|Hard|
|84|Sun|Linux|Web exploitation, RCE, privilege escalation|Medium|
|85|Exec|Linux|Command injection, filter bypass, SUID binary|Medium|
|86|Hook|Linux|Function hooking, binary exploitation, root|Hard|
|87|System|Linux|System call abuse, kernel-level privesc|Medium|
|88|Gattaca|Linux|Bioinformatics-themed, file analysis, privesc|Easy|
|89|Arpon|Linux|ARP poisoning themed, network attack, privesc|Medium|
|90|Twitx|Linux|Social media API exploitation, OAuth bypass|Medium|
|91|Service|Linux|Service misconfig, systemd exploit, root|Medium|
|92|YourWAF|Linux|WAF bypass, web exploitation, privesc|Medium|
|93|Yincana|Linux|CTF-style puzzles, chained exploits, root|Medium|
|94|Bunker|Linux|Hardened system bypass, escape techniques|Hard|
|95|MyWAF|Linux|Custom WAF bypass, web app, privilege escalation|Medium|
|96|Admin|Windows|Windows AD admin privesc, domain enumeration|Hard|
|97|Send|Linux|File send service exploit, code exec, privesc|Medium|
|98|Call|Linux|RPC call exploitation, service abuse, root|Medium|
|99|JarJar|Linux|Java JAR exploitation, deserialization, root|Medium|
|100|Lang|Linux|Language interpreter abuse, script exec, privesc|Hard|
|101|Hosting|Windows|Web hosting panel exploit, RCE, privesc|Hard|
|102|Spooisong|Linux|Spoofing-based attack, DNS/ARP, privesc|Easy|
|103|Psymin|Linux|Psychological-themed, multi-vector, root|Medium|
|104|Solar|Linux|SolarWinds-style recon, web exploit, root|Medium|
|105|Express|Linux|Express.js web app, prototype pollution, root|Medium|
|106|Controler|Windows|Windows controller service, privesc chain|Hard|
|107|Fuser|Linux|fuser command abuse, process kill, root|Hard|
|108|Manager|Linux|Service manager exploitation, config abuse|Easy|
|109|War|Windows|Windows Active Directory, Kerberoasting, root|Hard|
|110|Tunnel|Linux|SSH tunneling, port forwarding, privesc|Easy|
|111|Lower|Linux|Privilege lowering exploit, escalation back to root|Hard|
|112|Blogger|Linux|WordPress/blog exploitation, plugin RCE, root|Medium|
|113|Magic|Linux|Magic bytes file upload bypass, RCE, root|Medium|
|114|Swamp|Linux|Murky web exploitation, chained vulnerabilities|Medium|
|115|APex|Linux|Advanced exploitation, multi-step privesc|Medium|
|116|Matrix|Linux|Matrix-themed, complex chaining, root|Medium|
|117|Hit|Linux|Direct exploitation path, web app, root|Medium|
|118|Anon|Linux|Anonymous access abuse, FTP, web, privesc|Medium|
|119|Bola|Linux|BOLA/IDOR vulnerability, API exploit, root|Medium|
|120|Lower2|Linux|Level 2 privilege series, escalation challenge|Hard|
|121|Change|Windows|Windows AD password change, privesc chain|Hard|
|122|Lower3|Linux|Level 3 privilege series, complex root path|Hard|
|123|Zerotrace|Linux|Evasion techniques, traceless exploitation|Hard|
|124|Lower4|Linux|Level 4 privilege series, kernel-adjacent|Hard|
|125|Loweb|Linux|Web-specific privilege lowering challenge|Hard|
|126|Sandwich|Linux|Layered exploitation, multi-service attack|Hard|
|127|Lower5|Linux|Level 5 privilege series, advanced techniques|Hard|
|128|Ober|Linux|Obfuscated service, reverse engineering, root|Medium|
|129|Carlam|Linux|Custom application exploitation, root|Medium|
|130|Denied|Linux|Access denied bypass, web app, privesc|Medium|
|131|Lower6|Linux|Level 6 privilege series, near-kernel privesc|Hard|
|132|Build|Windows|Build server exploitation, CI/CD, AD privesc|Hard|
|133|Sales|Linux|CRM/sales app exploit, SQL injection, root|Medium|
|134|LostTape|Linux|Forensics-themed, data recovery, privesc|Medium|
|135|Observer|Linux|Monitoring tool abuse, log poisoning, root|Medium|
|136|EID|Linux|Electronic ID/smart card themed, crypto, root|Medium|
|137|Init|Linux|Init system (SysV/systemd) exploitation, root|Medium|
|138|Absolute|Linux|Comprehensive exploitation challenge, root|Medium|
|139|ExposedDev|Linux|Exposed dev environment, secrets, root|Medium|
|140|SlyWindow|Linux|Stealthy exploitation, evasion, root|Medium|
|141|Yadis|Linux|Identity discovery service exploit, privesc|Medium|
|142|Chimera|Linux|Multi-faceted attack surface, chained exploits|Medium|
|143|Open|Linux|Open services, default creds, privesc|Easy|
|144|Misstep|Linux|Configuration mistake exploitation, root|Medium|
|145|Static|Linux|Static site exploitation, SSTI, root|Medium|
|146|Explorer|Linux|File system exploration, hidden data, root|Medium|
|147|Reset|Linux|Password reset vulnerability, account takeover|Medium|
|148|Mirage|Linux|Illusion/deception-themed, hidden attack path|Easy|
|149|Care|Linux|Health-themed, web app exploitation, privesc|Medium|
|150|Misconfigured|Windows|Windows misconfiguration, privesc chain|Medium|
|151|Store|Windows|Windows store/shop app, AD exploitation|Medium|
|152|Lower7|Linux|Level 7 privilege series, final challenge|Hard|
|153|Debug|Linux|Debug mode exploitation, code execution, root|Medium|
|154|Memory|Linux|Memory corruption, heap/stack exploit, root|Hard|
|155|Coliseum|Linux|Arena-style multiple vulnerabilities, root|Medium|
|156|Alpine|Linux|Alpine Linux container escape, privesc|Medium|
|157|MailForge|Linux|Mail server exploitation, RCE, root|Medium|
|158|TheDoor|Linux|Hidden door/backdoor discovery, exploitation|Medium|
|159|Headache|Linux|Painful multi-step exploitation chain, root|Easy|
|160|SRV|Windows|Windows server services, privesc to admin|Medium|
|161|School|Windows|Windows AD school environment, full chain|Easy|
|162|Blind|Linux|Blind SQL injection, time-based, root|Medium|
|163|Hellman|Linux|Diffie-Hellman crypto, key exchange attack|Easy|
|164|Policy|Windows|Windows Group Policy exploitation, privesc|Hard|
|165|Northwing|Linux|Advanced lateral movement, pivoting, root|Easy|
|166|University|Linux|Academic-themed, full exploitation chain, root|Easy|

  

# 🟢 SECTION 4: DOCKERLABS MACHINES

DockerLabs is a free platform created by El Pingüino de Mario (Mario). All machines run as Docker containers — lightweight, fast, and beginner-friendly. No virtualization overhead. Simply download, unzip, and run. Website: dockerlabs.es

DockerLabs is PERFECT for beginners with limited RAM/CPU. Each machine starts in seconds and requires minimal setup. Ideal for quick daily practice sessions.

### Quick Setup

1. Install Docker   
2.  Download machine.zip from dockerlabs.es  
3.  Unzip   
4. Run: bash deploy.sh machine.tar   
5.  Hack the container!   
6.  Run: bash destroy.sh to clean up

## DOCKERLABS — ALL MACHINES (#1–54)

DockerLabs machines range from 'Very Easy' (absolute beginner) to 'Hard'. Great first machines for CTF newcomers.

|**#**|**Machine Name**|**OS**|**Skills / Focus Areas**|**Difficulty**|
|---|---|---|---|---|
|1|Trust|Linux|Hydra SSH brute force, vim sudo GTFOBins privesc|Very Easy|
|2|Upload|Linux|PHP file upload bypass, web shell, SUID privesc|Very Easy|
|3|WalkingCMS|Linux|WordPress exploitation, plugin RCE, sudo abuse|Very Easy|
|4|Vacaciones|Linux|Web enum, SSH brute force, basic privesc|Very Easy|
|5|Injection|Linux|SQL injection, MySQL credential dump, privesc|Very Easy|
|6|BreakMySSH|Linux|SSH brute force, authorized_keys manipulation|Very Easy|
|7|BuscaLove|Linux|Web fuzzing, LFI, credential abuse, root|Easy|
|8|Amor|Linux|Web recon, user enumeration, privesc chain|Very Easy|
|9|BorazuwarahCTF|Linux|Steganography, SSH brute force, sudo GTFOBins|Very Easy|
|10|Pinguinazo|Linux|SSTI, Jinja2 template injection, escalation|Easy|
|11|AguaDeMayo|Linux|Web app, hidden creds, sudo privesc|Very Easy|
|12|Picadilly|Linux|File upload RCE, web shell, privilege escalation|Very Easy|
|13|NodeClimb|Linux|FTP anon login, ZIP cracking, Node.js sudo privesc|Easy|
|14|Move|Linux|Web recon, default creds, move binary sudo abuse|Very Easy|
|15|Los 40 ladrones|Linux|Web enum, hidden dirs, password cracking, root|Easy|
|16|Vulnvault|Linux|Credential storage exploit, web app, root|Easy|
|17|Pntopntobarra|Linux|Point-to-point service exploitation, RCE, privesc|Easy|
|18|Library|Linux|Library web app, SQL injection, sudo escalation|Easy|
|19|Escolares|Linux|School CMS exploitation, web vulnerabilities, root|Easy|
|20|ConsoleLog|Linux|JS console source exposure, code review, privesc|Easy|
|21|Obsession|Linux|FTP anon access, SSH brute force, sudo escalation|Very Easy|
|22|FirstHacking|Linux|Intro hacking box, web basics, simple privesc|Very Easy|
|23|SecretJenkins|Linux|Jenkins secrets exposure, Groovy script RCE|Easy|
|24|HedgeHog|Linux|SSH brute force (reversed wordlist), sudo to root|Very Easy|
|25|AnonymousPingu|Linux|FTP anonymous, reverse shell upload, sudo man|Easy|
|26|ChocolateLovers|Linux|Web exploitation, cookie manipulation, root|Easy|
|27|Dockerlabs|Linux|File upload bypass, web shell, arbitrary RCE|Easy|
|28|Pressenter|Linux|WordPress admin, plugin RCE, root escalation|Easy|
|29|Candy|Linux|Web app credential extraction, SSH privesc|Easy|
|30|JenkHack|Linux|Jenkins RCE via Groovy console, privesc|Easy|
|31|ShowTime|Linux|Entertainment web app, OS command injection, root|Easy|
|32|Verdejo|Linux|SSTI Python template injection, root|Easy|
|33|WhereIsMyWebShell|Linux|Hidden web shell discovery, RCE, root|Easy|
|34|Whoiam|Linux|User impersonation, sudo binary abuse, privesc|Easy|
|35|Winterfell|Linux|Game of Thrones themed, multi-user, privesc chain|Medium|
|36|-Pn|Linux|Firewall bypass themed, Nmap evasion, root|Easy|
|37|Psycho|Linux|Web exploitation, OS injection, root|Medium|
|38|Mirame|Linux|Image mirror themed, web app, privesc|Easy|
|39|Backend|Linux|Backend API exploitation, auth bypass, root|Easy|
|40|Paradise|Linux|Credential enumeration, web app, privesc|Easy|
|41|Balurero|Linux|Custom service exploitation, port knocking, root|Medium|
|42|Allien|Linux|Alien-themed web service exploit, root|Medium|
|43|Vendetta|Linux|V for Vendetta themed, web exploit, root|Medium|
|44|FindYourStyle|Linux|CSS/web themed, LFI exploitation, privesc|Easy|
|45|Stellarjwt|Linux|JWT token exploitation, web auth bypass, root|Medium|
|46|File|Linux|SUID file command abuse, privilege escalation|Easy|
|47|Redirection|Linux|Open redirect, SSRF, web exploitation, root|Easy|
|48|Extraviado|Linux|Hidden services, multi-step exploitation, root|Medium|
|49|Patriaquerida|Linux|Multi-vector exploitation, chained privesc|Medium|
|50|Tproot|Linux|Direct escalation path, fast root challenge|Easy|
|51|Internship|Linux|Corporate-themed, low-priv access, escalation|Easy|
|52|Walking Dead|Linux|Zombie-themed, persistence mechanism, full chain|Medium|
|53|Bicho|Linux|Bug-themed web vulnerability, OS injection, root|Easy|
|54|BaluFood|Linux|Food delivery app, web exploitation, root|Easy|

  

# ⚙️ SECTION 5: GITHUB VULNERABLE PROJECTS

GitHub hosts hundreds of intentionally vulnerable applications, complete CVE recreation labs, web application security training platforms, and cloud security sandboxes. All 100% free and open source.

## GITHUB  VULNERABLE APPS & LABS (#1–80)

Web apps, CVE reproductions, cloud labs, mobile apps, API security. Most run via Docker or Docker Compose. Essential for practicing specific vulnerability classes.

|**#**|**App / Lab Name**|**Platform**|**Skills / Focus Areas**|**Difficulty**|
|---|---|---|---|---|
|**1**|Metasploitable 2 (Rapid7)|Linux|20+ services, FTP VSFTPD, Samba, Java RMI, PHP injection|**Easy**|
|**2**|Metasploitable 3 Win (Rapid7)|Windows|WampServer, Jenkins, ManageEngine, multi-vector|**Medium**|
|**3**|Metasploitable 3 Linux (Rapid7)|Linux|FTP, Apache Struts, Shellshock, proftpd, privesc|**Medium**|
|**4**|DVWA (digininja)|Linux|SQLi all types, XSS, CSRF, file inclusion, command exec|**Easy**|
|**5**|bWAPP (MME)|Linux|100+ bugs, OWASP Top 10, XXE, SSRF, insecure deserialize|**Easy**|
|**6**|WebGoat (OWASP)|Java|Injections, auth bypass, XXE, access control, crypto|**Easy**|
|**7**|Juice Shop (OWASP)|Node.js|Modern web vulns, JWT, IDOR, XSS, SQLi, OAuth|**Easy**|
|**8**|VulnLab (Docker)|Multi|Multi-container vulnerable web app lab|**Easy**|
|**9**|VAmPI (VAmPI)|Python|REST API vulns, OWASP API Top 10, JWT, mass assign|**Medium**|
|**10**|NodeGoat (OWASP)|Node.js|Node.js OWASP Top 10, NoSQLi, SSRF|**Easy**|
|**11**|RailsGoat (OWASP)|Ruby|Ruby on Rails OWASP, mass assignment, IDOR|**Medium**|
|**12**|WebSheep|PHP|PHP OWASP lab, SQLi, LFI, XSS, CSRF|**Easy**|
|**13**|HackMe (Firefox)|Multi|Browser exploitation, plugin vulns|**Easy**|
|**14**|InsecureBank|Android|Android banking app, IDOR, XSS, cert pinning bypass|**Medium**|
|**15**|DIVA Android|Android|Android app vulns, hardcoded creds, insecure storage|**Easy**|
|**16**|PentesterLab|Multi|Real-world vuln replicas, CVE exploitation|**Medium**|
|**17**|LAMPSecurity CTF1-7|Linux|LAMP stack, SQLi, PHP, SUID privesc series|**Easy**|
|**18**|LAMPSecurity CTF8|Linux|Advanced LAMP, custom binary exploitation|**Medium**|
|**19**|VulnApp (ASP.NET)|Windows|ASP.NET vulns, SQLi, XSS, file upload|**Medium**|
|**20**|Hackazon (Rapid7)|Linux|E-commerce app, SQLi, SSRF, XXE|**Medium**|
|**21**|TiredfulAPI|Python|API security testing, REST API vulns|**Easy**|
|**22**|Vapi|Python|Vulnerable API with OWASP API Top 10|**Easy**|
|**23**|crAPI|Multi|Completely Ridiculous API, modern API vulns|**Medium**|
|**24**|Pixi (42Crunch)|Node.js|Pixelated API, JWT, IDOR, unauthorized access|**Easy**|
|**25**|Webseclab (Yahoo)|Go|Real-world web security vulnerabilities|**Hard**|
|**26**|SecurityShepherd (OWASP)|Java|CTF platform, web and mobile security|**Easy**|
|**27**|Mutillidae II (OWASP)|PHP|160+ vulnerabilities, OWASP, web hacking|**Easy**|
|**28**|Rootme|Multi|Multi-challenge, web, network, forensics|**Medium**|
|**29**|InfoSecWarrior Docker Lab|Multi|Docker container pentesting lab|**Medium**|
|**30**|VulnHub Docker labs|Multi|Docker-based vulnerable app collection|**Easy**|
|**31**|Pentest_lab (docker-compose)|Multi|Multi-app pentest lab, all classic vulns|**Easy**|
|**32**|Vulnerable-GraphQL-API|Node.js|GraphQL injections, IDOR, auth bypass|**Medium**|
|**33**|SSRF_Vulnerable_Lab|PHP|SSRF lab, file read, cloud metadata|**Easy**|
|**34**|PHP Vulnerable Lab|PHP|PHP-specific vulns, RCE, LFI, RFI|**Easy**|
|**35**|Vulhub (docker)|Multi|200+ CVE reproductions, container-based|**Medium**|
|**36**|Sqli-labs|PHP|20+ SQLi techniques, error-based, blind, OOB|**Easy**|
|**37**|XSStrike Lab|Python|XSS fuzzing and exploitation lab|**Easy**|
|**38**|SSTImap Lab|Multi|Template injection lab, Jinja2, Twig, Freemarker|**Medium**|
|**39**|Log4Shell Lab|Java|Log4j CVE-2021-44228 exploitation lab|**Medium**|
|**40**|Spring4Shell Lab|Java|Spring4Shell CVE-2022-22965 exploit lab|**Medium**|
|**41**|ProxyLogon Lab|Windows|Exchange CVE-2021-26855 lab setup|**Hard**|
|**42**|PrintNightmare Lab|Windows|CVE-2021-1675 Print Spooler privesc|**Hard**|
|**43**|Zerologon Lab|Windows|CVE-2020-1472 NetLogon privesc to DC|**Hard**|
|**44**|EternalBlue Lab|Windows|MS17-010 SMBv1 exploit recreation|**Medium**|
|**45**|BlueKeep Lab|Windows|CVE-2019-0708 RDP RCE exploitation|**Hard**|
|**46**|Heartbleed Lab|Linux|OpenSSL CVE-2014-0160, memory leak|**Easy**|
|**47**|Shellshock Lab|Linux|Bash CVE-2014-6271, CGI exploitation|**Easy**|
|**48**|Dirty Cow Lab|Linux|CVE-2016-5195 kernel privilege escalation|**Medium**|
|**49**|DirtyPipe Lab|Linux|CVE-2022-0847 kernel pipe exploit|**Medium**|
|**50**|PwnKit Lab|Linux|CVE-2021-4034 Polkit privesc|**Easy**|
|**51**|Sudo Baron Lab|Linux|CVE-2021-3156 sudo heap BOF|**Medium**|
|**52**|PKexec Lab|Linux|CVE-2021-4034 pkexec privesc|**Easy**|
|**53**|Nmap NSE Script Lab|Linux|Nmap scripting exploitation practice|**Easy**|
|**54**|WPScan Lab|Linux|WordPress scanning and exploitation|**Easy**|
|**55**|CMSmap Lab|Multi|Multi-CMS exploitation practice|**Easy**|
|**56**|Commix Lab|Linux|Command injection automation practice|**Easy**|
|**57**|SQLmap Lab|MySQL|SQL injection automation, all techniques|**Easy**|
|**58**|Nikto Lab|Multi|Web server misconfiguration detection|**Easy**|
|**59**|OWASP BWA|Multi|Broken Web App bundle, 20+ apps|**Easy**|
|**60**|CloudGoat (Rhino)|AWS|Vulnerable AWS environment, IAM abuse|**Hard**|
|**61**|TerraGoat (Bridgecrew)|Multi|IaC misconfigs, Terraform, AWS, Azure, GCP|**Hard**|
|**62**|HackableIII|Linux|Web, SQLi, LFI, privilege escalation|**Easy**|
|**63**|SecDevOps Lab|Multi|DevSecOps pipeline exploitation|**Hard**|
|**64**|InsecureShip|Node.js|E-commerce app, IDOR, XSS, SSRF|**Medium**|
|**65**|Altoro Mutual|Java|Banking web app, OWASP vulns|**Easy**|
|**66**|Hackazon (community)|PHP|PHP e-commerce, full OWASP coverage|**Medium**|
|**67**|SafeBank|Node.js|Banking sim, API vulns, JWT, IDOR|**Medium**|
|**68**|VulnerableApp|Java|Spring Boot, multi-vuln training app|**Easy**|
|**69**|CICD Goat|Multi|CI/CD pipeline exploitation lab|**Hard**|
|**70**|KubernetesGoat|Kubernetes|K8s security vulns, pod escape, RBAC|**Hard**|
|**71**|CloudFoxable|AWS|AWS exploitation lab, IAM privesc|**Hard**|
|**72**|IAM Vulnerable|AWS|AWS IAM privilege escalation lab|**Hard**|
|**73**|Damn Vulnerable AWS|AWS|Multiple AWS exploitation scenarios|**Hard**|
|**74**|Damn Vulnerable GCP|GCP|GCP-specific exploitation scenarios|**Hard**|
|**75**|Damn Vulnerable Azure|Azure|Azure-specific exploitation scenarios|**Hard**|
|**76**|PurpleLabs|Multi|Purple team, offensive + defensive|**Hard**|
|**77**|TIBER-EU Framework Lab|Multi|Advanced threat intelligence red team sim|**Insane**|
|**78**|GOAD (Game of AD)|Windows|Active Directory attack lab, 5 VMs|**Insane**|
|**79**|DetectionLab|Windows|AD lab with detection and logging|**Hard**|
|**80**|BadBlood|Windows|AD population tool for attack simulation|**Hard**|

  

# 📚 SECTION 6: SKILL-BASED LEARNING PATHS

Use these curated paths to master specific skill areas. Each path lists machines in progressive order from easiest to hardest.

|**Skill Focus Path**|**Recommended Machine Order**|**Difficulty Range**|
|---|---|---|
|🔐 SQL Injection Path|DVWA (GitHub) → Sqli-labs → NullByte:1 → billu:b0x → Healthcare:1 → DC:3 → DarkHole:2 → Symfonos:5 → Prime:1 → Ouija|Easy → Hard|
|🌐 Web Application Path|DVWA → WebGoat → bWAPP → Mr.Robot → FristiLeaks → billu:b0x → Raven:1 → DevGuru:1 → Shuriken:1 → Corrosion:2|Easy → Hard|
|📂 File Inclusion (LFI/RFI) Path|DVWA LFI → NullByte:1 → SickOs:1.1 → The Ether → DC:5 → Symfonos:3 → Pikaboo → Interface → VulNyx LFI box|Easy → Hard|
|🔑 Privilege Escalation Path|Escalate_Linux:1 → Lin.Security → VulNyx (Sudo/SUID/Cron boxes) → Kioptrix series → HA:Narak → Prime:1 → Insomnia|Easy → Hard|
|💥 Buffer Overflow Path|/dev/random:Scream → Brainpan:1 → Brainpan:2 → IMF:1 → VulNyx Overflow → VulNyx Format → VulNyx ROP → Fawkes → Pinky's Palace v2|Easy → Insane|
|🏢 Active Directory Path|GOAD Lab → VulNyx Forest/Cascade → VulNyx Sauna/Resolute → VulNyx Blackfield → VulNHub VulnNet:Roasted → BadBlood Lab|Medium → Insane|
|🐳 Container / Cloud Path|DockerLabs Trust → VulNyx Docker → VulNyx LXD → HackMyVM Docker → CloudGoat → KubernetesGoat → TerraGoat → DVAG|Easy → Hard|
|🔵 WordPress Path|DC:1 → DC:2 → DC:6 → Mr.Robot → BSides Vancouver → EVM:1 → Raven:1 → HarryPotter:Aragog → ColddBox → VulNyx WordPress|Easy → Hard|
|📡 Network Services Path|Kioptrix:L1 → HackLAB:Vulnix → Fowsniff → SolidState → GoldenEye:1 → Mercy → Nully Cybersecurity → Typhoon|Easy → Hard|
|🔓 OSCP Preparation Path|Kioptrix 1-5 → DC 1-9 → VulnOS 2 → FristiLeaks → Stapler → Lin.Security → Mr.Robot → Brainpan:1 → SolidState → Temple of Doom → Pinky's Palace v2|Medium → Hard|

# 🏆 SECTION 7: CERTIFICATION PREP PATHS

|**Certification**|**Relevant Machines / Labs**|**Key Skills Tested**|
|---|---|---|
|eJPT (INE)|Kioptrix L1, DC:1, Basic Pentesting:1, DockerLabs Trust/Upload, VulNyx Easy boxes|Nmap, basic SQLi, web enum, SSH, simple privesc|
|eWPT (INE)|DVWA, bWAPP, Mr.Robot, billu:b0x, Raven:1, Healthcare:1, Prime:1, Shuriken|Full web app testing, SQLi, XSS, LFI, CMSs|
|OSCP (OffSec)|Kioptrix 1-5, DC 1-9, Brainpan, FristiLeaks, Stapler, Temple of Doom, SolidState, Zico2|Multi-vector, BOF, privesc, AD basics|
|PNPT (TCM)|AD labs (GOAD), Mr.Robot, DC:6, VulnNet:Roasted, DetectionLab, Monteverde|AD pentest, report writing, full chain|
|CPTS (HTB)|All intermediate + advanced machines, AD path, Container path|Deep exploitation, full network pentest|
|CRTO (Zero-Point)|GOAD, DetectionLab, Blackfield, Forest, Cascade, VulNyx AD boxes|Red team ops, C2 frameworks, AD attacks|
|CEH (EC-Council)|DVWA, Metasploitable 2/3, bWAPP, Juice Shop, WebGoat|Broad surface, tools-based exploitation|
|CompTIA PenTest+|Metasploitable 2, DVWA, DC:1, Basic Pentesting:1, Lin.Security|Standard pentest methodology|

  

# 💡 SECTION 8: STRATEGY, TIPS & RESOURCES

## Methodology Framework

|**Phase**|**Actions**|**Key Tools**|
|---|---|---|
|1. Recon|Full port scan, OS detection, service version detection|Nmap, Rustscan, Masscan|
|2. Enumeration|Enumerate each open service, find usernames, files, configs|Gobuster, Nikto, Enum4linux, SMBmap|
|3. Exploitation|Find and exploit vulnerabilities for initial access|Metasploit, Searchsploit, Manual exploits|
|4. Post-Exploitation|Enumerate as low-privileged user, find privesc vectors|LinPEAS, PSPY, GTFOBins, WinPEAS|
|5. Privilege Escalation|Escalate to root/SYSTEM using discovered vectors|Sudo abuse, SUID, Kernel exploits, Cron|
|6. Documentation|Write detailed report: screenshots, commands, findings|Markdown, CherryTree, Obsidian|

## Time Planning — One Machine Per Day

|**Difficulty**|**Avg. Time**|**When Stuck**|**Success Metric**|
|---|---|---|---|
|Very Easy / Easy|30–60 min|Check after 30 min|Rooted without hints|
|Medium|1–3 hours|Check hint after 2 hrs|Rooted, understand all steps|
|Hard|3–8 hours|Check after 4 hrs|Rooted, research write-up after|
|Insane|8–24+ hours|Use writeup after 8 hrs|Understand the technique even if not rooted solo|

## Key Resources

|**Resource**|**URL / Reference**|**Use Case**|
|---|---|---|
|GTFOBins|gtfobins.github.io|SUID/Sudo binary privilege escalation|
|LOLBAS|lolbas-project.github.io|Living-off-the-land Windows binaries|
|PayloadsAllTheThings|github.com/swisskyrepo/PayloadsAllTheThings|Payload collection for all vuln types|
|HackTricks|book.hacktricks.xyz|Comprehensive pentest technique guide|
|Exploit-DB|exploit-db.com / searchsploit|Public exploit database|
|RevShells|revshells.com|Reverse shell generator, all languages|
|CyberChef|gchq.github.io/CyberChef|Encoding/decoding/crypto operations|
|PentestMonkey|pentestmonkey.net/cheat-sheet|Reverse shell cheat sheets|
|IPPSEC|ippsec.rocks|Video walkthroughs, searchable by technique|
|0xdf Hacks Stuff|0xdf.gitlab.io|Detailed HTB/VulnHub writeups|
|HackingArticles|hackingarticles.in|VulnHub walkthroughs, detailed guides|
|Rana Khalil|rana-khalil.gitbook.io|OSCP/web app guides, detailed explanations|

  

# 📊 SECTION 9: PROGRESS TRACKING OVERVIEW

|**Platform**|**Total Machines Listed**|**Beginner**|**Intermediate**|**Advanced / Insane**|
|---|---|---|---|---|
|VulnHub|300 machines|100 machines (1-100)|100 machines (101-200)|100 machines (201-300)|
|HackMyVM|200 machines|80 machines|80 machines|40 machines|
|VulNyx|120 machines|40 machines|50 machines|30 machines|
|DockerLabs|60 machines|30 machines|20 machines|10 machines|
|GitHub Projects|80 apps/labs|30 apps|30 apps|20 apps/labs|
|TOTAL|760+ entries in catalog|~280 beginner|~280 intermediate|~200 advanced|

NOTE: VulnHub has 700+ total machines, HackMyVM has 300+, VulNyx has 166, and DockerLabs has 54+. This catalog lists 760+ curated entries from the best-known and most educational machines across all platforms. The full catalogs of each site contain thousands of additional hours of practice.

With ~3 machines per week, you will complete 150+ machines in 12 months. With 5 machines per week, you will reach 250+ machines. The catalog is intentionally larger than one year so you always have more to explore.

**_"The more you sweat in practice, the less you bleed in the field."_**

** Start hacking. Stay consistent. Own everything. **
