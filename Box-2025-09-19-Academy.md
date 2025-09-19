---
box: Academy
date: 2025-09-19
category: Web
difficulty: Easy
tags:
- php
- web
- cryptography
- pwn
- sysadmin
- developer
start:2025-09-19 14:33
finish: 2025-09-19 17:27
status: in-progress
---

# Box Overview – Box-2025-09-19-Academy

##### Network Enumeration

- **Timestamp:** 2025-09-19 14:35
- **Action:** 
	- Doing nmap scan on target with defaults.
- **Commands:** 
	- `sudo namp $ip -sVCO -oA recon`
	- `sudo namp $ip -sVC -oA recon2`
	- `sudo nmap $ip -sUV -oA recon3`
		- This last scan is because apparently in my mistake, I actually uncovered some UDP ports. Calls for a follow-up even if it's slower.
- **Notes:** 
	- First scan wasn't super great, as `-sV` is incompatible with IPProto Scan (`-sO`)
		- Returned interesting results.
			- 17 and 103 are associated with MotD and MS Exchange, but also both associated with Skun trojan?
			- 136 also used but apparently is deprecated (might be malicious)
			- Might be an artifact rather than a lead.
				- Following up below.
	- Second scan returns some info useful to us:
		- `22` open as `OpenSSH 8.2p1 Ubuntu`
		- `80` is also open running `Apache httpd 2.4.41`
		- We've determined an apache webserver with ssh enabled on an Ubuntu system from this.
		- Also in scan:
			- `_http-title: Did not follow redirect to http://academy.htb/`
				- Potentially have to point our hostfile here.
	- Third scan with larger port range returns:
		- `33060/tcp open  mysqlx`
		- Looks like we also have mysql running.
- **Next Steps:** 
	- Explore leads while UDP scan completes.

##### Adding to hostfile and visiting site.

- **Timestamp:** 2025-09-19 14:55
- **Action:** 
	- Updated hostfile and browsed to website.
- **Commands:** 
	- `echo "${ip}  academy.htb | sudo tee -a /etc/hosts`
- **Notes:** 
	- Visited site after adding to hostfile. Looks like we're met with a login to a fake academy site.
- **Next Steps:** 
	- Explore fields, logins, etc.

##### Interacting with the site

- **Timestamp:** 2025-09-19 14:57
- **Overview:** 
	- We see immediately a `login.php` page
		- Potential endpoint for injection.
	- Also a `register.php` field.
	- Let's try fuzzing. Our UDP scan is STILL running.
- **Next Steps:**
	- Going to try experimenting with the register section first, as often in these engagements, that can be a weak php endpoint.

##### Burp with the register.php endpoint.

- **Timestamp:** 2025-09-19 15:02
- **Action:** Using burpsuite to inspect POST requests on the endpoint.
- **Commands:**
	- `burpsuite`
- **Notes:** 
	- `uid=lazarus&password=lazarus&confirm=lazarus&roleid=0`
		- As we can see, `roleid` looks interesting, might be able to trick it into thinking we're someone different. But how to find that?
		- `<input type="hidden" value="0" name="roleid" />`
			- Okay this for sure can be manipulated so we'll need to explore the different `roleid` options.
	- Also note that it assigns a `Cookie: PHPSESSID=<ID>`
		- Session hijacking?
	- Upon registering, there's a split second where the browser redirects to a `success-page.php` GET request.
	- Looks like no frontend javascript - it's all php baybee.
- **Next Steps:** 
	- Switching to a fuzz to make sure we properly enumerate

##### Fuffing other .php endpoints

- **Timestamp:** 2025-09-19 15:23
- **Action:**
	- As said, using endpoint ffufing.
- **Commands:** 
	- `ffuf -w ./api-endpoints-res.txt -u "http://academy.htb/FUZZ.php"`
- **Notes:** 
	- Found a few including an admin and home page.
	- Admin endpoint is locked by `roleid` most likely.
	- Looks like we're redirected to a separate login that looks almost identical, but the URI is different.
		- Both `login.php` and `admin.php` do not have `roleid` in their POST options.
		- 13 and 69 return different responses in burp.
- **Next Steps:** 
	- Return to fudging the roleid.

##### Gaining access with fudged id

- **Timestamp:** 2025-09-19 15:50
- **Action:**
	- We created an admin account and forced the `roleid` to register under 1.
- **Commands:** 
	- `burpsuite`
- **Notes:** 
	- I went a bit overboard and used burp intruder to create 100 accounts with roleids up to 100.
	- Turns out we just needed to swap the `roleid=1`, derp.
- **Next Steps:** 
	- Enumerate internal endpoint.

##### Enumerating `dev-staging-01.academy.htb`

- **Timestamp:** 2025-09-19 15:53
- **Overview:** 
	- We're enumerating this endpoint.
		- `echo "10.129.148.64  dev-staging-01.academy.htb" | sudo tee -a /etc/hosts`
	- We find a `laravel` page.
		- I've never heard of Laravel, so I need to do some digging now.
		- I'll be honest, I'll get gpt to give me a rundown of common techniques before continuing.
		- Looks like we have all sorts of juicy info available on the page though, including a localhost mysql instance on `3306` (default port)
`|APP_KEY|"base64:dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0="|
`|DB_HOST|"127.0.0.1"|`
`|DB_PORT|"3306"|`
`|DB_DATABASE|"homestead"|`
`|DB_USERNAME|"homestead"|`
`|DB_PASSWORD|"secret"|`
- Also found [a potential CVE](https://www.cvedetails.com/cve/CVE-2018-15133/)
	- Check version number.
- Okay, doing some research and the reason we see the splash screen with info and errors is:
`|APP_DEBUG|"true"|`
- When debug is set to true, lots of delicious data is spilled for us to use.
- Specifically that app key looks exploitable, and according to hacktricks this is a classic attack.

![[academy-laravel.png]]
*Laravel debug mode. Note how the key is exposed to us.*

##### Breakdown of Exploit:
- Insecure call to `Illuminate/Encrypter/Encryption`
	- When the app tries to decrypt a serialized payload, it will execute code.
	- This allows RCE along at least [4 different paths, according to this script](https://github.com/aljavier/exploit_laravel_cve-2018-15133/blob/main/pwn_laravel.py)
	- Many such scripts in existence to do this exploit (even on msf), so we don't have to write our own.
- We utilize an http header `X-XSRF-TOKEN` on a POST request to the endpoint.
- The above exploit failed, so we're going to try msfconsole before writing our own (which might take days lol).

##### Metasploit Version of Exploit

- **Timestamp:** 2025-09-19 16:48
- **Action:** Using the metasploit framework to deliver a payload
- **Commands:** `msfconsole`, `search laravel`, `use 6`, various internal settings for IP and importantly the API key, `python3 -c 'import pty; pty.spawn("/bin/bash")'`
- **Notes:**
	- Managed to get a shell.
	- Upgraded the shell
- **Next Steps:**
	- Enumeration and privesc.

##### OS Enumeration

- **Timestamp:** 2025-09-19 16:51
- **Timeline & Commands:** 
	- Laravel has info stored in `.env` file -> basically a configuration file with plaintext creds.
	- `cd /var/www/html/academy`
		- Web app folder
	- `ls -lah`
		- Shows us hidden folders, such as `.env`
	- `cat ./.env`
		- `DB_PASSWORD=mySup3rP4s5w0rd!!`
			- Previously secret of laravel dashboard.
			- Demonstrates how weak plaintext config creds are such as this.
				- **Blue team exercise:** research ways to prevent this sort of lateral move.
			- Could be a username password on system.
		- `DB_USERNAME=dev`
			- Check system for this.
	- `cat /etc/passwd`
		- Shows `/bin/sh` users on system.
		- `cat /etc/passwd | grep /bin/sh`
		- ![[academy-etc-passwd.png]]
		- *could be any of these, check all*
	- `su cry0l1t3`
		- Seems to work
	- `whoami`
	- `id`
		- `uid=1002(cry0l1t3) gid=1002(cry0l1t3) groups=1002(cry0l1t3),4(adm)`
		- Well that's certainly interesting, what is the `4(adm)` group?
	- `cat user.txt`
		- Our flag.
	- `getent group adm`
		- Shit, froze the shell. Derp.
		- `mfconsole` was a bit janky, so changed LHOST port to 4445 rather than 4444 (original).
	- Google shows `adm` group has access to log reviewing capability.
		- Checked `/var/log/syslog` -> huge amount, but accessible.
	- `cd /var/log && ls /var/log`
		- `auth` shows bootup procedures and a cron-job running.
		- `pam_unix(su:session): session opened for user cry0l1t3 by (uid=33)`
			- What is pam_unix?
			- Okay so it's basically an authentication module, the framework for linux auth/session management.
	- Time constraint, so I just used `aureport` with flags to get `tty` activity.
		- Hello, old friend `mrb3n` with password `mrb3n_Ac@d3my!`
		- `whoami` and `id` don't disclose special groups, how about sudo privileges?
			- `sudo -l`
			- `(ALL) /usr/bin/composer`
	- Went to gtfobins to exploit this binary.
		- Second from top is what we need:
```
TF=$(mktemp -d)
echo '{"scripts":{"x":"/bin/sh -i 0<&3 1>&3 2>&3"}}' >$TF/composer.json
composer --working-dir=$TF run-script x
```
- `# cat /root/root.txt`

### Post-Box Analysis
#### What Worked?
- Trying the userpwn on my own worked.
	- Enumerating the web front-end and using the simple bypass was pretty fun.
	- I also did *too* much work for the admin access exploit, is that actually an IDOR based authentication bypass?
		- I almost can't believe how easy that is, not to act incredulous, but as a developer that would be one of the first things to clamp down on.
		- Maybe that's it though - developers are so busy they leave shit open. I know I've done it "in the lab", but what if that labwork gets pushed to production code?
		- #justblueteamthings

#### What was misleading?
- At the beginning, doing the nmap of all ports was diligent but I spent too much time on that when an avenue already existed.
- The `mysql` server was never used in this box, although I'm wondering now if there was another avenue through that.
- Engaging with the `.php` endpoint directly wasn't an accurate stance.

#### What to work on?
- As always, coding and cryptography:
	- While I understood the AES and XSRF token exploit of Lavarel on a cursory level (what it's actually exploiting), actually programming an exploit is a much deeper and complicated endeavour.
	- If we don't have an exploit that's public, then how would we proceed with a wall like this?
		- I would consider this where real skill is at.
		- Don't be too hard on yourself, Grey, but also try to do more coding work on the pwn.
- Dumping logs into the shell with `cat` kind of reminds me of how a barbarian would do it.
	- We can get a bit more sophisticated and also efficient!
	- #workonit
- Better nmap flags and script knowledge is always a plus.
	- I've heard that it's not really relevant but it seems like a useful tool if you utilize it properly.
	- I've also heard of people who code their own nmap-like tools...interesting, although I have a specific goal in mind and that's a bit tangential.













