---
title: "Mouse Cursor Offset in QEMU/KVM VM with SPICE"
date: 2025-10-01T10:47:11+02:00
draft: false
tags: ["qemu", "mouse", "spice-agent"]
categories: ["Bugs"]
---
# Solved: Mouse Cursor Offset in QEMU/KVM VM with SPICE

**Problem:** You're using a QEMU/KVM virtual machine with SPICE display and the mouse cursor is always offset? Clicks register in the wrong place, especially after resolution changes? This is a common issue – and the solution is simpler than you think!

## The Cause: Missing SPICE Guest Agent

The problem occurs because the SPICE client (on the host) and the guest system aren't communicating properly. The **SPICE Guest Agent** is either not installed or – as in most cases – it's installed but the **user-space agent** isn't running.

## The Solution in 3 Steps

### 1. Install SPICE Guest Agent (Guest System)

Make sure `spice-vdagent` is installed in the guest system:

**Debian/Ubuntu/Kali:**
```bash
sudo apt update && sudo apt install spice-vdagent
```

**Arch Linux/Manjaro:**
```bash
sudo pacman -S spice-vdagent
```

**Fedora/RHEL:**
```bash
sudo dnf install spice-vdagent
```

### 2. Start the User-Space Agent (This is the key!)

After installation, you need to start the agent in your user session:

```bash
# Check if it's already running
ps aux | grep spice-vdagent

# If not running: Start it!
spice-vdagent -d
```

**💡 Important:** The `-d` parameter starts the process as a daemon in the background.

### 3. Make it Permanent

To avoid having to start it manually after every reboot, add it to your autostart:

**For most desktop environments:**
- Add `spice-vdagent -d` to your startup applications

**Or create a desktop file:**
```bash
mkdir -p ~/.config/autostart
echo "[Desktop Entry]
Type=Application
Name=SPICE Agent
Exec=spice-vdagent -d
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true" > ~/.config/autostart/spice-vdagent.desktop
```

## Additional Configuration Tips

### Fix Input Device Conflicts

In your VM configuration, make sure you're using a USB tablet instead of PS/2 mouse:

```xml
<!-- Good: USB tablet for absolute positioning -->
<input type='tablet' bus='usb'/>

<!-- Remove this if possible -->
<input type='mouse' bus='ps2'/>
```

### Verify SPICE Channel

Ensure the VM has the SPICE communication channel:

```bash
# Check from host
sudo virsh dumpxml "vm-name" | grep -A5 "spicevmc"
```

## Why This Works

The `spice-vdagent` provides:
- **Cursor synchronization** between host and guest
- **Automatic resolution adjustment** when resizing the VM window
- **Copy-paste integration** between host and guest
- **File sharing** capabilities

## Quick Diagnosis

If mouse issues persist, check:

1. **Is the agent running?**
   ```bash
   ps aux | grep spice-vdagent
   ```

2. **Check service status:**
   ```bash
   systemctl status spice-vdagentd
   ```

3. **Verify SPICE graphics in VM config:**
   ```xml
   <graphics type='spice' autoport='yes'>
   ```
