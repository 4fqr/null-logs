# Quick Setup for Linux/Kali

## Option 1: One-Command Install (Recommended)

```bash
git clone https://github.com/4fqr/null-logs.git
cd null-logs
sudo make install
```

That's it! Then run:
```bash
sudo null-log live
```

---

## Option 2: Manual Install Script

```bash
git clone https://github.com/4fqr/null-logs.git
cd null-logs
chmod +x scripts/install.sh
sudo ./scripts/install.sh
```

---

## Option 3: Build Only (No Install)

```bash
git clone https://github.com/4fqr/null-logs.git
cd null-logs
make quick           # Fast build
# OR
make dev             # Optimized build

# Then run directly:
sudo ./null-log live
```

---

## Requirements

- **Go 1.21+** (install with: `sudo apt install golang-go`)
- **Linux** (tested on Kali, Ubuntu, Debian)
- **Root/sudo** (needed to read system logs)

---

## Quick Commands

```bash
# Real-time threat monitoring
sudo null-log live

# Network threat scanner (detects nmap, port scans, etc)
sudo null-log net

# Hunt through historical logs
sudo null-log hunt --hours 24

# Show all commands
null-log --help
```

---

## What Gets Detected?

✅ **Windows Attacks** (when monitoring Windows logs):
- Mimikatz credential dumping
- PowerShell malware downloads
- Registry persistence
- Suspicious scheduled tasks
- Windows Defender disabled

✅ **Network Attacks** (all platforms):
- Nmap scans
- Port scanning
- SYN flood attacks
- Reverse shells
- C2 beaconing

✅ **Linux Attacks** (when monitoring Linux):
- SSH brute force
- Unauthorized SSH keys
- Suspicious cronjobs
- Kernel module loading
- Sudo abuse

---

## Troubleshooting

**"Go not found"**
```bash
sudo apt update
sudo apt install golang-go
```

**"Permission denied"**
```bash
# Must run with sudo to read system logs
sudo null-log live
```

**"Rules not found"**
```bash
# Make sure you're in the null-logs directory
cd /path/to/null-logs
sudo make install
```

**"Not in PATH"**
```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

---

## Verify Installation

```bash
null-log --version
ls ~/.null.log/rules/  # Should show 21 .yml files
```

---

## Uninstall

```bash
sudo make uninstall
# Config kept at ~/.null.log (remove manually if desired)
```
