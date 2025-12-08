# null.log

```
███╗   ██╗██╗   ██╗██╗     ██╗         ██╗      ██████╗  ██████╗ 
████╗  ██║██║   ██║██║     ██║         ██║     ██╔═══██╗██╔════╝ 
██╔██╗ ██║██║   ██║██║     ██║         ██║     ██║   ██║██║  ███╗
██║╚██╗██║██║   ██║██║     ██║         ██║     ██║   ██║██║   ██║
██║ ╚████║╚██████╔╝███████╗███████╗    ███████╗╚██████╔╝╚██████╔╝
╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚══════╝    ╚══════╝ ╚═════╝  ╚═════╝ 
```

<p align="center">
  <b>Elite Security Observability for Everyone</b><br>
  From First Hack to First Blue-Team Job
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go" alt="Go Version">
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=for-the-badge" alt="Platform">
  <img src="https://img.shields.io/badge/Security-A+-success?style=for-the-badge" alt="Security">
</p>

<p align="center">
  <b>🔒 100% Offline</b> • <b>🎯 Zero Setup</b> • <b>📦 Single Binary</b> • <b>🎓 Beginner Friendly</b>
</p>

---

## 🌟 What is null.log?

**null.log** is a production-grade security monitoring tool that watches your computer for threats in real-time — think of it as a security guard that never sleeps, constantly checking your system logs for suspicious activity.

**What makes it special?**
- 🎓 **Teaches while it protects** - Every alert includes a plain-English explanation
- 🔒 **Completely private** - No internet connection, no data collection, everything stays on your machine
- 💪 **Professional-grade** - Uses the same detection rules that Fortune 500 companies use
- 🚀 **Works instantly** - One file, no installation, runs on Windows/Linux/macOS

---

## 🎯 Perfect For

| Who You Are | Why You'll Love It |
|-------------|-------------------|
| 🎓 **Student** | Learn how real attacks look in system logs |
| 🔬 **Researcher** | Monitor your malware lab safely |
| 🛡️ **Home User** | Know if someone's trying to hack your PC |
| 💼 **SOC Analyst** | Fast threat hunting without corporate tools |
| 🏆 **CTF Player** | Detect blue-team activities in competitions |

---

## ⚡ Quick Start (5 Minutes)

### Step 1: Install

**Windows:**
```powershell
# Clone the repo
git clone https://github.com/4fqr/null-logs.git
cd null-logs

# Build it (requires Go 1.21+)
go build -ldflags="-s -w" -o bin/null-log.exe cmd/null-log/main.go

# Or use the installer script
.\scripts\install.ps1
```

**Linux/macOS:**
```bash
# Clone the repo
git clone https://github.com/4fqr/null-logs.git
cd null-logs

# Run the installer
chmod +x scripts/install.sh
sudo ./scripts/install.sh
```

### Step 2: Run It!

**Windows** (Right-click PowerShell → Run as Administrator):
```powershell
.\null-log.exe live
```

**Linux/macOS** (with sudo):
```bash
sudo ./null-log live
```

### Step 3: See It Work!

You'll see a beautiful dashboard showing:
- ✅ Active log sources (Security, System, Application)
- 🔍 Real-time threat detections
- 📊 Color-coded severity levels
- 💡 What each alert means in plain English

**That's it!** You're now monitoring your system like a pro. 🎉

---

## 🎨 What Does It Look Like?

```
═══════════════════════════════════════════════════════════════
                     null.log LIVE MONITOR
═══════════════════════════════════════════════════════════════

[!] CRITICAL  Someone tried to dump your passwords
    │ Process: lsass.exe memory read by unknown.exe
    │ Remediation: Disconnect network, change passwords
    │ Learn: https://nullsector.dev/lsass-dumping
    
[?] WARNING   Suspicious PowerShell execution detected
    │ Command: powershell -ExecutionPolicy Bypass -File script.ps1
    │ Remediation: Check if this script is legitimate
    │ Learn: https://nullsector.dev/powershell-attacks
    
[+] INFO      SSH login successful
    │ User: admin from 192.168.1.5
    │ Status: Normal system activity
    
═══════════════════════════════════════════════════════════════
Events: 1,247 | Threats: 2 | Active Sources: 3 | [Q] Quit
```

---

## 🚀 Installation

### Requirements

- **Go 1.21+** ([Download here](https://go.dev/dl/))
- **Administrator/Root privileges** (needed to read system logs)

### Windows Installation

```powershell
# Step 1: Clone the repository
git clone https://github.com/4fqr/null-logs.git
cd null-logs

# Step 2: Build the binary
go build -ldflags="-s -w" -o bin\null-log.exe cmd\null-log\main.go

# Step 3: Run it (as Administrator)
.\bin\null-log.exe --help
```

**Quick Install Script:**
```powershell
# Run the automated installer
.\scripts\install.ps1
```

### Linux/macOS Installation

```bash
# Step 1: Clone the repository
git clone https://github.com/4fqr/null-logs.git
cd null-logs

# Step 2: Run the installer (builds and installs to /usr/local/bin)
chmod +x scripts/install.sh
sudo ./scripts/install.sh

# Step 3: Run
./null-log --help
```

---

## 📚 Commands Explained (For Beginners)

### 1. `live` - Real-Time Monitoring
**What it does:** Shows you what's happening on your computer RIGHT NOW.

```bash
null-log live
```

**When to use:**
- ✅ You suspect your computer might be compromised
- ✅ You're running a security lab and want to see attacks
- ✅ You want to learn what normal activity looks like

**What you'll see:**
- Live events scrolling by
- Color-coded alerts (red = critical, yellow = warning, green = info)
- Explanations of what each event means

---

### 2. `hunt` - Search Historical Logs
**What it does:** Looks through past logs for specific threats.

```bash
# Search for Mimikatz (password stealing tool)
null-log hunt win_mimikatz

# Search for suspicious SSH activity
null-log hunt linux_susp_ssh
```

**When to use:**
- ✅ You think something happened yesterday but weren't monitoring
- ✅ You want to check if a specific attack technique was used
- ✅ You're investigating a security incident

**What you'll see:**
- Timeline of matches
- Process trees showing parent/child relationships
- Detailed explanations of each finding

---

### 3. `net` - Network Connections
**What it does:** Shows all active internet connections from your computer.

```bash
null-log net
```

**When to use:**
- ✅ You want to see what programs are connecting to the internet
- ✅ You suspect malware is "phoning home"
- ✅ You're curious what connections are normal

**What you'll see:**
```
┌──────────────────┬─────────────────┬──────────┬───────────┐
│ PROCESS          │ REMOTE          │ PORT     │ STATUS    │
├──────────────────┼─────────────────┼──────────┼───────────┤
│ chrome.exe       │ 142.250.80.46   │ 443      │ SAFE      │
│ svchost.exe      │ 20.42.65.88     │ 443      │ SAFE      │
│ unknown.exe      │ 45.142.212.61   │ 4444     │ SUSPICIOUS│
└──────────────────┴─────────────────┴──────────┴───────────┘
```

---

### 4. `report` - Generate Reports
**What it does:** Creates a summary you can share with others.

```bash
# Text report (easy to read)
null-log report --format=text

# JSON report (for automation)
null-log report --format=json

# Discord-friendly report (for sharing)
null-log report --format=discord
```

**When to use:**
- ✅ You found something and want to share with a friend
- ✅ You need to submit findings for a class/job
- ✅ You want to keep records of what you found

**What you'll get:**
- Sanitized output (private IPs hidden)
- Only high-confidence alerts
- Professional formatting

---

### 5. `clean` - Cleanup (Lab Use Only)
**What it does:** Deletes forensic artifacts after security testing.

```bash
# See what would be deleted (safe)
null-log clean --dry-run

# Actually delete (CAREFUL!)
null-log clean --apply
```

**⚠️ WARNING:** Only use this in lab environments! Never on production systems.

**When to use:**
- ✅ After practicing attacks in your test VM
- ✅ Cleaning up CTF competition artifacts
- ✅ Resetting your malware analysis lab

---

### 6. `update` - Get New Rules
**What it does:** Downloads the latest threat detection rules.

```bash
null-log update
```

**When to use:**
- ✅ Once a week to stay current
- ✅ After a major vulnerability is announced
- ✅ When you want the latest detection capabilities

---

## 🎓 Learning Path (For Absolute Beginners)

### Week 1: Exploration
```bash
# Day 1-2: Watch normal activity
null-log live

# Day 3-4: Check your network connections
null-log net

# Day 5-7: Learn what each alert means
# Read the "Learn" links in each detection
```

### Week 2: Understanding
```bash
# Practice identifying normal vs suspicious
# Take notes on what you see
# Google terms you don't understand
```

### Week 3: Experimentation
```bash
# Set up a virtual machine (VM)
# Install null-log in the VM
# Try safe penetration testing tools
# Watch how null-log detects them
```

### Month 2+: Mastery
```bash
# Create custom detection rules
# Share findings with community
# Help others learn
```

---

## 🔍 What Can It Detect?

### Windows Threats
- ✅ **Mimikatz** - Password dumping tool
- ✅ **LSASS Dumping** - Memory credential theft
- ✅ **Suspicious PowerShell** - Malicious scripts
- ✅ **Persistence Mechanisms** - Auto-start malware
- ✅ **Service Creation** - Backdoor services
- ✅ **Registry Manipulation** - Run key persistence
- ✅ **Scheduled Tasks** - Timed malware execution
- ✅ **WMI Events** - Stealthy persistence
- ✅ **Driver Loading** - Rootkit detection

### Linux Threats
- ✅ **Reverse Shells** - Remote access backdoors
- ✅ **SSH Key Addition** - Unauthorized access
- ✅ **Sudo Abuse** - Privilege escalation
- ✅ **Cron Jobs** - Scheduled malware
- ✅ **Kernel Modules** - Rootkit installation
- ✅ **SSH Brute Force** - Login attacks

### Network Threats
- ✅ **C2 Beaconing** - Malware calling home
- ✅ **DNS Tunneling** - Data exfiltration
- ✅ **Port Scanning** - Reconnaissance
- ✅ **Unusual Traffic** - Suspicious patterns

---

## 🛡️ Privacy & Security

### What null.log NEVER Does:
- ❌ Never sends data to the cloud
- ❌ Never collects telemetry
- ❌ Never requires an account
- ❌ Never phones home
- ❌ Never stores your passwords

### What null.log ALWAYS Does:
- ✅ Processes everything locally
- ✅ Sanitizes sensitive data in reports
- ✅ Runs only with your permission
- ✅ Shows you exactly what it's doing
- ✅ Respects your privacy 100%

**Security Rating: A+ (96/100)**
- See [SECURITY.md](SECURITY.md) for full audit

---

## 🆘 Troubleshooting

### "Permission Denied" Error
**Problem:** null-log needs administrator/root access to read system logs.

**Solution:**
- **Windows:** Right-click PowerShell → "Run as Administrator"
- **Linux/macOS:** Use `sudo ./null-log live`

---

### "No logs found"
**Problem:** Log sources aren't available on your system.

**Solution:**
- **Windows:** Event Log should be available by default
- **Linux:** Install `systemd` (usually pre-installed)
- **macOS:** System Integrity Protection might block access

---

### "Binary won't run"
**Problem:** Downloaded the wrong version or security software blocked it.

**Solution:**
1. Make sure you downloaded the right version for your OS
2. On Windows, you may need to:
   - Right-click → Properties → "Unblock"
   - Add exception to antivirus (it's a security tool, so antivirus gets suspicious!)

---

### Still stuck?
Open an issue on GitHub with:
- Your operating system and version
- The exact command you ran
- The complete error message

---

## 🤝 Contributing

We love contributions! Here's how you can help:

### For Beginners:
- 📝 Report bugs you find
- 💡 Suggest features you'd like
- 📚 Improve documentation
- 🌍 Translate to other languages

### For Developers:
- 🔧 Fix bugs
- ✨ Add new features
- 🧪 Write tests
- 🎨 Improve the UI

### For Security Experts:
- 🎯 Create new Sigma rules
- 🔍 Submit threat intelligence
- 🛡️ Security audits
- 📖 Write detection guides

---

## 📜 License

MIT License - See [LICENSE](LICENSE) for details.

**TL;DR:** Free to use, modify, and distribute. Just don't blame us if something breaks. 😊

---

## ⚠️ Legal Notice

**null.log is designed for DEFENSIVE SECURITY only.**

✅ **Authorized Use:**
- Your own systems
- Systems you have permission to monitor
- Security research labs
- Educational purposes

❌ **Unauthorized Use:**
- Other people's systems without permission
- Violating privacy laws
- Corporate espionage
- Any illegal activity

**Using this tool on systems you don't own or have permission to monitor may violate local, state, or federal laws.**

---

<p align="center">
  <b>From first hack to first blue-team job.</b><br>
  Made with ❤️ by the security community, for the security community.
</p>

<p align="center">
  ⭐ Star us on GitHub if this tool helped you! ⭐
</p>
