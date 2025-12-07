# Server Security Toolkit

Emergency security tools for Linux servers. Created after surviving a real crypto-mining attack.

## Quick Start

```bash
# Download and run scanner
curl -sSL https://raw.githubusercontent.com/YOUR_REPO/security-toolkit/main/scan.sh | sudo bash

# Or clone and use all tools
git clone https://github.com/YOUR_REPO/security-toolkit.git
cd security-toolkit
sudo ./scan.sh        # Scan for malware
sudo ./harden.sh      # Harden server security
sudo ./monitor.sh     # Start 24/7 monitoring
```

## Tools Included

| Script | Purpose |
|--------|---------|
| `scan.sh` | Detect crypto miners, backdoors, rootkits |
| `harden.sh` | Secure SSH, firewall, fail2ban setup |
| `monitor.sh` | 24/7 malware monitoring daemon |
| `cleanup.sh` | Remove known malware families |
| `audit.sh` | Full security audit report |

## What It Detects

- Crypto miners (XMRig, c3pool, cryptonight)
- Backdoors (reverse shells, unauthorized SSH)
- Credential scanners (TruffleHog, GitLeaks)
- Suspicious systemd services
- Exposed database ports (Prisma Studio, etc.)
- Unauthorized cron jobs
- Hidden processes

## Real Attack This Stopped

- **Attacker Location:** Tokyo, Japan
- **Attack Vector:** Exposed Prisma Studio (port 5555)
- **Malware:** XMRig miner, rsyslo backdoor
- **Impact:** 100% CPU, credential theft attempt
- **Result:** Detected, removed, server hardened

## License

MIT - Free to use, modify, share. Stay safe!
