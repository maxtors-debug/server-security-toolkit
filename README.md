# 🛡️ Server Security Toolkit

Emergency security tools for Linux servers. Created after surviving a real attack exploiting **CVE-2025-55182** (React Server Components RCE).

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CVSS](https://img.shields.io/badge/CVSS-10.0%20CRITICAL-red)](https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components)

---

## 🚀 Quick Start

```bash
# One-liner scan (no install needed)
curl -sSL https://raw.githubusercontent.com/maxtors-debug/server-security-toolkit/main/scan.sh | sudo bash

# Or clone and use all tools
git clone https://github.com/maxtors-debug/server-security-toolkit.git
cd server-security-toolkit
sudo ./scan.sh        # Scan for malware
sudo ./cleanup.sh     # Remove malware
sudo ./harden.sh      # Harden server security
sudo ./monitor.sh     # Real-time monitoring
sudo ./audit.sh       # Full security audit
```

---

## 🧰 Tools Included

| Script | Purpose |
|--------|---------|
| `scan.sh` | Detect crypto miners, backdoors, rootkits |
| `cleanup.sh` | Remove known malware families |
| `harden.sh` | Secure SSH, firewall, fail2ban setup |
| `monitor.sh` | 24/7 real-time monitoring |
| `audit.sh` | Generate full security report |

---

## 🔍 What It Detects

- ⛏️ Crypto miners (XMRig, c3pool, cryptonight, kinsing)
- 🚪 Backdoors (reverse shells, unauthorized SSH)
- 🔑 Credential scanners (TruffleHog, GitLeaks)
- ⚙️ Malicious systemd services
- 🌐 Exposed database ports (Prisma Studio, MongoDB, Redis)
- 📅 Unauthorized cron jobs
- 👻 Hidden processes

---

## 🔴 The Attack That Inspired This

### CVE-2025-55182 - React Server Components RCE

| Field | Value |
|-------|-------|
| **CVE** | CVE-2025-55182 |
| **CVSS Score** | 10.0 (CRITICAL) |
| **Attack Type** | Unauthenticated Remote Code Execution |
| **Attacker Location** | Tokyo, Japan 🇯🇵 |

### What Happened

Attackers exploited a critical vulnerability in React Server Components. They sent a malicious HTTP request to my Next.js server - **no password or authentication needed**. Within hours:

- 💀 XMRig crypto miner installed (CPU at 100%)
- 🚪 rsyslo backdoor for persistent access
- 📡 Reverse shell connecting to attacker's C2 server
- 🔑 TruffleHog scanning for credentials

### Affected Packages

Versions **19.0, 19.1.0, 19.1.1, 19.2.0** of:

- `react-server-dom-webpack`
- `react-server-dom-parcel`
- `react-server-dom-turbopack`

### Affected Frameworks

- Next.js
- React Router
- Waku
- @parcel/rsc
- @vitejs/plugin-rsc
- rwsdk (Redwood SDK)

### ⚠️ Fix NOW

```bash
npm install react@latest react-dom@latest react-server-dom-webpack@latest
```

**Fixed versions:** 19.0.1, 19.1.2, 19.2.1

> **Note:** If your app doesn't use React Server Components, you're NOT affected.

📖 Full details: [React Security Advisory](https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components)

---

## 📅 Timeline

| Date | Event |
|------|-------|
| Nov 29, 2025 | Vulnerability reported by Lachlan Davidson |
| Nov 30, 2025 | Meta security confirmed the issue |
| Dec 1, 2025 | Fix created, hosting providers notified |
| Dec 3, 2025 | Fix published to npm, CVE disclosed |
| Dec 5, 2025 | My server compromised |
| Dec 6, 2025 | Attack detected, cleaned, tools created |
| Dec 7, 2025 | This toolkit open-sourced |

---

## 🛡️ Prevention Tips

1. **Keep dependencies updated** - This attack used a 2-day old vulnerability
2. **Monitor CPU usage** - Crypto miners are noisy
3. **Use fail2ban** - Block brute force attempts
4. **Firewall everything** - Only expose necessary ports
5. **Rotate credentials** - Assume they're compromised after an attack
6. **Backup regularly** - You'll thank yourself later

---

## 🤝 Contributing

Found a new malware pattern? Open a PR! Let's help each other stay safe.

---

## 📜 License

MIT - Free to use, modify, share. **Stay safe!** 🔒

---

## ⭐ Support

If this helped you, consider:
- ⭐ Starring this repo
- 🔄 Sharing with other devs
- 🐛 Reporting new malware patterns

---

*Created with 💪 after surviving CVE-2025-55182*
