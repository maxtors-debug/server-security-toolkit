#!/bin/bash
#
# Security Audit Script v1.0
# Generates a complete security report
#
# Usage: sudo ./audit.sh
#

# Output file
REPORT="/tmp/security-audit-$(date +%Y%m%d-%H%M%S).txt"

# Colors (for terminal)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}Generating security audit report...${NC}"

{
echo "=============================================="
echo "   SECURITY AUDIT REPORT"
echo "   Generated: $(date)"
echo "   Hostname: $(hostname)"
echo "=============================================="
echo ""

echo "## SYSTEM INFO"
echo "=============================================="
echo "OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)"
echo "Kernel: $(uname -r)"
echo "Uptime: $(uptime -p)"
echo ""

echo "## USERS WITH LOGIN SHELL"
echo "=============================================="
grep -v '/nologin\|/false' /etc/passwd | cut -d: -f1,7
echo ""

echo "## SUDO USERS"
echo "=============================================="
getent group sudo | cut -d: -f4
echo ""

echo "## SSH AUTHORIZED KEYS"
echo "=============================================="
for home in /root /home/*; do
    if [ -f "$home/.ssh/authorized_keys" ]; then
        echo "$home/.ssh/authorized_keys:"
        cat "$home/.ssh/authorized_keys" | while read key; do
            echo "  - $(echo "$key" | awk '{print $3}')"
        done
    fi
done
echo ""

echo "## LISTENING PORTS"
echo "=============================================="
netstat -tlnp 2>/dev/null | grep LISTEN || ss -tlnp | grep LISTEN
echo ""

echo "## ESTABLISHED CONNECTIONS"
echo "=============================================="
netstat -tn 2>/dev/null | grep ESTABLISHED | head -20 || ss -tn | grep ESTAB | head -20
echo ""

echo "## FIREWALL STATUS"
echo "=============================================="
if command -v ufw &> /dev/null; then
    ufw status verbose
else
    iptables -L -n | head -30
fi
echo ""

echo "## FAIL2BAN STATUS"
echo "=============================================="
if command -v fail2ban-client &> /dev/null; then
    fail2ban-client status 2>/dev/null
    echo ""
    fail2ban-client status sshd 2>/dev/null
else
    echo "fail2ban not installed"
fi
echo ""

echo "## RUNNING SERVICES"
echo "=============================================="
systemctl list-units --type=service --state=running | head -30
echo ""

echo "## CRON JOBS (ALL USERS)"
echo "=============================================="
for user in $(cut -f1 -d: /etc/passwd); do
    cron=$(crontab -l -u "$user" 2>/dev/null)
    if [ -n "$cron" ]; then
        echo "=== $user ==="
        echo "$cron"
    fi
done
echo ""

echo "## RECENT AUTH FAILURES (Last 20)"
echo "=============================================="
grep -i "failed\|invalid" /var/log/auth.log 2>/dev/null | tail -20
echo ""

echo "## RECENT SUCCESSFUL LOGINS"
echo "=============================================="
last -n 10
echo ""

echo "## TOP PROCESSES BY CPU"
echo "=============================================="
ps aux --sort=-%cpu | head -10
echo ""

echo "## TOP PROCESSES BY MEMORY"
echo "=============================================="
ps aux --sort=-%mem | head -10
echo ""

echo "## DISK USAGE"
echo "=============================================="
df -h | grep -v tmpfs
echo ""

echo "## WORLD-WRITABLE FILES IN /etc"
echo "=============================================="
find /etc -perm -002 -type f 2>/dev/null | head -20
echo ""

echo "## SUID/SGID BINARIES"
echo "=============================================="
find /usr -perm -4000 -o -perm -2000 2>/dev/null | head -20
echo ""

echo "## SECURITY RECOMMENDATIONS"
echo "=============================================="

# Check root SSH login
if grep -q "^PermitRootLogin yes" /etc/ssh/sshd_config 2>/dev/null; then
    echo "[!] CRITICAL: Root SSH login is enabled"
fi

# Check password auth
if grep -q "^PasswordAuthentication yes" /etc/ssh/sshd_config 2>/dev/null; then
    echo "[!] WARNING: Password authentication is enabled"
fi

# Check fail2ban
if ! systemctl is-active fail2ban > /dev/null 2>&1; then
    echo "[!] WARNING: fail2ban is not running"
fi

# Check firewall
if ! iptables -L INPUT -n 2>/dev/null | grep -q "DROP\|REJECT"; then
    echo "[!] WARNING: No DROP/REJECT rules in firewall"
fi

# Check exposed ports
if netstat -tln 2>/dev/null | grep -E "0.0.0.0:(5555|5556|27017|6379)" > /dev/null; then
    echo "[!] CRITICAL: Database ports exposed publicly"
fi

echo ""
echo "=============================================="
echo "   END OF AUDIT REPORT"
echo "=============================================="
} > "$REPORT"

echo -e "${GREEN}Report saved to: $REPORT${NC}"
echo ""
echo "View with: cat $REPORT"
echo "Or: less $REPORT"
