#!/bin/bash
#
# Server Security Scanner v1.0
# Detects crypto miners, backdoors, and common malware
#
# Usage: sudo ./scan.sh
#
# Created after surviving a real attack from Tokyo, Japan
# Free to use - help others stay safe!

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
THREATS=0
WARNINGS=0

echo -e "${BLUE}"
echo "=============================================="
echo "   SERVER SECURITY SCANNER v1.0"
echo "=============================================="
echo -e "${NC}"
echo "Scanning for malware, backdoors, and threats..."
echo ""

# Function to report threat
threat() {
    echo -e "${RED}[THREAT]${NC} $1"
    ((THREATS++))
}

# Function to report warning
warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
    ((WARNINGS++))
}

# Function to report OK
ok() {
    echo -e "${GREEN}[OK]${NC} $1"
}

# 1. Check for known malware processes
echo -e "${BLUE}[1/10] Checking for malware processes...${NC}"
MALWARE_PATTERNS="xmrig|c3pool|cryptonight|minerd|kdevtmpfsi|kinsing|solr\.sh|ld\.so\.preload|rsyslo[^g]|masscan|zgrab"

FOUND=$(ps aux | grep -iE "$MALWARE_PATTERNS" | grep -v grep | grep -v "scan.sh" || true)
if [ -n "$FOUND" ]; then
    threat "Malware processes detected!"
    echo "$FOUND"
else
    ok "No known malware processes"
fi

# 2. Check for crypto mining connections
echo -e "${BLUE}[2/10] Checking for mining pool connections...${NC}"
MINING_POOLS="c3pool|nanopool|f2pool|minexmr|supportxmr|hashvault|moneroocean"

MINING=$(netstat -tn 2>/dev/null | grep -iE "$MINING_POOLS" || ss -tn 2>/dev/null | grep -iE "$MINING_POOLS" || true)
if [ -n "$MINING" ]; then
    threat "Connection to mining pool detected!"
    echo "$MINING"
else
    ok "No mining pool connections"
fi

# 3. Check for suspicious systemd services
echo -e "${BLUE}[3/10] Checking systemd services...${NC}"
SUSPICIOUS_SERVICES="miner|c3pool|xmrig|crypto|rsyslo[^g]"

SERVICES=$(systemctl list-units --type=service --all 2>/dev/null | grep -iE "$SUSPICIOUS_SERVICES" || true)
if [ -n "$SERVICES" ]; then
    threat "Suspicious systemd services found!"
    echo "$SERVICES"
else
    ok "No suspicious systemd services"
fi

# 4. Check for suspicious cron jobs
echo -e "${BLUE}[4/10] Checking cron jobs...${NC}"
CRON_THREATS=0

for user in $(cut -f1 -d: /etc/passwd); do
    CRON=$(crontab -l -u "$user" 2>/dev/null | grep -iE "curl|wget|\.sh|python|perl|nc |ncat|bash" | grep -v "^#" || true)
    if [ -n "$CRON" ]; then
        warning "Suspicious cron for user $user:"
        echo "$CRON"
        ((CRON_THREATS++))
    fi
done

# Check system cron directories
for dir in /etc/cron.d /etc/cron.daily /etc/cron.hourly; do
    if [ -d "$dir" ]; then
        SUSPICIOUS=$(ls -la "$dir" 2>/dev/null | grep -vE "^total|^\.|anacron|logrotate|apt|dpkg|man-db|popularity|update-notifier" || true)
        if [ -n "$SUSPICIOUS" ]; then
            warning "Check cron directory $dir"
        fi
    fi
done

if [ $CRON_THREATS -eq 0 ]; then
    ok "No suspicious cron jobs"
fi

# 5. Check for exposed database ports
echo -e "${BLUE}[5/10] Checking for exposed database ports...${NC}"
EXPOSED_PORTS=""

# Check Prisma Studio (5555, 5556)
if netstat -tln 2>/dev/null | grep -E ":555[56].*0\.0\.0\.0" > /dev/null || ss -tln 2>/dev/null | grep -E ":555[56].*0\.0\.0\.0" > /dev/null; then
    threat "Prisma Studio exposed on 0.0.0.0 (CRITICAL!)"
    EXPOSED_PORTS="yes"
fi

# Check MongoDB (27017)
if netstat -tln 2>/dev/null | grep -E ":27017.*0\.0\.0\.0" > /dev/null || ss -tln 2>/dev/null | grep -E ":27017.*0\.0\.0\.0" > /dev/null; then
    warning "MongoDB exposed on 0.0.0.0"
    EXPOSED_PORTS="yes"
fi

# Check Redis (6379)
if netstat -tln 2>/dev/null | grep -E ":6379.*0\.0\.0\.0" > /dev/null || ss -tln 2>/dev/null | grep -E ":6379.*0\.0\.0\.0" > /dev/null; then
    warning "Redis exposed on 0.0.0.0"
    EXPOSED_PORTS="yes"
fi

if [ -z "$EXPOSED_PORTS" ]; then
    ok "No dangerous database ports exposed"
fi

# 6. Check for backdoor files
echo -e "${BLUE}[6/10] Checking for backdoor files...${NC}"
BACKDOOR_PATHS=(
    "/usr/local/rsyslo"
    "/root/c3pool"
    "/var/tmp/trufflehog"
    "/opt/openssh_service"
    "/tmp/.X11-unix/.x"
    "/dev/shm/.x"
    "/usr/bin/sshd-agent"
)

BACKDOORS_FOUND=0
for path in "${BACKDOOR_PATHS[@]}"; do
    if [ -e "$path" ]; then
        threat "Backdoor file/directory found: $path"
        ((BACKDOORS_FOUND++))
    fi
done

if [ $BACKDOORS_FOUND -eq 0 ]; then
    ok "No known backdoor files"
fi

# 7. Check for unauthorized SSH keys
echo -e "${BLUE}[7/10] Checking SSH authorized_keys...${NC}"
for user_home in /root /home/*; do
    if [ -f "$user_home/.ssh/authorized_keys" ]; then
        KEYS=$(wc -l < "$user_home/.ssh/authorized_keys")
        if [ "$KEYS" -gt 5 ]; then
            warning "$user_home has $KEYS SSH keys - verify these are legitimate"
        fi
    fi
done
ok "SSH keys checked"

# 8. Check for high CPU processes
echo -e "${BLUE}[8/10] Checking for high CPU usage...${NC}"
HIGH_CPU=$(ps aux --sort=-%cpu | head -5 | tail -4 | awk '$3 > 80 {print $0}')
if [ -n "$HIGH_CPU" ]; then
    warning "High CPU processes detected:"
    echo "$HIGH_CPU"
else
    ok "No abnormally high CPU usage"
fi

# 9. Check for suspicious network connections
echo -e "${BLUE}[9/10] Checking outbound connections...${NC}"
SUSPICIOUS_PORTS="4444|5555|6666|7777|8888|9999|1337|31337"
SUSPICIOUS_CONN=$(netstat -tn 2>/dev/null | grep ESTABLISHED | grep -E ":($SUSPICIOUS_PORTS)" || ss -tn 2>/dev/null | grep -E ":($SUSPICIOUS_PORTS)" || true)

if [ -n "$SUSPICIOUS_CONN" ]; then
    warning "Connections on suspicious ports:"
    echo "$SUSPICIOUS_CONN"
else
    ok "No suspicious port connections"
fi

# 10. Check firewall status
echo -e "${BLUE}[10/10] Checking firewall...${NC}"
if command -v ufw &> /dev/null; then
    UFW_STATUS=$(ufw status 2>/dev/null | head -1)
    if echo "$UFW_STATUS" | grep -q "inactive"; then
        warning "UFW firewall is INACTIVE"
    else
        ok "UFW firewall is active"
    fi
elif command -v iptables &> /dev/null; then
    RULES=$(iptables -L INPUT -n 2>/dev/null | wc -l)
    if [ "$RULES" -lt 5 ]; then
        warning "Very few iptables rules - firewall may be open"
    else
        ok "iptables has rules configured"
    fi
else
    warning "No firewall detected"
fi

# Summary
echo ""
echo -e "${BLUE}=============================================="
echo "   SCAN COMPLETE"
echo "==============================================${NC}"
echo ""

if [ $THREATS -gt 0 ]; then
    echo -e "${RED}THREATS FOUND: $THREATS${NC}"
    echo -e "${RED}ACTION REQUIRED: Run ./cleanup.sh to remove malware${NC}"
elif [ $WARNINGS -gt 0 ]; then
    echo -e "${YELLOW}WARNINGS: $WARNINGS${NC}"
    echo -e "${YELLOW}Review the warnings above and take action if needed${NC}"
else
    echo -e "${GREEN}ALL CLEAR - No threats detected!${NC}"
fi

echo ""
echo "For hardening, run: sudo ./harden.sh"
echo "For monitoring, run: sudo ./monitor.sh"
echo ""

exit $THREATS
