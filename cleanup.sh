#!/bin/bash
#
# Malware Cleanup Script v1.0
# Removes known crypto miners, backdoors, and malware
#
# Usage: sudo ./cleanup.sh
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${RED}"
echo "=============================================="
echo "   MALWARE CLEANUP SCRIPT v1.0"
echo "=============================================="
echo -e "${NC}"

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root (sudo ./cleanup.sh)${NC}"
    exit 1
fi

echo -e "${YELLOW}WARNING: This will kill processes and delete files!${NC}"
read -p "Continue? (y/N): " confirm
if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
    echo "Aborted."
    exit 0
fi

REMOVED=0

# 1. Kill malware processes
echo ""
echo -e "${BLUE}[1/6] Killing malware processes...${NC}"

MALWARE_PROCS="xmrig|c3pool|cryptonight|minerd|kdevtmpfsi|kinsing|rsyslo[^g]|masscan|trufflehog"

# Get PIDs
PIDS=$(ps aux | grep -iE "$MALWARE_PROCS" | grep -v grep | grep -v cleanup.sh | awk '{print $2}')

if [ -n "$PIDS" ]; then
    for pid in $PIDS; do
        kill -9 "$pid" 2>/dev/null && echo "  Killed PID $pid" && ((REMOVED++))
    done
else
    echo "  No malware processes found"
fi

# 2. Remove malware systemd services
echo ""
echo -e "${BLUE}[2/6] Removing malware systemd services...${NC}"

MALWARE_SERVICES=(
    "c3pool_miner"
    "rsyslo"
    "xmrig"
    "cryptominer"
    "kinsing"
    "sshd-agent"
)

for svc in "${MALWARE_SERVICES[@]}"; do
    if systemctl is-active "${svc}.service" > /dev/null 2>&1 || [ -f "/etc/systemd/system/${svc}.service" ]; then
        systemctl stop "${svc}.service" 2>/dev/null || true
        systemctl disable "${svc}.service" 2>/dev/null || true
        rm -f "/etc/systemd/system/${svc}.service"
        echo "  Removed ${svc}.service"
        ((REMOVED++))
    fi
done

systemctl daemon-reload

# 3. Remove malware files and directories
echo ""
echo -e "${BLUE}[3/6] Removing malware files...${NC}"

MALWARE_PATHS=(
    "/usr/local/rsyslo"
    "/root/c3pool"
    "/var/tmp/trufflehog"
    "/opt/openssh_service"
    "/tmp/.X11-unix/.x"
    "/dev/shm/.x"
    "/dev/shm/.r"
    "/tmp/.font-unix"
    "/var/tmp/.cache"
    "/usr/bin/sshd-agent"
    "/usr/bin/.sshd"
)

for path in "${MALWARE_PATHS[@]}"; do
    if [ -e "$path" ]; then
        # Remove immutable flag if present
        chattr -i "$path" 2>/dev/null || true
        rm -rf "$path"
        echo "  Removed $path"
        ((REMOVED++))
    fi
done

# 4. Check for hidden miners in common locations
echo ""
echo -e "${BLUE}[4/6] Checking hidden locations...${NC}"

HIDDEN_LOCATIONS=(
    "/dev/shm"
    "/var/tmp"
    "/tmp"
    "/run/user"
)

for loc in "${HIDDEN_LOCATIONS[@]}"; do
    if [ -d "$loc" ]; then
        # Find suspicious executables
        SUSPICIOUS=$(find "$loc" -type f -executable -name ".*" 2>/dev/null || true)
        for file in $SUSPICIOUS; do
            echo "  Found hidden executable: $file"
            rm -f "$file" && ((REMOVED++))
        done
    fi
done

# 5. Remove malicious cron jobs
echo ""
echo -e "${BLUE}[5/6] Checking cron jobs...${NC}"

# Check each user's crontab for suspicious entries
for user in $(cut -f1 -d: /etc/passwd); do
    CRON=$(crontab -l -u "$user" 2>/dev/null || true)
    if echo "$CRON" | grep -qiE "xmrig|c3pool|miner|kinsing"; then
        echo "  Suspicious cron found for $user - clearing"
        crontab -r -u "$user" 2>/dev/null || true
        ((REMOVED++))
    fi
done

# Check /etc/cron.d for suspicious files
for file in /etc/cron.d/*; do
    if [ -f "$file" ]; then
        if grep -qiE "xmrig|c3pool|miner|kinsing|curl.*sh|wget.*sh" "$file" 2>/dev/null; then
            echo "  Removing suspicious cron file: $file"
            rm -f "$file"
            ((REMOVED++))
        fi
    fi
done

# 6. Block known attacker IPs
echo ""
echo -e "${BLUE}[6/6] Blocking known attacker IPs...${NC}"

ATTACKER_IPS=(
    "104.233.162.77"   # C2 Server - Tokyo, Japan
    "85.239.243.201"   # c3pool mining server
    "168.119.145.117"  # 0x0.st malware host
)

for ip in "${ATTACKER_IPS[@]}"; do
    if ! iptables -C INPUT -s "$ip" -j DROP 2>/dev/null; then
        iptables -A INPUT -s "$ip" -j DROP
        echo "  Blocked $ip"
    fi
done

# Save iptables
iptables-save > /etc/iptables/rules.v4 2>/dev/null || netfilter-persistent save 2>/dev/null || true

# Summary
echo ""
echo -e "${BLUE}=============================================="
echo "   CLEANUP COMPLETE"
echo "==============================================${NC}"
echo ""

if [ $REMOVED -gt 0 ]; then
    echo -e "${GREEN}Removed $REMOVED malware items${NC}"
else
    echo -e "${GREEN}No malware found to remove${NC}"
fi

echo ""
echo "Next steps:"
echo "  1. Run ./scan.sh to verify cleanup"
echo "  2. Run ./harden.sh to secure the server"
echo "  3. Rotate ALL passwords and API keys!"
echo "  4. Check for any data exfiltration"
echo ""
echo -e "${YELLOW}IMPORTANT: Change all passwords - attacker may have stolen credentials!${NC}"
echo ""
