#!/bin/bash
#
# Server Security Hardening Script v1.0
# Secures SSH, firewall, and installs monitoring
#
# Usage: sudo ./harden.sh [YOUR_IP]
#
# Example: sudo ./harden.sh 123.45.67.89
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
echo "=============================================="
echo "   SERVER SECURITY HARDENING v1.0"
echo "=============================================="
echo -e "${NC}"

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root (sudo ./harden.sh)${NC}"
    exit 1
fi

# Get user's IP for whitelisting
YOUR_IP="$1"
if [ -z "$YOUR_IP" ]; then
    echo -e "${YELLOW}No IP provided for whitelisting.${NC}"
    echo "Usage: sudo ./harden.sh YOUR_IP"
    echo ""
    read -p "Enter your IP to whitelist (or press Enter to skip): " YOUR_IP
fi

echo ""
echo "Starting security hardening..."
echo ""

# 1. Update system
echo -e "${BLUE}[1/8] Updating system packages...${NC}"
apt-get update -qq
apt-get upgrade -y -qq
echo -e "${GREEN}Done${NC}"

# 2. Install security tools
echo -e "${BLUE}[2/8] Installing security tools...${NC}"
apt-get install -y -qq fail2ban iptables-persistent net-tools > /dev/null 2>&1 || true
echo -e "${GREEN}Done${NC}"

# 3. Configure fail2ban
echo -e "${BLUE}[3/8] Configuring fail2ban...${NC}"

JAIL_LOCAL="/etc/fail2ban/jail.local"
cat > "$JAIL_LOCAL" << EOF
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1 ${YOUR_IP}
bantime = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled = true
port = 22,2222
maxretry = 5
bantime = 1h

[sshd-aggressive]
enabled = true
port = 22,2222
filter = sshd
logpath = %(sshd_log)s
maxretry = 3
bantime = 24h
EOF

systemctl enable fail2ban > /dev/null 2>&1
systemctl restart fail2ban > /dev/null 2>&1
echo -e "${GREEN}Done - Your IP ($YOUR_IP) is whitelisted${NC}"

# 4. Configure firewall
echo -e "${BLUE}[4/8] Configuring firewall...${NC}"

# Whitelist user IP first
if [ -n "$YOUR_IP" ]; then
    iptables -I INPUT 1 -s "$YOUR_IP" -j ACCEPT 2>/dev/null || true
fi

# Block known attacker IPs (from our real attack)
ATTACKER_IPS="104.233.162.77 137.184.202.107 157.245.71.230"
for ip in $ATTACKER_IPS; do
    iptables -A INPUT -s "$ip" -j DROP 2>/dev/null || true
done

# Block dangerous ports from public access
DANGEROUS_PORTS="5555 5556 27017 6379"
for port in $DANGEROUS_PORTS; do
    iptables -A INPUT -p tcp --dport "$port" -j DROP 2>/dev/null || true
done

# Save rules
netfilter-persistent save > /dev/null 2>&1 || iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
echo -e "${GREEN}Done${NC}"

# 5. Secure SSH
echo -e "${BLUE}[5/8] Securing SSH configuration...${NC}"

SSHD_CONFIG="/etc/ssh/sshd_config"
if [ -f "$SSHD_CONFIG" ]; then
    # Backup original
    cp "$SSHD_CONFIG" "${SSHD_CONFIG}.backup.$(date +%Y%m%d)"

    # Apply security settings (only if not already set)
    grep -q "^PermitRootLogin" "$SSHD_CONFIG" || echo "PermitRootLogin prohibit-password" >> "$SSHD_CONFIG"
    grep -q "^MaxAuthTries" "$SSHD_CONFIG" || echo "MaxAuthTries 3" >> "$SSHD_CONFIG"
    grep -q "^PasswordAuthentication" "$SSHD_CONFIG" || echo "PasswordAuthentication yes" >> "$SSHD_CONFIG"

    systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
fi
echo -e "${GREEN}Done${NC}"

# 6. Create security monitoring agent
echo -e "${BLUE}[6/8] Installing security monitoring agent...${NC}"

AGENT_SCRIPT="/opt/security-agent.sh"
cat > "$AGENT_SCRIPT" << 'EOF'
#!/bin/bash
# Security Agent - Auto-detects and kills malware
LOG="/var/log/security-agent.log"
MALWARE_PATTERNS="xmrig|c3pool|cryptonight|minerd|kdevtmpfsi|kinsing"
BAD_DIRS="/usr/local/rsyslo /root/c3pool /var/tmp/trufflehog /opt/openssh_service"

while true; do
    # Check for malware processes
    FOUND=$(ps aux | grep -iE "$MALWARE_PATTERNS" | grep -v grep | grep -v security-agent)
    if [ -n "$FOUND" ]; then
        echo "[$(date)] THREAT DETECTED:" >> $LOG
        echo "$FOUND" >> $LOG
        pkill -9 -f "$MALWARE_PATTERNS" 2>/dev/null
        echo "[$(date)] Killed malware processes" >> $LOG
    fi

    # Remove known bad directories
    for DIR in $BAD_DIRS; do
        if [ -d "$DIR" ]; then
            rm -rf "$DIR" 2>/dev/null
            echo "[$(date)] Removed: $DIR" >> $LOG
        fi
    done

    sleep 30
done
EOF

chmod +x "$AGENT_SCRIPT"

# Create systemd service
cat > /etc/systemd/system/security-agent.service << EOF
[Unit]
Description=Security Agent - Auto-detects and kills malware
After=network.target

[Service]
Type=simple
ExecStart=/opt/security-agent.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable security-agent > /dev/null 2>&1
systemctl start security-agent
echo -e "${GREEN}Done - Agent running 24/7${NC}"

# 7. Disable unnecessary services
echo -e "${BLUE}[7/8] Disabling unnecessary services...${NC}"
UNNECESSARY="cups avahi-daemon bluetooth"
for svc in $UNNECESSARY; do
    systemctl disable "$svc" 2>/dev/null || true
    systemctl stop "$svc" 2>/dev/null || true
done
echo -e "${GREEN}Done${NC}"

# 8. Create port registry
echo -e "${BLUE}[8/8] Creating port registry...${NC}"

PORTS_FILE="/home/ubuntu/PORTS.md"
if [ ! -f "$PORTS_FILE" ]; then
    cat > "$PORTS_FILE" << 'EOF'
# Port Registry

Track all ports used by your applications.

| Port | App | Status |
|------|-----|--------|
| 22   | SSH | System |
| 80   | Nginx HTTP | System |
| 443  | Nginx HTTPS | System |
| 3000 | Reserved | - |

## Rules
- All apps bind to 127.0.0.1 (localhost)
- Nginx handles public traffic
- Never expose database ports publicly (5555, 5556, 27017, 6379)

## Next available port: 3001
EOF
    echo -e "${GREEN}Created $PORTS_FILE${NC}"
else
    echo -e "${GREEN}Port registry already exists${NC}"
fi

# Summary
echo ""
echo -e "${BLUE}=============================================="
echo "   HARDENING COMPLETE"
echo "==============================================${NC}"
echo ""
echo -e "${GREEN}Security measures applied:${NC}"
echo "  - Fail2ban configured and running"
echo "  - Firewall rules applied"
echo "  - SSH hardened"
echo "  - Security agent running 24/7"
echo "  - Known attacker IPs blocked"
echo "  - Dangerous ports blocked"
if [ -n "$YOUR_IP" ]; then
    echo -e "  - Your IP whitelisted: ${GREEN}$YOUR_IP${NC}"
fi
echo ""
echo "Logs: /var/log/security-agent.log"
echo ""
echo -e "${YELLOW}IMPORTANT: Test SSH login in a NEW terminal before closing this session!${NC}"
echo ""
