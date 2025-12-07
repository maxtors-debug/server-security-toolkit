#!/bin/bash
#
# Security Monitor v1.0
# Real-time monitoring for threats
#
# Usage: sudo ./monitor.sh
#

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

clear
echo -e "${BLUE}"
echo "=============================================="
echo "   SECURITY MONITOR v1.0"
echo "   Press Ctrl+C to exit"
echo "=============================================="
echo -e "${NC}"

# Malware patterns
MALWARE="xmrig|c3pool|cryptonight|minerd|kdevtmpfsi|kinsing|rsyslo[^g]"

check_count=0

while true; do
    ((check_count++))

    # Clear previous output (keep header)
    tput cup 6 0

    echo -e "${BLUE}[Check #$check_count - $(date '+%H:%M:%S')]${NC}"
    echo "----------------------------------------"

    # 1. Check CPU
    CPU=$(top -bn1 | grep "Cpu(s)" | awk '{print 100 - $8}' | cut -d. -f1)
    if [ "$CPU" -gt 80 ]; then
        echo -e "CPU Usage: ${RED}${CPU}% (HIGH!)${NC}"
    else
        echo -e "CPU Usage: ${GREEN}${CPU}%${NC}"
    fi

    # 2. Check for malware processes
    MALWARE_FOUND=$(ps aux | grep -iE "$MALWARE" | grep -v grep | grep -v monitor.sh | wc -l)
    if [ "$MALWARE_FOUND" -gt 0 ]; then
        echo -e "Malware:   ${RED}$MALWARE_FOUND DETECTED!${NC}"
        ps aux | grep -iE "$MALWARE" | grep -v grep | grep -v monitor.sh
    else
        echo -e "Malware:   ${GREEN}None detected${NC}"
    fi

    # 3. Check suspicious connections
    SUSPICIOUS=$(netstat -tn 2>/dev/null | grep -E ":4444|:5555|:6666|:1337" | wc -l)
    if [ "$SUSPICIOUS" -gt 0 ]; then
        echo -e "Suspicious Connections: ${RED}$SUSPICIOUS${NC}"
    else
        echo -e "Suspicious Connections: ${GREEN}0${NC}"
    fi

    # 4. Check fail2ban
    BANNED=$(fail2ban-client status sshd 2>/dev/null | grep "Currently banned" | awk '{print $4}')
    echo -e "IPs Banned: ${YELLOW}${BANNED:-0}${NC}"

    # 5. Check security agent
    if systemctl is-active security-agent > /dev/null 2>&1; then
        echo -e "Security Agent: ${GREEN}Running${NC}"
    else
        echo -e "Security Agent: ${RED}Stopped!${NC}"
    fi

    # 6. Active SSH sessions
    SSH_SESSIONS=$(who | wc -l)
    echo -e "SSH Sessions: ${YELLOW}$SSH_SESSIONS${NC}"

    # 7. Last failed login
    LAST_FAIL=$(grep "Failed password" /var/log/auth.log 2>/dev/null | tail -1 | awk '{print $1, $2, $3, $9, $11}')
    if [ -n "$LAST_FAIL" ]; then
        echo -e "Last Failed Login: $LAST_FAIL"
    fi

    echo "----------------------------------------"
    echo -e "${BLUE}Refreshing every 5 seconds...${NC}"

    sleep 5
done
