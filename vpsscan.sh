#!/bin/bash



echo "================================================"
echo "       VPS SYSTEM COMPREHENSIVE SCAN REPORT     "
echo "================================================"
echo "Scan Date: $(date)"
echo "Hostname: $(hostname)"
echo "================================================"

echo -e "\n🖥️  SYSTEM INFORMATION"
echo "----------------------------------------"
echo "OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)"
echo "Kernel: $(uname -r)"
echo "Architecture: $(uname -m)"
echo "Uptime: $(uptime -p)"
echo "Load Average: $(uptime | awk -F'load average:' '{print $2}')"

echo -e "\n💾 HARDWARE RESOURCES"
echo "----------------------------------------"
echo "CPU Info: $(lscpu | grep 'Model name' | cut -d':' -f2 | xargs)"
echo "CPU Cores: $(nproc)"
echo "Total Memory: $(free -h | awk '/^Mem:/ {print $2}')"
echo "Available Memory: $(free -h | awk '/^Mem:/ {print $7}')"
echo "Disk Usage:"
df -h | grep -E '^/dev/' | awk '{print "  " $1 " -> " $3 "/" $2 " (" $5 " used)"}'

echo -e "\n🌐 NETWORK CONFIGURATION"
echo "----------------------------------------"
echo "Network Interfaces:"
ip addr show | grep -E '^[0-9]+:' | awk '{print "  " $2}' | sed 's/://'
echo "Active IP Addresses:"
ip addr show | grep 'inet ' | grep -v '127.0.0.1' | awk '{print "  " $2}' | cut -d'/' -f1

echo -e "\n👥 SYSTEM USERS"
echo "----------------------------------------"
echo "Total Users: $(cat /etc/passwd | wc -l)"
echo "Human Users (UID >= 1000):"
awk -F: '$3 >= 1000 {print "  " $1 " (UID: " $3 ", Shell: " $7 ")"}' /etc/passwd
echo "System Users (UID < 1000):"
awk -F: '$3 < 1000 && $3 != 0 {print "  " $1 " (UID: " $3 ")"}' /etc/passwd | head -10
echo "  ... (showing first 10, total: $(awk -F: '$3 < 1000 && $3 != 0' /etc/passwd | wc -l))"

echo -e "\n🔐 ACTIVE SESSIONS"
echo "----------------------------------------"
w | head -1
w | tail -n +2 | awk '{print "  User: " $1 ", TTY: " $2 ", Login: " $4 " " $5 ", Activity: " $6}'

echo -e "\n⚙️  SYSTEM SERVICES"
echo "----------------------------------------"
echo "Active Services:"
systemctl list-units --type=service --state=active --no-pager --no-legend | awk '{print "  ✓ " $1}' | head -20
echo "  ... (showing first 20 services)"
echo "Total Active Services: $(systemctl list-units --type=service --state=active --no-pager --no-legend | wc -l)"

echo -e "\nFailed Services:"
systemctl list-units --type=service --state=failed --no-pager --no-legend | awk '{print "  ✗ " $1}'

echo -e "\n🔌 LISTENING PORTS & SERVICES"
echo "----------------------------------------"
echo "TCP Ports:"
netstat -tlnp 2>/dev/null | grep LISTEN | awk '{print "  Port " $4 " -> " $7}' | sed 's/:::/0.0.0.0:/' | sort -t: -k2 -n
echo -e "\nUDP Ports:"
netstat -ulnp 2>/dev/null | awk 'NR>2 {print "  Port " $4 " -> " $6}' | head -10

echo -e "\n📦 INSTALLED SOFTWARE"
echo "----------------------------------------"
if command -v dpkg &> /dev/null; then
    echo "Total Packages (dpkg): $(dpkg -l | grep '^ii' | wc -l)"
    echo "Recently Installed (last 10):"
    dpkg -l | grep '^ii' | tail -10 | awk '{print "  " $2 " (" $3 ")"}'
elif command -v rpm &> /dev/null; then
    echo "Total Packages (rpm): $(rpm -qa | wc -l)"
    echo "Recently Installed (last 10):"
    rpm -qa --last | head -10 | awk '{print "  " $1}'
fi

echo -e "\n🔄 RUNNING PROCESSES"
echo "----------------------------------------"
echo "Total Processes: $(ps aux | wc -l)"
echo "Top CPU Consumers:"
ps aux --sort=-%cpu | head -6 | tail -5 | awk '{print "  " $11 " (CPU: " $3 "%, MEM: " $4 "%, PID: " $2 ")"}'
echo "Top Memory Consumers:"
ps aux --sort=-%mem | head -6 | tail -5 | awk '{print "  " $11 " (MEM: " $4 "%, CPU: " $3 "%, PID: " $2 ")"}'

if command -v docker &> /dev/null; then
    echo -e "\n🐳 DOCKER CONTAINERS"
    echo "----------------------------------------"
    echo "Running Containers: $(docker ps | tail -n +2 | wc -l)"
    if [ $(docker ps | tail -n +2 | wc -l) -gt 0 ]; then
        docker ps --format "  {{.Names}} ({{.Image}}) - {{.Status}}"
    fi
    echo "Total Images: $(docker images | tail -n +2 | wc -l)"
fi

echo -e "\n🌍 WEB SERVERS"
echo "----------------------------------------"
for service in apache2 httpd nginx; do
    if systemctl is-active --quiet $service 2>/dev/null; then
        echo "  ✓ $service is running"
        if [ "$service" = "nginx" ]; then
            nginx -v 2>&1 | awk '{print "    Version: " $3}'
        elif [ "$service" = "apache2" ] || [ "$service" = "httpd" ]; then
            $service -v 2>/dev/null | head -1 | awk '{print "    Version: " $3}'
        fi
    fi
done

echo -e "\n🗄️  DATABASE SERVERS"
echo "----------------------------------------"
for db in mysql mariadb postgresql mongod redis-server; do
    if systemctl is-active --quiet $db 2>/dev/null; then
        echo "  ✓ $db is running"
    fi
done

echo -e "\n🔒 SECURITY STATUS"
echo "----------------------------------------"
echo "Firewall Status:"
if command -v ufw &> /dev/null; then
    ufw status | head -3 | sed 's/^/  /'
elif command -v firewall-cmd &> /dev/null; then
    echo "  FirewallD: $(firewall-cmd --state 2>/dev/null || echo 'not running')"
elif command -v iptables &> /dev/null; then
    iptables_rules=$(iptables -L | wc -l)
    echo "  iptables rules: $iptables_rules"
fi

echo "SSH Status:"
if systemctl is-active --quiet ssh 2>/dev/null || systemctl is-active --quiet sshd 2>/dev/null; then
    echo "  ✓ SSH service is running"
    ssh_port=$(netstat -tlnp 2>/dev/null | grep sshd | awk '{print $4}' | cut -d':' -f2 | head -1)
    echo "  SSH Port: ${ssh_port:-22}"
else
    echo "  ✗ SSH service not detected"
fi

echo -e "\n⏰ SCHEDULED TASKS"
echo "----------------------------------------"
echo "System Crontabs:"
if [ -f /etc/crontab ]; then
    grep -v '^#' /etc/crontab | grep -v '^$' | wc -l | awk '{print "  /etc/crontab entries: " $1}'
fi
for user in $(cut -f1 -d: /etc/passwd); do
    if crontab -l -u $user 2>/dev/null | grep -v '^#' | grep -v '^$' | wc -l | grep -v '^0$' >/dev/null; then
        entries=$(crontab -l -u $user 2>/dev/null | grep -v '^#' | grep -v '^$' | wc -l)
        echo "  User $user: $entries cron jobs"
    fi
done

echo -e "\n📋 LOG FILES"
echo "----------------------------------------"
echo "Large Log Files (>10MB):"
find /var/log -type f -size +10M -exec ls -lh {} \; 2>/dev/null | awk '{print "  " $9 " (" $5 ")"}'

echo -e "\n================================================"
echo "           SCAN COMPLETED SUCCESSFULLY           "
echo "================================================"
echo "Report generated on: $(date)"
echo "For detailed analysis of any section, run specific commands manually."
