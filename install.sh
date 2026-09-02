#!/usr/bin/env bash
# ==============================================================================
# PHP FreeBase — Automated Cybersecurity Training Lab Installer
# ==============================================================================
# Sets up a complete training laboratory on Debian (and multi-platform Linux/Termux):
#   - Port 80  : HTTP (automatically redirects to HTTPS port 443 for "security")
#   - Port 443 : HTTPS (Apache SSL VirtualHost with self-signed TLS cert)
#   - Port 3306: MySQL/MariaDB (binds to 0.0.0.0 for external/lab connectivity)
#   - Port 22  : OpenSSH Server (remote shell access with prompted password)
# Pre-seeds default lab accounts:
#   - root   / root     (Super Admin - manages web user roles & permissions)
#   - admin  / password (Administrator - security console & password reset)
#   - user   / user     (Standard User)
#   - hacker / hacker   (Standard User - test persona)
# ==============================================================================

set -e

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo -e "${CYAN}${BOLD}"
echo "=================================================================="
echo "      PHP FreeBase — Security Training Lab Setup & Deployment     "
echo "=================================================================="
echo -e "${NC}"
echo -e "${YELLOW}[!] WARNING: This installer is strictly intended for educational laboratories,"
echo -e "    CTF environments, and penetration testing benchmarks.${NC}"
echo ""

# ------------------------------------------------------------------------------
# 1. Environment & Privilege Verification
# ------------------------------------------------------------------------------
IS_TERMUX=false
if [ -n "$TERMUX_VERSION" ] || [ -d "/data/data/com.termux" ]; then
    IS_TERMUX=true
    echo -e "${BLUE}[*] Detected Android Termux environment.${NC}"
fi

if [ "$IS_TERMUX" = false ] && [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[ERROR] This installation script must be run as root (or with sudo).${NC}"
    echo -e "Usage: sudo bash install.sh"
    exit 1
fi

# Detect Package Manager
PKG_MANAGER=""
if command -v apt-get >/dev/null 2>&1; then
    PKG_MANAGER="apt"
elif command -v pkg >/dev/null 2>&1; then
    PKG_MANAGER="pkg"
elif command -v dnf >/dev/null 2>&1; then
    PKG_MANAGER="dnf"
elif command -v yum >/dev/null 2>&1; then
    PKG_MANAGER="yum"
elif command -v pacman >/dev/null 2>&1; then
    PKG_MANAGER="pacman"
elif command -v apk >/dev/null 2>&1; then
    PKG_MANAGER="apk"
else
    echo -e "${YELLOW}[!] Warning: Unrecognized package manager. Assuming manual dependencies.${NC}"
fi

echo -e "${GREEN}[+] Operating System / Package Manager: ${PKG_MANAGER:-Manual}${NC}"

# Detect Host IP
DEFAULT_IP=$(hostname -I 2>/dev/null | awk '{print $1}') || true
if [ -z "$DEFAULT_IP" ]; then
    DEFAULT_IP="127.0.0.1"
fi

# ------------------------------------------------------------------------------
# 2. Interactive Configuration Prompts
# ------------------------------------------------------------------------------
echo -e "${PURPLE}${BOLD}[1/7] Laboratory Configuration Parameters${NC}"

# Domain / Hostname
if [ -z "$LAB_DOMAIN" ]; then
    read -rp "Enter Domain or Server IP [Default: $DEFAULT_IP]: " input_domain
    LAB_DOMAIN="${input_domain:-$DEFAULT_IP}"
fi
echo -e "    -> Web Domain/IP: ${BOLD}$LAB_DOMAIN${NC}"

# SSH Password Prompt (Explicit User Requirement)
if [ -z "$SSH_PASSWORD" ]; then
    echo ""
    echo -e "${YELLOW}[?] Please set the password for the SSH account (${BOLD}root${NC}${YELLOW} / lab user):${NC}"
    read -rsp "Enter new SSH password: " input_ssh_pass
    echo ""
    while [ -z "$input_ssh_pass" ]; do
        echo -e "${RED}[!] SSH password cannot be empty for lab access.${NC}"
        read -rsp "Enter new SSH password: " input_ssh_pass
        echo ""
    done
    SSH_PASSWORD="$input_ssh_pass"
fi
echo -e "    -> SSH access password configured."

# MySQL Credentials Prompt (Explicit User Requirement)
if [ -z "$DB_USER" ]; then
    read -rp "Enter MySQL lab username [Default: freebase_user]: " input_db_user
    DB_USER="${input_db_user:-freebase_user}"
fi

if [ -z "$DB_PASS" ]; then
    echo ""
    read -rsp "Enter MySQL lab user password [Default: lab_db_pass]: " input_db_pass
    echo ""
    DB_PASS="${input_db_pass:-lab_db_pass}"
fi
DB_NAME="freebase"
DB_PORT="3306"
echo -e "    -> MySQL Lab Database: ${BOLD}$DB_NAME${NC}"
echo -e "    -> MySQL Lab User:     ${BOLD}$DB_USER${NC}"
echo ""

# ------------------------------------------------------------------------------
# 3. Install Required Packages (Debian / Linux / Termux)
# ------------------------------------------------------------------------------
echo -e "${PURPLE}${BOLD}[2/7] Installing System Dependencies & Services${NC}"

if [ "$PKG_MANAGER" = "apt" ]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y \
        apache2 \
        libapache2-mod-php \
        php \
        php-cli \
        php-mysql \
        php-mbstring \
        php-xml \
        php-curl \
        mariadb-server \
        openssh-server \
        openssl \
        ufw \
        curl \
        net-tools \
        iproute2
elif [ "$PKG_MANAGER" = "pkg" ]; then
    # Android Termux
    pkg update -y
    pkg install -y apache2 php php-apache mariadb openssh openssl curl
elif [ "$PKG_MANAGER" = "dnf" ] || [ "$PKG_MANAGER" = "yum" ]; then
    $PKG_MANAGER update -y
    $PKG_MANAGER install -y httpd php php-cli php-mysqlnd php-mbstring php-xml php-curl mariadb-server openssh-server openssl firewalld
elif [ "$PKG_MANAGER" = "pacman" ]; then
    pacman -Sy --noconfirm apache php php-apache mariadb openssh openssl
fi

echo -e "${GREEN}[+] Packages and runtime components installed successfully.${NC}"

# ------------------------------------------------------------------------------
# 4. Configure OpenSSH Server (Port 22)
# ------------------------------------------------------------------------------
echo -e "${PURPLE}${BOLD}[3/7] Configuring OpenSSH Server (Port 22)${NC}"

if [ "$IS_TERMUX" = false ]; then
    # Ensure sshd_config permits password authentication & root login if desired in lab
    SSHD_CONFIG="/etc/ssh/sshd_config"
    if [ -f "$SSHD_CONFIG" ]; then
        cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak"
        # Enable Port 22, PasswordAuthentication, and PermitRootLogin in lab
        sed -i 's/^#\?Port .*/Port 22/' "$SSHD_CONFIG" || true
        sed -i 's/^#\?PasswordAuthentication .*/PasswordAuthentication yes/' "$SSHD_CONFIG" || true
        sed -i 's/^#\?PermitRootLogin .*/PermitRootLogin yes/' "$SSHD_CONFIG" || true
    fi

    # Set root password for SSH
    echo "root:${SSH_PASSWORD}" | chpasswd 2>/dev/null || true

    # Optional: ensure a 'lab' user also exists with this password
    if ! id "lab" >/dev/null 2>&1; then
        useradd -m -s /bin/bash lab 2>/dev/null || true
    fi
    echo "lab:${SSH_PASSWORD}" | chpasswd 2>/dev/null || true

    # Enable and start SSH service
    systemctl enable ssh 2>/dev/null || systemctl enable sshd 2>/dev/null || true
    systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || service ssh restart 2>/dev/null || true
    echo -e "${GREEN}[+] SSH Server configured and running on port 22.${NC}"
else
    # Termux SSH configuration
    echo "root:${SSH_PASSWORD}" | passwd 2>/dev/null || true
    sshd 2>/dev/null || true
    echo -e "${GREEN}[+] Termux OpenSSH started.${NC}"
fi

# ------------------------------------------------------------------------------
# 5. Configure MariaDB/MySQL (Port 3306 - Open & Remote Accessible)
# ------------------------------------------------------------------------------
echo -e "${PURPLE}${BOLD}[4/7] Configuring MariaDB / MySQL Server (Port 3306 - 0.0.0.0)${NC}"

if [ "$IS_TERMUX" = false ]; then
    systemctl enable mariadb 2>/dev/null || systemctl enable mysql 2>/dev/null || true
    systemctl start mariadb 2>/dev/null || systemctl start mysql 2>/dev/null || service mariadb start 2>/dev/null || true

    # Configure bind-address = 0.0.0.0 to expose MySQL on port 3306
    MYSQL_CONF_DIR="/etc/mysql/mariadb.conf.d"
    if [ ! -d "$MYSQL_CONF_DIR" ]; then
        MYSQL_CONF_DIR="/etc/mysql/conf.d"
    fi
    mkdir -p "$MYSQL_CONF_DIR"

    cat <<EOF > "${MYSQL_CONF_DIR}/99-lab-open-port.cnf"
[mysqld]
bind-address = 0.0.0.0
port = 3306
skip-networking = 0
EOF

    systemctl restart mariadb 2>/dev/null || systemctl restart mysql 2>/dev/null || true
else
    mysql_install_db 2>/dev/null || true
    mysqld_safe --bind-address=0.0.0.0 --port=3306 &
    sleep 3
fi

# Initialize database and import schema
echo -e "[*] Initializing database '$DB_NAME' and creating lab user '$DB_USER'..."

MYSQL_CMD="mysql"
if command -v mariadb >/dev/null 2>&1; then
    MYSQL_CMD="mariadb"
fi

$MYSQL_CMD -u root <<EOF
CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '${DB_USER}'@'%' IDENTIFIED BY '${DB_PASS}';
ALTER USER '${DB_USER}'@'%' IDENTIFIED BY '${DB_PASS}';
GRANT ALL PRIVILEGES ON \`${DB_NAME}\`.* TO '${DB_USER}'@'%';

CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';
ALTER USER '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';
GRANT ALL PRIVILEGES ON \`${DB_NAME}\`.* TO '${DB_USER}'@'localhost';

FLUSH PRIVILEGES;
EOF

# Import schema with the 4 default lab users (root, admin, user, hacker)
echo -e "[*] Importing schema and seeding default lab accounts..."
$MYSQL_CMD -u root "${DB_NAME}" < "${SCRIPT_DIR}/db/schema.sql"

echo -e "${GREEN}[+] MySQL Database initialized and listening on 0.0.0.0:3306.${NC}"

# ------------------------------------------------------------------------------
# 6. Generate SSL Certificate and Configure Web Server (Ports 80 & 443)
# ------------------------------------------------------------------------------
echo -e "${PURPLE}${BOLD}[5/7] Configuring Web Server (Port 80 -> 443 Redirect, SSL TLS 443)${NC}"

SSL_CERT_DIR="/etc/ssl/certs"
SSL_KEY_DIR="/etc/ssl/private"
mkdir -p "$SSL_CERT_DIR" "$SSL_KEY_DIR"

CERT_FILE="${SSL_CERT_DIR}/freebase-lab.crt"
KEY_FILE="${SSL_KEY_DIR}/freebase-lab.key"

# Generate self-signed SSL Certificate
echo -e "[*] Generating self-signed SSL certificate for domain: ${LAB_DOMAIN}..."
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout "$KEY_FILE" \
    -out "$CERT_FILE" \
    -subj "/C=ES/ST=Lab/L=Cyber/O=FreeBase/CN=${LAB_DOMAIN}" \
    -addext "subjectAltName=DNS:${LAB_DOMAIN},IP:${DEFAULT_IP},IP:127.0.0.1" 2>/dev/null || \
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout "$KEY_FILE" \
    -out "$CERT_FILE" \
    -subj "/C=ES/ST=Lab/L=Cyber/O=FreeBase/CN=${LAB_DOMAIN}" 2>/dev/null

chmod 600 "$KEY_FILE"
chmod 644 "$CERT_FILE"

if [ "$PKG_MANAGER" = "apt" ]; then
    # Enable necessary Apache modules
    a2enmod rewrite ssl headers 2>/dev/null || true

    # Create VirtualHost configuration
    VHOST_CONF="/etc/apache2/sites-available/freebase-lab.conf"
    cat <<EOF > "$VHOST_CONF"
# VirtualHost HTTP (Port 80) -> Automatically redirects to HTTPS (Port 443)
<VirtualHost *:80>
    ServerName ${LAB_DOMAIN}
    ServerAlias *
    
    # Force HTTP to HTTPS redirection
    Redirect permanent / https://${LAB_DOMAIN}/
</VirtualHost>

# VirtualHost HTTPS (Port 443) -> SSL/TLS Encrypted Web Portal
<VirtualHost *:443>
    ServerName ${LAB_DOMAIN}
    DocumentRoot ${SCRIPT_DIR}

    SSLEngine on
    SSLCertificateFile ${CERT_FILE}
    SSLCertificateKeyFile ${KEY_FILE}

    <Directory ${SCRIPT_DIR}>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    ErrorLog \${APACHE_LOG_DIR}/freebase_error.log
    CustomLog \${APACHE_LOG_DIR}/freebase_access.log combined
</VirtualHost>
EOF

    # Disable default site and enable lab site
    a2dissite 000-default.conf 2>/dev/null || true
    a2dissite default-ssl.conf 2>/dev/null || true
    a2ensite freebase-lab.conf 2>/dev/null || true

    # Test and restart Apache
    apache2ctl configtest || true
    systemctl restart apache2 || service apache2 restart || true
    echo -e "${GREEN}[+] Apache2 configured: Port 80 redirects to 443; SSL active on 443.${NC}"
elif [ "$PKG_MANAGER" = "dnf" ] || [ "$PKG_MANAGER" = "yum" ]; then
    systemctl enable httpd 2>/dev/null || true
    systemctl restart httpd 2>/dev/null || true
fi

# Set file permissions for web server execution
chown -R www-data:www-data "$SCRIPT_DIR" 2>/dev/null || chown -R apache:apache "$SCRIPT_DIR" 2>/dev/null || true
chmod -R 755 "$SCRIPT_DIR"

# ------------------------------------------------------------------------------
# 7. Configure Application Environment (.env)
# ------------------------------------------------------------------------------
echo -e "${PURPLE}${BOLD}[6/7] Writing Application Configuration (.env)${NC}"

cat <<EOF > "${SCRIPT_DIR}/.env"
# ==========================================
# PHP FreeBase — Lab Environment Settings
# ==========================================
APP_ENV=development
APP_DEBUG=true
APP_NAME="PHP FreeBase Security Lab"
APP_URL=https://${LAB_DOMAIN}

# Database Connection (Local / Remote)
DB_HOST=127.0.0.1
DB_PORT=3306
DB_NAME=${DB_NAME}
DB_USER=${DB_USER}
DB_PASS=${DB_PASS}
DB_CHARSET=utf8mb4

# Session & Security Settings
SESSION_NAME=freebase_sec_session
SESSION_LIFETIME=3600
SESSION_MAX_LIFETIME=28800

# Brute Force Protection (Database-backed)
LOGIN_MAX_ATTEMPTS=5
LOGIN_LOCKOUT_SECONDS=300

# Token Lifetimes
RESET_TOKEN_LIFETIME=3600
VERIFY_TOKEN_LIFETIME=86400

# Emergency Secret (Optional)
ADMIN_RECOVERY_SECRET=lab-emergency-secret-key-32ch

# Timezone
APP_TIMEZONE=Europe/Madrid
EOF

chmod 600 "${SCRIPT_DIR}/.env"
chown www-data:www-data "${SCRIPT_DIR}/.env" 2>/dev/null || true

echo -e "${GREEN}[+] .env generated with active database credentials.${NC}"

# ------------------------------------------------------------------------------
# 8. Firewall & Port Opening (80, 443, 3306, 22)
# ------------------------------------------------------------------------------
echo -e "${PURPLE}${BOLD}[7/7] Opening Firewall Ports & Testing Sockets${NC}"

if command -v ufw >/dev/null 2>&1; then
    ufw allow 22/tcp >/dev/null 2>&1 || true
    ufw allow 80/tcp >/dev/null 2>&1 || true
    ufw allow 443/tcp >/dev/null 2>&1 || true
    ufw allow 3306/tcp >/dev/null 2>&1 || true
    echo -e "${GREEN}[+] UFW Firewall rules applied: Ports 22, 80, 443, 3306 allowed.${NC}"
fi

# Socket check
echo ""
echo -e "${BOLD}[*] Active Port Listener Verification:${NC}"
if command -v ss >/dev/null 2>&1; then
    ss -tulpn | grep -E ':(22|80|443|3306) ' || true
elif command -v netstat >/dev/null 2>&1; then
    netstat -tulpn | grep -E ':(22|80|443|3306) ' || true
fi

# ------------------------------------------------------------------------------
# Summary & Credential Banner
# ------------------------------------------------------------------------------
echo ""
echo -e "${GREEN}${BOLD}==================================================================${NC}"
echo -e "${GREEN}${BOLD}   PHP FreeBase Security Lab Successfully Deployed!              ${NC}"
echo -e "${GREEN}${BOLD}==================================================================${NC}"
echo ""
echo -e "${BOLD}1. NETWORK ACCESS & PORTS:${NC}"
echo -e "   - HTTP Web:    ${CYAN}http://${LAB_DOMAIN}:80${NC} (Redirects to HTTPS)"
echo -e "   - HTTPS Web:   ${CYAN}https://${LAB_DOMAIN}:443${NC}"
echo -e "   - MySQL Port:  ${CYAN}${LAB_DOMAIN}:3306${NC} (Open to 0.0.0.0 / external)"
echo -e "   - SSH Port:    ${CYAN}${LAB_DOMAIN}:22${NC}"
echo ""
echo -e "${BOLD}2. WEB APPLICATION LAB USERS:${NC}"
echo -e "   +------------------+------------------+---------------------------------------------------+"
echo -e "   | Username         | Password         | Role & Web Capabilities                           |"
echo -e "   +------------------+------------------+---------------------------------------------------+"
echo -e "   | ${YELLOW}root${NC}             | ${YELLOW}root${NC}             | ${BOLD}SUPER ADMIN${NC}: Can grant/revoke admin roles, reset  |"
echo -e "   | ${CYAN}admin${NC}            | ${CYAN}password${NC}         | ${BOLD}ADMIN${NC}: Access Security Console, reset user pass |"
echo -e "   | ${NC}user${NC}             | ${NC}user${NC}             | ${BOLD}USER${NC}: Standard Member Account                       |"
echo -e "   | ${RED}hacker${NC}           | ${RED}hacker${NC}           | ${BOLD}USER${NC}: Target Member Test Persona                   |"
echo -e "   +------------------+------------------+---------------------------------------------------+"
echo ""
echo -e "${BOLD}3. DATABASE (MySQL 3306) LAB CREDENTIALS:${NC}"
echo -e "   - Host:     ${CYAN}${LAB_DOMAIN}${NC} (or 127.0.0.1 / remote client)"
echo -e "   - Port:     ${CYAN}3306${NC}"
echo -e "   - Database: ${CYAN}${DB_NAME}${NC}"
echo -e "   - Username: ${CYAN}${DB_USER}${NC}"
echo -e "   - Password: ${CYAN}${DB_PASS}${NC}"
echo -e "   - Remote Connect Command: ${BOLD}mysql -h ${LAB_DOMAIN} -P 3306 -u ${DB_USER} -p${DB_PASS} ${DB_NAME}${NC}"
echo ""
echo -e "${BOLD}4. SSH ACCESS CREDENTIALS:${NC}"
echo -e "   - Host:     ${CYAN}${LAB_DOMAIN}${NC}"
echo -e "   - Port:     ${CYAN}22${NC}"
echo -e "   - User:     ${CYAN}root${NC} (or ${CYAN}lab${NC})"
echo -e "   - Password: ${CYAN}[Configured during setup]${NC}"
echo -e "   - Connect:  ${BOLD}ssh root@${LAB_DOMAIN}${NC}"
echo ""
echo -e "${BOLD}5. EMERGENCY RESET (Lab Feature):${NC}"
echo -e "   - Secret:   ${CYAN}lab-emergency-secret-key-32ch${NC}"
echo -e "   - URL:      ${CYAN}https://${LAB_DOMAIN}/emergency-reset.php${NC}"
echo ""
echo -e "${GREEN}Lab environment is ready! Review the README.md for CTF challenges & audit guides.${NC}"
echo "=================================================================="
