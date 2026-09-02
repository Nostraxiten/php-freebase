#!/usr/bin/env bash
set -e

# Generate self-signed SSL cert if missing
mkdir -p /etc/ssl/certs /etc/ssl/private
if [ ! -f /etc/ssl/certs/freebase-lab.crt ]; then
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/ssl/private/freebase-lab.key \
        -out /etc/ssl/certs/freebase-lab.crt \
        -subj "/C=ES/ST=Lab/L=Cyber/O=FreeBase/CN=localhost" 2>/dev/null
fi

# Configure and start MariaDB
mkdir -p /var/run/mysqld /var/lib/mysql
chown -R mysql:mysql /var/run/mysqld /var/lib/mysql

if [ ! -d /var/lib/mysql/mysql ]; then
    mysql_install_db --user=mysql --datadir=/var/lib/mysql >/dev/null 2>&1
fi

mysqld_safe --bind-address=0.0.0.0 --port=3306 &
sleep 3

# Wait for MariaDB
for i in {1..30}; do
    if mysqladmin ping -h localhost --silent; then
        break
    fi
    sleep 1
done

# Initialize Lab Database and User
mysql -u root <<EOF
CREATE DATABASE IF NOT EXISTS \`freebase\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'freebase_user'@'%' IDENTIFIED BY 'lab_db_pass';
GRANT ALL PRIVILEGES ON \`freebase\`.* TO 'freebase_user'@'%';
CREATE USER IF NOT EXISTS 'freebase_user'@'localhost' IDENTIFIED BY 'lab_db_pass';
GRANT ALL PRIVILEGES ON \`freebase\`.* TO 'freebase_user'@'localhost';
FLUSH PRIVILEGES;
EOF

# Import schema
if [ -f /var/www/html/db/schema.sql ]; then
    mysql -u root freebase < /var/www/html/db/schema.sql
fi

# Generate .env if missing
if [ ! -f /var/www/html/.env ]; then
    cat <<EOF > /var/www/html/.env
APP_ENV=development
APP_DEBUG=true
APP_NAME="PHP FreeBase Security Lab"
APP_URL=https://localhost

DB_HOST=127.0.0.1
DB_PORT=3306
DB_NAME=freebase
DB_USER=freebase_user
DB_PASS=lab_db_pass
DB_CHARSET=utf8mb4

SESSION_NAME=freebase_sec_session
SESSION_LIFETIME=3600
SESSION_MAX_LIFETIME=28800

LOGIN_MAX_ATTEMPTS=5
LOGIN_LOCKOUT_SECONDS=300

RESET_TOKEN_LIFETIME=3600
VERIFY_TOKEN_LIFETIME=86400

ADMIN_RECOVERY_SECRET=lab-emergency-secret-key-32ch
APP_TIMEZONE=Europe/Madrid
EOF
    chmod 600 /var/www/html/.env
fi

# Set SSH root password (default 'root' or SSH_PASS)
SSH_PASSWORD="${SSH_PASSWORD:-root}"
echo "root:${SSH_PASSWORD}" | chpasswd
mkdir -p /var/run/sshd
/usr/sbin/sshd

# Apache VirtualHost config
a2enmod rewrite ssl headers >/dev/null 2>&1 || true

cat <<EOF > /etc/apache2/sites-available/freebase-lab.conf
<VirtualHost *:80>
    ServerName localhost
    Redirect permanent / https://localhost/
</VirtualHost>

<VirtualHost *:443>
    ServerName localhost
    DocumentRoot /var/www/html

    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/freebase-lab.crt
    SSLCertificateKeyFile /etc/ssl/private/freebase-lab.key

    <Directory /var/www/html>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
EOF

a2dissite 000-default.conf default-ssl.conf >/dev/null 2>&1 || true
a2ensite freebase-lab.conf >/dev/null 2>&1 || true

# Start Apache in foreground
exec apache2ctl -D FOREGROUND
