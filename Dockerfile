FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
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
    curl \
    net-tools \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Configure SSH
RUN sed -i 's/^#\?Port .*/Port 22/' /etc/ssh/sshd_config && \
    sed -i 's/^#\?PasswordAuthentication .*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/^#\?PermitRootLogin .*/PermitRootLogin yes/' /etc/ssh/sshd_config

WORKDIR /var/www/html
COPY . /var/www/html/
RUN chmod +x /var/www/html/docker-entrypoint.sh

EXPOSE 80 443 3306 22

ENTRYPOINT ["/var/www/html/docker-entrypoint.sh"]
