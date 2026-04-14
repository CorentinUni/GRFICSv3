FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    openssh-server telnetd xinetd vsftpd apache2 \
    net-tools iputils-ping curl vim python3 sudo cron \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/run/sshd
RUN useradd -m -s /bin/bash -g operator operator && echo "operator:password123" | chpasswd
RUN useradd -m -s /bin/bash sysadmin && echo "sysadmin:admin" | chpasswd && usermod -aG sudo sysadmin

RUN printf 'Port 22\nPermitRootLogin yes\nPasswordAuthentication yes\nBanner /etc/ssh/banner.txt\nMaxAuthTries 10\n' > /etc/ssh/sshd_config
RUN printf '*************************************************************\n* SCADA Remote Access Server v2.1.4                        *\n* System  : Ubuntu 22.04.3 LTS                             *\n* Hostname: vuln-server.ics.local  -- Zone DMZ             *\n*************************************************************\n' > /etc/ssh/banner.txt

RUN echo "operator ALL=(ALL) NOPASSWD: /usr/bin/python3, /bin/cat, /usr/bin/vim" >> /etc/sudoers

RUN mkdir -p /var/log/scada && printf '2024-01-15 08:12:35 INFO  HMI authenticated -- user: scada_op password: Scada@2024!\n2024-01-15 08:15:00 INFO  DB backup -- db_pass: Backup#Secure99\n2024-01-15 09:00:01 INFO  API token: eyJhbGciOiJIUzI1NiJ9.EXAMPLE\n' > /var/log/scada/system.log
RUN chmod 644 /var/log/scada/system.log && chown -R operator:operator /var/log/scada && ln -s /var/log/scada /home/operator/logs

RUN printf '*/5 * * * * root /opt/scada/backup.sh\n' > /etc/cron.d/scada-backup
RUN mkdir -p /opt/scada && printf '#!/bin/bash\ncp -r /var/log/scada /tmp/backup_$(date +%%Y%%m%%d)\n' > /opt/scada/backup.sh && chmod 777 /opt/scada/backup.sh

RUN printf 'listen=YES\nlisten_ipv6=NO\nanonymous_enable=YES\nlocal_enable=YES\nwrite_enable=YES\nanon_upload_enable=YES\nanon_root=/srv/ftp\nseccomp_sandbox=NO\n' > /etc/vsftpd.conf
RUN mkdir -p /srv/ftp/public && chmod 755 /srv/ftp && chmod 777 /srv/ftp/public && chown ftp:ftp /srv/ftp
RUN printf '# Network config DMZ\nRouter: 192.168.90.200\nHMI: 192.168.90.107\nPLC: 192.168.95.2\n\nSSH emergency:\n  user: admin\n  pass: EmergencyAccess2024\n' > /srv/ftp/public/network_config.txt

RUN printf 'service telnet\n{\n    flags = REUSE\n    socket_type = stream\n    wait = no\n    user = root\n    server = /usr/sbin/in.telnetd\n    disable = no\n}\n' > /etc/xinetd.d/telnet

RUN printf '<html><body><h1>SCADA Management v1.4.2</h1><ul><li><a href="/admin/">Admin Panel</a></li><li><a href="/backup/">Backups</a></li></ul></body></html>\n' > /var/www/html/index.html
RUN mkdir -p /var/www/html/admin && printf '<html><body><!-- default creds: admin/scada2024 --><form><input name="user"><input type="password" name="pass"><input type="submit"></form></body></html>\n' > /var/www/html/admin/index.html
RUN mkdir -p /var/www/html/backup && cp /var/log/scada/system.log /var/www/html/backup/
RUN printf 'INSERT INTO users VALUES (2,"operator","password123_plain");\nINSERT INTO config VALUES ("mqtt_pass","mqtt@2024");\n' > /var/www/html/backup/db_dump.sql
RUN printf '<Directory /var/www/html>\n  Options Indexes FollowSymLinks\n  Require all granted\n</Directory>\n' > /etc/apache2/conf-available/lab.conf && a2enconf lab

COPY entrypoint.sh /entrypoint.sh
EXPOSE 22 23 21 80
CMD ["/entrypoint.sh"]
