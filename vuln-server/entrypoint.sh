#!/bin/bash
# ============================================================
# entrypoint.sh — vuln-server
# Démarre tous les services vulnérables intentionnellement.
# ============================================================

set -e

echo "[VULN-SERVER] Starting services..."

# SSH
service ssh start
echo "[VULN-SERVER] SSH started (port 22) — PermitRootLogin yes, weak passwords"

# FTP (vsftpd)
service vsftpd start
echo "[VULN-SERVER] FTP started (port 21) — anonymous enabled"

# Telnet (xinetd)
service xinetd start
echo "[VULN-SERVER] Telnet started (port 23) — cleartext, no strong auth"

# HTTP (Apache)
service apache2 start
echo "[VULN-SERVER] HTTP started (port 80) — admin panel without HTTPS, directory listing"

# Cron (pour le script backup.sh — vecteur d'escalade)
service cron start
echo "[VULN-SERVER] Cron started — /opt/scada/backup.sh writable (privilege escalation vector)"

echo "[VULN-SERVER] All services running. Vulnerabilities active:"
echo "  SR 1.1 — FTP anonymous, SSH weak passwords (operator:password123, sysadmin:admin)"
echo "  SR 1.1 — HTTP admin panel default creds (admin:scada2024)"
echo "  SR 3.1 — Telnet cleartext, FTP cleartext, HTTP without TLS"
echo "  SR 2.1 — sudo misconfiguration operator → python3/cat/vim NOPASSWD"
echo "  SR 6.1 — credentials in cleartext logs (/var/log/scada/system.log)"

# Maintenir le conteneur actif
tail -f /var/log/apache2/access.log /var/log/auth.log
