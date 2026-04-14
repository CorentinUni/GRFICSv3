#!/usr/bin/env python3
"""
healthcheck_compliance.py — Scaffold chemin 1 (Compliance Tool IEC 62443)
==========================================================================
Point de départ fourni aux étudiants.

Ce script interroge les services du labo GRFICSv3 et retourne des
résultats BRUTS non interprétés. Votre travail :

    1. Compléter les sondes manquantes (OPC-UA, HTTP, Telnet)
    2. Implémenter le moteur de scoring IEC 62443 (fonction score())
    3. Mapper chaque résultat sur une exigence IEC 62443 (fichier mapping)
    4. Générer un rapport HTML/PDF lisible par un RSSI

Usage :
    python3 healthcheck_compliance.py
    python3 healthcheck_compliance.py --target 192.168.95.2 --output rapport.html

Dépendances :
    pip install pymodbus paho-mqtt paramiko asyncua requests
"""

import argparse
import json
import socket
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s [COMPLIANCE] %(message)s')

# ------------------------------------------------------------------
# Configuration cibles (valeurs par défaut — réseau labo)
# ------------------------------------------------------------------
TARGETS = {
    "plc":          {"ip": "192.168.95.2",  "port": 502},
    "mqtt_broker":  {"ip": "192.168.90.50", "port": 1883},
    "vuln_server":  {"ip": "192.168.90.30", "port": 22},
    "hmi":          {"ip": "192.168.90.107","port": 8080},
    "opcua_server": {"ip": "192.168.95.30", "port": 4840},
}

# ------------------------------------------------------------------
# Structure d'un résultat de sonde
# ------------------------------------------------------------------
def make_result(asset, check, status, detail, raw=None):
    """
    Retourne un dictionnaire structuré représentant le résultat d'une sonde.

    status : "PASS" | "FAIL" | "ERROR" | "UNKNOWN"
    detail : description lisible du résultat
    raw    : données brutes optionnelles (banner, payload JSON, etc.)
    """
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "asset":     asset,
        "check":     check,
        "status":    status,
        "detail":    detail,
        "raw":       raw,
        # TODO étudiants : ajouter ici le mapping IEC 62443
        # "iec62443_sr": "SR X.X",
        # "severity":    "Critical | High | Medium | Low",
    }


# ------------------------------------------------------------------
# SONDES — à compléter et enrichir
# ------------------------------------------------------------------

def probe_modbus_anonymous(ip, port):
    """
    Sonde Modbus : tente une lecture de registres sans authentification.
    Détecte la violation SR 1.1 (authentification absente).

    TODO étudiants :
        - Tenter une écriture (function code 6) en plus de la lecture
        - Mesurer le nombre de registres accessibles
        - Détecter la version du protocole dans la réponse
    """
    try:
        from pymodbus.client import ModbusTcpClient
        client = ModbusTcpClient(ip, port=port, timeout=3)
        if not client.connect():
            return make_result("plc", "modbus_anonymous_access",
                               "ERROR", f"Cannot connect to {ip}:{port}")

        result = client.read_holding_registers(0, 10, slave=1)
        client.close()

        if result.isError():
            return make_result("plc", "modbus_anonymous_access",
                               "PASS", "Read failed — possible access control")
        else:
            return make_result("plc", "modbus_anonymous_access",
                               "FAIL",
                               f"Read 10 registers without authentication — SR 1.1 violated",
                               raw={"registers": result.registers})
    except Exception as e:
        return make_result("plc", "modbus_anonymous_access",
                           "ERROR", str(e))


def probe_mqtt_anonymous(ip, port):
    """
    Sonde MQTT : connexion anonyme + abonnement wildcard #.
    Détecte les violations SR 1.1 et SR 3.1.

    TODO étudiants :
        - Tenter une publication sur ics/plc/commands
        - Vérifier la présence de TLS (port 8883)
        - Lister les topics avec données retained
    """
    try:
        import paho.mqtt.client as mqtt

        connected = []
        topics    = []

        def on_connect(client, userdata, flags, rc):
            connected.append(rc)
            if rc == 0:
                client.subscribe("#")

        def on_message(client, userdata, msg):
            topics.append(msg.topic)

        client = mqtt.Client(client_id="compliance-probe-01")
        client.on_connect = on_connect
        client.on_message = on_message
        client.connect(ip, port, keepalive=5)
        client.loop_start()

        import time
        time.sleep(3)
        client.loop_stop()
        client.disconnect()

        if connected and connected[0] == 0:
            return make_result("mqtt_broker", "mqtt_anonymous_access",
                               "FAIL",
                               f"Anonymous connection accepted — SR 1.1 violated. "
                               f"Topics observed: {list(set(topics))[:10]}",
                               raw={"topics": list(set(topics))})
        else:
            return make_result("mqtt_broker", "mqtt_anonymous_access",
                               "PASS", "Anonymous connection refused")
    except Exception as e:
        return make_result("mqtt_broker", "mqtt_anonymous_access",
                           "ERROR", str(e))


def probe_ssh_banner_and_weak_creds(ip, port):
    """
    Sonde SSH : récupère le banner et teste des credentials faibles.
    Détecte les violations SR 1.1 et SR 3.1.

    TODO étudiants :
        - Étendre la liste des credentials testés
        - Vérifier la version SSH (SSHv1 = violation SR 3.1)
        - Détecter PermitRootLogin yes dans le banner
    """
    result_banner = _probe_ssh_banner(ip, port)
    result_creds  = _probe_ssh_weak_creds(ip, port)
    return [result_banner, result_creds]


def _probe_ssh_banner(ip, port):
    try:
        sock = socket.create_connection((ip, port), timeout=3)
        banner = sock.recv(256).decode(errors="replace").strip()
        sock.close()
        detail = f"Banner: {banner}"
        status = "FAIL" if "2.1.4" in banner or "6.6" in banner or "SCADA" in banner else "INFO"
        return make_result("vuln_server", "ssh_banner",
                           status, detail, raw={"banner": banner})
    except Exception as e:
        return make_result("vuln_server", "ssh_banner", "ERROR", str(e))


def _probe_ssh_weak_creds(ip, port):
    """
    Teste une liste réduite de credentials faibles.
    NE PAS utiliser sur des systèmes réels sans autorisation écrite.
    """
    weak_creds = [
        ("operator", "password123"),
        ("sysadmin", "admin"),
        ("root",     "root"),
        ("admin",    "admin"),
    ]
    try:
        import paramiko
        for user, pwd in weak_creds:
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(ip, port=port, username=user, password=pwd, timeout=3)
                client.close()
                return make_result("vuln_server", "ssh_weak_credentials",
                                   "FAIL",
                                   f"Login succeeded with {user}:{pwd} — SR 1.1 violated",
                                   raw={"user": user, "password": pwd})
            except paramiko.AuthenticationException:
                continue
            except Exception:
                break
        return make_result("vuln_server", "ssh_weak_credentials",
                           "PASS", "No weak credentials accepted from tested list")
    except Exception as e:
        return make_result("vuln_server", "ssh_weak_credentials",
                           "ERROR", str(e))


def probe_opcua_security(ip, port):
    """
    Sonde OPC-UA : vérifie le SecurityMode et l'authentification.
    Détecte les violations SR 1.1 et SR 3.1.

    TODO étudiants — verrou pédagogique :
        - Implémenter cette sonde (protocole OPC-UA plus complexe)
        - Utiliser la bibliothèque asyncua pour se connecter
        - Vérifier : SecurityMode None, Anonymous accepté
        - Lire les nœuds accessibles sans authentification
        - Détecter l'exposition de PLCAddress (information réseau)

    Ressources :
        https://python-asyncua.readthedocs.io
        OPC Foundation — UA Part 2 : Security Model
        IEC 62443-3-3 SR 1.1, SR 3.1, SR 3.3
    """
    # TODO : implémenter la sonde OPC-UA
    return make_result("opcua_server", "opcua_security_mode",
                       "UNKNOWN",
                       "Sonde OPC-UA non implémentée — verrou chemin 1",
                       raw={"hint": "asyncua, SecurityPolicyType.NoSecurity, endpoint description"})


def probe_http_admin(ip, port):
    """
    Sonde HTTP : accès au panel admin sans authentification.
    Détecte les violations SR 1.1, SR 3.1 (HTTP sans TLS).

    TODO étudiants :
        - Détecter la présence de credentials en clair dans le code source HTML
        - Vérifier l'absence de HTTPS (redirection 301)
        - Tester le directory listing sur /backup/
        - Récupérer system.log et db_dump.sql accessibles publiquement
    """
    try:
        import requests
        resp = requests.get(f"http://{ip}:{port}/admin/", timeout=3)
        status = "FAIL" if resp.status_code == 200 else "PASS"
        detail = (f"HTTP /admin/ returned {resp.status_code} without authentication "
                  f"— SR 1.1 violated, SR 3.1 violated (no TLS)"
                  if status == "FAIL"
                  else f"HTTP /admin/ returned {resp.status_code}")
        return make_result("vuln_server", "http_admin_no_auth",
                           status, detail,
                           raw={"status_code": resp.status_code,
                                "content_length": len(resp.content)})
    except Exception as e:
        return make_result("vuln_server", "http_admin_no_auth",
                           "ERROR", str(e))


# ------------------------------------------------------------------
# MOTEUR DE SCORING — à implémenter
# ------------------------------------------------------------------

def score(results):
    """
    TODO étudiants : implémenter le moteur de scoring IEC 62443.

    Pour chaque résultat de sonde :
        1. Identifier l'exigence IEC 62443 violée (SR X.X)
        2. Attribuer une sévérité (Critical / High / Medium / Low)
        3. Calculer un score global de conformité par asset
        4. Calculer un score global du système

    Mapping de départ (à compléter avec votre table IEC 62443) :
        modbus_anonymous_access → SR 1.1 (Critical)
        mqtt_anonymous_access   → SR 1.1 (Critical) + SR 3.1 (High)
        ssh_weak_credentials    → SR 1.1 (Critical)
        ssh_banner              → SR 3.1 (Medium)
        opcua_security_mode     → SR 1.1 (Critical) + SR 3.1 (High)
        http_admin_no_auth      → SR 1.1 (High) + SR 3.1 (High)

    Retourner un dictionnaire :
        {
            "global_score": 0-100,
            "by_asset": { "plc": {"score": X, "findings": [...]}, ... },
            "critical_count": N,
            "high_count": N,
        }
    """
    raise NotImplementedError("score() — à implémenter (chemin 1, Jour 2 après-midi)")


# ------------------------------------------------------------------
# GENERATEUR DE RAPPORT — à implémenter
# ------------------------------------------------------------------

def generate_report(results, output_path="rapport_compliance.html"):
    """
    TODO étudiants : générer un rapport HTML lisible par un RSSI.

    Le rapport doit contenir :
        - Executive Summary : score global, nombre de violations critiques
        - Par asset : liste des findings avec sévérité et recommandation
        - Section recommandations : exigence IEC 62443 → action corrective
        - Annexe : résultats bruts JSON

    Conseil : utiliser un LLM pour rédiger les recommandations en langage
    naturel à partir des résultats bruts (voir section IA du brief).
    """
    raise NotImplementedError("generate_report() — à implémenter (chemin 1, Jour 3)")


# ------------------------------------------------------------------
# MAIN
# ------------------------------------------------------------------

def run_all_probes():
    """Lance toutes les sondes et retourne les résultats bruts."""
    results = []

    logging.info("=== GRFICSv3 Compliance Check — IEC 62443 ===")
    logging.info(f"Started at {datetime.utcnow().isoformat()}")

    # Modbus
    logging.info("Probing Modbus (PLC)...")
    results.append(probe_modbus_anonymous(
        TARGETS["plc"]["ip"], TARGETS["plc"]["port"]))

    # MQTT
    logging.info("Probing MQTT broker...")
    results.append(probe_mqtt_anonymous(
        TARGETS["mqtt_broker"]["ip"], TARGETS["mqtt_broker"]["port"]))

    # SSH
    logging.info("Probing SSH (vuln-server)...")
    ssh_results = probe_ssh_banner_and_weak_creds(
        TARGETS["vuln_server"]["ip"], TARGETS["vuln_server"]["port"])
    results.extend(ssh_results)

    # OPC-UA (verrou — à implémenter)
    logging.info("Probing OPC-UA server...")
    results.append(probe_opcua_security(
        TARGETS["opcua_server"]["ip"], TARGETS["opcua_server"]["port"]))

    # HTTP
    logging.info("Probing HTTP admin panel (vuln-server)...")
    results.append(probe_http_admin(
        TARGETS["vuln_server"]["ip"], 80))

    return results


def main():
    parser = argparse.ArgumentParser(description="GRFICSv3 IEC 62443 Compliance Tool")
    parser.add_argument("--output", default="rapport_compliance.html",
                        help="Chemin du rapport généré")
    parser.add_argument("--json-only", action="store_true",
                        help="Afficher uniquement les résultats JSON bruts")
    args = parser.parse_args()

    results = run_all_probes()

    # Affichage brut
    print("\n=== RESULTATS BRUTS ===")
    for r in results:
        symbol = {"FAIL": "✗", "PASS": "✓", "ERROR": "!", "UNKNOWN": "?"}.get(r["status"], "?")
        print(f"  [{symbol}] {r['asset']:15s} | {r['check']:35s} | {r['status']:7s} | {r['detail'][:80]}")

    if args.json_only:
        print(json.dumps(results, indent=2))
        return

    # TODO : appeler score() et generate_report() une fois implémentés
    print("\n[TODO] score() et generate_report() non encore implémentés.")
    print(f"[TODO] Rapport attendu : {args.output}")

    # Sauvegarde des résultats bruts
    raw_path = args.output.replace(".html", "_raw.json")
    with open(raw_path, "w") as f:
        json.dump(results, f, indent=2)
    logging.info(f"Résultats bruts sauvegardés : {raw_path}")


if __name__ == "__main__":
    main()
