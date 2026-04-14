"""
opcua-server/server.py
Serveur OPC-UA industriel simulé — intentionnellement non sécurisé.

Vulnérabilités documentées IEC 62443 :
  SR 1.1 : SecurityMode = None (pas d'authentification)
  SR 3.1 : pas de chiffrement (SecurityPolicy = NoSecurity)

Noeuds exposés (namespace 2) :
  ns=2;s=Temperature   — température process (°C)
  ns=2;s=Pressure      — pression process (bar)
  ns=2;s=Status        — état nominal/alarm
  ns=2;s=PLCAddress    — adresse IP du PLC (info réseau exposée)
  ns=2;s=FirmwareVer   — version firmware

Surface de test chemin 1 :
  La sonde OPC-UA du compliance tool doit détecter :
  - SecurityMode None
  - Absence de UserTokenPolicy (anonymous accepté)
  - Exposition d'informations réseau via PLCAddress
"""

import asyncio
import logging
import random
from asyncua import Server
from asyncua.ua import SecurityPolicyType

logging.basicConfig(level=logging.INFO, format='%(asctime)s [OPCUA] %(message)s')


async def main():
    server = Server()
    await server.init()

    # ----------------------------------------------------------
    # Configuration intentionnellement non sécurisée
    # SR 1.1 / SR 3.1
    # ----------------------------------------------------------
    server.set_endpoint("opc.tcp://0.0.0.0:4840/grfics/")
    server.set_server_name("GRFICS ICS OPC-UA Server v1.0")
    await server.set_security_policy([SecurityPolicyType.NoSecurity])

    # Accepter les connexions anonymes (SR 1.1)
    await server.set_security_IDs(["Anonymous"])

    # ----------------------------------------------------------
    # Namespace et noeuds
    # ----------------------------------------------------------
    uri = "urn:grfics:ics:opcua"
    idx = await server.register_namespace(uri)

    objects = server.nodes.objects
    process = await objects.add_object(idx, "Process")

    temp_node     = await process.add_variable(idx, "Temperature", 72.0)
    pressure_node = await process.add_variable(idx, "Pressure",    4.2)
    status_node   = await process.add_variable(idx, "Status",      "nominal")
    plc_node      = await process.add_variable(idx, "PLCAddress",  "192.168.95.2")
    fw_node       = await process.add_variable(idx, "FirmwareVer", "SensorFW-v1.2.0")

    # Rendre les variables accessibles en écriture (SR 2.1 — pas de contrôle d'accès)
    await temp_node.set_writable()
    await pressure_node.set_writable()
    await status_node.set_writable()

    logging.info("OPC-UA server started — opc.tcp://0.0.0.0:4840/grfics/")
    logging.info("SecurityMode: None | Authentication: Anonymous")
    logging.warning("INTENTIONALLY INSECURE — lab use only")

    # ----------------------------------------------------------
    # Simulation des valeurs process
    # ----------------------------------------------------------
    async with server:
        temp     = 72.0
        pressure = 4.2
        while True:
            temp     = max(55.0, min(92.0, temp + random.uniform(-0.8, 0.8)))
            pressure = max(3.0,  min(7.0,  pressure + random.uniform(-0.1, 0.1)))
            status   = "alarm" if (temp > 85.0 or pressure > 6.0) else "nominal"

            await temp_node.write_value(round(temp, 2))
            await pressure_node.write_value(round(pressure, 2))
            await status_node.write_value(status)

            logging.info(f"T={temp:.1f}°C P={pressure:.2f}bar status={status}")
            await asyncio.sleep(5)


if __name__ == "__main__":
    asyncio.run(main())
