import paho.mqtt.client as mqtt
import time, json, random, logging
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s [SENSOR] %(message)s')

BROKER_HOST = "mqtt-broker"
BROKER_PORT = 1883

# ------------------------------------------------------------------
# Callbacks
# ------------------------------------------------------------------
def on_connect(client, userdata, flags, rc):
    if rc == 0:
        logging.info(f"Connected to {BROKER_HOST}:{BROKER_PORT}")
        client.subscribe("ics/plc/commands")
    else:
        logging.error(f"Connection failed rc={rc}")

def on_message(client, userdata, msg):
    logging.warning(f"COMMAND received on {msg.topic}: {msg.payload.decode()}")

# ------------------------------------------------------------------
# Main
# ------------------------------------------------------------------
def main():
    client = mqtt.Client(client_id="ics-sensor-01")
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(BROKER_HOST, BROKER_PORT, keepalive=60)
    client.loop_start()

    temp, pressure = 72.0, 4.2
    cycle = 0

    while True:
        temp     = max(55.0, min(92.0, temp + random.uniform(-0.8, 0.8)))
        pressure = max(3.0,  min(7.0,  pressure + random.uniform(-0.1, 0.1)))
        status   = "alarm" if (temp > 85.0 or pressure > 6.0) else "nominal"
        cycle   += 1

        # ----------------------------------------------------------
        # Payload principal — expose intentionnellement :
        #   - plc_ip    : adresse du PLC sur le réseau ICS
        #   - auth      : absence d'authentification (SR 1.1)
        #   - protocol  : protocole et version utilisés
        # Ces champs sont volontairement présents pour les exercices.
        # ----------------------------------------------------------
        payload = json.dumps({
            "timestamp":        datetime.utcnow().isoformat(),
            "device_id":        "ics-sensor-01",
            "temperature_C":    round(temp, 2),
            "pressure_bar":     round(pressure, 2),
            "status":           status,
            "plc_ip":           "192.168.95.2",       # SR 1.1 — exposition info réseau
            "firmware":         "SensorFW-v1.2.0",
            "auth":             "none",                # SR 1.1 — pas d'authentification
            "protocol":         "MQTT/3.1.1",          # SR 3.1 — protocole en clair
            "tls":              False,                 # SR 3.1 — pas de chiffrement
            "cycle":            cycle,
        })

        # Topics principaux
        client.publish("ics/sensor/temperature", round(temp, 2),     qos=0, retain=True)
        client.publish("ics/sensor/pressure",    round(pressure, 2), qos=0, retain=True)
        client.publish("ics/sensor/status",      payload,            qos=0)

        # ----------------------------------------------------------
        # Topic raw_modbus — simule la remontée brute des registres
        # Modbus lus sur le PLC avant publication MQTT.
        # Vecteur d'attaque : un attaquant abonné à ce topic obtient
        # l'état des registres sans accéder directement au PLC.
        # ----------------------------------------------------------
        modbus_payload = json.dumps({
            "timestamp":   datetime.utcnow().isoformat(),
            "plc_ip":      "192.168.95.2",
            "unit_id":     1,
            "registers": {
                "holding_40001": round(temp * 10),       # température × 10
                "holding_40002": round(pressure * 100),  # pression × 100
                "coil_00001":    1 if status == "alarm" else 0,
            },
            "read_function_code": 3,   # Read Holding Registers
            "auth":               "none",
        })
        client.publish("ics/sensor/raw_modbus", modbus_payload, qos=0)

        # Alerte haute priorité
        if status == "alarm":
            client.publish(
                "ics/alerts",
                json.dumps({
                    "level":        "HIGH",
                    "temp_C":       round(temp, 2),
                    "pressure_bar": round(pressure, 2),
                    "plc_ip":       "192.168.95.2",
                }),
                qos=1
            )

        logging.info(f"T={temp:.1f}°C P={pressure:.2f}bar status={status} cycle={cycle}")
        time.sleep(5)

if __name__ == "__main__":
    time.sleep(15)   # attendre que mqtt-broker soit prêt
    main()
