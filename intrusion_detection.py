#!/usr/bin/env python3
"""
Network Intrusion Detection System (IDS) - version Python
CodeAlpha - Cyber Security Internship - Task 4

Ce script surveille le trafic reseau en direct et detecte des comportements
suspects a l'aide de regles simples (signature-based + comportementale) :

  1. Port scan          : une meme IP source contacte de nombreux ports
                           differents sur une courte periode.
  2. ICMP flood         : une meme IP source envoie un nombre anormal de
                           paquets ICMP (ping) en peu de temps.
  3. SYN flood (basique): un grand nombre de paquets TCP SYN sans reponse
                           depuis la meme source.

Chaque detection genere une alerte horodatee, affichee dans la console et
ecrite dans un fichier de log (ids_alerts.log).

Installation :
    pip install scapy

Utilisation :
    sudo python3 intrusion_detection.py
    sudo python3 intrusion_detection.py -i eth0
"""

import argparse
import time
import logging
from collections import defaultdict, deque

from scapy.all import sniff, IP, TCP, ICMP

# ---------------------------------------------------------------------------
# Configuration des seuils de detection (regles)
# ---------------------------------------------------------------------------
PORT_SCAN_THRESHOLD = 15       # nb de ports differents contactes...
PORT_SCAN_WINDOW = 10          # ...en X secondes -> alerte port scan

ICMP_FLOOD_THRESHOLD = 30      # nb de paquets ICMP...
ICMP_FLOOD_WINDOW = 5          # ...en X secondes -> alerte ICMP flood

SYN_FLOOD_THRESHOLD = 50       # nb de paquets SYN...
SYN_FLOOD_WINDOW = 5           # ...en X secondes -> alerte SYN flood

# ---------------------------------------------------------------------------
# Logging : console + fichier
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("ids_alerts.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("IDS")

# Historiques par IP source : deque de timestamps / ports pour calculer les
# evenements dans une fenetre glissante.
port_activity = defaultdict(lambda: deque())   # ip -> deque[(timestamp, port)]
icmp_activity = defaultdict(lambda: deque())   # ip -> deque[timestamp]
syn_activity = defaultdict(lambda: deque())    # ip -> deque[timestamp]

already_alerted = defaultdict(lambda: 0)       # anti-spam : ip+type -> dernier alert time
ALERT_COOLDOWN = 30  # secondes avant de re-alerter pour la meme IP/regle


def _prune(dq, now, window):
    """Retire de la deque les evenements plus vieux que la fenetre."""
    while dq and now - dq[0][0] > window:
        dq.popleft()


def _can_alert(key, now):
    if now - already_alerted[key] > ALERT_COOLDOWN:
        already_alerted[key] = now
        return True
    return False


def check_port_scan(src_ip, dst_port, now):
    dq = port_activity[src_ip]
    dq.append((now, dst_port))
    while dq and now - dq[0][0] > PORT_SCAN_WINDOW:
        dq.popleft()

    distinct_ports = {p for _, p in dq}
    if len(distinct_ports) >= PORT_SCAN_THRESHOLD and _can_alert(("scan", src_ip), now):
        logger.warning(
            f"PORT SCAN detecte depuis {src_ip} "
            f"({len(distinct_ports)} ports differents en {PORT_SCAN_WINDOW}s)"
        )


def check_icmp_flood(src_ip, now):
    dq = icmp_activity[src_ip]
    dq.append((now,))
    while dq and now - dq[0][0] > ICMP_FLOOD_WINDOW:
        dq.popleft()

    if len(dq) >= ICMP_FLOOD_THRESHOLD and _can_alert(("icmp", src_ip), now):
        logger.warning(
            f"ICMP FLOOD detecte depuis {src_ip} "
            f"({len(dq)} paquets ICMP en {ICMP_FLOOD_WINDOW}s)"
        )


def check_syn_flood(src_ip, now):
    dq = syn_activity[src_ip]
    dq.append((now,))
    while dq and now - dq[0][0] > SYN_FLOOD_WINDOW:
        dq.popleft()

    if len(dq) >= SYN_FLOOD_THRESHOLD and _can_alert(("syn", src_ip), now):
        logger.warning(
            f"SYN FLOOD (possible) detecte depuis {src_ip} "
            f"({len(dq)} paquets SYN en {SYN_FLOOD_WINDOW}s)"
        )


def handle_packet(packet):
    if IP not in packet:
        return

    src_ip = packet[IP].src
    now = time.time()

    if TCP in packet:
        flags = packet[TCP].flags
        dst_port = packet[TCP].dport
        check_port_scan(src_ip, dst_port, now)
        # flag SYN seul (0x02), sans ACK -> tentative de connexion
        if flags == "S":
            check_syn_flood(src_ip, now)

    elif ICMP in packet:
        check_icmp_flood(src_ip, now)


def main():
    parser = argparse.ArgumentParser(description="Simple Network IDS (CodeAlpha Task 4)")
    parser.add_argument("-i", "--interface", default=None,
                         help="Interface reseau a surveiller (ex: eth0, wlan0).")
    args = parser.parse_args()

    logger.info("=== IDS demarre - surveillance du trafic en cours ===")
    logger.info(f"Regles actives : port scan (>={PORT_SCAN_THRESHOLD} ports/{PORT_SCAN_WINDOW}s), "
                f"ICMP flood (>={ICMP_FLOOD_THRESHOLD}/{ICMP_FLOOD_WINDOW}s), "
                f"SYN flood (>={SYN_FLOOD_THRESHOLD}/{SYN_FLOOD_WINDOW}s)")

    sniff(iface=args.interface, prn=handle_packet, store=False)


if __name__ == "__main__":
    main()
