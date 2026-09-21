# Task 4 — Network Intrusion Detection System (IDS)

**CodeAlpha — Cyber Security Internship**
**Auteur :** Sarah Boucherou

## Objectif

Mettre en place un système capable de surveiller le trafic réseau en temps réel
et de détecter des comportements suspects, avec génération d'alertes.

## Approche

Plutôt que d'installer et configurer un IDS externe complet (Snort/Suricata),
ce projet implémente un **IDS léger en Python** (basé sur Scapy) qui applique
des règles de détection comportementale sur le trafic capturé en direct. Cette
approche permet de comprendre et de démontrer concrètement le fonctionnement
interne d'un IDS : captation du trafic → analyse par règles → génération d'alertes.

## Règles de détection implémentées

| Règle | Déclencheur |
|---|---|
| **Port Scan** | Une même IP source contacte ≥ 15 ports différents en moins de 10 secondes |
| **ICMP Flood** | Une même IP source envoie ≥ 30 paquets ICMP (ping) en moins de 5 secondes |
| **SYN Flood (basique)** | Une même IP source envoie ≥ 50 paquets TCP SYN en moins de 5 secondes |

Chaque règle utilise une **fenêtre glissante** (sliding window) : seuls les
évènements récents sont comptabilisés, ce qui évite les faux positifs liés à
une activité normale mais étalée dans le temps.

## Installation

```bash
pip install scapy
```

## Utilisation

```bash
# Surveillance sur l'interface par defaut
sudo python3 intrusion_detection.py

# Surveillance sur une interface precise
sudo python3 intrusion_detection.py -i eth0
```

Les alertes s'affichent dans la console **et** sont enregistrées dans le fichier
`ids_alerts.log` avec horodatage, pour permettre une analyse ultérieure.

## Exemple d'alerte générée

```
2026-09-17 14:02:03 [WARNING] PORT SCAN detecte depuis 192.168.1.42 (18 ports differents en 10s)
2026-09-17 14:05:11 [WARNING] ICMP FLOOD detecte depuis 192.168.1.77 (34 paquets ICMP en 5s)
```

## Test de la logique de détection

Les fonctions de détection ont été testées indépendamment de la capture réseau
en simulant des séquences de paquets (port scan et flood ICMP), ce qui confirme
que les règles se déclenchent correctement :

```
PORT SCAN detecte depuis 10.0.0.5 (15 ports differents en 10s)
ICMP FLOOD detecte depuis 10.0.0.9 (30 paquets ICMP en 5s)
```

## Limites et pistes d'amélioration

- Détection basée sur des seuils fixes (pas de machine learning).
- Pas de blocage automatique de l'IP suspecte (réponse passive : alerte uniquement).
- Amélioration possible : intégrer un dashboard (ex: via une petite interface web)
  pour visualiser les alertes en temps réel, ou ajouter des règles supplémentaires
  (détection de scan furtif, exfiltration de données, etc.).

## Ce que j'ai appris

- Le fonctionnement d'un IDS : captation, analyse par règles, alerte.
- La notion de fenêtre glissante pour l'analyse comportementale de trafic.
- La différence entre une approche par signature et une approche comportementale.
- Les techniques d'attaque réseau courantes (port scan, ICMP flood, SYN flood).

## Avertissement éthique

Ce script est destiné à un usage éducatif, sur des réseaux dont vous êtes
propriétaire ou pour lesquels vous avez une autorisation explicite.
