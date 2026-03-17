# Parcours 1 -- Reverse Engineering & Malware Lab
### Objectif principal
Mettre en place un Malware Lab isolé et analyser un ransomware ou
malware réel (échantillon contrôlé).

L'environnement doit être totalement isolé.

## Missions
### 1 Mise en place du Malware Lab
Déploiement via Ludus / Proxmox
Réseau totalement isolé (airgapped)
Machine Windows victime
Machine analyste
REMnux
INetSim (fake internet)
Snapshots fonctionnels
Documentation de l'architecture


### Analyse du Malware
Analyse statique
Étude du header PE
Analyse des imports
Strings intéressantes
Détection de packer
Extraction d'IOC
Écriture d'une règle YARA

##### Analyse dynamique

Observation avec ProcMon
Surveillance réseau (Wireshark)
Création fichiers / registry
Persistence
Comportement C2


### 3 Approfondissement
Mapping MITRE ATT&CK
Timeline d'exécution
Recommandations de détection


 Livrables attendus
Diagramme d'architecture du lab
Documentation technique
Rapport d'analyse structuré
IOC extraits
Règle YARA personnalisée
Présentation orale type CERT

