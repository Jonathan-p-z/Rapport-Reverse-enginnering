# Rapport d'analyze 
Le virus a était essentiellement conçus pour windows (il n'ai pas fais pour fonctionner sur linux) et essentiellement conçus en python, c'est un spyware.

### Identité du Malaware

| Information | Valeurs |
| :--- | :---: |
| Nom originel | bowser-classique.exe |
| Type de menace | Spyware / Infostealer  |
| MD5 | c460753d76401b98dc2fda2ce525e2ea |
| SHA-256 | 0d1c2850f63329a15ce207aadde382b22472263e1d12c4d4085b792bb8d40d29 |
| Langage | Python 3.13 (PyInstaller bundle)|

### Comment fonctionne le malware
Le malware s'autocopie dans C:\Windows\System32\bowser.exe qui utilise un dossier systéme qui permet de tromper l'utilisateur qui pensera qu'il s'agit d'un composant légitime de windows, il modifie aussi la base de registre pour crée la clé HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Bowser

### Le spyware 
Il fait du :
- Keylogging
- Capture d'écran
- Presse papier 

le keylogging comme dis dans le nom enregistre chque tout du clavier, grace a win32gui, il associe c'est frappe au nom de la fenêtre active, la capture d'écran va screen le bureau de la victime, le presse papier lui va surveiller se que l'on copie, imaginons je copie un hash ou juste une clé crypto, la personne récuperera se que l'on a copier

### Le coter stealer 
C'est le coté le plus utilisant du sqlite et de la cryptography 

Cette partie sera dangereux car il extrait les base de données de chrome/edge, récupére la clé de chiffrement via win32crypt, et décrypte tout les mot de passe (de la sorcellerie je dis..). Pour le chiffrement on utilise la function DPAPI, c'est une clé de coffre que windows prête au virus parce qu'il croit que cela est fichier légitime (le hacker se fait passer pour l'user pour récupérer les mot de passe, windows ne voit donc pas la supercherie)

Il utilise des commande systéme via subprocess pour lister tous les profils wi-fi et leurs mot de passe précis.

Il collecte aussi les nom du PC, l'adresse MAC, l'adresse ip et la configuration matérielle de notre machine.

### Traces sur le système
Fichiers crées automatiquement 
- `C:\Windows\System32\bowser.exe`
- `C:\Windows\System32\screenshot.jpg` (Se sont des fichier temporaire qui sont utilisé pour stocker les capture d'écran avant l'envoie au server)

Indice dans le Registre :

`HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Bowser`

Réseau :

- Requêtes HTTP POST (JSON) vers le domaine duckdns

### Impact sur les performences

Un stealer est pas connu pour être gourmand coter performence, il veux rester discret pour avoir un macimum de donnée.

| Composant | Impact |
| :--- | :---: |
| CPU | Il peux y avoir des pics d'activité lors de l'extraction de mot de passe, sinon en général il y a une utilisation légére pour rester discret |
| Réseau | Fuites de données, le processus bowser.execrée des connexion HTTPS sortantes réguliéres vers ducking.org, sa peux être une de ralentissement  |
| Disque | Il y a une forte lecture des fichiers de base de données des navigateurs au lancement |
| RAM | L'impact sur la RAM  est quand même trés minimes contrairement au autres (entre 50 - 150 Mo) uniquement pour maintenir l'interpréteur et les bibliothéque d'espionnage active |

### Analyse technique 
L'adresse du pirate https://bgfjb25kzxrhbwvyzq.duckdns.org

Fichier YARA :
```
cat << 'EOF' > Bowser_Final.yar
rule Win32_Spyware_Bowser {
    meta:
        description = "Détecte le Stealer Bowser (Python)"
        author = "Yaiito"
    strings:
        $a = "duckdns" ascii
        $b = "bowser" ascii
        $c = "pynput" ascii
    condition:
        any of them
}
EOF
```
Pour explique de bout en bout le fichier :

1. meta : C'est la partie administrative de la régle, c'est utilsée essentiellement pour l'organisation
- Description va permettre d'expliquer en bref la régle YARA
- L'autors va être pour désigné sont créateurs 
2. Le corps strings
C'est ici que l'on définira l'utilité de notre fichier avec des mots clés, pour sa j'ai choisi 3 variables 
- $a = "duckdns" pour cibler l'adresse du server du hacker 
- $b = "bowser" pour cibler le nom du fichier que le pirate a donné au virus 
- $c = "pynput" on cible la bibliothéque qu'a utiliser le pirate pour le virus 
- ascii sa sert a dire au fichier YARA de chercher ces mots sous forme de texte standars pour que sa soit compréhensible pour un humains
3. Le coeurs du fichier : condition
C'est l'une des partie les plus importante du fichier, en gros sa dis que si je trouve une des 3 varialbles cité une alerte de déclenches 

La régle est surtout la pour viser tout en ce qui concerne les viriables cité en haut pour bien tout analyser, grâce a cette régle j'ai pu confirmer le code malveillant, on a aussi pu définir de quel branches le virus appartenait se qui est une avancée majeur dans se reverse qui restreint l'analyse de recherche

Le fichier a notamment réussi a faire ressortir du strings qui ma été capital pour la compréhension du virus

---
Bibiliothéque suspecte que j'ai réussi a ressortir

```
import time
import requests
import winreg
import ctypes
import sys
import win32gui
from pynput import keyboard
import io as i
from PIL import ImageGrab
import base64 as b
import pyperclip
import os
import json
import shutil
import sqlite3
import subprocess
import platform
import socket
import uuid
import psutil
import base64
from datetime import datetime
from win32crypt import CryptUnprotectData
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import inspect
key_lo_g_runn_ing = False
st_e_a_l_runn_ing = False
```

### Recommendation de rémédition 

Premiérement le fichier se nomme bowser-classique.exe se qui n'ai pas un navigateur traditionnelle donc cela serai incensé de l'installer, mais imaginons que nous l'avons insaller bien que le processus soit facile a arrêter manuellement, les vol de mot de passe sont réellement la, il suffit simplement de kill le service dans la barre des tâches et le problême sera régler.

Supprimer ensuite le fichier dans notre pc dans `C:\Windows\System32\` (ne pas supprimer le dossier sa serai bête de finir avec un windows plus fonctionnel) 

Il important de supprimer la clé de registre de démarrage automatique 

#### Mesures a prendre
- Il sera forcément conseillé de changer les mot de passe de tout les compte que l'on a enregistré sur notre navigateur, car ils sont certainement était envoyer dans un server du hacker

- Un blocage DNS : A jouer le nom de domaine malveillant `bgfjb25kzxrhbwvyzqhejcjnjad.duckdns.org`(modifier légérement par mesure de précaution) a la liste noir du pare feu de notre pc ou du fichier hosts.

- 2FA (Double authentificateur) obligatoire et recommendez pour rendre les mot de passe unitilisable 

### Conclusion 
Le Malware bowser-classique.exe est logiciel espion qui utilise l'usurpation d'identité en se placant dans le dossier `C:\Windows\System32\` qui contient des dossier sensible de windows, pour bien sur tromper la vigilence de l'utilisateur.

- Sa particularité est qu'il vole les mot de passe enregistré de notre navigateur l'envoyant dans la base de données de l'attaquant.

- Il screen aussi se que l'on fait sur notre pc se et l'envoie sur l'url du pirate `bgfjb25kzxrhbwvyzqhejcjnjad.duckdns.org/screenshot.jpg` (modifier légérement par mesure de précaution)

- Le hacker va aussi surveiller se que l'on tape sur notre clavier cela s'appelle le keylogger

- La derniére fonctionnalité est que le virus va pouvoir accéder a se que j'ai copier, comme je l'ai dis plus haut si je copie une clé crypto par exemple, le pirate aura accés a cette clé sans que je soit au courant

Grâce a l'analyse du code source et $la régle YARA écrite un peu plus haut nous avons désormer les outil pour détécter et bloquer le virus avant qu'il ne puisse exfiltrer l'entiéreté de nos données