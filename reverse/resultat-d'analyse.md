# Rapport d'analyze 
Le virus a était essentiellement conçus pour windows (il n'ai pas fais pour fonctionner sur linux) et essentiellement conçus en python, c'est un spyware nommé Bowser, conçu pour Windows, qui vole des informations sensibles telles que les mots de passe, les données Wi-Fi, et effectue des captures d'écran.

### Identité du Malaware

| Information | Valeurs |
| :--- | :---: |
| Nom originel | bowser-classique.exe |
| Type de menace | Spyware / Infostealer  |
| MD5 | c460753d76401b98dc2fda2ce525e2ea |
| SHA-256 | 0d1c2850f63329a15ce207aadde382b22472263e1d12c4d4085b792bb8d40d29 |
| Langage | Python 3.13 (PyInstaller bundle)|

Commande utiliser 

```
md5sum bowser-classique.exe
sha256sum bowser-classique.exe
```

### Comment fonctionne le malware
Le malware s'autocopie dans C:\Windows\System32\bowser.exe qui utilise un dossier systéme qui permet de tromper l'utilisateur qui pensera qu'il s'agit d'un composant légitime de windows, il modifie aussi la base de registre pour crée la clé HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Bowser

### Le spyware 
Il fait du :
- Keylogging
- Capture d'écran
- Presse papier 

le keylogging comme dis dans le nom enregistre chque tout du clavier, grace a win32gui, il associe c'est frappe au nom de la fenêtre active, la capture d'écran va screen le bureau de la victime, le presse papier lui va surveiller se que l'on copie, imaginons je copie un hash ou juste une clé crypto, la personne récuperera se que l'on a copier

### Le coter stealer 
C’est la partie du virus qui utilise le plus les bibliothèques sqlite3 et cryptography 

Cette section est particulièrement dangereuse car le malware va fouiller dans les dossiers de Chrome et Edge pour extraire leurs bases de données. Pour lire les mots de passe, il utilise la fonction DPAPI (Data Protection Application Programming Interface) de Windows

C'est la que le piége va se refermer : la DPAPI est comme un coffre-fort personnel que Windows réserve à l'utilisateur. Comme le virus s'exécute avec vos droits, Windows croit que c'est une demande légitime de votre part et lui "prête" la clé pour déverrouiller vos mots de passe. Le hacker n'a même pas besoin de forcer la serrure, il se fait passer pour vous et Windows lui ouvre la porte sans voir la supercherie...

En plus des navigateurs, le virus utilise des commandes système (via subprocess) pour lister tous les profils Wi-Fi enregistrés sur le PC et récupérer leurs mots de passe en clair.

Est c'est a se moment que commence la fiche d'identité de la victime :
- Le nom du PC et l'adresse IP.

- L'adresse MAC (l'identifiant unique de la carte réseau).

- La configuration matérielle complète de la machine.

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

Sur cette image je montre l'impact qu'a le malware sur le pc on peux voir qu'au lancement le fichier prend un peu de performence pour au final rester en arriére plans

![impact](/images/impact.png)

### Analyse technique 
L'adresse du pirate `bgfjb25kzxrhbwvyzqhejcjnjad.duckdns.org/screenshot.jpg` (modifier légérement par mesure de précaution)

Fichier YARA :
L'utiliseation d'une régle YARA est essentielle pour passer a la réel analyse du malware, cela permet de détecter le malware de maniére fiable est controler et d'automatiser la recherche de menace 

```
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
```any of them```
C'est l'une des partie les plus importante du fichier, en gros sa dis que si je trouve une des 3 varialbles cité une alerte de déclenches 

La régle est surtout la pour viser tout en ce qui concerne les viriables cité en haut pour bien tout analyser, grâce a cette régle j'ai pu confirmer le code malveillant, on a aussi pu définir de quel branches le virus appartenait se qui est une avancée majeur dans se reverse qui restreint l'analyse de recherche

Le fichier a notamment réussi a faire ressortir du strings qui ma été capital pour la compréhension du virus

---
Bibiliothéque suspecte que j'ai réussi a ressortir

Grâce a cette commande on a pu extraire les librarie utilisée pour se malware se qui nous en dis long 

strings bowser-classique.exe | grep "import"
site_import

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

Cette librarie est donc la preuve formelle que c'est bien un malware. Encore plus claire sur ces 2 lignes qui est littéralement un aveux (on voit bien le keylog et le steal).
```
key_lo_g_runn_ing = False
st_e_a_l_runn_ing = False
```

Il y a d'autre d'autre preuve sur cette librarie que c'est un malware comme par exemple l'import de win32gui(déchiffrement windows), pyperclip(presse papier), ImageGrab(l'écran), pynput(le clavier). C'est vraiment les import qu'aurais un spyware.

Il y a aussi aucune interface utilisateur importer se qui est quand même bizarre quand on est sensée être un navigateur, le programme est fait pour tourner en silence sans que l'on s'en rend compte.

Sqlite3 et Win32gui sont importer pour une seule chose : le vol des identifiant de l'utilisateur 
### Recommendation de rémédition 

Premiérement le fichier se nomme bowser-classique.exe se qui n'ai pas un navigateur traditionnelle donc cela serai incensé de l'installer, mais imaginons que nous l'avons insaller bien que le processus soit facile a arrêter manuellement, les vol de mot de passe sont réellement la, il suffit simplement de kill le service dans la barre des tâches et le problême sera régler.

Supprimer ensuite le fichier dans notre pc dans `C:\Windows\System32\` (ne pas supprimer le dossier sa serai bête de finir avec un windows plus fonctionnel..) 

Il est important de supprimer la clé de registre de démarrage automatique 
Pour le supprimer vous avez plusieurs option mais la plus simple est la suivante :
1. Appuyer sur la touche Windows + R
2. Ecriver `regedit`
3. Naviguer dans l'arborescence à gauche pour suivre le chemin `HKEY_CURRENT_USER > Software > Microsoft > Windows > CurrentVersion > Run`
4. Chercher une logne noter bowser
5. Faire clic droit et supprimer simplement 

#### Mesures a prendre
- Il sera forcément conseillé de changer les mot de passe de tout les compte que l'on a enregistré sur notre navigateur, car ils sont certainement était envoyer dans un serveur du hacker

- Un blocage DNS : Ajouter le nom de domaine malveillant `bgfjb25kzxrhbwvyzqhejcjnjad.duckdns.org`(modifier légérement par mesure de précaution) a la liste noir du pare feu de notre pc ou du fichier hosts.

- 2FA (Double authentificateur) obligatoire et recommendez pour rendre les mot de passe unitilisable 

### Conclusion 
Le Malware bowser-classique.exe est logiciel espion qui utilise l'usurpation d'identité en se placant dans le dossier `C:\Windows\System32\` qui contient des dossier sensible de windows, pour bien sur tromper la vigilence de l'utilisateur.

- Sa particularité est qu'il vole les mot de passe enregistré de notre navigateur l'envoyant dans la base de données de l'attaquant.

- Il screen aussi se que l'on fait sur notre pc se et l'envoie sur l'url du pirate `bgfjb25kzxrhbwvyzqhejcjnjad.duckdns.org/screenshot.jpg` (modifier légérement par mesure de précaution)

- Le hacker va aussi surveiller se que l'on tape sur notre clavier cela s'appelle le keylogger

- La derniére fonctionnalité est que le virus va pouvoir accéder a se que j'ai copier, comme je l'ai dis plus haut si je copie une clé crypto par exemple, le pirate aura accés a cette clé sans que je soit au courant

Grâce a l'analyse du code source et la régle YARA écrite un peu plus haut nous avons désormer les outil pour détécter et bloquer le virus avant qu'il ne puisse exfiltrer l'entiéreté de nos données