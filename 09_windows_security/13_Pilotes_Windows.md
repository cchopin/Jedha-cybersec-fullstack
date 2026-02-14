# Le noyau Windows : pilotes et communication matérielle

**Module** : pilotes Windows (drivers)

---

## Objectifs du module

À l'issue de ce module, les compétences suivantes seront acquises :

- Comprendre le rôle des pilotes dans l'architecture Windows et leur fonctionnement en mode noyau
- Connaître le cycle de vie d'un pilote, de la détection matérielle à l'installation automatique
- Identifier les différents types de pilotes dans la pile de pilotes (driver stack)
- Vérifier la signature et la légitimité des pilotes installés sur un système
- Détecter les signes de pilotes malveillants ou compromis

---

## Introduction

Les pilotes (drivers) sont l'un des composants les plus critiques et les moins visibles de Windows. Ils forment l'interface entre le système d'exploitation et le matériel physique : clavier, souris, carte graphique, carte réseau, disque dur, etc. Un pilote compromis offre à un attaquant un accès total au système, car il s'exécute au niveau de privilège le plus élevé. Comprendre leur fonctionnement est donc essentiel en cybersécurité.

---

## 1. Qu'est-ce qu'un pilote ?

### 1.1 Définition

Un pilote (driver) est un composant logiciel qui permet au système d'exploitation de communiquer avec un périphérique matériel. Il agit comme un **traducteur** : il convertit les appels haut niveau émis par l'OS (« envoyer cette donnée au disque », « lire la frappe clavier ») en instructions bas niveau compréhensibles par le matériel.

Sans pilote, le système d'exploitation ne sait pas comment dialoguer avec un périphérique donné. Chaque constructeur fournit des pilotes adaptés à son matériel.

### 1.2 Mode noyau et niveau de privilège

Les pilotes s'exécutent en **mode noyau** (kernel mode), c'est-à-dire au niveau de privilège **Ring 0** du processeur. Cela leur confère un accès total aux ressources du système :

| Niveau | Nom | Accès | Exemples |
|---|---|---|---|
| Ring 0 | Mode noyau (Kernel mode) | Accès complet : mémoire, matériel, instructions CPU privilégiées | Noyau Windows, pilotes, HAL |
| Ring 3 | Mode utilisateur (User mode) | Accès restreint : espace mémoire isolé, appels système contrôlés | Applications, services utilisateur |

> **À noter** : cette position en Ring 0 rend les pilotes extrêmement puissants, mais aussi extrêmement dangereux s'ils sont compromis. Un pilote malveillant peut lire toute la mémoire, désactiver les protections de sécurité, ou installer un rootkit invisible pour les outils fonctionnant en mode utilisateur.

### 1.3 Pilotes et noyau Windows

Le noyau Windows (`ntoskrnl.exe`) délègue la gestion du matériel aux pilotes. Le schéma suivant résume l'architecture :

```
+---------------------------+
|   Applications (Ring 3)   |
+---------------------------+
|     API Windows (Win32)   |
+---------------------------+
|   I/O Manager (Ring 0)    |
+---------------------------+
|   Driver Stack (pilotes)  |
+---------------------------+
|         HAL               |
+---------------------------+
|   Matériel (hardware)     |
+---------------------------+
```

Le **HAL** (Hardware Abstraction Layer) fournit une couche d'abstraction entre le matériel physique et le noyau, permettant à Windows de fonctionner sur différentes architectures matérielles.

---

## 2. Architecture des pilotes

### 2.1 Le Bus Driver

Le **Bus Driver** est le pilote qui gère un bus matériel (USB, PCI, PCI Express, etc.). Son rôle est de détecter les périphériques connectés au bus et de signaler leur présence au système.

Exemples de Bus Drivers :

| Bus | Pilote | Rôle |
|---|---|---|
| USB | `usbhub.sys` | Gère les hubs USB et détecte les périphériques connectés |
| PCI | `pci.sys` | Énumère les périphériques sur le bus PCI/PCIe |
| ACPI | `acpi.sys` | Gère les périphériques déclarés par le BIOS/UEFI via ACPI |

### 2.2 Hardware ID (identifiant matériel)

Chaque périphérique possède un **Hardware ID** unique qui permet à Windows d'identifier précisément le matériel et de trouver le pilote correspondant. Cet identifiant suit un format standardisé :

```
PCI\VEN_10DE&DEV_1F82&SUBSYS_86751043&REV_A1
```

Décomposition :

| Champ | Signification | Exemple |
|---|---|---|
| `PCI` | Type de bus | PCI Express |
| `VEN_10DE` | Identifiant du fabricant (Vendor ID) | NVIDIA (10DE) |
| `DEV_1F82` | Identifiant du périphérique (Device ID) | GeForce GTX 1650 |
| `SUBSYS_86751043` | Sous-système (fabricant de la carte) | ASUS (1043) |
| `REV_A1` | Révision matérielle | Révision A1 |

Pour consulter le Hardware ID d'un périphérique :

```powershell
# Via PowerShell
Get-PnpDevice | Select-Object FriendlyName, InstanceId | Format-List

# Via le Gestionnaire de périphériques
# Clic droit sur un périphérique > Propriétés > Détails > ID du matériel
```

> **À noter** : les bases de données en ligne comme [https://devicehunt.com](https://devicehunt.com) permettent de retrouver le fabricant et le modèle à partir d'un Vendor ID et d'un Device ID.

### 2.3 Le PnP Manager (Plug and Play)

Le **PnP Manager** (Plug and Play Manager) est le composant du noyau responsable de la détection automatique des périphériques et du chargement des pilotes correspondants. Il coordonne l'ensemble du processus d'installation.

---

## 3. Cycle de vie d'un pilote : de la connexion au fonctionnement

### 3.1 Exemple concret : brancher un clavier USB

Voici la séquence complète des événements lorsqu'un utilisateur branche un clavier USB sur un poste Windows :

**Étape 1 — Détection matérielle**

Le contrôleur USB détecte un changement électrique sur le port. Un signal d'interruption matérielle (hardware interrupt) est généré.

**Étape 2 — Notification par le HAL**

Le HAL (Hardware Abstraction Layer) reçoit l'interruption et la transmet au noyau Windows. Le Bus Driver USB (`usbhub.sys`) est notifié qu'un nouveau périphérique est présent.

**Étape 3 — Identification du périphérique**

Le Bus Driver interroge le périphérique pour obtenir son Hardware ID. Le clavier répond avec son identifiant (ex : `USB\VID_046D&PID_C52B` pour un clavier Logitech).

**Étape 4 — Recherche du pilote par le PnP Manager**

Le PnP Manager cherche un pilote compatible dans l'ordre suivant :

1. **Driver Store** local (`C:\Windows\System32\DriverStore`)
2. **Windows Update** (si configuré)
3. Demande à l'utilisateur de fournir le pilote

**Étape 5 — Construction de la pile de pilotes (Driver Stack)**

L'**I/O Manager** construit la pile de pilotes pour le nouveau périphérique. Pour un clavier USB, cette pile inclut typiquement :

```
+----------------------------------+
|  Filter Driver (optionnel)       |  <-- Filtrage/modification des données
+----------------------------------+
|  Function Driver (kbdhid.sys)    |  <-- Traduction HID -> frappe clavier
+----------------------------------+
|  Function Driver (kbdclass.sys)  |  <-- Interface clavier générique
+----------------------------------+
|  Bus Driver (usbhub.sys)         |  <-- Gestion du bus USB
+----------------------------------+
```

**Étape 6 — Mise à jour du registre**

Le **Configuration Manager** enregistre le nouveau périphérique dans le registre Windows :

```
HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_046D&PID_C52B
```

Le pilote est référencé dans :

```
HKLM\SYSTEM\CurrentControlSet\Services\kbdclass
```

**Étape 7 — Gestion de l'alimentation**

Le **Power Manager** configure les paramètres d'alimentation du périphérique (mise en veille automatique, réveil par le clavier, etc.).

**Étape 8 — Le clavier est opérationnel**

L'utilisateur peut taper. Chaque frappe remonte la pile de pilotes jusqu'à l'application en cours.

### 3.2 Schéma récapitulatif

```
Connexion USB
      |
      v
  Hardware Interrupt
      |
      v
  HAL -> Noyau -> Bus Driver (usbhub.sys)
      |
      v
  PnP Manager : identification + recherche pilote
      |
      v
  I/O Manager : construction du Driver Stack
      |
      v
  Configuration Manager : mise à jour du registre
      |
      v
  Power Manager : alimentation
      |
      v
  Périphérique opérationnel
```

---

## 4. La pile de pilotes (Driver Stack)

### 4.1 Les trois types de pilotes

Une pile de pilotes est composée de plusieurs couches. Chaque couche a un rôle spécifique :

| Type | Rôle | Exemple (clavier USB) |
|---|---|---|
| **Bus Driver** | Gère le bus matériel, détecte et énumère les périphériques | `usbhub.sys` |
| **Function Driver** | Pilote principal du périphérique, gère ses fonctions spécifiques | `kbdhid.sys` (traduction HID), `kbdclass.sys` (interface clavier) |
| **Filter Driver** | Modifie ou surveille le comportement d'un autre pilote, en amont ou en aval | Pilote de filtrage clavier (ex : remappage de touches) |

> **À noter** : les Filter Drivers sont souvent utilisés par les logiciels antivirus pour inspecter les données transitant par la pile. Mais ils peuvent aussi être exploités par des malwares (keyloggers, rootkits).

### 4.2 Communication entre les couches : les IRP

Les différentes couches de la pile de pilotes communiquent entre elles via des **IRP** (I/O Request Packets). Un IRP est une structure de données créée par l'I/O Manager pour représenter une opération d'entrée/sortie.

Fonctionnement simplifié :

1. Une application demande une lecture (ex : attendre une frappe clavier)
2. L'I/O Manager crée un IRP de type `IRP_MJ_READ`
3. L'IRP descend dans la pile de pilotes, chaque couche le traite ou le transmet
4. Le Bus Driver communique avec le matériel
5. La réponse remonte dans la pile via le même IRP
6. L'I/O Manager retourne le résultat à l'application

```
Application
    |  IRP_MJ_READ (descente)
    v
Filter Driver
    |
    v
Function Driver (kbdhid.sys)
    |
    v
Bus Driver (usbhub.sys)
    |
    v
Matériel (clavier USB)
    |
    |  Réponse (remontée)
    v
Application reçoit la frappe
```

### 4.3 Entrée du pilote dans le registre

Chaque pilote installé possède une entrée dans le registre Windows sous :

```
HKLM\SYSTEM\CurrentControlSet\Services\<nom_du_pilote>
```

Exemple pour `kbdclass` :

```
HKLM\SYSTEM\CurrentControlSet\Services\kbdclass
    Type        : 1 (SERVICE_KERNEL_DRIVER)
    Start       : 1 (SERVICE_SYSTEM_START)
    ErrorControl: 1 (SERVICE_ERROR_NORMAL)
    ImagePath   : \SystemRoot\System32\drivers\kbdclass.sys
    Group       : Keyboard Class
```

Les valeurs clés à examiner :

| Valeur | Signification |
|---|---|
| `Type` | 1 = pilote noyau, 2 = pilote système de fichiers |
| `Start` | 0 = boot, 1 = système, 2 = automatique, 3 = manuel, 4 = désactivé |
| `ImagePath` | Chemin vers le fichier .sys du pilote |
| `Group` | Groupe de chargement (détermine l'ordre de démarrage) |

---

## 5. Signature des pilotes

### 5.1 Pourquoi la signature est importante

Depuis Windows Vista (et renforcée sous Windows 10/11 en 64 bits), Microsoft impose que les pilotes en mode noyau soient **signés numériquement**. Cette mesure de sécurité garantit deux choses :

1. **Authenticité** : le pilote provient d'un éditeur identifié et de confiance
2. **Intégrité** : le fichier n'a pas été modifié depuis sa signature

Un pilote non signé ne peut pas être chargé en mode noyau sur un Windows 64 bits avec Secure Boot activé (comportement par défaut).

### 5.2 Le processus de signature

Pour obtenir une signature valide, un éditeur de pilote doit :

1. Obtenir un **certificat de signature de code** (code signing certificate) auprès d'une autorité de certification reconnue par Microsoft
2. Soumettre le pilote au programme **Windows Hardware Compatibility** (WHCP) de Microsoft
3. Le pilote est testé et signé par Microsoft via le processus **attestation signing** ou **HLK (Hardware Lab Kit)**

### 5.3 Vérification de la signature

```powershell
# Lister tous les pilotes avec leur statut de signature
driverquery /v

# Vérifier la signature d'un fichier spécifique avec sigcheck (Sysinternals)
sigcheck.exe -v C:\Windows\System32\drivers\kbdclass.sys

# Vérifier via PowerShell
Get-AuthenticodeSignature C:\Windows\System32\drivers\kbdclass.sys
```

Exemple de sortie de `sigcheck` :

```
Verified:       Signed
Signing date:   10:24 AM 3/15/2024
Publisher:      Microsoft Windows
Company:        Microsoft Corporation
Description:    Keyboard Class Driver
Product:        Microsoft Windows Operating System
```

> **Bonne pratique** : vérifier régulièrement la signature de tous les pilotes chargés, en particulier ceux configurés en démarrage automatique. Un pilote non signé ou signé par un éditeur inconnu est un indicateur de compromission.

---

## 6. Outils de diagnostic et de vérification

### 6.1 Gestionnaire de périphériques (devmgmt.msc)

Le Gestionnaire de périphériques offre une vue graphique de tous les périphériques et de leurs pilotes :

```powershell
# Ouvrir le Gestionnaire de périphériques
devmgmt.msc
```

Informations accessibles pour chaque périphérique :

- Onglet **Pilote** : version, date, éditeur, fichiers du pilote
- Onglet **Détails** : Hardware ID, classe du périphérique, chemin du pilote
- Onglet **Événements** : historique des événements liés au périphérique

### 6.2 driverquery

```powershell
# Liste complète des pilotes avec détails
driverquery /v

# Format CSV pour analyse
driverquery /v /fo csv > C:\Temp\drivers.csv

# Pilotes signés uniquement
driverquery /si
```

### 6.3 Autoruns (Sysinternals)

Autoruns affiche tous les programmes et pilotes configurés pour démarrer automatiquement. L'onglet **Drivers** est particulièrement utile :

- Affiche le chemin, l'éditeur, et le statut de signature
- Surligne en rouge ou jaune les entrées suspectes (non signées, éditeur inconnu)
- Permet de désactiver temporairement un pilote sans le supprimer

```powershell
# Lancer Autoruns en tant qu'administrateur
autoruns.exe
# Onglet : Drivers
```

### 6.4 Observateur d'événements (Event Viewer)

Les échecs de chargement de pilotes sont journalisés dans l'Observateur d'événements :

```
Observateur d'événements > Journaux Windows > Système
```

Événements à surveiller :

| Event ID | Source | Signification |
|---|---|---|
| 7000 | Service Control Manager | Échec de démarrage d'un service/pilote |
| 7026 | Service Control Manager | Pilote de démarrage (boot-start) en échec |
| 219 | Kernel-PnP | Pilote non trouvé pour un périphérique |

```powershell
# Rechercher les événements liés aux pilotes en PowerShell
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7000,7026,219} |
    Select-Object TimeCreated, Id, Message |
    Format-Table -Wrap
```

---

## 7. Détecter un pilote suspect

### 7.1 Indicateurs de compromission

Un pilote malveillant peut être difficile à détecter car il fonctionne au niveau du noyau. Voici les signaux d'alerte à surveiller :

| Indicateur | Détail |
|---|---|
| **Pilote non signé** avec démarrage automatique | Un pilote légitime en production est toujours signé |
| **Chemin non standard** | Un pilote légitime se trouve dans `C:\Windows\System32\drivers\`. Un chemin comme `C:\Users\Public\driver.sys` est suspect |
| **Nom générique ou trompeur** | Noms comme `helper.sys`, `update.sys`, ou imitant un pilote légitime (`kbdc1ass.sys` au lieu de `kbdclass.sys`) |
| **Éditeur inconnu ou absent** | Vérifier avec `sigcheck` ou Autoruns |
| **Date de création incohérente** | Un pilote créé récemment dans un répertoire contenant des fichiers datant de l'installation du système |
| **Pas de description** | Les pilotes légitimes ont une description et un nom de produit |

### 7.2 Commandes de vérification rapide

```powershell
# Lister les pilotes non signés
driverquery /si | findstr /i "FALSE"

# Vérifier tous les fichiers .sys dans le dossier drivers
Get-ChildItem C:\Windows\System32\drivers\*.sys |
    ForEach-Object {
        $sig = Get-AuthenticodeSignature $_.FullName
        [PSCustomObject]@{
            Fichier = $_.Name
            Statut  = $sig.Status
            Editeur = $sig.SignerCertificate.Subject
        }
    } | Where-Object { $_.Statut -ne 'Valid' } |
    Format-Table -AutoSize

# Chercher des pilotes dans des emplacements non standards
Get-WmiObject Win32_SystemDriver |
    Where-Object { $_.PathName -notlike '*\Windows\System32\*' } |
    Select-Object Name, PathName, State, StartMode
```

### 7.3 Scénario d'attaque : pilote vulnérable exploité (BYOVD)

La technique **BYOVD** (Bring Your Own Vulnerable Driver) consiste à installer un pilote légitime mais vulnérable pour exploiter ses failles depuis le mode utilisateur et obtenir un accès noyau. Cette technique est utilisée par des groupes APT avancés.

Exemples connus :

- **RTCore64.sys** (MSI Afterburner) : permet la lecture/écriture arbitraire de la mémoire noyau
- **dbutil_2_3.sys** (Dell) : escalade de privilèges via CVE-2021-21551
- **Process Explorer driver** : utilisé pour tuer des processus antivirus

> **Bonne pratique** : maintenir une liste blanche des pilotes autorisés via **Windows Defender Application Control (WDAC)** et surveiller les chargements de pilotes via les journaux d'audit.

---

## Pour aller plus loin

- [Microsoft — Introduction au développement de pilotes Windows](https://learn.microsoft.com/fr-fr/windows-hardware/drivers/gettingstarted/)
- [Microsoft — Architecture des pilotes en mode noyau](https://learn.microsoft.com/fr-fr/windows-hardware/drivers/kernel/)
- [Microsoft — Signature des pilotes](https://learn.microsoft.com/fr-fr/windows-hardware/drivers/install/driver-signing)
- [Sysinternals — Autoruns](https://learn.microsoft.com/fr-fr/sysinternals/downloads/autoruns)
- [LOLDrivers — Catalogue de pilotes vulnérables exploitables](https://www.loldrivers.io/)
- [BYOVD — Liste des pilotes vulnérables connus](https://github.com/magicsword-io/LOLDrivers)
