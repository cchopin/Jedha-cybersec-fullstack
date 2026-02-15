# Le registre Windows

**Module** : comprendre la base de données de configuration centralisée de Windows

---

## Objectifs du module

À l'issue de ce module, les compétences suivantes seront acquises :

- Comprendre le rôle et l'architecture du registre Windows
- Naviguer dans la structure hiérarchique du registre (clés, valeurs, types de données)
- Connaître les cinq clés racines (root keys) et leur contenu
- Distinguer les hives (ruches) et localiser leurs fichiers physiques sur le disque
- Utiliser PowerShell et regedit pour lire et modifier le registre
- Identifier les risques de sécurité liés au registre

---

## 1. Présentation du registre

### 1.1 Définition

Le **registre Windows** (Windows Registry) est une base de données hiérarchique centralisée qui stocke l'ensemble des paramètres de configuration du système d'exploitation, des applications installées et des préférences utilisateur.

Le registre a été introduit avec Windows 3.1 (1992) pour remplacer progressivement les fichiers de configuration texte `.INI` qui étaient utilisés par les versions précédentes. Les fichiers `.INI` posaient plusieurs problèmes : pas de structure standard, pas de contrôle d'accès, difficultés de recherche, et risque de corruption.

### 1.2 Pourquoi le registre est important en sécurité

Le registre est un élément central pour la sécurité Windows car il contient :

| Contenu | Exemple |
|---|---|
| **Configuration des services** | Type de démarrage, chemin de l'exécutable, compte d'exécution |
| **Programmes de démarrage automatique** | Clés `Run`, `RunOnce` exécutées à chaque connexion |
| **Politique de sécurité** | Politique de mots de passe, restrictions d'accès |
| **Informations d'authentification** | Base SAM (hashes des mots de passe locaux) |
| **Configuration du pare-feu** | Règles et exceptions |
| **Historique d'exécution** | Derniers programmes exécutés, fichiers récents |

> **À noter** : le registre est l'un des premiers endroits où les malwares établissent leur **persistance** (capacité à survivre à un redémarrage). Les clés `Run` et `RunOnce` sont les vecteurs de persistance les plus courants (technique MITRE ATT&CK T1547.001).

### 1.3 Outils d'accès au registre

| Outil | Type | Usage |
|---|---|---|
| `regedit.exe` | Interface graphique | Navigation, recherche, modification manuelle |
| PowerShell | Ligne de commande | Automatisation, scripts d'audit |
| `reg.exe` | Ligne de commande (cmd) | Lecture, écriture, export/import en ligne de commande |
| Panneau de configuration | Interface graphique | Modifie le registre de manière transparente pour l'utilisateur |

---

## 2. Structure du registre

### 2.1 Clés et valeurs

Le registre est organisé de manière hiérarchique, similaire à un système de fichiers :

| Concept registre | Analogie système de fichiers | Description |
|---|---|---|
| **Clé** (Key) | Dossier | Conteneur qui peut contenir des sous-clés et des valeurs |
| **Sous-clé** (Subkey) | Sous-dossier | Clé contenue dans une autre clé |
| **Valeur** (Value) | Fichier | Donnée de configuration identifiée par un nom |
| **Donnée** (Data) | Contenu du fichier | La valeur effective stockée |

Exemple de structure :

```
HKEY_LOCAL_MACHINE
  └── SOFTWARE
        └── Microsoft
              └── Windows
                    └── CurrentVersion
                          └── Run
                                ├── SecurityHealth = "C:\...\SecurityHealthSystray.exe"
                                └── OneDrive = "C:\...\OneDrive.exe /background"
```

Dans cet exemple, `Run` est une **clé**, et `SecurityHealth` est une **valeur** dont la **donnée** est le chemin vers l'exécutable.

### 2.2 Types de données

Chaque valeur du registre a un type qui définit le format de la donnée stockée :

| Type | Description | Exemple d'usage |
|---|---|---|
| **REG_SZ** | Chaîne de caractères (string) | Chemins de fichiers, noms d'applications |
| **REG_DWORD** | Entier 32 bits (4 octets) | Paramètres booléens (0/1), compteurs, tailles |
| **REG_QWORD** | Entier 64 bits (8 octets) | Horodatages, grandes valeurs numériques |
| **REG_BINARY** | Données binaires brutes | Certificats, données chiffrées |
| **REG_MULTI_SZ** | Liste de chaînes (séparées par des null) | Listes de dépendances de services |
| **REG_EXPAND_SZ** | Chaîne avec variables d'environnement | `%SystemRoot%\System32\svchost.exe` |
| **REG_NONE** | Pas de type défini | Rare, utilisé pour des données non typées |

Les types les plus courants sont **REG_SZ** (chaînes) et **REG_DWORD** (entiers), qui représentent la grande majorité des valeurs du registre.

---

## 3. Les clés racines (Root Keys)

### 3.1 Vue d'ensemble

Le registre est organisé en cinq clés racines, chacune commençant par le préfixe `HKEY_` :

| Clé racine | Abréviation | Contenu |
|---|---|---|
| **HKEY_LOCAL_MACHINE** | HKLM | Configuration de la machine (matériel, logiciels, sécurité) |
| **HKEY_USERS** | HKU | Profils de configuration de tous les utilisateurs |
| **HKEY_CURRENT_USER** | HKCU | Profil de l'utilisateur actuellement connecté |
| **HKEY_CLASSES_ROOT** | HKCR | Associations de fichiers et objets COM |
| **HKEY_CURRENT_CONFIG** | HKCC | Configuration matérielle active |

> **À noter** : le préfixe **H** dans `HKEY` signifie **Handle**. Un handle est une référence légère que le système d'exploitation utilise pour identifier et interagir avec un objet du noyau. Chaque clé du registre est un objet noyau, et son handle permet aux programmes d'y accéder sans manipuler directement les structures internes du noyau.

### 3.2 HKEY_LOCAL_MACHINE (HKLM)

C'est la clé la plus importante pour la sécurité. Elle contient la configuration globale de la machine, indépendante de l'utilisateur connecté.

Sous-clés principales :

| Sous-clé | Contenu | Intérêt sécurité |
|---|---|---|
| **SAM** | Security Account Manager : base de données des comptes locaux et de leurs hashes de mots de passe | Cible de Mimikatz et des outils d'extraction de mots de passe. Accessible uniquement par le compte SYSTEM |
| **SECURITY** | Politique de sécurité locale, droits d'accès, politique d'audit | Configuration du LSA (Local Security Authority) |
| **SOFTWARE** | Configuration de tous les logiciels installés pour la machine | Clés `Run` pour la persistance, configuration des applications |
| **SYSTEM** | Configuration du noyau, des pilotes et des services | `CurrentControlSet\Services` contient la définition de tous les services |
| **HARDWARE** | Description du matériel détecté (clé volatile, régénérée à chaque démarrage) | Informations sur le processeur, la mémoire, les périphériques |

Clés de persistance à surveiller dans HKLM :

```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices
HKLM\SYSTEM\CurrentControlSet\Services\
```

### 3.3 HKEY_USERS (HKU)

Contient un profil de configuration pour **chaque utilisateur** ayant un compte sur la machine. Chaque sous-clé est identifiée par le **SID** (Security Identifier) de l'utilisateur.

Structure typique :

```
HKU
  ├── .DEFAULT                        <- Profil par défaut (utilisé pour la création de nouveaux profils)
  ├── S-1-5-18                        <- Compte SYSTEM
  ├── S-1-5-19                        <- Compte LOCAL SERVICE
  ├── S-1-5-20                        <- Compte NETWORK SERVICE
  ├── S-1-5-21-XXXX-XXXX-XXXX-1001   <- Premier utilisateur local
  └── S-1-5-21-XXXX-XXXX-XXXX-1002   <- Deuxième utilisateur local
```

Le SID suit le format `S-1-5-XXX...` :

| Partie du SID | Signification |
|---|---|
| `S` | Identifie une chaîne SID |
| `1` | Numéro de révision |
| `5` | Autorité d'identification (5 = NT Authority) |
| `21-XXXX-XXXX-XXXX` | Identifiant unique du domaine ou de la machine |
| `1001`, `1002`... | RID (Relative Identifier) de l'utilisateur |

Chaque profil utilisateur contient des paramètres tels que :

- Fond d'écran, résolution d'écran, thème
- Langue et région, disposition du clavier
- Préférences des applications
- Variables d'environnement utilisateur
- Clés `Run` spécifiques à l'utilisateur

```powershell
# Trouver le SID de l'utilisateur courant
whoami /user

# Lister les SID de tous les utilisateurs
Get-WmiObject Win32_UserAccount | Format-Table Name, SID -AutoSize
```

### 3.4 HKEY_CURRENT_USER (HKCU)

`HKCU` est un **lien symbolique** (alias) vers la sous-clé de `HKU` correspondant à l'utilisateur actuellement connecté. Ce n'est pas une copie : `HKCU` et `HKU\S-1-5-21-XXXX-1001` pointent exactement vers les mêmes données.

Clés de persistance à surveiller dans HKCU :

```
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKCU\Environment
```

### 3.5 HKEY_CLASSES_ROOT (HKCR) et HKEY_CURRENT_CONFIG (HKCC)

| Clé | Description |
|---|---|
| **HKCR** | Vue fusionnée de `HKLM\SOFTWARE\Classes` et `HKCU\SOFTWARE\Classes`. Contient les associations de fichiers (`.txt` -> Notepad) et les objets COM enregistrés |
| **HKCC** | Lien symbolique vers `HKLM\SYSTEM\CurrentControlSet\Hardware Profiles\Current`. Contient la configuration matérielle active (résolution, profil d'alimentation) |

---

## 4. Les ruches (Hives)

### 4.1 Définition

Une **ruche** (hive) est le fichier physique sur le disque qui contient une portion du registre. Au démarrage de Windows, le **Configuration Manager** (composant du noyau Executive) charge ces fichiers en mémoire et les rend accessibles sous forme de clés de registre.

### 4.2 Correspondance entre clés et fichiers

| Clé du registre | Fichier(s) sur le disque |
|---|---|
| `HKLM\SAM` | `C:\Windows\System32\config\SAM` |
| `HKLM\SECURITY` | `C:\Windows\System32\config\SECURITY` |
| `HKLM\SOFTWARE` | `C:\Windows\System32\config\SOFTWARE` |
| `HKLM\SYSTEM` | `C:\Windows\System32\config\SYSTEM` |
| `HKLM\HARDWARE` | Volatile (en mémoire uniquement, pas de fichier) |
| `HKU\.DEFAULT` | `C:\Windows\System32\config\DEFAULT` |
| `HKU\<SID utilisateur>` | `C:\Users\<nom>\NTUSER.DAT` |
| `HKU\<SID utilisateur>_Classes` | `C:\Users\<nom>\AppData\Local\Microsoft\Windows\UsrClass.dat` |

> **À noter** : les fichiers de ruche dans `C:\Windows\System32\config\` sont verrouillés par le système et ne peuvent pas être copiés directement pendant que Windows est en cours d'exécution. Pour une analyse forensique, il faut utiliser des outils spécialisés comme **FTK Imager** ou démarrer sur un autre système pour accéder au disque.

### 4.3 Fichiers associés aux ruches

Chaque fichier de ruche est accompagné de fichiers auxiliaires :

| Extension | Rôle |
|---|---|
| (aucune) | Fichier de ruche principal |
| `.LOG`, `.LOG1`, `.LOG2` | Journaux de transactions (permettent la récupération en cas de crash) |
| `.sav` | Sauvegarde de la ruche lors de l'installation |

### 4.4 Le Configuration Manager

Le **Configuration Manager** est le composant du noyau Windows (partie de l'Executive) responsable de la gestion du registre. Il assure les fonctions suivantes :

- Charger les fichiers de ruche au démarrage
- Gérer les lectures et écritures dans le registre
- Assurer la cohérence des données via les journaux de transactions
- Appliquer les contrôles d'accès (ACL) sur les clés du registre
- Flusher (écrire) périodiquement les modifications en mémoire vers les fichiers sur le disque

---

## 5. Utilisation du registre en PowerShell

### 5.1 Naviguer dans le registre

PowerShell traite le registre comme un système de fichiers. Les deux "lecteurs" (drives) disponibles sont `HKLM:` et `HKCU:`.

```powershell
# Lister les sous-clés d'une clé
Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion"

# Se déplacer dans le registre
Set-Location "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion"
Get-ChildItem
```

### 5.2 Lire des valeurs

```powershell
# Lire toutes les valeurs d'une clé
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

# Lire une valeur spécifique
Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth"

# Lister les programmes de démarrage automatique
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
```

### 5.3 Modifier des valeurs

```powershell
# Créer une nouvelle clé
New-Item -Path "HKCU:\SOFTWARE\MonApplication"

# Ajouter une valeur de type chaîne
New-ItemProperty -Path "HKCU:\SOFTWARE\MonApplication" -Name "Version" -Value "1.0" -PropertyType String

# Ajouter une valeur de type entier
New-ItemProperty -Path "HKCU:\SOFTWARE\MonApplication" -Name "Enabled" -Value 1 -PropertyType DWord

# Modifier une valeur existante
Set-ItemProperty -Path "HKCU:\SOFTWARE\MonApplication" -Name "Version" -Value "2.0"

# Supprimer une valeur
Remove-ItemProperty -Path "HKCU:\SOFTWARE\MonApplication" -Name "Version"

# Supprimer une clé entière (et toutes ses sous-clés)
Remove-Item -Path "HKCU:\SOFTWARE\MonApplication" -Recurse
```

### 5.4 Exporter et importer

```powershell
# Exporter une clé vers un fichier .reg (avec reg.exe)
reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" C:\backup_run.reg

# Importer un fichier .reg
reg import C:\backup_run.reg
```

### 5.5 Rechercher dans le registre

```powershell
# Rechercher une valeur dans toutes les sous-clés
Get-ChildItem -Path "HKLM:\SOFTWARE" -Recurse -ErrorAction SilentlyContinue |
    Get-ItemProperty -ErrorAction SilentlyContinue |
    Where-Object { $_ -match "svchost" }
```

> **Bonne pratique** : avant toute modification du registre, toujours exporter la clé concernée avec `reg export` pour pouvoir restaurer l'état initial en cas de problème.

---

## 6. Clés de registre critiques pour la sécurité

### 6.1 Persistance (programmes lancés automatiquement)

```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon (valeurs Shell, Userinit)
```

### 6.2 Services

```
HKLM\SYSTEM\CurrentControlSet\Services\
```

Chaque sous-clé contient la configuration d'un service : chemin de l'exécutable (`ImagePath`), type de démarrage (`Start`), compte d'exécution (`ObjectName`).

### 6.3 Sécurité et authentification

```
HKLM\SAM\SAM\Domains\Account\Users\       <- Hashes des mots de passe
HKLM\SECURITY\Policy\Secrets\             <- Secrets LSA (mots de passe de services)
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon <- Configuration de connexion
```

### 6.4 Pare-feu

```
HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\
```

### 6.5 Audit rapide des clés de persistance

```powershell
# Vérifier les programmes de démarrage automatique
Write-Host "=== HKLM Run ===" -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue

Write-Host "`n=== HKCU Run ===" -ForegroundColor Cyan
Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue

Write-Host "`n=== HKLM RunOnce ===" -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -ErrorAction SilentlyContinue

Write-Host "`n=== HKCU RunOnce ===" -ForegroundColor Cyan
Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -ErrorAction SilentlyContinue
```

---

## Récapitulatif

| Concept | Description |
|---|---|
| **Registre** | Base de données hiérarchique centralisée de configuration |
| **Clé** | Conteneur (équivalent d'un dossier) pouvant contenir des sous-clés et des valeurs |
| **Valeur** | Donnée de configuration identifiée par un nom et un type |
| **REG_SZ / REG_DWORD** | Types les plus courants : chaîne de caractères et entier 32 bits |
| **HKLM** | Configuration globale de la machine |
| **HKU** | Profils de tous les utilisateurs (identifiés par SID) |
| **HKCU** | Lien symbolique vers le profil de l'utilisateur courant dans HKU |
| **Hive (ruche)** | Fichier physique sur le disque contenant une portion du registre |
| **Configuration Manager** | Composant du noyau qui gère le registre |

---

## Pour aller plus loin

- [Windows Registry (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry)
- [Registry Hives (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives)
- [Autoruns (Sysinternals)](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns) - outil graphique pour visualiser tous les mécanismes de démarrage automatique
- [MITRE ATT&CK - Boot or Logon Autostart Execution: Registry Run Keys (T1547.001)](https://attack.mitre.org/techniques/T1547/001/)
- [SAM Database and Password Hashes (SANS)](https://www.sans.org/blog/protecting-privileged-domain-accounts-safeguarding-password-hashes/)
