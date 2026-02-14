# Le registre Windows

**Module** : comprendre la base de donnees de configuration centralisee de Windows

---

## Objectifs du module

A l'issue de ce module, les competences suivantes seront acquises :

- Comprendre le role et l'architecture du registre Windows
- Naviguer dans la structure hierarchique du registre (cles, valeurs, types de donnees)
- Connaitre les cinq cles racines (root keys) et leur contenu
- Distinguer les hives (ruches) et localiser leurs fichiers physiques sur le disque
- Utiliser PowerShell et regedit pour lire et modifier le registre
- Identifier les risques de securite lies au registre

---

## 1. Presentation du registre

### 1.1 Definition

Le **registre Windows** (Windows Registry) est une base de donnees hierarchique centralisee qui stocke l'ensemble des parametres de configuration du systeme d'exploitation, des applications installees et des preferences utilisateur.

Le registre a ete introduit avec Windows 3.1 (1992) pour remplacer progressivement les fichiers de configuration texte `.INI` qui etaient utilises par les versions precedentes. Les fichiers `.INI` posaient plusieurs problemes : pas de structure standard, pas de controle d'acces, difficultes de recherche, et risque de corruption.

### 1.2 Pourquoi le registre est important en securite

Le registre est un element central pour la securite Windows car il contient :

| Contenu | Exemple |
|---|---|
| **Configuration des services** | Type de demarrage, chemin de l'executable, compte d'execution |
| **Programmes de demarrage automatique** | Cles `Run`, `RunOnce` executees a chaque connexion |
| **Politique de securite** | Politique de mots de passe, restrictions d'acces |
| **Informations d'authentification** | Base SAM (hashes des mots de passe locaux) |
| **Configuration du pare-feu** | Regles et exceptions |
| **Historique d'execution** | Derniers programmes executes, fichiers recents |

> **A noter** : le registre est l'un des premiers endroits ou les malwares etablissent leur **persistance** (capacite a survivre a un redemarrage). Les cles `Run` et `RunOnce` sont les vecteurs de persistance les plus courants (technique MITRE ATT&CK T1547.001).

### 1.3 Outils d'acces au registre

| Outil | Type | Usage |
|---|---|---|
| `regedit.exe` | Interface graphique | Navigation, recherche, modification manuelle |
| PowerShell | Ligne de commande | Automatisation, scripts d'audit |
| `reg.exe` | Ligne de commande (cmd) | Lecture, ecriture, export/import en ligne de commande |
| Panneau de configuration | Interface graphique | Modifie le registre de maniere transparente pour l'utilisateur |

---

## 2. Structure du registre

### 2.1 Cles et valeurs

Le registre est organise de maniere hierarchique, similaire a un systeme de fichiers :

| Concept registre | Analogie systeme de fichiers | Description |
|---|---|---|
| **Cle** (Key) | Dossier | Conteneur qui peut contenir des sous-cles et des valeurs |
| **Sous-cle** (Subkey) | Sous-dossier | Cle contenue dans une autre cle |
| **Valeur** (Value) | Fichier | Donnee de configuration identifiee par un nom |
| **Donnee** (Data) | Contenu du fichier | La valeur effective stockee |

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

Dans cet exemple, `Run` est une **cle**, et `SecurityHealth` est une **valeur** dont la **donnee** est le chemin vers l'executable.

### 2.2 Types de donnees

Chaque valeur du registre a un type qui definit le format de la donnee stockee :

| Type | Description | Exemple d'usage |
|---|---|---|
| **REG_SZ** | Chaine de caracteres (string) | Chemins de fichiers, noms d'applications |
| **REG_DWORD** | Entier 32 bits (4 octets) | Parametres booleens (0/1), compteurs, tailles |
| **REG_QWORD** | Entier 64 bits (8 octets) | Horodatages, grandes valeurs numeriques |
| **REG_BINARY** | Donnees binaires brutes | Certificats, donnees chiffrees |
| **REG_MULTI_SZ** | Liste de chaines (separees par des null) | Listes de dependances de services |
| **REG_EXPAND_SZ** | Chaine avec variables d'environnement | `%SystemRoot%\System32\svchost.exe` |
| **REG_NONE** | Pas de type defini | Rare, utilise pour des donnees non typees |

Les types les plus courants sont **REG_SZ** (chaines) et **REG_DWORD** (entiers), qui representent la grande majorite des valeurs du registre.

---

## 3. Les cles racines (Root Keys)

### 3.1 Vue d'ensemble

Le registre est organise en cinq cles racines, chacune commencant par le prefixe `HKEY_` :

| Cle racine | Abreviation | Contenu |
|---|---|---|
| **HKEY_LOCAL_MACHINE** | HKLM | Configuration de la machine (materiel, logiciels, securite) |
| **HKEY_USERS** | HKU | Profils de configuration de tous les utilisateurs |
| **HKEY_CURRENT_USER** | HKCU | Profil de l'utilisateur actuellement connecte |
| **HKEY_CLASSES_ROOT** | HKCR | Associations de fichiers et objets COM |
| **HKEY_CURRENT_CONFIG** | HKCC | Configuration materielle active |

> **A noter** : le prefixe **H** dans `HKEY` signifie **Handle**. Un handle est une reference legere que le systeme d'exploitation utilise pour identifier et interagir avec un objet du noyau. Chaque cle du registre est un objet noyau, et son handle permet aux programmes d'y acceder sans manipuler directement les structures internes du noyau.

### 3.2 HKEY_LOCAL_MACHINE (HKLM)

C'est la cle la plus importante pour la securite. Elle contient la configuration globale de la machine, independante de l'utilisateur connecte.

Sous-cles principales :

| Sous-cle | Contenu | Interet securite |
|---|---|---|
| **SAM** | Security Account Manager : base de donnees des comptes locaux et de leurs hashes de mots de passe | Cible de Mimikatz et des outils d'extraction de mots de passe. Accessible uniquement par le compte SYSTEM |
| **SECURITY** | Politique de securite locale, droits d'acces, politique d'audit | Configuration du LSA (Local Security Authority) |
| **SOFTWARE** | Configuration de tous les logiciels installes pour la machine | Cles `Run` pour la persistance, configuration des applications |
| **SYSTEM** | Configuration du noyau, des pilotes et des services | `CurrentControlSet\Services` contient la definition de tous les services |
| **HARDWARE** | Description du materiel detecte (cle volatile, regeneree a chaque demarrage) | Informations sur le processeur, la memoire, les peripheriques |

Cles de persistance a surveiller dans HKLM :

```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices
HKLM\SYSTEM\CurrentControlSet\Services\
```

### 3.3 HKEY_USERS (HKU)

Contient un profil de configuration pour **chaque utilisateur** ayant un compte sur la machine. Chaque sous-cle est identifiee par le **SID** (Security Identifier) de l'utilisateur.

Structure typique :

```
HKU
  ├── .DEFAULT                        <- Profil par defaut (utilise pour la creation de nouveaux profils)
  ├── S-1-5-18                        <- Compte SYSTEM
  ├── S-1-5-19                        <- Compte LOCAL SERVICE
  ├── S-1-5-20                        <- Compte NETWORK SERVICE
  ├── S-1-5-21-XXXX-XXXX-XXXX-1001   <- Premier utilisateur local
  └── S-1-5-21-XXXX-XXXX-XXXX-1002   <- Deuxieme utilisateur local
```

Le SID suit le format `S-1-5-XXX...` :

| Partie du SID | Signification |
|---|---|
| `S` | Identifie une chaine SID |
| `1` | Numero de revision |
| `5` | Autorite d'identification (5 = NT Authority) |
| `21-XXXX-XXXX-XXXX` | Identifiant unique du domaine ou de la machine |
| `1001`, `1002`... | RID (Relative Identifier) de l'utilisateur |

Chaque profil utilisateur contient des parametres tels que :

- Fond d'ecran, resolution d'ecran, theme
- Langue et region, disposition du clavier
- Preferences des applications
- Variables d'environnement utilisateur
- Cles `Run` specifiques a l'utilisateur

```powershell
# Trouver le SID de l'utilisateur courant
whoami /user

# Lister les SID de tous les utilisateurs
Get-WmiObject Win32_UserAccount | Format-Table Name, SID -AutoSize
```

### 3.4 HKEY_CURRENT_USER (HKCU)

`HKCU` est un **lien symbolique** (alias) vers la sous-cle de `HKU` correspondant a l'utilisateur actuellement connecte. Ce n'est pas une copie : `HKCU` et `HKU\S-1-5-21-XXXX-1001` pointent exactement vers les memes donnees.

Cles de persistance a surveiller dans HKCU :

```
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKCU\Environment
```

### 3.5 HKEY_CLASSES_ROOT (HKCR) et HKEY_CURRENT_CONFIG (HKCC)

| Cle | Description |
|---|---|
| **HKCR** | Vue fusionnee de `HKLM\SOFTWARE\Classes` et `HKCU\SOFTWARE\Classes`. Contient les associations de fichiers (`.txt` -> Notepad) et les objets COM enregistres |
| **HKCC** | Lien symbolique vers `HKLM\SYSTEM\CurrentControlSet\Hardware Profiles\Current`. Contient la configuration materielle active (resolution, profil d'alimentation) |

---

## 4. Les ruches (Hives)

### 4.1 Definition

Une **ruche** (hive) est le fichier physique sur le disque qui contient une portion du registre. Au demarrage de Windows, le **Configuration Manager** (composant du noyau Executive) charge ces fichiers en memoire et les rend accessibles sous forme de cles de registre.

### 4.2 Correspondance entre cles et fichiers

| Cle du registre | Fichier(s) sur le disque |
|---|---|
| `HKLM\SAM` | `C:\Windows\System32\config\SAM` |
| `HKLM\SECURITY` | `C:\Windows\System32\config\SECURITY` |
| `HKLM\SOFTWARE` | `C:\Windows\System32\config\SOFTWARE` |
| `HKLM\SYSTEM` | `C:\Windows\System32\config\SYSTEM` |
| `HKLM\HARDWARE` | Volatile (en memoire uniquement, pas de fichier) |
| `HKU\.DEFAULT` | `C:\Windows\System32\config\DEFAULT` |
| `HKU\<SID utilisateur>` | `C:\Users\<nom>\NTUSER.DAT` |
| `HKU\<SID utilisateur>_Classes` | `C:\Users\<nom>\AppData\Local\Microsoft\Windows\UsrClass.dat` |

> **A noter** : les fichiers de ruche dans `C:\Windows\System32\config\` sont verrouilles par le systeme et ne peuvent pas etre copies directement pendant que Windows est en cours d'execution. Pour une analyse forensique, il faut utiliser des outils specialises comme **FTK Imager** ou demarrer sur un autre systeme pour acceder au disque.

### 4.3 Fichiers associes aux ruches

Chaque fichier de ruche est accompagne de fichiers auxiliaires :

| Extension | Role |
|---|---|
| (aucune) | Fichier de ruche principal |
| `.LOG`, `.LOG1`, `.LOG2` | Journaux de transactions (permettent la recuperation en cas de crash) |
| `.sav` | Sauvegarde de la ruche lors de l'installation |

### 4.4 Le Configuration Manager

Le **Configuration Manager** est le composant du noyau Windows (partie de l'Executive) responsable de la gestion du registre. Il assure les fonctions suivantes :

- Charger les fichiers de ruche au demarrage
- Gerer les lectures et ecritures dans le registre
- Assurer la coherence des donnees via les journaux de transactions
- Appliquer les controles d'acces (ACL) sur les cles du registre
- Flusher (ecrire) periodiquement les modifications en memoire vers les fichiers sur le disque

---

## 5. Utilisation du registre en PowerShell

### 5.1 Naviguer dans le registre

PowerShell traite le registre comme un systeme de fichiers. Les deux "lecteurs" (drives) disponibles sont `HKLM:` et `HKCU:`.

```powershell
# Lister les sous-cles d'une cle
Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion"

# Se deplacer dans le registre
Set-Location "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion"
Get-ChildItem
```

### 5.2 Lire des valeurs

```powershell
# Lire toutes les valeurs d'une cle
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

# Lire une valeur specifique
Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth"

# Lister les programmes de demarrage automatique
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
```

### 5.3 Modifier des valeurs

```powershell
# Creer une nouvelle cle
New-Item -Path "HKCU:\SOFTWARE\MonApplication"

# Ajouter une valeur de type chaine
New-ItemProperty -Path "HKCU:\SOFTWARE\MonApplication" -Name "Version" -Value "1.0" -PropertyType String

# Ajouter une valeur de type entier
New-ItemProperty -Path "HKCU:\SOFTWARE\MonApplication" -Name "Enabled" -Value 1 -PropertyType DWord

# Modifier une valeur existante
Set-ItemProperty -Path "HKCU:\SOFTWARE\MonApplication" -Name "Version" -Value "2.0"

# Supprimer une valeur
Remove-ItemProperty -Path "HKCU:\SOFTWARE\MonApplication" -Name "Version"

# Supprimer une cle entiere (et toutes ses sous-cles)
Remove-Item -Path "HKCU:\SOFTWARE\MonApplication" -Recurse
```

### 5.4 Exporter et importer

```powershell
# Exporter une cle vers un fichier .reg (avec reg.exe)
reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" C:\backup_run.reg

# Importer un fichier .reg
reg import C:\backup_run.reg
```

### 5.5 Rechercher dans le registre

```powershell
# Rechercher une valeur dans toutes les sous-cles
Get-ChildItem -Path "HKLM:\SOFTWARE" -Recurse -ErrorAction SilentlyContinue |
    Get-ItemProperty -ErrorAction SilentlyContinue |
    Where-Object { $_ -match "svchost" }
```

> **Bonne pratique** : avant toute modification du registre, toujours exporter la cle concernee avec `reg export` pour pouvoir restaurer l'etat initial en cas de probleme.

---

## 6. Cles de registre critiques pour la securite

### 6.1 Persistance (programmes lances automatiquement)

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

Chaque sous-cle contient la configuration d'un service : chemin de l'executable (`ImagePath`), type de demarrage (`Start`), compte d'execution (`ObjectName`).

### 6.3 Securite et authentification

```
HKLM\SAM\SAM\Domains\Account\Users\       <- Hashes des mots de passe
HKLM\SECURITY\Policy\Secrets\             <- Secrets LSA (mots de passe de services)
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon <- Configuration de connexion
```

### 6.4 Pare-feu

```
HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\
```

### 6.5 Audit rapide des cles de persistance

```powershell
# Verifier les programmes de demarrage automatique
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

## Recapitulatif

| Concept | Description |
|---|---|
| **Registre** | Base de donnees hierarchique centralisee de configuration |
| **Cle** | Conteneur (equivalent d'un dossier) pouvant contenir des sous-cles et des valeurs |
| **Valeur** | Donnee de configuration identifiee par un nom et un type |
| **REG_SZ / REG_DWORD** | Types les plus courants : chaine de caracteres et entier 32 bits |
| **HKLM** | Configuration globale de la machine |
| **HKU** | Profils de tous les utilisateurs (identifies par SID) |
| **HKCU** | Lien symbolique vers le profil de l'utilisateur courant dans HKU |
| **Hive (ruche)** | Fichier physique sur le disque contenant une portion du registre |
| **Configuration Manager** | Composant du noyau qui gere le registre |

---

## Pour aller plus loin

- [Windows Registry (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry)
- [Registry Hives (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives)
- [Autoruns (Sysinternals)](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns) - outil graphique pour visualiser tous les mecanismes de demarrage automatique
- [MITRE ATT&CK - Boot or Logon Autostart Execution: Registry Run Keys (T1547.001)](https://attack.mitre.org/techniques/T1547/001/)
- [SAM Database and Password Hashes (SANS)](https://www.sans.org/blog/protecting-privileged-domain-accounts-safeguarding-password-hashes/)
