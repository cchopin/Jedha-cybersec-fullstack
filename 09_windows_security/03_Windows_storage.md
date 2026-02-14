# Stockage et permissions sous Windows

**Module** : administration Windows 

---

## Objectifs du module

À l'issue de ce module, les compétences suivantes seront acquises :

- Comprendre les systèmes de fichiers utilisés par Windows, en particulier NTFS
- Lire et interpréter les permissions NTFS sur un fichier ou un dossier
- Gérer les permissions via l'interface graphique et en ligne de commande (PowerShell)
- Connaître les mécanismes d'héritage et de permissions avancées

> **Prérequis** : avoir suivi les modules "Prise en main de la sécurité Windows" et "Gestion des utilisateurs et groupes".

---

## 1. Les systèmes de fichiers Windows

### 1.1 NTFS : le système de fichiers principal

Les machines Windows modernes utilisent **NTFS** (New Technology File System) comme système de fichiers par défaut. C'est le seul système de fichiers Windows qui prend en charge nativement les permissions granulaires sur les fichiers et dossiers, ce qui en fait un pilier de la sécurité du système d'exploitation.

Pour vérifier le système de fichiers utilisé sur une machine, deux méthodes sont possibles :

**Via PowerShell** :

```powershell
Get-Volume | Select-Object DriveLetter, FileSystem, FileSystemLabel, Size, SizeRemaining
```

**Via l'interface graphique** : clic droit sur le lecteur `C:\` dans l'Explorateur de fichiers > Propriétés. Le type de système de fichiers apparaît dans l'onglet "Général".

### 1.2 Comparaison des systèmes de fichiers

NTFS n'est pas le seul système de fichiers que Windows peut utiliser. Le tableau ci-dessous recense les principaux systèmes de fichiers susceptibles d'être rencontrés :

| Système de fichiers | Taille max. de fichier | Usage principal | Permissions | Amorçable |
|---|---|---|---|---|
| **NTFS** | 16 To+ | Disques système, disques internes | Oui | Oui |
| **FAT32** | 4 Go | Clés USB de petite capacité, compatibilité legacy | Non | Oui |
| **exFAT** | 16 Eo | Stockage flash, cartes SD de grande capacité | Non | Partiel |
| **ReFS** | Très grande | Stockage serveur, volumes de données | Partiel | Non |
| **FAT16** | 2 Go | Appareils embarqués, systèmes legacy | Non | Oui |
| **CDFS** | N/A | CD-ROM | Lecture seule | Non |
| **UDF** | 2 To+ | DVD, Blu-ray, écriture ISO | Lecture seule (majoritairement) | Non |
| **ISO 9660** | N/A | Images amorçables | Lecture seule | Oui |

En pratique, deux systèmes de fichiers dominent l'écosystème Windows actuel :

- **NTFS** pour les disques système et les disques internes (seul choix offrant des permissions complètes)
- **FAT32** pour les supports amovibles nécessitant une compatibilité universelle entre systèmes d'exploitation (Windows, macOS, Linux)

ReFS (Resilient File System) est une alternative moderne à NTFS, conçue pour les environnements serveur. Elle offre une meilleure résistance à la corruption de données mais ne prend pas en charge toutes les fonctionnalités NTFS (notamment le démarrage système).

---

## 2. Permissions NTFS

La capacité à définir des permissions granulaires sur les fichiers et dossiers est la fonctionnalité la plus importante de NTFS du point de vue de la sécurité. Chaque fichier et chaque dossier possède une liste de contrôle d'accès (ACL) qui détermine quels utilisateurs ou groupes peuvent effectuer quelles opérations.

### 2.1 Les six niveaux de permissions

| Permission | Lecture | Écriture | Modification | Suppression | Exécution | Changement de permissions | Prise de propriété |
|---|---|---|---|---|---|---|---|
| **Full Control** | Oui | Oui | Oui | Oui | Oui | Oui | Oui |
| **Modify** | Oui | Oui | Oui | Oui | Oui | Non | Non |
| **Read & Execute** | Oui | Non | Non | Non | Oui | Non | Non |
| **List Folder Contents** | Oui (noms uniquement) | Non | Non | Non | Non | Non | Non |
| **Read** | Oui | Non | Non | Non | Non | Non | Non |
| **Write** | Non | Oui | Non | Non | Non | Non | Non |

Quelques précisions importantes :

- **Full Control** est la seule permission qui autorise la modification des permissions elles-mêmes et la prise de propriété d'un objet. Elle doit être attribuée avec parcimonie.
- **Modify** couvre la grande majorité des besoins en production (lecture, écriture, modification, suppression) sans donner le contrôle des permissions.
- **List Folder Contents** est spécifique aux dossiers : elle permet de voir les noms des fichiers et sous-dossiers, mais pas d'accéder à leur contenu.
- **Write** sans **Read** signifie qu'un utilisateur peut créer ou modifier des fichiers sans pouvoir lire le contenu existant (cas rare, mais utile pour certains dossiers de dépôt).

> **Bonne pratique** : toujours attribuer le niveau de permission le plus restrictif qui permet à l'utilisateur d'accomplir sa tâche. C'est l'application directe du principe du moindre privilège.

### 2.2 Héritage des permissions

Par défaut, les fichiers et dossiers **héritent** des permissions de leur dossier parent. Cela signifie que les permissions définies sur un dossier s'appliquent automatiquement à tout son contenu (fichiers et sous-dossiers).

Ce mécanisme est visible dans la colonne `IsInherited` lors de la consultation des permissions en PowerShell, et via la mention "Hérité de..." dans l'interface graphique.

Il est possible de **désactiver l'héritage** sur un dossier ou un fichier spécifique pour y appliquer des permissions personnalisées. Lors de la désactivation, Windows propose deux options :

- **Convertir les permissions héritées en permissions explicites** : les permissions actuelles sont conservées mais deviennent indépendantes du parent.
- **Supprimer toutes les permissions héritées** : le fichier ou dossier se retrouve sans aucune permission (à manipuler avec précaution).

### 2.3 Permissions avancées

Les six permissions présentées en section 2.1 sont en réalité des regroupements de permissions plus granulaires. L'interface graphique permet d'y accéder via le bouton "Afficher les autorisations avancées" lors de la modification des permissions d'un utilisateur ou d'un groupe.

Ces permissions avancées permettent un contrôle très fin, par exemple : autoriser la lecture des attributs d'un fichier sans autoriser la lecture de son contenu, ou autoriser la création de fichiers dans un dossier sans autoriser la création de sous-dossiers.

En pratique, les permissions standard suffisent dans la grande majorité des cas. Les permissions avancées sont surtout utiles pour des scénarios spécifiques (dossiers de dépôt, partages applicatifs, conformité réglementaire).

---

## 3. Gestion des permissions via l'interface graphique

### 3.1 Consulter les permissions

Pour consulter les permissions d'un fichier ou d'un dossier :

1. Clic droit sur l'élément > Propriétés
2. Onglet "Sécurité"
3. La liste des utilisateurs et groupes autorisés apparaît, ainsi que leurs permissions respectives

### 3.2 Modifier les permissions

1. Dans l'onglet "Sécurité", cliquer sur "Modifier"
2. Pour ajouter un utilisateur ou un groupe : cliquer sur "Ajouter", saisir le nom, puis cocher les permissions souhaitées
3. Pour modifier les permissions d'une entrée existante : la sélectionner et ajuster les cases à cocher
4. Pour supprimer une entrée : la sélectionner et cliquer sur "Supprimer"

> **Attention** : la suppression d'une entrée de permissions est immédiate et irréversible via cette interface. Toujours vérifier les permissions avant de valider.

---

## 4. Gestion des permissions en ligne de commande

L'interface graphique est pratique pour des opérations ponctuelles, mais la ligne de commande est indispensable pour l'automatisation et l'audit à grande échelle.

### 4.1 Le module NTFSSecurity

Le module PowerShell **NTFSSecurity** offre une syntaxe claire et des cmdlets dédiées à la gestion des permissions NTFS.

**Installation** (si nécessaire, en tant qu'administrateur) :

```powershell
Install-Module -Name NTFSSecurity -Scope CurrentUser
```

Si la politique d'exécution bloque l'importation du module :

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### 4.2 Consulter les permissions

```powershell
Get-NTFSAccess -Path "C:\Users\jedha-student\Desktop\helloFromJedha.txt"
```

Exemple de sortie :

```
Account                             Access Rights  Applies to                Type           IsInherited   InheritedFrom
-------                             -------------  ----------                ----           -----------   -------------
NT AUTHORITY\SYSTEM                 FullControl    ThisFolderOnly            Allow          True          C:\Users\j...
BUILTIN\Administrators              FullControl    ThisFolderOnly            Allow          True          C:\Users\j...
WIN11\jedha-student                 FullControl    ThisFolderOnly            Allow          True          C:\Users\j...
```

Lecture des colonnes :

| Colonne | Signification |
|---|---|
| `Account` | Utilisateur ou groupe concerné (préfixé par le nom de la machine ou du domaine) |
| `Access Rights` | Niveau de permission accordé |
| `Applies to` | Portée de la permission (dossier seul, fichiers, sous-dossiers...) |
| `Type` | `Allow` (autoriser) ou `Deny` (refuser) |
| `IsInherited` | `True` si la permission provient du dossier parent, `False` si elle est explicite |
| `InheritedFrom` | Chemin du dossier d'où provient l'héritage |

> **À noter** : le préfixe avant le nom du compte (ex. `WIN11\Finance`) correspond au nom de la machine locale. Pour les comptes de domaine, ce préfixe serait remplacé par le nom du domaine (ex. `JEDHA\Finance`). Le nom de la machine est visible dans Paramètres > Système > À propos.

### 4.3 Ajouter des permissions

```powershell
Add-NTFSAccess -Path "C:\Users\jedha-student\Desktop\helloFromJedha.txt" `
    -Account "WIN11\Finance" `
    -AccessRights Modify
```

Si la commande s'exécute sans erreur ni sortie, l'opération a réussi. Il est recommandé de vérifier ensuite avec `Get-NTFSAccess`.

Les valeurs possibles pour `-AccessRights` correspondent aux permissions standard : `FullControl`, `Modify`, `ReadAndExecute`, `ListDirectory`, `Read`, `Write`.

### 4.4 Supprimer des permissions

```powershell
Remove-NTFSAccess -Path "C:\Users\jedha-student\Desktop\helloFromJedha.txt" `
    -Account "WIN11\Finance" `
    -AccessRights Modify
```

> **Point de vigilance** : la suppression est immédiate. En environnement de production, toujours exporter les permissions existantes avant toute modification (voir section 4.5).

### 4.5 Commandes utiles pour l'audit

```powershell
# Lister les permissions de tous les fichiers d'un dossier (récursif)
Get-ChildItem -Path "C:\Partage" -Recurse | Get-NTFSAccess

# Exporter les permissions dans un fichier CSV pour analyse
Get-ChildItem -Path "C:\Partage" -Recurse | Get-NTFSAccess | Export-Csv -Path "C:\audit_permissions.csv" -NoTypeInformation

# Vérifier l'héritage sur un dossier
Get-NTFSInheritance -Path "C:\Partage"

# Rechercher les permissions explicites (non héritées) — souvent révélatrices d'exceptions à auditer
Get-ChildItem -Path "C:\Partage" -Recurse | Get-NTFSAccess | Where-Object { $_.IsInherited -eq $false }
```

### 4.6 Alternative : icacls

Windows intègre nativement l'outil en ligne de commande `icacls`, qui ne nécessite aucune installation de module. Sa syntaxe est moins lisible que celle de NTFSSecurity, mais il est disponible sur toutes les machines Windows :

```powershell
# Consulter les permissions
icacls "C:\Users\jedha-student\Desktop\helloFromJedha.txt"

# Accorder la permission Modify au groupe Finance
icacls "C:\Users\jedha-student\Desktop\helloFromJedha.txt" /grant "Finance:(M)"

# Retirer toutes les permissions du groupe Finance
icacls "C:\Users\jedha-student\Desktop\helloFromJedha.txt" /remove "Finance"

# Sauvegarder les permissions d'une arborescence
icacls "C:\Partage" /save "C:\backup_acl.txt" /T

# Restaurer les permissions depuis une sauvegarde
icacls "C:\Partage" /restore "C:\backup_acl.txt"
```

Les codes de permissions `icacls` les plus courants :

| Code | Permission |
|---|---|
| `(F)` | Full Control |
| `(M)` | Modify |
| `(RX)` | Read & Execute |
| `(R)` | Read |
| `(W)` | Write |

> **Conseil** : `icacls` est particulièrement utile pour les scripts de sauvegarde/restauration de permissions, là où NTFSSecurity excelle pour l'audit et la consultation.

---

## Récapitulatif

| Opération | GUI | PowerShell (NTFSSecurity) | icacls |
|---|---|---|---|
| Consulter les permissions | Clic droit > Propriétés > Sécurité | `Get-NTFSAccess` | `icacls chemin` |
| Ajouter une permission | Onglet Sécurité > Modifier > Ajouter | `Add-NTFSAccess` | `icacls /grant` |
| Supprimer une permission | Onglet Sécurité > Modifier > Supprimer | `Remove-NTFSAccess` | `icacls /remove` |
| Vérifier l'héritage | Autorisations avancées | `Get-NTFSInheritance` | `icacls /verify` |
| Sauvegarder les permissions | N/A | `Export-Csv` | `icacls /save` |

---

## Pour aller plus loin

- [Managing Windows permissions with CLI - icacls (YouTube)](https://www.youtube.com/results?search_query=Managing+Windows+permissions+CLI+icacls)
- [FAT32 vs exFAT vs NTFS - Windows File Systems (YouTube)](https://www.youtube.com/results?search_query=FAT32+vs+exFAT+vs+NTFS)
- [NTFS Permissions - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/storage/file-server/ntfs-overview)
- [NTFSSecurity Module - PowerShell Gallery](https://www.powershellgallery.com/packages/NTFSSecurity/)
- [icacls - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)
