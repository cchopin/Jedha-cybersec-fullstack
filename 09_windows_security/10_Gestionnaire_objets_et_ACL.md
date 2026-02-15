# Gestionnaire d'objets et listes de contrôle d'accès (ACL)

**Module** : comprendre l'Object Manager, la Win32 API et le système de permissions Windows

---

## Objectifs du module

À l'issue de ce module, les compétences suivantes seront acquises :

- Comprendre le rôle de l'Object Manager dans l'architecture du noyau Windows
- Maîtriser le concept d'objet noyau et de handle
- Connaître la Win32 API et son rôle d'intermédiaire entre les applications et le noyau
- Comprendre la résolution des chemins par le noyau (chemins Win32 vs chemins kernel)
- Maîtriser le système d'ACL Windows : Security Descriptor, DACL, SACL, ACE
- Utiliser `icacls`, `Get-Acl` et SDDL pour auditer et configurer les permissions
- Configurer l'audit d'accès via les SACL

---

## 1. L'Object Manager

### 1.1 Principe fondamental : tout est un objet

Dans l'architecture Windows, le noyau manipule toutes les ressources système sous forme d'**objets**. L'**Object Manager** est le composant de l'Executive du noyau responsable de la création, de la gestion et de la destruction de ces objets.

Exemples de ressources représentées comme des objets noyau :

| Type d'objet | Exemples |
|---|---|
| **Fichier** | Document Word, image, exécutable |
| **Dossier** | Répertoire du système de fichiers |
| **Processus** | Instance en cours d'exécution d'un programme |
| **Thread** | Fil d'exécution au sein d'un processus |
| **Clé de registre** | Clé dans la base de registre |
| **Section** | Zone de mémoire partagée entre processus |
| **Mutex** | Mécanisme de synchronisation entre threads |
| **Événement** | Signal de notification entre processus |
| **Pipe** | Canal de communication entre processus |

### 1.2 Propriétés d'un objet noyau

Chaque objet noyau possède des propriétés communes :

| Propriété | Description |
|---|---|
| **Nom** | Identifiant dans l'espace de noms du noyau (ex : `\Device\HarddiskVolume1\Users\...`) |
| **Type** | Type de l'objet (File, Process, Key, etc.) |
| **Security Descriptor** | Descripteur de sécurité contenant les ACL (qui peut accéder à cet objet et avec quelles permissions) |
| **Compteur de références** | Nombre de handles et de références pointant vers l'objet. L'objet est détruit quand ce compteur atteint zéro |
| **Handle** | Référence opaque permettant aux programmes en mode utilisateur d'interagir avec l'objet |

### 1.3 Les handles

Un **handle** est une référence indirecte et opaque vers un objet noyau. Les programmes en mode utilisateur ne peuvent jamais accéder directement aux structures internes du noyau. Ils utilisent des handles (de simples numéros) que le noyau traduit en références vers les vrais objets.

Chaque processus dispose d'une **table de handles** privée, gérée par le noyau. Lorsqu'un programme ouvre un fichier, le noyau :

1. Crée ou localise l'objet fichier
2. Vérifie les permissions via le Security Reference Monitor
3. Ajoute une entrée dans la table de handles du processus
4. Retourne le numéro de handle au programme

```powershell
# Voir les handles ouverts par un processus (nécessite Process Explorer ou handle.exe de Sysinternals)
# handle.exe -p explorer.exe
```

---

## 2. La Win32 API

### 2.1 Rôle

La **Win32 API** (Windows Application Programming Interface) est la couche intermédiaire entre les applications et les appels système (`ntdll.dll`). Elle est implémentée principalement dans trois DLL :

| DLL | Contenu |
|---|---|
| `kernel32.dll` | Fonctions système : fichiers, processus, mémoire, threads |
| `user32.dll` | Fonctions interface graphique : fenêtres, messages, entrées |
| `advapi32.dll` | Fonctions de sécurité : registre, services, tokens, chiffrement |

### 2.2 Pourquoi la Win32 API existe-t-elle ?

Les fonctions de `ntdll.dll` (préfixées par `Nt` ou `Zw`) sont des fonctions **internes** dont l'interface peut changer entre les versions de Windows. Microsoft ne documente pas publiquement la plupart de ces fonctions et ne garantit pas leur stabilité.

La Win32 API fournit une interface **stable et documentée** que les développeurs peuvent utiliser en toute confiance. Chaque fonction de la Win32 API appelle en interne une ou plusieurs fonctions de `ntdll.dll`.

Chaîne d'appel typique :

```
Application
    │
    ▼
kernel32.dll!CreateFile()       <- Win32 API (documentée, stable)
    │
    ▼
ntdll.dll!NtCreateFile()        <- Interface noyau (interne, instable)
    │
    ▼
syscall                         <- Transition Ring 3 → Ring 0
    │
    ▼
ntoskrnl.exe!NtCreateFile()     <- Implémentation dans le noyau
```

### 2.3 Exemple concret : CTRL+S dans Word

Lorsqu'un utilisateur appuie sur CTRL+S dans Microsoft Word, voici la séquence détaillée impliquant l'Object Manager :

```
1. Word appelle CreateFile() (kernel32.dll)
   avec le chemin "C:\Users\Alice\Documents\rapport.docx"
          │
          ▼
2. kernel32.dll appelle NtCreateFile() (ntdll.dll)
          │
          ▼
3. Transition vers le mode noyau (syscall)
          │
          ▼
4. L'Object Manager reçoit la requête et résout le chemin :
   "C:\Users\Alice\Documents\rapport.docx"
   devient :
   "\Device\HarddiskVolume1\Users\Alice\Documents\rapport.docx"
          │
          ▼
5. L'Object Manager vérifie que l'objet fichier existe
   (via le système de fichiers NTFS)
          │
          ▼
6. Le Security Reference Monitor (SRM) vérifie les permissions :
   - Lit le token d'accès du processus Word (SID de l'utilisateur)
   - Lit le Security Descriptor du fichier (DACL)
   - Compare les deux pour déterminer si l'écriture est autorisée
          │
          ▼
7. Si autorisé : le noyau crée un objet fichier,
   l'ajoute à la table de handles de Word,
   et retourne le handle au programme
          │
          ▼
8. Word utilise ce handle pour appeler WriteFile()
   et écrire le contenu du document
```

---

## 3. Chemins Win32 et chemins noyau

### 3.1 Deux espaces de noms

Windows utilise deux systèmes de chemins :

| Type | Exemple | Utilisé par |
|---|---|---|
| **Chemin Win32** | `C:\Users\Alice\Documents\rapport.docx` | Applications, utilisateurs, explorateur de fichiers |
| **Chemin noyau** | `\Device\HarddiskVolume1\Users\Alice\Documents\rapport.docx` | Object Manager, pilotes, noyau |

Le lecteur `C:` est en réalité un **lien symbolique** (symlink) géré par l'Object Manager. Il pointe vers le périphérique physique correspondant :

```
C:  →  \Device\HarddiskVolume1\
D:  →  \Device\HarddiskVolume2\
```

### 3.2 L'espace de noms de l'Object Manager

L'Object Manager maintient un espace de noms hiérarchique similaire à un système de fichiers. On peut l'explorer avec l'outil **WinObj** de Sysinternals :

```
\
├── Device                    <- Périphériques physiques
│     ├── HarddiskVolume1     <- Partition C:
│     ├── HarddiskVolume2     <- Partition D:
│     └── Tcp                 <- Pile réseau TCP
├── DosDevices                <- Liens symboliques (C:, D:, etc.)
├── ObjectTypes               <- Types d'objets enregistrés
├── Sessions                  <- Sessions utilisateur
├── BaseNamedObjects          <- Objets nommés (mutex, events, etc.)
└── KnownDlls                 <- DLL pré-chargées par le système
```

> **À noter** : la connaissance des chemins noyau est utile en forensique et en analyse de malwares. Certains malwares utilisent directement les chemins noyau (préfixés `\??\` ou `\\.\`) pour contourner les contrôles de sécurité basés sur les chemins Win32.

---

## 4. Les listes de contrôle d'accès (ACL)

### 4.1 Le Security Descriptor

Chaque objet noyau possède un **Security Descriptor** (descripteur de sécurité) qui définit qui peut faire quoi avec cet objet. Le Security Descriptor contient quatre éléments :

| Élément | Description |
|---|---|
| **Owner** | SID du propriétaire de l'objet |
| **Group** | SID du groupe propriétaire (principalement pour compatibilité POSIX) |
| **DACL** | Discretionary Access Control List : définit **qui peut accéder** à l'objet et avec quelles permissions |
| **SACL** | System Access Control List : définit quels accès doivent être **audités** (journalisés) |

### 4.2 La DACL (Discretionary Access Control List)

La **DACL** est la composante principale du contrôle d'accès. Elle est composée d'une liste d'**ACE** (Access Control Entry), chacune spécifiant :

| Champ de l'ACE | Description |
|---|---|
| **Type** | `Allow` (autoriser) ou `Deny` (refuser) |
| **SID** | Identifiant de l'utilisateur ou du groupe concerné |
| **Permissions** | Droits accordés ou refusés |
| **Héritage** | Si l'ACE se propage aux sous-dossiers et fichiers enfants |

Exemple de DACL pour un fichier :

| Type | SID | Permissions |
|---|---|---|
| Allow | SYSTEM | Full Control |
| Allow | Administrators | Full Control |
| Allow | Alice | Read, Write |
| Deny | Bob | Delete |

> **À noter** : les ACE de type **Deny** sont toujours évaluées **avant** les ACE de type **Allow**. Si un utilisateur fait partie d'un groupe autorisé mais aussi d'un groupe refusé, le refus prévaut.

### 4.3 Les permissions NTFS

| Permission | Code icacls | Description |
|---|---|---|
| **Full Control** | `F` | Tous les droits, y compris la modification des permissions |
| **Modify** | `M` | Lire, écrire, exécuter et supprimer |
| **Read & Execute** | `RX` | Lire le contenu et exécuter les programmes |
| **Read** | `R` | Lire le contenu et les attributs |
| **Write** | `W` | Créer des fichiers, écrire des données, modifier les attributs |
| **Delete** | `D` | Supprimer l'objet |

### 4.4 Examiner les DACL avec icacls

La commande `icacls` (Integrity Control Access Control List) permet de visualiser et modifier les DACL :

```cmd
icacls C:\Users\Alice\Documents\rapport.docx
```

Sortie typique :

```
C:\Users\Alice\Documents\rapport.docx
    NT AUTHORITY\SYSTEM:(F)
    BUILTIN\Administrators:(F)
    DESKTOP-ABC123\Alice:(RX)
    BUILTIN\Users:(R)
```

Lecture des flags :

| Flag | Signification |
|---|---|
| `F` | Full Control (contrôle total) |
| `M` | Modify (modification) |
| `RX` | Read and Execute (lecture et exécution) |
| `R` | Read (lecture) |
| `W` | Write (écriture) |
| `D` | Delete (suppression) |
| `(OI)` | Object Inherit - l'ACE s'applique aux fichiers enfants |
| `(CI)` | Container Inherit - l'ACE s'applique aux sous-dossiers enfants |
| `(IO)` | Inherit Only - l'ACE ne s'applique qu'aux enfants, pas à l'objet lui-même |
| `(NP)` | No Propagate - l'héritage ne se propage pas au-delà du premier niveau |

Modifier les DACL avec `icacls` :

```cmd
REM Accorder la lecture à Bob
icacls C:\Data\rapport.docx /grant Bob:R

REM Accorder le contrôle total avec héritage
icacls C:\Data\SharedFolder /grant "Marketing:(OI)(CI)F"

REM Refuser la suppression à un groupe
icacls C:\Data\rapport.docx /deny "Stagiaires:D"

REM Supprimer toutes les permissions d'un utilisateur
icacls C:\Data\rapport.docx /remove Bob

REM Réinitialiser les permissions (réappliquer l'héritage)
icacls C:\Data\SharedFolder /reset
```

### 4.5 Examiner les ACL avec PowerShell (Get-Acl)

La cmdlet `Get-Acl` affiche le Security Descriptor complet, y compris la DACL et la SACL :

```powershell
# Afficher le Security Descriptor d'un fichier
Get-Acl C:\Users\Alice\Documents\rapport.docx | Format-List

# Afficher uniquement les ACE de la DACL
(Get-Acl C:\Users\Alice\Documents\rapport.docx).Access |
    Format-Table IdentityReference, FileSystemRights, AccessControlType -AutoSize
```

Sortie typique :

```
IdentityReference        FileSystemRights  AccessControlType
-----------------        ----------------  -----------------
NT AUTHORITY\SYSTEM      FullControl       Allow
BUILTIN\Administrators   FullControl       Allow
DESKTOP-ABC123\Alice     ReadAndExecute    Allow
BUILTIN\Users            Read              Allow
```

```powershell
# Voir les ACL d'une clé de registre
Get-Acl "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" |
    Select-Object -ExpandProperty Access |
    Format-Table IdentityReference, RegistryRights, AccessControlType -AutoSize
```

---

## 5. Le format SDDL

### 5.1 Définition

Le **SDDL** (Security Descriptor Definition Language) est une représentation textuelle compacte d'un Security Descriptor. Il est utilisé dans les scripts, les GPO et les outils en ligne de commande.

### 5.2 Structure

Un SDDL se compose de quatre sections, chacune précédée d'un préfixe :

```
O:<owner>G:<group>D:<dacl>S:<sacl>
```

| Préfixe | Contenu |
|---|---|
| `O:` | SID du propriétaire |
| `G:` | SID du groupe |
| `D:` | DACL (liste des ACE d'accès) |
| `S:` | SACL (liste des ACE d'audit) |

### 5.3 Format d'une ACE en SDDL

Chaque ACE est encadrée par des parenthèses et suit le format :

```
(type;flags;permissions;;;SID)
```

| Champ | Valeurs courantes |
|---|---|
| **Type** | `A` = Allow, `D` = Deny |
| **Flags** | `CI` = Container Inherit, `OI` = Object Inherit |
| **Permissions** | `FA` = Full Access, `FR` = File Read, `FW` = File Write, `FX` = File Execute |
| **SID** | `SY` = SYSTEM, `BA` = Built-in Administrators, `BU` = Built-in Users, `AU` = Authenticated Users |

### 5.4 Exemple

```
O:BAG:SYD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)
```

Lecture :

| Élément | Signification |
|---|---|
| `O:BA` | Propriétaire : Built-in Administrators |
| `G:SY` | Groupe : SYSTEM |
| `D:` | Début de la DACL |
| `(A;;FA;;;SY)` | Allow Full Access à SYSTEM |
| `(A;;FA;;;BA)` | Allow Full Access aux Administrators |
| `(A;;FR;;;BU)` | Allow File Read aux Built-in Users |

```powershell
# Afficher le SDDL d'un objet
(Get-Acl C:\Data).Sddl
```

> **Bonne pratique** : le format SDDL est difficile à lire pour un humain. En pratique, on utilise `Get-Acl` avec `Format-Table` pour une lecture plus claire, et le SDDL pour les scripts d'automatisation ou les GPO.

---

## 6. La SACL (System Access Control List) et l'audit

### 6.1 Rôle de la SACL

La **SACL** définit quels accès à un objet doivent être enregistrés dans le journal de sécurité Windows (Security Event Log). Elle ne contrôle pas l'accès lui-même (c'est le rôle de la DACL), mais permet de détecter les tentatives d'accès suspectes.

### 6.2 Activer l'audit d'accès

L'audit d'accès nécessite deux étapes :

**Étape 1 : Activer la politique d'audit globale**

```powershell
# Activer l'audit des accès aux objets (succès et échecs)
auditpol /set /subcategory:"File System" /success:enable /failure:enable

# Vérifier la configuration
auditpol /get /subcategory:"File System"
```

**Étape 2 : Configurer la SACL sur l'objet à auditer**

```powershell
# Récupérer les ACL actuelles
$acl = Get-Acl "C:\Data\Confidentiel"

# Créer une règle d'audit : auditer toutes les écritures de tous les utilisateurs
$auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
    "Everyone",                          # Qui auditer
    "Write,Delete",                      # Quelles actions auditer
    "ContainerInherit,ObjectInherit",    # Héritage
    "None",                              # Flags de propagation
    "Success,Failure"                    # Auditer les succès et les échecs
)

# Ajouter la règle d'audit
$acl.AddAuditRule($auditRule)

# Appliquer
Set-Acl "C:\Data\Confidentiel" $acl

# Vérifier
(Get-Acl "C:\Data\Confidentiel").Audit |
    Format-Table IdentityReference, FileSystemRights, AuditFlags -AutoSize
```

Les événements d'audit sont ensuite consultables dans l'**Observateur d'événements** (`eventvwr.msc`), journal "Sécurité" (Security), avec les ID d'événement :

| Event ID | Description |
|---|---|
| **4663** | Accès à un objet (succès) |
| **4656** | Handle demandé pour un objet |
| **4660** | Objet supprimé |
| **4670** | Permissions modifiées sur un objet |

---

## 7. Configurer les DACL avec PowerShell

### 7.1 Ajouter une permission

```powershell
# Récupérer les ACL actuelles
$acl = Get-Acl "C:\Data\SharedFolder"

# Créer une nouvelle règle d'accès
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "Marketing",                         # Utilisateur ou groupe
    "Modify",                            # Permission
    "ContainerInherit,ObjectInherit",    # Héritage (s'applique aux sous-dossiers et fichiers)
    "None",                              # Flags de propagation
    "Allow"                              # Type (Allow ou Deny)
)

# Ajouter la règle
$acl.AddAccessRule($rule)

# Appliquer les modifications
Set-Acl "C:\Data\SharedFolder" $acl
```

### 7.2 Supprimer une permission

```powershell
$acl = Get-Acl "C:\Data\SharedFolder"

# Trouver la règle à supprimer
$ruleToRemove = $acl.Access | Where-Object {
    $_.IdentityReference -eq "BUILTIN\Users" -and
    $_.FileSystemRights -eq "ReadAndExecute, Synchronize"
}

# Supprimer la règle
$acl.RemoveAccessRule($ruleToRemove)

Set-Acl "C:\Data\SharedFolder" $acl
```

### 7.3 Désactiver l'héritage

```powershell
$acl = Get-Acl "C:\Data\SharedFolder"

# Désactiver l'héritage et convertir les permissions héritées en permissions explicites
# Premier paramètre : $true = protéger contre l'héritage
# Deuxième paramètre : $true = conserver les permissions héritées comme explicites
$acl.SetAccessRuleProtection($true, $true)

Set-Acl "C:\Data\SharedFolder" $acl
```

### 7.4 Prendre possession d'un objet

```powershell
# Prendre possession (nécessite le privilège SeTakeOwnershipPrivilege)
$acl = Get-Acl "C:\Data\Protege"
$acl.SetOwner([System.Security.Principal.NTAccount]"Administrators")
Set-Acl "C:\Data\Protege" $acl
```

---

## Récapitulatif

| Concept | Description |
|---|---|
| **Object Manager** | Composant du noyau qui gère tous les objets (fichiers, processus, clés de registre) |
| **Handle** | Référence opaque vers un objet noyau, utilisée par les programmes en mode utilisateur |
| **Win32 API** | Couche intermédiaire stable et documentée entre les applications et `ntdll.dll` |
| **Chemin noyau** | `\Device\HarddiskVolume1\...` - chemin réel utilisé par le noyau |
| **Security Descriptor** | Structure contenant le propriétaire, le groupe, la DACL et la SACL d'un objet |
| **DACL** | Liste d'ACE définissant qui peut accéder à l'objet et avec quelles permissions |
| **SACL** | Liste d'ACE définissant quels accès doivent être audités |
| **ACE** | Entrée dans une ACL : type (Allow/Deny) + SID + permissions |
| **SDDL** | Représentation textuelle compacte d'un Security Descriptor |
| **icacls** | Commande pour afficher et modifier les DACL |
| **Get-Acl / Set-Acl** | Cmdlets PowerShell pour manipuler les Security Descriptors complets |

---

## Pour aller plus loin

- [Access Control Lists (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control-lists)
- [Security Descriptor Definition Language (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language)
- [icacls Reference (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)
- [WinObj (Sysinternals)](https://learn.microsoft.com/en-us/sysinternals/downloads/winobj)
- [Windows Object Manager (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/managing-kernel-objects)
- [MITRE ATT&CK - File and Directory Permissions Modification: Windows (T1222.001)](https://attack.mitre.org/techniques/T1222/001/)
