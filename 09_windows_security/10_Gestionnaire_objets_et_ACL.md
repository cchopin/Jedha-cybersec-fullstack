# Gestionnaire d'objets et listes de controle d'acces (ACL)

**Module** : comprendre l'Object Manager, la Win32 API et le systeme de permissions Windows

---

## Objectifs du module

A l'issue de ce module, les competences suivantes seront acquises :

- Comprendre le role de l'Object Manager dans l'architecture du noyau Windows
- Maitriser le concept d'objet noyau et de handle
- Connaitre la Win32 API et son role d'intermediaire entre les applications et le noyau
- Comprendre la resolution des chemins par le noyau (chemins Win32 vs chemins kernel)
- Maitriser le systeme d'ACL Windows : Security Descriptor, DACL, SACL, ACE
- Utiliser `icacls`, `Get-Acl` et SDDL pour auditer et configurer les permissions
- Configurer l'audit d'acces via les SACL

---

## 1. L'Object Manager

### 1.1 Principe fondamental : tout est un objet

Dans l'architecture Windows, le noyau manipule toutes les ressources systeme sous forme d'**objets**. L'**Object Manager** est le composant de l'Executive du noyau responsable de la creation, de la gestion et de la destruction de ces objets.

Exemples de ressources representees comme des objets noyau :

| Type d'objet | Exemples |
|---|---|
| **Fichier** | Document Word, image, executable |
| **Dossier** | Repertoire du systeme de fichiers |
| **Processus** | Instance en cours d'execution d'un programme |
| **Thread** | Fil d'execution au sein d'un processus |
| **Cle de registre** | Cle dans la base de registre |
| **Section** | Zone de memoire partagee entre processus |
| **Mutex** | Mecanisme de synchronisation entre threads |
| **Evenement** | Signal de notification entre processus |
| **Pipe** | Canal de communication entre processus |

### 1.2 Proprietes d'un objet noyau

Chaque objet noyau possede des proprietes communes :

| Propriete | Description |
|---|---|
| **Nom** | Identifiant dans l'espace de noms du noyau (ex : `\Device\HarddiskVolume1\Users\...`) |
| **Type** | Type de l'objet (File, Process, Key, etc.) |
| **Security Descriptor** | Descripteur de securite contenant les ACL (qui peut acceder a cet objet et avec quelles permissions) |
| **Compteur de references** | Nombre de handles et de references pointant vers l'objet. L'objet est detruit quand ce compteur atteint zero |
| **Handle** | Reference opaque permettant aux programmes en mode utilisateur d'interagir avec l'objet |

### 1.3 Les handles

Un **handle** est une reference indirecte et opaque vers un objet noyau. Les programmes en mode utilisateur ne peuvent jamais acceder directement aux structures internes du noyau. Ils utilisent des handles (de simples numeros) que le noyau traduit en references vers les vrais objets.

Chaque processus dispose d'une **table de handles** privee, geree par le noyau. Lorsqu'un programme ouvre un fichier, le noyau :

1. Cree ou localise l'objet fichier
2. Verifie les permissions via le Security Reference Monitor
3. Ajoute une entree dans la table de handles du processus
4. Retourne le numero de handle au programme

```powershell
# Voir les handles ouverts par un processus (necessite Process Explorer ou handle.exe de Sysinternals)
# handle.exe -p explorer.exe
```

---

## 2. La Win32 API

### 2.1 Role

La **Win32 API** (Windows Application Programming Interface) est la couche intermediaire entre les applications et les appels systeme (`ntdll.dll`). Elle est implementee principalement dans trois DLL :

| DLL | Contenu |
|---|---|
| `kernel32.dll` | Fonctions systeme : fichiers, processus, memoire, threads |
| `user32.dll` | Fonctions interface graphique : fenetres, messages, entrees |
| `advapi32.dll` | Fonctions de securite : registre, services, tokens, chiffrement |

### 2.2 Pourquoi la Win32 API existe-t-elle ?

Les fonctions de `ntdll.dll` (prefixees par `Nt` ou `Zw`) sont des fonctions **internes** dont l'interface peut changer entre les versions de Windows. Microsoft ne documente pas publiquement la plupart de ces fonctions et ne garantit pas leur stabilite.

La Win32 API fournit une interface **stable et documentee** que les developpeurs peuvent utiliser en toute confiance. Chaque fonction de la Win32 API appelle en interne une ou plusieurs fonctions de `ntdll.dll`.

Chaine d'appel typique :

```
Application
    │
    ▼
kernel32.dll!CreateFile()       <- Win32 API (documentee, stable)
    │
    ▼
ntdll.dll!NtCreateFile()        <- Interface noyau (interne, instable)
    │
    ▼
syscall                         <- Transition Ring 3 → Ring 0
    │
    ▼
ntoskrnl.exe!NtCreateFile()     <- Implementation dans le noyau
```

### 2.3 Exemple concret : CTRL+S dans Word

Lorsqu'un utilisateur appuie sur CTRL+S dans Microsoft Word, voici la sequence detaillee impliquant l'Object Manager :

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
4. L'Object Manager recoit la requete et resout le chemin :
   "C:\Users\Alice\Documents\rapport.docx"
   devient :
   "\Device\HarddiskVolume1\Users\Alice\Documents\rapport.docx"
          │
          ▼
5. L'Object Manager verifie que l'objet fichier existe
   (via le systeme de fichiers NTFS)
          │
          ▼
6. Le Security Reference Monitor (SRM) verifie les permissions :
   - Lit le token d'acces du processus Word (SID de l'utilisateur)
   - Lit le Security Descriptor du fichier (DACL)
   - Compare les deux pour determiner si l'ecriture est autorisee
          │
          ▼
7. Si autorise : le noyau cree un objet fichier,
   l'ajoute a la table de handles de Word,
   et retourne le handle au programme
          │
          ▼
8. Word utilise ce handle pour appeler WriteFile()
   et ecrire le contenu du document
```

---

## 3. Chemins Win32 et chemins noyau

### 3.1 Deux espaces de noms

Windows utilise deux systemes de chemins :

| Type | Exemple | Utilise par |
|---|---|---|
| **Chemin Win32** | `C:\Users\Alice\Documents\rapport.docx` | Applications, utilisateurs, explorateur de fichiers |
| **Chemin noyau** | `\Device\HarddiskVolume1\Users\Alice\Documents\rapport.docx` | Object Manager, pilotes, noyau |

Le lecteur `C:` est en realite un **lien symbolique** (symlink) gere par l'Object Manager. Il pointe vers le peripherique physique correspondant :

```
C:  →  \Device\HarddiskVolume1\
D:  →  \Device\HarddiskVolume2\
```

### 3.2 L'espace de noms de l'Object Manager

L'Object Manager maintient un espace de noms hierarchique similaire a un systeme de fichiers. On peut l'explorer avec l'outil **WinObj** de Sysinternals :

```
\
├── Device                    <- Peripheriques physiques
│     ├── HarddiskVolume1     <- Partition C:
│     ├── HarddiskVolume2     <- Partition D:
│     └── Tcp                 <- Pile reseau TCP
├── DosDevices                <- Liens symboliques (C:, D:, etc.)
├── ObjectTypes               <- Types d'objets enregistres
├── Sessions                  <- Sessions utilisateur
├── BaseNamedObjects          <- Objets nommes (mutex, events, etc.)
└── KnownDlls                 <- DLL pre-chargees par le systeme
```

> **A noter** : la connaissance des chemins noyau est utile en forensique et en analyse de malwares. Certains malwares utilisent directement les chemins noyau (prefixes `\??\` ou `\\.\`) pour contourner les controles de securite bases sur les chemins Win32.

---

## 4. Les listes de controle d'acces (ACL)

### 4.1 Le Security Descriptor

Chaque objet noyau possede un **Security Descriptor** (descripteur de securite) qui definit qui peut faire quoi avec cet objet. Le Security Descriptor contient quatre elements :

| Element | Description |
|---|---|
| **Owner** | SID du proprietaire de l'objet |
| **Group** | SID du groupe proprietaire (principalement pour compatibilite POSIX) |
| **DACL** | Discretionary Access Control List : definit **qui peut acceder** a l'objet et avec quelles permissions |
| **SACL** | System Access Control List : definit quels acces doivent etre **audites** (journalises) |

### 4.2 La DACL (Discretionary Access Control List)

La **DACL** est la composante principale du controle d'acces. Elle est composee d'une liste d'**ACE** (Access Control Entry), chacune specifiant :

| Champ de l'ACE | Description |
|---|---|
| **Type** | `Allow` (autoriser) ou `Deny` (refuser) |
| **SID** | Identifiant de l'utilisateur ou du groupe concerne |
| **Permissions** | Droits accordes ou refuses |
| **Heritage** | Si l'ACE se propage aux sous-dossiers et fichiers enfants |

Exemple de DACL pour un fichier :

| Type | SID | Permissions |
|---|---|---|
| Allow | SYSTEM | Full Control |
| Allow | Administrators | Full Control |
| Allow | Alice | Read, Write |
| Deny | Bob | Delete |

> **A noter** : les ACE de type **Deny** sont toujours evaluees **avant** les ACE de type **Allow**. Si un utilisateur fait partie d'un groupe autorise mais aussi d'un groupe refuse, le refus prevaut.

### 4.3 Les permissions NTFS

| Permission | Code icacls | Description |
|---|---|---|
| **Full Control** | `F` | Tous les droits, y compris la modification des permissions |
| **Modify** | `M` | Lire, ecrire, executer et supprimer |
| **Read & Execute** | `RX` | Lire le contenu et executer les programmes |
| **Read** | `R` | Lire le contenu et les attributs |
| **Write** | `W` | Creer des fichiers, ecrire des donnees, modifier les attributs |
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
| `F` | Full Control (controle total) |
| `M` | Modify (modification) |
| `RX` | Read and Execute (lecture et execution) |
| `R` | Read (lecture) |
| `W` | Write (ecriture) |
| `D` | Delete (suppression) |
| `(OI)` | Object Inherit - l'ACE s'applique aux fichiers enfants |
| `(CI)` | Container Inherit - l'ACE s'applique aux sous-dossiers enfants |
| `(IO)` | Inherit Only - l'ACE ne s'applique qu'aux enfants, pas a l'objet lui-meme |
| `(NP)` | No Propagate - l'heritage ne se propage pas au-dela du premier niveau |

Modifier les DACL avec `icacls` :

```cmd
REM Accorder la lecture a Bob
icacls C:\Data\rapport.docx /grant Bob:R

REM Accorder le controle total avec heritage
icacls C:\Data\SharedFolder /grant "Marketing:(OI)(CI)F"

REM Refuser la suppression a un groupe
icacls C:\Data\rapport.docx /deny "Stagiaires:D"

REM Supprimer toutes les permissions d'un utilisateur
icacls C:\Data\rapport.docx /remove Bob

REM Reinitialiser les permissions (reappliquer l'heritage)
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
# Voir les ACL d'une cle de registre
Get-Acl "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" |
    Select-Object -ExpandProperty Access |
    Format-Table IdentityReference, RegistryRights, AccessControlType -AutoSize
```

---

## 5. Le format SDDL

### 5.1 Definition

Le **SDDL** (Security Descriptor Definition Language) est une representation textuelle compacte d'un Security Descriptor. Il est utilise dans les scripts, les GPO et les outils en ligne de commande.

### 5.2 Structure

Un SDDL se compose de quatre sections, chacune precedee d'un prefixe :

```
O:<owner>G:<group>D:<dacl>S:<sacl>
```

| Prefixe | Contenu |
|---|---|
| `O:` | SID du proprietaire |
| `G:` | SID du groupe |
| `D:` | DACL (liste des ACE d'acces) |
| `S:` | SACL (liste des ACE d'audit) |

### 5.3 Format d'une ACE en SDDL

Chaque ACE est encadree par des parentheses et suit le format :

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

| Element | Signification |
|---|---|
| `O:BA` | Proprietaire : Built-in Administrators |
| `G:SY` | Groupe : SYSTEM |
| `D:` | Debut de la DACL |
| `(A;;FA;;;SY)` | Allow Full Access a SYSTEM |
| `(A;;FA;;;BA)` | Allow Full Access aux Administrators |
| `(A;;FR;;;BU)` | Allow File Read aux Built-in Users |

```powershell
# Afficher le SDDL d'un objet
(Get-Acl C:\Data).Sddl
```

> **Bonne pratique** : le format SDDL est difficile a lire pour un humain. En pratique, on utilise `Get-Acl` avec `Format-Table` pour une lecture plus claire, et le SDDL pour les scripts d'automatisation ou les GPO.

---

## 6. La SACL (System Access Control List) et l'audit

### 6.1 Role de la SACL

La **SACL** definit quels acces a un objet doivent etre enregistres dans le journal de securite Windows (Security Event Log). Elle ne controle pas l'acces lui-meme (c'est le role de la DACL), mais permet de detecter les tentatives d'acces suspectes.

### 6.2 Activer l'audit d'acces

L'audit d'acces necessite deux etapes :

**Etape 1 : Activer la politique d'audit globale**

```powershell
# Activer l'audit des acces aux objets (succes et echecs)
auditpol /set /subcategory:"File System" /success:enable /failure:enable

# Verifier la configuration
auditpol /get /subcategory:"File System"
```

**Etape 2 : Configurer la SACL sur l'objet a auditer**

```powershell
# Recuperer les ACL actuelles
$acl = Get-Acl "C:\Data\Confidentiel"

# Creer une regle d'audit : auditer toutes les ecritures de tous les utilisateurs
$auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
    "Everyone",                          # Qui auditer
    "Write,Delete",                      # Quelles actions auditer
    "ContainerInherit,ObjectInherit",    # Heritage
    "None",                              # Flags de propagation
    "Success,Failure"                    # Auditer les succes et les echecs
)

# Ajouter la regle d'audit
$acl.AddAuditRule($auditRule)

# Appliquer
Set-Acl "C:\Data\Confidentiel" $acl

# Verifier
(Get-Acl "C:\Data\Confidentiel").Audit |
    Format-Table IdentityReference, FileSystemRights, AuditFlags -AutoSize
```

Les evenements d'audit sont ensuite consultables dans l'**Observateur d'evenements** (`eventvwr.msc`), journal "Securite" (Security), avec les ID d'evenement :

| Event ID | Description |
|---|---|
| **4663** | Acces a un objet (succes) |
| **4656** | Handle demande pour un objet |
| **4660** | Objet supprime |
| **4670** | Permissions modifiees sur un objet |

---

## 7. Configurer les DACL avec PowerShell

### 7.1 Ajouter une permission

```powershell
# Recuperer les ACL actuelles
$acl = Get-Acl "C:\Data\SharedFolder"

# Creer une nouvelle regle d'acces
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "Marketing",                         # Utilisateur ou groupe
    "Modify",                            # Permission
    "ContainerInherit,ObjectInherit",    # Heritage (s'applique aux sous-dossiers et fichiers)
    "None",                              # Flags de propagation
    "Allow"                              # Type (Allow ou Deny)
)

# Ajouter la regle
$acl.AddAccessRule($rule)

# Appliquer les modifications
Set-Acl "C:\Data\SharedFolder" $acl
```

### 7.2 Supprimer une permission

```powershell
$acl = Get-Acl "C:\Data\SharedFolder"

# Trouver la regle a supprimer
$ruleToRemove = $acl.Access | Where-Object {
    $_.IdentityReference -eq "BUILTIN\Users" -and
    $_.FileSystemRights -eq "ReadAndExecute, Synchronize"
}

# Supprimer la regle
$acl.RemoveAccessRule($ruleToRemove)

Set-Acl "C:\Data\SharedFolder" $acl
```

### 7.3 Desactiver l'heritage

```powershell
$acl = Get-Acl "C:\Data\SharedFolder"

# Desactiver l'heritage et convertir les permissions heritees en permissions explicites
# Premier parametre : $true = proteger contre l'heritage
# Deuxieme parametre : $true = conserver les permissions heritees comme explicites
$acl.SetAccessRuleProtection($true, $true)

Set-Acl "C:\Data\SharedFolder" $acl
```

### 7.4 Prendre possession d'un objet

```powershell
# Prendre possession (necessite le privilege SeTakeOwnershipPrivilege)
$acl = Get-Acl "C:\Data\Protege"
$acl.SetOwner([System.Security.Principal.NTAccount]"Administrators")
Set-Acl "C:\Data\Protege" $acl
```

---

## Recapitulatif

| Concept | Description |
|---|---|
| **Object Manager** | Composant du noyau qui gere tous les objets (fichiers, processus, cles de registre) |
| **Handle** | Reference opaque vers un objet noyau, utilisee par les programmes en mode utilisateur |
| **Win32 API** | Couche intermediaire stable et documentee entre les applications et `ntdll.dll` |
| **Chemin noyau** | `\Device\HarddiskVolume1\...` - chemin reel utilise par le noyau |
| **Security Descriptor** | Structure contenant le proprietaire, le groupe, la DACL et la SACL d'un objet |
| **DACL** | Liste d'ACE definissant qui peut acceder a l'objet et avec quelles permissions |
| **SACL** | Liste d'ACE definissant quels acces doivent etre audites |
| **ACE** | Entree dans une ACL : type (Allow/Deny) + SID + permissions |
| **SDDL** | Representation textuelle compacte d'un Security Descriptor |
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
