# Jetons d'accès, LSASS et SRM

**Module** : sécurité Windows -- mécanismes d'authentification et de contrôle d'accès

---

## Objectifs du module

À l'issue de ce module, les compétences suivantes seront acquises :

- Comprendre la structure et le rôle des Access Tokens dans le modèle de sécurité Windows
- Identifier les privileges associés à un token et leur impact sur la sécurité
- Maîtriser le fonctionnement de LSASS et son rôle dans l'authentification
- Comprendre le mécanisme de vérification d'accès opéré par le SRM (Security Reference Monitor)
- Connaître les vecteurs d'attaque liés aux tokens d'impersonation et aux Named Pipes

---

## 1. Les Access Tokens

### 1.1 Définition et rôle

Un **Access Token** est une structure de sécurité créée par le système d'exploitation et attachée à chaque processus et thread en cours d'exécution. Il représente l'identité de sécurité de l'utilisateur qui a lancé le processus et contient toutes les informations nécessaires pour que Windows puisse prendre des décisions de contrôle d'accès.

Concrètement, lorsqu'un processus tente d'accéder à un objet (fichier, clé de registre, pipe, etc.), l'**Object Manager** compare le contenu du token du processus avec la **liste de contrôle d'accès** (ACL) de l'objet pour déterminer si l'accès est autorisé ou refusé.

### 1.2 Contenu d'un Access Token

Un token contient les éléments suivants :

| Élément | Description |
|---|---|
| **User SID** | Identifiant de sécurité unique de l'utilisateur (ex. `S-1-5-21-...-1001`) |
| **Group SIDs** | Liste des groupes auxquels l'utilisateur appartient (Administrators, Users, etc.) |
| **Privileges** | Liste des privileges système accordés au token (ex. `SeDebugPrivilege`) |
| **Integrity Level** | Niveau d'intégrité du processus (Low, Medium, High, System) |
| **Logon SID** | SID unique à cette session de connexion |
| **Token Type** | Primary (processus) ou Impersonation (thread) |
| **Owner SID** | SID utilisé par défaut lors de la création d'objets |
| **Default DACL** | ACL appliquée par défaut aux objets créés par le processus |

### 1.3 Niveaux d'intégrité (Integrity Levels)

Windows utilise un système de niveaux d'intégrité pour renforcer le contrôle d'accès au-delà des ACL traditionnelles. Un processus ne peut pas écrire dans un objet dont le niveau d'intégrité est supérieur au sien.

| Niveau | Valeur | Exemple d'utilisation |
|---|---|---|
| **Untrusted** | 0 | Processus anonymes |
| **Low** | 1 | Navigateurs web en mode protégé, processus sandboxés |
| **Medium** | 2 | Processus utilisateur standard (explorer.exe, notepad.exe) |
| **High** | 3 | Processus lancés en tant qu'administrateur (via UAC) |
| **System** | 4 | Services système, processus SYSTEM |

> **À noter** : même un utilisateur membre du groupe Administrators exécute ses processus au niveau Medium par défaut. Le niveau High n'est obtenu qu'après élévation UAC.

---

## 2. Privileges système

### 2.1 Liste des privileges importants

Les privileges sont des autorisations spéciales qui permettent à un processus d'effectuer des opérations sensibles, indépendamment des ACL sur les objets. Ils sont définis dans le token et peuvent être activés ou désactivés.

| Privilege | Description | Risque de sécurité |
|---|---|---|
| `SeDebugPrivilege` | Permet d'attacher un débogueur à n'importe quel processus, y compris ceux d'autres utilisateurs | Critique : permet de lire la mémoire de LSASS pour extraire des credentials |
| `SeShutdownPrivilege` | Permet d'arrêter le système | Faible : déni de service uniquement |
| `SeBackupPrivilege` | Permet de lire n'importe quel fichier en contournant les ACL | Élevé : exfiltration de données, lecture de SAM |
| `SeRestorePrivilege` | Permet d'écrire n'importe quel fichier en contournant les ACL | Élevé : remplacement de fichiers système |
| `SeTakeOwnershipPrivilege` | Permet de prendre la propriété de n'importe quel objet | Élevé : modification ultérieure des ACL |
| `SeImpersonatePrivilege` | Permet à un service d'usurper l'identité d'un client | Critique : escalade de privileges via Potato attacks |
| `SeLoadDriverPrivilege` | Permet de charger des pilotes noyau | Critique : exécution de code en mode kernel |
| `SeAssignPrimaryTokenPrivilege` | Permet d'assigner un token primaire à un processus | Élevé : création de processus sous une autre identité |

### 2.2 Visualiser ses privileges

La commande `whoami /priv` affiche les privileges associés au token du processus courant.

**En tant qu'utilisateur standard** :

```cmd
C:\Users\alice> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```

**En tant qu'administrateur (invite élevée)** :

```cmd
C:\Windows\system32> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State
========================================= ================================================================== ========
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Disabled
SeSecurityPrivilege                       Manage auditing and security log                                   Disabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Disabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Disabled
SeSystemProfilePrivilege                  Profile system performance                                         Disabled
SeBackupPrivilege                         Back up files and directories                                      Disabled
SeRestorePrivilege                        Restore files and directories                                      Disabled
SeShutdownPrivilege                       Shut down the system                                               Disabled
SeDebugPrivilege                          Debug programs                                                     Disabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Disabled
...
```

> **À noter** : la différence entre les deux sorties est considérable. Un attaquant qui obtient une invite élevée dispose de privileges comme `SeDebugPrivilege` et `SeImpersonatePrivilege`, qui sont des vecteurs majeurs d'escalade de privileges.

Pour afficher toutes les informations du token en une seule commande :

```cmd
whoami /all
```

---

## 3. Création du token : le rôle de LSASS

### 3.1 Qu'est-ce que LSASS ?

**LSASS** (Local Security Authority Subsystem Service) est un processus user-mode critique qui s'exécute sous le compte **SYSTEM**. Son exécutable se trouve à l'emplacement suivant :

```
C:\Windows\System32\lsass.exe
```

LSASS est le composant central de l'authentification Windows. Il assure les responsabilités suivantes :

- **Authentification des utilisateurs** : validation des credentials (mot de passe, carte à puce, biométrie) contre la base SAM locale ou Active Directory
- **Création des Access Tokens** : après authentification réussie, LSASS appelle le syscall `NtCreateToken` pour générer le token primaire de l'utilisateur
- **Stockage temporaire des credentials** : les credentials sont conservés en mémoire pour permettre le SSO (Single Sign-On) vers les ressources réseau
- **Application des politiques de sécurité** : politiques de mots de passe, verrouillage de comptes, audit

> **Bonne pratique** : LSASS étant une cible prioritaire pour les attaquants (extraction de credentials en mémoire), il est fortement recommandé d'activer la protection **Credential Guard** sur les machines Windows 10/11 Enterprise et Server.

### 3.2 Flux de connexion interactive

Le processus de connexion interactive suit le flux suivant :

```
1. L'utilisateur saisit ses identifiants (Ctrl+Alt+Del -> écran de connexion)
2. winlogon.exe transmet les credentials à LSASS
3. LSASS valide les credentials (SAM local ou contrôleur de domaine)
4. LSASS crée un Access Token via NtCreateToken
5. LSASS retourne le token à winlogon.exe
6. winlogon.exe lance userinit.exe avec ce token
7. userinit.exe lance explorer.exe (le shell utilisateur)
8. explorer.exe crée les processus enfants qui héritent du token
```

Ce mécanisme d'héritage de token est fondamental : tous les processus lancés par l'utilisateur depuis le Bureau héritent du même token. C'est pourquoi l'élévation UAC crée un **second token** avec un niveau d'intégrité High, plutôt que de modifier le token existant.

---

## 4. Tokens d'impersonation

### 4.1 Principe

Les **Impersonation Tokens** sont utilisés dans les architectures client/serveur. Lorsqu'un client se connecte à un service (ex. un partage de fichiers, un serveur web IIS), le service peut temporairement "impersonner" l'identité du client pour accéder aux ressources en son nom.

Il existe quatre niveaux d'impersonation :

| Niveau | Description |
|---|---|
| **Anonymous** | Le serveur ne peut pas identifier le client |
| **Identification** | Le serveur peut identifier le client mais ne peut pas agir en son nom |
| **Impersonation** | Le serveur peut agir en tant que le client sur la machine locale |
| **Delegation** | Le serveur peut agir en tant que le client sur des machines distantes |

Le privilege `SeImpersonatePrivilege` est nécessaire pour qu'un processus puisse impersonner un client. Ce privilege est accordé par défaut aux comptes de service (LOCAL SERVICE, NETWORK SERVICE, SYSTEM).

### 4.2 Named Pipes et exploitation

Les **Named Pipes** sont un mécanisme de communication inter-processus (IPC) utilisé par Windows, notamment pour les appels RPC (Remote Procedure Call). Un Named Pipe est un pseudo-fichier accessible via le chemin `\\.\pipe\nom_du_pipe`.

Pour lister les Named Pipes actifs sur un système :

```powershell
Get-ChildItem -Path "\\.\pipe\"
```

Résultat partiel typique :

```
    Directory: \\.\pipe

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
------        12/31/1600   4:00 PM              3 InitShutdown
------        12/31/1600   4:00 PM              4 lsass
------        12/31/1600   4:00 PM              3 ntsvcs
------        12/31/1600   4:00 PM              3 scerpc
------        12/31/1600   4:00 PM              1 Winsock2\CatalogChangeListener-...
------        12/31/1600   4:00 PM              3 epmapper
------        12/31/1600   4:00 PM              3 LSM_API_service
------        12/31/1600   4:00 PM              3 eventlog
------        12/31/1600   4:00 PM              1 spoolss
```

> **À noter** : les attaques de type "Potato" (RottenPotato, JuicyPotato, PrintSpoofer, etc.) exploitent les Named Pipes et le privilege `SeImpersonatePrivilege` pour forcer un processus SYSTEM à se connecter à un pipe contrôlé par l'attaquant, puis impersonner ce token SYSTEM. C'est l'une des techniques d'escalade de privileges les plus courantes sur Windows.

---

## 5. Le Security Reference Monitor (SRM)

### 5.1 Rôle du SRM

Le **Security Reference Monitor** (SRM) est un composant du noyau Windows (Executive) responsable de l'application effective du contrôle d'accès. Contrairement à LSASS qui opère en mode utilisateur, le SRM s'exécute en mode noyau et constitue le dernier point de vérification avant l'accès à tout objet protégé.

Le SRM effectue la vérification suivante à chaque tentative d'accès :

```
Token du processus demandeur
         |
         v
   SRM compare :
   - User SID et Group SIDs du token
   - avec la DACL de l'objet cible
         |
         v
   Résultat : ALLOW ou DENY
```

### 5.2 Responsabilités détaillées du SRM

| Responsabilité | Description |
|---|---|
| **Vérification des ACL** | Compare le token du processus avec la DACL de l'objet pour autoriser ou refuser l'accès |
| **Vérification des privileges** | Vérifie si le token possède un privilege spécifique activé (ex. `SeBackupPrivilege` pour contourner les ACL en lecture) |
| **Contrôle d'intégrité** | Applique la politique d'intégrité obligatoire (Mandatory Integrity Control) : un processus ne peut pas écrire dans un objet de niveau supérieur |
| **UAC** | Participe à l'application de l'UAC en vérifiant le niveau d'intégrité des tokens |
| **Audit logging** | Génère les événements d'audit de sécurité (Event ID 4656, 4663, etc.) lorsque l'audit est activé sur un objet |

### 5.3 Interaction entre LSASS et SRM

LSASS et le SRM travaillent en tandem mais dans des espaces différents :

| Aspect | LSASS | SRM |
|---|---|---|
| **Mode d'exécution** | User-mode | Kernel-mode |
| **Rôle principal** | Authentification, création de tokens | Vérification d'accès, application des ACL |
| **Moment d'intervention** | À la connexion de l'utilisateur | À chaque accès à un objet protégé |
| **Communication** | Via le port ALPC `\SeLsaCommandPort` | Reçoit les requêtes de l'Object Manager |

---

## Pour aller plus loin

- [Microsoft -- Access Tokens](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- [Microsoft -- Privilege Constants](https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants)
- [Microsoft -- LSASS](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
- [Microsoft -- Mandatory Integrity Control](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)
- [SpecterOps -- Understanding Windows Tokens](https://posts.specterops.io/understanding-and-defending-against-access-token-theft-finding-alternatives-to-winlogon-exe-80696c8a73b)
