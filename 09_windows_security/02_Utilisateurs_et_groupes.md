# Gestion des utilisateurs et groupes sous Windows

**Module** : administration Windows 

---

## Objectifs du module

À l'issue de ce module, les compétences suivantes seront acquises :

- Créer, modifier et supprimer des utilisateurs et groupes locaux
- Connaître les comptes et groupes intégrés à Windows et leurs implications en sécurité
- Définir et appliquer des politiques de comptes (mots de passe, verrouillage, déconnexion)
- Gérer les utilisateurs et groupes en ligne de commande (PowerShell / cmd)
- Comprendre le rôle du Contrôle de compte d'utilisateur (UAC)

> **Prérequis** : avoir suivi le module "Prise en main de la sécurité Windows".

> **Périmètre** : ce module traite exclusivement des **utilisateurs locaux**. La gestion des utilisateurs de domaine via Active Directory sera abordée dans un module ultérieur.

---

## 1. Gestion via l'interface graphique

### 1.1 Accès aux outils

Deux méthodes permettent d'accéder à la gestion des utilisateurs et groupes locaux :

- **Computer Management** : clic droit sur le menu Démarrer > Gestion de l'ordinateur > Utilisateurs et groupes locaux
- **lusrmgr.msc** : ouvrir la boîte de dialogue Exécuter (`Win + R`), taper `lusrmgr.msc` et valider

Les deux méthodes mènent à la même console MMC.

### 1.2 Opérations de base

Depuis cette console, il est possible de :

- **Créer un utilisateur** : clic droit dans le volet "Utilisateurs" > Nouvel utilisateur. Renseigner le nom, le mot de passe et les options souhaitées.
- **Créer un groupe** : clic droit dans le volet "Groupes" > Nouveau groupe. Nommer le groupe et y ajouter des membres.
- **Affecter un utilisateur à un groupe** : double-clic sur le groupe souhaité > Ajouter > saisir le nom de l'utilisateur.
- **Supprimer un utilisateur ou un groupe** : clic droit sur l'élément > Supprimer.

> **Bonne pratique en production** : lors de la création d'un compte, toujours cocher l'option "L'utilisateur doit changer le mot de passe à la prochaine ouverture de session". L'administrateur ne doit jamais connaître le mot de passe définitif d'un utilisateur.

---

## 2. Comptes et groupes intégrés

Windows est livré avec un ensemble de comptes et de groupes préconfigurés. Leur connaissance est indispensable pour sécuriser correctement un système.

### 2.1 Comptes intégrés

| Compte | Rôle | Remarque sécurité |
|---|---|---|
| `Administrator` | Contrôle total du système | Compte très ciblé par les attaques par force brute. À renommer, désactiver ou restreindre. |
| `Guest` | Accès limité pour utilisateurs temporaires | Désactivé par défaut. Ne pas réactiver sauf besoin justifié. |
| `DefaultAccount` | Compte système pour le provisionnement d'applications | Géré automatiquement par Windows. Ne pas modifier. |
| `WDAGUtilityAccount` | Utilisé par Windows Defender Application Guard pour isoler les sessions de navigation | Géré automatiquement par Windows. Ne pas modifier. |

### 2.2 Groupes intégrés

| Groupe | Rôle | Niveau de privilèges |
|---|---|---|
| `Administrators` | Contrôle total : gestion du système, des utilisateurs, des services | Maximal |
| `Users` | Utilisation standard : exécution d'applications, pas de modification système | Standard |
| `Guests` | Accès très restreint, généralement en lecture seule | Minimal |
| `Power Users` | Groupe hérité avec des privilèges intermédiaires | Obsolète (ne plus utiliser) |
| `Remote Desktop Users` | Connexion à distance via RDP, sans droits locaux supplémentaires | Limité |
| `Backup Operators` | Possibilité de contourner les permissions de fichiers pour la sauvegarde et la restauration | Élevé (dangereux si mal encadré) |
| `Network Configuration Operators` | Modification des paramètres TCP/IP et renouvellement des baux DHCP | Limité |
| `Replicator` | Support des services de réplication de fichiers (DFS) | Technique (ne pas utiliser manuellement) |

Deux entités apparaissent fréquemment dans les permissions sans être des groupes au sens classique :

| Entité | Description |
|---|---|
| `Everyone` | Inclut tous les utilisateurs, y compris les non authentifiés (dans les anciennes versions de Windows) |
| `Authenticated Users` | Inclut uniquement les utilisateurs ayant ouvert une session |
| `SYSTEM` | Compte interne disposant des privilèges les plus élevés du système. Ce n'est pas un groupe, mais il apparaît dans de nombreuses ACL. |

> **Règle importante** : ne jamais attribuer de permissions à `Everyone`. Préférer systématiquement `Authenticated Users` pour garantir que seuls les utilisateurs authentifiés y ont accès.

### 2.3 Bonnes pratiques de gestion des comptes et groupes

Ces recommandations s'appliquent à tout environnement Windows, local ou de domaine :

**Principe du moindre privilège**

Le principe fondamental : chaque utilisateur ne doit disposer que des droits strictement nécessaires à ses fonctions. Concrètement, cela implique de limiter au maximum l'appartenance au groupe `Administrators`, d'utiliser un compte séparé pour les tâches d'administration (ne jamais utiliser son compte quotidien), et de préférer les GPO et groupes de domaine pour les machines jointes à un domaine.

**Sécurisation du compte Administrator**

Le compte `Administrator` intégré est la première cible des attaques par force brute. Il convient de le renommer pour compliquer l'identification, de le désactiver s'il n'est pas utilisé, et d'appliquer des restrictions via GPO si nécessaire.

**Gestion du compte Guest et du groupe Guests**

Le compte `Guest` est désactivé par défaut et doit le rester. Le groupe `Guests` ne devrait contenir aucun membre dans un environnement de production.

**Groupe Power Users : à éviter**

Ce groupe est obsolète depuis Windows Vista. Son comportement est imprévisible sur les versions modernes de Windows. Il convient de retirer tous ses membres et de ne pas l'utiliser pour le contrôle d'accès.

**Restriction de Remote Desktop Users**

Seuls les utilisateurs ayant un besoin légitime d'accès à distance doivent être membres de ce groupe. Cette mesure doit être combinée avec des règles de pare-feu, de l'authentification multifacteur (MFA) et une segmentation réseau appropriée.

**Restriction de Backup Operators**

Ce groupe permet de contourner les permissions de fichiers, ce qui représente un risque important. Il ne devrait contenir que des comptes de service dédiés à la sauvegarde. Son utilisation doit être surveillée.

**Contrôle centralisé via GPO**

L'utilisation de Restricted Groups ou de Group Policy Preferences permet de gérer centralement l'appartenance aux groupes. Cela évite les dérives locales par rapport à la baseline de sécurité.

**Audit régulier**

Un script PowerShell ou un outil comme SCCM permet de détecter automatiquement les changements d'appartenance aux groupes. Des solutions comme LAPS (Local Administrator Password Solution) ou l'administration Just-In-Time permettent de limiter les élévations de privilèges dans le temps.

**Approche RBAC (contrôle d'accès basé sur les rôles)**

La bonne pratique consiste à créer des groupes personnalisés correspondant à des rôles métier (ex. "HelpDesk", "DevOps", "Finance"), puis à ajouter ces groupes aux groupes intégrés si nécessaire. Cela évite l'affectation directe d'utilisateurs aux groupes à privilèges élevés.

**Comptes système : ne pas toucher**

Les comptes `DefaultAccount` et `WDAGUtilityAccount` sont gérés par Windows. Ne pas les ajouter à des groupes ni leur attribuer de rôles.

---

## 3. Gestion en ligne de commande

L'interface graphique est pratique pour des opérations ponctuelles, mais elle atteint rapidement ses limites en matière d'automatisation et de reproductibilité. La maîtrise des commandes est indispensable pour tout administrateur système ou professionnel de la cybersécurité.

> **Note** : les commandes `net` présentées ci-dessous fonctionnent aussi bien dans PowerShell que dans l'invite de commandes classique (`cmd.exe`). PowerShell dispose en plus de cmdlets dédiées (`Get-LocalUser`, `Get-LocalGroup`, etc.) qui offrent davantage de flexibilité. Les deux approches sont valables.

> **Prérequis** : toutes les commandes de cette section nécessitent une exécution en tant qu'administrateur. Dans PowerShell, effectuer un clic droit > "Exécuter en tant qu'administrateur".

### 3.1 Gestion des utilisateurs

```powershell
# Créer un utilisateur (le système demandera le mot de passe)
net user NOM_UTILISATEUR * /add

# Supprimer un utilisateur
net user NOM_UTILISATEUR /delete

# Désactiver un utilisateur
net user NOM_UTILISATEUR /active:no

# Réactiver un utilisateur
net user NOM_UTILISATEUR /active:yes

# Afficher les informations d'un utilisateur
net user NOM_UTILISATEUR
```

### 3.2 Politiques de comptes

Les politiques de comptes permettent d'appliquer des règles de sécurité globales sur les mots de passe et les sessions. Elles constituent un élément fondamental du durcissement d'un système.

```powershell
# Afficher les politiques actuelles
net accounts

# Déconnexion automatique après X minutes d'inactivité
net accounts /FORCELOGOFF:minutes

# Longueur minimale du mot de passe
net accounts /MINPWLEN:longueur

# Durée maximale de validité du mot de passe (en jours)
net accounts /MAXPWAGE:jours

# Durée minimale avant de pouvoir changer le mot de passe (en jours)
net accounts /MINPWAGE:jours

# Nombre de mots de passe uniques avant réutilisation
net accounts /UNIQUEPW:nombre
```

Trois règles essentielles à retenir pour les politiques de mots de passe :

1. **Longueur minimale élevée** : plus un mot de passe est long, plus il est résistant aux attaques par force brute. Un minimum de 12 caractères est recommandé par l'ANSSI.
2. **Historique des mots de passe** : empêcher la réutilisation des anciens mots de passe oblige les utilisateurs à en choisir de nouveaux.
3. **Déconnexion automatique** : forcer la déconnexion après une période d'inactivité réduit le risque d'accès non autorisé sur un poste laissé sans surveillance.

### 3.3 Gestion des groupes

```powershell
# Lister les membres d'un groupe
net localgroup NOM_GROUPE

# Créer un nouveau groupe
net localgroup NOM_GROUPE /add

# Ajouter un utilisateur à un groupe
net localgroup NOM_GROUPE NOM_UTILISATEUR /add

# Retirer un utilisateur d'un groupe
net localgroup NOM_GROUPE NOM_UTILISATEUR /del
```

### 3.4 Équivalents PowerShell natifs

Pour aller plus loin, PowerShell propose des cmdlets dédiées à la gestion locale :

```powershell
# Lister tous les utilisateurs locaux
Get-LocalUser

# Créer un utilisateur avec mot de passe sécurisé
$password = Read-Host -AsSecureString "Mot de passe"
New-LocalUser -Name "NOM_UTILISATEUR" -Password $password

# Supprimer un utilisateur
Remove-LocalUser -Name "NOM_UTILISATEUR"

# Lister tous les groupes locaux
Get-LocalGroup

# Lister les membres d'un groupe
Get-LocalGroupMember -Group "Administrators"

# Ajouter un utilisateur à un groupe
Add-LocalGroupMember -Group "NOM_GROUPE" -Member "NOM_UTILISATEUR"

# Retirer un utilisateur d'un groupe
Remove-LocalGroupMember -Group "NOM_GROUPE" -Member "NOM_UTILISATEUR"
```

> **Avantage des cmdlets PowerShell** : elles retournent des objets structurés, ce qui permet de les combiner avec des filtres (`Where-Object`), des exports (`Export-Csv`) et des pipelines complexes. C'est l'approche à privilégier pour l'automatisation et l'audit.

---

## 4. Le Contrôle de compte d'utilisateur (UAC)

### 4.1 Principe de fonctionnement

Le **Contrôle de compte d'utilisateur** (User Account Control, UAC) est un mécanisme de sécurité intégré à Windows depuis Vista. Son rôle est d'empêcher les programmes d'exécuter des actions à privilèges élevés de manière silencieuse.

Le fonctionnement est le suivant : même lorsqu'une session est ouverte avec un compte membre du groupe `Administrators`, tous les programmes s'exécutent par défaut avec des privilèges standard. Lorsqu'une action nécessite des droits d'administration (installation d'un logiciel, modification de paramètres système, etc.), Windows affiche une boîte de dialogue demandant une confirmation explicite.

Ce mécanisme présente un intérêt majeur en sécurité : si un malware tente d'élever ses privilèges en arrière-plan, l'utilisateur sera averti par la fenêtre UAC. L'apparition inattendue de cette boîte de dialogue doit toujours être considérée comme suspecte.

### 4.2 Niveaux de notification

UAC propose quatre niveaux de notification, configurables via le Panneau de configuration (Comptes d'utilisateurs > Modifier les paramètres de contrôle de compte d'utilisateur) :

| Niveau | Comportement | Recommandation |
|---|---|---|
| Toujours notifier | Notification pour toute modification système et toute installation | Le plus sécurisé, mais intrusif |
| Notifier uniquement pour les applications (par défaut) | Notification uniquement lorsqu'une application tente une modification | Bon compromis sécurité/confort |
| Notifier sans assombrir le bureau | Identique au précédent, mais sans le bureau sécurisé | Moins sécurisé (vulnérable au détournement de l'interface) |
| Ne jamais notifier | UAC désactivé | À proscrire en production |

> **Recommandation** : conserver le niveau par défaut au minimum. Sur les systèmes sensibles, le niveau "Toujours notifier" est préférable. Ne jamais désactiver complètement UAC en environnement de production.

### 4.3 UAC et élévation de privilèges

En contexte offensif (tests de pénétration), le contournement de l'UAC (UAC bypass) est une technique classique d'escalade de privilèges. Parmi les méthodes connues :

- Exploitation de binaires Windows signés qui s'exécutent automatiquement avec des privilèges élevés (auto-elevation)
- Manipulation de clés de registre liées à l'exécution de programmes
- Injection de DLL dans des processus de confiance

La connaissance de ces vecteurs d'attaque est essentielle pour évaluer la posture de sécurité d'un système. Ces techniques seront abordées plus en détail dans les modules de tests d'intrusion.

---

## Récapitulatif des commandes

| Commande | Usage |
|---|---|
| `net user NOM *  /add` | Créer un utilisateur |
| `net user NOM /delete` | Supprimer un utilisateur |
| `net user NOM /active:no` | Désactiver un utilisateur |
| `net accounts` | Afficher les politiques de comptes |
| `net accounts /MINPWLEN:N` | Longueur minimale de mot de passe |
| `net accounts /MAXPWAGE:N` | Durée maximale de validité du mot de passe |
| `net accounts /UNIQUEPW:N` | Historique de mots de passe uniques |
| `net accounts /FORCELOGOFF:N` | Déconnexion automatique après inactivité |
| `net localgroup NOM` | Lister les membres d'un groupe |
| `net localgroup NOM /add` | Créer un groupe |
| `net localgroup NOM USER /add` | Ajouter un utilisateur à un groupe |
| `net localgroup NOM USER /del` | Retirer un utilisateur d'un groupe |

---

## Pour aller plus loin

- [Local Accounts (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/local-accounts)
- [Windows Users and Groups - CompTIA A+ 220-802: 1.4 (YouTube)](https://www.youtube.com/results?search_query=Windows+Users+and+Groups+CompTIA+A%2B+220-802+1.4)
- [How to Manage Users and Groups in Windows (YouTube)](https://www.youtube.com/results?search_query=How+to+Manage+Users+and+Groups+in+Windows)
- [User Account Control (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/)
- [LAPS - Local Administrator Password Solution (Microsoft)](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
