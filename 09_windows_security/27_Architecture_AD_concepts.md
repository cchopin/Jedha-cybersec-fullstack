# Architecture et concepts fondamentaux d'Active Directory

**Module** : comprendre l'architecture, les composants et les concepts cles d'AD

---

## Objectifs du module

A l'issue de ce module, les competences suivantes seront acquises :

- Comprendre le role d'AD DS (Active Directory Domain Services) dans un environnement Windows
- Maitriser les concepts de Forest, Tree et Domain
- Savoir organiser les objets avec les Organizational Units (OUs)
- Comprendre le role et le fonctionnement des Domain Controllers
- Connaitre le Global Catalog et son utilite
- Apprehender les mecanismes de replication entre sites

---

## 1. Active Directory Domain Services (AD DS)

### 1.1 Definition

**AD DS** (Active Directory Domain Services) est le service central d'identite et d'acces dans un environnement Windows Server. C'est le composant principal d'Active Directory, celui qui stocke les informations sur les objets du reseau (utilisateurs, groupes, machines) et qui gere l'authentification et les autorisations.

### 1.2 Roles d'AD DS

| Role | Description |
|---|---|
| **Base d'identites** | Stocke les objets utilisateurs, groupes, ordinateurs et leurs attributs |
| **Gestionnaire de politiques** | Permet l'application des Group Policy Objects (GPO) sur les machines et utilisateurs |
| **Systeme d'authentification** | Gere l'authentification via les protocoles **Kerberos** (par defaut) et **NTLM** (legacy) |
| **Service d'annuaire** | Fournit un annuaire interrogeable via le protocole **LDAP** (Lightweight Directory Access Protocol) |

> **A noter** : Kerberos est le protocole d'authentification par defaut depuis Windows 2000. NTLM est conserve pour la retrocompatibilite mais est considere comme moins securise. En audit de securite, la presence de trafic NTLM est un indicateur a surveiller.

---

## 2. Forests, Trees et Domains

### 2.1 Domain

Un **domaine** Active Directory est l'unite administrative de base. Il peut etre compare a un domaine DNS : il definit un perimetre au sein duquel s'appliquent des politiques de securite, des utilisateurs, des groupes et des Domain Controllers.

Chaque domaine possede :

- Un **namespace** (espace de noms) unique, par exemple `jedha.co`
- Sa propre base de donnees Active Directory
- Ses propres politiques de securite
- Au moins un **Domain Controller**

```powershell
# Afficher les informations du domaine courant
Get-ADDomain

# Afficher le nom DNS du domaine
(Get-ADDomain).DNSRoot
```

### 2.2 Tree (Arborescence)

Un **Tree** est une hierarchie de domaines partageant un meme espace de noms contigu. Les domaines enfants heritent du namespace du domaine parent.

```
jedha.co                    (domaine racine)
  |
  +-- labs.jedha.co         (domaine enfant)
  |
  +-- paris.jedha.co        (domaine enfant)
       |
       +-- dev.paris.jedha.co  (sous-domaine)
```

Les domaines d'un meme arbre sont relies par des **relations de confiance** (trusts) bidirectionnelles et transitives. Un utilisateur de `labs.jedha.co` peut acceder aux ressources de `paris.jedha.co` si les permissions le permettent.

### 2.3 Forest (Foret)

Une **Forest** (foret) est le conteneur de plus haut niveau dans Active Directory. Elle regroupe un ou plusieurs Trees (arborescences) lies par des relations de confiance.

```
Foret
|
+-- jedha.co (Tree 1)
|   +-- labs.jedha.co
|   +-- paris.jedha.co
|
+-- partner.com (Tree 2)
    +-- eu.partner.com
```

Caracteristiques d'une foret :

| Element | Description |
|---|---|
| **Schema** | Unique pour toute la foret, definit les types d'objets et leurs attributs |
| **Configuration** | Partagee entre tous les domaines de la foret |
| **Global Catalog** | Repertoire en lecture seule de tous les objets de la foret |
| **Relations de confiance** | Automatiques et transitives entre les domaines de la foret |
| **Frontiere de securite** | La foret est la veritable frontiere de securite dans AD |

> **Bonne pratique** : la foret constitue la **frontiere de securite** d'Active Directory, et non le domaine. Un administrateur de domaine peut potentiellement compromettre d'autres domaines de la meme foret. C'est pourquoi la segmentation en forets separees est recommandee pour les environnements necessitant un isolement strict.

---

## 3. Organizational Units (OUs)

### 3.1 Definition

Les **Organizational Units** (Unites d'Organisation) sont des conteneurs logiques au sein d'un domaine. Elles permettent d'organiser les objets AD (utilisateurs, ordinateurs, groupes) de maniere hierarchique, a l'image de dossiers dans un systeme de fichiers.

### 3.2 Roles des OUs

Les OUs servent trois objectifs principaux :

1. **Organisation** : structurer logiquement les objets (par service, localisation, fonction)
2. **Application de GPO** : les Group Policy Objects peuvent etre liees a une OU et s'appliquent a tous les objets qu'elle contient
3. **Delegation de controle** : il est possible de deleguer l'administration d'une OU a un groupe d'utilisateurs specifique

```
jedha.local
|
+-- OU=Paris
|   +-- OU=Informatique
|   |   +-- user: j.dupont
|   |   +-- computer: PC-DEV-01
|   +-- OU=Comptabilite
|       +-- user: m.martin
|
+-- OU=Lyon
    +-- OU=Commercial
        +-- user: a.bernard
```

> **A noter** : les OUs ne sont **pas** des frontieres de securite. Un administrateur du domaine a un acces complet a toutes les OUs. Elles servent uniquement a l'organisation et a la delegation.

### 3.3 Commandes PowerShell

```powershell
# Lister toutes les OUs du domaine
Get-ADOrganizationalUnit -Filter * | Select-Object Name, DistinguishedName

# Creer une nouvelle OU
New-ADOrganizationalUnit -Name "Informatique" -Path "OU=Paris,DC=jedha,DC=local"

# Creer une OU protegee contre la suppression accidentelle
New-ADOrganizationalUnit -Name "Serveurs" -Path "DC=jedha,DC=local" -ProtectedFromAccidentalDeletion $true

# Deplacer un utilisateur dans une OU
Move-ADObject -Identity "CN=j.dupont,CN=Users,DC=jedha,DC=local" -TargetPath "OU=Informatique,OU=Paris,DC=jedha,DC=local"
```

### 3.4 Containers vs OUs

| Critere | Container | Organizational Unit (OU) |
|---|---|---|
| **Origine** | Legacy, present par defaut (CN=Users, CN=Computers) | Cree par l'administrateur |
| **Support GPO** | Non, les GPO ne peuvent pas etre liees a un container | Oui, les GPO peuvent etre liees a une OU |
| **Delegation** | Limitee | Complete |
| **Visibilite** | Visible dans AD Users and Computers en mode avance | Toujours visible |
| **Usage recommande** | Eviter, conserver uniquement pour la compatibilite | Utiliser systematiquement pour organiser les objets |

> **Bonne pratique** : ne laissez pas les comptes utilisateurs et ordinateurs dans les containers par defaut (`CN=Users` et `CN=Computers`). Creez des OUs adaptees a votre organisation et deplacez-y les objets pour pouvoir leur appliquer des GPO.

---

## 4. Domain Controllers

### 4.1 Definition et role

Un **Domain Controller** (DC) est un serveur Windows sur lequel le role AD DS est installe et qui a ete promu. Il est responsable de :

- L'**authentification** des utilisateurs et des machines du domaine
- L'**autorisation** d'acces aux ressources
- La **replication** des donnees AD vers les autres DC
- Le **stockage** de la base de donnees Active Directory

### 4.2 Fichiers critiques

Deux elements sont particulierement importants du point de vue securite :

| Fichier | Emplacement | Contenu |
|---|---|---|
| **ntds.dit** | `C:\Windows\NTDS\` | Base de donnees Active Directory contenant tous les objets, utilisateurs et leurs **hashes de mots de passe** |
| **SYSVOL** | `C:\Windows\SYSVOL\` | Repertoire partage contenant les **GPO**, les scripts de connexion et les fichiers distribues aux machines du domaine |

> **A noter** : le fichier `ntds.dit` est la cible principale lors d'une compromission de Domain Controller. En combinant `ntds.dit` avec la ruche registre **SYSTEM** (qui contient la cle de dechiffrement), un attaquant peut extraire les **hashes de tous les comptes du domaine**. C'est la technique connue sous le nom de **DCSync** ou d'extraction hors ligne avec des outils comme `secretsdump.py`.

```powershell
# Verifier l'emplacement de la base ntds.dit
(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters")."DSA Database File"

# Lister le contenu de SYSVOL
Get-ChildItem "C:\Windows\SYSVOL\sysvol" -Recurse | Select-Object FullName
```

### 4.3 Haute disponibilite

En production, il est indispensable d'avoir au minimum **deux Domain Controllers**. Si un DC tombe en panne, le second assure la continuite de l'authentification et de l'acces aux ressources.

> **Bonne pratique** : deployer au moins deux DC par domaine, idealement sur des sites physiques differents. Les DC repliquent automatiquement leurs donnees entre eux.

---

## 5. Global Catalog

### 5.1 Definition

Le **Global Catalog** (GC) est un service qui maintient une copie **en lecture seule** et **partielle** de tous les objets de la foret. Il contient un sous-ensemble d'attributs pour chaque objet, ce qui permet des recherches rapides a l'echelle de la foret sans interroger chaque domaine individuellement.

### 5.2 Utilite

| Fonction | Description |
|---|---|
| **Recherche inter-domaines** | Permet de trouver un objet dans n'importe quel domaine de la foret |
| **Resolution des groupes universels** | Necessaire lors de l'authentification pour resoudre l'appartenance aux groupes universels |
| **Verification UPN** | Utilise pour valider les noms UPN (User Principal Name) lors de l'authentification |

### 5.3 Verification

Pour verifier si un DC est egalement serveur Global Catalog :

1. Ouvrir **Active Directory Sites and Services**
2. Developper **Sites > Default-First-Site-Name > Servers > DC1**
3. Cliquer droit sur **NTDS Settings** > **Properties**
4. Verifier que la case **Global Catalog** est cochee

```powershell
# Verifier si le DC local est un Global Catalog
(Get-ADDomainController).IsGlobalCatalog

# Lister tous les Global Catalogs de la foret
Get-ADDomainController -Filter { IsGlobalCatalog -eq $true } | Select-Object Name, IPv4Address
```

> **Bonne pratique** : dans un environnement a domaine unique, tous les DC devraient etre configures comme Global Catalog. Dans un environnement multi-domaines, au moins un GC doit etre accessible sur chaque site.

---

## 6. Sites et replication

### 6.1 Sites AD

Les **Sites** dans Active Directory representent les localisations physiques du reseau. Ils permettent d'optimiser le trafic de replication et l'authentification en orientant les clients vers le DC le plus proche.

Un site est defini par un ou plusieurs **subnets** (sous-reseaux IP) associes. Quand une machine s'authentifie, AD utilise son adresse IP pour determiner son site et la diriger vers un DC local.

### 6.2 Replication

La replication AD assure la coherence des donnees entre les Domain Controllers. Il existe deux types de replication :

| Type | Contexte | Frequence | Compression |
|---|---|---|---|
| **Intra-site** | Entre DC d'un meme site | Rapide et frequent (toutes les 15 secondes apres notification) | Non compressee |
| **Inter-site** | Entre DC de sites differents | Planifie (par defaut toutes les 3 heures) | Compressee pour economiser la bande passante |

La replication intra-site est optimisee pour la rapidite : des qu'un changement est effectue sur un DC, il notifie ses partenaires de replication qui recuperent la modification dans les secondes qui suivent.

La replication inter-site est optimisee pour la bande passante : les changements sont regroupes, compresses et transmis selon un calendrier configurable.

```powershell
# Verifier l'etat de la replication
repadmin /replsummary

# Forcer la replication entre DC
repadmin /syncall /AdeP

# Afficher les partenaires de replication
repadmin /showrepl
```

### 6.3 Configuration des sites

La gestion des sites se fait via la console **Active Directory Sites and Services** :

1. Ouvrir **Active Directory Sites and Services**
2. Creer les sites correspondant aux localisations physiques
3. Associer les sous-reseaux IP a chaque site
4. Configurer les **Site Links** (liens entre sites) avec leur cout et leur frequence de replication

> **A noter** : une mauvaise configuration des sites peut entrainer des problemes de performance (authentification lente) ou de replication (donnees incoherentes entre DC). C'est un point a verifier systematiquement lors d'un audit d'infrastructure AD.

---

## Pour aller plus loin

- [Documentation Microsoft - AD DS Design](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/ad-ds-design-and-planning)
- [Documentation Microsoft - Active Directory Replication](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/replication/active-directory-replication-concepts)
- [Comprendre la base ntds.dit](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc772829(v=ws.10))
- [Active Directory Sites and Services](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/creating-a-site-design)
- [MITRE ATT&CK - DCSync](https://attack.mitre.org/techniques/T1003/006/)
