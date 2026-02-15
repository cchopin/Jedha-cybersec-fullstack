# Architecture et concepts fondamentaux d'Active Directory

**Module** : comprendre l'architecture, les composants et les concepts clés d'AD

---

## Objectifs du module

À l'issue de ce module, les compétences suivantes seront acquises :

- Comprendre le rôle d'AD DS (Active Directory Domain Services) dans un environnement Windows
- Maîtriser les concepts de Forest, Tree et Domain
- Savoir organiser les objets avec les Organizational Units (OUs)
- Comprendre le rôle et le fonctionnement des Domain Controllers
- Connaître le Global Catalog et son utilité
- Appréhender les mécanismes de réplication entre sites

---

## 1. Active Directory Domain Services (AD DS)

### 1.1 Définition

**AD DS** (Active Directory Domain Services) est le service central d'identité et d'accès dans un environnement Windows Server. C'est le composant principal d'Active Directory, celui qui stocke les informations sur les objets du réseau (utilisateurs, groupes, machines) et qui gère l'authentification et les autorisations.

### 1.2 Rôles d'AD DS

| Rôle | Description |
|---|---|
| **Base d'identités** | Stocke les objets utilisateurs, groupes, ordinateurs et leurs attributs |
| **Gestionnaire de politiques** | Permet l'application des Group Policy Objects (GPO) sur les machines et utilisateurs |
| **Système d'authentification** | Gère l'authentification via les protocoles **Kerberos** (par défaut) et **NTLM** (legacy) |
| **Service d'annuaire** | Fournit un annuaire interrogeable via le protocole **LDAP** (Lightweight Directory Access Protocol) |

> **À noter** : Kerberos est le protocole d'authentification par défaut depuis Windows 2000. NTLM est conservé pour la rétrocompatibilité mais est considéré comme moins sécurisé. En audit de sécurité, la présence de trafic NTLM est un indicateur à surveiller.

---

## 2. Forests, Trees et Domains

### 2.1 Domain

Un **domaine** Active Directory est l'unité administrative de base. Il peut être comparé à un domaine DNS : il définit un périmètre au sein duquel s'appliquent des politiques de sécurité, des utilisateurs, des groupes et des Domain Controllers.

Chaque domaine possède :

- Un **namespace** (espace de noms) unique, par exemple `jedha.co`
- Sa propre base de données Active Directory
- Ses propres politiques de sécurité
- Au moins un **Domain Controller**

```powershell
# Afficher les informations du domaine courant
Get-ADDomain

# Afficher le nom DNS du domaine
(Get-ADDomain).DNSRoot
```

### 2.2 Tree (Arborescence)

Un **Tree** est une hiérarchie de domaines partageant un même espace de noms contigu. Les domaines enfants héritent du namespace du domaine parent.

```
jedha.co                    (domaine racine)
  |
  +-- labs.jedha.co         (domaine enfant)
  |
  +-- paris.jedha.co        (domaine enfant)
       |
       +-- dev.paris.jedha.co  (sous-domaine)
```

Les domaines d'un même arbre sont reliés par des **relations de confiance** (trusts) bidirectionnelles et transitives. Un utilisateur de `labs.jedha.co` peut accéder aux ressources de `paris.jedha.co` si les permissions le permettent.

### 2.3 Forest (Forêt)

Une **Forest** (forêt) est le conteneur de plus haut niveau dans Active Directory. Elle regroupe un ou plusieurs Trees (arborescences) liés par des relations de confiance.

```
Forêt
|
+-- jedha.co (Tree 1)
|   +-- labs.jedha.co
|   +-- paris.jedha.co
|
+-- partner.com (Tree 2)
    +-- eu.partner.com
```

Caractéristiques d'une forêt :

| Élément | Description |
|---|---|
| **Schema** | Unique pour toute la forêt, définit les types d'objets et leurs attributs |
| **Configuration** | Partagée entre tous les domaines de la forêt |
| **Global Catalog** | Répertoire en lecture seule de tous les objets de la forêt |
| **Relations de confiance** | Automatiques et transitives entre les domaines de la forêt |
| **Frontière de sécurité** | La forêt est la véritable frontière de sécurité dans AD |

> **Bonne pratique** : la forêt constitue la **frontière de sécurité** d'Active Directory, et non le domaine. Un administrateur de domaine peut potentiellement compromettre d'autres domaines de la même forêt. C'est pourquoi la segmentation en forêts séparées est recommandée pour les environnements nécessitant un isolement strict.

---

## 3. Organizational Units (OUs)

### 3.1 Définition

Les **Organizational Units** (Unités d'Organisation) sont des conteneurs logiques au sein d'un domaine. Elles permettent d'organiser les objets AD (utilisateurs, ordinateurs, groupes) de manière hiérarchique, à l'image de dossiers dans un système de fichiers.

### 3.2 Rôles des OUs

Les OUs servent trois objectifs principaux :

1. **Organisation** : structurer logiquement les objets (par service, localisation, fonction)
2. **Application de GPO** : les Group Policy Objects peuvent être liées à une OU et s'appliquent à tous les objets qu'elle contient
3. **Délégation de contrôle** : il est possible de déléguer l'administration d'une OU à un groupe d'utilisateurs spécifique

```
jedha.local
|
+-- OU=Paris
|   +-- OU=Informatique
|   |   +-- user: j.dupont
|   |   +-- computer: PC-DEV-01
|   +-- OU=Comptabilité
|       +-- user: m.martin
|
+-- OU=Lyon
    +-- OU=Commercial
        +-- user: a.bernard
```

> **À noter** : les OUs ne sont **pas** des frontières de sécurité. Un administrateur du domaine a un accès complet à toutes les OUs. Elles servent uniquement à l'organisation et à la délégation.

### 3.3 Commandes PowerShell

```powershell
# Lister toutes les OUs du domaine
Get-ADOrganizationalUnit -Filter * | Select-Object Name, DistinguishedName

# Créer une nouvelle OU
New-ADOrganizationalUnit -Name "Informatique" -Path "OU=Paris,DC=jedha,DC=local"

# Créer une OU protégée contre la suppression accidentelle
New-ADOrganizationalUnit -Name "Serveurs" -Path "DC=jedha,DC=local" -ProtectedFromAccidentalDeletion $true

# Déplacer un utilisateur dans une OU
Move-ADObject -Identity "CN=j.dupont,CN=Users,DC=jedha,DC=local" -TargetPath "OU=Informatique,OU=Paris,DC=jedha,DC=local"
```

### 3.4 Containers vs OUs

| Critère | Container | Organizational Unit (OU) |
|---|---|---|
| **Origine** | Legacy, présent par défaut (CN=Users, CN=Computers) | Créé par l'administrateur |
| **Support GPO** | Non, les GPO ne peuvent pas être liées à un container | Oui, les GPO peuvent être liées à une OU |
| **Délégation** | Limitée | Complète |
| **Visibilité** | Visible dans AD Users and Computers en mode avancé | Toujours visible |
| **Usage recommandé** | Éviter, conserver uniquement pour la compatibilité | Utiliser systématiquement pour organiser les objets |

> **Bonne pratique** : ne laissez pas les comptes utilisateurs et ordinateurs dans les containers par défaut (`CN=Users` et `CN=Computers`). Créez des OUs adaptées à votre organisation et déplacez-y les objets pour pouvoir leur appliquer des GPO.

---

## 4. Domain Controllers

### 4.1 Définition et rôle

Un **Domain Controller** (DC) est un serveur Windows sur lequel le rôle AD DS est installé et qui a été promu. Il est responsable de :

- L'**authentification** des utilisateurs et des machines du domaine
- L'**autorisation** d'accès aux ressources
- La **réplication** des données AD vers les autres DC
- Le **stockage** de la base de données Active Directory

### 4.2 Fichiers critiques

Deux éléments sont particulièrement importants du point de vue sécurité :

| Fichier | Emplacement | Contenu |
|---|---|---|
| **ntds.dit** | `C:\Windows\NTDS\` | Base de données Active Directory contenant tous les objets, utilisateurs et leurs **hashes de mots de passe** |
| **SYSVOL** | `C:\Windows\SYSVOL\` | Répertoire partagé contenant les **GPO**, les scripts de connexion et les fichiers distribués aux machines du domaine |

> **À noter** : le fichier `ntds.dit` est la cible principale lors d'une compromission de Domain Controller. En combinant `ntds.dit` avec la ruche registre **SYSTEM** (qui contient la clé de déchiffrement), un attaquant peut extraire les **hashes de tous les comptes du domaine**. C'est la technique connue sous le nom de **DCSync** ou d'extraction hors ligne avec des outils comme `secretsdump.py`.

```powershell
# Vérifier l'emplacement de la base ntds.dit
(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters")."DSA Database File"

# Lister le contenu de SYSVOL
Get-ChildItem "C:\Windows\SYSVOL\sysvol" -Recurse | Select-Object FullName
```

### 4.3 Haute disponibilité

En production, il est indispensable d'avoir au minimum **deux Domain Controllers**. Si un DC tombe en panne, le second assure la continuité de l'authentification et de l'accès aux ressources.

> **Bonne pratique** : déployer au moins deux DC par domaine, idéalement sur des sites physiques différents. Les DC répliquent automatiquement leurs données entre eux.

---

## 5. Global Catalog

### 5.1 Définition

Le **Global Catalog** (GC) est un service qui maintient une copie **en lecture seule** et **partielle** de tous les objets de la forêt. Il contient un sous-ensemble d'attributs pour chaque objet, ce qui permet des recherches rapides à l'échelle de la forêt sans interroger chaque domaine individuellement.

### 5.2 Utilité

| Fonction | Description |
|---|---|
| **Recherche inter-domaines** | Permet de trouver un objet dans n'importe quel domaine de la forêt |
| **Résolution des groupes universels** | Nécessaire lors de l'authentification pour résoudre l'appartenance aux groupes universels |
| **Vérification UPN** | Utilisé pour valider les noms UPN (User Principal Name) lors de l'authentification |

### 5.3 Vérification

Pour vérifier si un DC est également serveur Global Catalog :

1. Ouvrir **Active Directory Sites and Services**
2. Développer **Sites > Default-First-Site-Name > Servers > DC1**
3. Cliquer droit sur **NTDS Settings** > **Properties**
4. Vérifier que la case **Global Catalog** est cochée

```powershell
# Vérifier si le DC local est un Global Catalog
(Get-ADDomainController).IsGlobalCatalog

# Lister tous les Global Catalogs de la forêt
Get-ADDomainController -Filter { IsGlobalCatalog -eq $true } | Select-Object Name, IPv4Address
```

> **Bonne pratique** : dans un environnement à domaine unique, tous les DC devraient être configurés comme Global Catalog. Dans un environnement multi-domaines, au moins un GC doit être accessible sur chaque site.

---

## 6. Sites et réplication

### 6.1 Sites AD

Les **Sites** dans Active Directory représentent les localisations physiques du réseau. Ils permettent d'optimiser le trafic de réplication et l'authentification en orientant les clients vers le DC le plus proche.

Un site est défini par un ou plusieurs **subnets** (sous-réseaux IP) associés. Quand une machine s'authentifie, AD utilise son adresse IP pour déterminer son site et la diriger vers un DC local.

### 6.2 Réplication

La réplication AD assure la cohérence des données entre les Domain Controllers. Il existe deux types de réplication :

| Type | Contexte | Fréquence | Compression |
|---|---|---|---|
| **Intra-site** | Entre DC d'un même site | Rapide et fréquent (toutes les 15 secondes après notification) | Non compressée |
| **Inter-site** | Entre DC de sites différents | Planifié (par défaut toutes les 3 heures) | Compressée pour économiser la bande passante |

La réplication intra-site est optimisée pour la rapidité : dès qu'un changement est effectué sur un DC, il notifie ses partenaires de réplication qui récupèrent la modification dans les secondes qui suivent.

La réplication inter-site est optimisée pour la bande passante : les changements sont regroupés, compressés et transmis selon un calendrier configurable.

```powershell
# Vérifier l'état de la réplication
repadmin /replsummary

# Forcer la réplication entre DC
repadmin /syncall /AdeP

# Afficher les partenaires de réplication
repadmin /showrepl
```

### 6.3 Configuration des sites

La gestion des sites se fait via la console **Active Directory Sites and Services** :

1. Ouvrir **Active Directory Sites and Services**
2. Créer les sites correspondant aux localisations physiques
3. Associer les sous-réseaux IP à chaque site
4. Configurer les **Site Links** (liens entre sites) avec leur coût et leur fréquence de réplication

> **À noter** : une mauvaise configuration des sites peut entraîner des problèmes de performance (authentification lente) ou de réplication (données incohérentes entre DC). C'est un point à vérifier systématiquement lors d'un audit d'infrastructure AD.

---

## Pour aller plus loin

- [Documentation Microsoft - AD DS Design](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/ad-ds-design-and-planning)
- [Documentation Microsoft - Active Directory Replication](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/replication/active-directory-replication-concepts)
- [Comprendre la base ntds.dit](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc772829(v=ws.10))
- [Active Directory Sites and Services](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/creating-a-site-design)
- [MITRE ATT&CK - DCSync](https://attack.mitre.org/techniques/T1003/006/)
