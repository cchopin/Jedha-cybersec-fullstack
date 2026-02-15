# Installation d'Active Directory

**Module** : mise en place d'un environnement Active Directory avec GNS3

---

## Objectifs du module

À l'issue de ce module, les compétences suivantes seront acquises :

- Comprendre ce qu'est Active Directory et pourquoi il est utilisé en entreprise
- Mettre en place un environnement de lab avec GNS3
- Installer et configurer un Domain Controller sous Windows Server 2022
- Joindre un serveur membre au domaine
- Distinguer un Workgroup d'un Domain

---

## 1. Qu'est-ce qu'Active Directory ?

### 1.1 Définition

**Active Directory** (AD) est la solution Microsoft pour gérer un parc informatique à grande échelle. Il permet de centraliser la gestion des utilisateurs, des machines, des politiques de sécurité et des ressources réseau au sein d'une organisation.

Dans un environnement sans Active Directory, chaque machine est indépendante : les comptes utilisateurs, les permissions et les configurations sont gérés localement sur chaque poste. Cela devient rapidement ingérable dès que le nombre de machines augmente. Active Directory résout ce problème en fournissant un annuaire centralisé et un système d'authentification unique.

### 1.2 Cas d'usage en entreprise

| Fonction | Description |
|---|---|
| **Gestion centralisée des utilisateurs** | Création, modification et suppression des comptes depuis un point unique |
| **Authentification unique (SSO)** | Un seul couple identifiant/mot de passe pour accéder à toutes les ressources |
| **Politiques de sécurité (GPO)** | Application uniforme des règles de sécurité sur l'ensemble du parc |
| **Gestion des permissions** | Contrôle granulaire de l'accès aux fichiers, dossiers et applications |
| **Déploiement logiciel** | Installation et mise à jour de logiciels à distance |

> **À noter** : Active Directory est présent dans la quasi-totalité des entreprises utilisant un environnement Windows. Sa compromission est l'un des objectifs principaux des attaquants lors d'une intrusion réseau, ce qui en fait un sujet central en cybersécurité.

---

## 2. Mise en place du lab avec GNS3

### 2.1 Prérequis

Pour réaliser les exercices de ce module, un environnement de lab est nécessaire. L'infrastructure repose sur **GNS3**, un simulateur de réseaux qui permet de créer des topologies virtuelles complexes.

Les éléments requis sont :

- Une connexion **VPN Jedha** active
- Le client **GNS3** installé sur votre machine locale

### 2.2 Connexion à la VM GNS3 distante

Le client GNS3 local doit être connecté à la VM GNS3 distante hébergée sur l'infrastructure Jedha. Pour cela :

1. Lancer le client GNS3
2. Aller dans **Edit > Preferences > Server**
3. Configurer la connexion vers la VM distante en renseignant l'adresse IP fournie (par exemple `192.168.1.160`)
4. Vérifier que la connexion est établie (icône verte dans la barre de statut)

### 2.3 Topologie de base

La topologie du lab se compose des éléments suivants :

```
+--------+      +----------+      +--------+
|  DC1   |------| Switch   |------|  SRV1  |
+--------+      +----------+      +--------+
                     |
                +----------+
                |  Cloud   |
                +----------+
```

| Machine | Rôle | Description |
|---|---|---|
| **DC1** | Domain Controller | Serveur principal hébergeant Active Directory |
| **SRV1** | Serveur membre | Serveur enfant joint au domaine |
| **Switch** | Commutateur | Interconnecte les machines du lab |
| **Cloud** | Accès externe | Fournit la connectivité réseau vers l'extérieur |

Les deux serveurs sont des machines **Windows Server 2022** connectées via un switch à un node Cloud pour l'accès réseau.

---

## 3. Windows Server 2022

### 3.1 Présentation

**Windows Server 2022** est le système d'exploitation serveur de Microsoft, conçu pour la gestion de réseaux, le stockage, les applications et les services en entreprise. Contrairement à Windows 10 ou 11 qui sont destinés aux postes de travail, Windows Server offre des fonctionnalités spécifiques aux environnements professionnels.

### 3.2 Différences avec Windows 10/11

| Fonctionnalité | Windows 10/11 | Windows Server 2022 |
|---|---|---|
| **Active Directory** | Non disponible (peut uniquement joindre un domaine) | Installation et gestion complète d'AD |
| **DNS** | Client DNS uniquement | Serveur DNS complet |
| **DHCP** | Client DHCP uniquement | Serveur DHCP complet |
| **Hyper-V** | Version limitée | Version complète avec fonctionnalités avancées |
| **Rôles serveur** | Non disponible | Rôles et fonctionnalités installables (AD, DNS, DHCP, IIS, etc.) |
| **Connexions simultanées** | Limitées | Gestion multi-utilisateurs via Remote Desktop Services |
| **Interface** | Bureau complet avec applications grand public | Mode Desktop Experience ou Server Core (sans interface graphique) |

> **À noter** : Windows Server peut être installé en mode **Server Core** (ligne de commande uniquement) ou en mode **Desktop Experience** (avec interface graphique). Le mode Server Core est recommandé en production pour réduire la surface d'attaque.

---

## 4. Installation d'Active Directory sur DC1

### 4.1 Ajout du rôle AD DS

L'installation d'Active Directory se fait via le **Server Manager** de Windows Server :

1. Ouvrir **Server Manager**
2. Cliquer sur **Manage > Add Roles and Features**
3. Suivre l'assistant :
   - **Installation Type** : Role-based or feature-based installation
   - **Server Selection** : sélectionner DC1
   - **Server Roles** : cocher **Active Directory Domain Services**
4. Cliquer sur **Add Features** lorsque les dépendances sont proposées
5. Poursuivre l'assistant jusqu'à la fin et lancer l'installation

### 4.2 Promotion en Domain Controller

Une fois le rôle AD DS installé, le serveur doit être **promu** en Domain Controller :

1. Dans Server Manager, cliquer sur le drapeau de notification (icône jaune)
2. Sélectionner **Promote this server to a domain controller**
3. Choisir **Add a new forest** et renseigner le nom de domaine racine (par exemple `jedha.local`)
4. Configurer le mot de passe DSRM (Directory Services Restore Mode)
5. Valider les options DNS et NetBIOS
6. Lancer l'installation et redémarrer le serveur

Après le redémarrage, DC1 est désormais le **Domain Controller** du domaine `jedha.local`.

```powershell
# Vérifier que le rôle AD DS est bien installé
Get-WindowsFeature AD-Domain-Services

# Vérifier le domaine
Get-ADDomain
```

---

## 5. Joindre SRV1 au domaine

### 5.1 Configuration réseau de SRV1

Avant de joindre SRV1 au domaine, sa configuration réseau doit être adaptée. Le point essentiel est que le **DNS principal de SRV1 doit pointer vers l'adresse IP de DC1**, car c'est le Domain Controller qui héberge les enregistrements DNS du domaine.

1. Ouvrir les paramètres réseau de SRV1
2. Configurer l'adresse IP de manière statique
3. Renseigner les serveurs DNS :
   - **DNS principal** : adresse IP de DC1 (par exemple `192.168.1.10`)
   - **DNS secondaire** : `8.8.8.8` (Google DNS, en backup pour la résolution Internet)

```powershell
# Configurer le DNS sur SRV1 via PowerShell
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses "192.168.1.10","8.8.8.8"

# Vérifier la configuration
Get-DnsClientServerAddress -InterfaceAlias "Ethernet"
```

> **Bonne pratique** : le DNS secondaire `8.8.8.8` permet à SRV1 de continuer à résoudre les noms Internet même si DC1 est temporairement indisponible. En production, un second DC avec le rôle DNS est préférable.

### 5.2 Jonction au domaine

Une fois le DNS configuré :

1. Ouvrir **System Properties** (clic droit sur Ce PC > Propriétés > Paramètres système avancés)
2. Onglet **Computer Name** > cliquer sur **Change**
3. Sélectionner **Domain** et renseigner le nom du domaine (par exemple `jedha.local`)
4. Entrer les identifiants d'un compte ayant le droit de joindre des machines au domaine (par défaut, le compte Administrator du domaine)
5. Redémarrer SRV1

```powershell
# Joindre le domaine via PowerShell
Add-Computer -DomainName "jedha.local" -Credential (Get-Credential) -Restart
```

Après le redémarrage, SRV1 est désormais membre du domaine `jedha.local` et apparaît dans Active Directory sur DC1.

---

## 6. Workgroup vs Domain

### 6.1 Comparaison

| Critère | Workgroup | Domain |
|---|---|---|
| **Gestion** | Décentralisée, chaque machine est autonome | Centralisée via un Domain Controller |
| **Authentification** | Locale sur chaque machine (base SAM) | Centralisée via Active Directory (base ntds.dit) |
| **Taille du réseau** | Petits réseaux (< 10 machines) | Réseaux de toute taille (de 10 à plusieurs milliers) |
| **Administration** | Chaque machine est administrée individuellement | Administration unifiée depuis le DC |
| **Politiques de sécurité** | Locales uniquement | GPO déployées centralement |
| **Partage de ressources** | Partage simple entre machines | Permissions basées sur les comptes du domaine |

### 6.2 Workgroup

Dans un **Workgroup** (groupe de travail), chaque machine fonctionne de manière indépendante :

- Les comptes utilisateurs sont créés localement sur chaque poste
- Il n'y a pas de serveur central d'authentification
- Le partage de fichiers repose sur des permissions locales
- C'est la configuration par défaut de Windows

Ce mode est adapté aux très petits réseaux (domicile, TPE) où la simplicité prime sur la gestion centralisée.

### 6.3 Domain

Dans un **Domain** (domaine), la gestion est centralisée :

- Un ou plusieurs **Domain Controllers** hébergent Active Directory
- Les comptes utilisateurs sont créés dans l'annuaire AD et sont valides sur toutes les machines du domaine
- Les politiques de sécurité (GPO) sont appliquées uniformément
- Les permissions sont gérées de manière centralisée

Ce mode est indispensable dès que le réseau dépasse quelques machines ou que des exigences de sécurité et de conformité s'appliquent.

> **À noter** : lors d'un audit de sécurité, identifier si l'environnement est en Workgroup ou en Domain est l'une des premières étapes. Un environnement Workgroup dans une entreprise de taille moyenne est un signal d'alerte en termes de sécurité.

---

## Pour aller plus loin

- [Documentation officielle Microsoft - Active Directory Domain Services](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-domain-services-overview)
- [Documentation GNS3](https://docs.gns3.com/)
- [Windows Server 2022 - Nouveautés](https://learn.microsoft.com/en-us/windows-server/get-started/whats-new-in-windows-server-2022)
- [Guide d'installation AD DS étape par étape](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/deploy/install-active-directory-domain-services--level-100-)
