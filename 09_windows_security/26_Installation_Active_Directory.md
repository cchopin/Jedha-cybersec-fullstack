# Installation d'Active Directory

**Module** : mise en place d'un environnement Active Directory avec GNS3

---

## Objectifs du module

A l'issue de ce module, les competences suivantes seront acquises :

- Comprendre ce qu'est Active Directory et pourquoi il est utilise en entreprise
- Mettre en place un environnement de lab avec GNS3
- Installer et configurer un Domain Controller sous Windows Server 2022
- Joindre un serveur membre au domaine
- Distinguer un Workgroup d'un Domain

---

## 1. Qu'est-ce qu'Active Directory ?

### 1.1 Definition

**Active Directory** (AD) est la solution Microsoft pour gerer un parc informatique a grande echelle. Il permet de centraliser la gestion des utilisateurs, des machines, des politiques de securite et des ressources reseau au sein d'une organisation.

Dans un environnement sans Active Directory, chaque machine est independante : les comptes utilisateurs, les permissions et les configurations sont geres localement sur chaque poste. Cela devient rapidement ingerable des que le nombre de machines augmente. Active Directory resout ce probleme en fournissant un annuaire centralise et un systeme d'authentification unique.

### 1.2 Cas d'usage en entreprise

| Fonction | Description |
|---|---|
| **Gestion centralisee des utilisateurs** | Creation, modification et suppression des comptes depuis un point unique |
| **Authentification unique (SSO)** | Un seul couple identifiant/mot de passe pour acceder a toutes les ressources |
| **Politiques de securite (GPO)** | Application uniforme des regles de securite sur l'ensemble du parc |
| **Gestion des permissions** | Controle granulaire de l'acces aux fichiers, dossiers et applications |
| **Deploiement logiciel** | Installation et mise a jour de logiciels a distance |

> **A noter** : Active Directory est present dans la quasi-totalite des entreprises utilisant un environnement Windows. Sa compromission est l'un des objectifs principaux des attaquants lors d'une intrusion reseau, ce qui en fait un sujet central en cybersecurite.

---

## 2. Mise en place du lab avec GNS3

### 2.1 Prerequis

Pour realiser les exercices de ce module, un environnement de lab est necessaire. L'infrastructure repose sur **GNS3**, un simulateur de reseaux qui permet de creer des topologies virtuelles complexes.

Les elements requis sont :

- Une connexion **VPN Jedha** active
- Le client **GNS3** installe sur votre machine locale

### 2.2 Connexion a la VM GNS3 distante

Le client GNS3 local doit etre connecte a la VM GNS3 distante hebergee sur l'infrastructure Jedha. Pour cela :

1. Lancer le client GNS3
2. Aller dans **Edit > Preferences > Server**
3. Configurer la connexion vers la VM distante en renseignant l'adresse IP fournie (par exemple `192.168.1.160`)
4. Verifier que la connexion est etablie (icone verte dans la barre de statut)

### 2.3 Topologie de base

La topologie du lab se compose des elements suivants :

```
+--------+      +----------+      +--------+
|  DC1   |------| Switch   |------|  SRV1  |
+--------+      +----------+      +--------+
                     |
                +----------+
                |  Cloud   |
                +----------+
```

| Machine | Role | Description |
|---|---|---|
| **DC1** | Domain Controller | Serveur principal hebergeant Active Directory |
| **SRV1** | Serveur membre | Serveur enfant joint au domaine |
| **Switch** | Commutateur | Interconnecte les machines du lab |
| **Cloud** | Acces externe | Fournit la connectivite reseau vers l'exterieur |

Les deux serveurs sont des machines **Windows Server 2022** connectees via un switch a un node Cloud pour l'acces reseau.

---

## 3. Windows Server 2022

### 3.1 Presentation

**Windows Server 2022** est le systeme d'exploitation serveur de Microsoft, concu pour la gestion de reseaux, le stockage, les applications et les services en entreprise. Contrairement a Windows 10 ou 11 qui sont destines aux postes de travail, Windows Server offre des fonctionnalites specifiques aux environnements professionnels.

### 3.2 Differences avec Windows 10/11

| Fonctionnalite | Windows 10/11 | Windows Server 2022 |
|---|---|---|
| **Active Directory** | Non disponible (peut uniquement joindre un domaine) | Installation et gestion complete d'AD |
| **DNS** | Client DNS uniquement | Serveur DNS complet |
| **DHCP** | Client DHCP uniquement | Serveur DHCP complet |
| **Hyper-V** | Version limitee | Version complete avec fonctionnalites avancees |
| **Roles serveur** | Non disponible | Roles et fonctionnalites installables (AD, DNS, DHCP, IIS, etc.) |
| **Connexions simultanees** | Limitees | Gestion multi-utilisateurs via Remote Desktop Services |
| **Interface** | Bureau complet avec applications grand public | Mode Desktop Experience ou Server Core (sans interface graphique) |

> **A noter** : Windows Server peut etre installe en mode **Server Core** (ligne de commande uniquement) ou en mode **Desktop Experience** (avec interface graphique). Le mode Server Core est recommande en production pour reduire la surface d'attaque.

---

## 4. Installation d'Active Directory sur DC1

### 4.1 Ajout du role AD DS

L'installation d'Active Directory se fait via le **Server Manager** de Windows Server :

1. Ouvrir **Server Manager**
2. Cliquer sur **Manage > Add Roles and Features**
3. Suivre l'assistant :
   - **Installation Type** : Role-based or feature-based installation
   - **Server Selection** : selectionner DC1
   - **Server Roles** : cocher **Active Directory Domain Services**
4. Cliquer sur **Add Features** lorsque les dependances sont proposees
5. Poursuivre l'assistant jusqu'a la fin et lancer l'installation

### 4.2 Promotion en Domain Controller

Une fois le role AD DS installe, le serveur doit etre **promu** en Domain Controller :

1. Dans Server Manager, cliquer sur le drapeau de notification (icone jaune)
2. Selectionner **Promote this server to a domain controller**
3. Choisir **Add a new forest** et renseigner le nom de domaine racine (par exemple `jedha.local`)
4. Configurer le mot de passe DSRM (Directory Services Restore Mode)
5. Valider les options DNS et NetBIOS
6. Lancer l'installation et redemarrer le serveur

Apres le redemarrage, DC1 est desormais le **Domain Controller** du domaine `jedha.local`.

```powershell
# Verifier que le role AD DS est bien installe
Get-WindowsFeature AD-Domain-Services

# Verifier le domaine
Get-ADDomain
```

---

## 5. Joindre SRV1 au domaine

### 5.1 Configuration reseau de SRV1

Avant de joindre SRV1 au domaine, sa configuration reseau doit etre adaptee. Le point essentiel est que le **DNS principal de SRV1 doit pointer vers l'adresse IP de DC1**, car c'est le Domain Controller qui heberge les enregistrements DNS du domaine.

1. Ouvrir les parametres reseau de SRV1
2. Configurer l'adresse IP de maniere statique
3. Renseigner les serveurs DNS :
   - **DNS principal** : adresse IP de DC1 (par exemple `192.168.1.10`)
   - **DNS secondaire** : `8.8.8.8` (Google DNS, en backup pour la resolution Internet)

```powershell
# Configurer le DNS sur SRV1 via PowerShell
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses "192.168.1.10","8.8.8.8"

# Verifier la configuration
Get-DnsClientServerAddress -InterfaceAlias "Ethernet"
```

> **Bonne pratique** : le DNS secondaire `8.8.8.8` permet a SRV1 de continuer a resoudre les noms Internet meme si DC1 est temporairement indisponible. En production, un second DC avec le role DNS est preferable.

### 5.2 Jonction au domaine

Une fois le DNS configure :

1. Ouvrir **System Properties** (clic droit sur Ce PC > Proprietes > Parametres systeme avances)
2. Onglet **Computer Name** > cliquer sur **Change**
3. Selectionner **Domain** et renseigner le nom du domaine (par exemple `jedha.local`)
4. Entrer les identifiants d'un compte ayant le droit de joindre des machines au domaine (par defaut, le compte Administrator du domaine)
5. Redemarrer SRV1

```powershell
# Joindre le domaine via PowerShell
Add-Computer -DomainName "jedha.local" -Credential (Get-Credential) -Restart
```

Apres le redemarrage, SRV1 est desormais membre du domaine `jedha.local` et apparait dans Active Directory sur DC1.

---

## 6. Workgroup vs Domain

### 6.1 Comparaison

| Critere | Workgroup | Domain |
|---|---|---|
| **Gestion** | Decentralisee, chaque machine est autonome | Centralisee via un Domain Controller |
| **Authentification** | Locale sur chaque machine (base SAM) | Centralisee via Active Directory (base ntds.dit) |
| **Taille du reseau** | Petits reseaux (< 10 machines) | Reseaux de toute taille (de 10 a plusieurs milliers) |
| **Administration** | Chaque machine est administree individuellement | Administration unifiee depuis le DC |
| **Politiques de securite** | Locales uniquement | GPO deployees centralement |
| **Partage de ressources** | Partage simple entre machines | Permissions basees sur les comptes du domaine |

### 6.2 Workgroup

Dans un **Workgroup** (groupe de travail), chaque machine fonctionne de maniere independante :

- Les comptes utilisateurs sont crees localement sur chaque poste
- Il n'y a pas de serveur central d'authentification
- Le partage de fichiers repose sur des permissions locales
- C'est la configuration par defaut de Windows

Ce mode est adapte aux tres petits reseaux (domicile, TPE) ou la simplicite prime sur la gestion centralisee.

### 6.3 Domain

Dans un **Domain** (domaine), la gestion est centralisee :

- Un ou plusieurs **Domain Controllers** hebergent Active Directory
- Les comptes utilisateurs sont crees dans l'annuaire AD et sont valides sur toutes les machines du domaine
- Les politiques de securite (GPO) sont appliquees uniformement
- Les permissions sont gerees de maniere centralisee

Ce mode est indispensable des que le reseau depasse quelques machines ou que des exigences de securite et de conformite s'appliquent.

> **A noter** : lors d'un audit de securite, identifier si l'environnement est en Workgroup ou en Domain est l'une des premieres etapes. Un environnement Workgroup dans une entreprise de taille moyenne est un signal d'alerte en termes de securite.

---

## Pour aller plus loin

- [Documentation officielle Microsoft - Active Directory Domain Services](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-domain-services-overview)
- [Documentation GNS3](https://docs.gns3.com/)
- [Windows Server 2022 - Nouveautes](https://learn.microsoft.com/en-us/windows-server/get-started/whats-new-in-windows-server-2022)
- [Guide d'installation AD DS etape par etape](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/deploy/install-active-directory-domain-services--level-100-)
