# Strategies de groupe et Group Policy Objects (GPO)

**Module** : configurer et deployer des GPO pour gerer centralement un parc Windows

---

## Objectifs du module

A l'issue de ce module, les competences suivantes seront acquises :

- Comprendre le role et le fonctionnement des Group Policy Objects (GPO)
- Maitriser la structure d'une GPO (User Configuration, Computer Configuration)
- Connaitre l'ordre d'application des GPO (LSDOU)
- Creer, lier et diagnostiquer des GPO
- Connaitre les GPO de securite les plus courantes
- Comprendre la difference entre GPO et Group Policy Preferences (GPP)

---

## 1. Qu'est-ce qu'une GPO ?

### 1.1 Definition

Une **Group Policy Object** (GPO) est un objet Active Directory qui contient un ensemble de parametres de configuration. Les GPO permettent de gerer centralement les configurations des utilisateurs et des machines du domaine, d'appliquer des parametres de securite et de deployer des logiciels.

Les GPO sont l'un des outils les plus puissants d'Active Directory pour les administrateurs systeme et l'un des mecanismes les plus importants a comprendre pour les professionnels de la cybersecurite.

### 1.2 Cas d'usage

| Usage | Exemple |
|---|---|
| **Securite** | Imposer une complexite minimale de mot de passe |
| **Configuration** | Definir un fond d'ecran d'entreprise sur tous les postes |
| **Restriction** | Bloquer l'acces au panneau de configuration pour certains utilisateurs |
| **Deploiement** | Installer automatiquement un logiciel sur toutes les machines d'une OU |
| **Audit** | Activer la journalisation des tentatives de connexion |

---

## 2. Structure d'une GPO

### 2.1 Les deux sections

Chaque GPO est divisee en deux sections principales :

| Section | Cible | Exemples de parametres |
|---|---|---|
| **Computer Configuration** | S'applique a la machine, quel que soit l'utilisateur connecte | Scripts de demarrage/arret, politiques de mot de passe, pare-feu, audit, services |
| **User Configuration** | S'applique a l'utilisateur, quelle que soit la machine utilisee | Bureau (fond d'ecran, icones), panneau de configuration, scripts de connexion/deconnexion, redirection de dossiers |

Chaque section contient trois sous-categories :

- **Policies** : parametres forces, non modifiables par l'utilisateur
- **Preferences** : parametres par defaut, modifiables par l'utilisateur (voir section 7)
- **Software Settings** : deploiement de logiciels

### 2.2 Stockage

Les GPO sont stockees a deux endroits :

| Composant | Emplacement | Contenu |
|---|---|---|
| **Group Policy Container (GPC)** | Dans Active Directory (base ntds.dit) | Attributs de la GPO, liens, permissions, versionning |
| **Group Policy Template (GPT)** | Dans le dossier **SYSVOL** (`\\domaine\SYSVOL\domaine\Policies\{GUID}`) | Fichiers de configuration effectifs (fichiers .pol, scripts, modeles ADMX) |

```powershell
# Lister les GPO du domaine
Get-GPO -All | Select-Object DisplayName, Id, CreationTime

# Afficher le contenu du dossier SYSVOL pour une GPO
Get-ChildItem "\\jedha.local\SYSVOL\jedha.local\Policies" -Recurse
```

> **A noter** : le dossier SYSVOL est replique entre tous les Domain Controllers. C'est un point d'attention en securite : un attaquant ayant acces a SYSVOL peut lire les GPO et potentiellement y trouver des informations sensibles (comme des mots de passe stockes dans les anciennes GPP).

---

## 3. Ordre d'application des GPO (LSDOU)

### 3.1 Principe

Lorsqu'un utilisateur se connecte ou qu'une machine demarre, les GPO sont appliquees dans un ordre precis connu sous l'acronyme **LSDOU** :

```
L → S → D → OU
Local   Site   Domain   Organizational Unit
```

1. **Local** : la politique locale de la machine (gpedit.msc)
2. **Site** : les GPO liees au site AD
3. **Domain** : les GPO liees au domaine
4. **OU** : les GPO liees aux OUs, de la plus haute a la plus basse dans la hierarchie

### 3.2 Resolution des conflits

En cas de conflit entre deux GPO sur un meme parametre, **la derniere GPO appliquee gagne**. Puisque les GPO d'OU sont appliquees en dernier, elles ont la priorite la plus elevee.

| Priorite | Source | Exemple |
|---|---|---|
| 1 (la plus basse) | Local | Politique locale de la machine |
| 2 | Site | GPO du site "Paris" |
| 3 | Domain | GPO du domaine "jedha.local" |
| 4 (la plus haute) | OU | GPO de l'OU "Informatique" |

> **A noter** : deux mecanismes permettent de modifier ce comportement par defaut. Le flag **Enforced** (anciennement "No Override") sur une GPO de niveau superieur force ses parametres meme si une GPO de niveau inferieur les contredit. Le flag **Block Inheritance** sur une OU empeche l'heritage des GPO parentes (sauf celles marquees Enforced).

---

## 4. Creation et liaison d'une GPO

### 4.1 Console GPMC

La creation et la gestion des GPO se font via la **GPMC** (Group Policy Management Console) :

1. Ouvrir **Group Policy Management** (`gpmc.msc`)
2. Naviguer vers **Forest > Domains > jedha.local**
3. Cliquer droit sur l'OU cible > **Create a GPO in this domain, and Link it here**
4. Nommer la GPO (par exemple "GPO_Wallpaper_Entreprise")
5. Cliquer droit sur la GPO > **Edit** pour configurer les parametres

### 4.2 Exemple : definir un fond d'ecran par defaut

1. Creer et lier une GPO a l'OU souhaitee
2. Editer la GPO
3. Naviguer vers **User Configuration > Policies > Administrative Templates > Desktop > Desktop**
4. Activer le parametre **Desktop Wallpaper**
5. Renseigner le chemin UNC de l'image (par exemple `\\SRV1\Partages\wallpaper.jpg`)
6. Choisir le style d'affichage (Fill, Fit, Stretch, etc.)

```powershell
# Creer une GPO via PowerShell
New-GPO -Name "GPO_Wallpaper_Entreprise" -Comment "Fond d'ecran entreprise pour tous les utilisateurs"

# Lier la GPO a une OU
New-GPLink -Name "GPO_Wallpaper_Entreprise" -Target "OU=Paris,DC=jedha,DC=local"
```

---

## 5. Diagnostic des GPO

### 5.1 gpupdate

La commande `gpupdate` permet de forcer le rafraichissement des GPO sur une machine sans attendre le prochain cycle automatique (par defaut toutes les 90 minutes, avec un decalage aleatoire de 0 a 30 minutes).

```powershell
# Forcer la mise a jour des GPO
gpupdate /force

# Forcer uniquement les GPO utilisateur
gpupdate /target:user /force

# Forcer uniquement les GPO machine
gpupdate /target:computer /force
```

### 5.2 gpresult

La commande `gpresult` affiche le jeu resultant de GPO appliquees a un utilisateur ou a une machine. C'est l'outil de diagnostic principal pour les GPO.

```powershell
# Afficher un resume des GPO appliquees
gpresult /r

# Generer un rapport HTML detaille
gpresult /h C:\rapport_gpo.html

# Afficher les GPO pour un utilisateur distant
gpresult /s SRV1 /user jedha\jdupont /r
```

### 5.3 Resultant Set of Policy (RSoP)

La console **RSoP** (`rsop.msc`) fournit une vue graphique de l'ensemble des parametres de strategie effectivement appliques, en tenant compte de l'ordre LSDOU et des eventuels conflits.

```powershell
# Simuler l'application des GPO (mode planification)
Get-GPResultantSetOfPolicy -ReportType Html -Path "C:\rsop_report.html"
```

---

## 6. GPO de securite courantes

### 6.1 Politiques de mots de passe

| Parametre | Chemin | Valeur recommandee |
|---|---|---|
| Longueur minimale | Computer Config > Policies > Windows Settings > Security Settings > Account Policies > Password Policy | 12 caracteres minimum |
| Complexite | Meme chemin | Active |
| Historique | Meme chemin | 24 mots de passe memorises |
| Age maximal | Meme chemin | 90 jours (ou plus selon la politique) |

### 6.2 Verrouillage de compte

| Parametre | Valeur recommandee |
|---|---|
| Seuil de verrouillage | 5 tentatives echouees |
| Duree de verrouillage | 30 minutes |
| Reinitialisation du compteur | 30 minutes |

### 6.3 Autres GPO courantes

| GPO | Description |
|---|---|
| **Restrictions logicielles** | Bloquer l'execution de certains programmes (AppLocker, Software Restriction Policies) |
| **Pare-feu Windows** | Configurer les regles de pare-feu de maniere centralisee |
| **Audit** | Activer la journalisation des evenements de securite (connexions, acces aux fichiers, modifications de permissions) |
| **Ecran de veille** | Forcer le verrouillage automatique apres une periode d'inactivite |
| **Restriction USB** | Bloquer ou limiter l'utilisation de peripheriques USB |

> **Bonne pratique** : appliquez le principe du **moindre privilege** dans vos GPO. Commencez par des parametres restrictifs et ouvrez progressivement les acces si necessaire, plutot que l'inverse.

---

## 7. Group Policy Preferences (GPP)

### 7.1 Definition

Les **Group Policy Preferences** (GPP) sont une extension des GPO classiques. Contrairement aux GPO Policies (qui forcent un parametre et empechent l'utilisateur de le modifier), les GPP definissent un parametre par defaut que l'utilisateur **peut modifier** par la suite.

### 7.2 Comparaison GPO Policies vs GPP

| Critere | GPO Policies | GPP (Preferences) |
|---|---|---|
| **Application** | Forcee | Initiale, modifiable par l'utilisateur |
| **Comportement a la suppression** | Le parametre revient a sa valeur par defaut | Le parametre reste en place |
| **Ciblage granulaire** | Par OU, site, domaine | **Item-level targeting** (voir ci-dessous) |
| **Indicateur visuel** | Parametre grise dans l'interface utilisateur | Pas d'indicateur |

### 7.3 Fonctionnalites des GPP

Les GPP permettent de configurer de nombreux elements :

| Element | Description |
|---|---|
| **Lecteurs reseau** | Mapper automatiquement des lecteurs reseau (ex: `H:` vers `\\SRV1\HomeDir`) |
| **Imprimantes** | Deployer des imprimantes reseau automatiquement |
| **Variables d'environnement** | Definir des variables d'environnement systeme ou utilisateur |
| **Taches planifiees** | Creer des taches planifiees sur les machines du domaine |
| **Cles de registre** | Modifier des cles de registre a distance |
| **Raccourcis** | Creer des raccourcis sur le bureau ou dans le menu Demarrer |

### 7.4 Item-level targeting

L'une des fonctionnalites les plus puissantes des GPP est le **ciblage au niveau de l'element** (Item-level targeting). Il permet d'appliquer un preference uniquement si certaines conditions sont remplies :

| Condition | Exemple |
|---|---|
| **Groupe de securite** | Appliquer uniquement aux membres du groupe "GG_Commerciaux" |
| **Plage IP** | Appliquer uniquement aux machines du sous-reseau 10.0.1.0/24 |
| **Systeme d'exploitation** | Appliquer uniquement aux machines Windows 11 |
| **Nom de la machine** | Appliquer uniquement aux machines dont le nom commence par "PC-PAR-" |
| **OU** | Appliquer uniquement aux objets d'une OU specifique |
| **Variable d'environnement** | Appliquer si une variable d'environnement specifique existe |

```
Exemple de configuration Item-level targeting :
1. Editer la GPO > User Configuration > Preferences > Windows Settings > Drive Maps
2. Nouveau lecteur reseau > configurer le chemin et la lettre
3. Onglet "Common" > cocher "Item-level targeting" > cliquer "Targeting"
4. Ajouter les conditions (par exemple : Security Group = "GG_Commerciaux")
```

> **A noter** : historiquement, les GPP permettaient de stocker des mots de passe (par exemple pour des comptes de service locaux). Microsoft a corrige cette vulnerabilite (MS14-025) en 2014, mais des mots de passe chiffres avec une cle connue peuvent encore etre presents dans d'anciens fichiers `Groups.xml` dans SYSVOL. C'est un vecteur d'attaque classique lors d'un pentest AD.

---

## Pour aller plus loin

- [Documentation Microsoft - Group Policy Overview](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh831791(v=ws.11))
- [Documentation Microsoft - Group Policy Preferences](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn581922(v=ws.11))
- [MS14-025 - Vulnerability in Group Policy Preferences](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2014/ms14-025)
- [MITRE ATT&CK - Group Policy Modification](https://attack.mitre.org/techniques/T1484/001/)
- [Audit des GPO avec PowerShell](https://learn.microsoft.com/en-us/powershell/module/grouppolicy/)
