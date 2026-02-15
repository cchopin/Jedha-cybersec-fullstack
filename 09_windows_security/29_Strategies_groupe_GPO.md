# Stratégies de groupe et Group Policy Objects (GPO)

**Module** : configurer et déployer des GPO pour gérer centralement un parc Windows

---

## Objectifs du module

À l'issue de ce module, les compétences suivantes seront acquises :

- Comprendre le rôle et le fonctionnement des Group Policy Objects (GPO)
- Maîtriser la structure d'une GPO (User Configuration, Computer Configuration)
- Connaître l'ordre d'application des GPO (LSDOU)
- Créer, lier et diagnostiquer des GPO
- Connaître les GPO de sécurité les plus courantes
- Comprendre la différence entre GPO et Group Policy Preferences (GPP)

---

## 1. Qu'est-ce qu'une GPO ?

### 1.1 Définition

Une **Group Policy Object** (GPO) est un objet Active Directory qui contient un ensemble de paramètres de configuration. Les GPO permettent de gérer centralement les configurations des utilisateurs et des machines du domaine, d'appliquer des paramètres de sécurité et de déployer des logiciels.

Les GPO sont l'un des outils les plus puissants d'Active Directory pour les administrateurs système et l'un des mécanismes les plus importants à comprendre pour les professionnels de la cybersécurité.

### 1.2 Cas d'usage

| Usage | Exemple |
|---|---|
| **Sécurité** | Imposer une complexité minimale de mot de passe |
| **Configuration** | Définir un fond d'écran d'entreprise sur tous les postes |
| **Restriction** | Bloquer l'accès au panneau de configuration pour certains utilisateurs |
| **Déploiement** | Installer automatiquement un logiciel sur toutes les machines d'une OU |
| **Audit** | Activer la journalisation des tentatives de connexion |

---

## 2. Structure d'une GPO

### 2.1 Les deux sections

Chaque GPO est divisée en deux sections principales :

| Section | Cible | Exemples de paramètres |
|---|---|---|
| **Computer Configuration** | S'applique à la machine, quel que soit l'utilisateur connecté | Scripts de démarrage/arrêt, politiques de mot de passe, pare-feu, audit, services |
| **User Configuration** | S'applique à l'utilisateur, quelle que soit la machine utilisée | Bureau (fond d'écran, icônes), panneau de configuration, scripts de connexion/déconnexion, redirection de dossiers |

Chaque section contient trois sous-catégories :

- **Policies** : paramètres forcés, non modifiables par l'utilisateur
- **Preferences** : paramètres par défaut, modifiables par l'utilisateur (voir section 7)
- **Software Settings** : déploiement de logiciels

### 2.2 Stockage

Les GPO sont stockées à deux endroits :

| Composant | Emplacement | Contenu |
|---|---|---|
| **Group Policy Container (GPC)** | Dans Active Directory (base ntds.dit) | Attributs de la GPO, liens, permissions, versionning |
| **Group Policy Template (GPT)** | Dans le dossier **SYSVOL** (`\\domaine\SYSVOL\domaine\Policies\{GUID}`) | Fichiers de configuration effectifs (fichiers .pol, scripts, modèles ADMX) |

```powershell
# Lister les GPO du domaine
Get-GPO -All | Select-Object DisplayName, Id, CreationTime

# Afficher le contenu du dossier SYSVOL pour une GPO
Get-ChildItem "\\jedha.local\SYSVOL\jedha.local\Policies" -Recurse
```

> **À noter** : le dossier SYSVOL est répliqué entre tous les Domain Controllers. C'est un point d'attention en sécurité : un attaquant ayant accès à SYSVOL peut lire les GPO et potentiellement y trouver des informations sensibles (comme des mots de passe stockés dans les anciennes GPP).

---

## 3. Ordre d'application des GPO (LSDOU)

### 3.1 Principe

Lorsqu'un utilisateur se connecte ou qu'une machine démarre, les GPO sont appliquées dans un ordre précis connu sous l'acronyme **LSDOU** :

```
L → S → D → OU
Local   Site   Domain   Organizational Unit
```

1. **Local** : la politique locale de la machine (gpedit.msc)
2. **Site** : les GPO liées au site AD
3. **Domain** : les GPO liées au domaine
4. **OU** : les GPO liées aux OUs, de la plus haute à la plus basse dans la hiérarchie

### 3.2 Résolution des conflits

En cas de conflit entre deux GPO sur un même paramètre, **la dernière GPO appliquée gagne**. Puisque les GPO d'OU sont appliquées en dernier, elles ont la priorité la plus élevée.

| Priorité | Source | Exemple |
|---|---|---|
| 1 (la plus basse) | Local | Politique locale de la machine |
| 2 | Site | GPO du site "Paris" |
| 3 | Domain | GPO du domaine "jedha.local" |
| 4 (la plus haute) | OU | GPO de l'OU "Informatique" |

> **À noter** : deux mécanismes permettent de modifier ce comportement par défaut. Le flag **Enforced** (anciennement "No Override") sur une GPO de niveau supérieur force ses paramètres même si une GPO de niveau inférieur les contredit. Le flag **Block Inheritance** sur une OU empêche l'héritage des GPO parentes (sauf celles marquées Enforced).

---

## 4. Création et liaison d'une GPO

### 4.1 Console GPMC

La création et la gestion des GPO se font via la **GPMC** (Group Policy Management Console) :

1. Ouvrir **Group Policy Management** (`gpmc.msc`)
2. Naviguer vers **Forest > Domains > jedha.local**
3. Cliquer droit sur l'OU cible > **Create a GPO in this domain, and Link it here**
4. Nommer la GPO (par exemple "GPO_Wallpaper_Entreprise")
5. Cliquer droit sur la GPO > **Edit** pour configurer les paramètres

### 4.2 Exemple : définir un fond d'écran par défaut

1. Créer et lier une GPO à l'OU souhaitée
2. Éditer la GPO
3. Naviguer vers **User Configuration > Policies > Administrative Templates > Desktop > Desktop**
4. Activer le paramètre **Desktop Wallpaper**
5. Renseigner le chemin UNC de l'image (par exemple `\\SRV1\Partages\wallpaper.jpg`)
6. Choisir le style d'affichage (Fill, Fit, Stretch, etc.)

```powershell
# Créer une GPO via PowerShell
New-GPO -Name "GPO_Wallpaper_Entreprise" -Comment "Fond d'écran entreprise pour tous les utilisateurs"

# Lier la GPO à une OU
New-GPLink -Name "GPO_Wallpaper_Entreprise" -Target "OU=Paris,DC=jedha,DC=local"
```

---

## 5. Diagnostic des GPO

### 5.1 gpupdate

La commande `gpupdate` permet de forcer le rafraîchissement des GPO sur une machine sans attendre le prochain cycle automatique (par défaut toutes les 90 minutes, avec un décalage aléatoire de 0 à 30 minutes).

```powershell
# Forcer la mise à jour des GPO
gpupdate /force

# Forcer uniquement les GPO utilisateur
gpupdate /target:user /force

# Forcer uniquement les GPO machine
gpupdate /target:computer /force
```

### 5.2 gpresult

La commande `gpresult` affiche le jeu résultant de GPO appliquées à un utilisateur ou à une machine. C'est l'outil de diagnostic principal pour les GPO.

```powershell
# Afficher un résumé des GPO appliquées
gpresult /r

# Générer un rapport HTML détaillé
gpresult /h C:\rapport_gpo.html

# Afficher les GPO pour un utilisateur distant
gpresult /s SRV1 /user jedha\jdupont /r
```

### 5.3 Resultant Set of Policy (RSoP)

La console **RSoP** (`rsop.msc`) fournit une vue graphique de l'ensemble des paramètres de stratégie effectivement appliqués, en tenant compte de l'ordre LSDOU et des éventuels conflits.

```powershell
# Simuler l'application des GPO (mode planification)
Get-GPResultantSetOfPolicy -ReportType Html -Path "C:\rsop_report.html"
```

---

## 6. GPO de sécurité courantes

### 6.1 Politiques de mots de passe

| Paramètre | Chemin | Valeur recommandée |
|---|---|---|
| Longueur minimale | Computer Config > Policies > Windows Settings > Security Settings > Account Policies > Password Policy | 12 caractères minimum |
| Complexité | Même chemin | Active |
| Historique | Même chemin | 24 mots de passe mémorisés |
| Âge maximal | Même chemin | 90 jours (ou plus selon la politique) |

### 6.2 Verrouillage de compte

| Paramètre | Valeur recommandée |
|---|---|
| Seuil de verrouillage | 5 tentatives échouées |
| Durée de verrouillage | 30 minutes |
| Réinitialisation du compteur | 30 minutes |

### 6.3 Autres GPO courantes

| GPO | Description |
|---|---|
| **Restrictions logicielles** | Bloquer l'exécution de certains programmes (AppLocker, Software Restriction Policies) |
| **Pare-feu Windows** | Configurer les règles de pare-feu de manière centralisée |
| **Audit** | Activer la journalisation des évènements de sécurité (connexions, accès aux fichiers, modifications de permissions) |
| **Écran de veille** | Forcer le verrouillage automatique après une période d'inactivité |
| **Restriction USB** | Bloquer ou limiter l'utilisation de périphériques USB |

> **Bonne pratique** : appliquez le principe du **moindre privilège** dans vos GPO. Commencez par des paramètres restrictifs et ouvrez progressivement les accès si nécessaire, plutôt que l'inverse.

---

## 7. Group Policy Preferences (GPP)

### 7.1 Définition

Les **Group Policy Preferences** (GPP) sont une extension des GPO classiques. Contrairement aux GPO Policies (qui forcent un paramètre et empêchent l'utilisateur de le modifier), les GPP définissent un paramètre par défaut que l'utilisateur **peut modifier** par la suite.

### 7.2 Comparaison GPO Policies vs GPP

| Critère | GPO Policies | GPP (Preferences) |
|---|---|---|
| **Application** | Forcée | Initiale, modifiable par l'utilisateur |
| **Comportement à la suppression** | Le paramètre revient à sa valeur par défaut | Le paramètre reste en place |
| **Ciblage granulaire** | Par OU, site, domaine | **Item-level targeting** (voir ci-dessous) |
| **Indicateur visuel** | Paramètre grisé dans l'interface utilisateur | Pas d'indicateur |

### 7.3 Fonctionnalités des GPP

Les GPP permettent de configurer de nombreux éléments :

| Élément | Description |
|---|---|
| **Lecteurs réseau** | Mapper automatiquement des lecteurs réseau (ex: `H:` vers `\\SRV1\HomeDir`) |
| **Imprimantes** | Déployer des imprimantes réseau automatiquement |
| **Variables d'environnement** | Définir des variables d'environnement système ou utilisateur |
| **Tâches planifiées** | Créer des tâches planifiées sur les machines du domaine |
| **Clés de registre** | Modifier des clés de registre à distance |
| **Raccourcis** | Créer des raccourcis sur le bureau ou dans le menu Démarrer |

### 7.4 Item-level targeting

L'une des fonctionnalités les plus puissantes des GPP est le **ciblage au niveau de l'élément** (Item-level targeting). Il permet d'appliquer une préférence uniquement si certaines conditions sont remplies :

| Condition | Exemple |
|---|---|
| **Groupe de sécurité** | Appliquer uniquement aux membres du groupe "GG_Commerciaux" |
| **Plage IP** | Appliquer uniquement aux machines du sous-réseau 10.0.1.0/24 |
| **Système d'exploitation** | Appliquer uniquement aux machines Windows 11 |
| **Nom de la machine** | Appliquer uniquement aux machines dont le nom commence par "PC-PAR-" |
| **OU** | Appliquer uniquement aux objets d'une OU spécifique |
| **Variable d'environnement** | Appliquer si une variable d'environnement spécifique existe |

```
Exemple de configuration Item-level targeting :
1. Éditer la GPO > User Configuration > Preferences > Windows Settings > Drive Maps
2. Nouveau lecteur réseau > configurer le chemin et la lettre
3. Onglet "Common" > cocher "Item-level targeting" > cliquer "Targeting"
4. Ajouter les conditions (par exemple : Security Group = "GG_Commerciaux")
```

> **À noter** : historiquement, les GPP permettaient de stocker des mots de passe (par exemple pour des comptes de service locaux). Microsoft a corrigé cette vulnérabilité (MS14-025) en 2014, mais des mots de passe chiffrés avec une clé connue peuvent encore être présents dans d'anciens fichiers `Groups.xml` dans SYSVOL. C'est un vecteur d'attaque classique lors d'un pentest AD.

---

## Pour aller plus loin

- [Documentation Microsoft - Group Policy Overview](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh831791(v=ws.11))
- [Documentation Microsoft - Group Policy Preferences](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn581922(v=ws.11))
- [MS14-025 - Vulnerability in Group Policy Preferences](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2014/ms14-025)
- [MITRE ATT&CK - Group Policy Modification](https://attack.mitre.org/techniques/T1484/001/)
- [Audit des GPO avec PowerShell](https://learn.microsoft.com/en-us/powershell/module/grouppolicy/)
