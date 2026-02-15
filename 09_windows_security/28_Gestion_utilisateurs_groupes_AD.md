# Gestion des utilisateurs et des groupes dans Active Directory

**Module** : créer et gérer les comptes utilisateurs et les groupes dans AD

---

## Objectifs du module

À l'issue de ce module, les compétences suivantes seront acquises :

- Distinguer les comptes de domaine des comptes locaux
- Connaître les attributs clés d'un compte utilisateur AD
- Maîtriser les types et portées des groupes AD
- Comprendre et appliquer le modèle AGDLP
- Créer des utilisateurs et des groupes via l'interface graphique et PowerShell
- Appliquer les bonnes pratiques de gestion des identités

---

## 1. Domain Users vs Local Users

### 1.1 Comparaison

| Critère | Domain User | Local User |
|---|---|---|
| **Authentification** | Par le Domain Controller | Par la machine locale |
| **Stockage** | Base de données Active Directory (`ntds.dit`) | Base de données locale SAM (`C:\Windows\System32\config\SAM`) |
| **Portée** | Accès aux ressources de tout le domaine | Accès uniquement aux ressources de la machine locale |
| **Gestion** | Centralisée depuis le DC | Individuelle sur chaque machine |
| **Politiques de mot de passe** | Définies par GPO au niveau du domaine | Définies localement sur chaque poste |

### 1.2 Fonctionnement

Lorsqu'un utilisateur se connecte à une machine jointe au domaine :

1. La machine transmet les identifiants au **Domain Controller**
2. Le DC vérifie les identifiants dans la base **ntds.dit**
3. Si l'authentification réussit, le DC délivre un **ticket Kerberos** (TGT)
4. L'utilisateur utilise ce ticket pour accéder aux ressources du domaine

Lorsqu'un utilisateur se connecte avec un compte local :

1. La machine vérifie les identifiants dans la base **SAM** locale
2. L'accès est limité aux ressources de cette machine uniquement

> **À noter** : même sur une machine jointe au domaine, il est possible de se connecter avec un compte local en préfixant le nom d'utilisateur avec `.\` (par exemple `.\Administrator`). C'est une technique utile en cas de panne du DC.

---

## 2. Attributs d'un compte utilisateur

### 2.1 Attributs principaux

Chaque objet utilisateur dans Active Directory possède de nombreux attributs. Les plus importants sont :

| Attribut | Description | Exemple |
|---|---|---|
| **sAMAccountName** | Nom de connexion pré-Windows 2000, unique dans le domaine | `jdupont` |
| **UserPrincipalName (UPN)** | Nom de connexion au format email, unique dans la forêt | `jdupont@jedha.local` |
| **CN (Common Name)** | Nom affiché de l'objet | `Jean Dupont` |
| **distinguishedName (DN)** | Chemin complet de l'objet dans l'annuaire LDAP | `CN=Jean Dupont,OU=Informatique,OU=Paris,DC=jedha,DC=local` |
| **MemberOf** | Liste des groupes dont l'utilisateur est membre | `CN=IT-Admins,OU=Groups,DC=jedha,DC=local` |

### 2.2 Consultation des attributs

```powershell
# Afficher tous les attributs d'un utilisateur
Get-ADUser -Identity "jdupont" -Properties *

# Afficher les attributs spécifiques
Get-ADUser -Identity "jdupont" -Properties sAMAccountName, UserPrincipalName, MemberOf, DistinguishedName |
    Select-Object sAMAccountName, UserPrincipalName, MemberOf, DistinguishedName

# Rechercher un utilisateur par UPN
Get-ADUser -Filter { UserPrincipalName -eq "jdupont@jedha.local" }
```

> **À noter** : le `distinguishedName` est l'identifiant unique d'un objet dans l'annuaire LDAP. Il est utilisé dans les scripts, les requêtes LDAP et les outils d'audit. Sa syntaxe suit la hiérarchie de l'arbre AD de l'objet vers la racine.

---

## 3. Types de groupes

### 3.1 Security Group vs Distribution Group

| Type | Fonction | Utilisation |
|---|---|---|
| **Security Group** | Attribution de permissions sur les ressources | Contrôle d'accès aux fichiers, dossiers, applications, GPO |
| **Distribution Group** | Listes de distribution email | Envoi de mails à un ensemble d'utilisateurs (Exchange, Microsoft 365) |

> **Bonne pratique** : en pratique, privilégiez toujours les **Security Groups**. Un Security Group peut être utilisé comme liste de distribution, mais l'inverse n'est pas vrai (un Distribution Group ne peut pas servir à attribuer des permissions).

### 3.2 Portées (Scopes)

La portée d'un groupe détermine où il peut être utilisé et quels membres il peut contenir :

| Portée | Membres possibles | Utilisation possible | Cas d'usage |
|---|---|---|---|
| **Domain Local** | Utilisateurs et groupes de n'importe quel domaine de la forêt | Uniquement dans le domaine où il est créé | Attribution de permissions sur les ressources locales |
| **Global** | Utilisateurs et groupes du même domaine uniquement | Dans n'importe quel domaine de la forêt | Regroupement d'utilisateurs par rôle ou fonction |
| **Universal** | Utilisateurs et groupes de n'importe quel domaine de la forêt | Dans n'importe quel domaine de la forêt | Environnements multi-domaines, groupes inter-domaines |

```powershell
# Lister les groupes par portée
Get-ADGroup -Filter { GroupScope -eq "Global" } | Select-Object Name
Get-ADGroup -Filter { GroupScope -eq "DomainLocal" } | Select-Object Name
Get-ADGroup -Filter { GroupScope -eq "Universal" } | Select-Object Name
```

---

## 4. Modèle AGDLP

### 4.1 Principe

Le modèle **AGDLP** est la méthode recommandée par Microsoft pour structurer les permissions dans Active Directory :

```
A   →   G   →   DL   →   P
Accounts    Global    Domain Local    Permissions
            Groups    Groups
```

1. **A (Accounts)** : les comptes utilisateurs sont placés dans...
2. **G (Global Groups)** : des groupes globaux qui représentent des rôles ou fonctions, qui sont eux-mêmes placés dans...
3. **DL (Domain Local Groups)** : des groupes de domaine local qui représentent les permissions sur une ressource, auxquels sont attribuées...
4. **P (Permissions)** : les autorisations effectives sur les ressources (fichiers, dossiers, etc.)

### 4.2 Exemple concret

Contexte : le service comptabilité doit avoir accès en lecture au dossier `\\SRV1\Factures`.

```
Utilisateurs: m.martin, p.leroy, s.garcia
        |
        v
Groupe Global: GG_Comptabilite
        |
        v
Groupe Domain Local: DL_Factures_Lecture
        |
        v
Permission: Lecture sur \\SRV1\Factures
```

```powershell
# 1. Créer le groupe global
New-ADGroup -Name "GG_Comptabilite" -GroupScope Global -GroupCategory Security -Path "OU=Groups,DC=jedha,DC=local"

# 2. Ajouter les utilisateurs au groupe global
Add-ADGroupMember -Identity "GG_Comptabilite" -Members "m.martin","p.leroy","s.garcia"

# 3. Créer le groupe domain local
New-ADGroup -Name "DL_Factures_Lecture" -GroupScope DomainLocal -GroupCategory Security -Path "OU=Groups,DC=jedha,DC=local"

# 4. Imbriquer le groupe global dans le groupe domain local
Add-ADGroupMember -Identity "DL_Factures_Lecture" -Members "GG_Comptabilite"

# 5. Attribuer les permissions NTFS au groupe domain local (sur le serveur de fichiers)
# Cela se fait via l'interface graphique ou icacls
```

> **Bonne pratique** : le modèle AGDLP peut sembler complexe au début, mais il simplifie énormément la gestion des permissions à grande échelle. Quand un nouvel employé arrive au service comptabilité, il suffit de l'ajouter au groupe `GG_Comptabilite` pour qu'il hérite automatiquement de toutes les permissions associées.

---

## 5. Création d'utilisateurs

### 5.1 Via l'interface graphique

1. Ouvrir **Active Directory Users and Computers** (dsa.msc)
2. Naviguer vers l'OU cible
3. Clic droit > **New > User**
4. Renseigner les champs : prénom, nom, nom de connexion (sAMAccountName et UPN)
5. Définir le mot de passe et les options (changement au prochain login, compte actif, etc.)

### 5.2 Via PowerShell

```powershell
# Créer un utilisateur simple
New-ADUser -Name "Jean Dupont" `
    -GivenName "Jean" `
    -Surname "Dupont" `
    -SamAccountName "jdupont" `
    -UserPrincipalName "jdupont@jedha.local" `
    -Path "OU=Informatique,OU=Paris,DC=jedha,DC=local" `
    -AccountPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) `
    -Enabled $true `
    -ChangePasswordAtLogon $true

# Créer plusieurs utilisateurs depuis un fichier CSV
Import-Csv "C:\Users\utilisateurs.csv" | ForEach-Object {
    New-ADUser -Name "$($_.Prenom) $($_.Nom)" `
        -GivenName $_.Prenom `
        -Surname $_.Nom `
        -SamAccountName $_.Login `
        -UserPrincipalName "$($_.Login)@jedha.local" `
        -Path $_.OU `
        -AccountPassword (ConvertTo-SecureString $_.MotDePasse -AsPlainText -Force) `
        -Enabled $true
}
```

---

## 6. Création de groupes

### 6.1 Via l'interface graphique

1. Ouvrir **Active Directory Users and Computers**
2. Naviguer vers l'OU cible
3. Clic droit > **New > Group**
4. Renseigner le nom, la portée (Global, Domain Local, Universal) et le type (Security, Distribution)

### 6.2 Via PowerShell

```powershell
# Créer un groupe de sécurité global
New-ADGroup -Name "GG_Developpeurs" `
    -GroupScope Global `
    -GroupCategory Security `
    -Path "OU=Groups,DC=jedha,DC=local" `
    -Description "Groupe global des développeurs"

# Ajouter des membres à un groupe
Add-ADGroupMember -Identity "GG_Developpeurs" -Members "jdupont","mmartin"

# Vérifier les membres d'un groupe
Get-ADGroupMember -Identity "GG_Developpeurs" | Select-Object Name, SamAccountName

# Retirer un membre d'un groupe
Remove-ADGroupMember -Identity "GG_Developpeurs" -Members "mmartin" -Confirm:$false
```

---

## 7. Bonnes pratiques

### 7.1 Gestion des groupes

| Pratique | Description |
|---|---|
| **Imbriquer les groupes** | Toujours imbriquer les groupes globaux dans les groupes domain local (modèle AGDLP) |
| **Jamais de permissions directes** | Ne jamais attribuer de permissions directement à un compte utilisateur |
| **Conventions de nommage** | Utiliser des préfixes cohérents : `GG_` (Global Group), `DL_` (Domain Local), `U_` (Universal) |
| **Éviter Domain Admins** | Ne pas utiliser le groupe Domain Admins sauf stricte nécessité. Créer des groupes délégués avec les permissions minimales requises |
| **Documenter** | Renseigner systématiquement le champ Description de chaque groupe |

### 7.2 Token bloat

Le **token bloat** est un problème qui survient lorsqu'un utilisateur est membre d'un trop grand nombre de groupes. Le token Kerberos (qui contient la liste de tous les groupes) dépasse alors la taille maximale autorisée, ce qui peut provoquer :

- Des échecs de connexion
- Des refus d'accès inexpliqués
- Des erreurs lors de l'ouverture de session

> **À noter** : par défaut, la taille maximale du token Kerberos est de 12 000 octets (environ 1 015 groupes). Ce seuil peut être augmenté via le registre, mais la bonne pratique est de limiter le nombre de groupes par utilisateur en rationalisant la structure des groupes.

### 7.3 Délégation

La délégation permet de confier l'administration de certaines tâches à des utilisateurs non-administrateurs du domaine :

- Déléguer le contrôle au niveau d'une **OU** (par exemple, permettre au service IT de réinitialiser les mots de passe des utilisateurs de leur OU)
- Utiliser des **groupes** pour définir qui a quel droit de délégation
- Appliquer le **principe du moindre privilège** : ne donner que les droits strictement nécessaires

```powershell
# Exemple : déléguer le droit de réinitialiser les mots de passe
# Se fait via l'assistant "Delegate Control" dans AD Users and Computers
# Clic droit sur l'OU > Delegate Control > sélectionner le groupe et les permissions
```

---

## 8. Partage de fichiers

### 8.1 Permissions NTFS dans un contexte AD

Le partage de fichiers dans un environnement AD repose sur les mêmes **permissions NTFS** que sur un système local, mais les identités sont celles du domaine :

| Permission | Description |
|---|---|
| **Full Control** | Contrôle total : lecture, écriture, modification, suppression, changement de permissions |
| **Modify** | Lecture, écriture, modification et suppression |
| **Read & Execute** | Lecture et exécution des fichiers |
| **Read** | Lecture seule |
| **Write** | Écriture (création et modification) |

Les permissions sont attribuées aux **groupes Domain Local** (dans le cadre du modèle AGDLP), jamais directement aux utilisateurs.

```powershell
# Afficher les permissions NTFS d'un dossier
Get-Acl "C:\Partages\Factures" | Format-List

# Afficher les permissions de partage
Get-SmbShareAccess -Name "Factures"
```

> **Bonne pratique** : lorsqu'un dossier est partagé sur le réseau, deux couches de permissions s'appliquent : les **permissions de partage** (Share Permissions) et les **permissions NTFS**. La permission effective est la plus restrictive des deux. La pratique recommandée est de définir les permissions de partage à "Full Control" pour le groupe concerné et de gérer la granularité via les permissions NTFS.

---

## Pour aller plus loin

- [Documentation Microsoft - AD DS Accounts](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-default-user-accounts)
- [Documentation Microsoft - AD Groups](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups)
- [Best Practices for AD Group Management](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory)
- [Understanding Kerberos Token Bloat](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/kerberos-authentication-problems-if-user-belongs-to-groups)
