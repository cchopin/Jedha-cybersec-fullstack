# Gestion des utilisateurs et des groupes dans Active Directory

**Module** : creer et gerer les comptes utilisateurs et les groupes dans AD

---

## Objectifs du module

A l'issue de ce module, les competences suivantes seront acquises :

- Distinguer les comptes de domaine des comptes locaux
- Connaitre les attributs cles d'un compte utilisateur AD
- Maitriser les types et portees des groupes AD
- Comprendre et appliquer le modele AGDLP
- Creer des utilisateurs et des groupes via l'interface graphique et PowerShell
- Appliquer les bonnes pratiques de gestion des identites

---

## 1. Domain Users vs Local Users

### 1.1 Comparaison

| Critere | Domain User | Local User |
|---|---|---|
| **Authentification** | Par le Domain Controller | Par la machine locale |
| **Stockage** | Base de donnees Active Directory (`ntds.dit`) | Base de donnees locale SAM (`C:\Windows\System32\config\SAM`) |
| **Portee** | Acces aux ressources de tout le domaine | Acces uniquement aux ressources de la machine locale |
| **Gestion** | Centralisee depuis le DC | Individuelle sur chaque machine |
| **Politiques de mot de passe** | Definies par GPO au niveau du domaine | Definies localement sur chaque poste |

### 1.2 Fonctionnement

Lorsqu'un utilisateur se connecte a une machine jointe au domaine :

1. La machine transmet les identifiants au **Domain Controller**
2. Le DC verifie les identifiants dans la base **ntds.dit**
3. Si l'authentification reussit, le DC delivre un **ticket Kerberos** (TGT)
4. L'utilisateur utilise ce ticket pour acceder aux ressources du domaine

Lorsqu'un utilisateur se connecte avec un compte local :

1. La machine verifie les identifiants dans la base **SAM** locale
2. L'acces est limite aux ressources de cette machine uniquement

> **A noter** : meme sur une machine jointe au domaine, il est possible de se connecter avec un compte local en prefixant le nom d'utilisateur avec `.\` (par exemple `.\Administrator`). C'est une technique utile en cas de panne du DC.

---

## 2. Attributs d'un compte utilisateur

### 2.1 Attributs principaux

Chaque objet utilisateur dans Active Directory possede de nombreux attributs. Les plus importants sont :

| Attribut | Description | Exemple |
|---|---|---|
| **sAMAccountName** | Nom de connexion pre-Windows 2000, unique dans le domaine | `jdupont` |
| **UserPrincipalName (UPN)** | Nom de connexion au format email, unique dans la foret | `jdupont@jedha.local` |
| **CN (Common Name)** | Nom affiche de l'objet | `Jean Dupont` |
| **distinguishedName (DN)** | Chemin complet de l'objet dans l'annuaire LDAP | `CN=Jean Dupont,OU=Informatique,OU=Paris,DC=jedha,DC=local` |
| **MemberOf** | Liste des groupes dont l'utilisateur est membre | `CN=IT-Admins,OU=Groups,DC=jedha,DC=local` |

### 2.2 Consultation des attributs

```powershell
# Afficher tous les attributs d'un utilisateur
Get-ADUser -Identity "jdupont" -Properties *

# Afficher les attributs specifiques
Get-ADUser -Identity "jdupont" -Properties sAMAccountName, UserPrincipalName, MemberOf, DistinguishedName |
    Select-Object sAMAccountName, UserPrincipalName, MemberOf, DistinguishedName

# Rechercher un utilisateur par UPN
Get-ADUser -Filter { UserPrincipalName -eq "jdupont@jedha.local" }
```

> **A noter** : le `distinguishedName` est l'identifiant unique d'un objet dans l'annuaire LDAP. Il est utilise dans les scripts, les requetes LDAP et les outils d'audit. Sa syntaxe suit la hierarchie de l'arbre AD de l'objet vers la racine.

---

## 3. Types de groupes

### 3.1 Security Group vs Distribution Group

| Type | Fonction | Utilisation |
|---|---|---|
| **Security Group** | Attribution de permissions sur les ressources | Controle d'acces aux fichiers, dossiers, applications, GPO |
| **Distribution Group** | Listes de distribution email | Envoi de mails a un ensemble d'utilisateurs (Exchange, Microsoft 365) |

> **Bonne pratique** : en pratique, privilegiez toujours les **Security Groups**. Un Security Group peut etre utilise comme liste de distribution, mais l'inverse n'est pas vrai (un Distribution Group ne peut pas servir a attribuer des permissions).

### 3.2 Portees (Scopes)

La portee d'un groupe determine ou il peut etre utilise et quels membres il peut contenir :

| Portee | Membres possibles | Utilisation possible | Cas d'usage |
|---|---|---|---|
| **Domain Local** | Utilisateurs et groupes de n'importe quel domaine de la foret | Uniquement dans le domaine ou il est cree | Attribution de permissions sur les ressources locales |
| **Global** | Utilisateurs et groupes du meme domaine uniquement | Dans n'importe quel domaine de la foret | Regroupement d'utilisateurs par role ou fonction |
| **Universal** | Utilisateurs et groupes de n'importe quel domaine de la foret | Dans n'importe quel domaine de la foret | Environnements multi-domaines, groupes inter-domaines |

```powershell
# Lister les groupes par portee
Get-ADGroup -Filter { GroupScope -eq "Global" } | Select-Object Name
Get-ADGroup -Filter { GroupScope -eq "DomainLocal" } | Select-Object Name
Get-ADGroup -Filter { GroupScope -eq "Universal" } | Select-Object Name
```

---

## 4. Modele AGDLP

### 4.1 Principe

Le modele **AGDLP** est la methode recommandee par Microsoft pour structurer les permissions dans Active Directory :

```
A   →   G   →   DL   →   P
Accounts    Global    Domain Local    Permissions
            Groups    Groups
```

1. **A (Accounts)** : les comptes utilisateurs sont places dans...
2. **G (Global Groups)** : des groupes globaux qui representent des roles ou fonctions, qui sont eux-memes places dans...
3. **DL (Domain Local Groups)** : des groupes de domaine local qui representent les permissions sur une ressource, auxquels sont attribuees...
4. **P (Permissions)** : les autorisations effectives sur les ressources (fichiers, dossiers, etc.)

### 4.2 Exemple concret

Contexte : le service comptabilite doit avoir acces en lecture au dossier `\\SRV1\Factures`.

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
# 1. Creer le groupe global
New-ADGroup -Name "GG_Comptabilite" -GroupScope Global -GroupCategory Security -Path "OU=Groups,DC=jedha,DC=local"

# 2. Ajouter les utilisateurs au groupe global
Add-ADGroupMember -Identity "GG_Comptabilite" -Members "m.martin","p.leroy","s.garcia"

# 3. Creer le groupe domain local
New-ADGroup -Name "DL_Factures_Lecture" -GroupScope DomainLocal -GroupCategory Security -Path "OU=Groups,DC=jedha,DC=local"

# 4. Imbriquer le groupe global dans le groupe domain local
Add-ADGroupMember -Identity "DL_Factures_Lecture" -Members "GG_Comptabilite"

# 5. Attribuer les permissions NTFS au groupe domain local (sur le serveur de fichiers)
# Cela se fait via l'interface graphique ou icacls
```

> **Bonne pratique** : le modele AGDLP peut sembler complexe au debut, mais il simplifie enormement la gestion des permissions a grande echelle. Quand un nouvel employe arrive au service comptabilite, il suffit de l'ajouter au groupe `GG_Comptabilite` pour qu'il herite automatiquement de toutes les permissions associees.

---

## 5. Creation d'utilisateurs

### 5.1 Via l'interface graphique

1. Ouvrir **Active Directory Users and Computers** (dsa.msc)
2. Naviguer vers l'OU cible
3. Clic droit > **New > User**
4. Renseigner les champs : prenom, nom, nom de connexion (sAMAccountName et UPN)
5. Definir le mot de passe et les options (changement au prochain login, compte actif, etc.)

### 5.2 Via PowerShell

```powershell
# Creer un utilisateur simple
New-ADUser -Name "Jean Dupont" `
    -GivenName "Jean" `
    -Surname "Dupont" `
    -SamAccountName "jdupont" `
    -UserPrincipalName "jdupont@jedha.local" `
    -Path "OU=Informatique,OU=Paris,DC=jedha,DC=local" `
    -AccountPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) `
    -Enabled $true `
    -ChangePasswordAtLogon $true

# Creer plusieurs utilisateurs depuis un fichier CSV
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

## 6. Creation de groupes

### 6.1 Via l'interface graphique

1. Ouvrir **Active Directory Users and Computers**
2. Naviguer vers l'OU cible
3. Clic droit > **New > Group**
4. Renseigner le nom, la portee (Global, Domain Local, Universal) et le type (Security, Distribution)

### 6.2 Via PowerShell

```powershell
# Creer un groupe de securite global
New-ADGroup -Name "GG_Developpeurs" `
    -GroupScope Global `
    -GroupCategory Security `
    -Path "OU=Groups,DC=jedha,DC=local" `
    -Description "Groupe global des developpeurs"

# Ajouter des membres a un groupe
Add-ADGroupMember -Identity "GG_Developpeurs" -Members "jdupont","mmartin"

# Verifier les membres d'un groupe
Get-ADGroupMember -Identity "GG_Developpeurs" | Select-Object Name, SamAccountName

# Retirer un membre d'un groupe
Remove-ADGroupMember -Identity "GG_Developpeurs" -Members "mmartin" -Confirm:$false
```

---

## 7. Bonnes pratiques

### 7.1 Gestion des groupes

| Pratique | Description |
|---|---|
| **Imbriquer les groupes** | Toujours imbriquer les groupes globaux dans les groupes domain local (modele AGDLP) |
| **Jamais de permissions directes** | Ne jamais attribuer de permissions directement a un compte utilisateur |
| **Conventions de nommage** | Utiliser des prefixes coherents : `GG_` (Global Group), `DL_` (Domain Local), `U_` (Universal) |
| **Eviter Domain Admins** | Ne pas utiliser le groupe Domain Admins sauf stricte necessite. Creer des groupes delegues avec les permissions minimales requises |
| **Documenter** | Renseigner systematiquement le champ Description de chaque groupe |

### 7.2 Token bloat

Le **token bloat** est un probleme qui survient lorsqu'un utilisateur est membre d'un trop grand nombre de groupes. Le token Kerberos (qui contient la liste de tous les groupes) depasse alors la taille maximale autorisee, ce qui peut provoquer :

- Des echecs de connexion
- Des refus d'acces inexpliques
- Des erreurs lors de l'ouverture de session

> **A noter** : par defaut, la taille maximale du token Kerberos est de 12 000 octets (environ 1 015 groupes). Ce seuil peut etre augmente via le registre, mais la bonne pratique est de limiter le nombre de groupes par utilisateur en rationalisant la structure des groupes.

### 7.3 Delegation

La delegation permet de confier l'administration de certaines taches a des utilisateurs non-administrateurs du domaine :

- Deleguer le controle au niveau d'une **OU** (par exemple, permettre au service IT de reinitialiser les mots de passe des utilisateurs de leur OU)
- Utiliser des **groupes** pour definir qui a quel droit de delegation
- Appliquer le **principe du moindre privilege** : ne donner que les droits strictement necessaires

```powershell
# Exemple : deleguer le droit de reinitialiser les mots de passe
# Se fait via l'assistant "Delegate Control" dans AD Users and Computers
# Clic droit sur l'OU > Delegate Control > selectionner le groupe et les permissions
```

---

## 8. Partage de fichiers

### 8.1 Permissions NTFS dans un contexte AD

Le partage de fichiers dans un environnement AD repose sur les memes **permissions NTFS** que sur un systeme local, mais les identites sont celles du domaine :

| Permission | Description |
|---|---|
| **Full Control** | Controle total : lecture, ecriture, modification, suppression, changement de permissions |
| **Modify** | Lecture, ecriture, modification et suppression |
| **Read & Execute** | Lecture et execution des fichiers |
| **Read** | Lecture seule |
| **Write** | Ecriture (creation et modification) |

Les permissions sont attribuees aux **groupes Domain Local** (dans le cadre du modele AGDLP), jamais directement aux utilisateurs.

```powershell
# Afficher les permissions NTFS d'un dossier
Get-Acl "C:\Partages\Factures" | Format-List

# Afficher les permissions de partage
Get-SmbShareAccess -Name "Factures"
```

> **Bonne pratique** : lorsqu'un dossier est partage sur le reseau, deux couches de permissions s'appliquent : les **permissions de partage** (Share Permissions) et les **permissions NTFS**. La permission effective est la plus restrictive des deux. La pratique recommandee est de definir les permissions de partage a "Full Control" pour le groupe concerne et de gerer la granularite via les permissions NTFS.

---

## Pour aller plus loin

- [Documentation Microsoft - AD DS Accounts](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-default-user-accounts)
- [Documentation Microsoft - AD Groups](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups)
- [Best Practices for AD Group Management](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory)
- [Understanding Kerberos Token Bloat](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/kerberos-authentication-problems-if-user-belongs-to-groups)
