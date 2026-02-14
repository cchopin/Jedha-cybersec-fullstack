# Erreurs de configuration Active Directory

**Module** : misconfigurations courantes et leurs consequences en securite

---

## Objectifs du module

A l'issue de ce module, les competences suivantes seront acquises :

- Identifier les erreurs de configuration les plus courantes dans Active Directory
- Comprendre les risques lies aux privileges excessifs et au group nesting
- Maitriser les trois types de delegation Kerberos et leurs implications de securite
- Connaitre les abus d'ACL, d'AdminSDHolder et de GPO
- Comprendre les risques lies aux droits de replication (DCSync)
- Identifier les problemes lies aux SPN et aux comptes de service

---

## 1. Qu'est-ce qu'une misconfiguration ?

Une **misconfiguration** (erreur de configuration) est un parametrage incorrect, faible ou incomplet d'un composant Active Directory qui cree une vulnerabilite exploitable par un attaquant. Contrairement aux vulnerabilites logicielles qui necessitent un correctif de l'editeur, les misconfigurations relevent de la responsabilite de l'administrateur.

Les misconfigurations sont la cause principale des compromissions AD dans les entreprises. Elles sont souvent le resultat de :

- Configurations par defaut jamais renforcees
- Acces temporaires jamais revoques
- Meconnaissance des implications de securite de certains parametres
- Accumulation de dette technique au fil du temps

> **A noter** : un audit regulier de la configuration AD est indispensable. Des outils comme PingCastle ou BloodHound permettent d'identifier automatiquement la plupart de ces problemes.

---

## 2. Utilisateurs sur-privilegies

### 2.1 Le probleme

L'une des erreurs les plus frequentes est l'accumulation de privileges sur des comptes utilisateurs. Ce phenomene se produit typiquement lorsqu'un acces temporaire est accorde pour une tache specifique puis jamais revoque.

### 2.2 Exemple concret

L'utilisateur **jarjar** a ete temporairement ajoute avec des droits d'ecriture (Write Access) sur le groupe **Domain Admins** pour une operation de maintenance. Plusieurs mois plus tard, ce droit est toujours en place.

Consequence : un attaquant qui compromet le compte de jarjar peut s'ajouter lui-meme au groupe Domain Admins et prendre le controle complet du domaine.

```powershell
# Verifier les ACL sur le groupe Domain Admins
(Get-Acl "AD:\CN=Domain Admins,CN=Users,DC=corp,DC=local").Access |
    Where-Object { $_.ActiveDirectoryRights -match "Write" } |
    Format-Table IdentityReference, ActiveDirectoryRights
```

### 2.3 Remediations

| Action | Detail |
|---|---|
| **Revue reguliere des privileges** | Auditer les ACL sur les groupes privilegies au minimum chaque trimestre |
| **Acces temporaires** | Utiliser des groupes temporaires avec expiration automatique (PAM, JIT Access) |
| **Principe du moindre privilege** | Ne jamais accorder plus de droits que necessaire pour la tache |
| **Comptes dedies** | Utiliser des comptes d'administration separes (tiering model) |

---

## 3. Group Nesting dangereux

### 3.1 Le probleme

Active Directory permet d'imbriquer des groupes les uns dans les autres (**group nesting**). Les privileges se propagent de maniere transitive : si le groupe A est membre du groupe B, et le groupe B est membre du groupe C, alors tous les membres du groupe A heritent des privileges du groupe C.

Cette transitivite peut creer des **chemins d'escalade de privileges caches** que les administrateurs ne voient pas dans l'interface graphique standard.

### 3.2 Exemple concret

L'utilisateur **C3PO** est membre du groupe **Help Desk Level 1**. La chaine de nesting suivante existe dans l'annuaire :

```
C3PO
  └── Help Desk Level 1
        └── Help Desk Level 2
              └── Help Desk Level 3
                    └── Operations
                          └── Domain Admins
```

Resultat : C3PO est **Domain Admin** sans que cela soit visible au premier coup d'oeil. Un administrateur qui examine les membres directs du groupe Domain Admins ne verra pas C3PO.

### 3.3 Detection

```powershell
# Lister les membres recursifs du groupe Domain Admins
Get-ADGroupMember -Identity "Domain Admins" -Recursive |
    Select-Object Name, ObjectClass, DistinguishedName

# Comparer avec les membres directs
Get-ADGroupMember -Identity "Domain Admins" |
    Select-Object Name, ObjectClass, DistinguishedName
```

Si le nombre de membres recursifs est significativement superieur au nombre de membres directs, des chaines de nesting existent et doivent etre examinees.

> **Bonne pratique** : limiter le nesting a un maximum de deux niveaux et documenter chaque imbrication. Utiliser BloodHound pour visualiser graphiquement les chemins de nesting vers les groupes privilegies.

---

## 4. Delegation Kerberos

### 4.1 Principe

La **delegation Kerberos** permet a un service d'agir au nom d'un utilisateur aupres d'autres services. C'est un mecanisme legitime dans les architectures multi-tiers (par exemple, un serveur web frontal qui accede a une base de donnees au nom de l'utilisateur connecte).

Cependant, une delegation mal configuree constitue un vecteur d'attaque majeur.

### 4.2 Les trois types de delegation

| Type | Niveau de risque | Configuration | Description |
|---|---|---|---|
| **Unconstrained Delegation** | Tres eleve | GUI (proprietes du compte) | Le service peut utiliser le ticket de l'utilisateur pour acceder a **n'importe quel** autre service |
| **Constrained Delegation** | Modere | GUI (proprietes du compte) | Le service ne peut deleguer qu'a une **liste definie** de services (SPN) |
| **Resource-Based Constrained Delegation (RBCD)** | Modere | PowerShell uniquement | La delegation est definie **cote service cible** plutot que cote service source |

### 4.3 Unconstrained Delegation

Lorsqu'un serveur est configure en Unconstrained Delegation, tout utilisateur qui s'authentifie aupres de ce serveur lui transmet son **TGT complet**. Le serveur stocke ce TGT en memoire et peut l'utiliser pour s'authentifier aupres de n'importe quel service en tant que cet utilisateur.

```
Utilisateur ──── TGT ────> Serveur (Unconstrained)
                           Le serveur stocke le TGT en memoire
                           et peut acceder a tout service en tant que l'utilisateur
```

Risque : si le serveur en Unconstrained Delegation est compromis, l'attaquant recupere les TGT de tous les utilisateurs qui s'y sont authentifies et peut usurper leur identite.

> **A noter** : les Domain Controllers sont toujours en Unconstrained Delegation. C'est un comportement normal et attendu. Le risque concerne les serveurs membres configures avec cette option.

Pour identifier les machines en Unconstrained Delegation :

```powershell
Get-ADComputer -Filter { TrustedForDelegation -eq $true } -Properties TrustedForDelegation |
    Select-Object Name, TrustedForDelegation
```

### 4.4 Constrained Delegation

La Constrained Delegation limite les services vers lesquels la delegation est autorisee. Le serveur ne peut deleguer que vers les SPN specifies dans l'attribut `msDS-AllowedToDelegateTo`.

```powershell
# Identifier les comptes avec Constrained Delegation
Get-ADObject -Filter { msDS-AllowedToDelegateTo -like "*" } -Properties msDS-AllowedToDelegateTo |
    Select-Object Name, msDS-AllowedToDelegateTo
```

Bien que plus sure que l'Unconstrained Delegation, elle reste abusable si un attaquant compromet le compte de service delegue.

### 4.5 Resource-Based Constrained Delegation (RBCD)

La RBCD inverse la logique : c'est le **service cible** qui definit quels comptes sont autorises a deleguer vers lui, via l'attribut `msDS-AllowedToActOnBehalfOfOtherIdentity`.

```powershell
# Configurer la RBCD (PowerShell requis)
Set-ADComputer -Identity "ServeurCible" `
    -PrincipalsAllowedToDelegateToAccount (Get-ADComputer "ServeurSource")

# Verifier la configuration RBCD
Get-ADComputer "ServeurCible" -Properties msDS-AllowedToActOnBehalfOfOtherIdentity |
    Select-Object -ExpandProperty msDS-AllowedToActOnBehalfOfOtherIdentity
```

Risque : un attaquant qui possede le droit d'ecriture sur l'attribut `msDS-AllowedToActOnBehalfOfOtherIdentity` d'une machine peut configurer la RBCD pour s'y deleguer lui-meme.

---

## 5. Abus d'ACL (Access Control Lists)

### 5.1 Le probleme

Les objets Active Directory (utilisateurs, groupes, OUs, GPOs) sont proteges par des ACL. Certains droits sont particulierement dangereux lorsqu'ils sont accordes a des comptes non privilegies.

### 5.2 Droits dangereux

| Droit | Description | Exploitation possible |
|---|---|---|
| **GenericAll** | Controle total sur l'objet | Modification du mot de passe, ajout au groupe, modification de n'importe quel attribut |
| **GenericWrite** | Ecriture sur tous les attributs | Modification du SPN (Kerberoasting cible), modification du script de logon |
| **WriteOwner** | Modification du proprietaire de l'objet | L'attaquant se definit comme proprietaire puis modifie la DACL |
| **WriteDACL** | Modification de la DACL de l'objet | L'attaquant s'accorde GenericAll puis exploite l'objet |
| **ForceChangePassword** | Reinitialisation du mot de passe sans connaitre l'ancien | Prise de controle directe du compte cible |
| **AddMember** | Ajout de membres a un groupe | Ajout de l'attaquant dans un groupe privilege |

### 5.3 Detection

```powershell
# Examiner les ACL d'un objet AD
(Get-Acl "AD:\CN=Domain Admins,CN=Users,DC=corp,DC=local").Access |
    Format-Table IdentityReference, ActiveDirectoryRights, AccessControlType
```

> **Bonne pratique** : utiliser BloodHound pour cartographier les chemins d'attaque bases sur les ACL. Auditer regulierement les ACL des objets critiques (groupes privilegies, AdminSDHolder, OUs contenant les DCs).

---

## 6. AdminSDHolder

### 6.1 Mecanisme

**AdminSDHolder** est un objet conteneur special situe dans le conteneur System du domaine :

```
CN=AdminSDHolder,CN=System,DC=corp,DC=local
```

Toutes les **60 minutes**, le processus **SDProp** (SD Propagator) copie l'ACL de l'objet AdminSDHolder sur tous les objets consideres comme privilegies (membres de Domain Admins, Enterprise Admins, Schema Admins, Account Operators, etc.).

Ce mecanisme est concu pour proteger les comptes privilegies en ecrasant toute modification non autorisee de leurs ACL.

### 6.2 Risque de backdoor

Si un attaquant parvient a modifier l'ACL de l'objet AdminSDHolder, cette modification sera **automatiquement propagee** toutes les 60 minutes sur tous les comptes privilegies du domaine.

Exemple : un attaquant ajoute un droit GenericAll pour le compte `attacker` sur AdminSDHolder. Dans les 60 minutes suivantes, le compte `attacker` disposera de GenericAll sur tous les comptes Domain Admins.

```powershell
# Verifier l'ACL de AdminSDHolder
(Get-Acl "AD:\CN=AdminSDHolder,CN=System,DC=corp,DC=local").Access |
    Where-Object { $_.IdentityReference -notmatch "BUILTIN|NT AUTHORITY|S-1-5-32" } |
    Format-Table IdentityReference, ActiveDirectoryRights
```

> **Bonne pratique** : surveiller les modifications sur l'objet AdminSDHolder via les journaux d'audit (Event ID 5136 -- Directory Service Changes).

---

## 7. GPO et SYSVOL

### 7.1 Risques lies aux GPO

Les **Group Policy Objects** (GPO) sont un vecteur d'attaque sous-estime. Plusieurs scenarios de misconfiguration existent :

| Misconfiguration | Risque |
|---|---|
| **Scripts malveillants dans les GPO de demarrage** | Execution de code sur toutes les machines ciblees par la GPO |
| **Permissions faibles sur les GPO** | Un attaquant modifie une GPO pour executer du code ou modifier des parametres |
| **GPO trop permissives** | Desactivation de protections de securite (UAC, Windows Defender, pare-feu) |
| **Preferences de GPO avec mots de passe** | Mots de passe chiffres avec une cle publique connue (MS14-025) |

### 7.2 Permissions SYSVOL

Le partage **SYSVOL** (`\\domain\SYSVOL`) contient les scripts de logon et les fichiers de politique. Les permissions par defaut permettent a tout utilisateur authentifie de lire le contenu.

```powershell
# Verifier les permissions sur SYSVOL
Get-Acl "\\corp.local\SYSVOL\corp.local\Policies" | Format-List

# Lister les GPO du domaine et leurs permissions
Get-GPO -All | ForEach-Object {
    $gpo = $_
    $gpo.GetSecurityInfo() | Where-Object { $_.Permission -match "Edit|Full" } |
        Select-Object @{N='GPO';E={$gpo.DisplayName}}, Trustee, Permission
}
```

> **Bonne pratique** : restreindre les droits de modification des GPO aux seuls administrateurs habilites. Auditer regulierement le contenu de SYSVOL pour detecter des scripts ou fichiers suspects.

---

## 8. Replication et attaque DCSync

### 8.1 Les droits de replication

Dans Active Directory, la replication entre Domain Controllers utilise le protocole **DRS** (Directory Replication Service). Les droits suivants controlent l'acces a ce mecanisme :

| Droit | Description |
|---|---|
| **Replicating Directory Changes** | Permet de repliquer les donnees de l'annuaire (hors donnees sensibles) |
| **Replicating Directory Changes All** | Permet de repliquer **toutes** les donnees, y compris les hashes de mots de passe |

Ces deux droits combines permettent d'extraire l'integralite de la base de mots de passe du domaine.

### 8.2 Comptes autorises par defaut

Par defaut, seuls les comptes suivants possedent ces droits :

- **Domain Controllers** (groupe)
- **Domain Admins** (groupe)
- **Enterprise Admins** (groupe)
- **SYSTEM** (compte local)

### 8.3 Attaque DCSync

Si un attaquant compromet un compte possedant les droits de replication, il peut effectuer une attaque **DCSync** :

```
1. L'attaquant utilise un outil comme Mimikatz ou Impacket
2. L'outil simule un Domain Controller et envoie une requete de replication (DRSGetNCChanges)
3. Le vrai DC repond en envoyant les hashes de mots de passe demandes
4. L'attaquant obtient les NT hashes de tous les comptes du domaine
```

```
Attaquant (avec droits de replication)
    |
    ├── "Je suis un DC, j'ai besoin de repliquer"
    |        |
    |        v
    |   Domain Controller
    |        |
    |        v
    └── Recoit tous les NT hashes (dont krbtgt, Administrator, etc.)
```

La detection repose sur la surveillance des requetes de replication provenant de machines qui ne sont pas des Domain Controllers.

```powershell
# Identifier les comptes avec droits de replication
(Get-Acl "AD:\DC=corp,DC=local").Access |
    Where-Object {
        $_.ObjectType -eq "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" -or  # Replicating Directory Changes All
        $_.ObjectType -eq "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"      # Replicating Directory Changes
    } | Format-Table IdentityReference, ActiveDirectoryRights
```

> **Bonne pratique** : verifier regulierement que seuls les Domain Controllers et les comptes d'administration legitimes possedent les droits de replication. Toute delegation de ces droits a un compte de service ou un utilisateur doit etre consideree comme un risque critique.

---

## 9. SPN et comptes de service

### 9.1 Le probleme des SPN sur les comptes utilisateurs

Un **SPN** (Service Principal Name) doit idealement etre lie a un **compte de service manage** (gMSA) ou a un **compte machine**. Lorsqu'un SPN est associe a un compte utilisateur standard, ce compte devient vulnerable a l'attaque **Kerberoasting**.

Le principe du Kerberoasting :

```
1. L'attaquant demande un Service Ticket (TGS) pour le SPN cible
2. Le KDC delivre un Service Ticket chiffre avec le hash du compte de service
3. L'attaquant effectue un brute-force hors ligne sur le Service Ticket
4. Si le mot de passe est faible, l'attaquant recupere le mot de passe en clair
```

### 9.2 Comptes de service avec privileges excessifs

Un autre probleme courant est l'attribution de privileges excessifs aux comptes de service :

| Probleme | Exemple | Risque |
|---|---|---|
| Service account membre de Domain Admins | `svc_backup` dans Domain Admins | Compromission du compte = compromission du domaine |
| Mot de passe faible sur un service account | `svc_sql` avec le mot de passe `Password1` | Kerberoasting trivial |
| Mot de passe jamais change | `svc_web` avec le meme mot de passe depuis 5 ans | Augmente la fenetre d'exploitation |

```powershell
# Lister les comptes utilisateurs avec un SPN (cibles de Kerberoasting)
Get-ADUser -Filter { ServicePrincipalName -like "*" } `
    -Properties ServicePrincipalName, MemberOf, PasswordLastSet |
    Select-Object Name, ServicePrincipalName, PasswordLastSet,
        @{N='Groups';E={($_.MemberOf | ForEach-Object { ($_ -split ',')[0] -replace 'CN=' }) -join ', '}}
```

> **Bonne pratique** : utiliser des **Group Managed Service Accounts** (gMSA) qui gerent automatiquement la rotation des mots de passe (mots de passe de 240 caracteres aleatoires, changes tous les 30 jours). Eviter d'ajouter des comptes de service dans des groupes privilegies.

---

## 10. Comptes integres dangereux

### 10.1 Le compte Administrator (RID 500)

Le compte **Administrator** integre possede le **RID 500** (Relative Identifier). Ce RID est constant et ne change jamais, meme si le compte est renomme.

| Propriete | Valeur |
|---|---|
| **RID** | 500 (toujours) |
| **SID** | `S-1-5-21-<domain>-500` |
| **Renommable** | Oui, mais le RID reste 500 |
| **Desactivable** | Non recommande (peut poser des problemes) |
| **Soumis au verrouillage** | Non par defaut |

Un attaquant peut toujours identifier le compte Administrator meme s'il a ete renomme :

```powershell
# Identifier le compte Administrator meme renomme
Get-ADUser -Filter { SID -like "*-500" } | Select-Object Name, SID, Enabled
```

### 10.2 Le compte Guest

Le compte **Guest** est desactive par defaut dans les domaines AD modernes. S'il est active, il permet un acces sans credentials (acces anonyme) a certaines ressources.

```powershell
# Verifier le statut du compte Guest
Get-ADUser -Identity "Guest" -Properties Enabled | Select-Object Name, Enabled
```

> **Bonne pratique** : verifier que le compte Guest est bien desactive. Definir un mot de passe fort sur le compte Administrator integre et limiter son utilisation aux seules situations d'urgence (break glass).

---

## Pour aller plus loin

- [Microsoft -- Best Practices for Securing Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory)
- [Microsoft -- Kerberos Constrained Delegation](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Microsoft -- AdminSDHolder](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [HarmJ0y -- Abusing Active Directory ACLs](https://www.harmj0y.net/blog/redteaming/abusing-active-directory-permissions-with-powershell/)
- [ADSecurity.org -- DCSync Attack](https://adsecurity.org/?p=1729)
- [SpecterOps -- BloodHound Documentation](https://bloodhound.readthedocs.io/)
