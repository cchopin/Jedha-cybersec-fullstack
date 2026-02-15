# Erreurs de configuration Active Directory

**Module** : misconfigurations courantes et leurs conséquences en sécurité

---

## Objectifs du module

À l'issue de ce module, les compétences suivantes seront acquises :

- Identifier les erreurs de configuration les plus courantes dans Active Directory
- Comprendre les risques liés aux privilèges excessifs et au group nesting
- Maîtriser les trois types de délégation Kerberos et leurs implications de sécurité
- Connaître les abus d'ACL, d'AdminSDHolder et de GPO
- Comprendre les risques liés aux droits de réplication (DCSync)
- Identifier les problèmes liés aux SPN et aux comptes de service

---

## 1. Qu'est-ce qu'une misconfiguration ?

Une **misconfiguration** (erreur de configuration) est un paramétrage incorrect, faible ou incomplet d'un composant Active Directory qui crée une vulnérabilité exploitable par un attaquant. Contrairement aux vulnérabilités logicielles qui nécessitent un correctif de l'éditeur, les misconfigurations relèvent de la responsabilité de l'administrateur.

Les misconfigurations sont la cause principale des compromissions AD dans les entreprises. Elles sont souvent le résultat de :

- Configurations par défaut jamais renforcées
- Accès temporaires jamais révoqués
- Méconnaissance des implications de sécurité de certains paramètres
- Accumulation de dette technique au fil du temps

> **À noter** : un audit régulier de la configuration AD est indispensable. Des outils comme PingCastle ou BloodHound permettent d'identifier automatiquement la plupart de ces problèmes.

---

## 2. Utilisateurs sur-privilégiés

### 2.1 Le problème

L'une des erreurs les plus fréquentes est l'accumulation de privilèges sur des comptes utilisateurs. Ce phénomène se produit typiquement lorsqu'un accès temporaire est accordé pour une tâche spécifique puis jamais révoqué.

### 2.2 Exemple concret

L'utilisateur **jarjar** a été temporairement ajouté avec des droits d'écriture (Write Access) sur le groupe **Domain Admins** pour une opération de maintenance. Plusieurs mois plus tard, ce droit est toujours en place.

Conséquence : un attaquant qui compromet le compte de jarjar peut s'ajouter lui-même au groupe Domain Admins et prendre le contrôle complet du domaine.

```powershell
# Vérifier les ACL sur le groupe Domain Admins
(Get-Acl "AD:\CN=Domain Admins,CN=Users,DC=corp,DC=local").Access |
    Where-Object { $_.ActiveDirectoryRights -match "Write" } |
    Format-Table IdentityReference, ActiveDirectoryRights
```

### 2.3 Remédiations

| Action | Détail |
|---|---|
| **Revue régulière des privilèges** | Auditer les ACL sur les groupes privilégiés au minimum chaque trimestre |
| **Accès temporaires** | Utiliser des groupes temporaires avec expiration automatique (PAM, JIT Access) |
| **Principe du moindre privilège** | Ne jamais accorder plus de droits que nécessaire pour la tâche |
| **Comptes dédiés** | Utiliser des comptes d'administration séparés (tiering model) |

---

## 3. Group Nesting dangereux

### 3.1 Le problème

Active Directory permet d'imbriquer des groupes les uns dans les autres (**group nesting**). Les privilèges se propagent de manière transitive : si le groupe A est membre du groupe B, et le groupe B est membre du groupe C, alors tous les membres du groupe A héritent des privilèges du groupe C.

Cette transitivité peut créer des **chemins d'escalade de privilèges cachés** que les administrateurs ne voient pas dans l'interface graphique standard.

### 3.2 Exemple concret

L'utilisateur **C3PO** est membre du groupe **Help Desk Level 1**. La chaîne de nesting suivante existe dans l'annuaire :

```
C3PO
  └── Help Desk Level 1
        └── Help Desk Level 2
              └── Help Desk Level 3
                    └── Operations
                          └── Domain Admins
```

Résultat : C3PO est **Domain Admin** sans que cela soit visible au premier coup d'oeil. Un administrateur qui examine les membres directs du groupe Domain Admins ne verra pas C3PO.

### 3.3 Détection

```powershell
# Lister les membres récursifs du groupe Domain Admins
Get-ADGroupMember -Identity "Domain Admins" -Recursive |
    Select-Object Name, ObjectClass, DistinguishedName

# Comparer avec les membres directs
Get-ADGroupMember -Identity "Domain Admins" |
    Select-Object Name, ObjectClass, DistinguishedName
```

Si le nombre de membres récursifs est significativement supérieur au nombre de membres directs, des chaînes de nesting existent et doivent être examinées.

> **Bonne pratique** : limiter le nesting à un maximum de deux niveaux et documenter chaque imbrication. Utiliser BloodHound pour visualiser graphiquement les chemins de nesting vers les groupes privilégiés.

---

## 4. Délégation Kerberos

### 4.1 Principe

La **délégation Kerberos** permet à un service d'agir au nom d'un utilisateur auprès d'autres services. C'est un mécanisme légitime dans les architectures multi-tiers (par exemple, un serveur web frontal qui accède à une base de données au nom de l'utilisateur connecté).

Cependant, une délégation mal configurée constitue un vecteur d'attaque majeur.

### 4.2 Les trois types de délégation

| Type | Niveau de risque | Configuration | Description |
|---|---|---|---|
| **Unconstrained Delegation** | Très élevé | GUI (propriétés du compte) | Le service peut utiliser le ticket de l'utilisateur pour accéder à **n'importe quel** autre service |
| **Constrained Delegation** | Modéré | GUI (propriétés du compte) | Le service ne peut déléguer qu'à une **liste définie** de services (SPN) |
| **Resource-Based Constrained Delegation (RBCD)** | Modéré | PowerShell uniquement | La délégation est définie **côté service cible** plutôt que côté service source |

### 4.3 Unconstrained Delegation

Lorsqu'un serveur est configuré en Unconstrained Delegation, tout utilisateur qui s'authentifie auprès de ce serveur lui transmet son **TGT complet**. Le serveur stocke ce TGT en mémoire et peut l'utiliser pour s'authentifier auprès de n'importe quel service en tant que cet utilisateur.

```
Utilisateur ──── TGT ────> Serveur (Unconstrained)
                           Le serveur stocke le TGT en mémoire
                           et peut accéder à tout service en tant que l'utilisateur
```

Risque : si le serveur en Unconstrained Delegation est compromis, l'attaquant récupère les TGT de tous les utilisateurs qui s'y sont authentifiés et peut usurper leur identité.

> **À noter** : les Domain Controllers sont toujours en Unconstrained Delegation. C'est un comportement normal et attendu. Le risque concerne les serveurs membres configurés avec cette option.

Pour identifier les machines en Unconstrained Delegation :

```powershell
Get-ADComputer -Filter { TrustedForDelegation -eq $true } -Properties TrustedForDelegation |
    Select-Object Name, TrustedForDelegation
```

### 4.4 Constrained Delegation

La Constrained Delegation limite les services vers lesquels la délégation est autorisée. Le serveur ne peut déléguer que vers les SPN spécifiés dans l'attribut `msDS-AllowedToDelegateTo`.

```powershell
# Identifier les comptes avec Constrained Delegation
Get-ADObject -Filter { msDS-AllowedToDelegateTo -like "*" } -Properties msDS-AllowedToDelegateTo |
    Select-Object Name, msDS-AllowedToDelegateTo
```

Bien que plus sûre que l'Unconstrained Delegation, elle reste abusable si un attaquant compromet le compte de service délégué.

### 4.5 Resource-Based Constrained Delegation (RBCD)

La RBCD inverse la logique : c'est le **service cible** qui définit quels comptes sont autorisés à déléguer vers lui, via l'attribut `msDS-AllowedToActOnBehalfOfOtherIdentity`.

```powershell
# Configurer la RBCD (PowerShell requis)
Set-ADComputer -Identity "ServeurCible" `
    -PrincipalsAllowedToDelegateToAccount (Get-ADComputer "ServeurSource")

# Vérifier la configuration RBCD
Get-ADComputer "ServeurCible" -Properties msDS-AllowedToActOnBehalfOfOtherIdentity |
    Select-Object -ExpandProperty msDS-AllowedToActOnBehalfOfOtherIdentity
```

Risque : un attaquant qui possède le droit d'écriture sur l'attribut `msDS-AllowedToActOnBehalfOfOtherIdentity` d'une machine peut configurer la RBCD pour s'y déléguer lui-même.

---

## 5. Abus d'ACL (Access Control Lists)

### 5.1 Le problème

Les objets Active Directory (utilisateurs, groupes, OUs, GPOs) sont protégés par des ACL. Certains droits sont particulièrement dangereux lorsqu'ils sont accordés à des comptes non privilégiés.

### 5.2 Droits dangereux

| Droit | Description | Exploitation possible |
|---|---|---|
| **GenericAll** | Contrôle total sur l'objet | Modification du mot de passe, ajout au groupe, modification de n'importe quel attribut |
| **GenericWrite** | Écriture sur tous les attributs | Modification du SPN (Kerberoasting ciblé), modification du script de logon |
| **WriteOwner** | Modification du propriétaire de l'objet | L'attaquant se définit comme propriétaire puis modifie la DACL |
| **WriteDACL** | Modification de la DACL de l'objet | L'attaquant s'accorde GenericAll puis exploite l'objet |
| **ForceChangePassword** | Réinitialisation du mot de passe sans connaître l'ancien | Prise de contrôle directe du compte cible |
| **AddMember** | Ajout de membres à un groupe | Ajout de l'attaquant dans un groupe privilégié |

### 5.3 Détection

```powershell
# Examiner les ACL d'un objet AD
(Get-Acl "AD:\CN=Domain Admins,CN=Users,DC=corp,DC=local").Access |
    Format-Table IdentityReference, ActiveDirectoryRights, AccessControlType
```

> **Bonne pratique** : utiliser BloodHound pour cartographier les chemins d'attaque basés sur les ACL. Auditer régulièrement les ACL des objets critiques (groupes privilégiés, AdminSDHolder, OUs contenant les DCs).

---

## 6. AdminSDHolder

### 6.1 Mécanisme

**AdminSDHolder** est un objet conteneur spécial situé dans le conteneur System du domaine :

```
CN=AdminSDHolder,CN=System,DC=corp,DC=local
```

Toutes les **60 minutes**, le processus **SDProp** (SD Propagator) copie l'ACL de l'objet AdminSDHolder sur tous les objets considérés comme privilégiés (membres de Domain Admins, Enterprise Admins, Schema Admins, Account Operators, etc.).

Ce mécanisme est conçu pour protéger les comptes privilégiés en écrasant toute modification non autorisée de leurs ACL.

### 6.2 Risque de backdoor

Si un attaquant parvient à modifier l'ACL de l'objet AdminSDHolder, cette modification sera **automatiquement propagée** toutes les 60 minutes sur tous les comptes privilégiés du domaine.

Exemple : un attaquant ajoute un droit GenericAll pour le compte `attacker` sur AdminSDHolder. Dans les 60 minutes suivantes, le compte `attacker` disposera de GenericAll sur tous les comptes Domain Admins.

```powershell
# Vérifier l'ACL de AdminSDHolder
(Get-Acl "AD:\CN=AdminSDHolder,CN=System,DC=corp,DC=local").Access |
    Where-Object { $_.IdentityReference -notmatch "BUILTIN|NT AUTHORITY|S-1-5-32" } |
    Format-Table IdentityReference, ActiveDirectoryRights
```

> **Bonne pratique** : surveiller les modifications sur l'objet AdminSDHolder via les journaux d'audit (Event ID 5136 -- Directory Service Changes).

---

## 7. GPO et SYSVOL

### 7.1 Risques liés aux GPO

Les **Group Policy Objects** (GPO) sont un vecteur d'attaque sous-estimé. Plusieurs scénarios de misconfiguration existent :

| Misconfiguration | Risque |
|---|---|
| **Scripts malveillants dans les GPO de démarrage** | Exécution de code sur toutes les machines ciblées par la GPO |
| **Permissions faibles sur les GPO** | Un attaquant modifie une GPO pour exécuter du code ou modifier des paramètres |
| **GPO trop permissives** | Désactivation de protections de sécurité (UAC, Windows Defender, pare-feu) |
| **Préférences de GPO avec mots de passe** | Mots de passe chiffrés avec une clé publique connue (MS14-025) |

### 7.2 Permissions SYSVOL

Le partage **SYSVOL** (`\\domain\SYSVOL`) contient les scripts de logon et les fichiers de politique. Les permissions par défaut permettent à tout utilisateur authentifié de lire le contenu.

```powershell
# Vérifier les permissions sur SYSVOL
Get-Acl "\\corp.local\SYSVOL\corp.local\Policies" | Format-List

# Lister les GPO du domaine et leurs permissions
Get-GPO -All | ForEach-Object {
    $gpo = $_
    $gpo.GetSecurityInfo() | Where-Object { $_.Permission -match "Edit|Full" } |
        Select-Object @{N='GPO';E={$gpo.DisplayName}}, Trustee, Permission
}
```

> **Bonne pratique** : restreindre les droits de modification des GPO aux seuls administrateurs habilités. Auditer régulièrement le contenu de SYSVOL pour détecter des scripts ou fichiers suspects.

---

## 8. Réplication et attaque DCSync

### 8.1 Les droits de réplication

Dans Active Directory, la réplication entre Domain Controllers utilise le protocole **DRS** (Directory Replication Service). Les droits suivants contrôlent l'accès à ce mécanisme :

| Droit | Description |
|---|---|
| **Replicating Directory Changes** | Permet de répliquer les données de l'annuaire (hors données sensibles) |
| **Replicating Directory Changes All** | Permet de répliquer **toutes** les données, y compris les hashes de mots de passe |

Ces deux droits combinés permettent d'extraire l'intégralité de la base de mots de passe du domaine.

### 8.2 Comptes autorisés par défaut

Par défaut, seuls les comptes suivants possèdent ces droits :

- **Domain Controllers** (groupe)
- **Domain Admins** (groupe)
- **Enterprise Admins** (groupe)
- **SYSTEM** (compte local)

### 8.3 Attaque DCSync

Si un attaquant compromet un compte possédant les droits de réplication, il peut effectuer une attaque **DCSync** :

```
1. L'attaquant utilise un outil comme Mimikatz ou Impacket
2. L'outil simule un Domain Controller et envoie une requête de réplication (DRSGetNCChanges)
3. Le vrai DC répond en envoyant les hashes de mots de passe demandés
4. L'attaquant obtient les NT hashes de tous les comptes du domaine
```

```
Attaquant (avec droits de réplication)
    |
    ├── "Je suis un DC, j'ai besoin de répliquer"
    |        |
    |        v
    |   Domain Controller
    |        |
    |        v
    └── Reçoit tous les NT hashes (dont krbtgt, Administrator, etc.)
```

La détection repose sur la surveillance des requêtes de réplication provenant de machines qui ne sont pas des Domain Controllers.

```powershell
# Identifier les comptes avec droits de réplication
(Get-Acl "AD:\DC=corp,DC=local").Access |
    Where-Object {
        $_.ObjectType -eq "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" -or  # Replicating Directory Changes All
        $_.ObjectType -eq "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"      # Replicating Directory Changes
    } | Format-Table IdentityReference, ActiveDirectoryRights
```

> **Bonne pratique** : vérifier régulièrement que seuls les Domain Controllers et les comptes d'administration légitimes possèdent les droits de réplication. Toute délégation de ces droits à un compte de service ou un utilisateur doit être considérée comme un risque critique.

---

## 9. SPN et comptes de service

### 9.1 Le problème des SPN sur les comptes utilisateurs

Un **SPN** (Service Principal Name) doit idéalement être lié à un **compte de service managé** (gMSA) ou à un **compte machine**. Lorsqu'un SPN est associé à un compte utilisateur standard, ce compte devient vulnérable à l'attaque **Kerberoasting**.

Le principe du Kerberoasting :

```
1. L'attaquant demande un Service Ticket (TGS) pour le SPN cible
2. Le KDC délivre un Service Ticket chiffré avec le hash du compte de service
3. L'attaquant effectue un brute-force hors ligne sur le Service Ticket
4. Si le mot de passe est faible, l'attaquant récupère le mot de passe en clair
```

### 9.2 Comptes de service avec privilèges excessifs

Un autre problème courant est l'attribution de privilèges excessifs aux comptes de service :

| Problème | Exemple | Risque |
|---|---|---|
| Service account membre de Domain Admins | `svc_backup` dans Domain Admins | Compromission du compte = compromission du domaine |
| Mot de passe faible sur un service account | `svc_sql` avec le mot de passe `Password1` | Kerberoasting trivial |
| Mot de passe jamais changé | `svc_web` avec le même mot de passe depuis 5 ans | Augmente la fenêtre d'exploitation |

```powershell
# Lister les comptes utilisateurs avec un SPN (cibles de Kerberoasting)
Get-ADUser -Filter { ServicePrincipalName -like "*" } `
    -Properties ServicePrincipalName, MemberOf, PasswordLastSet |
    Select-Object Name, ServicePrincipalName, PasswordLastSet,
        @{N='Groups';E={($_.MemberOf | ForEach-Object { ($_ -split ',')[0] -replace 'CN=' }) -join ', '}}
```

> **Bonne pratique** : utiliser des **Group Managed Service Accounts** (gMSA) qui gèrent automatiquement la rotation des mots de passe (mots de passe de 240 caractères aléatoires, changés tous les 30 jours). Éviter d'ajouter des comptes de service dans des groupes privilégiés.

---

## 10. Comptes intégrés dangereux

### 10.1 Le compte Administrator (RID 500)

Le compte **Administrator** intégré possède le **RID 500** (Relative Identifier). Ce RID est constant et ne change jamais, même si le compte est renommé.

| Propriété | Valeur |
|---|---|
| **RID** | 500 (toujours) |
| **SID** | `S-1-5-21-<domain>-500` |
| **Renommable** | Oui, mais le RID reste 500 |
| **Désactivable** | Non recommandé (peut poser des problèmes) |
| **Soumis au verrouillage** | Non par défaut |

Un attaquant peut toujours identifier le compte Administrator même s'il a été renommé :

```powershell
# Identifier le compte Administrator même renommé
Get-ADUser -Filter { SID -like "*-500" } | Select-Object Name, SID, Enabled
```

### 10.2 Le compte Guest

Le compte **Guest** est désactivé par défaut dans les domaines AD modernes. S'il est activé, il permet un accès sans credentials (accès anonyme) à certaines ressources.

```powershell
# Vérifier le statut du compte Guest
Get-ADUser -Identity "Guest" -Properties Enabled | Select-Object Name, Enabled
```

> **Bonne pratique** : vérifier que le compte Guest est bien désactivé. Définir un mot de passe fort sur le compte Administrator intégré et limiter son utilisation aux seules situations d'urgence (break glass).

---

## Pour aller plus loin

- [Microsoft -- Best Practices for Securing Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory)
- [Microsoft -- Kerberos Constrained Delegation](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Microsoft -- AdminSDHolder](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [HarmJ0y -- Abusing Active Directory ACLs](https://www.harmj0y.net/blog/redteaming/abusing-active-directory-permissions-with-powershell/)
- [ADSecurity.org -- DCSync Attack](https://adsecurity.org/?p=1729)
- [SpecterOps -- BloodHound Documentation](https://bloodhound.readthedocs.io/)
