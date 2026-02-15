# DNS avec Active Directory

**Module** : comprendre et gérer le DNS intégré à Active Directory

---

## Objectifs du module

À l'issue de ce module, les compétences suivantes seront acquises :

- Comprendre le rôle central du DNS dans Active Directory
- Connaître les enregistrements DNS créés automatiquement par AD
- Maîtriser le format des enregistrements SRV
- Utiliser les outils de vérification DNS (nslookup, Resolve-DnsName)
- Gérer les enregistrements DNS manuellement

---

## 1. DNS et Active Directory

### 1.1 Rôle du DNS dans AD

Le **DNS** (Domain Name System) est un composant indispensable d'Active Directory. Il est installé par défaut lors de la promotion d'un serveur en Domain Controller. Sans DNS fonctionnel, Active Directory ne peut pas fonctionner.

Le DNS remplit plusieurs fonctions critiques dans AD :

| Fonction | Description |
|---|---|
| **Localisation des DC** | Les machines utilisent le DNS pour trouver les Domain Controllers |
| **Authentification Kerberos** | Le client résout le nom du KDC (Key Distribution Center) via DNS |
| **Jonction au domaine** | Une machine qui rejoint le domaine doit résoudre les enregistrements SRV du domaine |
| **Réplication AD** | Les DC se trouvent mutuellement via le DNS pour répliquer leurs données |
| **Résolution de noms** | Traduction des noms de machines en adresses IP |

> **À noter** : la majorité des problèmes Active Directory sont liés au DNS. Lorsqu'un utilisateur ne peut pas se connecter, qu'une machine ne peut pas joindre le domaine ou que la réplication échoue, le DNS est le premier élément à vérifier.

---

## 2. Enregistrements DNS par défaut

### 2.1 Enregistrements automatiques

Lors de l'installation d'Active Directory, plusieurs enregistrements DNS sont créés automatiquement. Ces enregistrements permettent aux machines du domaine de localiser les services essentiels.

| Service | Enregistrement | Rôle |
|---|---|---|
| **Kerberos** | `_kerberos._tcp.jedha.local` | Localise le serveur d'authentification Kerberos (KDC) |
| **LDAP** | `_ldap._tcp.jedha.local` | Localise le serveur LDAP pour les requêtes d'annuaire et la jonction au domaine |
| **Global Catalog** | `_gc._tcp.jedha.local` | Localise le serveur Global Catalog pour les recherches inter-domaines |
| **Kerberos Password Change** | `_kpasswd._tcp.jedha.local` | Localise le service de changement de mot de passe Kerberos |

### 2.2 Format des enregistrements SRV

Les enregistrements **SRV** (Service) suivent un format spécifique qui permet aux clients de découvrir automatiquement les services disponibles sur le réseau :

```
_service._protocole.nom    TTL    IN    SRV    priorité    poids    port    cible
```

| Champ | Description | Exemple |
|---|---|---|
| **_service** | Nom du service | `_ldap`, `_kerberos`, `_gc` |
| **_protocole** | Protocole de transport | `_tcp`, `_udp` |
| **nom** | Nom du domaine | `jedha.local` |
| **priorité** | Priorité du serveur (plus bas = prioritaire) | `0` |
| **poids** | Poids pour la répartition de charge entre serveurs de même priorité | `100` |
| **port** | Port du service | `389` (LDAP), `88` (Kerberos), `3268` (GC) |
| **cible** | FQDN du serveur hébergeant le service | `DC1.jedha.local` |

Exemple concret :

```
_ldap._tcp.jedha.local.    600    IN    SRV    0    100    389    DC1.jedha.local.
```

Cet enregistrement indique que le service LDAP est disponible sur `DC1.jedha.local` sur le port 389, avec une priorité de 0 et un poids de 100.

---

## 3. Outils de vérification DNS

### 3.1 nslookup

L'outil **nslookup** est l'utilitaire classique pour interroger le DNS depuis la ligne de commande :

```powershell
# Vérifier la résolution du nom du domaine
nslookup jedha.local

# Interroger les enregistrements SRV pour LDAP
nslookup -type=SRV _ldap._tcp.jedha.local

# Interroger les enregistrements SRV pour Kerberos
nslookup -type=SRV _kerberos._tcp.jedha.local

# Interroger les enregistrements SRV pour le Global Catalog
nslookup -type=SRV _gc._tcp.jedha.local

# Interroger un serveur DNS spécifique
nslookup jedha.local 192.168.1.10
```

### 3.2 Resolve-DnsName

Le cmdlet PowerShell **Resolve-DnsName** offre une alternative plus moderne et plus flexible à nslookup :

```powershell
# Résoudre un nom de domaine
Resolve-DnsName -Name "jedha.local"

# Interroger un type d'enregistrement spécifique
Resolve-DnsName -Name "_ldap._tcp.jedha.local" -Type SRV

# Interroger les enregistrements Kerberos
Resolve-DnsName -Name "_kerberos._tcp.jedha.local" -Type SRV

# Résoudre un nom en spécifiant le serveur DNS
Resolve-DnsName -Name "DC1.jedha.local" -Server "192.168.1.10"

# Recherche inverse (IP vers nom)
Resolve-DnsName -Name "192.168.1.10" -Type PTR
```

> **Bonne pratique** : après l'installation d'AD ou la jonction d'une machine au domaine, utilisez ces outils pour vérifier que les enregistrements DNS sont bien en place. Un enregistrement SRV manquant pour `_ldap._tcp` ou `_kerberos._tcp` empêche les machines de s'authentifier auprès du DC.

---

## 4. Inscription automatique des machines

### 4.1 Dynamic DNS (DDNS)

Lorsqu'une machine rejoint le domaine Active Directory, elle s'inscrit automatiquement dans le DNS. Ce mécanisme est appelé **Dynamic DNS** (DDNS).

Le processus est le suivant :

1. La machine rejoint le domaine et reçoit une adresse IP (statique ou via DHCP)
2. La machine envoie une requête de mise à jour dynamique au serveur DNS
3. Le serveur DNS crée un enregistrement **A** (nom → IP) pour la machine
4. Un enregistrement **PTR** (IP → nom) est également créé si la zone de recherche inversée est configurée

```powershell
# Vérifier les enregistrements d'une machine dans le DNS
Resolve-DnsName -Name "SRV1.jedha.local" -Type A

# Forcer la mise à jour de l'enregistrement DNS d'une machine
ipconfig /registerdns

# Lister tous les enregistrements A de la zone
Get-DnsServerResourceRecord -ZoneName "jedha.local" -RRType A
```

### 4.2 Secure Dynamic Updates

Par défaut, les zones DNS intégrées à AD sont configurées en mode **Secure Dynamic Updates Only**. Cela signifie que seules les machines authentifiées dans le domaine peuvent créer ou modifier des enregistrements DNS.

> **À noter** : si les mises à jour dynamiques non sécurisées sont autorisées, un attaquant pourrait empoisonner le DNS en créant de faux enregistrements (DNS spoofing). Vérifiez toujours que la zone est configurée en "Secure only".

---

## 5. Gestion manuelle des enregistrements

### 5.1 Types d'enregistrements

Il est parfois nécessaire de créer manuellement des enregistrements DNS, par exemple pour un serveur web interne, un alias ou un enregistrement de validation.

| Type | Description | Exemple |
|---|---|---|
| **A** | Associe un nom à une adresse IPv4 | `webmail.jedha.local → 192.168.1.50` |
| **AAAA** | Associe un nom à une adresse IPv6 | `webmail.jedha.local → fd00::50` |
| **CNAME** | Alias pointant vers un autre nom | `www.jedha.local → SRV2.jedha.local` |
| **TXT** | Enregistrement texte libre | `jedha.local → "v=spf1 include:..."` |
| **MX** | Serveur de messagerie | `jedha.local → mail.jedha.local (priorité 10)` |
| **PTR** | Recherche inverse (IP → nom) | `192.168.1.50 → webmail.jedha.local` |

### 5.2 Création via l'interface graphique

1. Ouvrir **DNS Manager** (`dnsmgmt.msc`)
2. Développer le serveur > **Forward Lookup Zones > jedha.local**
3. Clic droit > **New Host (A or AAAA)** ou **New Alias (CNAME)** selon le besoin
4. Renseigner les informations et valider

### 5.3 Création via PowerShell

```powershell
# Créer un enregistrement A
Add-DnsServerResourceRecordA -ZoneName "jedha.local" -Name "webmail" -IPv4Address "192.168.1.50"

# Créer un enregistrement CNAME
Add-DnsServerResourceRecordCName -ZoneName "jedha.local" -Name "www" -HostNameAlias "SRV2.jedha.local"

# Créer un enregistrement TXT
Add-DnsServerResourceRecord -ZoneName "jedha.local" -Name "@" -Txt -DescriptiveText "v=spf1 ip4:192.168.1.0/24 -all"

# Supprimer un enregistrement
Remove-DnsServerResourceRecord -ZoneName "jedha.local" -Name "webmail" -RRType A -Force

# Lister tous les enregistrements de la zone
Get-DnsServerResourceRecord -ZoneName "jedha.local"
```

### 5.4 Exemple pratique : alias CNAME

Pour créer un alias `www.jedha.local` pointant vers le serveur `SRV2.jedha.local` :

```powershell
# Créer l'alias CNAME
Add-DnsServerResourceRecordCName -ZoneName "jedha.local" -Name "www" -HostNameAlias "SRV2.jedha.local"

# Vérifier
Resolve-DnsName -Name "www.jedha.local" -Type CNAME
```

Résultat attendu : une requête DNS pour `www.jedha.local` renverra d'abord l'alias CNAME vers `SRV2.jedha.local`, puis l'adresse IP de SRV2.

> **Bonne pratique** : documentez tous les enregistrements DNS créés manuellement. Dans un environnement AD, les enregistrements dynamiques sont gérés automatiquement, mais les enregistrements manuels peuvent être oubliés et devenir obsolètes, créant des problèmes de sécurité ou de fonctionnement.

---

## Pour aller plus loin

- [Documentation Microsoft - DNS in Active Directory](https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-top)
- [Documentation Microsoft - SRV Records](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc759550(v=ws.10))
- [Documentation Microsoft - Dynamic DNS Updates](https://learn.microsoft.com/en-us/windows-server/networking/dns/deploy/dynamic-updates)
- [PowerShell DNS Server Cmdlets](https://learn.microsoft.com/en-us/powershell/module/dnsserver/)
- [Troubleshooting DNS in Active Directory](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/dns-troubleshooting-guidance)
