# DNS avec Active Directory

**Module** : comprendre et gerer le DNS integre a Active Directory

---

## Objectifs du module

A l'issue de ce module, les competences suivantes seront acquises :

- Comprendre le role central du DNS dans Active Directory
- Connaitre les enregistrements DNS crees automatiquement par AD
- Maitriser le format des enregistrements SRV
- Utiliser les outils de verification DNS (nslookup, Resolve-DnsName)
- Gerer les enregistrements DNS manuellement

---

## 1. DNS et Active Directory

### 1.1 Role du DNS dans AD

Le **DNS** (Domain Name System) est un composant indispensable d'Active Directory. Il est installe par defaut lors de la promotion d'un serveur en Domain Controller. Sans DNS fonctionnel, Active Directory ne peut pas fonctionner.

Le DNS remplit plusieurs fonctions critiques dans AD :

| Fonction | Description |
|---|---|
| **Localisation des DC** | Les machines utilisent le DNS pour trouver les Domain Controllers |
| **Authentification Kerberos** | Le client resout le nom du KDC (Key Distribution Center) via DNS |
| **Jonction au domaine** | Une machine qui rejoint le domaine doit resoudre les enregistrements SRV du domaine |
| **Replication AD** | Les DC se trouvent mutuellement via le DNS pour repliquer leurs donnees |
| **Resolution de noms** | Traduction des noms de machines en adresses IP |

> **A noter** : la majorite des problemes Active Directory sont lies au DNS. Lorsqu'un utilisateur ne peut pas se connecter, qu'une machine ne peut pas joindre le domaine ou que la replication echoue, le DNS est le premier element a verifier.

---

## 2. Enregistrements DNS par defaut

### 2.1 Enregistrements automatiques

Lors de l'installation d'Active Directory, plusieurs enregistrements DNS sont crees automatiquement. Ces enregistrements permettent aux machines du domaine de localiser les services essentiels.

| Service | Enregistrement | Role |
|---|---|---|
| **Kerberos** | `_kerberos._tcp.jedha.local` | Localise le serveur d'authentification Kerberos (KDC) |
| **LDAP** | `_ldap._tcp.jedha.local` | Localise le serveur LDAP pour les requetes d'annuaire et la jonction au domaine |
| **Global Catalog** | `_gc._tcp.jedha.local` | Localise le serveur Global Catalog pour les recherches inter-domaines |
| **Kerberos Password Change** | `_kpasswd._tcp.jedha.local` | Localise le service de changement de mot de passe Kerberos |

### 2.2 Format des enregistrements SRV

Les enregistrements **SRV** (Service) suivent un format specifique qui permet aux clients de decouvrir automatiquement les services disponibles sur le reseau :

```
_service._protocole.nom    TTL    IN    SRV    priorite    poids    port    cible
```

| Champ | Description | Exemple |
|---|---|---|
| **_service** | Nom du service | `_ldap`, `_kerberos`, `_gc` |
| **_protocole** | Protocole de transport | `_tcp`, `_udp` |
| **nom** | Nom du domaine | `jedha.local` |
| **priorite** | Priorite du serveur (plus bas = prioritaire) | `0` |
| **poids** | Poids pour la repartition de charge entre serveurs de meme priorite | `100` |
| **port** | Port du service | `389` (LDAP), `88` (Kerberos), `3268` (GC) |
| **cible** | FQDN du serveur hebergeant le service | `DC1.jedha.local` |

Exemple concret :

```
_ldap._tcp.jedha.local.    600    IN    SRV    0    100    389    DC1.jedha.local.
```

Cet enregistrement indique que le service LDAP est disponible sur `DC1.jedha.local` sur le port 389, avec une priorite de 0 et un poids de 100.

---

## 3. Outils de verification DNS

### 3.1 nslookup

L'outil **nslookup** est l'utilitaire classique pour interroger le DNS depuis la ligne de commande :

```powershell
# Verifier la resolution du nom du domaine
nslookup jedha.local

# Interroger les enregistrements SRV pour LDAP
nslookup -type=SRV _ldap._tcp.jedha.local

# Interroger les enregistrements SRV pour Kerberos
nslookup -type=SRV _kerberos._tcp.jedha.local

# Interroger les enregistrements SRV pour le Global Catalog
nslookup -type=SRV _gc._tcp.jedha.local

# Interroger un serveur DNS specifique
nslookup jedha.local 192.168.1.10
```

### 3.2 Resolve-DnsName

Le cmdlet PowerShell **Resolve-DnsName** offre une alternative plus moderne et plus flexible a nslookup :

```powershell
# Resoudre un nom de domaine
Resolve-DnsName -Name "jedha.local"

# Interroger un type d'enregistrement specifique
Resolve-DnsName -Name "_ldap._tcp.jedha.local" -Type SRV

# Interroger les enregistrements Kerberos
Resolve-DnsName -Name "_kerberos._tcp.jedha.local" -Type SRV

# Resoudre un nom en specifiant le serveur DNS
Resolve-DnsName -Name "DC1.jedha.local" -Server "192.168.1.10"

# Recherche inverse (IP vers nom)
Resolve-DnsName -Name "192.168.1.10" -Type PTR
```

> **Bonne pratique** : apres l'installation d'AD ou la jonction d'une machine au domaine, utilisez ces outils pour verifier que les enregistrements DNS sont bien en place. Un enregistrement SRV manquant pour `_ldap._tcp` ou `_kerberos._tcp` empeche les machines de s'authentifier aupres du DC.

---

## 4. Inscription automatique des machines

### 4.1 Dynamic DNS (DDNS)

Lorsqu'une machine rejoint le domaine Active Directory, elle s'inscrit automatiquement dans le DNS. Ce mecanisme est appele **Dynamic DNS** (DDNS).

Le processus est le suivant :

1. La machine rejoint le domaine et recoit une adresse IP (statique ou via DHCP)
2. La machine envoie une requete de mise a jour dynamique au serveur DNS
3. Le serveur DNS cree un enregistrement **A** (nom → IP) pour la machine
4. Un enregistrement **PTR** (IP → nom) est egalement cree si la zone de recherche inversee est configuree

```powershell
# Verifier les enregistrements d'une machine dans le DNS
Resolve-DnsName -Name "SRV1.jedha.local" -Type A

# Forcer la mise a jour de l'enregistrement DNS d'une machine
ipconfig /registerdns

# Lister tous les enregistrements A de la zone
Get-DnsServerResourceRecord -ZoneName "jedha.local" -RRType A
```

### 4.2 Secure Dynamic Updates

Par defaut, les zones DNS integrees a AD sont configurees en mode **Secure Dynamic Updates Only**. Cela signifie que seules les machines authentifiees dans le domaine peuvent creer ou modifier des enregistrements DNS.

> **A noter** : si les mises a jour dynamiques non securisees sont autorisees, un attaquant pourrait empoisonner le DNS en creant de faux enregistrements (DNS spoofing). Verifiez toujours que la zone est configuree en "Secure only".

---

## 5. Gestion manuelle des enregistrements

### 5.1 Types d'enregistrements

Il est parfois necessaire de creer manuellement des enregistrements DNS, par exemple pour un serveur web interne, un alias ou un enregistrement de validation.

| Type | Description | Exemple |
|---|---|---|
| **A** | Associe un nom a une adresse IPv4 | `webmail.jedha.local → 192.168.1.50` |
| **AAAA** | Associe un nom a une adresse IPv6 | `webmail.jedha.local → fd00::50` |
| **CNAME** | Alias pointant vers un autre nom | `www.jedha.local → SRV2.jedha.local` |
| **TXT** | Enregistrement texte libre | `jedha.local → "v=spf1 include:..."` |
| **MX** | Serveur de messagerie | `jedha.local → mail.jedha.local (priorite 10)` |
| **PTR** | Recherche inverse (IP → nom) | `192.168.1.50 → webmail.jedha.local` |

### 5.2 Creation via l'interface graphique

1. Ouvrir **DNS Manager** (`dnsmgmt.msc`)
2. Developper le serveur > **Forward Lookup Zones > jedha.local**
3. Clic droit > **New Host (A or AAAA)** ou **New Alias (CNAME)** selon le besoin
4. Renseigner les informations et valider

### 5.3 Creation via PowerShell

```powershell
# Creer un enregistrement A
Add-DnsServerResourceRecordA -ZoneName "jedha.local" -Name "webmail" -IPv4Address "192.168.1.50"

# Creer un enregistrement CNAME
Add-DnsServerResourceRecordCName -ZoneName "jedha.local" -Name "www" -HostNameAlias "SRV2.jedha.local"

# Creer un enregistrement TXT
Add-DnsServerResourceRecord -ZoneName "jedha.local" -Name "@" -Txt -DescriptiveText "v=spf1 ip4:192.168.1.0/24 -all"

# Supprimer un enregistrement
Remove-DnsServerResourceRecord -ZoneName "jedha.local" -Name "webmail" -RRType A -Force

# Lister tous les enregistrements de la zone
Get-DnsServerResourceRecord -ZoneName "jedha.local"
```

### 5.4 Exemple pratique : alias CNAME

Pour creer un alias `www.jedha.local` pointant vers le serveur `SRV2.jedha.local` :

```powershell
# Creer l'alias CNAME
Add-DnsServerResourceRecordCName -ZoneName "jedha.local" -Name "www" -HostNameAlias "SRV2.jedha.local"

# Verifier
Resolve-DnsName -Name "www.jedha.local" -Type CNAME
```

Resultat attendu : une requete DNS pour `www.jedha.local` renverra d'abord l'alias CNAME vers `SRV2.jedha.local`, puis l'adresse IP de SRV2.

> **Bonne pratique** : documentez tous les enregistrements DNS crees manuellement. Dans un environnement AD, les enregistrements dynamiques sont geres automatiquement, mais les enregistrements manuels peuvent etre oublies et devenir obsoletes, creant des problemes de securite ou de fonctionnement.

---

## Pour aller plus loin

- [Documentation Microsoft - DNS in Active Directory](https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-top)
- [Documentation Microsoft - SRV Records](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc759550(v=ws.10))
- [Documentation Microsoft - Dynamic DNS Updates](https://learn.microsoft.com/en-us/windows-server/networking/dns/deploy/dynamic-updates)
- [PowerShell DNS Server Cmdlets](https://learn.microsoft.com/en-us/powershell/module/dnsserver/)
- [Troubleshooting DNS in Active Directory](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/dns-troubleshooting-guidance)
