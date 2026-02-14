# Authentification dans Active Directory

**Module** : protocoles d'authentification Kerberos et NTLM

---

## Objectifs du module

A l'issue de ce module, les competences suivantes seront acquises :

- Comprendre les deux protocoles d'authentification utilises dans Active Directory : NTLM et Kerberos
- Maitriser le flux challenge-response de NTLM et identifier ses faiblesses de securite
- Connaitre le fonctionnement complet de Kerberos et son systeme de tickets
- Identifier les composants du KDC (Key Distribution Center) et leur role
- Comprendre pourquoi Kerberos resout les problemes de securite poses par NTLM

---

## 1. Vue d'ensemble des protocoles d'authentification AD

Active Directory repose sur deux protocoles d'authentification reseau :

| Protocole | Statut | Introduit avec | Utilisation |
|---|---|---|---|
| **Kerberos** | Protocole par defaut | Windows 2000 | Authentification moderne dans les environnements AD |
| **NTLM** | Legacy (compatibilite) | Windows NT | Fallback lorsque Kerberos ne peut pas etre utilise |

Kerberos est le protocole principal depuis Windows 2000. NTLM est conserve pour la compatibilite descendante et entre en jeu lorsque Kerberos echoue ou n'est pas disponible (par exemple, lorsque le client ne peut pas joindre un Domain Controller, ou lorsqu'une adresse IP est utilisee au lieu d'un nom DNS).

> **A noter** : meme dans les environnements modernes, NTLM reste actif par defaut. Sa desactivation complete est souvent difficile en raison de dependances legacy. Comprendre ses faiblesses est donc essentiel pour securiser un domaine AD.

---

## 2. NTLM : protocole challenge-response

### 2.1 Principe general

NTLM (NT LAN Manager) est un protocole d'authentification de type **challenge-response**. Le mot de passe de l'utilisateur n'est jamais transmis sur le reseau. A la place, le client prouve qu'il connait le mot de passe en repondant correctement a un defi (challenge) envoye par le serveur.

La version actuelle est **NTLMv2**, qui renforce la securite par rapport a NTLMv1 en ajoutant un nonce client et un horodatage dans la reponse.

### 2.2 Flux d'authentification NTLM

Le flux NTLMv2 se deroule en quatre etapes principales :

#### Step 0 : Negociation

Le client et le serveur negocient la version du protocole a utiliser. Dans un environnement correctement configure, NTLMv2 est selectionne.

```
Client ──── NEGOTIATE_MESSAGE ────> Serveur
       (annonce les capacites NTLM supportees)
```

#### Step 1 : Challenge du serveur

Le serveur genere un **challenge aleatoire de 8 octets** (Server Challenge) et l'envoie au client.

```
Client <──── CHALLENGE_MESSAGE ──── Serveur
        (contient le Server Challenge de 8 bytes)
```

#### Step 2 : Construction de la reponse par le client

Le client construit la reponse NTLMv2 en plusieurs sous-etapes :

1. Le client genere un **nonce client aleatoire de 16 octets** (Client Challenge)
2. Le client collecte les informations contextuelles : **timestamp** (heure courante), **nom de domaine**, **nom du serveur**
3. Ces elements sont assembles dans une structure appelee **NTLMv2 Blob** :

```
NTLMv2 Blob = Client Challenge (16 bytes) + Timestamp + Domain Info + ...
```

4. Le client calcule le **NT hash** du mot de passe de l'utilisateur :

```
NT Hash = MD4(UTF-16LE(password))
```

5. Le client derive une cle intermediaire :

```
NTLMv2 Hash = HMAC-MD5(NT Hash, UPPERCASE(Username) + DomainName)
```

6. La reponse finale est calculee :

```
NTLMv2 Response = HMAC-MD5(NTLMv2 Hash, Server Challenge + NTLMv2 Blob)
```

#### Step 3 : Envoi de la reponse et verification

Le client envoie au serveur un message contenant :

- Le **nom d'utilisateur** (username)
- La **reponse NTLMv2** calculee
- Le **NTLMv2 Blob** (contenant le nonce client, le timestamp, les informations de domaine)

```
Client ──── AUTHENTICATE_MESSAGE ────> Serveur
       (username + NTLMv2 Response + NTLMv2 Blob)
```

Le serveur **ne peut pas verifier lui-meme la reponse** car il ne possede pas le NT hash de l'utilisateur. Il forwarde donc l'ensemble des informations au **Domain Controller** via le protocole **Netlogon RPC** (Secure Channel).

```
Serveur ──── Netlogon RPC ────> Domain Controller
        (Server Challenge + Username + NTLMv2 Response + Blob)
```

Le DC effectue la verification :

1. Il recupere le **NT hash** de l'utilisateur depuis la base Active Directory
2. Il recalcule le HMAC avec les memes parametres (Server Challenge + NTLMv2 Blob)
3. Si le resultat correspond a la NTLMv2 Response envoyee, l'authentification est reussie

```
DC ──── Resultat (succes/echec) ────> Serveur
```

### 2.3 Faiblesses de securite de NTLM

Le probleme fondamental de NTLM est l'**absence d'authentification mutuelle** :

| Verification | Presente dans NTLM ? | Consequence |
|---|---|---|
| Le serveur authentifie le client | Oui (via le challenge-response) | Le serveur sait que le client connait le mot de passe |
| Le client authentifie le serveur | **Non** | Le client ne peut pas verifier qu'il parle au bon serveur |
| Le client authentifie le DC | **Non** | Le client fait confiance au serveur pour contacter le DC |

Cette absence d'authentification mutuelle ouvre la voie a deux attaques majeures :

- **Attaque Man-in-the-Middle (MITM)** : un attaquant se positionne entre le client et le serveur et intercepte les echanges NTLM
- **Attaque NTLM Relay** : un attaquant capture la reponse NTLM d'un client et la rejoue vers un autre serveur pour s'authentifier en tant que la victime

> **Bonne pratique** : restreindre l'utilisation de NTLM au maximum via les GPO (Group Policy) `Network security: Restrict NTLM`. Activer le signing SMB et le channel binding pour limiter les attaques relay.

### 2.4 Cas d'utilisation residuels de NTLM

Malgre ses faiblesses, NTLM reste utilise dans les situations suivantes :

| Scenario | Raison |
|---|---|
| **Imprimantes reseau** | Firmware ancien ne supportant pas Kerberos |
| **Scanners** | Protocoles d'authentification limites |
| **Applications legacy** | Applications internes developpees pour Windows NT/2000 |
| **RDP mal configure** | Connexion RDP utilisant une adresse IP au lieu d'un FQDN |
| **Acces par IP** | Kerberos necessite un nom DNS, pas une adresse IP |
| **Workgroups** | Machines hors domaine sans acces au KDC |

---

## 3. Kerberos : authentification par tickets

### 3.1 Principe general

**Kerberos** est un protocole d'authentification reseau base sur un systeme de **tickets** et de **cles symetriques**. Contrairement a NTLM, Kerberos assure une **authentification mutuelle** : le client authentifie le serveur et le serveur authentifie le client.

Le protocole porte le nom du chien a trois tetes de la mythologie grecque, refletant les trois entites impliquees dans chaque transaction d'authentification.

### 3.2 Composants de Kerberos

| Composant | Role | Localisation |
|---|---|---|
| **Client** | Utilisateur ou machine qui souhaite acceder a un service | Poste de travail |
| **Service** | Application reseau cible (partage de fichiers, serveur web, etc.) | Serveur membre |
| **KDC (Key Distribution Center)** | Centre de distribution de cles, autorite de confiance | Chaque Domain Controller |

Le **KDC** est installe sur chaque Domain Controller et se compose de deux sous-services :

| Sous-service du KDC | Role |
|---|---|
| **Authentication Server (AS)** | Authentifie l'utilisateur et delivre le **TGT** (Ticket Granting Ticket) |
| **Ticket Granting Server (TGS)** | Delivre les **Service Tickets** permettant d'acceder aux services specifiques |

### 3.3 Service Principal Name (SPN)

Un **SPN** (Service Principal Name) est un identifiant unique qui lie un service reseau a un compte de domaine (compte de service ou compte machine). Il permet a Kerberos d'identifier de facon non ambigue le service auquel le client souhaite acceder.

Format d'un SPN :

```
service_class/hostname:port/service_name
```

Exemples :

```
HTTP/webserver01.corp.local          # Serveur web IIS
MSSQLSvc/sqlserver.corp.local:1433   # Instance SQL Server
HOST/dc01.corp.local                 # Services generiques du DC
```

Pour lister les SPN enregistres dans le domaine :

```powershell
# Lister tous les SPN du domaine
setspn -T corp.local -Q */*

# Lister les SPN d'un compte specifique
setspn -L svc_sql
```

### 3.4 Gestion des cles dans Kerberos

Kerberos utilise exclusivement le **chiffrement symetrique**. Le KDC stocke les cles secretes (derivees des mots de passe) de tous les comptes du domaine :

| Cle | Derivee de | Stockee par |
|---|---|---|
| **Cle client** | Hash du mot de passe de l'utilisateur | KDC + client (derive a la volee) |
| **Cle TGS** | Hash du mot de passe du compte `krbtgt` | KDC uniquement |
| **Cle service** | Hash du mot de passe du compte de service | KDC + service |

> **A noter** : le compte **krbtgt** est un compte AD special dont le hash est utilise pour chiffrer tous les TGT. Si ce hash est compromis, un attaquant peut forger des TGT arbitraires : c'est l'attaque **Golden Ticket**.

### 3.5 Flux complet d'authentification Kerberos

Le flux Kerberos complet comprend trois echanges distincts : l'authentification initiale (AS Exchange), l'obtention du ticket de service (TGS Exchange), et l'acces au service (AP Exchange).

#### Phase 1 : AS Exchange (Client <-> Authentication Server)

**Etape 1 -- Le client demande un TGT**

Le client envoie un message **AS-REQ** (Authentication Service Request) a l'Authentication Server du KDC. Ce message contient :

- Le nom d'utilisateur (principal name)
- Le nom du service TGS (demande d'un TGT)
- Un horodatage (timestamp) chiffre avec la cle derivee du mot de passe de l'utilisateur (pre-authentification)

```
Client ──── AS-REQ ────> Authentication Server (KDC)
       (username + encrypted timestamp)
```

> **A noter** : l'etape de pre-authentification (PA-DATA) empeche un attaquant de demander un TGT pour n'importe quel utilisateur. Sans pre-authentification, il suffirait de connaitre le nom d'un utilisateur pour obtenir un blob chiffre avec sa cle et tenter un brute-force hors ligne. Si la pre-authentification est desactivee sur un compte, ce compte est vulnerable a l'attaque **AS-REP Roasting**.

**Etape 2 -- Le KDC delivre le TGT**

L'Authentication Server dechiffre le timestamp avec la cle de l'utilisateur (stockee dans AD). Si le dechiffrement reussit et que le timestamp est recent, l'utilisateur est authentifie.

Le KDC genere une **TGS Session Key** aleatoire et retourne deux elements :

| Element | Chiffre avec | Contenu |
|---|---|---|
| **TGT** (Ticket Granting Ticket) | Cle secrete du compte `krbtgt` | TGS Session Key + identite de l'utilisateur + timestamp + duree de validite |
| **Session Message** | Cle de l'utilisateur | TGS Session Key + timestamp + duree de validite du TGT |

```
Client <──── AS-REP ──── Authentication Server (KDC)
        (TGT chiffre avec cle krbtgt + Session Message chiffre avec cle client)
```

**Etape 3 -- Le client recupere la TGS Session Key**

Le client dechiffre le **Session Message** avec sa propre cle (derivee de son mot de passe) et recupere la **TGS Session Key**. Cette cle sera utilisee pour communiquer avec le TGS.

Le client **ne peut pas dechiffrer le TGT** car il est chiffre avec la cle du compte `krbtgt` que seul le KDC connait. Le TGT est stocke en memoire et presente tel quel au TGS lors des requetes suivantes.

#### Phase 2 : TGS Exchange (Client <-> Ticket Granting Server)

**Etape 4 -- Le client demande un Service Ticket**

Le client souhaite acceder a un service specifique (ex. un partage de fichiers). Il envoie un message **TGS-REQ** au Ticket Granting Server contenant :

| Element | Chiffrement | Contenu |
|---|---|---|
| **TGT** | Inchange (chiffre avec cle krbtgt) | Presente tel que recu a l'etape 2 |
| **SPN du service cible** | Non chiffre | Identifie le service demande |
| **User Authenticator** | Chiffre avec la TGS Session Key | Username + timestamp |

```
Client ──── TGS-REQ ────> Ticket Granting Server (KDC)
       (TGT + SPN + User Authenticator)
```

**Etape 5 -- Le TGS verifie l'identite du client**

Le TGS effectue les operations suivantes :

1. Il **dechiffre le TGT** avec la cle du compte `krbtgt` et recupere la **TGS Session Key** ainsi que l'identite de l'utilisateur
2. Il utilise la **TGS Session Key** pour **dechiffrer le User Authenticator**
3. Il compare l'identite contenue dans le User Authenticator avec celle du TGT
4. Il verifie que le timestamp est recent (protection contre le replay)

Si toutes les verifications sont positives, l'utilisateur est authentifie aupres du TGS.

**Etape 6 -- Le TGS delivre le Service Ticket**

Le TGS genere une **Service Session Key** aleatoire et retourne deux elements :

| Element | Chiffre avec | Contenu |
|---|---|---|
| **Ticket Service Message** | TGS Session Key | Service Session Key + SPN + timestamp + duree de validite |
| **Service Ticket** | Cle secrete du service (Secret Key du compte de service) | Service Session Key + identite de l'utilisateur + PAC (Privilege Attribute Certificate) |

```
Client <──── TGS-REP ──── Ticket Granting Server (KDC)
        (Ticket Service Message + Service Ticket)
```

**Etape 7 -- Le client recupere la Service Session Key**

Le client dechiffre le **Ticket Service Message** avec la **TGS Session Key** et recupere la **Service Session Key**. Le client **ne peut pas dechiffrer le Service Ticket** car il est chiffre avec la cle du service.

#### Phase 3 : AP Exchange (Client <-> Service)

**Etape 8 -- Le client s'authentifie aupres du service**

Le client envoie un message **AP-REQ** au service cible contenant :

| Element | Chiffrement | Contenu |
|---|---|---|
| **Service Ticket** | Inchange (chiffre avec cle du service) | Presente tel que recu a l'etape 6 |
| **User Authenticator** | Chiffre avec la Service Session Key | Username + timestamp |

```
Client ──── AP-REQ ────> Service
       (Service Ticket + User Authenticator)
```

**Etape 9 -- Le service authentifie le client**

Le service effectue les operations suivantes :

1. Il **dechiffre le Service Ticket** avec sa propre cle secrete et recupere la **Service Session Key** et l'identite de l'utilisateur
2. Il utilise la **Service Session Key** pour **dechiffrer le User Authenticator**
3. Il compare les identites et verifie le timestamp
4. Il consulte le **PAC** (Privilege Attribute Certificate) pour connaitre les groupes de l'utilisateur et appliquer les autorisations

Le client est desormais **authentifie aupres du service**.

**Etape 10 -- Authentification mutuelle**

Le service renvoie un **Service Authenticator** au client, chiffre avec la **Service Session Key**. Ce message contient le timestamp du User Authenticator recu a l'etape 8.

```
Client <──── AP-REP ──── Service
        (Service Authenticator chiffre avec Service Session Key)
```

Le client dechiffre le Service Authenticator et verifie le timestamp. Si la verification reussit, le client a la preuve que le service est bien celui qu'il pretend etre (car seul le vrai service possede la cle pour dechiffrer le Service Ticket et recuperer la Service Session Key).

L'**authentification mutuelle est complete** : le client et le service se sont mutuellement authentifies.

### 3.6 Resume du flux Kerberos

```
Phase 1 : AS Exchange
  [1] Client ──── AS-REQ (username + encrypted timestamp) ────> KDC (AS)
  [2] Client <──── AS-REP (TGT + Session Message) ──────────── KDC (AS)
  [3] Client dechiffre Session Message -> TGS Session Key

Phase 2 : TGS Exchange
  [4] Client ──── TGS-REQ (TGT + SPN + Authenticator) ────> KDC (TGS)
  [5] TGS dechiffre TGT, verifie Authenticator
  [6] Client <──── TGS-REP (Service Ticket + Ticket Service Message) ──── KDC (TGS)
  [7] Client dechiffre Ticket Service Message -> Service Session Key

Phase 3 : AP Exchange
  [8] Client ──── AP-REQ (Service Ticket + Authenticator) ────> Service
  [9] Service dechiffre Service Ticket, verifie Authenticator -> Client authentifie
  [10] Client <──── AP-REP (Service Authenticator) ──── Service -> Authentification mutuelle
```

### 3.7 Comparaison NTLM vs Kerberos

| Critere | NTLM | Kerberos |
|---|---|---|
| **Type** | Challenge-response | Tickets + cles symetriques |
| **Authentification mutuelle** | Non | Oui |
| **Delegation** | Non native | Supportee (constrained, unconstrained, RBCD) |
| **Resistance au relay** | Faible (necessite des protections supplementaires) | Forte (tickets lies au service cible via SPN) |
| **Performance** | Contact du DC a chaque authentification | TGT reutilisable pendant sa duree de validite |
| **Prerequis** | Aucun (fonctionne avec IP) | DNS fonctionnel + synchronisation horaire (<5 min) |
| **Protocole par defaut** | Non (fallback) | Oui (depuis Windows 2000) |

> **Bonne pratique** : surveiller les evenements NTLM dans les journaux d'evenements (Event ID 4776 pour la validation NTLM) pour identifier les systemes et applications qui utilisent encore NTLM, afin de planifier leur migration vers Kerberos.

---

## Pour aller plus loin

- [Microsoft -- Kerberos Authentication Overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview)
- [Microsoft -- NTLM Overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/ntlm-overview)
- [Microsoft -- Service Principal Names](https://learn.microsoft.com/en-us/windows/win32/ad/service-principal-names)
- [RFC 4120 -- The Kerberos Network Authentication Service (V5)](https://www.rfc-editor.org/rfc/rfc4120)
- [IETF -- NTLMv2 Authentication](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/)
- [ADSecurity.org -- Kerberos and Attacks](https://adsecurity.org/?page_id=1821)
