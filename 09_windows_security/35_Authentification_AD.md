# Authentification dans Active Directory

**Module** : protocoles d'authentification Kerberos et NTLM

---

## Objectifs du module

À l'issue de ce module, les compétences suivantes seront acquises :

- Comprendre les deux protocoles d'authentification utilisés dans Active Directory : NTLM et Kerberos
- Maîtriser le flux challenge-response de NTLM et identifier ses faiblesses de sécurité
- Connaître le fonctionnement complet de Kerberos et son système de tickets
- Identifier les composants du KDC (Key Distribution Center) et leur rôle
- Comprendre pourquoi Kerberos résout les problèmes de sécurité posés par NTLM

---

## 1. Vue d'ensemble des protocoles d'authentification AD

Active Directory repose sur deux protocoles d'authentification réseau :

| Protocole | Statut | Introduit avec | Utilisation |
|---|---|---|---|
| **Kerberos** | Protocole par défaut | Windows 2000 | Authentification moderne dans les environnements AD |
| **NTLM** | Legacy (compatibilité) | Windows NT | Fallback lorsque Kerberos ne peut pas être utilisé |

Kerberos est le protocole principal depuis Windows 2000. NTLM est conservé pour la compatibilité descendante et entre en jeu lorsque Kerberos échoue ou n'est pas disponible (par exemple, lorsque le client ne peut pas joindre un Domain Controller, ou lorsqu'une adresse IP est utilisée au lieu d'un nom DNS).

> **À noter** : même dans les environnements modernes, NTLM reste actif par défaut. Sa désactivation complète est souvent difficile en raison de dépendances legacy. Comprendre ses faiblesses est donc essentiel pour sécuriser un domaine AD.

---

## 2. NTLM : protocole challenge-response

### 2.1 Principe général

NTLM (NT LAN Manager) est un protocole d'authentification de type **challenge-response**. Le mot de passe de l'utilisateur n'est jamais transmis sur le réseau. À la place, le client prouve qu'il connaît le mot de passe en répondant correctement à un défi (challenge) envoyé par le serveur.

La version actuelle est **NTLMv2**, qui renforce la sécurité par rapport à NTLMv1 en ajoutant un nonce client et un horodatage dans la réponse.

### 2.2 Flux d'authentification NTLM

Le flux NTLMv2 se déroule en quatre étapes principales :

#### Step 0 : Négociation

Le client et le serveur négocient la version du protocole à utiliser. Dans un environnement correctement configuré, NTLMv2 est sélectionné.

```
Client ──── NEGOTIATE_MESSAGE ────> Serveur
       (annonce les capacités NTLM supportées)
```

#### Step 1 : Challenge du serveur

Le serveur génère un **challenge aléatoire de 8 octets** (Server Challenge) et l'envoie au client.

```
Client <──── CHALLENGE_MESSAGE ──── Serveur
        (contient le Server Challenge de 8 bytes)
```

#### Step 2 : Construction de la réponse par le client

Le client construit la réponse NTLMv2 en plusieurs sous-étapes :

1. Le client génère un **nonce client aléatoire de 16 octets** (Client Challenge)
2. Le client collecte les informations contextuelles : **timestamp** (heure courante), **nom de domaine**, **nom du serveur**
3. Ces éléments sont assemblés dans une structure appelée **NTLMv2 Blob** :

```
NTLMv2 Blob = Client Challenge (16 bytes) + Timestamp + Domain Info + ...
```

4. Le client calcule le **NT hash** du mot de passe de l'utilisateur :

```
NT Hash = MD4(UTF-16LE(password))
```

5. Le client dérive une clé intermédiaire :

```
NTLMv2 Hash = HMAC-MD5(NT Hash, UPPERCASE(Username) + DomainName)
```

6. La réponse finale est calculée :

```
NTLMv2 Response = HMAC-MD5(NTLMv2 Hash, Server Challenge + NTLMv2 Blob)
```

#### Step 3 : Envoi de la réponse et vérification

Le client envoie au serveur un message contenant :

- Le **nom d'utilisateur** (username)
- La **réponse NTLMv2** calculée
- Le **NTLMv2 Blob** (contenant le nonce client, le timestamp, les informations de domaine)

```
Client ──── AUTHENTICATE_MESSAGE ────> Serveur
       (username + NTLMv2 Response + NTLMv2 Blob)
```

Le serveur **ne peut pas vérifier lui-même la réponse** car il ne possède pas le NT hash de l'utilisateur. Il forwarde donc l'ensemble des informations au **Domain Controller** via le protocole **Netlogon RPC** (Secure Channel).

```
Serveur ──── Netlogon RPC ────> Domain Controller
        (Server Challenge + Username + NTLMv2 Response + Blob)
```

Le DC effectue la vérification :

1. Il récupère le **NT hash** de l'utilisateur depuis la base Active Directory
2. Il recalcule le HMAC avec les mêmes paramètres (Server Challenge + NTLMv2 Blob)
3. Si le résultat correspond à la NTLMv2 Response envoyée, l'authentification est réussie

```
DC ──── Résultat (succès/échec) ────> Serveur
```

### 2.3 Faiblesses de sécurité de NTLM

Le problème fondamental de NTLM est l'**absence d'authentification mutuelle** :

| Vérification | Présente dans NTLM ? | Conséquence |
|---|---|---|
| Le serveur authentifie le client | Oui (via le challenge-response) | Le serveur sait que le client connaît le mot de passe |
| Le client authentifie le serveur | **Non** | Le client ne peut pas vérifier qu'il parle au bon serveur |
| Le client authentifie le DC | **Non** | Le client fait confiance au serveur pour contacter le DC |

Cette absence d'authentification mutuelle ouvre la voie à deux attaques majeures :

- **Attaque Man-in-the-Middle (MITM)** : un attaquant se positionne entre le client et le serveur et intercepte les échanges NTLM
- **Attaque NTLM Relay** : un attaquant capture la réponse NTLM d'un client et la rejoue vers un autre serveur pour s'authentifier en tant que la victime

> **Bonne pratique** : restreindre l'utilisation de NTLM au maximum via les GPO (Group Policy) `Network security: Restrict NTLM`. Activer le signing SMB et le channel binding pour limiter les attaques relay.

### 2.4 Cas d'utilisation résiduels de NTLM

Malgré ses faiblesses, NTLM reste utilisé dans les situations suivantes :

| Scénario | Raison |
|---|---|
| **Imprimantes réseau** | Firmware ancien ne supportant pas Kerberos |
| **Scanners** | Protocoles d'authentification limités |
| **Applications legacy** | Applications internes développées pour Windows NT/2000 |
| **RDP mal configuré** | Connexion RDP utilisant une adresse IP au lieu d'un FQDN |
| **Accès par IP** | Kerberos nécessite un nom DNS, pas une adresse IP |
| **Workgroups** | Machines hors domaine sans accès au KDC |

---

## 3. Kerberos : authentification par tickets

### 3.1 Principe général

**Kerberos** est un protocole d'authentification réseau basé sur un système de **tickets** et de **clés symétriques**. Contrairement à NTLM, Kerberos assure une **authentification mutuelle** : le client authentifie le serveur et le serveur authentifie le client.

Le protocole porte le nom du chien à trois têtes de la mythologie grecque, reflétant les trois entités impliquées dans chaque transaction d'authentification.

### 3.2 Composants de Kerberos

| Composant | Rôle | Localisation |
|---|---|---|
| **Client** | Utilisateur ou machine qui souhaite accéder à un service | Poste de travail |
| **Service** | Application réseau cible (partage de fichiers, serveur web, etc.) | Serveur membre |
| **KDC (Key Distribution Center)** | Centre de distribution de clés, autorité de confiance | Chaque Domain Controller |

Le **KDC** est installé sur chaque Domain Controller et se compose de deux sous-services :

| Sous-service du KDC | Rôle |
|---|---|
| **Authentication Server (AS)** | Authentifie l'utilisateur et délivre le **TGT** (Ticket Granting Ticket) |
| **Ticket Granting Server (TGS)** | Délivre les **Service Tickets** permettant d'accéder aux services spécifiques |

### 3.3 Service Principal Name (SPN)

Un **SPN** (Service Principal Name) est un identifiant unique qui lie un service réseau à un compte de domaine (compte de service ou compte machine). Il permet à Kerberos d'identifier de façon non ambiguë le service auquel le client souhaite accéder.

Format d'un SPN :

```
service_class/hostname:port/service_name
```

Exemples :

```
HTTP/webserver01.corp.local          # Serveur web IIS
MSSQLSvc/sqlserver.corp.local:1433   # Instance SQL Server
HOST/dc01.corp.local                 # Services génériques du DC
```

Pour lister les SPN enregistrés dans le domaine :

```powershell
# Lister tous les SPN du domaine
setspn -T corp.local -Q */*

# Lister les SPN d'un compte spécifique
setspn -L svc_sql
```

### 3.4 Gestion des clés dans Kerberos

Kerberos utilise exclusivement le **chiffrement symétrique**. Le KDC stocke les clés secrètes (dérivées des mots de passe) de tous les comptes du domaine :

| Clé | Dérivée de | Stockée par |
|---|---|---|
| **Clé client** | Hash du mot de passe de l'utilisateur | KDC + client (dérivé à la volée) |
| **Clé TGS** | Hash du mot de passe du compte `krbtgt` | KDC uniquement |
| **Clé service** | Hash du mot de passe du compte de service | KDC + service |

> **À noter** : le compte **krbtgt** est un compte AD spécial dont le hash est utilisé pour chiffrer tous les TGT. Si ce hash est compromis, un attaquant peut forger des TGT arbitraires : c'est l'attaque **Golden Ticket**.

### 3.5 Flux complet d'authentification Kerberos

Le flux Kerberos complet comprend trois échanges distincts : l'authentification initiale (AS Exchange), l'obtention du ticket de service (TGS Exchange), et l'accès au service (AP Exchange).

#### Phase 1 : AS Exchange (Client <-> Authentication Server)

**Étape 1 -- Le client demande un TGT**

Le client envoie un message **AS-REQ** (Authentication Service Request) à l'Authentication Server du KDC. Ce message contient :

- Le nom d'utilisateur (principal name)
- Le nom du service TGS (demande d'un TGT)
- Un horodatage (timestamp) chiffré avec la clé dérivée du mot de passe de l'utilisateur (pré-authentification)

```
Client ──── AS-REQ ────> Authentication Server (KDC)
       (username + encrypted timestamp)
```

> **À noter** : l'étape de pré-authentification (PA-DATA) empêche un attaquant de demander un TGT pour n'importe quel utilisateur. Sans pré-authentification, il suffirait de connaître le nom d'un utilisateur pour obtenir un blob chiffré avec sa clé et tenter un brute-force hors ligne. Si la pré-authentification est désactivée sur un compte, ce compte est vulnérable à l'attaque **AS-REP Roasting**.

**Étape 2 -- Le KDC délivre le TGT**

L'Authentication Server déchiffre le timestamp avec la clé de l'utilisateur (stockée dans AD). Si le déchiffrement réussit et que le timestamp est récent, l'utilisateur est authentifié.

Le KDC génère une **TGS Session Key** aléatoire et retourne deux éléments :

| Élément | Chiffré avec | Contenu |
|---|---|---|
| **TGT** (Ticket Granting Ticket) | Clé secrète du compte `krbtgt` | TGS Session Key + identité de l'utilisateur + timestamp + durée de validité |
| **Session Message** | Clé de l'utilisateur | TGS Session Key + timestamp + durée de validité du TGT |

```
Client <──── AS-REP ──── Authentication Server (KDC)
        (TGT chiffré avec clé krbtgt + Session Message chiffré avec clé client)
```

**Étape 3 -- Le client récupère la TGS Session Key**

Le client déchiffre le **Session Message** avec sa propre clé (dérivée de son mot de passe) et récupère la **TGS Session Key**. Cette clé sera utilisée pour communiquer avec le TGS.

Le client **ne peut pas déchiffrer le TGT** car il est chiffré avec la clé du compte `krbtgt` que seul le KDC connaît. Le TGT est stocké en mémoire et présenté tel quel au TGS lors des requêtes suivantes.

#### Phase 2 : TGS Exchange (Client <-> Ticket Granting Server)

**Étape 4 -- Le client demande un Service Ticket**

Le client souhaite accéder à un service spécifique (ex. un partage de fichiers). Il envoie un message **TGS-REQ** au Ticket Granting Server contenant :

| Élément | Chiffrement | Contenu |
|---|---|---|
| **TGT** | Inchangé (chiffré avec clé krbtgt) | Présenté tel que reçu à l'étape 2 |
| **SPN du service cible** | Non chiffré | Identifie le service demandé |
| **User Authenticator** | Chiffré avec la TGS Session Key | Username + timestamp |

```
Client ──── TGS-REQ ────> Ticket Granting Server (KDC)
       (TGT + SPN + User Authenticator)
```

**Étape 5 -- Le TGS vérifie l'identité du client**

Le TGS effectue les opérations suivantes :

1. Il **déchiffre le TGT** avec la clé du compte `krbtgt` et récupère la **TGS Session Key** ainsi que l'identité de l'utilisateur
2. Il utilise la **TGS Session Key** pour **déchiffrer le User Authenticator**
3. Il compare l'identité contenue dans le User Authenticator avec celle du TGT
4. Il vérifie que le timestamp est récent (protection contre le replay)

Si toutes les vérifications sont positives, l'utilisateur est authentifié auprès du TGS.

**Étape 6 -- Le TGS délivre le Service Ticket**

Le TGS génère une **Service Session Key** aléatoire et retourne deux éléments :

| Élément | Chiffré avec | Contenu |
|---|---|---|
| **Ticket Service Message** | TGS Session Key | Service Session Key + SPN + timestamp + durée de validité |
| **Service Ticket** | Clé secrète du service (Secret Key du compte de service) | Service Session Key + identité de l'utilisateur + PAC (Privilege Attribute Certificate) |

```
Client <──── TGS-REP ──── Ticket Granting Server (KDC)
        (Ticket Service Message + Service Ticket)
```

**Étape 7 -- Le client récupère la Service Session Key**

Le client déchiffre le **Ticket Service Message** avec la **TGS Session Key** et récupère la **Service Session Key**. Le client **ne peut pas déchiffrer le Service Ticket** car il est chiffré avec la clé du service.

#### Phase 3 : AP Exchange (Client <-> Service)

**Étape 8 -- Le client s'authentifie auprès du service**

Le client envoie un message **AP-REQ** au service cible contenant :

| Élément | Chiffrement | Contenu |
|---|---|---|
| **Service Ticket** | Inchangé (chiffré avec clé du service) | Présenté tel que reçu à l'étape 6 |
| **User Authenticator** | Chiffré avec la Service Session Key | Username + timestamp |

```
Client ──── AP-REQ ────> Service
       (Service Ticket + User Authenticator)
```

**Étape 9 -- Le service authentifie le client**

Le service effectue les opérations suivantes :

1. Il **déchiffre le Service Ticket** avec sa propre clé secrète et récupère la **Service Session Key** et l'identité de l'utilisateur
2. Il utilise la **Service Session Key** pour **déchiffrer le User Authenticator**
3. Il compare les identités et vérifie le timestamp
4. Il consulte le **PAC** (Privilege Attribute Certificate) pour connaître les groupes de l'utilisateur et appliquer les autorisations

Le client est désormais **authentifié auprès du service**.

**Étape 10 -- Authentification mutuelle**

Le service renvoie un **Service Authenticator** au client, chiffré avec la **Service Session Key**. Ce message contient le timestamp du User Authenticator reçu à l'étape 8.

```
Client <──── AP-REP ──── Service
        (Service Authenticator chiffré avec Service Session Key)
```

Le client déchiffre le Service Authenticator et vérifie le timestamp. Si la vérification réussit, le client a la preuve que le service est bien celui qu'il prétend être (car seul le vrai service possède la clé pour déchiffrer le Service Ticket et récupérer la Service Session Key).

L'**authentification mutuelle est complète** : le client et le service se sont mutuellement authentifiés.

### 3.6 Résumé du flux Kerberos

```
Phase 1 : AS Exchange
  [1] Client ──── AS-REQ (username + encrypted timestamp) ────> KDC (AS)
  [2] Client <──── AS-REP (TGT + Session Message) ──────────── KDC (AS)
  [3] Client déchiffre Session Message -> TGS Session Key

Phase 2 : TGS Exchange
  [4] Client ──── TGS-REQ (TGT + SPN + Authenticator) ────> KDC (TGS)
  [5] TGS déchiffre TGT, vérifie Authenticator
  [6] Client <──── TGS-REP (Service Ticket + Ticket Service Message) ──── KDC (TGS)
  [7] Client déchiffre Ticket Service Message -> Service Session Key

Phase 3 : AP Exchange
  [8] Client ──── AP-REQ (Service Ticket + Authenticator) ────> Service
  [9] Service déchiffre Service Ticket, vérifie Authenticator -> Client authentifié
  [10] Client <──── AP-REP (Service Authenticator) ──── Service -> Authentification mutuelle
```

### 3.7 Comparaison NTLM vs Kerberos

| Critère | NTLM | Kerberos |
|---|---|---|
| **Type** | Challenge-response | Tickets + clés symétriques |
| **Authentification mutuelle** | Non | Oui |
| **Délégation** | Non native | Supportée (constrained, unconstrained, RBCD) |
| **Résistance au relay** | Faible (nécessite des protections supplémentaires) | Forte (tickets liés au service cible via SPN) |
| **Performance** | Contact du DC à chaque authentification | TGT réutilisable pendant sa durée de validité |
| **Prérequis** | Aucun (fonctionne avec IP) | DNS fonctionnel + synchronisation horaire (<5 min) |
| **Protocole par défaut** | Non (fallback) | Oui (depuis Windows 2000) |

> **Bonne pratique** : surveiller les événements NTLM dans les journaux d'événements (Event ID 4776 pour la validation NTLM) pour identifier les systèmes et applications qui utilisent encore NTLM, afin de planifier leur migration vers Kerberos.

---

## Pour aller plus loin

- [Microsoft -- Kerberos Authentication Overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview)
- [Microsoft -- NTLM Overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/ntlm-overview)
- [Microsoft -- Service Principal Names](https://learn.microsoft.com/en-us/windows/win32/ad/service-principal-names)
- [RFC 4120 -- The Kerberos Network Authentication Service (V5)](https://www.rfc-editor.org/rfc/rfc4120)
- [IETF -- NTLMv2 Authentication](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/)
- [ADSecurity.org -- Kerberos and Attacks](https://adsecurity.org/?page_id=1821)
