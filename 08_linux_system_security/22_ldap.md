# Introduction à LDAP

**Durée : 50 min**

## Ce que vous allez apprendre dans ce cours

Dans les environnements d'entreprise, gérer les utilisateurs et leurs accès sur des dizaines ou centaines de machines individuellement devient vite impraticable. LDAP permet de centraliser cette gestion. Dans cette leçon, vous apprendrez :

- ce qu'est LDAP et à quoi il sert,
- la structure d'un annuaire LDAP,
- comment effectuer des requêtes LDAP de base,
- comment configurer un client LDAP pour l'authentification.

---

## Qu'est-ce que LDAP ?

**LDAP** (Lightweight Directory Access Protocol) est un protocole pour accéder et gérer des services d'annuaire. Un annuaire est une base de données optimisée pour la lecture, stockant des informations sur des entités comme les utilisateurs, groupes, machines et services.

### Cas d'usage de LDAP

| Cas d'usage | Description |
|-------------|-------------|
| **Authentification centralisée** | Un seul compte pour se connecter à toutes les machines |
| **Gestion des groupes** | Droits d'accès basés sur l'appartenance aux groupes |
| **Carnet d'adresses** | Annuaire des employés |
| **Gestion des certificats** | Stockage et distribution de certificats PKI |
| **Configuration centralisée** | Politiques de sécurité, profils utilisateurs |

### LDAP vs bases de données relationnelles

| Aspect | LDAP | Base de données relationnelle |
|--------|------|------------------------------|
| Optimisation | Lecture | Lecture et écriture |
| Structure | Hiérarchique | Tables |
| Schéma | Flexible, extensible | Rigide |
| Requêtes | Simples, basées sur les attributs | SQL complexe |
| Réplication | Excellente | Variable |

### Implémentations LDAP

| Produit | Description |
|---------|-------------|
| **OpenLDAP** | Implémentation open source référence |
| **Active Directory** | Solution Microsoft (utilise LDAP) |
| **389 Directory Server** | Implémentation Red Hat |
| **ApacheDS** | Implémentation Java Apache |
| **FreeIPA** | Solution intégrée Red Hat (LDAP + Kerberos) |

---

## Structure de l'annuaire LDAP

### L'arbre DIT (Directory Information Tree)

L'annuaire LDAP est organisé en arbre hiérarchique :

```
                    dc=example,dc=com
                           |
         +-----------------+------------------+
         |                 |                  |
    ou=People         ou=Groups         ou=Computers
         |                 |                  |
    +----+----+       +----+----+        +----+
    |         |       |         |        |
uid=alice  uid=bob  cn=admins cn=devs  cn=server1
```

### Composants de nommage

| Composant | Nom complet | Description | Exemple |
|-----------|-------------|-------------|---------|
| **dc** | Domain Component | Composant du domaine | `dc=example,dc=com` |
| **ou** | Organizational Unit | Unité organisationnelle | `ou=People` |
| **cn** | Common Name | Nom commun | `cn=admins` |
| **uid** | User ID | Identifiant utilisateur | `uid=alice` |
| **dn** | Distinguished Name | Nom unique complet | `uid=alice,ou=People,dc=example,dc=com` |

### DN (Distinguished Name)

Le **DN** est l'identifiant unique d'une entrée dans l'annuaire. Il se lit de l'entrée vers la racine :

```
uid=alice,ou=People,dc=example,dc=com
   ^        ^          ^         ^
   |        |          |         |
 Entrée   Parent    Domaine   TLD
```

### Entrées et attributs

Chaque entrée a des **attributs** définis par des **classes d'objets** :

```ldif
dn: uid=alice,ou=People,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: alice
cn: Alice Martin
sn: Martin
givenName: Alice
mail: alice@example.com
uidNumber: 1001
gidNumber: 1001
homeDirectory: /home/alice
loginShell: /bin/bash
userPassword: {SSHA}hashDuMotDePasse...
```

### Classes d'objets courantes

| Classe | Description | Attributs principaux |
|--------|-------------|---------------------|
| `inetOrgPerson` | Personne dans une organisation | cn, sn, mail, telephoneNumber |
| `posixAccount` | Compte Unix | uid, uidNumber, gidNumber, homeDirectory |
| `posixGroup` | Groupe Unix | cn, gidNumber, memberUid |
| `organizationalUnit` | Unité organisationnelle | ou, description |

---

## Opérations LDAP de base

### Outils en ligne de commande

```bash
# Installer les outils LDAP
$ sudo apt install ldap-utils
```

### Recherche (Search)

```bash
# Recherche de base
$ ldapsearch -x -H ldap://ldap.example.com -b "dc=example,dc=com" "(uid=alice)"

# Options courantes
# -x : authentification simple
# -H : URI du serveur LDAP
# -b : base de recherche (Base DN)
# -D : DN pour le bind (authentification)
# -W : demander le mot de passe
# -LLL : sortie LDIF simplifiée
```

### Filtres de recherche

| Filtre | Description |
|--------|-------------|
| `(uid=alice)` | Égalité |
| `(uid=a*)` | Commence par "a" |
| `(uidNumber>=1000)` | Supérieur ou égal |
| `(&(objectClass=person)(uid=alice))` | ET logique |
| `(\|(uid=alice)(uid=bob))` | OU logique |
| `(!(uid=alice))` | Négation |

### Exemples de recherches

```bash
# Tous les utilisateurs
$ ldapsearch -x -H ldap://ldap.example.com \
  -b "ou=People,dc=example,dc=com" "(objectClass=posixAccount)"

# Un utilisateur spécifique
$ ldapsearch -x -H ldap://ldap.example.com \
  -b "dc=example,dc=com" "(uid=alice)" cn mail uidNumber

# Membres d'un groupe
$ ldapsearch -x -H ldap://ldap.example.com \
  -b "ou=Groups,dc=example,dc=com" "(cn=admins)" memberUid

# Recherche avec authentification
$ ldapsearch -x -H ldap://ldap.example.com \
  -D "cn=admin,dc=example,dc=com" -W \
  -b "dc=example,dc=com" "(uid=alice)"
```

### Ajout (Add)

```bash
# Fichier LDIF pour ajouter un utilisateur
$ cat nouveau_user.ldif
dn: uid=bob,ou=People,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: bob
cn: Bob Dupont
sn: Dupont
mail: bob@example.com
uidNumber: 1002
gidNumber: 1002
homeDirectory: /home/bob
loginShell: /bin/bash
userPassword: {SSHA}motdepasse_hashe

# Ajouter l'entrée
$ ldapadd -x -H ldap://ldap.example.com \
  -D "cn=admin,dc=example,dc=com" -W -f nouveau_user.ldif
```

### Modification (Modify)

```bash
# Fichier LDIF pour modifier
$ cat modification.ldif
dn: uid=alice,ou=People,dc=example,dc=com
changetype: modify
replace: mail
mail: alice.martin@example.com
-
add: telephoneNumber
telephoneNumber: +33 1 23 45 67 89

# Appliquer la modification
$ ldapmodify -x -H ldap://ldap.example.com \
  -D "cn=admin,dc=example,dc=com" -W -f modification.ldif
```

### Suppression (Delete)

```bash
# Supprimer une entrée
$ ldapdelete -x -H ldap://ldap.example.com \
  -D "cn=admin,dc=example,dc=com" -W "uid=bob,ou=People,dc=example,dc=com"
```

---

## Configurer un client LDAP

### Installation des packages

```bash
# Debian/Ubuntu
$ sudo apt install libnss-ldapd libpam-ldapd

# Configuration interactive
$ sudo dpkg-reconfigure libnss-ldapd
$ sudo dpkg-reconfigure libpam-ldapd
```

### Configuration NSS (/etc/nsswitch.conf)

NSS (Name Service Switch) détermine où le système cherche les informations utilisateurs :

```bash
# /etc/nsswitch.conf
passwd:         files ldap
group:          files ldap
shadow:         files ldap
```

### Configuration nslcd (/etc/nslcd.conf)

```bash
# /etc/nslcd.conf
uid nslcd
gid nslcd

# URI du serveur LDAP
uri ldap://ldap.example.com/

# Base de recherche
base dc=example,dc=com

# Mappings
base passwd ou=People,dc=example,dc=com
base group ou=Groups,dc=example,dc=com
base shadow ou=People,dc=example,dc=com

# TLS (recommandé)
ssl start_tls
tls_reqcert demand
tls_cacertfile /etc/ssl/certs/ca-certificates.crt
```

### Configuration PAM

```bash
# /etc/pam.d/common-auth
auth    sufficient      pam_ldap.so
auth    required        pam_unix.so nullok_secure use_first_pass

# /etc/pam.d/common-account
account sufficient      pam_ldap.so
account required        pam_unix.so

# /etc/pam.d/common-session
session optional        pam_ldap.so
session required        pam_unix.so
session required        pam_mkhomedir.so skel=/etc/skel umask=0022
```

### Tester la configuration

```bash
# Redémarrer nslcd
$ sudo systemctl restart nslcd

# Vérifier qu'un utilisateur LDAP est visible
$ getent passwd alice
alice:*:1001:1001:Alice Martin:/home/alice:/bin/bash

# Tester l'authentification
$ su - alice
```

---

## Comprendre le flux d'authentification

```
+----------+    1. Login    +----------+    2. Requête    +----------+
|          | -------------> |          | ---------------> |          |
| Terminal |                |   PAM    |                  |  nslcd   |
|          | <------------- |          | <--------------- |          |
+----------+    6. Résultat +----------+    5. Réponse    +----------+
                                                               |
                                                               | 3. LDAP Search
                                                               | 4. LDAP Bind
                                                               v
                                                         +----------+
                                                         |  Serveur |
                                                         |   LDAP   |
                                                         +----------+
```

1. L'utilisateur entre ses identifiants
2. PAM demande à nslcd de vérifier l'utilisateur
3. nslcd cherche l'utilisateur dans LDAP
4. nslcd tente un bind LDAP avec le mot de passe fourni
5. Le serveur LDAP confirme ou rejette
6. L'utilisateur est authentifié ou refusé

---

## Glossaire des sigles et définitions

| Sigle/Terme | Définition |
|-------------|------------|
| **LDAP** | Lightweight Directory Access Protocol |
| **DIT** | Directory Information Tree - Arbre d'information de l'annuaire |
| **DN** | Distinguished Name - Nom unique d'une entrée |
| **RDN** | Relative Distinguished Name - Partie locale du DN |
| **dc** | Domain Component - Composant de domaine |
| **ou** | Organizational Unit - Unité organisationnelle |
| **cn** | Common Name - Nom commun |
| **uid** | User ID - Identifiant utilisateur |
| **LDIF** | LDAP Data Interchange Format - Format d'échange de données |
| **Bind** | Opération d'authentification auprès du serveur LDAP |
| **Base DN** | Point de départ pour les recherches |
| **NSS** | Name Service Switch - Commutation de services de noms |
| **PAM** | Pluggable Authentication Modules |
| **nslcd** | NSS LDAP Connection Daemon |
| **OpenLDAP** | Implémentation open source de LDAP |

---

## Récapitulatif des commandes

### Recherche

| Commande | Description |
|----------|-------------|
| `ldapsearch -x -H ldap://server -b "base" "filtre"` | Recherche de base |
| `ldapsearch -x -LLL -H ldap://server -b "base" "(uid=user)"` | Recherche simplifiée |
| `ldapsearch -x -D "bind_dn" -W -H ldap://server -b "base"` | Avec authentification |

### Modification

| Commande | Description |
|----------|-------------|
| `ldapadd -x -D "bind_dn" -W -f fichier.ldif` | Ajouter des entrées |
| `ldapmodify -x -D "bind_dn" -W -f fichier.ldif` | Modifier des entrées |
| `ldapdelete -x -D "bind_dn" -W "dn_a_supprimer"` | Supprimer une entrée |
| `ldappasswd -x -D "bind_dn" -W "dn_user"` | Changer un mot de passe |

### Client

| Commande | Description |
|----------|-------------|
| `getent passwd utilisateur` | Vérifier la résolution utilisateur |
| `getent group groupe` | Vérifier la résolution groupe |
| `id utilisateur` | Vérifier les groupes d'un utilisateur |
| `systemctl restart nslcd` | Redémarrer le service client |

### Fichiers importants

| Fichier | Description |
|---------|-------------|
| `/etc/ldap/ldap.conf` | Configuration client LDAP globale |
| `/etc/nslcd.conf` | Configuration du daemon nslcd |
| `/etc/nsswitch.conf` | Configuration NSS |
| `/etc/pam.d/common-*` | Configuration PAM |

---

## Ressources

- OpenLDAP Administrator's Guide - openldap.org
- LDAP for Rocket Scientists - zytrax.com
- RFC 4511 - LDAP Protocol
- Red Hat Identity Management Guide

### Ressources pratiques - TryHackMe / HackTheBox

| Plateforme | Room/Lab | Description |
|------------|----------|-------------|
| TryHackMe | [Attacktive Directory](https://tryhackme.com/room/dvattacktivedirectory) | Attaques sur AD/LDAP |
| TryHackMe | [Breaching Active Directory](https://tryhackme.com/room/dvbreachingad) | Techniques d'intrusion AD |
| TryHackMe | [LDAP Injection](https://tryhackme.com/room/dvldapinjection) | Injection LDAP |
| HackTheBox | [Machines AD](https://app.hackthebox.com/machines) | Scénarios Active Directory |
