# Sécurité LDAP

**Durée : 45 min**

## Ce que vous allez apprendre dans ce cours

LDAP est un composant critique de l'infrastructure : une compromission peut donner accès à tous les systèmes. Dans cette leçon, vous apprendrez :

- les risques de sécurité liés à LDAP,
- comment sécuriser les communications LDAP,
- les bonnes pratiques de configuration,
- comment détecter et prévenir les attaques.

---

## Risques de sécurité LDAP

### Surface d'attaque

| Vecteur | Description | Impact |
|---------|-------------|--------|
| **Écoute du trafic** | LDAP non chiffré transmet les mots de passe en clair | Vol d'identifiants |
| **Bind anonyme** | Accès sans authentification | Énumération d'utilisateurs |
| **Injection LDAP** | Manipulation des filtres de recherche | Bypass d'authentification |
| **Attaques par force brute** | Tentatives multiples de connexion | Compromission de comptes |
| **Mauvaises ACL** | Permissions trop permissives | Modification non autorisée |

### Ports LDAP

| Port | Protocole | Description |
|------|-----------|-------------|
| 389 | LDAP | Non chiffré (dangereux) |
| 636 | LDAPS | Chiffré avec TLS |
| 389 + STARTTLS | LDAP + TLS | Chiffrement opportuniste |

---

## Chiffrer les communications

### LDAPS vs STARTTLS

| Méthode | Description | Avantages | Inconvénients |
|---------|-------------|-----------|---------------|
| **LDAPS** | TLS dès la connexion | Simple, port dédié | Port supplémentaire |
| **STARTTLS** | Upgrade vers TLS | Port unique | Plus complexe |

### Configurer LDAPS sur OpenLDAP

1. **Générer ou obtenir des certificats** :

```bash
# Générer une clé privée et un CSR
$ openssl req -new -newkey rsa:4096 -nodes \
  -keyout /etc/ldap/ssl/ldap.key \
  -out /etc/ldap/ssl/ldap.csr \
  -subj "/CN=ldap.example.com"

# Signer avec votre CA ou utiliser un certificat auto-signé
$ openssl x509 -req -days 365 \
  -in /etc/ldap/ssl/ldap.csr \
  -signkey /etc/ldap/ssl/ldap.key \
  -out /etc/ldap/ssl/ldap.crt

# Permissions
$ chown openldap:openldap /etc/ldap/ssl/*
$ chmod 600 /etc/ldap/ssl/ldap.key
```

2. **Configurer OpenLDAP** :

```ldif
# tls.ldif
dn: cn=config
changetype: modify
add: olcTLSCertificateFile
olcTLSCertificateFile: /etc/ldap/ssl/ldap.crt
-
add: olcTLSCertificateKeyFile
olcTLSCertificateKeyFile: /etc/ldap/ssl/ldap.key
-
add: olcTLSCACertificateFile
olcTLSCACertificateFile: /etc/ldap/ssl/ca.crt
```

```bash
sudo ldapmodify -Y EXTERNAL -H ldapi:/// -f tls.ldif
```

3. **Activer LDAPS dans le service** :

```bash
# /etc/default/slapd
SLAPD_SERVICES="ldap:/// ldaps:/// ldapi:///"

# Redémarrer
$ sudo systemctl restart slapd
```

### Configurer le client pour TLS

```bash
# /etc/ldap/ldap.conf
URI ldaps://ldap.example.com
BASE dc=example,dc=com

TLS_CACERT /etc/ssl/certs/ca-certificates.crt
TLS_REQCERT demand

# Test
$ ldapsearch -x -H ldaps://ldap.example.com -b "dc=example,dc=com"
```

---

## Contrôler l'accès (ACL)

### Syntaxe des ACL OpenLDAP

```
access to <what>
    by <who> <access>
```

### Niveaux d'accès

| Niveau | Description |
|--------|-------------|
| `none` | Aucun accès |
| `disclose` | Révèle l'existence de l'entrée |
| `auth` | Peut s'authentifier |
| `compare` | Peut comparer des attributs |
| `search` | Peut chercher |
| `read` | Peut lire |
| `write` | Peut modifier |
| `manage` | Contrôle total |

### Exemples d'ACL

```ldif
# acl.ldif - ACL recommandées
dn: olcDatabase={1}mdb,cn=config
changetype: modify
replace: olcAccess
# Accès root complet
olcAccess: {0}to * by dn="cn=admin,dc=example,dc=com" manage
# Utilisateurs peuvent lire leur propre entrée
olcAccess: {1}to dn.base="" by * read
# Utilisateurs peuvent changer leur mot de passe
olcAccess: {2}to attrs=userPassword
  by self write
  by anonymous auth
  by * none
# Utilisateurs peuvent lire les attributs publics
olcAccess: {3}to attrs=cn,sn,mail,telephoneNumber
  by users read
  by * none
# Accès en lecture aux entrées pour les utilisateurs authentifiés
olcAccess: {4}to *
  by users read
  by * none
```

```bash
sudo ldapmodify -Y EXTERNAL -H ldapi:/// -f acl.ldif
```

### Vérifier les ACL

```bash
# Test d'accès anonyme
$ ldapsearch -x -H ldap://ldap.example.com -b "dc=example,dc=com"

# Test d'accès authentifié
$ ldapsearch -x -D "uid=alice,ou=People,dc=example,dc=com" -W \
  -H ldap://ldap.example.com -b "dc=example,dc=com"
```

---

## Désactiver le bind anonyme

Par défaut, OpenLDAP peut accepter des connexions anonymes. Pour les désactiver :

```ldif
# disable-anon.ldif
dn: cn=config
changetype: modify
add: olcDisallows
olcDisallows: bind_anon

dn: olcDatabase={-1}frontend,cn=config
changetype: modify
add: olcRequires
olcRequires: authc
```

```bash
sudo ldapmodify -Y EXTERNAL -H ldapi:/// -f disable-anon.ldif
```

---

## Politique de mots de passe

### Activer le module ppolicy

```ldif
# ppolicy-module.ldif
dn: cn=module{0},cn=config
changetype: modify
add: olcModuleLoad
olcModuleLoad: ppolicy

# ppolicy-overlay.ldif
dn: olcOverlay=ppolicy,olcDatabase={1}mdb,cn=config
objectClass: olcOverlayConfig
objectClass: olcPPolicyConfig
olcOverlay: ppolicy
olcPPolicyDefault: cn=default,ou=Policies,dc=example,dc=com
olcPPolicyHashCleartext: TRUE
olcPPolicyUseLockout: TRUE
```

### Créer une politique de mots de passe

```ldif
# Créer l'OU pour les politiques
dn: ou=Policies,dc=example,dc=com
objectClass: organizationalUnit
ou: Policies

# Politique par défaut
dn: cn=default,ou=Policies,dc=example,dc=com
objectClass: pwdPolicy
objectClass: person
cn: default
sn: default
# Longueur minimale
pwdMinLength: 12
# Historique des mots de passe (empêche réutilisation)
pwdInHistory: 5
# Durée de vie maximale (90 jours)
pwdMaxAge: 7776000
# Verrouillage après 5 échecs
pwdMaxFailure: 5
# Durée du verrouillage (30 minutes)
pwdLockoutDuration: 1800
# Fenêtre de comptage des échecs
pwdFailureCountInterval: 300
# Forcer le changement au premier login
pwdMustChange: TRUE
# Permettre à l'utilisateur de changer
pwdAllowUserChange: TRUE
# Vérifier la qualité
pwdCheckQuality: 2
```

---

## Prévention des injections LDAP

### Qu'est-ce que l'injection LDAP ?

L'injection LDAP se produit quand une application construit des requêtes LDAP avec des entrées utilisateur non validées :

```python
# Code vulnérable
username = request.get('username')
filter = f"(uid={username})"
# Si username = "alice)(uid=*" -> (uid=alice)(uid=*)
```

### Caractères dangereux

| Caractère | Signification |
|-----------|---------------|
| `*` | Wildcard |
| `(` | Début de filtre |
| `)` | Fin de filtre |
| `\` | Échappement |
| `NUL` | Fin de chaîne |
| `/` | Séparateur DN |

### Protection côté serveur

Bien que la validation doive se faire dans l'application, vous pouvez limiter les dégâts :

```ldif
# Limiter la taille des résultats
dn: olcDatabase={1}mdb,cn=config
changetype: modify
replace: olcSizeLimit
olcSizeLimit: 500

# Limiter le temps de recherche
dn: olcDatabase={1}mdb,cn=config
changetype: modify
replace: olcTimeLimit
olcTimeLimit: 60
```

### Validation côté application

```python
import ldap

def escape_filter_chars(s):
    """Échappe les caractères spéciaux pour les filtres LDAP"""
    return ldap.filter.escape_filter_chars(s)

# Utilisation sécurisée
username = escape_filter_chars(request.get('username'))
filter = f"(uid={username})"
```

---

## Surveillance et audit

### Activer les logs OpenLDAP

```ldif
# logging.ldif
dn: cn=config
changetype: modify
replace: olcLogLevel
olcLogLevel: stats stats2 sync
```

Niveaux de log utiles :

| Niveau | Description |
|--------|-------------|
| `none` | Aucun log |
| `stats` | Statistiques de connexion |
| `stats2` | Statistiques détaillées |
| `args` | Arguments des opérations |
| `sync` | Réplication |
| `-1` | Tout (debug) |

### Configurer rsyslog

```bash
# /etc/rsyslog.d/slapd.conf
local4.* /var/log/slapd.log
```

```bash
sudo systemctl restart rsyslog
```

### Surveiller les tentatives échouées

```bash
# Rechercher les échecs d'authentification
$ grep "BIND" /var/log/slapd.log | grep "err="

# Avec fail2ban
# /etc/fail2ban/filter.d/slapd.conf
[Definition]
failregex = conn=\d+ fd=\d+ ACCEPT from IP=<HOST>:\d+ \(.*\)$
            conn=\d+ op=\d+ BIND dn=".*" method=\d+$
            conn=\d+ op=\d+ RESULT tag=97 err=49 .*$
```

---

## Checklist de sécurisation LDAP

### Communication

- [ ] Activer TLS (LDAPS ou STARTTLS)
- [ ] Utiliser des certificats valides
- [ ] Désactiver le LDAP non chiffré en production

### Authentification

- [ ] Désactiver le bind anonyme
- [ ] Implémenter une politique de mots de passe
- [ ] Activer le verrouillage après échecs

### Autorisation

- [ ] Configurer des ACL restrictives
- [ ] Appliquer le principe du moindre privilège
- [ ] Séparer les comptes admin des comptes applicatifs

### Surveillance

- [ ] Activer les logs détaillés
- [ ] Configurer fail2ban
- [ ] Alertes sur les échecs d'authentification

---

## Glossaire des sigles et définitions

| Sigle/Terme | Définition |
|-------------|------------|
| **LDAPS** | LDAP over SSL/TLS - LDAP chiffré |
| **STARTTLS** | Commande pour upgrader vers TLS |
| **ACL** | Access Control List - Liste de contrôle d'accès |
| **ppolicy** | Password Policy - Politique de mots de passe LDAP |
| **Bind** | Opération d'authentification LDAP |
| **Anonymous bind** | Connexion sans authentification |
| **LDAP injection** | Attaque par injection de filtres LDAP |
| **olc** | On-Line Configuration - Configuration dynamique OpenLDAP |
| **cn=config** | Arbre de configuration OpenLDAP |

---

## Récapitulatif des commandes

### Configuration TLS

| Commande | Description |
|----------|-------------|
| `ldapsearch -x -H ldaps://server` | Test LDAPS |
| `ldapsearch -x -ZZ -H ldap://server` | Test STARTTLS |
| `openssl s_client -connect server:636` | Vérifier le certificat |

### Gestion des ACL

| Commande | Description |
|----------|-------------|
| `ldapsearch -Y EXTERNAL -H ldapi:/// -b cn=config "(olcAccess=*)"` | Voir les ACL |
| `ldapmodify -Y EXTERNAL -H ldapi:/// -f acl.ldif` | Modifier les ACL |

### Audit

| Commande | Description |
|----------|-------------|
| `ldapwhoami -x -H ldap://server` | Test de bind anonyme |
| `tail -f /var/log/slapd.log` | Suivre les logs |
| `grep "err=49" /var/log/slapd.log` | Échecs d'authentification |

### Fichiers importants

| Fichier | Description |
|---------|-------------|
| `/etc/ldap/slapd.d/` | Configuration OpenLDAP (cn=config) |
| `/etc/ldap/ssl/` | Certificats TLS |
| `/var/log/slapd.log` | Logs LDAP |
| `/etc/fail2ban/filter.d/slapd.conf` | Filtre fail2ban |

---

## Ressources

- OpenLDAP Security Considerations - openldap.org
- LDAP Injection Prevention - OWASP
- CIS Benchmark for LDAP
- NIST Guidelines for LDAP Security

### Ressources pratiques - TryHackMe / HackTheBox

| Plateforme | Room/Lab | Description |
|------------|----------|-------------|
| TryHackMe | [LDAP Injection](https://tryhackme.com/room/dvldapinjection) | Exploitation et prévention |
| TryHackMe | [Attacktive Directory](https://tryhackme.com/room/dvattacktivedirectory) | Attaques AD/LDAP |
| TryHackMe | [Post-Exploitation Basics](https://tryhackme.com/room/dvpostexploit) | Énumération LDAP post-exploit |
| HackTheBox | [Machines avec LDAP](https://app.hackthebox.com/machines) | Scénarios réalistes |
