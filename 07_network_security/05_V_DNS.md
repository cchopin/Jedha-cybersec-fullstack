# Le DNS - Version Simplifiée

## L'idée en une phrase

Le DNS est l'annuaire d'Internet : il traduit les noms (google.com) en adresses IP (142.250.74.110) parce que les humains retiennent mal les chiffres.

---

## Pourquoi est-ce important ?

Sans DNS, il faudrait taper `142.250.74.110` au lieu de `google.com`. Retenir l'adresse IP de chaque site visité serait impossible !

---

## Comment cela fonctionne-t-il ?

### Version ultra-simplifiée

```
Utilisateur : "Connexion à google.com"
DNS : "google.com = 142.250.74.110"
Utilisateur : "Merci !" → connexion à 142.250.74.110
```

### Version un peu plus détaillée

1. L'utilisateur tape google.com dans le navigateur
2. Le PC demande au serveur DNS : "Quelle est l'IP de google.com ?"
3. Le serveur DNS cherche la réponse (il demande à d'autres serveurs si nécessaire)
4. Il répond : "C'est 142.250.74.110"
5. Le navigateur se connecte à cette IP

---

## La hiérarchie DNS : une pyramide inversée

Le DNS est organisé comme un arbre, de la racine vers les feuilles :

```
                    . (racine)
                    |
        +-----------+-----------+
        |           |           |
       com         org         fr      ← TLD (domaine de 1er niveau)
        |           |           |
     google    wikipedia    gouv      ← Domaine
        |
       www                            ← Sous-domaine
```

### Les niveaux

| Niveau | Exemple | Qui le gère |
|--------|---------|-------------|
| Racine (.) | Le "." invisible à la fin | 13 serveurs mondiaux |
| TLD | .com, .fr, .org | Registres (Verisign, AFNIC...) |
| Domaine | google, wikipedia | Le propriétaire du domaine |
| Sous-domaine | www, mail, api | Le propriétaire du domaine |

### Lecture d'une URL

```
     mail.support.example.com
     ─┬──  ───┬───  ──┬───  ─┬─
      │       │       │      │
      │       │       │      └─ TLD
      │       │       └──────── Domaine
      │       └──────────────── Sous-domaine
      └──────────────────────── Sous-sous-domaine
```

La lecture s'effectue de **droite à gauche** !

---

## Les types d'enregistrements DNS

### Les plus courants

| Type | Utilité | Exemple |
|------|----------------|---------|
| **A** | Nom → IP (v4) | google.com → 142.250.74.110 |
| **AAAA** | Nom → IP (v6) | google.com → 2a00:1450:... |
| **MX** | Serveurs mail | Où envoyer les emails pour @gmail.com |
| **CNAME** | Alias | www.example.com → example.com |
| **NS** | Serveurs DNS | Qui connaît les infos de ce domaine |
| **TXT** | Texte libre | Vérification, anti-spam (SPF, DKIM) |

### Analogie avec l'annuaire

| Enregistrement | Équivalent annuaire |
|----------------|---------------------|
| A | Numéro de téléphone fixe |
| AAAA | Numéro de téléphone mobile |
| MX | Adresse postale pour le courrier |
| CNAME | "Voir aussi" (renvoi vers une autre entrée) |

---

## Le cache DNS : pour aller plus vite

Chaque réponse DNS est gardée en mémoire (cache) pendant un certain temps (TTL).

**Avantage** : pas besoin de redemander à chaque fois
**Inconvénient** : si l'IP change, il faut attendre que le cache expire

### Où est le cache ?

1. Dans le navigateur
2. Dans le système d'exploitation
3. Chez le FAI
4. Sur les serveurs DNS intermédiaires

---

## Les serveurs DNS publics

| Fournisseur | Adresse | Particularité |
|-------------|---------|---------------|
| Google | 8.8.8.8 | Le plus connu |
| Cloudflare | 1.1.1.1 | Rapide, respect vie privée |
| Quad9 | 9.9.9.9 | Bloque les sites malveillants |
| OpenDNS | 208.67.222.222 | Filtrage parental disponible |

---

## Les risques de sécurité

### Attaques courantes

| Attaque | Explication simple | Conséquence |
|---------|-------------------|-------------|
| **DNS Spoofing** | Attribution d'une fausse réponse | Redirection vers un faux site |
| **Cache Poisoning** | Empoisonnement du cache DNS | Tout le monde va sur le faux site |
| **DNS Hijacking** | Modification des paramètres DNS | Toutes les requêtes sont détournées |
| **DNS Tunneling** | Dissimulation de données dans les requêtes DNS | Exfiltration de données, malware |

### Analogie : l'annuaire truqué

Une personne modifie l'annuaire pour mettre son propre numéro à la place de celui de la banque. Lors de l'appel à "la banque", la communication est interceptée par l'escroc.

---

## Les protections

### DNSSEC

Signature cryptographique des réponses DNS.

**Analogie** : un tampon officiel sur un document. Si le tampon manque ou est faux, le document n'est pas authentique.

### DNS chiffré (DoH, DoT)

| Protocole | Port | Description |
|-----------|------|-------------|
| DNS classique | 53 | En clair, visible par tous |
| DoT (DNS over TLS) | 853 | Chiffré, mais port identifiable |
| DoH (DNS over HTTPS) | 443 | Chiffré et caché parmi le trafic web |

---

## Commandes utiles

```bash
# Interroger le DNS (Linux/Mac)
dig example.com
dig MX example.com        # Serveurs mail
dig +short example.com    # Juste l'IP

# Version simple
nslookup example.com
host example.com

# Résolution inverse (IP → nom)
dig -x 8.8.8.8

# Utiliser un serveur DNS spécifique
dig @8.8.8.8 example.com

# Vider le cache DNS (Windows)
ipconfig /flushdns

# Vider le cache DNS (Linux)
sudo systemd-resolve --flush-caches
```

---

## Le DNS en pentest

### Reconnaissance passive

- Trouver tous les sous-domaines d'une cible
- Identifier les serveurs (mail, web, API...)
- Historique des changements DNS

### Transfert de zone (AXFR)

Si mal configuré, il est possible de récupérer TOUTE la zone DNS d'un domaine :

```bash
dig axfr example.com @ns1.example.com
```

**Résultat** : la liste complète des serveurs, sous-domaines, IPs...

---

## Les termes à retenir

| Terme | Définition simple |
|-------|------------------|
| **DNS** | Traduit les noms en adresses IP |
| **TLD** | Extension du domaine (.com, .fr) |
| **A record** | Associe un nom à une IPv4 |
| **MX record** | Indique les serveurs mail |
| **CNAME** | Alias vers un autre nom |
| **TTL** | Durée de vie en cache |
| **DNSSEC** | Authentification des réponses DNS |
| **DoH/DoT** | DNS chiffré |

---

## Résumé en 30 secondes

1. **DNS** = annuaire qui traduit les noms en IP
2. Hiérarchie : racine → TLD → domaine → sous-domaine
3. **Types principaux** : A (IPv4), AAAA (IPv6), MX (mail), CNAME (alias)
4. **Cache** = réponses gardées en mémoire (TTL)
5. **Risques** : spoofing, poisoning, hijacking
6. **Protections** : DNSSEC, DoH, DoT

---

## Pour aller plus loin

- **Wireshark** : voir les requêtes DNS en temps réel
- **subfinder, amass** : trouver les sous-domaines
- **dnsviz.net** : visualiser la chaîne DNSSEC
