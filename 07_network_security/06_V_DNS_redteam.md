# DNS en red team - version simplifiée

## L'idée en une phrase

Le DNS est un outil précieux pour les attaquants : il est rarement bloqué, permet de découvrir l'infrastructure d'une cible, et peut servir à cacher des communications malveillantes.

---

## Pourquoi le DNS intéresse-t-il les attaquants ?

| Raison | Explication |
|--------|-------------|
| Rarement bloqué | Le DNS est essentiel, donc les firewalls le laissent passer |
| Révèle l'infrastructure | Sous-domaines, serveurs mail, VPN, environnements de dev... |
| Peut cacher du trafic | Il est possible d'encapsuler des données dans les requêtes DNS |

---

## 1. Reconnaissance : découvrir l'infrastructure

### Transfert de zone (AXFR)

**Le principe** : normalement, le transfert de zone sert à synchroniser les serveurs DNS. Mais si la configuration est incorrecte, un attaquant peut récupérer TOUTE la liste des sous-domaines.

**Analogie** : demander à un annuaire de fournir la liste complète de tous ses abonnés au lieu d'un seul numéro.

```bash
# Tester si le transfert de zone est autorisé
dig axfr cible.com @ns1.cible.com
```

**Si cela fonctionne**, tout est révélé : les serveurs, les sous-domaines, les IPs internes...

### Énumération de sous-domaines

Même si le transfert de zone est bloqué, des sous-domaines peuvent être trouvés autrement :

| Méthode | Comment cela fonctionne | Détectabilité |
|---------|-------------------|---------------|
| **Bruteforce** | Tester une liste de noms communs (dev, admin, test...) | Visible (beaucoup de requêtes) |
| **Passive DNS** | Chercher dans des bases historiques | Invisible (pas de requête vers la cible) |
| **Certificats SSL** | Regarder les certificats émis | Invisible |

**Outils courants** :
- subfinder, amass : énumération passive
- gobuster, fierce : bruteforce actif

### Sous-domaines intéressants à chercher

| Pattern | Pourquoi c'est intéressant |
|---------|---------------------------|
| dev, test, staging | Environnements moins sécurisés |
| admin, panel | Interfaces d'administration |
| vpn, remote | Points d'entrée |
| api, api-v1 | Endpoints API |
| jenkins, gitlab | Outils DevOps (souvent vulnérables) |

---

## 2. DNS Tunneling : cacher des données

### Le principe

Des données sont cachées dans les requêtes DNS pour :
- Exfiltrer des informations (voler des données)
- Communiquer avec un malware (C2 - Command & Control)
- Contourner les portails captifs (WiFi d'hôtel, aéroport...)

### Comment cela fonctionne-t-il ?

```
Machine infectée                    Serveur de l'attaquant
       |                                    |
       |  Requête : ZXhmaWx0cmF0ZWQ.evil.com
       |  (données cachées en base64)       |
       |----------------------------------->|
       |                                    |
       |  Réponse : TXT "Y29tbWFuZA=="     |
       |  (commande encodée)                |
       |<-----------------------------------|
```

**Analogie** : envoyer un message secret en le cachant dans l'adresse d'une lettre. Le facteur (serveur DNS) transporte le message sans connaître son contenu.

### Signes de DNS tunneling

| Indicateur | Pourquoi c'est suspect |
|------------|----------------------|
| Sous-domaines très longs | Données encodées (>30 caractères) |
| Beaucoup de requêtes DNS | Bien plus que la normale |
| Requêtes vers domaines bizarres | Domaines récemment créés |
| Pattern régulier (beacon) | Le malware "ping" toutes les X minutes |

---

## 3. DNS Spoofing : mentir sur les réponses

### Le principe

L'attaquant intercepte une requête DNS et répond avec une fausse adresse IP.

```
Victime : "google.com, quelle IP ?"
Attaquant (avant le vrai serveur) : "C'est 185.evil.evil.1 !"
La victime va sur le faux site en pensant être sur Google.
```

### Conséquences

- **Phishing** : la victime va sur un faux site et donne ses identifiants
- **Man-in-the-Middle** : l'attaquant intercepte tout le trafic
- **Malware** : la victime télécharge un faux logiciel infecté

### Protection : DNSSEC

DNSSEC ajoute une signature cryptographique aux réponses DNS.

**Analogie** : un cachet officiel sur un document. Si le cachet manque ou est faux, le document n'est pas authentique.

---

## 4. DNS pour le Command & Control (C2)

### Pourquoi les malwares utilisent-ils le DNS ?

| Avantage | Explication |
|----------|-------------|
| Passe les firewalls | Port 53 rarement bloqué |
| Difficile à détecter | Se mélange au trafic normal |
| Résilient | Peut changer de domaines automatiquement (DGA) |

### DGA : Domain Generation Algorithm

Le malware génère des noms de domaine différents chaque jour :

```
Jour 1 : xk2m3n4o.com
Jour 2 : 9p8q7r6s.com
Jour 3 : a1b2c3d4.com
```

L'attaquant enregistre ces domaines à l'avance et le malware sait lesquels contacter.

**Problème pour la défense** : difficile de bloquer des domaines qui n'existent pas encore.

---

## 5. Comment se défendre ?

### Surveiller le DNS

| Quoi surveiller | Pourquoi |
|-----------------|----------|
| Volume de requêtes | Pic anormal = potentiel tunneling |
| Domaines inhabituels | Domaines récents, noms aléatoires |
| Longueur des requêtes | Sous-domaines >30 caractères = suspect |
| Patterns temporels | Requêtes régulières = beacon malware |

### Techniques de protection

| Technique | Fonction |
|-----------|----------------|
| **DNS Sinkhole** | Redirige les domaines malveillants vers un serveur interne |
| **DNSSEC** | Vérifie l'authenticité des réponses |
| **DoH/DoT** | Chiffre les requêtes DNS |
| **Proxy DNS interne** | Force tout le trafic DNS par un point central |
| **Threat Intelligence** | Listes de domaines malveillants connus |

### Bloquer le transfert de zone

```
# Configuration BIND pour n'autoriser que les secondaires
allow-transfer { 192.168.1.2; 192.168.1.3; };
# Ou pour tout bloquer :
allow-transfer { none; };
```

---

## Les termes à retenir

| Terme | Définition simple |
|-------|------------------|
| **AXFR** | Transfert de zone DNS (donne tous les enregistrements) |
| **DNS Tunneling** | Cacher des données dans les requêtes DNS |
| **DNS Spoofing** | Donner de fausses réponses DNS |
| **C2** | Command & Control - serveur qui contrôle les malwares |
| **DGA** | Algorithme qui génère des domaines aléatoires |
| **Sinkhole** | Rediriger les domaines malveillants vers un piège |
| **DNSSEC** | Signature cryptographique des réponses DNS |
| **Beacon** | Signal régulier envoyé par un malware à son C2 |

---

## Résumé en 30 secondes

1. **Reconnaissance** : le DNS révèle l'infrastructure (sous-domaines, serveurs...)
2. **Tunneling** : des données peuvent être cachées dans les requêtes DNS
3. **Spoofing** : donner de fausses réponses pour rediriger les victimes
4. **C2** : les malwares utilisent le DNS car il est rarement bloqué
5. **Défense** : surveiller, filtrer, utiliser DNSSEC

---

## Outils à connaître

### Pour l'attaque (red team)

| Outil | Usage |
|-------|-------|
| dig, host | Requêtes DNS manuelles |
| subfinder, amass | Énumération de sous-domaines |
| dnscat2 | Tunneling et C2 via DNS |
| responder | Spoofing DNS/LLMNR local |

### Pour la défense (blue team)

| Outil | Usage |
|-------|-------|
| passivedns | Capture des résolutions |
| pi-hole | Filtrage DNS et sinkhole |
| zeek (bro) | Analyse de trafic DNS |
| dnstwist | Détection de typosquatting |
