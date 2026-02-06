# Rapport d'incident - Serveur [SERVEUR] ([NDD])

**Date du rapport :** 2026-02-06
**Statut :** NETTOYAGE EFFECTUÉ - SÉCURISATION EN COURS

---

## 1. Résumé exécutif

Le serveur `[SERVEUR]` (Intel N100, Ubuntu, 16 Go RAM) hébergeant le site [NDD] est compromis depuis **au minimum le 5 décembre 2025** (soit ~2 mois). Deux campagnes de malware distinctes ont été identifiées :

1. **Cryptominer XMRig** (depuis le 5 déc 2025) - minage de Monero
2. **Botnet Mirai (variante)** (depuis le 3 fév 2026) - attaques DDoS sortantes

Le vecteur d'entrée est l'**application Strapi CMS** avec sa configuration par défaut, présentant plusieurs points d'amélioration sécurité.

---

## 2. Vecteur d'entrée : Comment l'attaquant est entré

### 2.1 Vecteur principal identifié : Strapi CMS (strapi.[NDD])

L'application **Strapi v5.19.0** présente de multiples vulnérabilités critiques qui ont permis la compromission :

#### CRITIQUE : Inscription publique ouverte
- L'endpoint `POST /api/auth/local/register` est ouvert à tous
- Aucune vérification d'email, aucun CAPTCHA, aucun rate-limiting
- Les comptes sont auto-confirmés (`confirmed: true`) immédiatement
- N'importe qui peut obtenir un JWT valide en quelques secondes

#### CRITIQUE : Secrets exposés dans le fichier .env
Le fichier `/var/www/cms-strapi/cms/.env` contient en clair :

| Secret | Impact |
|--------|--------|
| `ADMIN_JWT_SECRET` | Permet de **forger des tokens admin** sans connaître le mot de passe |
| `JWT_SECRET` | Permet de forger des tokens pour n'importe quel utilisateur |
| `API_TOKEN_SALT` | Permet de dériver les tokens API |
| `TRANSFER_TOKEN_SALT` | Accès à l'API de transfert de données Strapi |
| `APP_KEYS` | Clés de session de l'application |

#### CRITIQUE : Panneau admin exposé sans restriction
- `https://strapi.[NDD]/admin` est accessible depuis tout internet
- Aucune restriction IP dans nginx
- Aucune authentification supplémentaire (HTTP Basic Auth, VPN, etc.)
- Proxy nginx direct sans filtrage :
  ```nginx
  location / {
      proxy_pass http://127.0.0.1:1337;
  }
  ```

#### HAUTE : Strapi écoute sur 0.0.0.0
- Le port 1337 est bind sur toutes les interfaces
- Si un trou dans le firewall existe (et il n'y a PAS de firewall), Strapi est accessible directement

#### HAUTE : Firewall non configuré
- iptables et nftables sont en configuration par défaut
- Les ports applicatifs sont accessibles depuis l'extérieur (y compris NetData sur 19999)

### 2.2 Vecteur secondaire : Strapi (déc. 2025, première compromission)

L'IP `103[.]151[.]172[.]73` a tenté un `POST /api/content-manager/relations/upload` avec referer `strapi.[NDD]/admin` le 25 janvier (réponse 405). Cela suggère que la **première compromission de décembre 2025** (cryptominer) a pu passer par Strapi, dont l'admin est exposé sans protection. Les logs de décembre ne sont plus disponibles pour confirmer.

### 2.3 Vecteur principal confirmé par les logs : Next.js Server Actions (fév. 2026)

L'analyse des logs nginx révèle une **attaque coordonnée massive ciblant les Server Actions de Next.js** via des requêtes `POST /`.

```
1. Reconnaissance (22-28 jan) : scanners Assetnote fingerprint Next.js
       |
2. Probing (22-27 jan) : IP 193[.]142[.]147[.]209 envoie ~27 POST / par jour
       |
3. Première exploitation (28 jan) : IP 195[.]3[.]222[.]78 déclenche des erreurs 500
   sur POST / -- le payload atteint le code applicatif Next.js
       |
4. Escalade (3-5 fév) : IP 193[.]142[.]147[.]209 passe à 4,004 req/jour
   coordonné avec ~320 autres IPs botnet
       |
5. Déploiement botnet (6 fév 07:00) : processus /x86_64.kok lancés
       |
6. Dernière vague (6 fév 11:46) : IP 87[.]121[.]84[.]24 déclenche 46 erreurs 500
```

**Preuves dans les logs :**
- 73 erreurs HTTP 500 sur `POST /` -- le payload Next.js Server Actions crashe l'app
- 8,979 requêtes depuis `193[.]142[.]147[.]209` (IP principale de l'attaque)
- Rotation de User-Agent (Chrome, Firefox, Safari, Android, iOS) pour évader la détection
- Séquence fixe de 6 endpoints testés : `POST /`, `POST /_next`, `POST /api`, `POST /_next/server`, `POST /app`, `POST /api/route`
- Scanner Assetnote utilisé pour le fingerprinting préalable

**IPs attaquantes principales :**

| IP | Requêtes | Rôle |
|----|----------|------|
| `193[.]142[.]147[.]209` | 8,979 | Coordinateur principal |
| `195[.]3[.]222[.]218` | 2,463 | Nœud botnet |
| `144[.]172[.]114[.]199` | 2,100 | Nœud botnet |
| `15[.]204[.]132[.]49` | 1,512 | Nœud botnet (OVH) |
| `195[.]3[.]222[.]78` | 622 | **Première exploitation réussie** (500 le 28 jan) |
| `87[.]121[.]84[.]24` | 226 | Dernière exploitation active (500 le 6 fév) |
| `104[.]219[.]238[.]86` | 727 | Scanner SSRF/LFI agressif |
| `103[.]151[.]172[.]73` | - | Tentative exploit Strapi upload |

**Autres attaques détectées dans les logs (non liées, opportunistes) :**
- SSRF vers AWS/GCP metadata (`169[.]254[.]169[.]254`, `metadata[.]google[.]internal`)
- LFI : `?file=../../../../etc/passwd`
- Path traversal : `/../.env`, `/%2e%2e%2f.env`
- Shellshock dans User-Agent
- Mozi botnet (`setup.cgi?cmd=rm+-rf+/tmp/*;wget+...Mozi.m`)
- ThinkPHP RCE
- Chasse aux shells PHP/WordPress (50+ noms testés)

### 2.4 Preuves excluant les autres vecteurs

- **SSH :** Aucun login suspect dans `last`. Seuls `[USER1]` depuis [IP_INTERNE] et `[USER2]` depuis [IP_ADMIN].
- **SSRF/LFI :** Les tentatives ont toutes retourné la page normale (200, ~5456 octets). Non exploitées.
- **Accès physique :** Exclu par les timestamps et la nature des malwares.

### 2.5 Pourquoi le malware tourne sous nextjs-app

Le service systemd `nextjs-app.service` exécute Next.js sous l'utilisateur `nextjs-app`. Les processus malveillants sont dans le même CGroup systemd. L'exploitation des Server Actions de Next.js permet l'exécution de code directement dans le processus Node.js, donc sous l'utilisateur `nextjs-app`.

---

## 3. Timeline de la compromission

### Première compromission : Cryptominer (5 décembre 2025)

| Horodatage | Événement |
|------------|-----------|
| 2025-12-05 09:48 | `.profile` modifié dans `/var/www/webserver-next/` (persistance) |
| 2025-12-05 10:02 | Répertoire `c3pool/` créé avec xmrig + config + miner.sh |
| 2025-12-05 10:09 | `config_background.json` créé (config mining en arrière-plan) |
| 2025-12-05 10:19 | `sex.sh` déposé (script d'installation du cryptominer) |
| 2025-12-05 11:20 | `kal.tar.gz` téléchargé (archive XMRig 6.24.0 renommée) |
| 2025-12-05 ~ 2025-12-11 | Minage actif pendant ~6 jours, 16,894 shares acceptés |

**Pools de minage :**
- `pool[.]hashvault[.]pro:443` (via sex.sh)
- `auto[.]c3pool[.]org:80` (via c3pool/miner.sh)

**Wallets Monero :**
- `89ASvi6ZBHXE6ykUZZFtqE1QqVhmwxCDCUvW2jvGZy1yP6n34uNdMKYj54ck81UC87KAKLaZT2L4YfC85ZCePDVeQPWoeAq`
- `44VvVLU2Vmja6gTMbhNHAzc7heYTiT7VmQEXkjdaYo6K41WqH8qWw1CL8wKAAgz5xLYT3XL3pb9KCUZS7PPZbzUGCCpZ9Ee`

### Deuxième compromission : Botnet Mirai (janvier-février 2026)

| Horodatage | Événement |
|------------|-----------|
| 2026-01-28 06:42 | Binaire `lrt` déposé (1.3 Mo, UPX-packed ELF) dans `/dev/shm/` |
| 2026-02-03 23:26 | `x86_32.kok.1` déposé dans `/tmp/` (botnet 32-bit, 107 Ko) |
| 2026-02-03 23:28 | `logic.sh` déposé (dropper multi-méthode, 10 Ko) |
| 2026-02-06 07:00 | Binaires botnet reconstitués : `.bins`, `.b_aa` à `.b_ah`, `.x` |
| 2026-02-06 07:01 | Processus `/x86_64.kok` lancés (3 PIDs), persistance `.monitor` |
| 2026-02-06 07:01+ | Attaques DDoS (SYN flood) en cours depuis le serveur |

---

## 4. Inventaire des malwares

### 4.1 Botnet Mirai (variante)

| Fichier | Taille | Type | Description |
|---------|--------|------|-------------|
| `/tmp/x86_32.kok.1` | 107,508 o | ELF 32-bit x86 statique | Binaire botnet principal (copie) |
| `/tmp/x86_32.kok` | 0 o | Vide | Binaire vide après exécution |
| `/tmp/.b_aa` | 150,000 o | ELF 32-bit ARM | Payload architecture ARM |
| `/tmp/.b_ab` à `.b_ag` | 150,000 o chaque | data | Fragments binaires multi-arch |
| `/tmp/.b_ah` | 492 o | script | Fragment final / loader |
| `/tmp/.bins` | 1,050,492 o | ELF 32-bit ARM | Archive binaires botnet |
| `/tmp/.x` | 492 o | script | Script exécution |
| `/tmp/logic.sh` | 10,104 o | Shell script | Dropper principal (30+ méthodes de DL) |
| `/var/tmp/.monitor` | 76 o | Shell script | Boucle de persistance (relance /60s) |
| `/tmp/.b_ae`, `/tmp/.b_af` | 150,000 o | data | Binaires additionnels |

**C2 (Command & Control) :** `91[.]92[.]243[.]113:235` (dropper), `91[.]92[.]241[.]12:6969` (C2 actif)

**SHA256 du binaire principal :** `833bca151dc3ff83cbed22b6e7e849f0ee752bac55f68e156660e4d33d17caad`

**Comportement identifié (strings analysis) :**
- Se déguise en processus système (`udhcpc`, `httpd`, `dnsmasq`, `syslogd`, etc.)
- Tue les malwares concurrents (`killall -9 .update .monitor`)
- Communication C2 via HTTP (`GET /info.json`, `POST /client`)
- Persistance via `/etc/rc2.d/S99backup*`
- Scan telnet avec credentials par défaut (`PASS guest@`)

### 4.2 Cryptominer XMRig

| Fichier | Taille | Description |
|---------|--------|-------------|
| `/var/www/webserver-next/c3pool/xmrig` | 3,411,884 o | XMRig 6.24.0-C3 (fork c3pool) |
| `/var/www/webserver-next/c3pool/miner.sh` | 299 o | Script de lancement |
| `/var/www/webserver-next/c3pool/config_background.json` | 4,340 o | Config mining arrière-plan |
| `/var/www/webserver-next/c3pool/config.json` | 2,605 o | Config mining |
| `/var/www/webserver-next/c3pool/xmrig.log` | 4,095,225 o | Logs de minage (4 Mo) |
| `/var/www/webserver-next/sex.sh` | 1,619 o | Script installateur (hashvault) |
| `/var/www/webserver-next/kal.tar.gz` | 3,522,081 o | Archive XMRig officiel |
| `/var/www/webserver-next/lrt` | 1,305,112 o | Binaire (probablement miner) |
| `/dev/shm/lrt` | 1,308,604 o | Copie en mémoire partagée |
| `/var/www/webserver-next/.profile` | 131 o | Persistance (lance miner au login) |

### 4.3 Processus malveillants actifs

```
PID 1061829  nextjs-app  /x86_64.kok          (parent botnet)
PID 1061864  nextjs-app  /x86_64.kok          (worker)
PID 1061865  nextjs-app  /x86_64.kok          (worker - "udhcpc")
```

---

## 5. Impact sur le serveur

### 5.1 Réseau
- **974 Go transmis** en 12 jours (ratio TX/RX de 360:1)
- **~30 connexions SYN-RECV** permanentes depuis 138[.]121[.]0[.]0/16 (LACNIC)
- **~137,000 interrupts/sec**, NET_TX softirq à 3.9 milliards
- **2.5 millions de SYN retransmissions** (TcpExtTCPSynRetrans)
- Le serveur participe activement à des attaques DDoS sortantes

### 5.2 CPU
- 63% user + 14.6% softirq = CPU quasi saturé
- Le softirq à 14.6% est la cause directe des ralentissements (traitement paquets réseau)
- La ventilation excessive est due à la charge CPU permanente

### 5.3 Température
- 59°C mesuré (chaud mais pas critique pour un N100)
- La ventilation accrue est cohérente avec la charge

---

## 6. Vulnérabilités identifiées

| # | Sévérité | Description |
|---|----------|-------------|
| 1 | **CRITIQUE** | Inscription publique ouverte sur Strapi |
| 2 | **CRITIQUE** | Secrets (.env) lisibles, ADMIN_JWT_SECRET exposé |
| 3 | **CRITIQUE** | Panneau admin Strapi exposé sans restriction |
| 4 | **CRITIQUE** | Firewall non configuré (iptables/nftables par défaut) |
| 5 | **HAUTE** | Strapi bind sur 0.0.0.0 (toutes interfaces) |
| 6 | **HAUTE** | NetData (port 19999) exposé publiquement |
| 7 | **HAUTE** | Aucun rate-limiting sur Strapi |
| 8 | **HAUTE** | 35 backups SQLite world-readable dans /var/lib/strapi/ |
| 9 | **HAUTE** | Token API "Full Access" configuré dans Strapi |
| 10 | **MOYENNE** | Pas de logging applicatif Strapi (détection impossible) |
| 11 | **MOYENNE** | IP interne leakée dans la config |
| 12 | **MOYENNE** | `dangerouslyAllowSVG: true` dans Next.js |

---

## 7. Recommandations de remédiation

### Immédiat (dans l'heure)
- [ ] Tuer les processus malveillants
- [ ] Supprimer tous les fichiers malveillants (cf. inventaire section 4)
- [ ] Bloquer les IPs C2 (91[.]92[.]243[.]113, 91[.]92[.]241[.]12)

### Court terme (dans la journée)
- [ ] Mettre en place un firewall (ufw/nftables)
- [ ] Désactiver l'inscription publique Strapi
- [ ] Restreindre l'accès admin Strapi par IP
- [ ] Régénérer TOUS les secrets (.env Strapi + .env Next.js)
- [ ] Changer le mot de passe admin Strapi
- [ ] Bind Strapi sur 127.0.0.1 uniquement
- [ ] Restreindre les permissions des fichiers .env (chmod 600)
- [ ] Fermer le port 19999 (NetData) de l'extérieur

### Moyen terme (dans la semaine)
- [x] ~~Auditer le contenu Strapi (articles/projets) pour du code injecté~~ **FAIT - Aucune injection trouvée**
- [ ] **PRIORITAIRE** Mettre à jour Next.js (Server Actions vuln exploitée)
- [ ] Mettre à jour Strapi
- [ ] Configurer le logging applicatif
- [ ] Mettre en place fail2ban
- [ ] Supprimer les backups SQLite excessifs
- [ ] Envisager une réinstallation complète du serveur

---

## 8. IOCs (Indicators of Compromise)

### IPs malveillantes (infrastructure)
- `91[.]92[.]243[.]113` - Serveur de distribution du botnet (port 235)
- `91[.]92[.]241[.]12` - Serveur C2 actif (port 6969)
- `138[.]121[.]0[.]0/16` - Bloc source du SYN flood entrant (LACNIC)

### IPs attaquantes (exploitation Next.js, identifiées dans les logs nginx)
- `193[.]142[.]147[.]209` - Coordinateur principal (8,979 req, escalade du 22 jan au 5 fév)
- `195[.]3[.]222[.]78` - Première exploitation réussie (erreurs 500 le 28 jan)
- `195[.]3[.]222[.]218` - Nœud botnet (2,463 req)
- `144[.]172[.]114[.]199` - Nœud botnet (2,100 req)
- `15[.]204[.]132[.]49` - Nœud botnet OVH (1,512 req)
- `45[.]194[.]92[.]35` - Nœud botnet (1,098 req)
- `87[.]121[.]84[.]24` - Exploitation active le 6 fév (46 erreurs 500)
- `104[.]219[.]238[.]86` - Scanner SSRF/LFI (727 req)
- `103[.]151[.]172[.]73` - Tentative exploit Strapi upload

### Hashes
- `833bca151dc3ff83cbed22b6e7e849f0ee752bac55f68e156660e4d33d17caad` (SHA256) - x86_32.kok.1

### Noms de fichiers
- `*.kok` (x86_64.kok, x86_32.kok, arm7.kok)
- `logic.sh`
- `.monitor`
- `.b_aa` à `.b_ah`
- `.bins`
- `.x`

### Wallets Monero
- `89ASvi6ZBHXE6ykUZZFtqE1QqVhmwxCDCUvW2jvGZy1yP6n34uNdMKYj54ck81UC87KAKLaZT2L4YfC85ZCePDVeQPWoeAq`
- `44VvVLU2Vmja6gTMbhNHAzc7heYTiT7VmQEXkjdaYo6K41WqH8qWw1CL8wKAAgz5xLYT3XL3pb9KCUZS7PPZbzUGCCpZ9Ee`

### User-Agent
- `curl/7.83.1-DEV` (utilisé par le botnet)

---

## 9. Journal du nettoyage (2026-02-06 ~11:40 UTC)

### Actions effectuées
- [x] Processus botnet tués (`kill -9` sur tous les PIDs /x86_64.kok)
- [x] Service nextjs-app stoppé puis relancé proprement
- [x] Fichiers botnet supprimés : `/tmp/.b_aa` à `.b_ah`, `/tmp/.bins`, `/tmp/.x`, `/tmp/logic.sh`, `/tmp/x86_32.kok`, `/tmp/x86_32.kok.1`
- [x] Persistance supprimée : `/var/tmp/.monitor`
- [x] Binaire mémoire partagée supprimé : `/dev/shm/lrt`
- [x] Cryptominer supprimé : `c3pool/`, `xmrig-6.24.0/`, `sex.sh`, `kal.tar.gz`, `lrt`
- [x] `.profile` restauré (contenu malveillant retiré)

### Résultats après nettoyage

| Métrique | Avant | Après | Amélioration |
|----------|-------|-------|--------------|
| CPU user | 63.4% | ~10% | -84% |
| CPU softirq | 14.6% | 0.0% | -100% |
| Interrupts/s | 137,000 | 1,500 | -99% |
| Processus malveillants | 5 | 0 | Éliminés |
| Connexions C2 | 2 | 0 | Éliminées |
| Fichiers malveillants | 20+ | 0 | Supprimés |

### Observations post-nettoyage
- Le SYN flood entrant depuis `138[.]121[.]0[.]0/16` persiste (~30 SYN-RECV) car il est initié de l'extérieur
- Nécessite un blocage firewall : `sudo iptables -I INPUT -s 138.121.0.0/16 -j DROP`
- Un fichier résiduel avec nom encodé existe dans `/tmp/` (0 octets, inoffensif)

### Actions restantes (sécurisation)
- [ ] Bloquer le bloc IP 138[.]121[.]0[.]0/16 au firewall
- [ ] Mettre en place un firewall complet (ufw/nftables)
- [ ] Sécuriser Strapi (désactiver inscription publique, restreindre admin, régénérer secrets)
- [ ] Fermer les ports exposés inutilement (19999, 1337 direct)

---

## 10. Audit du contenu Strapi (2026-02-06 ~11:50 UTC)

### Scan des injections dans la base de données

| Table | Nb entrées | Injections trouvées |
|-------|------------|---------------------|
| `ai_projects` | 49 articles | **Aucune** |
| `writing_projects` | 8 projets | **Aucune** |
| `pdf_documents` | 2 PDFs | **Aucune** |
| `files` (uploads) | 58 fichiers | **Aucune** (que des .webp, .png, 1 .pdf) |
| `strapi_webhooks` | 0 | Vide |
| `strapi_transfer_tokens` | 0 | Vide |
| `strapi_core_store_settings` | - | **Aucune injection** |

**Méthode :** Recherche exhaustive dans le dump complet de la base SQLite avec les patterns :
`<script>`, `<iframe>`, `javascript:`, `onerror=`, `eval(`, `exec(`, `system(`, `child_process`,
`spawn`, `.kok`, `91.92.`, `wget`, `curl`, `/bin/sh`, `/bin/bash`, `base64_decode`, `passthru`,
`shell_exec`, `nc -e`, `reverse.shell`, `mkfifo`

**Résultat : Le contenu éditorial est propre. L'attaquant n'a pas injecté de code dans les articles.**

### Comptes utilisateurs

| Type | Compte | Statut |
|------|--------|--------|
| Admin Strapi | [ADMIN_EMAIL] ([ADMIN_NAME]) | Actif, seul admin |
| User public | `testprobe` (probe@test.com) | Créé pendant l'audit (à supprimer) |

Aucun compte admin rogue. Aucun compte utilisateur suspect (hors testprobe).

### Permissions du rôle Public

Le rôle **Public** a les permissions suivantes (trop permissives) :
- `auth.register` -- **inscription ouverte, auto-confirmée, sans email verification**
- `auth.forgotPassword`, `auth.resetPassword`
- Lecture de tout le contenu (find/findOne sur ai-projects, writing-projects, pdf-documents)

Le rôle **Authenticated** n'a que `changePassword` et `user.me` (pas de permission d'écriture).

### Tokens API

| Token | Type | Risque |
|-------|------|--------|
| `t246f9umfuyk34pvpme50wtm` | Read Only | Faible |
| `ria151nu96f38qn2o6o9fwdt` | **Full Access** | **CRITIQUE** - lecture/écriture sur toute l'API |

### Fichiers uploadés

58 fichiers, tous des images légitimes (.webp, .png) et 1 PDF (rhaelos). **Aucun webshell.**

### Clés SSH

Aucune clé SSH déposée par l'attaquant dans les répertoires web.

### Logs

Les logs Strapi (journalctl -u strapi) et nextjs-app sont **vides** -- aucune trace.
Les logs nginx ne sont pas lisibles sans droits `adm` (nécessite `sudo usermod -aG adm [USER]`).

---
