# Rapport de Renseignement sur les Cybermenaces (CTI)

**Référence incident :** Double compromission Mirai/XMRig
**Date d'analyse :** 2026-02-06
**Classification :** TLP:CLEAR

---

## Résumé exécutif

Ce rapport CTI documente l'analyse d'attribution réalisée suite à une compromission réelle de serveur. L'investigation a identifié une **variante du botnet Mirai (EIW)** opérant via une **infrastructure d'hébergement bulletproof russe** (Virtualine Technologies), avec des serveurs Command & Control hébergés aux Pays-Bas via des fournisseurs de transit bulgares.

---

## 1. Identification du malware

### 1.1 Échantillon principal

| Attribut | Valeur |
|----------|--------|
| **SHA256** | `833bca151dc3ff83cbed22b6e7e849f0ee752bac55f68e156660e4d33d17caad` |
| **Type de fichier** | ELF 32-bit x86 statique |
| **Taille** | 107 508 octets |
| **Noms de fichiers** | `x86_32.kok`, `x86_64.kok`, `arm7.kok` |
| **Packer** | Aucun détecté (binaire statique) |

### 1.2 Détection VirusTotal (34/72)

| Éditeur | Signature |
|---------|-----------|
| ESET-NOD32 | `Linux/Mirai.EIW Trojan` |
| Fortinet | `ELF/Mirai.EIW!tr` |
| DrWeb | `Linux.Mirai.9774` |
| Kaspersky | `HEUR:Backdoor.Linux.Gafgyt.gu` |
| Microsoft | `Backdoor:Linux/Mirai.DN!MTB` |
| Tencent | `Backdoor.Linux.Mirai.ckb` |
| Avast/AVG | `ELF:Mirai-BXK [Bot]` |
| ClamAV | `Unix.Trojan.Mirai-10001386-0` |

**Non-détections notables :** CrowdStrike Falcon, Malwarebytes, McAfee

### 1.3 Classification de la famille de malware

```
Gafgyt (2014)
    |
    +-- Mirai (2016) - Code source fuité
            |
            +-- Multiples variantes (2016-présent)
                    |
                    +-- Mirai.EIW (2025-2026) <-- CET ÉCHANTILLON
                    +-- Broadside (déc 2025)
                    +-- Murdoc (jan 2025)
                    +-- CatDDoS
                    +-- V3G4
```

---

## 2. Infrastructure de Command & Control

### 2.1 Serveurs C2 identifiés

| Adresse IP | Port | Rôle | Statut |
|------------|------|------|--------|
| `91[.]92[.]241[.]12` | 6969 | C2 principal | Actif (vu le 2026-02-01) |
| `91[.]92[.]243[.]113` | 235 | Distribution du dropper | Actif |
| `91[.]92[.]241[.]10` | 80 | Téléchargement des payloads | Actif |

### 2.2 Analyse de l'infrastructure (Shodan)

**Cible : 91[.]92[.]241[.]12**

| Champ | Valeur |
|-------|--------|
| Pays | Pays-Bas |
| Ville | Amsterdam |
| Organisation | Neterra Ltd. (Bulgarie) |
| FAI | NTT America, Inc. |
| ASN | AS2914 |
| OS | Linux (Ubuntu 24.04) |
| Ports ouverts | 22/tcp (SSH) |
| Version SSH | OpenSSH 9.6p1 Ubuntu-3ubuntu13.14 |
| Dernière observation | 2026-02-01 |

### 2.3 Signification du port 6969

L'utilisation du **port TCP 6969** comme C2 est un marqueur distinctif associé à la variante Mirai **Broadside** :

- C2 principal : TCP/1026
- **C2 de secours : TCP/6969**
- Magic Header : `0x36694201`

Source : [Cydome Research - Analyse Broadside](https://cydome.io/cydome-identifies-broadside-a-new-mirai-botnet-variant-targeting-maritime-iot/)

---

## 3. Infrastructure de l'acteur de la menace

### 3.1 Chaîne d'hébergement

```
[Acteur malveillant]
      |
      v
+------------------+
| Virtualine       |  <-- Hébergement bulletproof russe
| Technologies     |      Publicité sur forums underground
+------------------+
      |
      v
+------------------+
| Railnet LLC      |  <-- Façade légale (enregistrée aux US)
| ASN 214943       |      Loue des préfixes IP
+------------------+
      |
      v
+------------------+
| Neterra Ltd.     |  <-- Fournisseur de transit bulgare
| (Transit)        |
+------------------+
      |
      v
+------------------+
| NTT America      |  <-- Opérateur Tier 1
| ASN 2914         |      Routage final
+------------------+
      |
      v
[Datacenter Amsterdam]
```

### 3.2 Profil de Virtualine Technologies

| Attribut | Détails |
|----------|---------|
| **Type** | Hébergeur bulletproof |
| **Origine** | Russie |
| **Présence forums** | Forums underground russes (alias "Secury") |
| **Façade légale** | Railnet LLC (US) |
| **Services liés** | Proxio, DripHosting, RetryHost |
| **Suivi par** | Spamhaus, Recorded Future |
| **Clients connus** | UAC-0006, divers opérateurs de botnets |

### 3.3 Sources OSINT

- [Alerte Spamhaus sur Virtualine](https://x.com/spamhaus/status/1968663056524644781) - Suivi de l'expansion
- [IPinfo AS214943](https://ipinfo.io/AS214943) - Détails de l'ASN
- [Intel Insights - Bulletproof Hosting Hunt](https://intelinsights.substack.com/p/bulletproof-hosting-hunt)

---

## 4. Analyse du dropper

### 4.1 logic.sh / logicdr.sh

Le script dropper a été analysé sur ANY.RUN :

**Échantillon :** [Rapport ANY.RUN](https://any.run/report/bf5a1e8b25d6ef368f11028fc492cc5e4a7e623a5b603a505828ae1c2e62fa3d/ea466e56-b198-4997-b76a-5b7f80caa591)

| Attribut | Valeur |
|----------|--------|
| **SHA256** | `bf5a1e8b25d6ef368f11028fc492cc5e4a7e623a5b603a505828ae1c2e62fa3d` |
| **Type** | Script shell Bash |
| **C2** | `91[.]92[.]241[.]12:6969` |
| **Serveur de téléchargement** | `91[.]92[.]241[.]10:80` |

### 4.2 Payloads téléchargés

Le dropper récupère des binaires spécifiques à chaque architecture :

```
x86_64.kok
x86_32.kok
arm.kok
arm5.kok
arm7.kok
mips.kok
mipsel.kok
powerpc.kok
```

### 4.3 Mécanismes de persistance

| Méthode | Emplacement |
|---------|-------------|
| Tâche cron | Crontab modifiée |
| Script de surveillance | `/var/tmp/.monitor` (boucle de relance 60s) |
| Script d'init | `/etc/rc2.d/S99backup*` |
| Fichiers cachés | `.bins`, `.b_aa` à `.b_ah`, `.x` |

---

## 5. Payload secondaire : Cryptominer XMRig

### 5.1 Configuration du minage

| Attribut | Valeur |
|----------|--------|
| **Mineur** | XMRig 6.24.0-C3 (fork c3pool) |
| **Algorithme** | RandomX (Monero) |
| **Pool 1** | `pool[.]hashvault[.]pro:443` |
| **Pool 2** | `auto[.]c3pool[.]org:80` |

### 5.2 Adresses de wallets

```
89ASvi6ZBHXE6ykUZZFtqE1QqVhmwxCDCUvW2jvGZy1yP6n34uNdMKYj54ck81UC87KAKLaZT2L4YfC85ZCePDVeQPWoeAq

44VvVLU2Vmja6gTMbhNHAzc7heYTiT7VmQEXkjdaYo6K41WqH8qWw1CL8wKAAgz5xLYT3XL3pb9KCUZS7PPZbzUGCCpZ9Ee
```

### 5.3 Évaluation de l'attribution

- Pools publics (pas d'infrastructure privée)
- Les wallets Monero sont anonymes par conception
- Outils communs (XMRig est open source)
- **Évaluation :** Minage opportuniste, faible confiance d'attribution

---

## 6. Mapping MITRE ATT&CK

### 6.1 Accès initial

| Technique | ID | Description |
|-----------|----|-------------|
| Exploitation d'application exposée | T1190 | Exploitation Next.js Server Actions |
| Comptes valides | T1078 | Abus de l'inscription ouverte Strapi |

### 6.2 Exécution

| Technique | ID | Description |
|-----------|----|-------------|
| Interpréteur de commandes | T1059.004 | Script shell dropper (logic.sh) |
| API native | T1106 | Exécution directe d'ELF |

### 6.3 Persistance

| Technique | ID | Description |
|-----------|----|-------------|
| Tâche planifiée | T1053.003 | Persistance via cron |
| Scripts d'initialisation | T1037 | Modification du .profile |
| Modification des processus système | T1543 | Scripts rc.d init |

### 6.4 Évasion des défenses

| Technique | ID | Description |
|-----------|----|-------------|
| Usurpation d'identité | T1036 | Usurpation de noms de processus (udhcpc, httpd) |
| Fichiers et répertoires cachés | T1564.001 | Fichiers préfixés par un point (.monitor, .bins) |
| Suppression d'indicateurs | T1070 | Auto-suppression après exécution |

### 6.5 Command and Control

| Technique | ID | Description |
|-----------|----|-------------|
| Protocole de couche application | T1071 | C2 basé sur HTTP (/info.json, /client) |
| Port non standard | T1571 | Port 6969 pour le C2 |
| Canaux de secours | T1008 | Multiples serveurs C2 |

### 6.6 Impact

| Technique | ID | Description |
|-----------|----|-------------|
| Détournement de ressources | T1496 | Cryptominage (XMRig) |
| Déni de service réseau | T1498 | Attaques DDoS (SYN flood) |

---

## 7. Évaluation de l'attribution

### 7.1 Matrice de confiance

| Élément | Attribution | Confiance |
|---------|-------------|-----------|
| Famille de malware | Variante Mirai EIW | **Élevée** (34 détections AV) |
| Infrastructure C2 | Virtualine/Railnet | **Élevée** (OSINT confirmé) |
| Origine de l'hébergement | Russie | **Élevée** (publicité sur forums) |
| Localisation physique | Pays-Bas (Amsterdam) | **Élevée** (Shodan) |
| Type de variante | Lié à Broadside | **Moyenne** (correspondance port 6969) |
| Profil des opérateurs | Cybercriminels russophones | **Moyenne** |
| Parrainage étatique | Aucun (crime organisé) | **Élevée** |

### 7.2 Profil de l'acteur de la menace

| Attribut | Évaluation |
|----------|------------|
| **Type** | Cybercriminel (non-APT) |
| **Motivation** | Financière (DDoS-as-a-Service + Cryptominage) |
| **Sophistication** | Moyenne (outils commoditisés, infra bulletproof) |
| **Langue** | Russe (présence sur forums) |
| **Opérations** | Scanning et exploitation opportunistes |

### 7.3 Ce que nous ne pouvons pas prouver

- Identités individuelles des opérateurs
- Lien direct avec des groupes criminels spécifiques
- Opérateur du cryptominer (pools publics utilisés)
- Lignée exacte de la variante Mirai

---

## 8. Indicateurs de compromission (IOCs)

### 8.1 IOCs réseau

```
# Serveurs C2
91[.]92[.]241[.]12:6969
91[.]92[.]243[.]113:235
91[.]92[.]241[.]10:80

# Bloc source DDoS
138[.]121[.]0[.]0/16

# Pools de minage
pool[.]hashvault[.]pro:443
auto[.]c3pool[.]org:80
```

### 8.2 IOCs fichiers

```
# Binaires du botnet
833bca151dc3ff83cbed22b6e7e849f0ee752bac55f68e156660e4d33d17caad (SHA256)

# Patterns de fichiers
*.kok
logic.sh
.monitor
.bins
.b_aa à .b_ah
.x
```

### 8.3 IOCs comportementaux

```
# Noms de processus (usurpation)
/x86_64.kok
udhcpc (faux)
httpd (faux)
dnsmasq (faux)

# Comportement réseau
HTTP GET /info.json
HTTP POST /client
Connexions TCP vers le port 6969
Volume élevé de paquets SYN (DDoS)
```

---

## 9. Recommandations

### 9.1 Règles de détection

**Snort/Suricata :**
```
alert tcp any any -> any 6969 (msg:"Possible Mirai C2 (port 6969)"; flow:established,to_server; sid:1000001; rev:1;)
alert http any any -> any any (msg:"Mirai C2 beacon"; content:"GET"; http_method; content:"/info.json"; http_uri; sid:1000002; rev:1;)
```

**YARA :**
```yara
rule Mirai_EIW_Variant {
    meta:
        description = "Détecte la variante Mirai.EIW"
        hash = "833bca151dc3ff83cbed22b6e7e849f0ee752bac55f68e156660e4d33d17caad"
    strings:
        $s1 = "/info.json" ascii
        $s2 = "/client" ascii
        $s3 = "udhcpc" ascii
        $s4 = ".kok" ascii
    condition:
        uint32(0) == 0x464C457F and 2 of them
}
```

### 9.2 Recommandations de blocage

```bash
# Bloquer l'infrastructure C2
iptables -A OUTPUT -d 91.92.241.0/24 -j DROP
iptables -A OUTPUT -d 91.92.243.0/24 -j DROP
iptables -A INPUT -s 138.121.0.0/16 -j DROP

# Bloquer le port C2
iptables -A OUTPUT -p tcp --dport 6969 -j DROP
```

### 9.3 Flux de renseignement sur les menaces

- [Spamhaus DROP List](https://www.spamhaus.org/drop/)
- [abuse.ch Feodo Tracker](https://feodotracker.abuse.ch/)
- [AbuseIPDB](https://www.abuseipdb.com/)

---

## 10. Références

1. [ANY.RUN - Analyse logicdr.sh](https://any.run/report/bf5a1e8b25d6ef368f11028fc492cc5e4a7e623a5b603a505828ae1c2e62fa3d/ea466e56-b198-4997-b76a-5b7f80caa591)
2. [ANY.RUN - Analyse x86_64.kok](https://any.run/report/430122ce9b795d5744234385ebfd0698d767f005cd663f6f6e9761ee1e885661/faf5b899-456f-484d-8d62-af908cfd4c09)
3. [Cydome - Variante Mirai Broadside](https://cydome.io/cydome-identifies-broadside-a-new-mirai-botnet-variant-targeting-maritime-iot/)
4. [Spamhaus - Alerte Virtualine Technologies](https://x.com/spamhaus/status/1968663056524644781)
5. [IPinfo - AS214943 Railnet LLC](https://ipinfo.io/AS214943)
6. [Qualys - Analyse du botnet Murdoc](https://blog.qualys.com/vulnerabilities-threat-research/2025/01/21/mass-campaign-of-murdoc-botnet-mirai-a-new-variant-of-corona-mirai)
7. [Cloudflare - Aperçu du botnet Mirai](https://www.cloudflare.com/learning/ddos/glossary/mirai-botnet/)
8. [USENIX - Understanding the Mirai Botnet](https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-antonakakis.pdf)

---

*Rapport généré dans le cadre d'un exercice de réponse à incident et de chasse aux menaces.*
