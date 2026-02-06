# Quand le serveur de ton coloc rejoint un botnet : étude de cas réelle

*Une investigation pratique de réponse à incident et de renseignement sur les menaces*

---

## Résumé

Un serveur web personnel a été compromis deux fois en deux mois :
1. **Décembre 2025** : Cryptominer XMRig déployé via des vulnérabilités Strapi CMS
2. **Février 2026** : Variante du botnet Mirai (EIW) déployée via exploitation des Server Actions Next.js

L'investigation a retracé l'infrastructure C2 jusqu'à **Virtualine Technologies**, un hébergeur bulletproof russe opérant via des sociétés écrans aux États-Unis et des fournisseurs de transit en Bulgarie et aux Pays-Bas.

---

## Partie 1 : La découverte

### Quelque chose ne va pas

Le premier signe était évident : le serveur était **bruyant**. Le ventilateur tournait à fond et les applications web étaient lentes. Une rapide session SSH a révélé l'horreur :

```
$ top
PID    USER        %CPU  COMMAND
1061829 nextjs-app  45.2  /x86_64.kok
1061864 nextjs-app  18.1  /x86_64.kok
1061865 nextjs-app  12.3  /x86_64.kok
```

Trois processus nommés `/x86_64.kok` consommaient 75% du CPU. L'extension `.kok` est un marqueur connu des **variantes du botnet Mirai**. Ce serveur participait activement à des attaques DDoS.

### Le réseau raconte une histoire

```
$ netstat -an | grep ESTABLISHED
tcp  0  0  [SERVEUR]:random  91.92.241.12:6969  ESTABLISHED
tcp  0  0  [SERVEUR]:random  91.92.241.12:6969  ESTABLISHED
```

Deux connexions persistantes vers `91.92.241.12` sur le port **6969**. Comportement C2 classique.

Mais attendez, il y a plus :

```
$ cat /proc/net/dev
eth0: 974Go transmis, 2.7Go reçus
```

**974 Go transmis en 12 jours**. Un ratio TX/RX de 360:1. Ce serveur n'était pas juste infecté, c'était un **canon à DDoS**.

---

## Partie 2 : L'analyse forensique

### Reconstruction de la timeline

L'analyse des timestamps des fichiers a révélé deux vagues de compromission distinctes :

**Vague 1 : 5 décembre 2025 - Cryptominer**
```
$ ls -la /var/www/webserver-next/c3pool/
-rwxr-xr-x  1 nextjs-app  3.4M Dec  5 10:02 xmrig
-rw-r--r--  1 nextjs-app  299  Dec  5 10:02 miner.sh
-rw-r--r--  1 nextjs-app  4.0M Dec  5 11:20 xmrig.log
```

Cryptominer XMRig, minant du Monero vers deux adresses de wallet via des pools publics (c3pool, hashvault).

**Vague 2 : 3-6 février 2026 - Botnet**
```
$ ls -la /tmp/
-rwxr-xr-x  1 nextjs-app  107K Feb  3 23:26 x86_32.kok.1
-rwxr-xr-x  1 nextjs-app   10K Feb  3 23:28 logic.sh
-rwxr-xr-x  1 nextjs-app  150K Feb  6 07:00 .b_aa
...
```

Un script dropper (`logic.sh`) téléchargeant des binaires Mirai multi-architectures.

### Le point d'entrée

Deux vulnérabilités ont été exploitées :

**1. Strapi CMS (Vague 1)**
- Inscription publique ouverte (`POST /api/auth/local/register`)
- Comptes auto-confirmés, pas de CAPTCHA
- Panneau d'admin exposé sans restriction IP
- Fichier `.env` avec secrets lisibles

**2. Next.js Server Actions (Vague 2)**

Les logs nginx ont montré une attaque coordonnée :

```
193.142.147.209 - - [22/Jan/2026] "POST / HTTP/1.1" 200 ...
193.142.147.209 - - [28/Jan/2026] "POST / HTTP/1.1" 500 ...  <-- Premier exploit réussi
195.3.222.78    - - [28/Jan/2026] "POST / HTTP/1.1" 500 ...
...
[8 979 requêtes de 193.142.147.209 seul]
```

Les erreurs HTTP 500 indiquaient l'exécution du payload faisant planter le processus Node.js - exactement ce qui se passe quand les Server Actions sont exploitées pour de l'exécution de code.

---

## Partie 3 : La chasse

### Partir de ce qu'on a

Après le nettoyage du serveur, nous avons préservé les IOCs clés :

| Type d'IOC | Valeur |
|------------|--------|
| SHA256 | `833bca151dc3ff83cbed22b6e7e849f0ee752bac55f68e156660e4d33d17caad` |
| IP C2 | `91.92.241.12:6969` |
| IP C2 | `91.92.243.113:235` |
| Pattern fichier | `*.kok` |

### VirusTotal confirme Mirai

Soumission du hash sur VirusTotal :

```
Détection : 34/72 (47%)
Consensus : Linux/Mirai.EIW
```

Chaque antivirus majeur qui l'a détecté était d'accord : **Mirai**. Kaspersky l'a appelé `Gafgyt.gu` (Gafgyt est le prédécesseur de Mirai), mais c'est la même famille.

### La connexion port 6969

Le port 6969 n'est pas aléatoire. Les chercheurs en sécurité de **Cydome** ont documenté une nouvelle variante de Mirai appelée **Broadside** en décembre 2025 :

> "Broadside utilise un protocole C2 personnalisé sur TCP/1026, avec **des communications de secours sur TCP/6969**."

Notre C2 utilisait le port de secours. Cela place notre échantillon dans l'arbre généalogique de Broadside.

### Suivre l'infrastructure

**Requête Shodan sur 91.92.241.12 :**

```
Pays : Pays-Bas
Ville : Amsterdam
Organisation : Neterra Ltd.
FAI : NTT America, Inc.
ASN : AS2914
OS : Ubuntu 24.04
Dernière observation : 2026-02-01  <-- 5 jours avant notre incident
```

Attendez - Neterra est bulgare, NTT est américain, mais la plage IP `91.92.x.x` appartient à **AS214943 (Railnet LLC)**. Que se passe-t-il ?

### Dévoiler Railnet LLC

L'OSINT a révélé la connexion :

1. **Railnet LLC** (ASN 214943) est enregistrée aux États-Unis
2. Railnet est une façade légale pour **Virtualine Technologies**
3. Virtualine est un **hébergeur bulletproof russe**
4. Publicité sur les forums underground russes par l'utilisateur "Secury"
5. **Spamhaus** les surveille activement comme une menace

Le chemin de routage :

```
Acteur malveillant
    ↓
Virtualine Technologies (Russie) - Commande l'hébergement bulletproof
    ↓
Railnet LLC (US) - Annonce les préfixes IP
    ↓
Neterra Ltd (Bulgarie) - Fournit le transit
    ↓
NTT America (US) - Opérateur Tier 1
    ↓
Datacenter Amsterdam - Localisation physique
```

C'est l'hébergement bulletproof classique : plusieurs couches d'indirection pour frustrer les takedowns et l'attribution.

### Le jackpot ANY.RUN

La recherche du pattern `.kok` sur ANY.RUN a trouvé une correspondance exacte :

**Échantillon : logicdr.sh**
- SHA256 : `bf5a1e8b25d6ef368f11028fc492cc5e4a7e623a5b603a505828ae1c2e62fa3d`
- C2 : `91.92.241.12:6969` *(correspondance exacte !)*
- Télécharge : `x86_64.kok`, `x86_32.kok`, `arm.kok`...
- Alerte SURICATA : **"MIRAI botnet detected"**

Quelqu'un avait déjà soumis essentiellement le même dropper. Notre incident n'était pas unique - il faisait partie d'une campagne en cours.

---

## Partie 4 : L'attribution

### Ce qu'on peut prouver

| Élément | Confiance | Preuve |
|---------|-----------|--------|
| Malware : Mirai.EIW | **Élevée** | 34 détections AV, signature SURICATA |
| Infra C2 : Virtualine/Railnet | **Élevée** | OSINT, surveillance Spamhaus |
| Origine : Russie | **Élevée** | Publicité sur forums underground |
| Variante : Liée à Broadside | **Moyenne** | Correspondance signature port 6969 |
| Opérateurs : Russophones | **Moyenne** | Langue des forums, choix d'infrastructure |

### Ce qu'on ne peut pas prouver

- **Identités individuelles** : L'hébergement bulletproof existe spécifiquement pour empêcher ça
- **Groupe criminel spécifique** : Pourrait être n'importe quel client de Virtualine
- **Attribution du cryptominer** : Pools publics, wallets Monero anonymes
- **Parrainage étatique** : Ça ressemble à du crime organisé, pas à une activité APT

### Profil de l'acteur de la menace

```
Type :           Cybercriminel (non-APT)
Motivation :     Financière
                 - DDoS-as-a-Service (location de botnet)
                 - Cryptominage (Monero)
Sophistication : Moyenne
                 - Utilise des malwares commoditisés (Mirai)
                 - S'appuie sur une infrastructure bulletproof
                 - Scanning et exploitation automatisés
Langue :         Russe (déduit de l'infrastructure)
Opérations :     Opportunistes
                 - Scanning de masse pour services vulnérables
                 - Pas de ciblage spécifique observé
```

---

## Partie 5 : Leçons apprises

### Facteurs ayant facilité la compromission

Ces éléments de configuration, courants sur les serveurs de développement ou personnels, ont été exploités :

1. **Firewall non configuré** - Les ports étaient accessibles depuis internet
2. **Admin Strapi accessible** - Configuration par défaut sans restriction IP
3. **Inscription ouverte** - Fonctionnalité Strapi activée par défaut
4. **Secrets dans .env** - Permissions par défaut du fichier
5. **Next.js non mis à jour** - Vulnérabilité Server Actions récente
6. **Absence de monitoring** - Pas d'alertes configurées

### La checklist de défense

```markdown
[ ] Firewall avec politique de refus par défaut
[ ] Panneaux d'admin restreints par IP ou VPN
[ ] Inscription désactivée ou protégée (CAPTCHA, vérification email)
[ ] Secrets avec permissions appropriées (chmod 600)
[ ] Calendrier de mise à jour régulier
[ ] Agrégation et alerting des logs
[ ] Surveillance du trafic réseau
[ ] Vérification régulière de l'intégrité (AIDE, Tripwire)
```

### Opportunités de détection

Les attaquants ont laissé plein de traces :

| Indicateur | Méthode de détection |
|------------|----------------------|
| Pic CPU | Surveillance des ressources |
| Processus inhabituels | Liste blanche de processus |
| Connexions C2 | Surveillance réseau, port 6969 |
| Fichiers cachés | Surveillance de l'intégrité des fichiers |
| Modifications cron | Audit de configuration |
| DDoS sortant | Analyse Netflow |

---

## Partie 6 : Le nettoyage

### Actions immédiates

```bash
# Tuer les processus malveillants
kill -9 $(pgrep -f '.kok')

# Supprimer les fichiers du botnet
rm -rf /tmp/.b_* /tmp/.bins /tmp/.x /tmp/logic.sh /tmp/*.kok
rm -f /var/tmp/.monitor
rm -f /dev/shm/lrt

# Supprimer le cryptominer
rm -rf /var/www/webserver-next/c3pool
rm -f /var/www/webserver-next/sex.sh
rm -f /var/www/webserver-next/kal.tar.gz

# Nettoyer la persistance
# (restaurer .profile, vérifier crontabs, vérifier rc.d)
```

### Résultats

| Métrique | Avant | Après |
|----------|-------|-------|
| Utilisation CPU | 78% | 10% |
| Réseau TX | 974 Go/12 jours | Normal |
| Processus malveillants | 5 | 0 |
| Connexions C2 | 2 | 0 |

### Durcissement

```bash
# Activer le firewall
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow http
ufw allow https
ufw enable

# Bloquer les IPs malveillantes connues
iptables -A OUTPUT -d 91.92.241.0/24 -j DROP
iptables -A OUTPUT -d 91.92.243.0/24 -j DROP
iptables -A INPUT -s 138.121.0.0/16 -j DROP
```

---

## Conclusion

Cet incident démontre la réalité de la cybercriminalité moderne :

1. **Les attaques opportunistes dominent** - Des scanners automatisés ont trouvé et exploité les mauvaises configurations
2. **Les payloads multiples sont courants** - Cryptominage et botnets coexistent souvent
3. **L'attribution est difficile mais possible** - Suivre l'infrastructure mène à l'hébergement bulletproof
4. **L'hébergement bulletproof permet le crime** - Virtualine et les fournisseurs similaires sont l'épine dorsale
5. **Quelques mesures simples suffisent** - Un firewall et des mises à jour régulières auraient bloqué ces attaques

Les attaquants n'étaient pas sophistiqués. Ils ont utilisé des malwares commoditisés (Mirai), des pools de minage publics et une infrastructure louée. Ce type d'attaque opportuniste cible des milliers de serveurs chaque jour - celui-ci faisait simplement partie des cibles.

**La bonne nouvelle : ces attaques sont facilement évitables avec quelques mesures de base. Un firewall et des restrictions d'accès auraient suffi.**

---

## Ressources

### Outils utilisés
- [VirusTotal](https://www.virustotal.com/) - Identification de malware
- [Shodan](https://www.shodan.io/) - Reconnaissance d'infrastructure
- [ANY.RUN](https://any.run/) - Sandbox malware
- [AbuseIPDB](https://www.abuseipdb.com/) - Réputation IP
- [IPinfo](https://ipinfo.io/) - Lookup ASN

### Références
- [Cydome - Analyse Broadside](https://cydome.io/cydome-identifies-broadside-a-new-mirai-botnet-variant-targeting-maritime-iot/)
- [USENIX - Understanding the Mirai Botnet](https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-antonakakis.pdf)
- [Spamhaus - Hébergement Bulletproof](https://www.spamhaus.org/resource-hub/bulletproof-hosting/)
- [MITRE ATT&CK - Techniques Linux](https://attack.mitre.org/matrices/enterprise/linux/)

---

*Ce write-up est basé sur un incident réel. Les informations d'identification du serveur ont été expurgées. Les IOCs sont défangés pour la sécurité.*

**Auteur :** Équipe de réponse aux incidents de sécurité  
**Date :** Février 2026  
**Classification :** TLP:CLEAR  
