# Versionnage du noyau

**Durée : 45 min**

## Ce que vous allez apprendre dans ce cours

Même si votre système est parfaitement verrouillé, avec des permissions durcies, des processus isolés et un stockage sécurisé, rien de tout cela n'a d'importance si votre noyau est vulnérable. Le noyau est la fondation : s'il est compromis, les attaquants peuvent contourner tout le reste. Dans cette leçon, vous allez :

- apprendre à vérifier la version du noyau de votre système,
- découvrir les différentes branches du noyau,
- voir les trois méthodes pour patcher le noyau,
- comprendre comment les red et blue teams surveillent les vulnérabilités du noyau.

---

## Introduction au versionnage du noyau

Le noyau Linux est le cœur du système d'exploitation. Il agit comme pont entre le logiciel et le matériel, gérant les ressources système comme la mémoire, l'ordonnancement CPU, les entrées/sorties des périphériques et les systèmes de fichiers. Chaque action de l'espace utilisateur, du lancement d'un navigateur web à la lecture d'un fichier, dépend finalement des services du noyau.

### Pourquoi le noyau est-il critique pour la sécurité ?

Parce que le noyau opère en **mode privilégié**, son code a un accès illimité à toutes les parties du système :

- Contrôle direct sur le matériel
- Visibilité complète de la mémoire
- Autorité sur tous les processus utilisateur

Toute faille dans le noyau peut donc devenir un vecteur d'attaque puissant, capable de contourner les permissions utilisateur, désactiver les mécanismes de sécurité ou installer des malwares persistants.

Pour protéger votre noyau, vous devez rester au courant des mises à jour et comprendre si elles sont nécessaires pour votre système, afin d'éviter d'être vulnérable à des vulnérabilités connues.

### L'exemple de Dirty COW

Une des vulnérabilités du noyau Linux les plus (in)fameuses est **Dirty Copy-On-Write** (CVE-2016-5195). Ce bug existait silencieusement dans le noyau depuis 2007 et n'a été découvert et divulgué qu'en 2016.

Il exploitait une **condition de course** dans le mécanisme copy-on-write, utilisé quand un processus essaie d'écrire dans une mémoire initialement partagée et marquée en lecture seule. Un exploit pour Dirty COW pouvait être exécuté rapidement et de manière fiable, transformant un utilisateur régulier en root en quelques secondes.

---

## Vérifier la version de votre noyau

La première étape pour sécuriser votre système est de savoir quelle version du noyau vous utilisez. Il existe de nombreuses commandes qui peuvent vous donner cette information.

### uname

La commande `uname -r` affiche la version release du noyau :

```bash
$ uname -r
6.8.0-60-generic
```

Utiliser `uname -a` donne les informations système complètes : nom du noyau, version, architecture et hostname :

```bash
$ uname -a
Linux jedha 6.8.0-60-generic #63-Ubuntu SMP PREEMPT_DYNAMIC Tue Apr 15 18:51:58 UTC 2025 aarch64 GNU/Linux
```

### hostnamectl

Cette commande est souvent utilisée sur les systèmes modernes basés sur systemd. Elle fournit non seulement la version du noyau mais aussi les informations matériel :

```bash
$ hostnamectl
 Static hostname: jedha
       Icon name: computer-vm
         Chassis: vm
      Machine ID: 8ee3016962e74989a26e938d3d0e369f
         Boot ID: c85f073d821947b9904638745c9667ef
  Virtualization: vmware
Operating System: Ubuntu 24.04.2 LTS
          Kernel: Linux 6.8.0-60-generic
    Architecture: arm64
```

### /proc/version

Ce fichier contient une chaîne brute montrant la version du noyau, le compilateur utilisé et la date de compilation :

```bash
$ cat /proc/version
Linux version 6.8.0-60-generic (buildd@bos03-arm64-002) (aarch64-linux-gnu-gcc-13 (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0, GNU ld (GNU Binutils for Ubuntu) 2.42) #63-Ubuntu SMP...
```

Particulièrement utile quand vous avez besoin de connaître l'environnement de compilation, par exemple pour vérifier des signes de compilation personnalisée.

### dmesg

Cette commande affiche les messages du noyau, incluant un des premiers logs où le noyau annonce sa version au démarrage :

```bash
$ sudo dmesg | grep Linux
[    0.000000] Linux version 6.8.0-60-generic (buildd@bos03-arm64-002)...
```

### lsb_release

Cette commande ne montre pas la version du noyau mais la version de la distribution. Elle est utile pour comparer la version de distribution à la version du noyau :

```bash
$ lsb_release -a
No LSB modules are available.
Distributor ID:    Ubuntu
Description:    Ubuntu 24.04.2 LTS
Release:    24.04
Codename:    noble
```

---

## Surveiller les vulnérabilités

Rester informé des vulnérabilités du noyau est essentiel pour la sécurité du système. De nouveaux bugs du noyau sont découverts régulièrement, et certains sont assez critiques pour permettre l'élévation de privilèges ou la compromission du système.

### Blue Team : automatiser la surveillance

Pour les Blue Teams, l'objectif est de réduire le temps d'exposition entre la divulgation d'une vulnérabilité et le déploiement d'un patch.

**Sources à suivre :**
- National Vulnerability Database (NVD)
- Linux Kernel Mailing List (LKML)
- Avis de sécurité spécifiques aux distributions (Ubuntu Security Notices, Red Hat Security Announcements)

**Outils automatisés :**
- **Grype** ou **Vulners** peuvent scanner les vulnérabilités connues et les mapper à la version du noyau de votre système

**Bonnes pratiques :**
- Automatiser la vérification des mises à jour et les flux de vulnérabilités
- Utiliser la surveillance des logs et les systèmes de détection d'intrusion pour suivre les anomalies liées au noyau
- Appliquer des politiques de gestion des patchs avec des délais pour appliquer les mises à jour critiques
- Valider les patchs dans des environnements de staging avant déploiement

### Red Team : trouver des exploits

Pour les red teams, surveiller les vulnérabilités du noyau signifie faire correspondre les faiblesses aux systèmes rencontrés. Une fois la version du noyau identifiée, les attaquants évaluent immédiatement si elle correspond à des exploits publics.

**Ressources utilisées par les red teamers :**

#### ExploitDB et searchsploit

ExploitDB est une archive web publique d'exploits et de code POC. L'interface en ligne de commande `searchsploit` permet de chercher la copie locale hors ligne :

```bash
$ searchsploit linux kernel 4.5

# En savoir plus sur un exploit spécifique
$ searchsploit -p linux/local/41886.c
```

#### Metasploit

Quand vous avez besoin de tester vos trouvailles, Metasploit est l'outil de choix :

```bash
$ msfconsole
msf6 > search linux kernel 4.5
```

#### Recherche CVE

La National Vulnerability Database (NVD) est un bon endroit pour suivre les nouvelles vulnérabilités. Une recherche régulière avec un numéro CVE est souvent le meilleur moyen de trouver si quelqu'un a posté un POC fonctionnel.

---

## Patching du noyau

Si vous êtes un sysadmin ou un blue teamer, une fois alerté d'une vulnérabilité dans votre noyau, vous devrez le patcher. Il existe plusieurs façons de patcher le noyau, chacune avec ses propres compromis en termes de temps d'arrêt, complexité et contrôle.

### Patching manuel

Le patching manuel implique de télécharger, compiler et installer une nouvelle version du noyau. Cela donne le plus de contrôle mais aussi le plus de risque.

**Étapes clés :**
1. Télécharger les sources depuis kernel.org ou les dépôts du distributeur
2. Appliquer la configuration (`make menuconfig` ou réutiliser `/boot/config-<version>`)
3. Compiler et installer avec `make` et `make install`
4. Mettre à jour le bootloader et redémarrer

> **Attention** : Le patching manuel devrait toujours être testé en staging d'abord. Un noyau mal configuré peut rendre un système non bootable.

**Cas d'usage :** Compilation personnalisée du noyau, matériel non supporté ou de niche, distributions durcies ou minimalistes.

### Patching automatique

La plupart des distributions supportent les mises à jour automatiques ou non surveillées du noyau via leurs gestionnaires de paquets :

| Distribution | Outil |
|--------------|-------|
| Debian/Ubuntu | `unattended-upgrades` |
| Red Hat/CentOS | `yum-cron` ou `dnf-automatic` |

Ces outils peuvent être configurés pour récupérer et installer les mises à jour de sécurité régulièrement. Cependant, parce que le patching traditionnel nécessite un redémarrage, les systèmes critiques peuvent rester vulnérables jusqu'au redémarrage manuel.

```bash
# Mise à jour manuelle du noyau vers une version spécifique
$ sudo apt upgrade linux-image-*
```

### Live Patching

Le live patching applique les correctifs du noyau sans redémarrer. Il fonctionne en remplaçant dynamiquement le code vulnérable dans le noyau en cours d'exécution. Crucial pour les environnements sensibles au temps de disponibilité comme les serveurs de production ou conteneurs.

| Solution | Distribution | Description |
|----------|--------------|-------------|
| **Canonical Livepatch** | Ubuntu | Nécessite un token gratuit ou commercial de Canonical. Simple à configurer avec `snap install canonical-livepatch` |
| **kpatch** | Red Hat | Outil de patching dynamique du noyau qui remplace les fonctions vulnérables en mémoire |

> **Note** : Le live patching ne supporte que certains types de correctifs (principalement liés à la sécurité) et est souvent légèrement en retard par rapport aux patches manuels. Ce n'est pas un remplacement pour les mises à niveau complètes du noyau.

---

## Branches du noyau et pratiques des distributions

Le noyau Linux est publié en plusieurs branches, chacune conçue pour différents cas d'usage.

### Branches du noyau

| Branche | Description |
|---------|-------------|
| **Mainline** | Le dernier noyau en développement actif, maintenu par Linus Torvalds. Nouvelles fonctionnalités et changements architecturaux. Pas destiné à la production. |
| **Stable** | Après qu'un noyau mainline est publié (ex: 6.8), il devient une release stable. Reçoit des corrections de bugs pendant une courte période (quelques semaines à mois). |
| **Longterm (LTS)** | Ces noyaux sont maintenus pendant des années (typiquement 2 à 6 ans), recevant des patches de sécurité et corrections de bugs sérieux. Choix privilégié pour les systèmes de production. |

### Pratiques des distributions

Les distributions n'utilisent pas toujours le noyau vanilla directement. Elles appliquent des backports, patches personnalisés et changements de durcissement :

| Distribution | Pratique |
|--------------|----------|
| **Ubuntu** | Livre des noyaux LTS et backporte les correctifs de sécurité des versions plus récentes |
| **Red Hat/CentOS/Rocky** | Utilise des versions fortement patchées et stabilisées de noyaux plus anciens |
| **Debian** | Priorise la stabilité, livrant typiquement des noyaux LTS plus anciens |
| **Arch Linux** | Suit de près la branche stable, mettant à jour rapidement et souvent |

> **Important** : Deux systèmes exécutant "kernel 5.15" peuvent se comporter très différemment selon leur distribution et ensemble de patches.

---

## Glossaire des sigles et définitions

| Sigle/Terme | Définition |
|-------------|------------|
| **Kernel version** | Version du noyau - Numéro identifiant la release du noyau |
| **CVE** | Common Vulnerabilities and Exposures - Identifiant unique pour les vulnérabilités |
| **NVD** | National Vulnerability Database - Base de données nationale des vulnérabilités |
| **LKML** | Linux Kernel Mailing List - Liste de diffusion du noyau Linux |
| **Mainline** | Branche principale du développement du noyau |
| **LTS** | Long Term Support - Support à long terme |
| **Live patching** | Application de correctifs sans redémarrage |
| **kpatch** | Outil de live patching pour Red Hat |
| **Livepatch** | Service de live patching de Canonical pour Ubuntu |
| **Dirty COW** | Vulnérabilité noyau CVE-2016-5195 |
| **POC** | Proof of Concept - Démonstration de faisabilité d'un exploit |
| **ExploitDB** | Base de données d'exploits publics |

---

## Récapitulatif des commandes

### Vérification de la version du noyau

| Commande | Description |
|----------|-------------|
| `uname -r` | Afficher la version release du noyau |
| `uname -a` | Afficher les informations système complètes |
| `hostnamectl` | Infos système incluant version noyau |
| `cat /proc/version` | Version du noyau et infos de compilation |
| `dmesg \| grep Linux` | Messages du noyau incluant la version |
| `lsb_release -a` | Version de la distribution |

### Mise à jour du noyau

| Commande | Description |
|----------|-------------|
| `sudo apt update && sudo apt upgrade` | Mettre à jour les paquets incluant le noyau |
| `sudo apt upgrade linux-image-*` | Mettre à jour spécifiquement le noyau |
| `sudo unattended-upgrade -v` | Exécuter les mises à jour automatiques |

### Recherche d'exploits (Red Team)

| Commande | Description |
|----------|-------------|
| `searchsploit linux kernel X.X` | Chercher des exploits pour une version |
| `searchsploit -p exploit/path` | Obtenir le chemin complet d'un exploit |
| `msfconsole` | Lancer Metasploit |
| `search linux kernel X.X` | Chercher des exploits dans Metasploit |

### Live Patching (Ubuntu)

| Commande | Description |
|----------|-------------|
| `snap install canonical-livepatch` | Installer le service Livepatch |
| `canonical-livepatch enable TOKEN` | Activer avec un token |
| `canonical-livepatch status` | Vérifier le statut |

---

## Ressources

- What is Linux kernel live patching? - Red Hat
- Understanding and mitigating the Dirty Cow Vulnerability - Red Hat
- Understanding Dirty COW - Thaddeus Pearson

### Ressources pratiques - TryHackMe / HackTheBox

| Plateforme | Room/Lab | Description |
|------------|----------|-------------|
| TryHackMe | [Linux Privilege Escalation](https://tryhackme.com/room/linprivesc) | Élévation de privilèges incluant exploits noyau |
| TryHackMe | [Dirty Pipe CVE-2022-0847](https://tryhackme.com/room/dvdirtypipe) | Exploitation de la vulnérabilité Dirty Pipe |
| TryHackMe | [Linux PrivEsc Arena](https://tryhackme.com/room/dvlinuxprivescarena) | Scénarios d'élévation de privilèges |
| HackTheBox | [Machines Linux](https://app.hackthebox.com/machines) | Machines avec vulnérabilités noyau |
