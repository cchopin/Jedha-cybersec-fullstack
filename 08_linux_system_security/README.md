# 08 - Sécurité Linux

**Durée :** 8 jours
**Modules :** 8 chapitres | 24 cours | 14 exercices

---

## Objectifs

Maîtriser la sécurisation des systèmes Linux, de l'architecture système aux conteneurs, en passant par le noyau, le stockage et la défense réseau.

---

## Sommaire

### Chapitre 1 - Fondamentaux Linux

| # | Fichier | Type | Sujet |
|---|---------|------|-------|
| 01 | `01_le_systeme_linux.md` | Cours | Histoire, composants, distributions, architecture du shell |
| 02 | `02_bash_et_scripts.md` | Cours | Bash, redirections, pipes, scripts, expressions régulières |
| 03 | `03_utilisateurs_et_permissions.md` | Cours | Utilisateurs, groupes, permissions, sudo, SUID/SGID |
| - | `01_shared_folder/` | Exercice | Partage de dossier et permissions |
| - | `02_exploiting_misconfigurations/` | Exercice | Exploitation de mauvaises configurations |
| - | `05_bash_scripting/` | Exercice | Scripting Bash |

**Rooms associées :**

| Plateforme | Room | Difficulté | Description |
|------------|------|------------|-------------|
| HackTheBox | [Lame](https://app.hackthebox.com/machines/Lame) | Easy | Première machine HTB, énumération basique, navigation Linux |
| HackTheBox | [Bashed](https://app.hackthebox.com/machines/Bashed) | Easy | Web shell, navigation dans le système de fichiers, permissions |
| HackTheBox | [Nibbles](https://app.hackthebox.com/machines/Nibbles) | Easy | Énumération de répertoires, permissions, script bash exécutable en root |
| HackTheBox | [TwoMillion](https://app.hackthebox.com/machines/TwoMillion) | Easy | API, injection de commandes, fichiers d'environnement, architecture Linux |
| TryHackMe | [Linux Fundamentals Part 1](https://tryhackme.com/room/linuxfundamentalspart1) | Easy | Introduction aux bases de Linux |
| TryHackMe | [Linux Fundamentals Part 2](https://tryhackme.com/room/linuxfundamentalspart2) | Easy | Permissions et systèmes de fichiers |
| TryHackMe | [Bash Scripting](https://tryhackme.com/room/dvbashscripting) | Easy | Scripts Bash avancés |

### Chapitre 2 - Exploitation et reconnaissance

| # | Fichier | Type | Sujet |
|---|---------|------|-------|
| 04 | `04_exploitation_et_reconnaissance_linux.md` | Cours | Énumération, élévation de privilèges, techniques offensives |
| - | `03_hungry_process/` | Exercice | Processus gourmand |
| - | `03_SUID_exploitation/` | Exercice | Exploitation de binaires SUID |
| - | `04_sudo_chain/` | Exercice | Chaîne d'élévation via sudo |

**Rooms associées :**

| Plateforme | Room | Difficulté | Description |
|------------|------|------------|-------------|
| HackTheBox | [Irked](https://app.hackthebox.com/machines/Irked) | Easy | Binaire SUID custom qui exécute un fichier contrôlable en root |
| HackTheBox | [OpenAdmin](https://app.hackthebox.com/machines/OpenAdmin) | Easy | Abus sudo (nano as root), chasse aux credentials |
| HackTheBox | [Pandora](https://app.hackthebox.com/machines/Pandora) | Easy | SUID PATH hijacking, injection via variable PATH |
| HackTheBox | [Shocker](https://app.hackthebox.com/machines/Shocker) | Easy | Abus sudo (perl as root), énumération `sudo -l` |
| HackTheBox | [FriendZone](https://app.hackthebox.com/machines/FriendZone) | Easy | Library hijacking Python via cron job root |
| TryHackMe | [Linux Privilege Escalation](https://tryhackme.com/room/linprivesc) | Medium | Techniques d'élévation complètes |
| TryHackMe | [Linux PrivEsc Arena](https://tryhackme.com/room/dvlinuxprivescarena) | Medium | Scénarios pratiques d'élévation de privilèges |

### Chapitre 3 - Processus, exécutables et services

| # | Fichier | Type | Sujet |
|---|---------|------|-------|
| 05 | `05_les_processus_linux.md` | Cours | Processus, threads, signaux, monitoring |
| 06 | `06_les_executables.md` | Cours | ELF, bibliothèques, PATH hijacking, analyse binaire |
| 07 | `07_services_et_planification.md` | Cours | systemd, cron, at, persistance |
| - | `06_rogue_process/` | Exercice | Processus malveillant |
| - | `07_privilege_escalation/` | Exercice | Élévation de privilèges |
| - | `08_adv_privilege_escalation/` | Exercice | Élévation de privilèges avancée |

**Rooms associées :**

| Plateforme | Room | Difficulté | Description |
|------------|------|------------|-------------|
| HackTheBox | [Cronos](https://app.hackthebox.com/machines/Cronos) | Medium | Cron job root exécutant un fichier modifiable par www-data |
| HackTheBox | [TartarSauce](https://app.hackthebox.com/machines/TartarSauce) | Medium | Abus de `tar` avec `--checkpoint-action` dans une tâche planifiée |
| HackTheBox | [Nineveh](https://app.hackthebox.com/machines/Nineveh) | Medium | Exploitation de chkrootkit en cron job, monitoring de processus |
| HackTheBox | [Retired](https://app.hackthebox.com/machines/Retired) | Medium | Buffer overflow ELF (ROP chain), symlink sur script de backup |
| TryHackMe | [Linux Forensics](https://tryhackme.com/room/linuxforensics) | Medium | Investigation forensique de processus et services |

### Chapitre 4 - Stockage et systèmes de fichiers

| # | Fichier | Type | Sujet |
|---|---------|------|-------|
| 08 | `08_stockage_linux.md` | Cours | Disques, partitions, LVM, RAID |
| 09 | `09_systemes_de_fichiers.md` | Cours | ext4, XFS, Btrfs, montage, fstab |
| 10 | `10_securite_du_stockage.md` | Cours | Chiffrement LUKS, intégrité, stéganographie |
| 11 | `11_sauvegarde_et_recuperation.md` | Cours | rsync, tar, snapshots, plans de sauvegarde |
| - | `09_secure_partition/` | Exercice | Partition sécurisée |
| - | `10_suspicious_storage/` | Exercice | Stockage suspect |

**Rooms associées :**

| Plateforme | Room | Difficulté | Description |
|------------|------|------------|-------------|
| HackTheBox | [Sunday](https://app.hackthebox.com/machines/Sunday) | Easy | Fichier shadow.backup, cracking de hash, forensique de backup |
| HackTheBox | [Vault](https://app.hackthebox.com/machines/Vault) | Medium | Fichiers chiffrés GPG/PGP, gestion de clés, tunneling |
| HackTheBox | [Obscurity](https://app.hackthebox.com/machines/Obscurity) | Medium | Algorithme de chiffrement custom, attaque par clair connu |
| HackTheBox | [TwoMillion](https://app.hackthebox.com/machines/TwoMillion) | Easy | Fichiers .env, exploit OverlayFS (CVE-2023-0386) |
| TryHackMe | [Disk Analysis & Autopsy](https://tryhackme.com/room/introtodiskanalysis) | Medium | Analyse forensique de disque et récupération |
| TryHackMe | [Encryption - Crypto 101](https://tryhackme.com/room/encryptioncrypto101) | Medium | Introduction au chiffrement |

### Chapitre 5 - Noyau Linux

| # | Fichier | Type | Sujet |
|---|---------|------|-------|
| 12 | `12_introduction_au_noyau_linux.md` | Cours | Architecture monolithique, appels système, /proc |
| 13 | `13_versionnage_du_noyau.md` | Cours | Versions, compilation, CVE noyau |
| 14 | `14_modules_du_noyau.md` | Cours | Modules chargeables, rootkits, sécurisation |

**Rooms associées :**

| Plateforme | Room | Difficulté | Description |
|------------|------|------------|-------------|
| HackTheBox | [Valentine](https://app.hackthebox.com/machines/Valentine) | Easy | Kernel 3.2.0 vulnérable à Dirty COW (CVE-2016-5195) |
| HackTheBox | [TwoMillion](https://app.hackthebox.com/machines/TwoMillion) | Easy | Exploit OverlayFS noyau (CVE-2023-0386) pour obtenir root |
| HackTheBox | [Retired](https://app.hackthebox.com/machines/Retired) | Medium | Abus de binfmt_misc pour élévation via binaire SUID |
| TryHackMe | [Dirty Pipe CVE-2022-0847](https://tryhackme.com/room/dvdirtypipe) | Medium | Exploitation pas à pas de la vulnérabilité Dirty Pipe |

### Chapitre 6 - Sécurité MAC et conteneurs

| # | Fichier | Type | Sujet |
|---|---------|------|-------|
| 15 | `15_selinux_et_apparmor.md` | Cours | SELinux, AppArmor, politiques MAC |
| 16 | `16_modeles_de_securite_des_conteneurs.md` | Cours | Namespaces, cgroups, capabilities |
| 17 | `17_mecanismes_d_isolation.md` | Cours | Seccomp, pivot_root, évasion de conteneur |
| 18 | `18_durcissement_des_conteneurs.md` | Cours | Images minimales, scan, runtime security |

**Rooms associées :**

| Plateforme | Room | Difficulté | Description |
|------------|------|------------|-------------|
| HackTheBox | [GoodGames](https://app.hackthebox.com/machines/GoodGames) | Easy | Évasion de conteneur Docker via SSTI |
| HackTheBox | [SteamCloud](https://app.hackthebox.com/machines/SteamCloud) | Easy | Exploitation Kubernetes, pods, montage du filesystem hôte |
| HackTheBox | [Tabby](https://app.hackthebox.com/machines/Tabby) | Easy | Exploitation LXD pour évasion de conteneur et accès root |
| HackTheBox | [Ready](https://app.hackthebox.com/machines/Ready) | Medium | Conteneur Docker privilegié, évasion via cgroups mount |
| TryHackMe | [Docker Rodeo](https://tryhackme.com/room/dvdockerrodeo) | Medium | Sécurité Docker offensive, évasion de conteneurs |

### Chapitre 7 - Sécurité réseau et services

| # | Fichier | Type | Sujet |
|---|---------|------|-------|
| 19 | `19_services_exposes.md` | Cours | Scan de ports, services courants, vecteurs d'attaque |
| 20 | `20_pare_feu.md` | Cours | iptables, nftables, UFW, zones réseau |
| 21 | `21_defense_des_services.md` | Cours | Hardening SSH, Apache, MySQL, fail2ban |
| - | `11_secure_linux_server/` | Exercice | Sécurisation d'un serveur Linux |

**Rooms associées :**

| Plateforme | Room | Difficulté | Description |
|------------|------|------------|-------------|
| HackTheBox | [Lame](https://app.hackthebox.com/machines/Lame) | Easy | Exploitation Samba 3.0.20 (CVE-2007-2447), service non patché |
| HackTheBox | [Beep](https://app.hackthebox.com/machines/Beep) | Easy | 10+ services exposés (SSH, SMTP, HTTP, MySQL, Webmin...) |
| HackTheBox | [Shocker](https://app.hackthebox.com/machines/Shocker) | Easy | ShellShock (CVE-2014-6271) sur Apache CGI |
| HackTheBox | [OpenAdmin](https://app.hackthebox.com/machines/OpenAdmin) | Easy | Apache + OpenNetAdmin RCE, service interne sur localhost |
| HackTheBox | [Nineveh](https://app.hackthebox.com/machines/Nineveh) | Medium | Port knocking pour SSH, brute-force sur services web |
| TryHackMe | [Nmap](https://tryhackme.com/room/furthernmap) | Easy | Maîtriser le scan de ports avec Nmap |
| TryHackMe | [Network Services](https://tryhackme.com/room/dvnetworkservices) | Easy | Attaques sur les services réseau courants |

### Chapitre 8 - LDAP et automatisation

| # | Fichier | Type | Sujet |
|---|---------|------|-------|
| 22 | `22_ldap.md` | Cours | Architecture LDAP, annuaires, schémas, requêtes |
| 23 | `23_securite_ldap.md` | Cours | TLS, ACL, injection LDAP, audit |
| 24 | `24_ansible_pour_la_securite_linux.md` | Cours | Playbooks, rôles, hardening automatisé |
| - | `12_LDAP_compromission/` | Exercice | Compromission d'un annuaire LDAP |
| - | `13_ansible/` | Exercice | Automatisation Ansible |

**Rooms associées :**

| Plateforme | Room | Difficulté | Description |
|------------|------|------------|-------------|
| HackTheBox | [Inject](https://app.hackthebox.com/machines/Inject) | Easy | Cron job ansible-parallel, injection de playbook YAML malveillant |
| HackTheBox | [Lightweight](https://app.hackthebox.com/machines/Lightweight) | Medium | Énumération OpenLDAP, capture credentials via tcpdump |
| HackTheBox | [Seal](https://app.hackthebox.com/machines/Seal) | Medium | Playbook Ansible avec symlinks, exfiltration de clés SSH |
| TryHackMe | [Attacktive Directory](https://tryhackme.com/room/dvattacktivedirectory) | Medium | Attaques sur AD/LDAP |
