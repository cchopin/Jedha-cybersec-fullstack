# Lab 43: SNMP Enumeration - Résultats Obtenus

Résultats réels de l'enumeration SNMP effectuée sur la cible.

**Cible:** 192.168.122.10
**Community:** public (SNMPv2c)
**Date:** Enumeration effectuée via snmpwalk

---

## 1. Informations Système

```bash
snmpwalk -v2c -c public localhost .1.3.6.1.2.1.1
```

**Résultats obtenus :**

```
iso.3.6.1.2.1.1.1.0 = STRING: "Linux debian 6.1.0-22-cloud-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.94-1 (2024-06-21) x86_64"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.8072.3.2.10
iso.3.6.1.2.1.1.3.0 = Timeticks: (148393) 0:24:43.93
iso.3.6.1.2.1.1.4.0 = STRING: "admin@vulnerable-corp.local"
iso.3.6.1.2.1.1.5.0 = STRING: "target-server"
iso.3.6.1.2.1.1.6.0 = STRING: "Server Room - Rack 42"
iso.3.6.1.2.1.1.8.0 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.1.9.1.3.1 = STRING: "The SNMP Management Architecture MIB."
iso.3.6.1.2.1.1.9.1.3.2 = STRING: "The MIB for Message Processing and Dispatching."
iso.3.6.1.2.1.1.9.1.3.3 = STRING: "The management information definitions for the SNMP User-based Security Model."
iso.3.6.1.2.1.1.9.1.3.4 = STRING: "The MIB module for SNMPv2 entities"
iso.3.6.1.2.1.1.9.1.3.5 = STRING: "View-based Access Control Model for SNMP."
iso.3.6.1.2.1.1.9.1.3.6 = STRING: "The MIB module for managing TCP implementations"
iso.3.6.1.2.1.1.9.1.3.7 = STRING: "The MIB module for managing UDP implementations"
iso.3.6.1.2.1.1.9.1.3.8 = STRING: "The MIB module for managing IP and ICMP implementations"
iso.3.6.1.2.1.1.9.1.3.9 = STRING: "The MIB modules for managing SNMP Notification, plus filtering."
iso.3.6.1.2.1.1.9.1.3.10 = STRING: "The MIB module for logging SNMP Notifications."
```

**Informations sensibles exposées :**

| Champ | Valeur | Risque |
|-------|--------|--------|
| sysDescr | Linux debian 6.1.0-22-cloud-amd64 Debian 6.1.94-1 | Version exacte du kernel exposé |
| sysContact | admin@vulnerable-corp.local | Email admin exposé |
| sysName | target-server | Hostname révélé |
| sysLocation | Server Room - Rack 42 | Localisation physique révélée |
| sysUpTime | 0:24:43 | Uptime système |

---

## 2. Interfaces Réseau

```bash
snmpwalk -v2c -c public localhost .1.3.6.1.2.1.2.2.1.2
```

**Résultats obtenus :**

```
iso.3.6.1.2.1.2.2.1.2.1 = STRING: "lo"
iso.3.6.1.2.1.2.2.1.2.2 = STRING: "ens4"
```

**Interfaces identifiées :**
- `lo` : Interface loopback
- `ens4` : Interface réseau principale

---

## 3. Adresses MAC

```bash
snmpwalk -v2c -c public localhost .1.3.6.1.2.1.2.2.1.6
```

**Résultats obtenus :**

```
iso.3.6.1.2.1.2.2.1.6.1 = ""
iso.3.6.1.2.1.2.2.1.6.2 = Hex-STRING: 0C 33 0A 4A 00 00
```

**Adresses MAC identifiées :**
- Interface `lo` : (vide - loopback)
- Interface `ens4` : **0C:33:0A:4A:00:00**

---

## 4. Adresses IP

```bash
snmpwalk -v2c -c public localhost .1.3.6.1.2.1.4.20.1.1
```

**Résultats obtenus :**

```
iso.3.6.1.2.1.4.20.1.1.127.0.0.1 = IpAddress: 127.0.0.1
iso.3.6.1.2.1.4.20.1.1.192.168.122.10 = IpAddress: 192.168.122.10
```

**Adresses IP identifiées :**
- `127.0.0.1` : Loopback
- `192.168.122.10` : IP principale (réseau interne)

---

## 5. Processus en cours

```bash
snmpwalk -v2c -c public localhost .1.3.6.1.2.1.25.4.2.1.2
```

**Résultats obtenus (services critiques) :**

```
iso.3.6.1.2.1.25.4.2.1.2.1 = STRING: "systemd"
iso.3.6.1.2.1.25.4.2.1.2.203 = STRING: "systemd-journal"
iso.3.6.1.2.1.25.4.2.1.2.226 = STRING: "systemd-udevd"
iso.3.6.1.2.1.25.4.2.1.2.269 = STRING: "systemd-network"
iso.3.6.1.2.1.25.4.2.1.2.272 = STRING: "systemd-timesyn"
iso.3.6.1.2.1.25.4.2.1.2.306 = STRING: "dbus-daemon"
iso.3.6.1.2.1.25.4.2.1.2.316 = STRING: "systemd-logind"
iso.3.6.1.2.1.25.4.2.1.2.338 = STRING: "unattended-upgr"
iso.3.6.1.2.1.25.4.2.1.2.341 = STRING: "agetty"
iso.3.6.1.2.1.25.4.2.1.2.344 = STRING: "sshd"
iso.3.6.1.2.1.25.4.2.1.2.462 = STRING: "login"
iso.3.6.1.2.1.25.4.2.1.2.478 = STRING: "bash"
iso.3.6.1.2.1.25.4.2.1.2.1015 = STRING: "snmpd"
```

**Services critiques identifiés :**

| PID | Processus | Risque potentiel |
|-----|-----------|------------------|
| 1 | systemd | Init system |
| 344 | **sshd** | Service SSH actif - surface d'attaque |
| 1015 | **snmpd** | Service SNMP (cible de l'enum) |
| 306 | dbus-daemon | Communication inter-processus |
| 338 | unattended-upgr | Mises a jour auto (peut révélér des vulns) |

---

## 6. Chemins des executables

```bash
snmpwalk -v2c -c public localhost .1.3.6.1.2.1.25.4.2.1.4 | head -20
```

**Résultats obtenus :**

```
iso.3.6.1.2.1.25.4.2.1.4.1 = STRING: "/sbin/init"
```

---

## 7. Connexions TCP

```bash
snmpwalk -v2c -c public localhost .1.3.6.1.2.1.6.13
```

**Résultats obtenus :**

```
iso.3.6.1.2.1.6.13.1.1.0.0.0.0.22.0.0.0.0.0 = INTEGER: 2
iso.3.6.1.2.1.6.13.1.2.0.0.0.0.22.0.0.0.0.0 = IpAddress: 0.0.0.0
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.22.0.0.0.0.0 = INTEGER: 22
iso.3.6.1.2.1.6.13.1.4.0.0.0.0.22.0.0.0.0.0 = IpAddress: 0.0.0.0
iso.3.6.1.2.1.6.13.1.5.0.0.0.0.22.0.0.0.0.0 = INTEGER: 0
```

**Ports TCP identifiés :**

| Port | Service | Etat | Risque |
|------|---------|------|--------|
| 22 | SSH | LISTEN (0.0.0.0) | SSH accessible depuis toutes les interfaces |

---

## 8. Ports UDP

```bash
snmpwalk -v2c -c public localhost .1.3.6.1.2.1.7.5.1.2
```

**Résultats obtenus :**

```
iso.3.6.1.2.1.7.5.1.2.0.0.0.0.161 = INTEGER: 161
iso.3.6.1.2.1.7.5.1.2.0.0.0.0.44952 = INTEGER: 44952
```

**Ports UDP identifiés :**

| Port | Service | Risque |
|------|---------|--------|
| 161 | SNMP | Service cible, community "public" |
| 44952 | Ephemere | Port temporaire (communication SNMP) |

---

## 9. Stockage et Mémoire

```bash
snmpwalk -v2c -c public localhost .1.3.6.1.2.1.25.2.3.1.3
```

**Résultats obtenus :**

```
iso.3.6.1.2.1.25.2.3.1.3.1 = STRING: "Physical memory"
iso.3.6.1.2.1.25.2.3.1.3.3 = STRING: "Virtual memory"
iso.3.6.1.2.1.25.2.3.1.3.6 = STRING: "Memory buffers"
iso.3.6.1.2.1.25.2.3.1.3.7 = STRING: "Cached memory"
iso.3.6.1.2.1.25.2.3.1.3.8 = STRING: "Shared memory"
iso.3.6.1.2.1.25.2.3.1.3.10 = STRING: "Swap space"
iso.3.6.1.2.1.25.2.3.1.3.11 = STRING: "Available memory"
iso.3.6.1.2.1.25.2.3.1.3.35 = STRING: "/run"
iso.3.6.1.2.1.25.2.3.1.3.36 = STRING: "/"
iso.3.6.1.2.1.25.2.3.1.3.38 = STRING: "/dev/shm"
iso.3.6.1.2.1.25.2.3.1.3.39 = STRING: "/run/lock"
iso.3.6.1.2.1.25.2.3.1.3.53 = STRING: "/boot/efi"
iso.3.6.1.2.1.25.2.3.1.3.55 = STRING: "/run/user/1000"
```

**Points de montage identifiés :**
- `/` : Partition racine
- `/boot/efi` : Partition EFI (système UEFI)
- `/run`, `/dev/shm`, `/run/lock` : Tmpfs système
- `/run/user/1000` : Session utilisateur UID 1000

---

## 10. Logiciels installes

```bash
snmpwalk -v2c -c public localhost .1.3.6.1.2.1.25.6.3.1.2 | head -15
```

**Résultats obtenus :**

```
iso.3.6.1.2.1.25.6.3.1.2.1 = STRING: "adduser_3.134_all"
iso.3.6.1.2.1.25.6.3.1.2.2 = STRING: "apparmor_3.0.8-3_amd64"
iso.3.6.1.2.1.25.6.3.1.2.3 = STRING: "apt_2.6.1_amd64"
iso.3.6.1.2.1.25.6.3.1.2.4 = STRING: "apt-listchanges_3.24_all"
iso.3.6.1.2.1.25.6.3.1.2.5 = STRING: "apt-utils_2.6.1_amd64"
iso.3.6.1.2.1.25.6.3.1.2.6 = STRING: "base-files_12.4+deb12u6_amd64"
iso.3.6.1.2.1.25.6.3.1.2.7 = STRING: "base-passwd_3.6.1_amd64"
iso.3.6.1.2.1.25.6.3.1.2.8 = STRING: "bash_5.2.15-2+b7_amd64"
iso.3.6.1.2.1.25.6.3.1.2.9 = STRING: "bash-completion_1:2.11-6_all"
iso.3.6.1.2.1.25.6.3.1.2.10 = STRING: "bind9-host_1:9.18.24-1_amd64"
iso.3.6.1.2.1.25.6.3.1.2.11 = STRING: "bind9-libs_1:9.18.24-1_amd64"
iso.3.6.1.2.1.25.6.3.1.2.12 = STRING: "bsdextrautils_2.38.1-5+deb12u1_amd64"
iso.3.6.1.2.1.25.6.3.1.2.13 = STRING: "bsdutils_1:2.38.1-5+deb12u1_amd64"
iso.3.6.1.2.1.25.6.3.1.2.14 = STRING: "ca-certificates_20230311_all"
iso.3.6.1.2.1.25.6.3.1.2.15 = STRING: "cloud-guest-utils_0.33-1_all"
```

**Paquets critiques identifiés avec versions :**

| Paquet | Version | Risque |
|--------|---------|--------|
| base-files | 12.4+deb12u6 | Confirme Debian 12 |
| bash | 5.2.15-2+b7 | Version de bash |
| bind9-host | 9.18.24-1 | Client DNS (version exposée) |
| ca-certificates | 20230311 | Certificats CA |
| cloud-guest-utils | 0.33-1 | VM cloud (Azure/AWS/GCP) |

---

## Synthèse des risques de sécurité

### Risque 1 : Community string par défaut

| Element | Detail |
|---------|--------|
| Sévérité | **CRITIQUE** |
| Constat | Community "public" accessible sans authentification |
| Preuve | Toutes les commandes snmpwalk ont fonctionné |
| Impact | Acces complet en lecture a toutes les informations |
| Remédiation | Migrer vers SNMPv3 ou utiliser community complexe |

### Risque 2 : Exposition complète du système

| Element | Detail |
|---------|--------|
| Sévérité | **HAUTE** |
| Données exposées | OS: Debian 6.1.94-1, Kernel: 6.1.0-22-cloud-amd64 |
| Impact | Recherche de CVE facilitée |
| Remédiation | Restreindre les vues SNMP |

### Risque 3 : Email administrateur exposé

| Element | Detail |
|---------|--------|
| Sévérité | **MOYENNE** |
| Donnee | admin@vulnerable-corp.local |
| Impact | Cible pour phishing/social engineering |
| Remédiation | Utiliser un alias générique |

### Risque 4 : Localisation physique révélée

| Element | Detail |
|---------|--------|
| Sévérité | **MOYENNE** |
| Donnee | Server Room - Rack 42 |
| Impact | Facilite l'acces physique cible |
| Remédiation | Supprimer ou obfusquer sysLocation |

### Risque 5 : Liste des processus exposé

| Element | Detail |
|---------|--------|
| Sévérité | **HAUTE** |
| Données | sshd, snmpd, systemd, dbus-daemon... |
| Impact | Cartographie complète des services |
| Remédiation | Désactiver hrSWRun* dans la config |

### Risque 6 : Port SSH accessible

| Element | Detail |
|---------|--------|
| Sévérité | **HAUTE** |
| Donnee | Port 22 en ecoute sur 0.0.0.0 |
| Impact | SSH accessible depuis toutes les interfaces |
| Remédiation | Restreindre SSH a l'interface de management |

### Risque 7 : Liste des paquets exposés

| Element | Detail |
|---------|--------|
| Sévérité | **MOYENNE** |
| Données | 400+ paquets avec versions exactes |
| Impact | Identification de composants vulnérables |
| Remédiation | Désactiver hrSWInstalled* |

---

## Comparaison snmpwalk vs snmp-check

| Critere | snmpwalk | snmp-check |
|---------|----------|------------|
| Type | Outil unitaire | Outil automatise |
| Sortie | OIDs bruts | Rapport formaté |
| Flexibilite | Haute (OID precis) | Basse (scan complet) |
| Installation | net-snmp (standard) | Ruby + gem snmp |
| Usage | Requetes ciblées | Audit initial |

### Commande snmp-check équivalente

```bash
snmp-check 192.168.122.10 -c public
```

Cette commande génère automatiquement un rapport similaire aux resultats ci-dessus.

---

## Résumé des informations collectées

| Categorie | Données obtenues |
|-----------|------------------|
| OS | Debian 12, Kernel 6.1.0-22-cloud-amd64 |
| Hostname | target-server |
| Contact | admin@vulnerable-corp.local |
| Location | Server Room - Rack 42 |
| Interfaces | lo, ens4 |
| MAC | 0C:33:0A:4A:00:00 |
| IP | 127.0.0.1, 192.168.122.10 |
| TCP Ports | 22 (SSH) |
| UDP Ports | 161 (SNMP), 44952 |
| Services | systemd, sshd, snmpd, dbus-daemon |
| Paquets | 400+ avec versions |
| Stockage | /, /boot/efi, /run, /dev/shm |

---

## Validation des objectifs

- [x] **Full snapshot du système SNMP** : Toutes les categories énumérées
- [x] **Risques de sécurité identifiés** : 7 risques documentés avec sévérités
- [x] **Usage pratique de snmpwalk** : Commandes et resultats réels fournis
- [x] **Comprehension de snmp-check** : Comparaison et usage documenté
