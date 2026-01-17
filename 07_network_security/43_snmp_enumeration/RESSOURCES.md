# Ressources pour aller plus loin - SNMP Enumeration

Liens verifies et ressources pour approfondir l'enumeration SNMP.

---

## HackTheBox - Machines avec SNMP

Machines retirees necessitant un abonnement VIP ou accessibles via writeups.

| Machine | Difficulte | Description |
|---------|------------|-------------|
| **Pit** | Medium | SNMP enumeration → decouverte de paths et usernames → SeedDMS exploit |
| **Mischief** | Insane | SNMP revele credentials dans les arguments de processus + IPv6 |
| **Carrier** | Medium | SNMP community "public" → serial number utilise comme password |
| **Pandora** | Easy | SNMP UDP scan → credentials pour SSH → Pandora FMS |
| **Sneaky** | Medium | SNMP enumeration → IPv6 discovery → buffer overflow |
| **Conceal** | Hard | SNMP + IKE VPN → decouverte des ports via snmp-netstat |

**Writeups detailles :**
- [Pit - Hackingarticles](https://www.hackingarticles.in/pit-hackthebox-walkthrough/)
- [Mischief - Snowscan](https://snowscan.io/htb-writeup-mischief/)
- [Carrier - 0xRick](https://0xrick.github.io/hack-the-box/carrier/)
- [Sneaky - Hackingarticles](https://www.hackingarticles.in/hack-the-box-challenge-sneaky-walkthrough/)
- [Conceal - Ethicalhacs](https://ethicalhacs.com/conceal-hackthebox-walkthrough/)

---

## TryHackMe - Rooms

| Room | Contenu SNMP |
|------|--------------|
| **Enumeration** | Post-exploitation enumeration avec snmpcheck |
| **Network Services 2** | Section sur les services reseau dont SNMP |

Lien direct :
- https://tryhackme.com/r/room/introtoisac (Introduction aux protocoles reseau)
- https://tryhackme.com/r/room/enumerationpe (Enumeration post-exploitation)

---

## Documentation et Cheatsheets

### HackTricks (Reference)

Guide complet sur le pentesting SNMP :
- [Pentesting SNMP](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-snmp/index.html)
- [Cisco SNMP](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-snmp/cisco-snmp.html)
- [SNMP RCE](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-snmp/snmp-rce.html)

**Contenu :**
- Brute-force community strings
- Enumeration avec snmpwalk, snmp-check, braa
- OIDs Windows et Linux
- Exploitation RCE via write access

### Tutoriels snmpwalk

- [Comparitech - snmpwalk Examples](https://www.comparitech.com/net-admin/snmpwalk-examples-windows-linux/)
- [IONOS - snmpwalk Tutorial](https://www.ionos.com/digitalguide/server/know-how/snmp-tutorial/)
- [Net-SNMP Official Tutorial](https://net-snmp.sourceforge.io/tutorial/tutorial-5/commands/snmpwalk.html)
- [Best Monitoring Tools - snmpwalk v2/v3](https://bestmonitoringtools.com/snmpwalk-example-v3-v2-snmpget-snmpset-snmptrap/)

---

## Outils

### Enumeration

| Outil | Usage | Installation |
|-------|-------|--------------|
| **snmpwalk** | Enumeration manuelle OID par OID | `apt install snmp` |
| **snmp-check** | Rapport automatise complet | `apt install snmp-check` |
| **onesixtyone** | Brute-force community strings | `apt install onesixtyone` |
| **braa** | Mass SNMP scanner | `apt install braa` |
| **snmpbulkwalk** | Enumeration rapide (bulk) | `apt install snmp` |

### Exploitation

| Outil | Usage | Lien |
|-------|-------|------|
| **snmp-shell** | RCE via SNMP write | https://github.com/mxrch/snmp-shell |
| **Metasploit** | Module snmp_enum | `auxiliary/scanner/snmp/snmp_enum` |

---

## OIDs utiles

### Systeme
```
1.3.6.1.2.1.1.1.0    sysDescr      Description systeme
1.3.6.1.2.1.1.3.0    sysUpTime     Uptime
1.3.6.1.2.1.1.4.0    sysContact    Contact admin
1.3.6.1.2.1.1.5.0    sysName       Hostname
1.3.6.1.2.1.1.6.0    sysLocation   Localisation
```

### Reseau
```
1.3.6.1.2.1.2.2.1.2  ifDescr       Interfaces
1.3.6.1.2.1.4.20.1.1 ipAdEntAddr   Adresses IP
1.3.6.1.2.1.4.21     ipRouteTable  Table de routage
1.3.6.1.2.1.4.22     ipNetToMedia  Table ARP
```

### Processus et services
```
1.3.6.1.2.1.25.4.2.1.2  hrSWRunName       Noms des processus
1.3.6.1.2.1.25.4.2.1.4  hrSWRunPath       Chemins executables
1.3.6.1.2.1.25.4.2.1.5  hrSWRunParameters Arguments (credentials!)
1.3.6.1.2.1.25.6.3.1.2  hrSWInstalledName Logiciels installes
```

### TCP/UDP
```
1.3.6.1.2.1.6.13     tcpConnTable  Connexions TCP
1.3.6.1.2.1.7.5.1.2  udpLocalPort  Ports UDP en ecoute
```

---

## Commandes rapides

```bash
# Enumeration basique
snmpwalk -v2c -c public <target> .1

# Informations systeme
snmpwalk -v2c -c public <target> 1.3.6.1.2.1.1

# Processus (peut contenir des credentials)
snmpwalk -v2c -c public <target> 1.3.6.1.2.1.25.4.2.1.5

# Brute-force community strings
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt <target>

# Rapport complet
snmp-check <target> -c public
```

---

## Wordlists community strings

- `/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt`
- `/usr/share/seclists/Discovery/SNMP/snmp.txt`
- `/usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt`

---

## Methodologie Red Team

1. **Scan UDP** : `nmap -sU -p 161 <target>`
2. **Brute-force community** : `onesixtyone` ou `hydra`
3. **Enumeration** : `snmpwalk` ou `snmp-check`
4. **Analyse** : Chercher credentials, usernames, paths
5. **Pivot** : Utiliser les infos pour mouvement lateral

---

## References additionnelles

- [MITRE ATT&CK - SNMP (T1602)](https://attack.mitre.org/techniques/T1602/)
- [Net-SNMP Documentation](http://www.net-snmp.org/docs/)
- [SNMP OID Repository](http://oid-info.com/)
