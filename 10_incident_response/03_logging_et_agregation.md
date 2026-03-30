# Logging et agrégation

**Durée : 50 min**

## Ce que vous allez apprendre dans ce cours

Les logs sont la matière première de toute investigation en cybersécurité. Sans logs, il est impossible de reconstituer une attaque, de détecter un comportement malveillant ou de prouver la conformité d'un système. Dans cette leçon, vous allez :

- comprendre pourquoi les logs sont essentiels en cybersécurité,
- identifier les différents types et formats de logs (syslog, CEF, EVTX, JSON),
- maîtriser les Event IDs Windows critiques pour la détection d'incidents,
- concevoir une architecture de centralisation des logs,
- manipuler les logs Linux avec les commandes journalctl, logger et logrotate,
- appréhender le pipeline complet de gestion des logs jusqu'au SIEM.

---

## Pourquoi les logs sont essentiels en cybersécurité

Un log (ou journal) est un enregistrement horodaté d'un événement survenu dans un système, une application ou un équipement réseau. Les logs constituent la mémoire de votre infrastructure. Voici les quatre raisons fondamentales pour lesquelles vous devez les collecter et les analyser.

### Détection des menaces

Les logs permettent d'identifier des comportements suspects en temps réel ou quasi-réel. Par exemple, une série de tentatives de connexion échouées (Event ID 4625 sous Windows) suivie d'une connexion réussie (Event ID 4624) peut signaler une attaque par brute force. Sans logs, cette attaque passerait totalement inaperçue.

### Investigation et réponse à incident

Lorsqu'un incident de sécurité survient, les logs sont votre principal outil pour reconstituer la chronologie des événements. Ils permettent de répondre aux questions critiques :

- **Quand** l'attaque a-t-elle commencé ?
- **Comment** l'attaquant est-il entré ?
- **Quels systèmes** ont été compromis ?
- **Quelles données** ont été exfiltrées ?

### Conformité réglementaire

De nombreuses réglementations exigent la conservation des logs :

| Réglementation | Exigence de logging |
|----------------|---------------------|
| **RGPD** | Traçabilité des accès aux données personnelles |
| **PCI DSS** | Conservation des logs d'accès pendant 1 an minimum |
| **ISO 27001** | Politique de journalisation et surveillance des événements |
| **HDS** | Traçabilité des accès aux données de santé |
| **NIS 2** | Capacité de détection et de réponse aux incidents |

### Audit trail (piste d'audit)

Les logs fournissent une piste d'audit complète et vérifiable. En cas de litige, de procédure judiciaire ou d'audit interne, ils constituent la preuve irréfutable de ce qui s'est passé sur vos systèmes. Un audit trail bien construit permet de démontrer que les actions ont été réalisées par des personnes autorisées et dans le cadre de leurs fonctions.

---

## Types de logs

Les logs proviennent de sources très variées. Voici les principales catégories que vous rencontrerez.

### Logs système

Les logs système enregistrent les événements liés au fonctionnement du système d'exploitation lui-même.

| Source | Emplacement (Linux) | Description |
|--------|---------------------|-------------|
| **syslog / rsyslog** | `/var/log/syslog` ou `/var/log/messages` | Journal principal du système |
| **journald (systemd)** | Binaire, accessible via `journalctl` | Journal structuré de systemd |
| **kern.log** | `/var/log/kern.log` | Messages du noyau Linux |
| **dmesg** | Mémoire ring buffer du noyau | Messages de démarrage et matériel |
| **boot.log** | `/var/log/boot.log` | Événements de démarrage |

### Logs applicatifs

Chaque application génère ses propres logs avec des formats souvent spécifiques.

| Application | Emplacement courant | Exemple de contenu |
|-------------|---------------------|--------------------|
| **Apache** | `/var/log/apache2/access.log` | `192.168.1.10 - - [15/03/2026:14:22:01] "GET /admin HTTP/1.1" 200 1234` |
| **Nginx** | `/var/log/nginx/access.log` | Requêtes HTTP, codes de retour, user-agents |
| **MySQL** | `/var/log/mysql/error.log` | Erreurs, connexions, requêtes lentes |
| **SSH** | `/var/log/auth.log` | Tentatives de connexion SSH réussies et échouées |

### Logs de sécurité

Ces logs sont spécifiquement dédiés aux événements de sécurité.

| Source | Système | Description |
|--------|---------|-------------|
| **auth.log** | Linux | Authentifications, sudo, su, SSH |
| **faillog** | Linux | Tentatives de connexion échouées |
| **Windows Security Log** | Windows | Connexions, modifications de permissions, accès aux objets |
| **Windows PowerShell Log** | Windows | Commandes PowerShell exécutées |
| **audit.log** | Linux (auditd) | Événements audités par le framework audit |

### Logs réseau

Les équipements réseau génèrent des logs essentiels pour la détection d'intrusions.

| Source | Description |
|--------|-------------|
| **Firewall** | Connexions autorisées et bloquées, règles déclenchées |
| **IDS/IPS** (Snort, Suricata) | Alertes de détection d'intrusion, signatures déclenchées |
| **Proxy** | URL visitées, catégorisation, données transférées |
| **DNS** | Requêtes de résolution de noms (détection de tunneling DNS, DGA) |
| **VPN** | Connexions VPN, utilisateurs, durées de session |
| **NetFlow / sFlow** | Métadonnées de flux réseau (IP source/destination, ports, volumes) |

---

## Format des logs

Les logs peuvent être écrits dans différents formats. Comprendre ces formats est indispensable pour parser et normaliser les données.

### Syslog (RFC 5424)

Syslog est le standard historique de journalisation sous Unix/Linux. La RFC 5424 définit le format moderne.

Structure d'un message syslog :

```
<PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
```

Exemple :

```
<34>1 2026-03-15T14:22:01.123Z webserver01 sshd 12345 - - Failed password for root from 192.168.1.100 port 22 ssh2
```

Le champ **PRI** (Priority) est calculé par la formule : `PRI = Facility * 8 + Severity`.

#### Facility (source du message)

| Code | Facility | Description |
|------|----------|-------------|
| 0 | kern | Messages du noyau |
| 1 | user | Messages des programmes utilisateur |
| 2 | mail | Système de messagerie |
| 3 | daemon | Daemons système |
| 4 | auth | Authentification et sécurité |
| 5 | syslog | Messages internes de syslog |
| 10 | authpriv | Authentification privée |
| 16-23 | local0-local7 | Usage personnalisé |

#### Severity (niveau de gravité)

| Code | Severity | Description | Exemple |
|------|----------|-------------|---------|
| 0 | **Emergency** | Système inutilisable | Kernel panic |
| 1 | **Alert** | Action immédiate requise | Base de données corrompue |
| 2 | **Critical** | Conditions critiques | Défaillance matérielle |
| 3 | **Error** | Conditions d'erreur | Échec d'écriture disque |
| 4 | **Warning** | Avertissements | Espace disque bas |
| 5 | **Notice** | Normal mais significatif | Démarrage d'un service |
| 6 | **Informational** | Messages d'information | Connexion utilisateur |
| 7 | **Debug** | Messages de débogage | Détail d'exécution d'une fonction |

### CEF (Common Event Format)

Le CEF est un format standardisé développé par ArcSight (Micro Focus). Il est largement utilisé pour l'interopérabilité entre les équipements de sécurité.

```
CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
```

Exemple :

```
CEF:0|Fortinet|FortiGate|7.0|123456|Intrusion Detected|8|src=192.168.1.100 dst=10.0.0.5 dpt=443 act=blocked
```

### JSON

Le format JSON est de plus en plus utilisé pour les logs car il est structuré, facilement parsable et extensible.

```json
{
  "timestamp": "2026-03-15T14:22:01.123Z",
  "hostname": "webserver01",
  "service": "sshd",
  "severity": "warning",
  "message": "Failed password for root from 192.168.1.100 port 22",
  "source_ip": "192.168.1.100",
  "user": "root",
  "event_type": "authentication_failure"
}
```

### Windows Event Log (EVTX)

Les logs Windows utilisent un format binaire propriétaire (EVTX) accessible via l'Event Viewer ou PowerShell. Chaque événement contient :

- **Event ID** : identifiant numérique unique du type d'événement
- **Source** : composant qui a généré l'événement
- **Level** : Information, Warning, Error, Critical, Verbose
- **Channel** : Security, System, Application, etc.
- **Timestamp** : date et heure de l'événement
- **Données structurées** : champs spécifiques selon l'Event ID

---

## Windows Event Logs en détail

Les Event Logs Windows sont une source d'information critique pour la détection d'incidents. Vous devez connaître les canaux principaux et les Event IDs les plus importants.

### Canaux principaux

| Canal | Description | Intérêt sécurité |
|-------|-------------|------------------|
| **Security** | Connexions, déconnexions, modifications de permissions | Très élevé |
| **System** | Événements système, démarrage/arrêt de services | Élevé |
| **Application** | Événements applicatifs, erreurs, crashes | Moyen |
| **Microsoft-Windows-PowerShell/Operational** | Commandes PowerShell exécutées | Très élevé |
| **Microsoft-Windows-Sysmon/Operational** | Événements Sysmon (si installé) | Très élevé |
| **Microsoft-Windows-Windows Defender/Operational** | Détections antivirus | Élevé |

### Event IDs critiques pour la sécurité

Voici les Event IDs que tout analyste SOC doit connaître. Ce tableau est votre référence quotidienne.

| Event ID | Canal | Description | Pourquoi c'est critique |
|----------|-------|-------------|------------------------|
| **4624** | Security | Connexion réussie | Identifier qui se connecte, quand et comment (type de logon) |
| **4625** | Security | Échec de connexion | Détecter les attaques brute force et le password spraying |
| **4648** | Security | Connexion avec des credentials explicites | Détecter le mouvement latéral (RunAs, PsExec) |
| **4672** | Security | Attribution de privilèges spéciaux | Détecter l'utilisation de comptes à hauts privilèges |
| **4688** | Security | Création d'un nouveau processus | Surveiller l'exécution de programmes suspects |
| **4697** | Security | Installation d'un service | Détecter la persistance par création de services |
| **4720** | Security | Création d'un compte utilisateur | Détecter la création de comptes backdoor |
| **4732** | Security | Ajout d'un membre à un groupe local | Détecter l'élévation de privilèges |
| **7045** | System | Installation d'un nouveau service | Détecter la persistance et les outils d'attaque |
| **1102** | Security | Journal d'audit effacé | Détecter la destruction de preuves (anti-forensics) |
| **4104** | PowerShell | Exécution de bloc de script | Détecter les scripts malveillants PowerShell |
| **1** | Sysmon | Création de processus | Ligne de commande complète, hash du binaire, processus parent |
| **3** | Sysmon | Connexion réseau | Détecter les communications C2 (Command & Control) |
| **11** | Sysmon | Création de fichier | Détecter le dépôt de malwares et d'outils |

### Exemple : détecter une attaque brute force

Voici la séquence d'événements que vous observerez dans les logs Windows lors d'une attaque brute force :

```
[4625] Échec de connexion - Utilisateur: admin - IP: 185.220.101.42 - 14:22:01
[4625] Échec de connexion - Utilisateur: admin - IP: 185.220.101.42 - 14:22:02
[4625] Échec de connexion - Utilisateur: admin - IP: 185.220.101.42 - 14:22:03
... (des centaines de tentatives)
[4624] Connexion réussie - Utilisateur: admin - IP: 185.220.101.42 - 14:25:17
[4672] Privilèges spéciaux attribués - Utilisateur: admin - 14:25:17
```

Cette séquence indique clairement une attaque brute force suivie d'une compromission du compte admin.

### Consulter les Event Logs avec PowerShell

```powershell
# Lister les 10 derniers événements de connexion échouée
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 10

# Chercher les connexions réussies depuis une IP spécifique
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} |
    Where-Object { $_.Message -match "185.220.101.42" }

# Lister les services installés récemment
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -MaxEvents 20

# Exporter les logs de sécurité des dernières 24h
$startTime = (Get-Date).AddDays(-1)
Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$startTime} |
    Export-Csv -Path "security_logs.csv" -NoTypeInformation
```

---

## Centralisation des logs

### Pourquoi centraliser ?

Sur une infrastructure de taille moyenne (50 serveurs, 200 postes de travail), les logs sont dispersés sur des dizaines de machines. Sans centralisation :

- vous devez vous connecter à chaque machine individuellement pour consulter les logs,
- un attaquant peut supprimer les logs locaux pour couvrir ses traces,
- la corrélation entre événements de différentes sources est impossible,
- la rétention à long terme est difficile à garantir.

La centralisation résout tous ces problèmes en envoyant une copie de tous les logs vers un serveur central sécurisé.

### Architectures de centralisation

| Architecture | Principe | Avantages | Inconvénients |
|--------------|----------|-----------|---------------|
| **Agent-based** | Un agent installé sur chaque machine envoie les logs | Fiable, supporte le buffering, chiffrement | Agent à déployer et maintenir |
| **Agentless** | Les machines envoient directement leurs logs via syslog | Simple, pas d'agent à maintenir | Moins fiable (UDP), moins de contrôle |
| **Hybride** | Agents sur les serveurs critiques, syslog pour le reste | Compromis coût/fiabilité | Complexité de gestion |

### Protocoles de transport

| Protocole | Port | Description |
|-----------|------|-------------|
| **Syslog UDP** | 514 | Transport classique, non fiable (perte de messages possible) |
| **Syslog TCP** | 514 | Transport fiable avec accusé de réception |
| **Syslog TLS** | 6514 | Syslog chiffré (recommandé en production) |
| **Beats** (Elastic) | 5044 | Agents légers Elastic (Filebeat, Winlogbeat) |
| **WEF** (Windows) | 5985/5986 | Windows Event Forwarding, natif Windows |
| **Wazuh Agent** | 1514 | Agent Wazuh, chiffré, compressé |

### Schéma d'architecture de centralisation

```
┌──────────────┐  ┌─────────────┐  ┌─────────────┐
│  Serveur Web │  │  Poste Win  │  │  Firewall   │
│   (syslog)   │  │   (agent)   │  │  (syslog)   │
└──────┬───────┘  └──────┬──────┘  └───────┬─────┘
       │                 │                 │
       │    Syslog TLS   │   Beats/WEF     │  Syslog TCP
       │                 │                 │
       └────────────┬────┴────────┬────────┘
                    │             │
              ┌─────▼─────────────▼─────┐
              │    Collecteur central   │
              │  (Wazuh / Logstash /    │
              │   Fluentd / rsyslog)    │
              └───────────┬─────────────┘
                          │
              ┌───────────▼─────────────┐
              │     Stockage / SIEM     │
              │  (Wazuh Indexer /       │
              │   Elasticsearch /       │
              │   OpenSearch)           │
              └───────────┬─────────────┘
                          │
              ┌───────────▼─────────────┐
              │      Dashboard          │
              │  (Wazuh Dashboard /     │
              │   Kibana / Grafana)     │
              └─────────────────────────┘
```

---

## Agrégation et normalisation

Une fois les logs centralisés, ils doivent être traités pour être exploitables.

### Pipeline de traitement des logs

Le pipeline complet suit ces étapes :

| Étape | Description | Exemple |
|-------|-------------|---------|
| **1. Collecte** | Réception des logs bruts depuis les sources | Réception d'un message syslog sur le port 514 |
| **2. Transport** | Acheminement vers le serveur central | Transmission via TLS vers le collecteur |
| **3. Parsing** | Extraction des champs structurés depuis le log brut | Extraction de l'IP source, l'utilisateur, l'action |
| **4. Normalisation** | Conversion dans un format commun | Renommer `src_ip` en `source.ip` selon un schéma commun |
| **5. Enrichissement** | Ajout d'informations contextuelles | Géolocalisation de l'IP, réputation, nom de l'asset |
| **6. Stockage** | Écriture dans la base de données | Indexation dans OpenSearch/Elasticsearch |
| **7. Indexation** | Création d'index pour la recherche rapide | Index par date : `wazuh-alerts-2026.03.15` |
| **8. Visualisation** | Affichage dans un dashboard | Graphiques, alertes, tableaux dans le SIEM |

### Exemple de parsing

Un log Apache brut :

```
192.168.1.10 - admin [15/Mar/2026:14:22:01 +0000] "POST /login HTTP/1.1" 401 512 "-" "Mozilla/5.0"
```

Après parsing et normalisation :

```json
{
  "source_ip": "192.168.1.10",
  "user": "admin",
  "timestamp": "2026-03-15T14:22:01Z",
  "method": "POST",
  "url": "/login",
  "protocol": "HTTP/1.1",
  "status_code": 401,
  "response_size": 512,
  "user_agent": "Mozilla/5.0",
  "event_type": "web_access",
  "outcome": "failure"
}
```

### Corrélation

La corrélation consiste à relier des événements provenant de sources différentes pour identifier un scénario d'attaque. Par exemple :

1. **Firewall** : connexion entrante depuis 185.220.101.42 vers le serveur web (port 443)
2. **Serveur web** : multiples requêtes POST vers /login avec code 401 depuis 185.220.101.42
3. **Windows Security** : Event ID 4624 - Connexion réussie de l'utilisateur "admin"
4. **Sysmon** : Exécution de `whoami.exe` puis `net user` par l'utilisateur "admin"

Individuellement, chaque événement peut paraître bénin. Ensemble, ils révèlent une intrusion complète.

---

## Rétention des logs

### Politiques de rétention

La durée de conservation des logs dépend de plusieurs facteurs :

| Type de log | Rétention recommandée | Justification |
|-------------|----------------------|---------------|
| **Logs de sécurité** | 12 à 24 mois | Investigation d'incidents, le temps moyen de détection (dwell time) est de ~200 jours |
| **Logs applicatifs** | 3 à 6 mois | Debugging et analyse de performance |
| **Logs système** | 6 à 12 mois | Troubleshooting et audit |
| **Logs réseau (NetFlow)** | 3 à 6 mois | Volume très important, conservation coûteuse |
| **Logs de conformité** | Selon réglementation | PCI DSS : 1 an, certaines réglementations : jusqu'à 5 ans |

### Contraintes légales (RGPD)

Le RGPD impose des contraintes spécifiques sur la conservation des logs :

- Les logs contenant des données personnelles (adresses IP, identifiants utilisateur) sont soumis au RGPD
- La durée de conservation doit être proportionnée à la finalité (sécurité)
- Les logs doivent être supprimés ou anonymisés lorsque la durée de rétention est atteinte
- L'accès aux logs doit être restreint et tracé

### Dimensionnement du stockage

Pour estimer l'espace nécessaire, voici des ordres de grandeur :

| Source | Volume estimé par jour | Volume par an |
|--------|----------------------|---------------|
| **1 serveur Linux** (syslog) | 50 à 200 Mo | 18 à 73 Go |
| **1 poste Windows** (Event Logs) | 100 à 500 Mo | 36 à 182 Go |
| **1 firewall** (moyen trafic) | 500 Mo à 2 Go | 182 à 730 Go |
| **1 serveur web** (accès moyen) | 200 Mo à 1 Go | 73 à 365 Go |

Pour une infrastructure de 100 machines, prévoyez entre **5 et 50 To par an** selon la verbosité des logs et le niveau de détail souhaité.

---

## Introduction au SIEM

### Qu'est-ce qu'un SIEM ?

Un **SIEM** (Security Information and Event Management) est une solution qui combine :

- **SIM** (Security Information Management) : collecte, stockage et analyse des logs
- **SEM** (Security Event Management) : corrélation en temps réel, alertes, dashboards

Le SIEM est l'outil central d'un **SOC** (Security Operations Center). Il permet de :

- centraliser tous les logs de l'infrastructure,
- appliquer des règles de détection automatiques,
- générer des alertes en cas d'activité suspecte,
- fournir des dashboards de supervision,
- faciliter l'investigation avec des outils de recherche.

### Solutions SIEM courantes

| Solution | Type | Points forts |
|----------|------|-------------|
| **Wazuh** | Open source | Gratuit, XDR intégré, large communauté |
| **Splunk** | Commercial | Très puissant, langage SPL, large écosystème |
| **Elastic SIEM** | Open source / Commercial | Basé sur Elasticsearch, flexible, scalable |
| **QRadar** (IBM) | Commercial | Corrélation avancée, threat intelligence intégrée |
| **Microsoft Sentinel** | Cloud (Azure) | Intégration native Microsoft, IA/ML |

Dans le prochain cours, nous étudierons en détail **Wazuh**, la solution SIEM open source que nous utiliserons tout au long de ce module.

---

## Commandes Linux pour la gestion des logs

### journalctl

`journalctl` est l'outil principal pour consulter les logs systemd (journald).

```bash
# Afficher tous les logs
journalctl

# Afficher les logs depuis le dernier démarrage
journalctl -b

# Afficher les logs en temps réel (comme tail -f)
journalctl -f

# Filtrer par service
journalctl -u sshd

# Filtrer par priorité (severity)
journalctl -p err    # Uniquement les erreurs et niveaux supérieurs

# Filtrer par période
journalctl --since "2026-03-15 14:00:00" --until "2026-03-15 15:00:00"

# Filtrer par PID
journalctl _PID=1234

# Afficher les logs du noyau
journalctl -k

# Format JSON pour l'export
journalctl -u sshd -o json-pretty
```

### Fichiers de logs dans /var/log/

```bash
# Lister les fichiers de logs
ls -la /var/log/

# Consulter les logs d'authentification
cat /var/log/auth.log          # Debian/Ubuntu
cat /var/log/secure            # RHEL/CentOS

# Suivre les logs en temps réel
tail -f /var/log/syslog

# Chercher les échecs de connexion SSH
grep "Failed password" /var/log/auth.log

# Compter les tentatives échouées par IP
grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head
```

### logger

La commande `logger` permet d'écrire manuellement un message dans syslog. Elle est utile dans les scripts.

```bash
# Écrire un message simple
logger "Backup completed successfully"

# Spécifier la facility et la severity
logger -p auth.warning "Suspicious login attempt detected"

# Ajouter un tag (nom de l'application)
logger -t mybackup "Backup of /data started"

# Résultat dans /var/log/syslog :
# Mar 15 14:22:01 webserver01 mybackup: Backup of /data started
```

### logrotate

`logrotate` gère la rotation automatique des fichiers de logs pour éviter qu'ils ne remplissent le disque.

```bash
# Fichier de configuration principal
cat /etc/logrotate.conf

# Configurations spécifiques par application
ls /etc/logrotate.d/
```

Exemple de configuration pour un log applicatif :

```
/var/log/myapp/*.log {
    daily              # Rotation quotidienne
    rotate 30          # Garder 30 fichiers
    compress           # Compresser les anciens fichiers
    delaycompress      # Ne pas compresser le fichier le plus récent
    missingok          # Ne pas échouer si le fichier n'existe pas
    notifempty         # Ne pas tourner si le fichier est vide
    create 0640 root adm  # Permissions du nouveau fichier
    postrotate
        systemctl reload myapp > /dev/null 2>&1 || true
    endscript
}
```

---

## Glossaire des sigles et définitions

| Sigle/Terme | Définition |
|-------------|------------|
| **Log** | Enregistrement horodaté d'un événement dans un système |
| **Syslog** | Protocole et format standard de journalisation (RFC 5424) |
| **EVTX** | Format binaire des Event Logs Windows |
| **CEF** | Common Event Format - Format standardisé pour les logs de sécurité |
| **SIEM** | Security Information and Event Management - Outil de centralisation et corrélation des logs |
| **SOC** | Security Operations Center - Centre opérationnel de sécurité |
| **Event ID** | Identifiant numérique d'un type d'événement dans les logs Windows |
| **Facility** | Catégorie source d'un message syslog (kern, auth, daemon, etc.) |
| **Severity** | Niveau de gravité d'un message syslog (0=Emergency à 7=Debug) |
| **Parsing** | Extraction de champs structurés depuis un log brut |
| **Normalisation** | Conversion des logs dans un format commun et cohérent |
| **Corrélation** | Mise en relation d'événements provenant de sources différentes |
| **Rétention** | Durée de conservation des logs |
| **Audit trail** | Piste d'audit - enregistrement chronologique des activités |
| **IDS/IPS** | Intrusion Detection/Prevention System |
| **WEF** | Windows Event Forwarding - Mécanisme natif Windows de transfert de logs |
| **NetFlow** | Protocole Cisco de collecte de métadonnées sur les flux réseau |
| **Dwell time** | Durée entre la compromission initiale et la détection de l'incident |
| **journald** | Service de journalisation de systemd |

---

## Récapitulatif des commandes

| Commande | Description |
|----------|-------------|
| `journalctl` | Consulter les logs systemd |
| `journalctl -b` | Logs depuis le dernier démarrage |
| `journalctl -f` | Suivre les logs en temps réel |
| `journalctl -u <service>` | Filtrer par service |
| `journalctl -p <priority>` | Filtrer par priorité (emerg, alert, crit, err, warning, notice, info, debug) |
| `journalctl --since "YYYY-MM-DD HH:MM:SS"` | Filtrer par date de début |
| `journalctl -o json-pretty` | Sortie au format JSON |
| `tail -f /var/log/syslog` | Suivre un fichier de log en temps réel |
| `logger "message"` | Écrire un message dans syslog |
| `logger -p <facility.severity> "message"` | Écrire avec facility et severity spécifiques |
| `logger -t <tag> "message"` | Écrire avec un tag applicatif |
| `logrotate /etc/logrotate.conf` | Exécuter la rotation des logs manuellement |
| `Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625}` | Consulter les Event Logs Windows (PowerShell) |

---

## Ressources

- RFC 5424 - The Syslog Protocol : https://www.rfc-editor.org/rfc/rfc5424
- NIST SP 800-92 - Guide to Computer Security Log Management
- Microsoft - Windows Security Event Log Reference
- SANS - Windows Event Log Analysis Cheat Sheet
- Elastic Common Schema (ECS) - Standard de normalisation des logs

### Ressources pratiques - TryHackMe / HackTheBox

| Plateforme | Room/Lab | Description |
|------------|----------|-------------|
| TryHackMe | [Windows Event Logs](https://tryhackme.com/room/dvwindowseventlogs) | Exploration et analyse des Event Logs Windows |
| TryHackMe | [Intro to Logs](https://tryhackme.com/room/dvintrotologs) | Introduction aux différents types de logs et leur analyse |
| HackTheBox | [Logjammer (Sherlock)](https://app.hackthebox.com/sherlocks/Logjammer) | Investigation forensique basée sur l'analyse de logs |
