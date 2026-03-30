# Installation de Wazuh sur les endpoints

**Durée : 45 min**

## Ce que vous allez apprendre dans ce cours

Le serveur Wazuh est en place, mais sans agents déployés sur les endpoints, il ne reçoit aucune donnée. Ce cours vous guide dans l'installation et la configuration des agents sur les machines à surveiller. Dans cette leçon, vous allez :

- comprendre le rôle de l'agent Wazuh et son fonctionnement,
- installer un agent sur une machine Linux (Debian/Ubuntu),
- installer un agent sur une machine Windows,
- vérifier la connexion entre l'agent et le manager,
- gérer les agents (groupes, configuration centralisée, suppression),
- diagnostiquer les problèmes de connexion courants.

---

## Concept d'agent Wazuh

### Qu'est-ce qu'un agent ?

L'agent Wazuh est un logiciel léger installé sur chaque machine (endpoint) que vous souhaitez surveiller. Il fonctionne en arrière-plan et collecte les données de sécurité pour les envoyer au manager.

### Données collectées par l'agent

| Type de données | Description | Exemple |
|-----------------|-------------|---------|
| **Logs système** | Événements du système d'exploitation | syslog, Windows Event Logs |
| **Logs applicatifs** | Événements des applications installées | Apache, Nginx, MySQL |
| **Intégrité des fichiers** | Hashes et attributs des fichiers surveillés | Modification de `/etc/passwd` |
| **Inventaire logiciel** | Packages et versions installés | Liste des paquets pour la détection de vulnérabilités |
| **Configuration système** | État de la configuration de sécurité | Vérification des benchmarks CIS |
| **Processus en cours** | Liste des processus actifs | Détection de processus suspects |
| **Ports ouverts** | Ports réseau en écoute | Détection de services non autorisés |
| **Informations matérielles** | CPU, RAM, réseau, OS | Inventaire des assets |

### Cycle de vie de la communication

```
┌──────────────┐                              ┌──────────────────┐
│              │   1. Enrollment (port 1515)  │                  │
│              │  ──────────────────────────► │                  │
│              │   ◄──────────────────────────│                  │
│              │   Clé d'authentification     │                  │
│              │                              │                  │
│    AGENT     │   2. Événements (port 1514)  │     MANAGER      │
│              │  ──────────────────────────► │                  │
│   Endpoint   │   (chiffré AES-256,          │   Serveur Wazuh  │
│              │    compressé)                │                  │
│              │                              │                  │
│              │  3. Configuration centralisée│                  │
│              │  ◄────────────────────────── │                  │
│              │                              │                  │
│              │   4. Active Response         │                  │
│              │  ◄────────────────────────── │                  │
│              │   (commandes de réponse)     │                  │
└──────────────┘                              └──────────────────┘
```

---

## Plateformes supportées

Wazuh supporte un large éventail de plateformes :

| Plateforme | Versions supportées | Méthode d'installation |
|------------|--------------------|-----------------------|
| **Ubuntu** | 16.04, 18.04, 20.04, 22.04, 24.04 | Package DEB |
| **Debian** | 9, 10, 11, 12 | Package DEB |
| **CentOS / RHEL** | 7, 8, 9 | Package RPM |
| **SUSE / openSUSE** | 12, 15 | Package RPM |
| **Amazon Linux** | 2, 2023 | Package RPM |
| **Windows** | 7, 8.1, 10, 11, Server 2012+, Server 2016+, Server 2019+, Server 2022 | Installeur MSI |
| **macOS** | 10.15 (Catalina) et supérieur | Package PKG |

---

## Méthodes d'enregistrement des agents

Avant de communiquer avec le manager, chaque agent doit être enregistré. Wazuh propose trois méthodes.

| Méthode | Description | Cas d'usage |
|---------|-------------|-------------|
| **Auto-enrollment** | L'agent s'enregistre automatiquement au premier démarrage | Méthode recommandée, la plus simple |
| **Mot de passe d'enregistrement** | L'agent fournit un mot de passe partagé pour s'enregistrer | Sécurité supplémentaire en environnement ouvert |
| **Clé manuelle** | L'administrateur génère une clé sur le manager et la copie sur l'agent | Environnements très restreints sans connectivité directe |

### Auto-enrollment (méthode recommandée)

L'auto-enrollment est activé par défaut. L'agent contacte le manager sur le port 1515, s'enregistre automatiquement et reçoit sa clé unique. C'est la méthode que nous utiliserons dans ce cours.

### Mot de passe d'enregistrement

Pour les environnements nécessitant un contrôle supplémentaire, vous pouvez configurer un mot de passe d'enregistrement sur le manager :

```bash
# Sur le manager : définir le mot de passe d'enrollment
echo "MonMotDePasseEnrollment123!" | sudo tee /var/ossec/etc/authd.pass
sudo chmod 640 /var/ossec/etc/authd.pass
sudo chown root:wazuh /var/ossec/etc/authd.pass

# Redémarrer le service d'authentification
sudo systemctl restart wazuh-manager
```

L'agent devra alors fournir ce mot de passe lors de son enregistrement.

---

## Installation de l'agent Linux (Debian/Ubuntu)

### Étape 1 : Ajouter le repository Wazuh

```bash
# Importer la clé GPG de Wazuh
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --no-default-keyring \
  --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && \
  sudo chmod 644 /usr/share/keyrings/wazuh.gpg

# Ajouter le repository
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | \
  sudo tee /etc/apt/sources.list.d/wazuh.list

# Mettre à jour la liste des packages
sudo apt update
```

### Étape 2 : Installer le package wazuh-agent

Lors de l'installation, vous devez spécifier l'adresse IP ou le nom DNS de votre serveur Wazuh manager.

```bash
# Installer l'agent en spécifiant l'adresse du manager
WAZUH_MANAGER="10.0.0.100" sudo apt install -y wazuh-agent
```

Remplacez `10.0.0.100` par l'adresse IP de votre serveur Wazuh.

Si vous utilisez un mot de passe d'enrollment :

```bash
WAZUH_MANAGER="10.0.0.100" \
WAZUH_REGISTRATION_PASSWORD="MonMotDePasseEnrollment123!" \
sudo apt install -y wazuh-agent
```

### Étape 3 : Vérifier la configuration

Le fichier de configuration de l'agent se trouve dans `/var/ossec/etc/ossec.conf`. Vérifiez que l'adresse du manager est correcte.

```bash
# Vérifier la configuration
sudo cat /var/ossec/etc/ossec.conf | grep -A 3 "<server>"
```

Vous devriez voir :

```xml
<server>
  <address>10.0.0.100</address>
  <port>1514</port>
  <protocol>tcp</protocol>
</server>
```

Si l'adresse n'est pas correcte, modifiez-la :

```bash
# Ouvrir le fichier de configuration
sudo nano /var/ossec/etc/ossec.conf
```

Localisez la section `<client>` et modifiez l'adresse :

```xml
<client>
  <server>
    <address>10.0.0.100</address>
    <port>1514</port>
    <protocol>tcp</protocol>
  </server>
  <enrollment>
    <enabled>yes</enabled>
  </enrollment>
</client>
```

### Étape 4 : Démarrer le service

```bash
# Activer le démarrage automatique
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent

# Démarrer l'agent
sudo systemctl start wazuh-agent

# Vérifier le statut
sudo systemctl status wazuh-agent
```

Sortie attendue :

```
● wazuh-agent.service - Wazuh agent
     Loaded: loaded (/usr/lib/systemd/system/wazuh-agent.service; enabled)
     Active: active (running) since Mon 2026-03-15 14:30:00 UTC; 10s ago
```

### Étape 5 : Vérifier la connexion

```bash
# Vérifier les logs de l'agent
sudo tail -20 /var/ossec/logs/ossec.log
```

Vous devriez voir des messages confirmant la connexion :

```
2026/03/15 14:30:05 wazuh-agentd: INFO: Connected to server (10.0.0.100:1514/tcp).
2026/03/15 14:30:05 wazuh-agentd: INFO: (4102): Connected to the server (10.0.0.100:1514/tcp).
```

### Installation sur CentOS / RHEL

La procédure est similaire mais utilise le gestionnaire de paquets YUM/DNF :

```bash
# Importer la clé GPG
sudo rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH

# Ajouter le repository
cat << EOF | sudo tee /etc/yum.repos.d/wazuh.repo
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-\$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF

# Installer l'agent
WAZUH_MANAGER="10.0.0.100" sudo yum install -y wazuh-agent

# Démarrer le service
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

---

## Installation de l'agent Windows

### Méthode 1 : Installation via l'interface graphique (GUI)

1. Téléchargez l'installeur MSI depuis le site officiel :
   ```
   https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.0-1.msi
   ```

2. Double-cliquez sur le fichier MSI téléchargé

3. Suivez l'assistant d'installation :
   - Acceptez la licence
   - Dans le champ **Manager IP**, entrez l'adresse de votre serveur Wazuh : `10.0.0.100`
   - Optionnel : entrez le mot de passe d'enrollment si configuré
   - Cliquez sur **Install**

4. L'agent se connecte automatiquement au manager après l'installation

### Méthode 2 : Installation en ligne de commande (CLI)

L'installation en ligne de commande est préférable pour les déploiements automatisés. Ouvrez une invite de commandes ou PowerShell **en tant qu'administrateur**.

```powershell
# Télécharger l'installeur
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.0-1.msi `
  -OutFile $env:TEMP\wazuh-agent.msi

# Installation silencieuse avec l'adresse du manager
msiexec.exe /i $env:TEMP\wazuh-agent.msi /q `
  WAZUH_MANAGER="10.0.0.100" `
  WAZUH_AGENT_NAME="PC-WINDOWS-01" `
  WAZUH_AGENT_GROUP="windows-workstations"
```

Paramètres disponibles pour `msiexec` :

| Paramètre | Description | Exemple |
|-----------|-------------|---------|
| `WAZUH_MANAGER` | Adresse IP ou hostname du manager | `10.0.0.100` |
| `WAZUH_AGENT_NAME` | Nom de l'agent (par défaut : hostname) | `PC-WINDOWS-01` |
| `WAZUH_AGENT_GROUP` | Groupe de l'agent | `windows-workstations` |
| `WAZUH_REGISTRATION_PASSWORD` | Mot de passe d'enrollment | `MonMotDePasse123!` |
| `WAZUH_REGISTRATION_SERVER` | Adresse du serveur d'enrollment (si différente du manager) | `10.0.0.101` |

### Configuration Windows

Le fichier de configuration de l'agent Windows se trouve dans :

```
C:\Program Files (x86)\ossec-agent\ossec.conf
```

Vérifiez que l'adresse du manager est correcte :

```powershell
# Afficher la section server du fichier de configuration
Select-String -Path "C:\Program Files (x86)\ossec-agent\ossec.conf" -Pattern "address" -Context 1,1
```

### Démarrage du service Windows

Le service Wazuh peut être géré de plusieurs manières :

```powershell
# Via PowerShell
# Démarrer le service
Start-Service WazuhSvc

# Vérifier le statut
Get-Service WazuhSvc

# Arrêter le service
Stop-Service WazuhSvc

# Redémarrer le service
Restart-Service WazuhSvc
```

```cmd
# Via la ligne de commande classique
net start WazuhSvc
net stop WazuhSvc
```

Vous pouvez également gérer le service via **services.msc** :

1. Appuyez sur `Win + R`
2. Tapez `services.msc` et validez
3. Cherchez **Wazuh** dans la liste des services
4. Clic droit pour démarrer, arrêter ou redémarrer le service

### Vérification des logs Windows

```powershell
# Afficher les dernières lignes du log de l'agent
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 30

# Chercher les erreurs
Select-String -Path "C:\Program Files (x86)\ossec-agent\ossec.log" -Pattern "error|ERROR"

# Suivre les logs en temps réel (PowerShell 7+)
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 10 -Wait
```

---

## Vérification de la connexion

Après l'installation d'un agent, vous devez vérifier qu'il communique correctement avec le manager. Voici les trois méthodes de vérification.

### Côté agent (Linux)

```bash
# Vérifier le statut de l'agent
sudo /var/ossec/bin/wazuh-control status

# Sortie attendue :
# wazuh-agentd is running...
# wazuh-execd is running...
# wazuh-modulesd is running...
# wazuh-syscheckd is running...
# wazuh-logcollector is running...

# Vérifier les logs de connexion
sudo grep "Connected" /var/ossec/logs/ossec.log

# Vérifier l'ID de l'agent
sudo cat /var/ossec/etc/client.keys
# Sortie : 001 linux-agent any TopSecretKey64EncodedHere==
```

### Côté agent (Windows)

```powershell
# Vérifier le statut du service
Get-Service WazuhSvc

# Vérifier les logs de connexion
Select-String -Path "C:\Program Files (x86)\ossec-agent\ossec.log" -Pattern "Connected"

# Vérifier l'ID de l'agent
Get-Content "C:\Program Files (x86)\ossec-agent\client.keys"
```

### Côté serveur (manager)

```bash
# Lister tous les agents connectés
sudo /var/ossec/bin/agent_control -l

# Sortie attendue :
# Wazuh agent_control. List of available agents:
#    ID: 000, Name: wazuh-server (server), IP: 127.0.0.1, Active/Local
#    ID: 001, Name: linux-agent, IP: 10.0.0.50, Active
#    ID: 002, Name: PC-WINDOWS-01, IP: 10.0.0.60, Active

# Obtenir les détails d'un agent spécifique
sudo /var/ossec/bin/agent_control -i 001

# Via l'API REST
TOKEN=$(curl -s -u admin:PASSWORD -k -X POST \
  "https://localhost:55000/security/user/authenticate" | \
  python3 -c "import sys,json; print(json.load(sys.stdin)['data']['token'])")

# Lister les agents
curl -s -k -X GET "https://localhost:55000/agents" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

# Obtenir les détails d'un agent
curl -s -k -X GET "https://localhost:55000/agents/001" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

### Via le dashboard

1. Connectez-vous au Wazuh Dashboard (https://IP:443)
2. Allez dans le menu **Agents** (ou **Server management > Endpoints Summary**)
3. Vous devriez voir vos agents listés avec leur statut :
   - **Active** (vert) : l'agent est connecté et envoie des données
   - **Disconnected** (rouge) : l'agent ne communique plus
   - **Pending** (jaune) : l'agent est en cours d'enregistrement
   - **Never connected** (gris) : l'agent est enregistré mais ne s'est jamais connecté

---

## Gestion des agents

### Groupes d'agents

Les groupes permettent d'appliquer des configurations spécifiques à un ensemble d'agents. Par exemple, vous pouvez créer un groupe pour les serveurs web avec une configuration de monitoring adaptée.

```bash
# Créer un groupe
sudo /var/ossec/bin/agent_groups -a -g linux-servers

# Affecter un agent à un groupe
sudo /var/ossec/bin/agent_groups -a -i 001 -g linux-servers

# Via l'API REST
curl -s -k -X PUT "https://localhost:55000/agents/001/group/linux-servers" \
  -H "Authorization: Bearer $TOKEN"

# Lister les groupes
sudo /var/ossec/bin/agent_groups -l

# Lister les agents d'un groupe
sudo /var/ossec/bin/agent_groups -l -g linux-servers
```

### Configuration centralisée

Chaque groupe possède un fichier de configuration partagé. Tous les agents du groupe reçoivent automatiquement cette configuration.

```bash
# Le fichier de configuration du groupe se trouve dans :
# /var/ossec/etc/shared/<nom_du_groupe>/agent.conf

# Éditer la configuration du groupe linux-servers
sudo nano /var/ossec/etc/shared/linux-servers/agent.conf
```

Exemple de configuration de groupe pour surveiller les logs Apache et activer le FIM sur des répertoires spécifiques :

```xml
<agent_config>
  <!-- Collecte des logs Apache -->
  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/apache2/access.log</location>
  </localfile>
  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/apache2/error.log</location>
  </localfile>

  <!-- File Integrity Monitoring personnalisé -->
  <syscheck>
    <directories check_all="yes" realtime="yes">/var/www/html</directories>
    <directories check_all="yes" realtime="yes">/etc/apache2</directories>
  </syscheck>
</agent_config>
```

### Suppression d'un agent

```bash
# Supprimer un agent (côté manager)
sudo /var/ossec/bin/manage_agents -r 001

# Via l'API REST
curl -s -k -X DELETE "https://localhost:55000/agents?agents_list=001&status=all&older_than=0s" \
  -H "Authorization: Bearer $TOKEN"
```

Sur l'endpoint, désinstallez le package :

```bash
# Linux (Debian/Ubuntu)
sudo apt remove --purge wazuh-agent
sudo rm -rf /var/ossec

# Linux (CentOS/RHEL)
sudo yum remove wazuh-agent
sudo rm -rf /var/ossec
```

```powershell
# Windows - Via PowerShell (administrateur)
msiexec.exe /x $env:TEMP\wazuh-agent.msi /q

# Ou via le Panneau de configuration > Programmes et fonctionnalités
```

---

## Communication agent-serveur

### Protocole de communication

| Aspect | Description |
|--------|-------------|
| **Protocole** | Propriétaire Wazuh (basé sur TCP ou UDP) |
| **Port** | 1514 (configurable) |
| **Chiffrement** | AES-256-CBC avec clé pré-partagée unique par agent |
| **Compression** | zlib pour réduire la bande passante |
| **Keep-alive** | L'agent envoie un signal toutes les 10 minutes (configurable) |
| **Buffer local** | En cas de perte de connexion, l'agent stocke les événements localement (jusqu'à 5000 événements par défaut) |

### Comportement en cas de perte de connexion

```
Agent connecté ─── Perte réseau ──► Buffering local ──► Reconnexion ──► Envoi du buffer
                                     (max 5000 événements)
```

L'agent tente de se reconnecter automatiquement selon un intervalle progressif :

1. Première tentative : 5 secondes
2. Tentatives suivantes : intervalle doublé à chaque échec (10s, 20s, 40s...)
3. Intervalle maximum : 10 minutes

### Configuration du buffer

Dans le fichier `ossec.conf` de l'agent :

```xml
<client_buffer>
  <disabled>no</disabled>
  <queue_size>5000</queue_size>
  <events_per_second>500</events_per_second>
</client_buffer>
```

---

## Troubleshooting

### Problème : l'agent n'apparaît pas comme "Active"

| Étape de diagnostic | Commande | Ce qu'il faut vérifier |
|--------------------|----------|----------------------|
| **1. Service démarré ?** | `sudo systemctl status wazuh-agent` | Le service doit être "active (running)" |
| **2. Adresse du manager correcte ?** | `grep -A3 "<server>" /var/ossec/etc/ossec.conf` | L'IP doit correspondre au serveur Wazuh |
| **3. Connectivité réseau ?** | `telnet 10.0.0.100 1514` ou `nc -zv 10.0.0.100 1514` | La connexion TCP doit réussir |
| **4. Firewall ?** | `sudo ufw status` (agent) et vérifier sur le manager | Le port 1514 doit être ouvert |
| **5. Clé valide ?** | `sudo cat /var/ossec/etc/client.keys` | Le fichier ne doit pas être vide |
| **6. Logs d'erreur ?** | `sudo tail -30 /var/ossec/logs/ossec.log` | Chercher les messages d'erreur |

### Problème : erreurs de clé d'authentification

Si l'agent affiche une erreur de type "Invalid key" :

```bash
# Sur l'agent : supprimer les clés actuelles
sudo rm /var/ossec/etc/client.keys

# Sur le manager : supprimer l'agent
sudo /var/ossec/bin/manage_agents -r <AGENT_ID>

# Redémarrer l'agent pour déclencher un nouvel enrollment
sudo systemctl restart wazuh-agent
```

### Problème : firewall bloquant la connexion

Test de connectivité depuis l'agent vers le manager :

```bash
# Test de connexion TCP sur le port 1514
nc -zv 10.0.0.100 1514
# Résultat attendu : Connection to 10.0.0.100 1514 port [tcp/*] succeeded!

# Si la connexion échoue, vérifier le firewall sur le manager
# Sur le manager :
sudo ufw status
sudo ss -tlnp | grep 1514

# Ouvrir le port si nécessaire
sudo ufw allow 1514/tcp
```

```powershell
# Test depuis Windows
Test-NetConnection -ComputerName 10.0.0.100 -Port 1514
# TcpTestSucceeded doit afficher True
```

### Problème : agent déconnecté après un certain temps

```bash
# Vérifier le keep-alive dans la configuration de l'agent
grep -A5 "<client>" /var/ossec/etc/ossec.conf

# Vérifier que le processus wazuh-agentd est en cours d'exécution
ps aux | grep wazuh-agentd

# Vérifier les logs pour des erreurs de communication
sudo grep -i "error\|disconnect\|timeout" /var/ossec/logs/ossec.log | tail -20
```

### Tableau récapitulatif des erreurs fréquentes

| Message d'erreur | Cause | Solution |
|------------------|-------|----------|
| `Unable to connect to server` | Manager inaccessible | Vérifier le réseau et le firewall |
| `Invalid key` | Clé corrompue ou désynchronisée | Supprimer la clé et réenregistrer l'agent |
| `Agent not found in keystore` | Agent supprimé du manager | Réenregistrer l'agent |
| `Connection timeout` | Réseau lent ou firewall | Augmenter le timeout ou vérifier le firewall |
| `Duplicate agent name` | Un agent avec le même nom existe déjà | Renommer l'agent ou supprimer l'ancien |
| `Enrollment request failed` | Mot de passe d'enrollment incorrect | Vérifier le mot de passe dans authd.pass |

---

## Glossaire des sigles et définitions

| Sigle/Terme | Définition |
|-------------|------------|
| **Agent** | Logiciel léger déployé sur un endpoint pour collecter les données de sécurité |
| **Endpoint** | Machine terminale (serveur, poste de travail, laptop) surveillée par un agent |
| **Enrollment** | Processus d'enregistrement d'un agent auprès du manager Wazuh |
| **Auto-enrollment** | Méthode d'enregistrement automatique des agents au premier démarrage |
| **client.keys** | Fichier contenant la clé d'authentification unique de l'agent |
| **ossec.conf** | Fichier de configuration principal de l'agent et du manager |
| **agent.conf** | Fichier de configuration centralisée par groupe d'agents |
| **WazuhSvc** | Nom du service Windows de l'agent Wazuh |
| **agent_control** | Outil en ligne de commande pour gérer les agents sur le manager |
| **manage_agents** | Outil en ligne de commande pour ajouter/supprimer des agents |
| **MSI** | Microsoft Installer - Format de package d'installation Windows |
| **msiexec** | Outil en ligne de commande Windows pour installer des packages MSI |
| **Keep-alive** | Signal périodique envoyé par l'agent pour signaler qu'il est actif |
| **Buffer** | Stockage temporaire local des événements en cas de perte de connexion |
| **FIM** | File Integrity Monitoring - Surveillance de l'intégrité des fichiers |
| **CIS** | Center for Internet Security - Organisation publiant des benchmarks de sécurité |

---

## Récapitulatif des commandes

| Commande | Description |
|----------|-------------|
| **Installation Linux (Debian/Ubuntu)** | |
| `WAZUH_MANAGER="IP" sudo apt install -y wazuh-agent` | Installer l'agent Linux |
| `sudo systemctl enable wazuh-agent` | Activer le démarrage automatique |
| `sudo systemctl start wazuh-agent` | Démarrer l'agent |
| `sudo systemctl status wazuh-agent` | Vérifier le statut de l'agent |
| `sudo systemctl restart wazuh-agent` | Redémarrer l'agent |
| `sudo tail -f /var/ossec/logs/ossec.log` | Suivre les logs de l'agent |
| `sudo /var/ossec/bin/wazuh-control status` | Vérifier les processus de l'agent |
| **Installation Windows** | |
| `msiexec.exe /i wazuh-agent.msi /q WAZUH_MANAGER="IP"` | Installation silencieuse Windows |
| `Start-Service WazuhSvc` | Démarrer le service (PowerShell) |
| `Get-Service WazuhSvc` | Vérifier le statut (PowerShell) |
| `Restart-Service WazuhSvc` | Redémarrer le service (PowerShell) |
| `Get-Content "...\ossec.log" -Tail 30` | Voir les dernières lignes de log |
| **Gestion des agents (côté manager)** | |
| `sudo /var/ossec/bin/agent_control -l` | Lister les agents |
| `sudo /var/ossec/bin/agent_control -i ID` | Détails d'un agent |
| `sudo /var/ossec/bin/agent_groups -a -g GROUPE` | Créer un groupe |
| `sudo /var/ossec/bin/agent_groups -a -i ID -g GROUPE` | Affecter un agent à un groupe |
| `sudo /var/ossec/bin/manage_agents -r ID` | Supprimer un agent |
| **Diagnostic** | |
| `nc -zv IP 1514` | Tester la connectivité agent vers manager |
| `Test-NetConnection -ComputerName IP -Port 1514` | Tester la connectivité depuis Windows |
| `sudo ss -tlnp \| grep 1514` | Vérifier que le port est en écoute (manager) |

---

## Ressources

- Documentation officielle Wazuh - Agent Installation : https://documentation.wazuh.com/current/installation-guide/wazuh-agent/
- Wazuh Agent Enrollment : https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/
- Wazuh Agent Configuration : https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/
- Wazuh Centralized Configuration : https://documentation.wazuh.com/current/user-manual/agent/agent-management/grouping-agents.html

### Ressources pratiques - TryHackMe / HackTheBox

| Plateforme | Room/Lab | Description |
|------------|----------|-------------|
| TryHackMe | [Wazuh](https://tryhackme.com/room/dvwazuhroom) | Déploiement d'agents et configuration de Wazuh |
