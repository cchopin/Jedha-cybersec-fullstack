# Installation du serveur Wazuh

**Durée : 60 min**

## Ce que vous allez apprendre dans ce cours

L'installation du serveur Wazuh est la première étape pour mettre en place votre plateforme de détection. Ce cours vous guide pas à pas dans le déploiement complet. Dans cette leçon, vous allez :

- évaluer les prérequis matériels et logiciels selon la taille de votre infrastructure,
- installer Wazuh en mode all-in-one avec le script officiel,
- configurer les ports réseau et les accès au dashboard,
- déployer Wazuh avec Docker Compose comme alternative,
- vérifier le bon fonctionnement de l'installation via les services et l'API,
- sécuriser votre serveur Wazuh en production.

---

## Prérequis matériels et logiciels

### Systèmes d'exploitation supportés

Le serveur Wazuh peut être installé sur les systèmes suivants :

| Système | Versions supportées |
|---------|-------------------|
| **Ubuntu** | 18.04, 20.04, 22.04, 24.04 LTS |
| **Debian** | 10, 11, 12 |
| **CentOS / RHEL** | 7, 8, 9 |
| **Amazon Linux** | 2, 2023 |
| **SUSE Linux Enterprise** | 12, 15 |

### Configurations recommandées

Les ressources nécessaires dépendent directement du nombre d'agents (endpoints) que vous souhaitez surveiller.

| Nombre d'agents | CPU | RAM | Disque | Déploiement recommandé |
|-----------------|-----|-----|--------|----------------------|
| **1 à 25** (lab/test) | 2 vCPU | 4 Go | 50 Go SSD | All-in-one |
| **25 à 50** (petite entreprise) | 4 vCPU | 8 Go | 100 Go SSD | All-in-one |
| **50 à 100** (moyenne entreprise) | 8 vCPU | 16 Go | 250 Go SSD | All-in-one ou distribué |
| **100 à 500** (grande entreprise) | 16 vCPU | 32 Go | 500 Go SSD | Distribué (cluster) |
| **500+** (très grande entreprise) | 32+ vCPU | 64+ Go | 1+ To SSD | Distribué multi-noeud |

Pour ce cours, une machine virtuelle avec **4 vCPU, 8 Go de RAM et 50 Go de disque** sera suffisante.

### Prérequis logiciels

Avant de commencer l'installation, vérifiez les points suivants :

```bash
# Vérifier le système d'exploitation
cat /etc/os-release

# Vérifier la mémoire disponible
free -h

# Vérifier l'espace disque
df -h

# Vérifier le nombre de CPU
nproc

# Vérifier la connectivité Internet (pour télécharger les packages)
curl -s https://packages.wazuh.com > /dev/null && echo "OK" || echo "ERREUR"
```

---

## Méthodes d'installation

Wazuh propose plusieurs méthodes d'installation selon vos besoins.

| Méthode | Description | Cas d'usage |
|---------|-------------|-------------|
| **All-in-one (script)** | Les trois composants sur une seule machine | Lab, petite entreprise, formation |
| **Distribué (packages)** | Chaque composant sur une machine dédiée | Production, grande infrastructure |
| **Docker** | Déploiement conteneurisé avec Docker Compose | Développement, test, environnements éphémères |
| **Wazuh Cloud** | Service managé par Wazuh Inc. | Entreprises sans équipe infra dédiée |
| **Kubernetes (Helm)** | Déploiement sur cluster Kubernetes | Environnements cloud-native |

Dans ce cours, nous couvrons les deux méthodes les plus courantes : **all-in-one** et **Docker**.

---

## Installation all-in-one pas à pas

L'installation all-in-one déploie le Wazuh Manager, le Wazuh Indexer et le Wazuh Dashboard sur une seule machine. C'est la méthode recommandée pour débuter.

### Étape 1 : Préparer le système

```bash
# Mettre à jour le système
sudo apt update && sudo apt upgrade -y    # Debian/Ubuntu
# ou
sudo yum update -y                         # CentOS/RHEL

# Installer les dépendances nécessaires
sudo apt install -y curl apt-transport-https   # Debian/Ubuntu
# ou
sudo yum install -y curl                        # CentOS/RHEL

# Désactiver le swap (recommandé pour OpenSearch)
sudo swapoff -a

# Augmenter les limites système pour OpenSearch
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
sudo sysctl -w vm.max_map_count=262144
```

### Étape 2 : Télécharger et exécuter le script d'installation

```bash
# Télécharger l'assistant d'installation Wazuh
curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh

# Rendre le script exécutable
chmod +x wazuh-install.sh

# Lancer l'installation complète (all-in-one)
sudo ./wazuh-install.sh -a
```

Le script va automatiquement :

1. Installer et configurer le **Wazuh Indexer** (OpenSearch)
2. Installer et configurer le **Wazuh Manager**
3. Installer et configurer le **Wazuh Dashboard**
4. Générer les certificats TLS pour la communication entre les composants
5. Configurer les services systemd
6. Afficher les **credentials** d'accès au dashboard

L'installation prend généralement entre **5 et 15 minutes** selon la vitesse de votre connexion Internet et les performances de votre machine.

### Étape 3 : Noter les credentials

À la fin de l'installation, le script affiche les identifiants d'accès :

```
INFO: --- Summary ---
INFO: You can access the web interface https://<YOUR_IP>:443
    User: admin
    Password: <GENERATED_PASSWORD>
```

**Notez ce mot de passe immédiatement.** Il est généré aléatoirement et ne sera pas affiché à nouveau. Si vous le perdez, vous devrez le réinitialiser.

### Configuration réseau : ports à ouvrir

Wazuh utilise plusieurs ports pour la communication entre ses composants et avec les agents. Voici les ports à ouvrir dans votre firewall.

| Port | Protocole | Service | Direction | Description |
|------|-----------|---------|-----------|-------------|
| **1514** | TCP | Wazuh Manager | Entrant | Communication agent → manager (envoi des événements) |
| **1515** | TCP | Wazuh Manager | Entrant | Enregistrement des agents (enrollment) |
| **55000** | TCP | Wazuh API | Entrant | API REST du manager (utilisée par le dashboard) |
| **443** | TCP | Wazuh Dashboard | Entrant | Interface web HTTPS |
| **9200** | TCP | Wazuh Indexer | Local/Interne | API OpenSearch (communication manager ↔ indexer) |
| **9300-9400** | TCP | Wazuh Indexer | Local/Interne | Communication inter-noeuds du cluster OpenSearch |

Configuration du firewall sous Linux (UFW) :

```bash
# Ouvrir les ports nécessaires
sudo ufw allow 1514/tcp    # Communication agents
sudo ufw allow 1515/tcp    # Enrollment agents
sudo ufw allow 443/tcp     # Dashboard web
sudo ufw allow 55000/tcp   # API (optionnel, selon votre architecture)

# Vérifier les règles
sudo ufw status

# Si UFW n'est pas activé
sudo ufw enable
```

Configuration avec iptables :

```bash
# Ouvrir les ports nécessaires
sudo iptables -A INPUT -p tcp --dport 1514 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 1515 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 55000 -j ACCEPT

# Sauvegarder les règles
sudo iptables-save | sudo tee /etc/iptables/rules.v4
```

---

## Configuration post-installation

### Accès au dashboard

Ouvrez votre navigateur et accédez à :

```
https://<ADRESSE_IP_DU_SERVEUR>:443
```

Vous verrez un avertissement de certificat auto-signé. C'est normal pour une installation de test. Acceptez l'exception et connectez-vous avec les credentials affichés lors de l'installation.

Le dashboard affiche par défaut :

- **Overview** : vue d'ensemble de la sécurité
- **Agents** : liste des agents connectés (vide pour l'instant)
- **Security Events** : alertes de sécurité
- **Integrity Monitoring** : alertes FIM
- **Vulnerabilities** : vulnérabilités détectées

### Changement du mot de passe admin

Il est fortement recommandé de changer le mot de passe par défaut immédiatement après l'installation.

```bash
# Utiliser l'outil Wazuh pour changer le mot de passe
sudo /usr/share/wazuh-indexer/plugins/opensearch-security/tools/wazuh-passwords-tool.sh \
  -u admin -p 'NouveauMotDePasseComplexe123!'
```

### Configuration principale : ossec.conf

Le fichier de configuration principal du Wazuh Manager se trouve dans `/var/ossec/etc/ossec.conf`. C'est le fichier le plus important de votre installation.

```bash
# Ouvrir le fichier de configuration
sudo nano /var/ossec/etc/ossec.conf
```

Sections principales du fichier `ossec.conf` :

| Section | Description |
|---------|-------------|
| `<global>` | Paramètres globaux (email de notification, alertes) |
| `<alerts>` | Niveau minimum d'alerte pour le logging et les emails |
| `<remote>` | Configuration de la réception des données des agents |
| `<syslog_output>` | Sortie syslog pour l'envoi vers d'autres systèmes |
| `<rules>` | Chemins vers les fichiers de règles |
| `<syscheck>` | Configuration du File Integrity Monitoring |
| `<rootcheck>` | Configuration de la détection de rootkits |
| `<vulnerability-detector>` | Configuration du scan de vulnérabilités |
| `<auth>` | Configuration de l'enrollment des agents |
| `<active-response>` | Configuration des réponses actives |

Exemple : configurer le niveau minimum d'alerte à 3 et activer les notifications email :

```xml
<global>
  <email_notification>yes</email_notification>
  <smtp_server>smtp.example.com</smtp_server>
  <email_from>wazuh@example.com</email_from>
  <email_to>soc@example.com</email_to>
</global>

<alerts>
  <log_alert_level>3</log_alert_level>
  <email_alert_level>12</email_alert_level>
</alerts>
```

### Structure des répertoires Wazuh

Tous les fichiers de Wazuh se trouvent dans `/var/ossec/`. Voici les répertoires les plus importants :

| Répertoire | Description |
|------------|-------------|
| `/var/ossec/etc/` | Fichiers de configuration (ossec.conf, client.keys, etc.) |
| `/var/ossec/etc/rules/` | Règles de détection personnalisées (local_rules.xml) |
| `/var/ossec/etc/decoders/` | Décodeurs personnalisés (local_decoder.xml) |
| `/var/ossec/ruleset/rules/` | Règles de détection par défaut (ne pas modifier) |
| `/var/ossec/ruleset/decoders/` | Décodeurs par défaut (ne pas modifier) |
| `/var/ossec/logs/` | Fichiers de logs de Wazuh |
| `/var/ossec/logs/ossec.log` | Log principal du manager |
| `/var/ossec/logs/alerts/` | Fichiers d'alertes (JSON et texte) |
| `/var/ossec/logs/archives/` | Archives de tous les événements reçus |
| `/var/ossec/queue/` | Files d'attente de traitement des événements |
| `/var/ossec/bin/` | Binaires et outils Wazuh |
| `/var/ossec/var/run/` | Fichiers PID et état des services |
| `/var/ossec/stats/` | Statistiques de fonctionnement |
| `/var/ossec/tmp/` | Fichiers temporaires |

```bash
# Explorer la structure
sudo ls -la /var/ossec/
sudo ls -la /var/ossec/etc/
sudo ls -la /var/ossec/logs/
```

---

## Installation avec Docker Compose

L'installation Docker est une alternative pratique, notamment pour le développement et les environnements de test.

### Prérequis Docker

```bash
# Installer Docker (si pas déjà installé)
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Installer Docker Compose
sudo apt install -y docker-compose-plugin   # Debian/Ubuntu

# Vérifier l'installation
docker --version
docker compose version

# Augmenter la limite vm.max_map_count (nécessaire pour OpenSearch)
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
sudo sysctl -w vm.max_map_count=262144
```

### Déploiement avec Docker Compose

```bash
# Cloner le dépôt officiel Wazuh Docker
git clone https://github.com/wazuh/wazuh-docker.git -b v4.9.0
cd wazuh-docker/single-node

# Générer les certificats TLS
docker compose -f generate-indexer-certs.yml run --rm generator

# Lancer l'ensemble des services
docker compose up -d
```

Le fichier `docker-compose.yml` du mode single-node déploie trois conteneurs :

```yaml
# Structure simplifiée du docker-compose.yml Wazuh single-node
services:
  # Wazuh Manager - Reçoit et analyse les événements
  wazuh.manager:
    image: wazuh/wazuh-manager:4.9.0
    hostname: wazuh.manager
    ports:
      - "1514:1514"      # Communication agents
      - "1515:1515"      # Enrollment agents
      - "514:514/udp"    # Syslog
      - "55000:55000"    # API REST
    volumes:
      - wazuh_api_configuration:/var/ossec/api/configuration
      - wazuh_etc:/var/ossec/etc
      - wazuh_logs:/var/ossec/logs
      - wazuh_queue:/var/ossec/queue
    environment:
      INDEXER_URL: https://wazuh.indexer:9200
      INDEXER_USERNAME: admin
      INDEXER_PASSWORD: SecretPassword
    restart: always

  # Wazuh Indexer - Stockage et indexation (OpenSearch)
  wazuh.indexer:
    image: wazuh/wazuh-indexer:4.9.0
    hostname: wazuh.indexer
    ports:
      - "9200:9200"      # API OpenSearch
    volumes:
      - wazuh-indexer-data:/var/lib/wazuh-indexer
    environment:
      OPENSEARCH_JAVA_OPTS: "-Xms1g -Xmx1g"  # Mémoire allouée à Java
    restart: always

  # Wazuh Dashboard - Interface web
  wazuh.dashboard:
    image: wazuh/wazuh-dashboard:4.9.0
    hostname: wazuh.dashboard
    ports:
      - "443:5601"       # Interface web HTTPS
    environment:
      INDEXER_USERNAME: admin
      INDEXER_PASSWORD: SecretPassword
      WAZUH_API_URL: https://wazuh.manager
      DASHBOARD_USERNAME: kibanaserver
      DASHBOARD_PASSWORD: kibanaserver
    depends_on:
      - wazuh.indexer
    restart: always

volumes:
  wazuh_api_configuration:
  wazuh_etc:
  wazuh_logs:
  wazuh_queue:
  wazuh-indexer-data:
```

### Avantages et inconvénients : Docker vs Bare Metal

| Critère | Docker | Bare Metal (packages) |
|---------|--------|----------------------|
| **Facilité d'installation** | Très simple (quelques commandes) | Simple (script all-in-one) |
| **Mise à jour** | Pull de la nouvelle image | Mise à jour des packages |
| **Isolation** | Conteneurs isolés | Processus sur l'OS hôte |
| **Performance** | Légère overhead | Performance native |
| **Persistance des données** | Via volumes Docker | Fichiers sur disque |
| **Production** | Possible mais moins courant | Recommandé |
| **Debugging** | Plus complexe (logs dans les conteneurs) | Direct (fichiers de logs) |
| **Sauvegarde** | Export des volumes | Backup classique des fichiers |
| **Haute disponibilité** | Docker Swarm / Kubernetes | Cluster Wazuh natif |

```bash
# Commandes utiles pour gérer Wazuh Docker

# Vérifier l'état des conteneurs
docker compose ps

# Voir les logs du manager
docker compose logs -f wazuh.manager

# Voir les logs du dashboard
docker compose logs -f wazuh.dashboard

# Redémarrer un service
docker compose restart wazuh.manager

# Arrêter tous les services
docker compose down

# Arrêter et supprimer les données (ATTENTION : perte de données)
docker compose down -v
```

---

## Vérification de l'installation

Après l'installation (quelle que soit la méthode), vérifiez que tout fonctionne correctement.

### Vérification des services (installation bare metal)

```bash
# Vérifier le statut du Wazuh Manager
sudo systemctl status wazuh-manager

# Vérifier le statut du Wazuh Indexer
sudo systemctl status wazuh-indexer

# Vérifier le statut du Wazuh Dashboard
sudo systemctl status wazuh-dashboard

# Les trois services doivent afficher "active (running)"
```

Sortie attendue pour chaque service :

```
● wazuh-manager.service - Wazuh manager
     Loaded: loaded (/usr/lib/systemd/system/wazuh-manager.service; enabled)
     Active: active (running) since Mon 2026-03-15 14:22:01 UTC; 5min ago
```

### Vérification via l'API Wazuh

L'API REST de Wazuh (port 55000) permet de vérifier l'état du manager par programmation.

```bash
# Obtenir un token d'authentification
TOKEN=$(curl -s -u admin:VOTRE_MOT_DE_PASSE -k -X POST \
  "https://localhost:55000/security/user/authenticate" | \
  python3 -c "import sys,json; print(json.load(sys.stdin)['data']['token'])")

# Vérifier les informations du manager
curl -s -k -X GET "https://localhost:55000/" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

# Réponse attendue :
# {
#   "data": {
#     "title": "Wazuh API REST",
#     "api_version": "4.9.0",
#     "revision": 40912,
#     "license_name": "GPL 2.0",
#     "hostname": "wazuh-server",
#     "timestamp": "2026-03-15T14:30:00Z"
#   }
# }

# Lister les agents connectés (vide pour l'instant)
curl -s -k -X GET "https://localhost:55000/agents" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

# Vérifier les statistiques du manager
curl -s -k -X GET "https://localhost:55000/manager/stats" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

### Vérification de l'indexer

```bash
# Vérifier que l'indexer répond
curl -s -k -u admin:VOTRE_MOT_DE_PASSE https://localhost:9200

# Lister les index Wazuh
curl -s -k -u admin:VOTRE_MOT_DE_PASSE https://localhost:9200/_cat/indices?v | grep wazuh

# Vérifier la santé du cluster
curl -s -k -u admin:VOTRE_MOT_DE_PASSE https://localhost:9200/_cluster/health?pretty
```

---

## Sécurisation du serveur Wazuh

En production, plusieurs mesures de sécurisation sont indispensables.

### Certificats TLS

L'installation all-in-one génère des certificats auto-signés. En production, vous devriez utiliser des certificats signés par une autorité de certification (CA) interne ou publique.

```bash
# Les certificats sont stockés dans :
# Indexer : /etc/wazuh-indexer/certs/
# Manager : /var/ossec/etc/sslmanager.cert et sslmanager.key
# Dashboard : /etc/wazuh-dashboard/certs/

# Vérifier les certificats actuels
sudo openssl x509 -in /etc/wazuh-indexer/certs/indexer.pem -text -noout | grep -E "Issuer|Subject|Not"
```

### Changement de tous les mots de passe

```bash
# L'outil de changement de mot de passe modifie tous les utilisateurs internes
sudo /usr/share/wazuh-indexer/plugins/opensearch-security/tools/wazuh-passwords-tool.sh -a
```

### Restriction d'accès réseau

Limitez l'accès aux ports de Wazuh aux seules adresses IP nécessaires :

```bash
# Autoriser uniquement le réseau interne pour les agents
sudo ufw allow from 10.0.0.0/8 to any port 1514

# Autoriser uniquement l'IP de l'administrateur pour le dashboard
sudo ufw allow from 192.168.1.100 to any port 443

# Bloquer l'accès à l'API depuis l'extérieur
sudo ufw deny 55000
```

### Bonnes pratiques de sécurisation

| Mesure | Description | Priorité |
|--------|-------------|----------|
| **Changer les mots de passe** | Remplacer tous les mots de passe par défaut | Critique |
| **Certificats TLS** | Utiliser des certificats signés par une CA | Élevée |
| **Firewall** | Restreindre les ports aux IP autorisées | Critique |
| **Mises à jour** | Maintenir Wazuh et l'OS à jour | Élevée |
| **Sauvegardes** | Sauvegarder régulièrement `/var/ossec/etc/` et les index | Élevée |
| **Monitoring** | Surveiller les ressources du serveur (CPU, RAM, disque) | Moyenne |
| **Audit** | Activer l'audit des accès à l'API et au dashboard | Moyenne |
| **Séparation réseau** | Placer le serveur Wazuh dans un VLAN dédié | Élevée |

---

## Troubleshooting courant

### Log principal de Wazuh

Le fichier `/var/ossec/logs/ossec.log` est votre première source d'information en cas de problème.

```bash
# Consulter les dernières lignes du log
sudo tail -50 /var/ossec/logs/ossec.log

# Chercher les erreurs
sudo grep -i "error\|critical\|warning" /var/ossec/logs/ossec.log | tail -20

# Suivre les logs en temps réel
sudo tail -f /var/ossec/logs/ossec.log
```

### Problèmes courants et solutions

| Problème | Cause probable | Solution |
|----------|---------------|----------|
| Dashboard inaccessible | Service arrêté ou port bloqué | `sudo systemctl restart wazuh-dashboard` et vérifier le firewall |
| Erreur "insufficient memory" | RAM insuffisante pour OpenSearch | Augmenter la RAM ou réduire le heap Java dans `jvm.options` |
| Erreur de certificat dans le navigateur | Certificat auto-signé | Normal en test, accepter l'exception ou installer un certificat CA |
| Indexer ne démarre pas | `vm.max_map_count` trop bas | `sudo sysctl -w vm.max_map_count=262144` |
| Agent ne se connecte pas | Port 1514 bloqué | Vérifier le firewall avec `sudo ufw status` |
| API renvoie "Unauthorized" | Mauvais mot de passe | Réinitialiser avec `wazuh-passwords-tool.sh` |
| Espace disque plein | Logs et index trop volumineux | Configurer la rotation des index et la rétention |

### Vérification des logs par composant

```bash
# Logs du Wazuh Manager
sudo tail -f /var/ossec/logs/ossec.log

# Logs du Wazuh Indexer
sudo tail -f /var/log/wazuh-indexer/wazuh-indexer.log

# Logs du Wazuh Dashboard
sudo tail -f /usr/share/wazuh-dashboard/data/wazuh/logs/wazuhapp.log

# Vérifier les ports en écoute
sudo ss -tlnp | grep -E "1514|1515|443|9200|55000"
```

Sortie attendue de la commande `ss` :

```
LISTEN  0  128  *:1514   *:*  users:(("wazuh-remoted",pid=1234,fd=5))
LISTEN  0  128  *:1515   *:*  users:(("wazuh-authd",pid=1235,fd=5))
LISTEN  0  128  *:443    *:*  users:(("node",pid=1236,fd=18))
LISTEN  0  128  *:9200   *:*  users:(("java",pid=1237,fd=200))
LISTEN  0  128  *:55000  *:*  users:(("python3",pid=1238,fd=6))
```

Si un port n'apparaît pas dans cette liste, le service correspondant n'est pas démarré correctement.

---

## Glossaire des sigles et définitions

| Sigle/Terme | Définition |
|-------------|------------|
| **All-in-one** | Mode d'installation où tous les composants sont sur une seule machine |
| **Distribué** | Mode d'installation où chaque composant est sur une machine dédiée |
| **Bare metal** | Installation directe sur le système d'exploitation (sans conteneurs) |
| **OpenSearch** | Moteur de recherche et d'analyse, fork open source d'Elasticsearch |
| **TLS** | Transport Layer Security - Protocole de chiffrement des communications |
| **CA** | Certificate Authority - Autorité de certification qui signe les certificats |
| **API REST** | Interface de programmation basée sur le protocole HTTP |
| **Heap** | Mémoire allouée à la machine virtuelle Java (JVM) pour OpenSearch |
| **vm.max_map_count** | Paramètre noyau Linux limitant le nombre de zones de mémoire mappées |
| **UFW** | Uncomplicated Firewall - Interface simplifiée pour iptables |
| **iptables** | Outil de filtrage de paquets du noyau Linux |
| **systemctl** | Commande pour gérer les services systemd |
| **Enrollment** | Processus d'enregistrement d'un agent auprès du manager |
| **VLAN** | Virtual LAN - Réseau local virtuel pour la segmentation réseau |

---

## Récapitulatif des commandes

| Commande | Description |
|----------|-------------|
| `curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh` | Télécharger le script d'installation |
| `sudo ./wazuh-install.sh -a` | Installer Wazuh en mode all-in-one |
| `sudo systemctl status wazuh-manager` | Vérifier le statut du manager |
| `sudo systemctl status wazuh-indexer` | Vérifier le statut de l'indexer |
| `sudo systemctl status wazuh-dashboard` | Vérifier le statut du dashboard |
| `sudo systemctl restart wazuh-manager` | Redémarrer le manager |
| `sudo tail -f /var/ossec/logs/ossec.log` | Suivre les logs du manager en temps réel |
| `sudo grep -i error /var/ossec/logs/ossec.log` | Chercher les erreurs dans les logs |
| `sudo ss -tlnp \| grep 1514` | Vérifier que le port 1514 est en écoute |
| `sudo ufw allow 1514/tcp` | Ouvrir le port 1514 dans le firewall |
| `docker compose up -d` | Démarrer Wazuh avec Docker |
| `docker compose ps` | Vérifier l'état des conteneurs |
| `docker compose logs -f wazuh.manager` | Suivre les logs du manager Docker |
| `curl -s -k -u admin:PASSWORD https://localhost:55000/` | Tester l'API Wazuh |
| `curl -s -k -u admin:PASSWORD https://localhost:9200/_cluster/health?pretty` | Vérifier la santé du cluster indexer |

---

## Ressources

- Documentation officielle Wazuh - Installation Guide : https://documentation.wazuh.com/current/installation-guide/
- Wazuh Docker Deployment : https://documentation.wazuh.com/current/deployment-options/docker/
- OpenSearch Documentation : https://opensearch.org/docs/latest/
- Wazuh API Reference : https://documentation.wazuh.com/current/user-manual/api/reference.html

### Ressources pratiques - TryHackMe / HackTheBox

| Plateforme | Room/Lab | Description |
|------------|----------|-------------|
| TryHackMe | [Wazuh](https://tryhackme.com/room/dvwazuhroom) | Installation et configuration de Wazuh dans un environnement guidé |
