# Collecte de logs personnalisée

**Durée : 50 min**

## Ce que vous allez apprendre dans ce cours

La collecte de logs par défaut d'un SIEM ne suffit pas à couvrir l'ensemble du périmètre de sécurité d'une organisation. Les applications métier, les formats de logs non standards et les sources réseau spécifiques nécessitent une configuration sur mesure. Dans cette leçon, vous apprendrez :

- pourquoi la collecte par défaut ne suffit pas et quels cas nécessitent une personnalisation,
- comment fonctionne l'architecture de collecte de Wazuh (localfile, syslog, command monitoring, journald),
- comment configurer la collecte de fichiers de logs locaux via `ossec.conf`,
- comment créer des décodeurs personnalisés pour extraire des champs à partir de logs bruts,
- comment collecter les logs Windows Event Channel et les logs réseau,
- comment surveiller le système via le monitoring de commandes.

---

## Pourquoi la collecte par défaut ne suffit pas

### Limites de la collecte standard

Lorsque vous installez l'agent Wazuh sur un système, il collecte automatiquement certains logs standard :

| Système | Logs collectés par défaut |
|---------|---------------------------|
| **Linux** | `/var/log/syslog`, `/var/log/auth.log`, `/var/log/secure` |
| **Windows** | Security, System, Application Event Logs |
| **macOS** | `/var/log/system.log` |

Cependant, cette collecte par défaut présente des lacunes importantes :

| Problème | Exemple concret |
|----------|-----------------|
| **Applications métier** | Votre application web interne écrit ses logs dans `/var/log/myapp/access.log` -- Wazuh ne les voit pas |
| **Formats non standards** | Un outil de monitoring génère des logs en JSON multi-lignes que Wazuh ne sait pas parser |
| **Sources réseau** | Votre firewall pfSense envoie des logs syslog que personne ne centralise |
| **Logs de sécurité spécifiques** | Les logs Sysmon sous Windows ne sont pas collectés par défaut |
| **Commandes de surveillance** | Vous voulez surveiller les connexions réseau actives (`netstat`) toutes les 5 minutes |

> **Bonne pratique** : la première étape d'un projet SIEM consiste à réaliser un inventaire complet des sources de logs pertinentes pour la sécurité. Identifiez chaque application, chaque équipement réseau et chaque service qui génère des événements utiles à la détection.

---

## Architecture de collecte dans Wazuh

Wazuh propose quatre mécanismes principaux pour collecter des logs :

| Mécanisme | Description | Cas d'usage |
|-----------|-------------|-------------|
| **Localfile** | Surveillance de fichiers de logs locaux sur l'agent | Applications, serveurs web, logs custom |
| **Remote syslog** | Réception de logs via le protocole syslog sur le manager | Firewalls, switches, équipements réseau |
| **Command monitoring** | Exécution périodique de commandes et collecte de la sortie | Surveillance système (netstat, ps, who) |
| **Journald** | Intégration avec le journal systemd | Services systemd, logs structurés Linux |

### Schéma de l'architecture de collecte

```
+-------------------+     +-------------------+     +-------------------+
|   Agent Linux     |     |   Agent Windows   |     |  Firewall/Switch  |
|                   |     |                   |     |                   |
| localfile         |     | eventchannel      |     | syslog            |
| command           |     | localfile         |     |                   |
| journald          |     | command           |     |                   |
+--------+----------+     +--------+----------+     +--------+----------+
         |                         |                          |
         |    (port 1514/TCP)      |    (port 1514/TCP)       |  (port 514/UDP)
         |                         |                          |
         v                         v                          v
+------------------------------------------------------------------------+
|                         Wazuh Manager                                  |
|                                                                        |
|  Réception  ->  Décodage  ->  Règles  ->  Alertes  ->  Indexeur        |
+------------------------------------------------------------------------+
```

---

## Configuration localfile dans ossec.conf

### Emplacement du fichier de configuration

La configuration de la collecte se fait dans le fichier `ossec.conf` de l'agent :

| Agent | Emplacement |
|-------|-------------|
| **Linux** | `/var/ossec/etc/ossec.conf` |
| **Windows** | `C:\Program Files (x86)\ossec-agent\ossec.conf` |
| **Manager** (centralised) | `/var/ossec/etc/ossec.conf` |

### Structure de la balise localfile

La balise `<localfile>` est l'élément fondamental pour déclarer un fichier de logs à surveiller :

```xml
<localfile>
  <log_format>FORMAT</log_format>
  <location>CHEMIN_DU_FICHIER</location>
</localfile>
```

### Formats de logs supportés (log_format)

| Format | Description | Utilisation |
|--------|-------------|-------------|
| `syslog` | Format syslog standard (une ligne par événement) | `/var/log/syslog`, `/var/log/auth.log` |
| `json` | Logs au format JSON (un objet JSON par ligne) | Applications modernes, conteneurs |
| `multi-line` | Logs répartis sur plusieurs lignes (regex pour délimiter) | Logs Java stack traces, logs applicatifs |
| `audit` | Format Linux Audit (`auditd`) | `/var/log/audit/audit.log` |
| `eventlog` | Windows Event Log (ancien format, legacy) | Anciens systèmes Windows |
| `eventchannel` | Windows Event Channel (format moderne, recommandé) | Windows Vista+ : Security, Sysmon, PowerShell |
| `command` | Sortie d'une commande exécutée périodiquement | Résultat de `netstat`, `ps`, `who` |
| `full_command` | Sortie complète d'une commande (multi-lignes) | Résultat complet avec toutes les lignes |

### Exemples de configuration localfile

**Exemple 1 : Logs Apache**

```xml
<!-- Collecte des logs d'accès Apache -->
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/apache2/access.log</location>
</localfile>

<!-- Collecte des logs d'erreurs Apache -->
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/apache2/error.log</location>
</localfile>
```

**Exemple 2 : Logs Nginx au format JSON**

Si vous avez configuré Nginx pour écrire ses logs en JSON :

```xml
<!-- Collecte des logs Nginx au format JSON -->
<localfile>
  <log_format>json</log_format>
  <location>/var/log/nginx/access.json</location>
</localfile>
```

**Exemple 3 : Application custom avec logs multi-lignes**

```xml
<!-- Logs d'une application Java (stack traces multi-lignes) -->
<localfile>
  <log_format>multi-line</log_format>
  <location>/var/log/myapp/application.log</location>
  <!-- Chaque nouveau log commence par un timestamp au format ISO -->
  <multiline_regex>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}</multiline_regex>
</localfile>
```

**Exemple 4 : Logs d'audit Linux**

```xml
<!-- Collecte des logs auditd -->
<localfile>
  <log_format>audit</log_format>
  <location>/var/log/audit/audit.log</location>
</localfile>
```

**Exemple 5 : Utilisation de wildcards**

```xml
<!-- Collecte de tous les fichiers .log dans un répertoire -->
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/myapp/*.log</location>
</localfile>
```

> **Bonne pratique** : après chaque modification de `ossec.conf`, vous devez redémarrer l'agent pour que les changements soient pris en compte :
>
> ```bash
> # Sur Linux
> sudo systemctl restart wazuh-agent
>
> # Sur Windows (PowerShell en administrateur)
> Restart-Service -Name WazuhSvc
> ```

---

## Décodeurs Wazuh (decoders)

### Rôle des décodeurs

Un **décodeur** (decoder) est un composant Wazuh qui extrait des champs structurés à partir d'un log brut. Sans décodeur, Wazuh voit le log comme une simple chaîne de texte. Avec un décodeur, il peut extraire l'adresse IP source, l'utilisateur, l'action effectuée, etc.

```
Log brut :
  "2025-03-15 14:32:01 ERROR [auth] Failed login for user admin from 192.168.1.50"

                        |
                   Décodeur
                        |
                        v

Champs extraits :
  timestamp  = 2025-03-15 14:32:01
  severity   = ERROR
  module     = auth
  action     = Failed login
  user       = admin
  srcip      = 192.168.1.50
```

### Décodeurs intégrés vs personnalisés

| Type | Emplacement | Usage |
|------|-------------|-------|
| **Intégrés** | `/var/ossec/ruleset/decoders/` | Logs standards (syslog, Apache, SSH, Windows...) |
| **Personnalisés** | `/var/ossec/etc/decoders/local_decoder.xml` | Vos logs custom |

> **Important** : ne modifiez jamais les fichiers dans `/var/ossec/ruleset/decoders/`. Vos personnalisations doivent aller dans `/var/ossec/etc/decoders/local_decoder.xml`. Les fichiers intégrés sont écrasés lors des mises à jour de Wazuh.

### Structure XML d'un décodeur

Un décodeur Wazuh est défini en XML avec les balises suivantes :

| Balise | Rôle | Obligatoire |
|--------|------|-------------|
| `<decoder name="...">` | Nom unique du décodeur | Oui |
| `<prematch>` | Pattern de pré-filtrage (le log doit contenir cette chaîne) | Oui (parent) |
| `<regex>` | Expression régulière pour extraire les champs | Oui (enfant) |
| `<order>` | Nom des champs extraits, dans l'ordre des groupes de capture | Oui (enfant) |
| `<parent>` | Nom du décodeur parent (pour les décodeurs enfants) | Oui (enfant) |

### Décodeurs parents et enfants

Wazuh utilise un système hiérarchique à deux niveaux :

1. **Décodeur parent** : identifie la source du log grâce à `<prematch>`. Il filtre les logs pertinents.
2. **Décodeur enfant** : extrait les champs spécifiques grâce à `<regex>` et `<order>`. Il hérite du parent via `<parent>`.

### Création d'un décodeur personnalisé pas à pas

Imaginons que votre application web génère des logs dans ce format :

```
[2025-03-15 14:32:01] AUTH_FAIL user=admin ip=192.168.1.50 reason=bad_password
[2025-03-15 14:33:15] AUTH_OK user=jdupont ip=10.0.0.25 reason=success
[2025-03-15 14:35:42] AUTH_FAIL user=root ip=203.0.113.10 reason=account_locked
```

**Etape 1 : Créer le décodeur parent**

Le décodeur parent identifie les logs provenant de votre application :

```xml
<decoder name="mywebapp">
  <prematch>] AUTH_</prematch>
</decoder>
```

Le `<prematch>` doit correspondre à une portion unique de vos logs. Ici, `] AUTH_` est présent dans tous les logs de votre application.

**Etape 2 : Créer le décodeur enfant pour les échecs**

```xml
<decoder name="mywebapp-auth-fail">
  <parent>mywebapp</parent>
  <regex>AUTH_FAIL user=(\S+) ip=(\S+) reason=(\S+)</regex>
  <order>user, srcip, extra_data</order>
</decoder>
```

**Etape 3 : Créer le décodeur enfant pour les succès**

```xml
<decoder name="mywebapp-auth-ok">
  <parent>mywebapp</parent>
  <regex>AUTH_OK user=(\S+) ip=(\S+) reason=(\S+)</regex>
  <order>user, srcip, extra_data</order>
</decoder>
```

**Fichier complet `/var/ossec/etc/decoders/local_decoder.xml`** :

```xml
<!-- Décodeur personnalisé pour l'application web MyWebApp -->

<!-- Parent : identifie les logs de l'application -->
<decoder name="mywebapp">
  <prematch>] AUTH_</prematch>
</decoder>

<!-- Enfant : extraction des champs pour les échecs d'authentification -->
<decoder name="mywebapp-auth-fail">
  <parent>mywebapp</parent>
  <regex>AUTH_FAIL user=(\S+) ip=(\S+) reason=(\S+)</regex>
  <order>user, srcip, extra_data</order>
</decoder>

<!-- Enfant : extraction des champs pour les authentifications réussies -->
<decoder name="mywebapp-auth-ok">
  <parent>mywebapp</parent>
  <regex>AUTH_OK user=(\S+) ip=(\S+) reason=(\S+)</regex>
  <order>user, srcip, extra_data</order>
</decoder>
```

### Syntaxe des regex Wazuh

Les expressions régulières Wazuh utilisent une syntaxe spécifique :

| Symbole | Signification |
|---------|---------------|
| `\S+` | Un ou plusieurs caractères non-espace |
| `\s+` | Un ou plusieurs espaces |
| `\d+` | Un ou plusieurs chiffres |
| `\.` | Un point littéral |
| `(\S+)` | Groupe de capture (champ extrait) |
| `\w+` | Un ou plusieurs caractères alphanumériques |
| `.+` | Un ou plusieurs caractères quelconques |

### Test avec wazuh-logtest

L'outil `wazuh-logtest` permet de tester vos décodeurs sans redémarrer le manager :

```bash
# Lancer l'outil de test
sudo /var/ossec/bin/wazuh-logtest
```

Collez ensuite un log de test :

```
[2025-03-15 14:32:01] AUTH_FAIL user=admin ip=192.168.1.50 reason=bad_password
```

Résultat attendu :

```
**Phase 1: Completed pre-decoding.
       full event: '[2025-03-15 14:32:01] AUTH_FAIL user=admin ip=192.168.1.50 reason=bad_password'

**Phase 2: Completed decoding.
       name: 'mywebapp-auth-fail'
       parent: 'mywebapp'
       srcip: '192.168.1.50'
       user: 'admin'
       extra_data: 'bad_password'

**Phase 3: Completed filtering (rules).
       No rule matched.
```

Si le décodeur fonctionne, vous voyez les champs extraits dans la phase 2. Si aucune règle ne matche (phase 3), c'est normal : vous devrez créer des règles dans le prochain cours.

> **Bonne pratique** : testez systématiquement vos décodeurs avec `wazuh-logtest` avant de redémarrer le manager. Un décodeur mal écrit peut empêcher le traitement des logs.

---

## Collecte de logs Windows

### Windows Event Channel (eventchannel)

Le format `eventchannel` est le mécanisme recommandé pour collecter les logs Windows. Il donne accès à tous les canaux d'événements du système.

**Canaux les plus importants pour la sécurité :**

| Canal | Contenu | Intérêt sécurité |
|-------|---------|-------------------|
| `Security` | Connexions, audit, accès aux objets | Critique -- détection d'intrusions |
| `System` | Services, erreurs système, pilotes | Important -- détection de persistence |
| `Application` | Événements applicatifs | Modéré -- détection d'erreurs suspectes |
| `Microsoft-Windows-Sysmon/Operational` | Création de processus, connexions réseau, modification de fichiers | Critique -- visibilité avancée |
| `Microsoft-Windows-PowerShell/Operational` | Exécution de scripts PowerShell | Critique -- détection de scripts malveillants |
| `Microsoft-Windows-Windows Defender/Operational` | Détections antivirus, mises à jour | Important -- suivi des détections |

### Configuration pour collecter les logs Sysmon

Sysmon (System Monitor) est un outil Sysinternals qui génère des événements de sécurité très détaillés. Sa collecte par Wazuh est fortement recommandée.

```xml
<!-- Configuration dans ossec.conf de l'agent Windows -->

<!-- Collecte des événements Sysmon -->
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>

<!-- Collecte des événements PowerShell -->
<localfile>
  <location>Microsoft-Windows-PowerShell/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>

<!-- Collecte des événements Windows Defender -->
<localfile>
  <location>Microsoft-Windows-Windows Defender/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

### Filtrage par Event ID

Vous pouvez filtrer les Event IDs collectés pour réduire le volume de données :

```xml
<!-- Collecter uniquement les Event IDs critiques du canal Security -->
<localfile>
  <location>Security</location>
  <log_format>eventchannel</log_format>
  <query>Event/System[EventID=4624 or EventID=4625 or EventID=4672 or
         EventID=4688 or EventID=4697 or EventID=1102]</query>
</localfile>
```

**Event IDs Sysmon les plus importants :**

| Event ID | Description | Intérêt |
|----------|-------------|---------|
| **1** | Création de processus | Détection d'exécution de malware |
| **3** | Connexion réseau | Détection de C2 (Command & Control) |
| **7** | Chargement d'image (DLL) | Détection d'injection de DLL |
| **8** | Création de thread distant | Détection d'injection de processus |
| **11** | Création de fichier | Détection de dépôt de malware |
| **13** | Modification de registre | Détection de persistence |
| **22** | Requête DNS | Détection de communication C2 via DNS |

---

## Collecte de logs réseau

### Syslog depuis des firewalls

Les équipements réseau (firewalls, switches, routeurs) envoient généralement leurs logs via le protocole syslog. Le manager Wazuh peut recevoir ces logs directement ou via un relai rsyslog.

**Architecture avec relai rsyslog :**

```
+------------+     syslog (UDP/514)     +------------+     fichier    +---------+
|  pfSense   | ---------------------->  |   rsyslog  | -------------> |  Wazuh  |
|  FortiGate |                          |  (relai)   |  /var/log/     |  Agent  |
+------------+                          +------------+  firewall.log  +---------+
```

### Configuration de rsyslog comme relai

Sur le serveur rsyslog, configurez la réception et l'écriture dans un fichier dédié :

```bash
# /etc/rsyslog.d/10-firewall.conf

# Activer la réception syslog sur UDP 514
module(load="imudp")
input(type="imudp" port="514")

# Écrire les logs du firewall dans un fichier dédié
# (en filtrant sur l'IP source du firewall)
if $fromhost-ip == '192.168.1.1' then /var/log/firewall/pfsense.log
& stop
```

Puis sur l'agent Wazuh installé sur ce même serveur rsyslog :

```xml
<!-- Collecte des logs pfSense via le fichier rsyslog -->
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/firewall/pfsense.log</location>
</localfile>
```

### Réception directe sur le manager Wazuh

Wazuh peut aussi recevoir directement les logs syslog sur le manager (sans relai) :

```xml
<!-- Configuration dans ossec.conf du manager -->
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>udp</protocol>
  <allowed-ips>192.168.1.1</allowed-ips>  <!-- IP du firewall -->
</remote>
```

> **Bonne pratique** : la méthode via rsyslog est préférée en production car elle offre un buffer local, une meilleure gestion des fichiers et la possibilité de filtrer les logs avant envoi à Wazuh.

---

## Monitoring de commandes

### Principe

Le monitoring de commandes permet d'exécuter périodiquement une commande système et de traiter sa sortie comme un log. C'est utile pour surveiller des informations qui ne sont pas écrites dans des fichiers de logs.

### La balise command dans localfile

```xml
<!-- Surveiller les connexions réseau actives toutes les 360 secondes -->
<localfile>
  <log_format>command</log_format>
  <command>netstat -tlnp</command>
  <frequency>360</frequency>
</localfile>
```

### Le module wodle command

Le module `wodle` offre une syntaxe plus riche pour le monitoring de commandes :

```xml
<!-- Surveillance avancée avec le module wodle -->
<wodle name="command">
  <disabled>no</disabled>
  <tag>network-connections</tag>
  <command>/usr/bin/ss -tlnp</command>
  <interval>5m</interval>
  <ignore_output>no</ignore_output>
  <run_on_start>yes</run_on_start>
  <timeout>30</timeout>
</wodle>
```

### Comparaison command vs wodle command

| Caractéristique | `<localfile>` command | `<wodle name="command">` |
|-----------------|----------------------|--------------------------|
| **Syntaxe** | Balise `<localfile>` | Balise `<wodle>` |
| **Fréquence** | `<frequency>` (secondes) | `<interval>` (ex: 5m, 1h) |
| **Tag personnalisé** | Non | Oui (`<tag>`) |
| **Timeout** | Non | Oui (`<timeout>`) |
| **Exécution au démarrage** | Oui | Configurable (`<run_on_start>`) |
| **Recommandation** | Cas simples | Cas avancés |

### Exemples de monitoring de commandes

**Surveillance des utilisateurs connectés :**

```xml
<localfile>
  <log_format>full_command</log_format>
  <command>who</command>
  <frequency>300</frequency>
</localfile>
```

**Surveillance des processus en écoute :**

```xml
<localfile>
  <log_format>full_command</log_format>
  <command>ss -tlnp</command>
  <frequency>600</frequency>
</localfile>
```

**Surveillance de l'espace disque :**

```xml
<wodle name="command">
  <disabled>no</disabled>
  <tag>disk-usage</tag>
  <command>df -h | grep -E '^/dev'</command>
  <interval>30m</interval>
  <run_on_start>yes</run_on_start>
  <timeout>10</timeout>
</wodle>
```

**Vérification de l'intégrité d'un fichier critique :**

```xml
<wodle name="command">
  <disabled>no</disabled>
  <tag>file-integrity-check</tag>
  <command>sha256sum /etc/passwd /etc/shadow /etc/sudoers</command>
  <interval>10m</interval>
  <run_on_start>yes</run_on_start>
  <timeout>10</timeout>
</wodle>
```

> **Attention** : le format `command` capture uniquement la dernière ligne de la sortie. Utilisez `full_command` si vous avez besoin de toutes les lignes.

---

## Intégration avec journald

Sur les systèmes Linux modernes utilisant systemd, les logs sont gérés par `journald`. Wazuh peut lire directement le journal systemd :

```xml
<!-- Collecte des logs journald -->
<localfile>
  <log_format>journald</log_format>
  <location>journald</location>
</localfile>
```

Vous pouvez filtrer par unité systemd :

```xml
<!-- Collecter uniquement les logs du service SSH -->
<localfile>
  <log_format>journald</log_format>
  <location>journald</location>
  <filter type="unit">sshd.service</filter>
</localfile>
```

---

## Bonnes pratiques pour la collecte de logs

| Bonne pratique | Explication |
|----------------|-------------|
| **Ne pas tout collecter** | Collectez uniquement les logs pertinents pour la sécurité. Un excès de logs noie les alertes et consomme des ressources |
| **Prioriser les logs de sécurité** | Authentification, accès réseau, exécution de processus, modifications système |
| **Tester avant déploiement** | Utilisez `wazuh-logtest` et vérifiez que les décodeurs fonctionnent avant de passer en production |
| **Documenter vos configurations** | Chaque `<localfile>` ajouté doit être documenté : source, format, raison de la collecte |
| **Surveiller le volume** | Vérifiez régulièrement que le volume de logs ne sature pas le stockage ou le réseau |
| **Normaliser les formats** | Privilégiez le format JSON pour vos applications. Il est plus facile à décoder |
| **Séparer les fichiers de logs** | Chaque application doit écrire dans son propre fichier pour faciliter le décodage |
| **Redémarrer proprement** | Après modification, redémarrez l'agent et vérifiez les logs Wazuh (`/var/ossec/logs/ossec.log`) pour détecter d'éventuelles erreurs |

---

## Glossaire des sigles et définitions

| Sigle/Terme | Définition |
|-------------|------------|
| **SIEM** | Security Information and Event Management -- système de centralisation et d'analyse des logs de sécurité |
| **Décodeur (Decoder)** | Composant Wazuh qui extrait des champs structurés à partir d'un log brut |
| **localfile** | Directive Wazuh pour déclarer un fichier de logs à surveiller sur l'agent |
| **eventchannel** | Format de collecte des logs Windows Event Log dans Wazuh |
| **syslog** | Protocole standard d'envoi de messages de logs sur le réseau (UDP/TCP port 514) |
| **rsyslog** | Implémentation avancée de syslog sous Linux, utilisée comme relai de logs |
| **journald** | Système de journalisation de systemd sur Linux |
| **Sysmon** | System Monitor -- outil Sysinternals générant des événements de sécurité détaillés sous Windows |
| **ossec.conf** | Fichier de configuration principal de l'agent et du manager Wazuh |
| **prematch** | Pattern de pré-filtrage dans un décodeur Wazuh, identifie la source du log |
| **regex** | Expression régulière utilisée dans les décodeurs pour extraire des champs |
| **wodle** | Module d'extension Wazuh (Wazuh Open Distributed Lightweight Engine) |
| **C2** | Command and Control -- serveur utilisé par un attaquant pour contrôler des machines compromises |

---

## Récapitulatif des commandes

| Commande | Description |
|----------|-------------|
| `sudo /var/ossec/bin/wazuh-logtest` | Tester les décodeurs et règles interactivement |
| `sudo systemctl restart wazuh-agent` | Redémarrer l'agent Wazuh (Linux) |
| `sudo systemctl restart wazuh-manager` | Redémarrer le manager Wazuh |
| `Restart-Service -Name WazuhSvc` | Redémarrer l'agent Wazuh (Windows PowerShell) |
| `sudo cat /var/ossec/logs/ossec.log` | Consulter les logs internes de Wazuh |
| `sudo cat /var/ossec/etc/ossec.conf` | Afficher la configuration de l'agent |
| `sudo cat /var/ossec/etc/decoders/local_decoder.xml` | Afficher les décodeurs personnalisés |
| `sudo tail -f /var/ossec/logs/alerts/alerts.json` | Suivre les alertes en temps réel |

---

## Ressources pratiques - TryHackMe / HackTheBox

| Plateforme | Room/Lab | Description |
|------------|----------|-------------|
| TryHackMe | [Wazuh](https://tryhackme.com/room/dvwazuhroom) | Prise en main de Wazuh : installation, configuration, collecte de logs |
| TryHackMe | [Log Operations](https://tryhackme.com/room/dvlogoperations) | Opérations sur les logs : collecte, parsing, analyse |
| HackTheBox | [Sherlock "Unit42"](https://app.hackthebox.com/sherlocks/Unit42) | Investigation forensique basée sur l'analyse de logs |

---

## Ressources

- [Wazuh Documentation -- Log data collection](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/index.html)
- [Wazuh Documentation -- Custom decoders](https://documentation.wazuh.com/current/user-manual/ruleset/custom.html)
- [Wazuh Documentation -- wazuh-logtest](https://documentation.wazuh.com/current/user-manual/reference/tools/wazuh-logtest.html)
- [Microsoft -- Sysmon Documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [SANS -- Sysmon Configuration Guide](https://www.sans.org/blog/sysmon/)
