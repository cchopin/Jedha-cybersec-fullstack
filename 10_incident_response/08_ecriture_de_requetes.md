# Écriture de requêtes

**Durée : 55 min**

## Ce que vous allez apprendre dans ce cours

Les décodeurs que vous avez appris à créer dans le cours précédent permettent d'extraire des champs structurés à partir des logs. Mais sans règles pour analyser ces champs, aucune alerte n'est générée. Dans cette leçon, vous apprendrez :

- comment fonctionne le moteur de règles Wazuh (pipeline complet du log à l'alerte),
- comment écrire des règles personnalisées pour détecter des menaces spécifiques,
- comment utiliser la corrélation d'événements pour détecter des attaques complexes,
- comment interroger les données dans le dashboard Wazuh avec la syntaxe Lucene,
- comment mapper vos règles au framework MITRE ATT&CK,
- comment configurer des réponses actives automatiques.

---

## Le moteur de règles Wazuh

### Pipeline de traitement

Chaque log collecté par Wazuh traverse un pipeline en quatre étapes :

```
+--------+     +-----------+     +---------+     +---------+
|  Log   | --> | Décodeur  | --> | Règles  | --> | Alerte  |
|  brut  |     | (decoder) |     | (rules) |     |         |
+--------+     +-----------+     +---------+     +---------+
                    |                 |                |
              Extraction         Matching         Stockage
              des champs        des conditions    + notification
```

1. **Log brut** : le log arrive depuis un agent (localfile, eventchannel, syslog, etc.)
2. **Décodeur** : les champs sont extraits (user, srcip, action, etc.)
3. **Règles** : les champs décodés sont comparés aux conditions définies dans les règles
4. **Alerte** : si une règle matche, une alerte est créée avec un niveau de sévérité

### Structure d'une règle XML

Une règle Wazuh est définie en XML avec la structure suivante :

```xml
<rule id="100001" level="5">
  <decoded_as>mywebapp-auth-fail</decoded_as>
  <description>MyWebApp : échec d'authentification</description>
</rule>
```

### Éléments d'une règle

| Élément/Attribut | Rôle | Exemple |
|------------------|------|---------|
| `id` | Identifiant unique de la règle (100000-120000 pour les règles custom) | `id="100001"` |
| `level` | Niveau d'alerte (0-15) | `level="10"` |
| `<decoded_as>` | Nom du décodeur qui doit avoir matché | `<decoded_as>sshd</decoded_as>` |
| `<match>` | Recherche de chaîne dans le log (insensible à la casse) | `<match>failed password</match>` |
| `<regex>` | Recherche par expression régulière dans le log | `<regex>FROM (\d+\.\d+)</regex>` |
| `<field name="...">` | Condition sur un champ décodé spécifique | `<field name="srcip">10.0.0.\.</field>` |
| `<srcip>` | Condition sur l'IP source | `<srcip>!192.168.1.0/24</srcip>` |
| `<dstip>` | Condition sur l'IP de destination | `<dstip>10.0.0.1</dstip>` |
| `<description>` | Description de l'alerte (apparaît dans le dashboard) | Texte libre |
| `<group>` | Groupes auxquels appartient la règle | `<group>authentication_failed,</group>` |
| `<options>` | Options supplémentaires (no_log, alert_by_email...) | `<options>no_log</options>` |

### Attributs de corrélation

Ces attributs permettent de créer des règles composites qui détectent des séquences d'événements :

| Attribut | Rôle | Exemple |
|----------|------|---------|
| `frequency` | Nombre d'occurrences nécessaires pour déclencher l'alerte | `frequency="5"` |
| `timeframe` | Fenêtre de temps (en secondes) pour compter les occurrences | `timeframe="120"` |
| `if_matched_sid` | Se déclenche si la règle référencée a matché (dans le timeframe) | `if_matched_sid="100001"` |
| `same_field` | Les occurrences doivent partager la même valeur pour ce champ | `same_field="srcip"` |
| `different_field` | Les occurrences doivent avoir des valeurs différentes | `different_field="user"` |
| `noalert` | La règle matche mais ne génère pas d'alerte (utilisée comme pré-condition) | `<options>no_log</options>` |

### Niveaux d'alerte (0-15)

Le niveau d'alerte détermine la sévérité de l'événement détecté. Voici la signification de chaque niveau :

| Niveau | Signification | Exemple |
|--------|---------------|---------|
| **0** | Règle ignorée (pas d'alerte) | Événements de bas niveau, bruit |
| **1** | Aucune pertinence | Logs de debug |
| **2** | Notification système de faible priorité | Changement de statut d'un service |
| **3** | Événement réussi ou autorisé | Connexion réussie |
| **4** | Erreur liée à une mauvaise configuration | Accès refusé à une ressource non critique |
| **5** | Erreur générée par l'utilisateur | Échec d'authentification isolé |
| **6** | Attaque de faible pertinence | Scan de port détecté |
| **7** | Événement correspondant à un "bad word" | Mot-clé suspect dans un log applicatif |
| **8** | Événement vu pour la première fois | Premier accès depuis une nouvelle IP |
| **9** | Erreur provenant d'une source invalide | Tentative de connexion avec un utilisateur inexistant |
| **10** | Erreurs multiples liées à l'utilisateur | Plusieurs échecs d'authentification |
| **11** | Alerte d'intégrité | Modification d'un fichier système critique |
| **12** | Événement de haute importance | Erreur ou attaque majeure |
| **13** | Erreur inhabituelle (haute importance) | Comportement anormal détecté |
| **14** | Événement de sécurité de haute importance | Attaque corrélée, exploitation détectée |
| **15** | Attaque sévère -- action immédiate requise | Compromission confirmée, rootkit détecté |

> **Bonne pratique** : pour vos règles personnalisées, utilisez les niveaux 5 à 7 pour les événements suspects isolés, 10 à 12 pour les corrélations et patterns d'attaque, et 13 à 15 uniquement pour les menaces confirmées nécessitant une action immédiate.

---

## Création de règles personnalisées

### Fichier de règles personnalisées

Toutes vos règles personnalisées doivent être ajoutées dans :

```
/var/ossec/etc/rules/local_rules.xml
```

> **Important** : ne modifiez jamais les fichiers dans `/var/ossec/ruleset/rules/`. Ils sont écrasés lors des mises à jour de Wazuh.

### Exemple 1 : Détection de brute force SSH

Cette règle détecte 5 échecs d'authentification SSH en 2 minutes depuis la même IP :

```xml
<!-- Règle de base : échec SSH (hérite de la règle intégrée 5716) -->
<rule id="100001" level="0">
  <if_sid>5716</if_sid>
  <description>SSH : échec d'authentification (pré-condition)</description>
</rule>

<!-- Règle composite : brute force SSH -->
<rule id="100002" level="10" frequency="5" timeframe="120">
  <if_matched_sid>100001</if_matched_sid>
  <same_field>srcip</same_field>
  <description>BRUTE FORCE : 5 échecs SSH en 2 minutes depuis la même IP</description>
  <group>authentication_failed,attack,</group>
  <mitre>
    <id>T1110</id>
  </mitre>
</rule>
```

**Explication :**

- La règle `100001` (level 0) sert de pré-condition : elle matche chaque échec SSH sans générer d'alerte.
- La règle `100002` (level 10) se déclenche quand la règle `100001` a matché 5 fois en 120 secondes depuis la même IP source (`same_field="srcip"`).
- Le tag `<mitre>` associe la détection à la technique MITRE ATT&CK T1110 (Brute Force).

### Exemple 2 : Détection d'exécution suspecte depuis /tmp

L'exécution de programmes depuis `/tmp` est un comportement courant des malwares. Cette règle la détecte :

```xml
<!-- Détection d'exécution de binaire depuis /tmp -->
<rule id="100010" level="12">
  <if_sid>80700</if_sid>
  <field name="audit.exe">^/tmp/</field>
  <description>SUSPICION : exécution d'un binaire depuis /tmp</description>
  <group>suspicious_execution,malware,</group>
  <mitre>
    <id>T1059</id>
  </mitre>
</rule>
```

**Explication :**

- `<if_sid>80700</if_sid>` : hérite des règles auditd de création de processus.
- `<field name="audit.exe">^/tmp/</field>` : le chemin de l'exécutable commence par `/tmp/`.
- Level 12 : événement de haute importance, car l'exécution depuis `/tmp` est rarement légitime.

### Exemple 3 : Détection de modification de fichiers sensibles

```xml
<!-- Modification de /etc/passwd -->
<rule id="100020" level="11">
  <if_sid>550</if_sid>
  <match>/etc/passwd</match>
  <description>INTÉGRITÉ : modification de /etc/passwd détectée</description>
  <group>file_integrity,system_critical,</group>
  <mitre>
    <id>T1098</id>
  </mitre>
</rule>

<!-- Modification de /etc/shadow -->
<rule id="100021" level="11">
  <if_sid>550</if_sid>
  <match>/etc/shadow</match>
  <description>INTÉGRITÉ : modification de /etc/shadow détectée</description>
  <group>file_integrity,system_critical,</group>
  <mitre>
    <id>T1098</id>
  </mitre>
</rule>

<!-- Modification de /etc/sudoers -->
<rule id="100022" level="13">
  <if_sid>550</if_sid>
  <match>/etc/sudoers</match>
  <description>CRITIQUE : modification de /etc/sudoers détectée</description>
  <group>file_integrity,privilege_escalation,</group>
  <mitre>
    <id>T1548</id>
  </mitre>
</rule>
```

**Explication :**

- `<if_sid>550</if_sid>` : hérite des règles de File Integrity Monitoring (FIM) de Wazuh.
- Les modifications de `/etc/passwd` et `/etc/shadow` (level 11) peuvent indiquer un ajout de compte malveillant.
- La modification de `/etc/sudoers` (level 13) est plus critique car elle permet une escalade de privileges.

### Exemple 4 : Détection de connexion admin hors heures ouvrées

```xml
<!-- Connexion avec un compte administrateur -->
<rule id="100030" level="3">
  <if_sid>5715</if_sid>
  <user>root|admin|administrator</user>
  <description>Connexion SSH avec un compte administrateur</description>
  <group>admin_login,</group>
</rule>

<!-- Connexion admin hors heures ouvrées (entre 20h et 6h, ou le weekend) -->
<rule id="100031" level="12">
  <if_sid>100030</if_sid>
  <time>8pm - 6am</time>
  <description>SUSPICION : connexion administrateur hors heures ouvrées</description>
  <group>admin_login,suspicious_time,</group>
  <mitre>
    <id>T1078</id>
  </mitre>
</rule>

<rule id="100032" level="12">
  <if_sid>100030</if_sid>
  <weekday>weekends</weekday>
  <description>SUSPICION : connexion administrateur le weekend</description>
  <group>admin_login,suspicious_time,</group>
  <mitre>
    <id>T1078</id>
  </mitre>
</rule>
```

**Explication :**

- La règle `100030` (level 3) matche toute connexion SSH réussie avec un compte admin.
- La règle `100031` (level 12) se déclenche si cette connexion a lieu entre 20h et 6h.
- La règle `100032` (level 12) se déclenche si cette connexion a lieu le weekend.
- Le tag MITRE T1078 correspond à "Valid Accounts" (utilisation de comptes légitimes par un attaquant).

### Exemple 5 : Détection de désactivation de Windows Defender

```xml
<!-- Windows Defender : protection temps réel désactivée (Event ID 5001) -->
<rule id="100040" level="13">
  <if_sid>61612</if_sid>
  <field name="win.system.eventID">^5001$</field>
  <description>CRITIQUE : Windows Defender protection temps réel désactivée</description>
  <group>windows_defender,defense_evasion,</group>
  <mitre>
    <id>T1562.001</id>
  </mitre>
</rule>

<!-- Windows Defender : détection de malware non remédiée -->
<rule id="100041" level="12">
  <if_sid>61612</if_sid>
  <field name="win.system.eventID">^1008$</field>
  <description>Windows Defender : échec de remédiation d'un malware</description>
  <group>windows_defender,malware,</group>
  <mitre>
    <id>T1211</id>
  </mitre>
</rule>
```

**Explication :**

- `<if_sid>61612</if_sid>` : hérite des règles Windows Defender de Wazuh.
- L'Event ID 5001 indique que la protection temps réel a été désactivée. C'est une technique classique des attaquants (T1562.001 -- Impair Defenses: Disable or Modify Tools).
- Level 13 : événement critique nécessitant une investigation immédiate.

---

## Requêtes dans le Dashboard Wazuh (OpenSearch)

### Syntaxe de recherche : Lucene query syntax

Le dashboard Wazuh utilise OpenSearch (fork d'Elasticsearch) et sa syntaxe de requêtes basée sur Lucene. Cette syntaxe permet de filtrer les alertes directement depuis l'interface web.

### Opérateurs de base

| Opérateur | Signification | Exemple |
|-----------|---------------|---------|
| `AND` | Les deux conditions doivent être vraies | `rule.level: 10 AND agent.name: "web-server"` |
| `OR` | Au moins une condition doit être vraie | `rule.id: 100001 OR rule.id: 100002` |
| `NOT` | Exclure les résultats correspondants | `NOT agent.name: "test-server"` |
| `:` | Égalité | `rule.level: 12` |
| `>=`, `<=` | Supérieur/inférieur ou égal | `rule.level >= 10` |
| `*` | Wildcard (tout caractère) | `agent.name: web*` |
| `" "` | Recherche exacte | `rule.description: "brute force"` |

### Champs les plus utilisés

| Champ | Description | Exemple de valeur |
|-------|-------------|-------------------|
| `rule.level` | Niveau d'alerte de la règle | `10` |
| `rule.id` | Identifiant de la règle | `100002` |
| `rule.description` | Description de l'alerte | `"BRUTE FORCE : 5 échecs SSH"` |
| `rule.groups` | Groupes auxquels appartient la règle | `authentication_failed` |
| `rule.mitre.id` | Identifiant technique MITRE ATT&CK | `T1110` |
| `rule.mitre.technique` | Nom de la technique MITRE | `Brute Force` |
| `agent.name` | Nom de l'agent qui a généré l'événement | `web-server-01` |
| `agent.id` | Identifiant numérique de l'agent | `003` |
| `data.srcip` | Adresse IP source | `192.168.1.50` |
| `data.dstip` | Adresse IP de destination | `10.0.0.1` |
| `data.srcuser` | Utilisateur source | `admin` |
| `location` | Source du log (fichier, canal Windows) | `/var/log/auth.log` |
| `timestamp` | Date et heure de l'événement | `2025-03-15T14:32:01` |

### Exemples de requêtes courantes

**Alertes de haute sévérité (level >= 10) :**

```
rule.level >= 10
```

**Alertes liées à l'exécution de commandes (MITRE T1059) :**

```
rule.mitre.id: T1059
```

**Échecs d'authentification sur le serveur web :**

```
agent.name: "web-server" AND rule.groups: "authentication_failed"
```

**Alertes provenant d'une IP spécifique :**

```
data.srcip: "203.0.113.10"
```

**Alertes des dernières 24 heures excluant le bruit :**

```
rule.level >= 7 AND NOT rule.id: 5502 AND NOT rule.id: 5503
```

**Détections de brute force :**

```
rule.mitre.id: T1110 AND rule.level >= 10
```

**Recherche sur une plage d'IPs :**

```
data.srcip: 10.0.0.* AND rule.groups: "authentication_failed"
```

**Activité suspecte sur les fichiers système :**

```
rule.groups: "syscheck" AND (rule.level >= 10)
```

### Création de dashboards et visualisations

Dans le dashboard Wazuh, vous pouvez créer des visualisations pour suivre vos règles personnalisées :

| Type de visualisation | Usage | Configuration |
|-----------------------|-------|---------------|
| **Pie chart** | Répartition des alertes par niveau | Champ : `rule.level`, Agrégation : Count |
| **Bar chart** | Top 10 des règles déclenchées | Champ : `rule.id`, Agrégation : Count, Tri : Descending |
| **Line chart** | Évolution des alertes dans le temps | Axe X : `timestamp`, Axe Y : Count |
| **Data table** | Liste détaillée des alertes | Colonnes : `timestamp`, `agent.name`, `rule.description`, `rule.level` |
| **Metric** | Compteur d'alertes critiques | Filtre : `rule.level >= 12`, Agrégation : Count |

> **Bonne pratique** : créez un dashboard dédié à vos règles personnalisées. Filtrez avec `rule.id >= 100000` pour n'afficher que vos règles (les règles intégrées ont des IDs inférieurs à 100000).

---

## Test des règles avec wazuh-logtest

### Utilisation interactive

L'outil `wazuh-logtest` permet de valider le bon fonctionnement de vos décodeurs et de vos règles sans attendre qu'un vrai événement se produise :

```bash
sudo /var/ossec/bin/wazuh-logtest
```

### Injection de logs de test

Collez un log dans `wazuh-logtest` pour voir comment il est traité :

```
Mar 15 14:32:01 webserver sshd[12345]: Failed password for admin from 192.168.1.50 port 22 ssh2
```

Résultat attendu :

```
**Phase 1: Completed pre-decoding.
       full event: 'Mar 15 14:32:01 webserver sshd[12345]: Failed password for admin from 192.168.1.50 port 22 ssh2'
       timestamp: 'Mar 15 14:32:01'
       hostname: 'webserver'
       program_name: 'sshd'

**Phase 2: Completed decoding.
       name: 'sshd'
       parent: 'sshd'
       srcip: '192.168.1.50'
       srcuser: 'admin'

**Phase 3: Completed filtering (rules).
       id: '5716'
       level: '5'
       description: 'SSHD authentication failed.'
       groups: '['syslog', 'sshd', 'authentication_failed']'
```

### Validation pas à pas

Lors du test, vérifiez les trois phases :

| Phase | Ce qu'il faut vérifier | Problème possible |
|-------|------------------------|-------------------|
| **Phase 1** (pre-decoding) | Le log est correctement reçu | Problème de collecte (localfile) |
| **Phase 2** (decoding) | Les bons champs sont extraits | Décodeur absent ou mal écrit |
| **Phase 3** (rules) | La bonne règle matche avec le bon niveau | Condition de règle trop restrictive ou trop large |

> **Bonne pratique** : créez un fichier de logs de test contenant des exemples représentatifs de chaque scénario que vos règles doivent détecter. Rejouez ce fichier après chaque modification pour vérifier qu'il n'y a pas de régression.

---

## Intégration MITRE ATT&CK

### Principe du mapping

Le framework **MITRE ATT&CK** est une base de connaissance qui répertorie les tactiques et techniques utilisées par les attaquants. Wazuh permet d'associer chaque règle à une ou plusieurs techniques MITRE, ce qui facilite la catégorisation des alertes.

### Attribut mitre dans les règles

```xml
<rule id="100050" level="10">
  <if_sid>5716</if_sid>
  <frequency>5</frequency>
  <timeframe>120</timeframe>
  <same_field>srcip</same_field>
  <description>Brute force SSH détectée</description>
  <mitre>
    <id>T1110</id>           <!-- Brute Force -->
  </mitre>
</rule>
```

### Techniques MITRE courantes et règles associées

| Technique MITRE | ID | Description | Détection Wazuh |
|-----------------|-----|-------------|-----------------|
| **Brute Force** | T1110 | Tentatives de connexion multiples | Corrélation frequency + timeframe sur les échecs d'auth |
| **Command and Scripting Interpreter** | T1059 | Exécution de scripts/commandes | Détection de PowerShell, bash dans des contextes suspects |
| **Valid Accounts** | T1078 | Utilisation de comptes légitimes | Connexion admin hors heures, depuis IP inhabituelle |
| **Account Manipulation** | T1098 | Modification de comptes | Changement de /etc/passwd, ajout de groupe admin |
| **Impair Defenses** | T1562 | Désactivation des défenses | Windows Defender désactivé, audit logs effacés |
| **Abuse Elevation Control** | T1548 | Escalade de privileges | Modification de sudoers, exploitation SUID |
| **Scheduled Task/Job** | T1053 | Tâche planifiée malveillante | Nouvelle entrée crontab, tâche planifiée Windows |
| **Boot or Logon Autostart** | T1547 | Persistence au démarrage | Modification des clés Run du registre, services ajoutés |

### Visualisation dans le dashboard

Le dashboard Wazuh intègre une vue MITRE ATT&CK qui affiche automatiquement :

- une matrice MITRE colorée selon le nombre d'alertes par technique,
- un classement des techniques les plus fréquemment détectées,
- la corrélation entre les agents et les techniques MITRE observées.

Pour accéder à cette vue : **Wazuh Dashboard > Security Events > MITRE ATT&CK**.

---

## Active Response : déclencher des actions automatiques

### Principe

L'Active Response permet à Wazuh de déclencher automatiquement une action lorsqu'une règle est déclenchée. C'est la capacité de réponse automatique du SIEM.

**Exemples d'actions automatiques :**

| Action | Commande Wazuh | Effet |
|--------|----------------|-------|
| **Bloquer une IP** | `firewall-drop` | Ajoute une règle iptables/nftables pour bloquer l'IP source |
| **Désactiver un compte** | `disable-account` | Verrouille le compte utilisateur sur le système |
| **Tuer un processus** | `kill` (custom) | Termine un processus malveillant |
| **Exécuter un script** | Script personnalisé | Action libre (notification Slack, isolation réseau...) |

### Configuration d'une active response

La configuration se fait en deux parties dans le `ossec.conf` du **manager** :

**Partie 1 : Définir la commande**

```xml
<command>
  <name>firewall-drop</name>
  <executable>firewall-drop</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>
```

**Partie 2 : Définir la réponse active**

```xml
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>100002</rules_id>
  <timeout>600</timeout>
</active-response>
```

### Explication des paramètres

| Paramètre | Description | Valeurs possibles |
|-----------|-------------|-------------------|
| `<command>` | Nom de la commande à exécuter | `firewall-drop`, `disable-account`, script custom |
| `<location>` | Où exécuter la commande | `local` (agent source), `server` (manager), `all` (tous les agents) |
| `<rules_id>` | Règle(s) qui déclenchent la réponse | ID de règle ou liste séparée par des virgules |
| `<timeout>` | Durée en secondes avant annulation automatique de l'action | Entier (ex: 600 = 10 minutes) |
| `<level>` | Niveau d'alerte minimum pour déclencher la réponse | Entier (ex: 10) |

### Exemple complet : bloquer une IP après brute force SSH

```xml
<!-- Commande de blocage firewall -->
<command>
  <name>firewall-drop</name>
  <executable>firewall-drop</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>

<!-- Active response : bloquer l'IP source pendant 10 minutes
     quand la règle 100002 (brute force SSH) est déclenchée -->
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>100002</rules_id>
  <timeout>600</timeout>
</active-response>
```

Quand la règle `100002` se déclenche (5 échecs SSH en 2 minutes), Wazuh :

1. Exécute `firewall-drop` sur l'agent concerné.
2. L'IP source est bloquée par une règle iptables/nftables.
3. Après 600 secondes (10 minutes), la règle de blocage est automatiquement retirée.

### Exemple : désactiver un compte

```xml
<command>
  <name>disable-account</name>
  <executable>disable-account</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>

<active-response>
  <command>disable-account</command>
  <location>local</location>
  <rules_id>100002</rules_id>
  <timeout>3600</timeout>
</active-response>
```

> **Attention** : les active responses sont puissantes mais risquées. Un faux positif peut bloquer un utilisateur légitime ou une IP critique. Testez vos règles abondamment avec `wazuh-logtest` avant d'activer des réponses automatiques en production. Commencez par des timeouts courts et augmentez progressivement.

---

## Workflow complet : de l'idée à la détection

Pour résumer, voici les étapes pour mettre en place une détection personnalisée complète :

| Étape | Action | Fichier / Outil |
|-------|--------|-----------------|
| 1 | Identifier la source de logs à collecter | Inventaire des sources |
| 2 | Configurer la collecte (`<localfile>`) | `ossec.conf` (agent) |
| 3 | Créer le décodeur si nécessaire | `/var/ossec/etc/decoders/local_decoder.xml` |
| 4 | Tester le décodage | `wazuh-logtest` |
| 5 | Écrire la règle de détection | `/var/ossec/etc/rules/local_rules.xml` |
| 6 | Tester la règle | `wazuh-logtest` |
| 7 | Mapper au framework MITRE ATT&CK | Balise `<mitre>` dans la règle |
| 8 | Configurer la réponse active (optionnel) | `ossec.conf` (manager) |
| 9 | Redémarrer le manager et les agents | `systemctl restart wazuh-manager` |
| 10 | Créer un dashboard de suivi | Interface web Wazuh |

---

## Glossaire des sigles et définitions

| Sigle/Terme | Définition |
|-------------|------------|
| **Règle (Rule)** | Composant Wazuh qui définit les conditions de déclenchement d'une alerte |
| **Alerte (Alert)** | Notification générée par Wazuh lorsqu'une règle matche un événement |
| **Corrélation** | Mise en relation de plusieurs événements pour détecter un pattern d'attaque |
| **Active Response** | Capacité de Wazuh à exécuter automatiquement une action suite à une alerte |
| **Lucene** | Syntaxe de requêtes utilisée par OpenSearch/Elasticsearch pour la recherche |
| **OpenSearch** | Moteur de recherche et d'indexation (fork d'Elasticsearch) utilisé par Wazuh |
| **MITRE ATT&CK** | Base de connaissances des tactiques et techniques d'attaque informatique |
| **FIM** | File Integrity Monitoring -- surveillance de l'intégrité des fichiers |
| **SID** | Security Identifier (dans le contexte Wazuh : identifiant de règle référencé par `if_sid` ou `if_matched_sid`) |
| **frequency** | Nombre d'occurrences d'un événement nécessaire pour déclencher une règle composite |
| **timeframe** | Fenêtre de temps dans laquelle les occurrences sont comptées pour la corrélation |
| **firewall-drop** | Script Wazuh d'active response qui bloque une IP via iptables/nftables |
| **wazuh-logtest** | Outil en ligne de commande pour tester les décodeurs et règles Wazuh |
| **T1110** | Technique MITRE ATT&CK : Brute Force |
| **T1059** | Technique MITRE ATT&CK : Command and Scripting Interpreter |

---

## Récapitulatif des commandes

| Commande | Description |
|----------|-------------|
| `sudo /var/ossec/bin/wazuh-logtest` | Tester les décodeurs et règles interactivement |
| `sudo systemctl restart wazuh-manager` | Redémarrer le manager Wazuh (appliquer les changements de règles) |
| `sudo systemctl restart wazuh-agent` | Redémarrer l'agent Wazuh |
| `sudo cat /var/ossec/etc/rules/local_rules.xml` | Afficher les règles personnalisées |
| `sudo cat /var/ossec/etc/decoders/local_decoder.xml` | Afficher les décodeurs personnalisés |
| `sudo tail -f /var/ossec/logs/alerts/alerts.json` | Suivre les alertes en temps réel (JSON) |
| `sudo tail -f /var/ossec/logs/alerts/alerts.log` | Suivre les alertes en temps réel (texte) |
| `sudo cat /var/ossec/logs/ossec.log` | Consulter les logs internes de Wazuh |
| `sudo /var/ossec/bin/wazuh-control status` | Vérifier le statut de tous les processus Wazuh |

---

## Ressources pratiques - TryHackMe / HackTheBox

| Plateforme | Room/Lab | Description |
|------------|----------|-------------|
| TryHackMe | [Custom Alert Rules in Wazuh](https://tryhackme.com/room/dvwazuhcustomrules) | Création de règles d'alerte personnalisées dans Wazuh |
| TryHackMe | [MITRE](https://tryhackme.com/room/dvmitre) | Compréhension du framework MITRE ATT&CK et son application |
| HackTheBox | [Sherlock "Noted"](https://app.hackthebox.com/sherlocks/Noted) | Investigation forensique avec analyse de logs et corrélation d'événements |

---

## Ressources

- [Wazuh Documentation -- Custom rules](https://documentation.wazuh.com/current/user-manual/ruleset/custom.html)
- [Wazuh Documentation -- Rule syntax](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html)
- [Wazuh Documentation -- Active response](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/index.html)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [OpenSearch Documentation -- Query DSL](https://opensearch.org/docs/latest/query-dsl/)
- [SANS -- Wazuh Cheat Sheet](https://www.sans.org/blog/wazuh/)
