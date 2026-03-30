# Analyse dynamique

**Durée : 55 min**

## Ce que vous allez apprendre dans ce cours

L'analyse dynamique est la seconde étape majeure de l'investigation d'un malware. Elle consiste à exécuter le sample dans un environnement contrôlé pour observer son comportement réel. Dans cette leçon, vous allez :

- comprendre quand et pourquoi utiliser l'analyse dynamique,
- préparer votre environnement de manière sécurisée avant l'exécution,
- surveiller les processus, le système de fichiers et le registre avec les outils Sysinternals,
- capturer et analyser le trafic réseau avec Wireshark, FakeNet-NG et INetSim,
- utiliser Volatility pour analyser la mémoire d'un système infecté,
- connaître les techniques d'évasion de sandbox utilisées par les malwares et leurs contre-mesures,
- suivre un workflow complet d'analyse dynamique,
- comparer les principales sandbox en ligne.

---

## 1. Principes de l'analyse dynamique

### 1.1 Définition

L'analyse dynamique consiste à **exécuter le malware** dans un environnement contrôlé et isolé pour observer son comportement en temps réel. Contrairement à l'analyse statique qui examine le fichier tel quel, l'analyse dynamique révèle ce que le malware fait réellement lorsqu'il s'exécute.

### 1.2 Quand utiliser l'analyse dynamique

L'analyse dynamique est particulièrement utile dans les situations suivantes :

| Situation | Pourquoi l'analyse dynamique est nécessaire |
|-----------|----------------------------------------------|
| **Après l'analyse statique** | Pour confirmer les hypothèses issues de l'analyse statique |
| **Code obfusqué ou packé** | Le code ne peut pas être lu statiquement, mais son comportement est observable |
| **Fileless malware** | Le malware n'existe qu'en mémoire, il faut l'exécuter pour l'observer |
| **Malware polymorphe** | Le code change à chaque exécution, le comportement reste identifiable |
| **Identification des IOCs réseau** | Pour capturer les domaines C2, les IPs, les patterns de communication |
| **Compréhension du payload final** | Quand le malware télécharge ou déchiffre un second payload |

### 1.3 Avantages et limites

| Avantages | Limites |
|-----------|---------|
| Observe le comportement **réel** du malware | **Risque** si l'environnement est mal isolé |
| Contourne l'obfuscation et le packing | Le malware peut détecter la **sandbox** et modifier son comportement |
| Identifie les IOCs réseau (C2, beaconing) | Le comportement peut varier selon l'**environnement** (OS, langue, timezone) |
| Capture les fichiers droppés et les modifications | Le malware peut avoir des **conditions de déclenchement** (date, domaine, etc.) |
| Permet de capturer un dump mémoire pour analyse | Nécessite un **lab isolé** correctement configuré |
| Rapports visuels et chronologiques | **Consomme du temps** (observation de plusieurs minutes) |

---

## 2. Préparation de l'environnement

Avant d'exécuter le moindre sample, votre environnement doit être prêt. Voici la checklist :

| Étape | Action | Vérification |
|-------|--------|--------------|
| 1 | **Snapshot** de la VM propre | Le snapshot est daté et nommé (ex: `clean_2025-01-15`) |
| 2 | **Réseau isolé** | La VM est en Internal Network / Host-Only |
| 3 | **Outils de monitoring lancés** | ProcMon, Process Explorer, Wireshark sont ouverts |
| 4 | **Capture réseau active** | Wireshark enregistre le trafic sur l'interface réseau |
| 5 | **INetSim ou FakeNet-NG actif** | Les services réseau simulés sont en cours d'exécution |
| 6 | **Copier-coller et dossiers partagés désactivés** | Vérifiés dans les paramètres de la VM |
| 7 | **Windows Defender désactivé** | Le malware ne sera pas bloqué par l'antivirus |
| 8 | **Documentation prête** | Fichier de notes ouvert pour consigner les observations |

### Configuration DNS et Gateway

Pour capturer le trafic réseau du malware, configurez votre lab comme vu dans le cours précédent :

```
FlareVM (192.168.100.10)  ───►  REMnux (192.168.100.1)
                                   ├── INetSim (simule DNS, HTTP, etc.)
                                   └── Wireshark (capture tout le trafic)
```

Le malware sur FlareVM tentera de résoudre des noms de domaine et d'établir des connexions. INetSim sur REMnux répondra à toutes les requêtes, et Wireshark capturera tout le trafic.

---

## 3. Monitoring des processus

### 3.1 Process Monitor (ProcMon)

**Process Monitor** (ProcMon) de la suite Sysinternals est l'outil central de l'analyse dynamique. Il capture en temps réel toutes les opérations effectuées par les processus : accès aux fichiers, modifications du registre, activité réseau et gestion des processus/threads.

**Filtres essentiels :**

ProcMon génère un volume énorme d'événements. Il est indispensable de filtrer pour se concentrer sur le malware :

| Filtre | Condition | Valeur | Usage |
|--------|-----------|--------|-------|
| `Process Name` | is | `sample.exe` | Ne voir que les événements du malware |
| `Process Name` | is not | `procmon.exe` | Exclure ProcMon lui-même |
| `Process Name` | is not | `System` | Exclure le processus System |
| `Operation` | is | `CreateFile` | Voir uniquement les créations de fichiers |
| `Operation` | is | `RegSetValue` | Voir uniquement les modifications du registre |
| `Operation` | contains | `TCP` | Voir l'activité réseau |
| `Path` | contains | `Run` | Voir les accès aux clés de persistance |
| `Path` | contains | `Temp` | Voir les fichiers dans le dossier temporaire |

**Configuration recommandée :**

```
1. Lancer ProcMon en tant qu'administrateur
2. Stopper la capture (Ctrl+E) pour configurer les filtres
3. Ajouter les filtres pertinents (Filter > Filter...)
4. Relancer la capture (Ctrl+E)
5. Exécuter le malware
6. Observer les événements pendant 5-15 minutes
7. Sauvegarder le log (File > Save... > format CSV ou PML)
```

**Que surveiller dans ProcMon :**

| Opération | Signification potentielle |
|-----------|---------------------------|
| `CreateFile` dans `%TEMP%` ou `%APPDATA%` | Le malware dépose un fichier (payload secondaire) |
| `RegSetValue` dans `...\Run` | Le malware crée une persistance au registre |
| `CreateFile` dans `System32` | Le malware tente de se copier dans un répertoire système |
| `Process Create` | Le malware lance un autre processus (enfant) |
| `TCP Connect` | Le malware tente une connexion réseau (C2) |
| `WriteFile` vers un fichier `.bat` ou `.ps1` | Le malware crée un script pour exécution |

### 3.2 Process Explorer

**Process Explorer** affiche l'arbre des processus en temps réel, avec des informations détaillées sur chaque processus :

| Fonctionnalité | Usage pour l'analyse |
|----------------|----------------------|
| **Arbre des processus** | Voir quels processus le malware a créés (relation parent/enfant) |
| **DLLs chargées** | Voir quelles DLLs le malware utilise (View > Lower Pane View > DLLs) |
| **Handles** | Voir les fichiers, clés de registre et mutex ouverts par le malware |
| **Propriétés du processus** | Vérifier le chemin de l'exécutable, le hash, les threads |
| **Verify** | Vérifier si l'exécutable est signé numériquement |
| **Coloration** | Les processus suspects apparaissent avec des couleurs différentes |

**Vérification VirusTotal intégrée :**

Process Explorer peut vérifier automatiquement les hashes des processus en cours sur VirusTotal :

```
Options > VirusTotal.com > Check VirusTotal.com
```

> **Attention** : cette fonctionnalité nécessite un accès Internet. Utilisez-la uniquement sur votre machine hôte, pas dans la VM d'analyse.

### 3.3 Process Hacker

**Process Hacker** est une alternative open source à Process Explorer, avec des fonctionnalités supplémentaires :

| Fonctionnalité | Description |
|----------------|-------------|
| **Injection de DLL** | Détecte les DLLs injectées dans les processus |
| **Memory inspection** | Permet d'inspecter la mémoire d'un processus |
| **Network connections** | Affiche les connexions réseau par processus |
| **Services** | Gestion et inspection des services Windows |
| **Kernel-mode** | Peut afficher des informations de niveau noyau |

---

## 4. Monitoring du système de fichiers

### 4.1 Avec ProcMon

Filtrez ProcMon pour ne voir que l'activité sur le système de fichiers :

```
Barre d'outils ProcMon : désactiver tout sauf l'icône "Show File System Activity"
```

**Emplacements à surveiller particulièrement :**

| Emplacement | Variable d'environnement | Pourquoi |
|-------------|--------------------------|----------|
| `C:\Users\<user>\AppData\Local\Temp` | `%TEMP%` | Dépôt courant de payloads temporaires |
| `C:\Users\<user>\AppData\Roaming` | `%APPDATA%` | Persistance utilisateur |
| `C:\Users\<user>\AppData\Local` | `%LOCALAPPDATA%` | Stockage de configuration malveillante |
| `C:\Windows\System32` | `%SystemRoot%\System32` | Camouflage en fichier système |
| `C:\Windows\Temp` | | Dépôt de fichiers avec droits SYSTEM |
| `C:\ProgramData` | `%ProgramData%` | Persistance pour tous les utilisateurs |
| `Startup folder` | `%APPDATA%\...\Startup` | Exécution automatique au login |

### 4.2 Fichiers droppés

Les **fichiers droppés** sont des fichiers que le malware dépose sur le disque pendant son exécution. Ils peuvent être :

| Type de fichier droppé | Description |
|------------------------|-------------|
| **Payload secondaire** | Exécutable principal après le dropper initial |
| **Script** | Fichier .bat, .ps1, .vbs pour exécuter des commandes |
| **DLL malveillante** | DLL à injecter dans un processus légitime |
| **Fichier de configuration** | Paramètres du malware (C2, clés de chiffrement) |
| **Note de rançon** | Fichier texte/HTML avec les instructions de paiement (ransomware) |
| **Keylogger output** | Fichier contenant les frappes clavier capturées |

> **Bonne pratique** : après l'exécution, utilisez un outil de comparaison de snapshots comme **Regshot** pour identifier tous les fichiers créés, modifiés ou supprimés.

---

## 5. Monitoring du registre

### 5.1 Avec ProcMon

Filtrez ProcMon pour ne voir que l'activité sur le registre :

```
Barre d'outils ProcMon : désactiver tout sauf l'icône "Show Registry Activity"
```

### 5.2 Clés de persistance à surveiller

Les malwares utilisent le registre Windows pour maintenir leur **persistance** (survivre à un redémarrage). Voici les clés les plus couramment abusées :

| Clé de registre | Description | Technique MITRE |
|-----------------|-------------|-----------------|
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | Exécution au démarrage pour tous les utilisateurs | T1547.001 |
| `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | Exécution au démarrage pour l'utilisateur courant | T1547.001 |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce` | Exécution unique au prochain démarrage | T1547.001 |
| `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce` | Exécution unique au prochain démarrage (utilisateur) | T1547.001 |
| `HKLM\SYSTEM\CurrentControlSet\Services` | Création de services Windows | T1543.003 |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` | Exécution lors du login (Shell, Userinit) | T1547.004 |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options` | Détournement de débogueur (IFEO) | T1546.012 |
| `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders` | Modification des dossiers spéciaux | T1547.001 |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run` | Politique d'exécution au démarrage | T1547.001 |

### 5.3 Outil complémentaire : Regshot

**Regshot** prend un "avant/après" du registre et du système de fichiers :

```
1. Lancer Regshot AVANT l'exécution du malware
2. Cliquer sur "1st shot" → "Shot"
3. Exécuter le malware et attendre
4. Cliquer sur "2nd shot" → "Shot"
5. Cliquer sur "Compare"
6. Regshot affiche toutes les différences :
   - Clés ajoutées
   - Clés modifiées
   - Clés supprimées
   - Fichiers créés/modifiés/supprimés
```

---

## 6. Monitoring réseau

### 6.1 Wireshark

**Wireshark** est l'outil de référence pour la capture et l'analyse du trafic réseau. Pendant l'analyse dynamique, Wireshark capture tout le trafic généré par le malware.

**Filtres utiles pour l'analyse de malware :**

| Filtre Wireshark | Description |
|------------------|-------------|
| `dns` | Voir toutes les requêtes DNS (domaines que le malware tente de résoudre) |
| `http` | Voir le trafic HTTP (communication C2 non chiffrée) |
| `http.request` | Voir uniquement les requêtes HTTP (plus lisible) |
| `tcp.port == 443` | Trafic HTTPS (C2 chiffré - on ne verra que les métadonnées) |
| `tcp.port == 4444` | Port courant de reverse shell (Metasploit) |
| `ip.addr == 192.168.100.10` | Trafic de la VM FlareVM |
| `dns.qry.name contains "evil"` | Requêtes DNS contenant un mot spécifique |
| `http.request.uri contains "gate"` | URLs contenant "gate" (portails C2 courants) |
| `tcp.flags.syn == 1 and tcp.flags.ack == 0` | Nouvelles connexions TCP (SYN) |
| `!(arp or dns)` | Exclure ARP et DNS pour voir le reste du trafic |

**Que chercher dans le trafic réseau :**

| Pattern | Signification |
|---------|---------------|
| **Requêtes DNS vers des domaines suspects** | Le malware résout l'adresse de son serveur C2 |
| **Requêtes HTTP POST régulières** | Beaconing : le malware contacte son C2 à intervalles réguliers |
| **Données encodées en Base64 dans les requêtes** | Exfiltration de données ou commandes C2 |
| **Connexions vers des IPs sans résolution DNS** | Communication directe avec une IP (hard-coded C2) |
| **Trafic sur des ports non standard** | Le malware utilise un port inhabituel pour le C2 |
| **Requêtes DNS très longues (sous-domaines)** | DNS tunneling (exfiltration de données via DNS) |
| **Trafic ICMP inhabituel** | ICMP tunneling |

### 6.2 FakeNet-NG

**FakeNet-NG** intercepte et simule les connexions réseau du malware. Il redirige tout le trafic vers lui-même et répond avec des réponses génériques.

```bash
# Lancer FakeNet-NG sur FlareVM (ou REMnux)
fakenet

# FakeNet-NG va :
# - Intercepter toutes les requêtes DNS et répondre avec 127.0.0.1
# - Simuler un serveur HTTP/HTTPS
# - Simuler un serveur SMTP
# - Logger toutes les connexions et les données échangées
# - Sauvegarder les fichiers téléchargés/envoyés par le malware
```

**Avantages de FakeNet-NG :**

| Avantage | Description |
|----------|-------------|
| **Tout-en-un** | Simule DNS, HTTP, HTTPS, SMTP, FTP, IRC, etc. |
| **Log détaillé** | Enregistre toutes les communications avec les données |
| **Fichiers capturés** | Sauvegarde les fichiers téléchargés/uploadés par le malware |
| **Pas besoin de réseau** | Fonctionne en local, même sans réseau configuré |
| **Configurable** | Les réponses peuvent être personnalisées |

### 6.3 INetSim

**INetSim** (Internet Services Simulation Suite) offre une simulation plus complète des services Internet :

```bash
# Sur REMnux, lancer INetSim
sudo inetsim

# Services simulés :
# - DNS (port 53)
# - HTTP (port 80)
# - HTTPS (port 443)
# - SMTP (port 25)
# - POP3 (port 110)
# - FTP (port 21)
# - TFTP (port 69)
# - IRC (port 6667)
# - NTP (port 123)

# Les logs sont enregistrés dans /var/log/inetsim/
# Les fichiers servis sont dans /var/lib/inetsim/
```

### 6.4 Beaconing : détection des communications C2

Le **beaconing** est un pattern de communication où le malware contacte son serveur C2 à intervalles réguliers (toutes les 30 secondes, toutes les 5 minutes, etc.).

**Comment détecter le beaconing dans Wireshark :**

```
1. Filtrer le trafic HTTP : http.request
2. Trier par Time (colonne temporelle)
3. Chercher des requêtes vers le même domaine/IP à intervalles réguliers
4. Exemple : des POST vers http://evil.com/gate.php toutes les 60 secondes

Caractéristiques typiques du beaconing :
- Intervalles réguliers (avec parfois un jitter / variation aléatoire)
- Même URL ou endpoint
- Données POST encodées (Base64, XOR, chiffrement custom)
- User-Agent inhabituel ou générique
```

---

## 7. Analyse de la mémoire

### 7.1 Volatility

**Volatility** est le framework de référence pour la forensique mémoire. Il permet d'analyser un dump mémoire (capture de la RAM) pour extraire des informations sur les processus, les connexions réseau, les DLLs chargées et les artefacts malveillants.

**Créer un dump mémoire :**

```bash
# Depuis VirtualBox : Machine > Take Snapshot (inclut la mémoire si coché)
# Le fichier .sav contient le dump mémoire

# Depuis VMware : le fichier .vmem contient la mémoire

# Avec un outil dédié dans la VM :
# - WinPmem (Windows) : winpmem_mini_x64.exe output.raw
# - LiME (Linux) : insmod lime.ko "path=/tmp/memdump.raw format=raw"
```

**Commandes Volatility essentielles :**

```bash
# Identifier le profil du système (Volatility 2)
volatility -f memdump.raw imageinfo

# Lister les processus
volatility -f memdump.raw --profile=Win10x64_19041 pslist

# Afficher l'arbre des processus (parent/enfant)
volatility -f memdump.raw --profile=Win10x64_19041 pstree

# Détecter les processus cachés
volatility -f memdump.raw --profile=Win10x64_19041 psxview

# Détecter les injections de code en mémoire
volatility -f memdump.raw --profile=Win10x64_19041 malfind

# Lister les connexions réseau
volatility -f memdump.raw --profile=Win10x64_19041 netscan

# Lister les DLLs chargées par un processus
volatility -f memdump.raw --profile=Win10x64_19041 dlllist -p 1234

# Dumper un processus suspect pour analyse statique
volatility -f memdump.raw --profile=Win10x64_19041 procdump -p 1234 -D output/

# Dumper la mémoire d'un processus
volatility -f memdump.raw --profile=Win10x64_19041 memdump -p 1234 -D output/

# Extraire les hashes de mots de passe
volatility -f memdump.raw --profile=Win10x64_19041 hashdump

# Lister les clés de registre
volatility -f memdump.raw --profile=Win10x64_19041 printkey -K "Software\Microsoft\Windows\CurrentVersion\Run"
```

**Volatility 3 (version récente) :**

```bash
# Volatility 3 utilise une syntaxe différente (pas de profil)
vol -f memdump.raw windows.pslist
vol -f memdump.raw windows.pstree
vol -f memdump.raw windows.malfind
vol -f memdump.raw windows.netscan
vol -f memdump.raw windows.dlllist --pid 1234
```

**Tableau des plugins Volatility les plus utiles :**

| Plugin | Description | Usage en analyse de malware |
|--------|-------------|------------------------------|
| `pslist` / `pstree` | Liste les processus | Identifier le processus malveillant |
| `psxview` | Compare différentes sources de processus | Détecter les processus cachés (rootkit) |
| `malfind` | Détecte les injections de code | Trouver du code injecté en mémoire |
| `netscan` | Liste les connexions réseau | Identifier les communications C2 |
| `dlllist` | Liste les DLLs par processus | Identifier les DLLs malveillantes |
| `handles` | Liste les handles (fichiers, registre, mutex) | Identifier les ressources utilisées |
| `cmdline` | Affiche la ligne de commande des processus | Voir les arguments de lancement |
| `procdump` | Dump un exécutable depuis la mémoire | Récupérer le malware dépacké en mémoire |
| `memdump` | Dump la mémoire d'un processus | Extraire des chaînes, des clés, des configs |
| `filescan` | Scanne les fichiers en mémoire | Trouver des fichiers ouverts par le malware |

### 7.2 Cas d'usage : récupérer un malware dépacké

Un des usages les plus puissants de Volatility pour l'analyse de malware est de **récupérer le code dépacké en mémoire**. Quand un malware packé s'exécute, il se décompresse en mémoire. Volatility permet de capturer cette version décompressée :

```bash
# 1. Exécuter le malware packé dans la VM
# 2. Attendre qu'il soit complètement dépacké (quelques secondes)
# 3. Prendre un dump mémoire
# 4. Identifier le PID du malware
vol -f memdump.raw windows.pslist | grep sample

# 5. Dumper l'exécutable dépacké
vol -f memdump.raw windows.procdump --pid 1234 --dump-dir output/

# 6. Analyser statiquement le fichier dépacké
strings output/pid.1234.exe
# Les strings sont maintenant lisibles (elles étaient masquées par le packing)
```

---

## 8. Techniques d'évasion de sandbox (anti-analysis)

Les malwares modernes intègrent des techniques pour détecter s'ils sont analysés dans un environnement contrôlé. Si une sandbox est détectée, le malware peut modifier son comportement ou simplement ne rien faire.

### 8.1 Techniques de détection

| Technique | Méthode | Exemple de code |
|-----------|---------|-----------------|
| **Détection de VM** | Vérification des clés de registre VMware/VirtualBox | `reg query "HKLM\SOFTWARE\VMware, Inc."` |
| **Détection de VM** | Vérification de l'adresse MAC (préfixe constructeur VM) | MAC commençant par `00:0C:29` (VMware), `08:00:27` (VBox) |
| **Détection de VM** | Instruction CPUID (hypervisor bit) | Le bit 31 du registre ECX indique la présence d'un hyperviseur |
| **Détection de VM** | Fichiers et services spécifiques | `vmtoolsd.exe`, `VBoxService.exe`, `vmhgfs.sys` |
| **Détection de debugging** | API `IsDebuggerPresent()` | Retourne TRUE si un débogueur est attaché |
| **Détection de debugging** | Timing checks (RDTSC) | L'exécution sous débogueur est plus lente |
| **Détection de debugging** | `NtQueryInformationProcess` | Vérifie le flag `DebugPort` du processus |
| **Sleep/delay** | Appel à `Sleep()` avec une longue durée | `Sleep(600000)` - attend 10 minutes avant d'agir |
| **Interaction utilisateur** | Vérification du mouvement de souris | `GetCursorPos()` appelé deux fois avec un délai |
| **Interaction utilisateur** | Nombre de fichiers sur le Bureau | Un Bureau vide = probable sandbox |
| **Interaction utilisateur** | Nombre de processus en cours | Peu de processus = probable sandbox |
| **Vérification de l'environnement** | Nom d'utilisateur | `malware`, `sandbox`, `analyst` = noms suspects |
| **Vérification de l'environnement** | Nom de machine | `WIN-ABC123` (nom générique) = probable VM |
| **Vérification de l'environnement** | Taille du disque | Disque < 60 Go = probable VM |
| **Vérification de l'environnement** | RAM installée | RAM < 4 Go = probable VM |
| **Vérification de l'environnement** | Résolution d'écran | Résolution basse ou non standard = sandbox |

### 8.2 Contre-mesures

| Technique d'évasion | Contre-mesure |
|---------------------|---------------|
| Détection de fichiers/services VM | Supprimer ou renommer les fichiers/services (VMware Tools, etc.) |
| Vérification MAC address | Changer la MAC address de la VM |
| Vérification du nom d'utilisateur | Utiliser un nom réaliste (`Jean.Dupont`, `jdupont`) |
| Vérification du nom de machine | Renommer la machine (`DESKTOP-A3K9F2`, `PC-COMPTA-03`) |
| Vérification du nombre de fichiers | Ajouter des fichiers réalistes sur le Bureau et dans Mes Documents |
| Vérification du disque/RAM | Allouer suffisamment de ressources (60 Go+, 4 Go+ RAM) |
| Vérification de la résolution | Configurer une résolution standard (1920x1080) |
| Sleep/delay | Utiliser des outils pour accélérer le temps (modifier `Sleep()` via hook) |
| Vérification de la souris | Utiliser un script qui simule le mouvement de souris |
| Vérification de processus | Lancer des applications légitimes (navigateur, Office, etc.) |

> **Astuce** : l'outil **al-khaser** (github.com/LordNoteworthy/al-khaser) regroupe une multitude de techniques anti-VM/anti-debug. Vous pouvez l'exécuter dans votre lab pour vérifier quelles techniques de détection votre environnement est vulnérable.

---

## 9. Workflow d'analyse dynamique complet

Voici le workflow recommandé, étape par étape :

| Étape | Action | Détail |
|-------|--------|--------|
| **1. Snapshot** | Prendre un snapshot de la VM propre | Nommer avec la date et un identifiant |
| **2. Lancer le monitoring** | Démarrer tous les outils de surveillance | ProcMon, Process Explorer, Wireshark, FakeNet-NG/INetSim |
| **3. Configurer les filtres** | Préparer ProcMon avec les filtres appropriés | Filtrer sur le nom du sample |
| **4. Exécuter le sample** | Lancer le malware | Double-clic, ou `cmd /c sample.exe` pour voir la sortie console |
| **5. Observer** | Surveiller pendant 5 à 15 minutes | Certains malwares ont un délai avant de s'activer |
| **6. Interagir** | Simuler l'activité utilisateur si nécessaire | Bouger la souris, ouvrir des applications |
| **7. Collecter** | Sauvegarder tous les artefacts | Logs ProcMon (.pml), capture Wireshark (.pcap), screenshots |
| **8. Dump mémoire** | Capturer la RAM de la VM | Pour analyse ultérieure avec Volatility |
| **9. Analyser** | Examiner les données collectées | Identifier les IOCs, le comportement, les TTPs |
| **10. Documenter** | Rédiger un rapport d'analyse | Résumer les findings, lister les IOCs |
| **11. Restaurer** | Revenir au snapshot propre | Ne jamais réutiliser une VM post-infection |

### Exemple pratique : chronologie d'une analyse

```
[00:00] - Snapshot pris, outils lancés
[00:01] - Exécution de sample_001.exe
[00:01] - ProcMon : sample_001.exe crée C:\Users\user\AppData\Local\Temp\update.exe
[00:01] - ProcMon : sample_001.exe modifie HKCU\...\Run avec "update.exe"
[00:02] - Wireshark : requête DNS pour "c2-server.evil.com"
[00:02] - Wireshark : connexion HTTP POST vers 192.168.100.1 (INetSim)
         → User-Agent: Mozilla/4.0 (compatible)
         → Body: Base64 encoded data
[00:03] - Process Explorer : sample_001.exe lance cmd.exe /c update.exe
[00:03] - ProcMon : update.exe se copie dans C:\ProgramData\Microsoft\update.exe
[00:05] - Wireshark : beaconing toutes les 60 secondes vers le même endpoint
[00:10] - Fin de l'observation, collecte des artefacts
[00:12] - Dump mémoire pris
[00:15] - Restauration du snapshot
```

---

## 10. Sandbox en ligne

Pour une analyse rapide ou complémentaire, les sandbox en ligne permettent de soumettre un sample et d'obtenir un rapport automatique.

| Sandbox | URL | Type | Gratuit | Points forts | Limites |
|---------|-----|------|---------|-------------|---------|
| **ANY.RUN** | [any.run](https://any.run) | Interactive | Version limitée | Interaction en temps réel, visualisation du comportement, enregistrement vidéo | 1 analyse/jour en gratuit, durée limitée |
| **Hybrid Analysis** | [hybrid-analysis.com](https://www.hybrid-analysis.com) | Automatique | Oui | Basé sur Falcon Sandbox (CrowdStrike), rapports détaillés, extraction IOCs | Pas d'interaction, file d'attente |
| **Joe Sandbox** | [joesandbox.com](https://www.joesandbox.com) | Automatique | Version limitée | Rapports très complets, détection comportementale avancée | Version gratuite très limitée |
| **VirusTotal** | [virustotal.com](https://www.virustotal.com) | Multi-AV + sandbox | Oui | 70+ moteurs antivirus, sandbox basique | Analyse sandbox superficielle |
| **Triage** | [tria.ge](https://tria.ge) | Automatique | Oui | Rapide, extraction d'IOCs, API | Moins détaillé que Joe Sandbox |
| **Intezer Analyze** | [analyze.intezer.com](https://analyze.intezer.com) | Automatique | Version limitée | Analyse de code génétique (similitudes avec des malwares connus) | Orienté classification |

> **Rappel** : lorsque vous soumettez un sample à une sandbox en ligne, il peut devenir public. Ne soumettez jamais de fichiers contenant des données sensibles de votre organisation ou des samples issus d'une investigation confidentielle.

---

## Glossaire des sigles et définitions

| Sigle/Terme | Définition |
|-------------|------------|
| **ProcMon** | Process Monitor - Outil Sysinternals de monitoring des processus |
| **Sysinternals** | Suite d'outils d'administration et de diagnostic Windows par Mark Russinovich (Microsoft) |
| **Beaconing** | Pattern de communication où le malware contacte son C2 à intervalles réguliers |
| **C2** | Command and Control - Serveur de commande de l'attaquant |
| **Sandbox** | Environnement isolé pour l'exécution sécurisée de code suspect |
| **Volatility** | Framework open source de forensique mémoire |
| **FakeNet-NG** | Outil de simulation réseau pour l'analyse dynamique |
| **INetSim** | Internet Services Simulation Suite - Simulateur de services Internet |
| **IOC** | Indicator of Compromise - Indicateur de compromission |
| **TTP** | Tactics, Techniques and Procedures - Méthodes d'attaque |
| **Anti-analysis** | Ensemble de techniques utilisées par les malwares pour détecter et échapper à l'analyse |
| **Dropper** | Malware dont le rôle est de déposer et exécuter un payload secondaire |
| **Payload** | Charge utile - Le code malveillant principal |
| **Jitter** | Variation aléatoire ajoutée aux intervalles de beaconing pour éviter la détection |
| **RDTSC** | Read Time-Stamp Counter - Instruction CPU utilisée pour les timing checks |
| **Process Hollowing** | Technique d'injection : vider un processus légitime pour y injecter du code malveillant |
| **DLL Injection** | Technique d'injection : charger une DLL malveillante dans un processus légitime |
| **DNS Tunneling** | Technique d'exfiltration de données en les encodant dans les requêtes DNS |
| **Dump mémoire** | Capture complète du contenu de la RAM à un instant donné |

---

## Récapitulatif des commandes

| Commande | Système | Description |
|----------|---------|-------------|
| `procmon.exe` | Windows | Lancer Process Monitor |
| `procexp.exe` | Windows | Lancer Process Explorer |
| `fakenet` | Windows/Linux | Lancer FakeNet-NG |
| `sudo inetsim` | Linux | Lancer INetSim |
| `wireshark` | Windows/Linux | Lancer Wireshark |
| `volatility -f dump.raw imageinfo` | Linux | Identifier le profil du dump mémoire (Vol2) |
| `vol -f dump.raw windows.pslist` | Linux | Lister les processus (Vol3) |
| `vol -f dump.raw windows.pstree` | Linux | Afficher l'arbre des processus (Vol3) |
| `vol -f dump.raw windows.malfind` | Linux | Détecter les injections en mémoire (Vol3) |
| `vol -f dump.raw windows.netscan` | Linux | Lister les connexions réseau (Vol3) |
| `vol -f dump.raw windows.dlllist --pid N` | Linux | Lister les DLLs d'un processus (Vol3) |
| `vol -f dump.raw windows.procdump --pid N --dump-dir out/` | Linux | Dumper un processus (Vol3) |
| `vol -f dump.raw windows.cmdline` | Linux | Voir les lignes de commande des processus (Vol3) |
| `winpmem_mini_x64.exe output.raw` | Windows | Créer un dump mémoire de la machine |

---

## Ressources pratiques - TryHackMe / HackTheBox

| Plateforme | Room/Lab | Description |
|------------|----------|-------------|
| TryHackMe | [Basic Dynamic Analysis](https://tryhackme.com/room/dvdynamicanalysis1) | Exercices pratiques d'analyse dynamique |
| TryHackMe | [Volatility](https://tryhackme.com/room/dvbvolatility) | Analyse forensique de dumps mémoire avec Volatility |
| HackTheBox | [Sherlock - Tracer](https://app.hackthebox.com/sherlocks/Tracer) | Investigation impliquant l'analyse dynamique d'un malware |

---

## Ressources

- Practical Malware Analysis - Michael Sikorski & Andrew Honig (chapitres 3, 5-8)
- The Art of Memory Forensics - Michael Hale Ligh et al.
- Volatility Foundation : [volatilityfoundation.org](https://www.volatilityfoundation.org)
- Volatility 3 - GitHub : [github.com/volatilityfoundation/volatility3](https://github.com/volatilityfoundation/volatility3)
- Sysinternals Suite : [learn.microsoft.com/sysinternals](https://learn.microsoft.com/en-us/sysinternals/)
- FakeNet-NG - GitHub : [github.com/mandiant/flare-fakenet-ng](https://github.com/mandiant/flare-fakenet-ng)
- INetSim : [inetsim.org](https://www.inetsim.org)
- ANY.RUN : [any.run](https://any.run)
- al-khaser (anti-VM/anti-debug testing) : [github.com/LordNoteworthy/al-khaser](https://github.com/LordNoteworthy/al-khaser)
