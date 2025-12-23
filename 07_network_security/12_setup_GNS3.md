# Configuration de GNS3

## Objectifs du cours

GNS3 (Graphical Network Simulator-3) est un outil de simulation réseau qui permet de concevoir, tester et simuler des réseaux complexes. Le client GNS3 peut être installé sur votre machine locale et connecté à un serveur distant pour effectuer des simulations exploitant des ressources et des images plus puissantes.

Compétences visées :
- Installer le client GNS3 sur différents systèmes d'exploitation
- Configurer une connexion VPN WireGuard
- Connecter le client GNS3 à un serveur distant
- Créer et gérer des projets de simulation réseau

---

## Glossaire

| Terme | Description |
|-------|-------------|
| **GNS3** | Graphical Network Simulator-3 - Simulateur de réseau graphique |
| **Client GNS3** | Application installée localement pour concevoir les topologies |
| **Serveur GNS3** | Machine distante exécutant les simulations réseau |
| **VPN** | Virtual Private Network - Tunnel sécurisé entre machines |
| **WireGuard** | Protocole VPN moderne et performant |
| **Topologie** | Représentation graphique de l'architecture réseau |
| **IOU** | IOS on Unix - Image Cisco pour simulation |

---

## Étape 1 : Installation du client GNS3

### Windows

1. Télécharger l'installateur version 2.2.54 depuis le site officiel
2. Exécuter l'installateur et suivre les instructions :
   - Accepter les termes de la licence
   - Sélectionner les composants (GNS3, Wireshark, etc.)
   - Choisir le répertoire d'installation
3. Lancer GNS3 une fois l'installation terminée

### macOS

1. Télécharger GNS3 version 2.2.54
2. Glisser l'application dans le dossier Applications
3. Au premier lancement :
   - Clic droit sur l'application → Ouvrir
   - Autoriser l'application dans Préférences Système → Sécurité

### Linux (Ubuntu/Debian)

1. Installer pipx :

```bash
sudo apt update
sudo apt install pipx
```

2. Installer le client GNS3 :

```bash
pipx install "gns3-gui==2.2.54"
pipx inject gns3-gui PyQt5
pipx ensurepath
source ~/.bashrc
```

3. Lancer GNS3 :

```bash
gns3
```

4. Si erreur PyQt5, installer les dépendances manquantes :

```bash
sudo apt install libxcb-xinerama0 libxcb-cursor0 libxkbcommon-x11-0 \
    libxcb-icccm4 libxcb-image0 libxcb-keysyms1 libxcb-randr0 \
    libxcb-render-util0 libxcb-shape0
```

5. Configuration initiale :
   - Au démarrage, une erreur indique qu'aucun serveur local n'est trouvé
   - Fermer les messages d'erreur
   - Sélectionner "Remote server" dans la fenêtre contextuelle

---

## Étape 2 : Configuration du VPN WireGuard

### Obtention de la configuration VPN

Le VPN est nécessaire pour accéder au serveur GNS3 distant.

1. Accéder au lab sur la plateforme Jedha
2. Cliquer sur "Get your VPN conf"
3. Télécharger le fichier de configuration `.conf` généré

### Installation de WireGuard

#### Windows

1. Télécharger WireGuard depuis le site officiel
2. Installer l'application
3. Importer la configuration :
   - Ouvrir WireGuard
   - Cliquer sur "Import tunnel(s) from file"
   - Sélectionner le fichier `.conf`
4. Activer le VPN :
   - Cliquer sur "Activate"
   - L'icône devient verte une fois connecté

#### macOS

1. Installer WireGuard depuis l'App Store
2. Importer la configuration :
   - Ouvrir WireGuard
   - Cliquer sur "Import tunnel(s) from file"
   - Sélectionner le fichier de configuration
3. Activer le VPN :
   - Cliquer sur "Activate"
   - Autoriser la création du VPN si demandé

#### Linux (Ubuntu/Debian)

1. Installer WireGuard :

```bash
sudo apt update
sudo apt install wireguard
```

2. Copier la configuration :

```bash
sudo cp <fichier_config.conf> /etc/wireguard/
```

3. Activer le VPN :

```bash
# Remplacer <nom_config> par le nom du fichier sans .conf
sudo wg-quick up <nom_config>

# Exemple : si le fichier est jedha_vpn.conf
sudo wg-quick up jedha_vpn
```

4. Vérifier la connexion :

```bash
sudo wg show
```

5. Désactiver le VPN (quand nécessaire) :

```bash
sudo wg-quick down <nom_config>
```

---

## Étape 3 : Connexion au serveur GNS3 distant

### Démarrage du serveur

1. Sur la plateforme Jedha, démarrer le lab GNS3
2. Attendre que l'environnement soit prêt
3. Noter l'adresse IP du serveur distant affichée

**Important :** À l'arrêt du lab, tous les projets et configurations sont perdus. Le serveur GNS3 est détruit et recréé. Il est nécessaire d'exporter les projets avant l'arrêt.

### Configuration de la connexion

1. Lancer le client GNS3
2. Accéder aux préférences :
   - Menu Edit → Preferences
3. Configurer le serveur principal :
   - Sélectionner Server → Main Server
   - Renseigner :
     - Host : adresse IP du serveur distant
     - Port : 80
   - Les identifiants sont généralement remplis automatiquement
4. Appliquer la configuration :
   - Cliquer sur Apply
   - Le statut devient vert si la connexion réussit

### Dépannage

| Symptôme | Solution |
|----------|----------|
| Connexion refusée | Vérifier que le VPN est actif |
| Timeout | Vérifier l'adresse IP du serveur |
| Échec d'authentification | Vérifier les identifiants |
| Serveur introuvable | Redémarrer le lab |

---

## Étape 4 : Utilisation de GNS3

### Création d'un projet

1. Menu File → New blank project
2. Nommer le projet
3. Cliquer sur Create

### Interface

L'interface GNS3 comprend trois zones principales :

- **Panneau de périphériques** (gauche) : Liste des équipements disponibles
- **Zone de travail** (centre) : Création de la topologie
- **Console** (droite) : Accès aux consoles des équipements

### Ajout d'équipements

1. Glisser-déposer depuis le panneau de gauche :
   - Router : pour le routage inter-réseaux
   - Switch : pour connecter des machines sur un même réseau
   - PC/Host : pour simuler des machines clientes
   - Cloud : pour connecter au réseau physique

2. Connexion des équipements :
   - Cliquer sur l'icône Link
   - Sélectionner le premier équipement puis le second
   - Choisir les interfaces à connecter

3. Démarrage :
   - Clic droit → Start
   - Ou bouton Play pour tout démarrer

4. Accès console :
   - Double-clic sur un équipement
   - La console s'ouvre pour la configuration

### Sauvegarde et export

**Sauvegarde :**
- Menu File → Save project

**Export :**
1. Menu File → Export portable project
2. Choisir l'emplacement sur la machine locale
3. Le projet est exporté en fichier `.gns3project`

**Import :**
1. Menu File → Import portable project
2. Sélectionner le fichier `.gns3project`

---

## Exemple de topologie simple

Configuration d'un réseau avec deux PCs connectés par un switch :

```
┌─────┐         ┌────────┐         ┌─────┐
│ PC1 │─────────│ Switch │─────────│ PC2 │
└─────┘         └────────┘         └─────┘
192.168.1.10/24                    192.168.1.20/24
```

**Configuration PC1 :**
```bash
ip 192.168.1.10/24 192.168.1.1
```

**Configuration PC2 :**
```bash
ip 192.168.1.20/24 192.168.1.1
```

**Test de connectivité :**
```bash
ping 192.168.1.20
```

---

## Ressources

- Documentation officielle GNS3 : [docs.gns3.com](https://docs.gns3.com/)
- Guide de démarrage : [Getting Started](https://docs.gns3.com/docs/)
- Forum communautaire : [gns3.com/community](https://www.gns3.com/community)
