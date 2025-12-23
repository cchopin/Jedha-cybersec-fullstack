# Configuration de l'environnement GNS3

## Objectifs du cours

GNS3 (Graphical Network Simulator-3) est un simulateur de réseau professionnel qui permet de concevoir, tester et simuler des architectures réseau complexes. C'est un outil indispensable pour :

- Pratiquer la configuration de routeurs et switches
- Tester des architectures réseau avant déploiement
- S'entraîner pour les certifications (CCNA, CCNP, etc.)
- Reproduire des environnements de production pour du pentesting

Ce cours couvre :
1. Installation du client GNS3
2. Configuration de la connexion VPN WireGuard
3. Connexion au serveur GNS3 distant
4. Création d'un premier projet réseau

---

## Glossaire

| Terme | Description |
|-------|-------------|
| **GNS3** | Graphical Network Simulator-3 - Simulateur de réseau graphique |
| **Client GNS3** | Application installée sur la machine locale pour concevoir les topologies |
| **Serveur GNS3** | Machine distante qui exécute les simulations (routeurs, switches virtuels) |
| **VPN** | Virtual Private Network - Tunnel sécurisé entre la machine locale et le serveur |
| **WireGuard** | Protocole VPN moderne, rapide et sécurisé |
| **Topologie** | Représentation graphique de l'architecture d'un réseau |
| **Image** | Système d'exploitation virtuel pour les équipements réseau (IOS Cisco, etc.) |

---

## Étape 1 : Installation du client GNS3

### Pour Windows

1. **Télécharger l'installateur** (version 2.2.54) depuis le site officiel :
   - [Télécharger GNS3 pour Windows](https://www.gns3.com/software/download)

2. **Exécuter l'installateur** et suivre les instructions :
   - Accepter les termes de la licence
   - Choisir les composants à installer :
     - **GNS3** (obligatoire)
     - **Wireshark** (recommandé pour l'analyse de trafic)
     - **Npcap** (pour la capture de paquets)
   - Sélectionner le répertoire d'installation
   - Cliquer sur **Install**

3. **Lancer GNS3** une fois l'installation terminée

### Pour macOS

1. **Télécharger** l'application GNS3 version 2.2.54 depuis le site officiel

2. **Installer** en faisant glisser l'application dans le dossier Applications

3. **Première exécution** :
   - Clic droit sur l'application → Ouvrir (pour contourner la sécurité macOS)
   - Autoriser l'application dans Préférences Système → Sécurité

### Pour Linux (Ubuntu/Debian)

1. **Installer pipx** si ce n'est pas déjà fait :

```bash
sudo apt update
sudo apt install pipx
```

2. **Installer le client GNS3** :

```bash
pipx install "gns3-gui==2.2.54"
pipx inject gns3-gui PyQt5
pipx ensurepath
source ~/.bashrc
```

3. **Lancer GNS3** :

```bash
gns3
```

4. **En cas d'erreur PyQt5** ("Fatal Python error: Aborted"), installer les dépendances :

```bash
sudo apt install libxcb-xinerama0 libxcb-cursor0 libxkbcommon-x11-0 \
    libxcb-icccm4 libxcb-image0 libxcb-keysyms1 libxcb-randr0 \
    libxcb-render-util0 libxcb-shape0
```

5. **Configuration du serveur distant** :
   - Comme nous n'avons pas installé de serveur local, une erreur s'affichera
   - Fermer les messages d'erreur
   - Choisir "**Remote server**" dans la fenêtre popup

---

## Étape 2 : Configuration du VPN WireGuard

Le VPN est nécessaire pour établir une connexion sécurisée avec le serveur GNS3 distant.

### Obtenir la configuration VPN

1. Dans le composant Lab, cliquer sur **"Get your VPN conf"**
2. Une page s'ouvre pour générer le fichier de configuration
3. Télécharger le fichier `.conf` généré

### Installation de WireGuard

#### Pour Windows

1. **Télécharger WireGuard** :
   - Aller sur [wireguard.com/install](https://www.wireguard.com/install/)
   - Télécharger l'installateur Windows
   - Exécuter et suivre les instructions

2. **Importer la configuration** :
   - Ouvrir WireGuard depuis le menu Démarrer
   - Cliquer sur **"Import tunnel(s) from file"**
   - Sélectionner le fichier `.conf` téléchargé

3. **Activer le VPN** :
   - Cliquer sur **"Activate"** à côté de la configuration
   - L'icône dans la barre des tâches devient verte quand connecté

#### Pour macOS

1. **Installer WireGuard** depuis l'App Store :
   - Rechercher "WireGuard" dans l'App Store
   - Installer l'application

2. **Importer la configuration** :
   - Ouvrir WireGuard
   - Cliquer sur **"Import tunnel(s) from file"**
   - Sélectionner le fichier de configuration téléchargé

3. **Activer le VPN** :
   - Cliquer sur **"Activate"**
   - Autoriser la création du VPN si demandé

#### Pour Linux (Ubuntu/Debian)

1. **Installer WireGuard** :

```bash
sudo apt update
sudo apt install wireguard
```

2. **Copier la configuration** :

```bash
sudo cp votre_config.conf /etc/wireguard/
```

3. **Activer le VPN** :

```bash
# Remplacer "votre_config" par le nom du fichier (sans .conf)
sudo wg-quick up votre_config

# Exemple : si le fichier est "jedha_vpn.conf"
sudo wg-quick up jedha_vpn
```

4. **Vérifier la connexion** :

```bash
sudo wg show
```

5. **Désactiver le VPN** (quand terminé) :

```bash
sudo wg-quick down votre_config
```

### Vérification de la connexion VPN

Une fois le VPN actif, vérifier que le serveur est accessible :

```bash
# Remplacer par l'IP du serveur GNS3
ping <IP_DU_SERVEUR>
```

---

## Étape 3 : Connexion au serveur GNS3 distant

### Démarrer le serveur distant

1. Dans le composant Lab, cliquer sur **"Start Lab"**
2. Attendre que l'environnement soit prêt
3. **Noter l'adresse IP** du serveur distant affichée

### Configurer la connexion dans GNS3

1. **Lancer le client GNS3** sur la machine locale

2. **Accéder aux préférences** :
   - Menu **Edit** → **Preferences** (ou Ctrl+Shift+P)

3. **Configurer le serveur principal** :
   - Dans le panneau de gauche, sélectionner **Server** → **Main Server**
   - Remplir les champs :
     - **Host** : `<IP_DU_SERVEUR>`
     - **Port** : `80`
     - L'utilisateur et le mot de passe sont généralement remplis automatiquement

4. **Appliquer et tester** :
   - Cliquer sur **Apply**
   - Le statut devrait passer au vert si la connexion est réussie

### Dépannage de la connexion

| Problème | Solution |
|----------|----------|
| Connexion refusée | Vérifier que le VPN est actif |
| Timeout | Vérifier l'IP du serveur |
| Authentification échouée | Vérifier les credentials dans les préférences |
| Serveur non trouvé | Redémarrer le lab |

---

## Étape 4 : Création d'un premier projet

### Créer un nouveau projet

1. Menu **File** → **New blank project**
2. Donner un nom au projet (ex: "Lab_Subnetting")
3. Sélectionner **Create**

### Interface GNS3

L'interface GNS3 est composée de plusieurs zones :

```
┌──────────────────────────────────────────────────────────┐
│  Menu Bar                                                │
├──────────┬───────────────────────────────────┬──────────┤
│          │                                   │          │
│  Device  │       Workspace                   │  Console │
│  Panel   │       (Zone de travail)           │  Panel   │
│          │                                   │          │
│          │                                   │          │
└──────────┴───────────────────────────────────┴──────────┘
```

- **Device Panel** (gauche) : Liste des équipements disponibles
- **Workspace** (centre) : Zone de création de la topologie
- **Console Panel** (droite) : Affiche les consoles des équipements

### Ajouter des équipements

1. **Glisser-déposer** un équipement depuis le panel de gauche vers le workspace :
   - **Router** : Pour le routage entre réseaux
   - **Switch** : Pour connecter des machines sur un même réseau
   - **PC/Host** : Pour simuler des machines clientes
   - **Cloud** : Pour connecter au réseau physique

2. **Connecter les équipements** :
   - Cliquer sur l'icône **Link** (câble) dans la toolbar
   - Cliquer sur le premier équipement, puis sur le second
   - Sélectionner les interfaces à connecter

3. **Démarrer les équipements** :
   - Clic droit sur un équipement → **Start**
   - Ou utiliser le bouton **Play** vert dans la toolbar pour tout démarrer

4. **Accéder à la console** :
   - Double-clic sur un équipement pour ouvrir sa console
   - La configuration peut alors être effectuée

### Exemple de topologie simple

Exemple de réseau avec 2 PCs connectés par un switch :

```
    ┌─────┐         ┌────────┐         ┌─────┐
    │ PC1 │─────────│ Switch │─────────│ PC2 │
    └─────┘         └────────┘         └─────┘

    192.168.1.10    VLAN 1            192.168.1.20
       /24                               /24
```

Configuration de PC1 :
```bash
# Dans la console de PC1
ip 192.168.1.10/24 192.168.1.1
```

Configuration de PC2 :
```bash
# Dans la console de PC2
ip 192.168.1.20/24 192.168.1.1
```

Test de connectivité :
```bash
# Depuis PC1
ping 192.168.1.20
```

---

## Sauvegarde et export des projets

### Sauvegarder régulièrement

Les projets sont sauvegardés automatiquement. Pour forcer une sauvegarde :
- Menu **File** → **Save project**

### Exporter un projet

Pour conserver le travail avant d'arrêter le lab :

1. Menu **File** → **Export portable project**
2. Choisir un emplacement sur la machine locale
3. Le projet sera exporté en fichier `.gns3project`

### Importer un projet

Pour reprendre un projet exporté :

1. Menu **File** → **Import portable project**
2. Sélectionner le fichier `.gns3project`
3. Le projet sera restauré avec toute sa configuration

---

## Avertissement important

```
+-----------------------------------------------------------+
|                                                           |
|   ATTENTION - SAUVEGARDE OBLIGATOIRE                      |
|                                                           |
|   A l'arret du lab :                                      |
|   - Tous les projets et configurations sont PERDUS        |
|   - Le serveur GNS3 est detruit et recree                 |
|   - TOUJOURS exporter les projets avant d'arreter         |
|                                                           |
+-----------------------------------------------------------+
```

---

## Bonnes pratiques

### Organisation des projets

1. **Nommer clairement** les projets (ex: "Lab_VLAN_Segmentation")
2. **Annoter** la topologie avec l'outil "Note" (N)
3. **Grouper** les équipements logiquement

### Performance

1. **Limiter le nombre d'équipements** actifs simultanément
2. **Démarrer** uniquement les équipements nécessaires
3. **Arrêter** les équipements inutilisés

### Documentation

1. **Documenter** les configurations dans des notes
2. **Exporter** régulièrement le travail
3. **Sauvegarder** les fichiers de configuration (running-config)

---

## Ressources

| Ressource | Lien |
|-----------|------|
| Documentation officielle GNS3 | [docs.gns3.com](https://docs.gns3.com/) |
| Guide de démarrage | [Getting Started](https://docs.gns3.com/docs/) |
| Forum communautaire | [gns3.com/community](https://www.gns3.com/community) |
| Tutoriels vidéo | [GNS3 YouTube](https://www.youtube.com/c/GNS3) |

---

## Exercice pratique

### Objectif

Créer une topologie avec :
- 1 routeur
- 2 switches
- 4 PCs (2 par switch)
- 2 sous-réseaux différents

### Schéma cible

```
      Réseau A                           Réseau B
   192.168.1.0/24                     192.168.2.0/24

   ┌─────┐  ┌─────┐                  ┌─────┐  ┌─────┐
   │ PC1 │  │ PC2 │                  │ PC3 │  │ PC4 │
   └──┬──┘  └──┬──┘                  └──┬──┘  └──┬──┘
      │        │                        │        │
      └───┬────┘                        └───┬────┘
          │                                 │
     ┌────┴────┐                       ┌────┴────┐
     │ Switch1 │                       │ Switch2 │
     └────┬────┘                       └────┬────┘
          │           ┌────────┐            │
          └───────────│ Router │────────────┘
                      └────────┘
                      Fa0/0: 192.168.1.1
                      Fa0/1: 192.168.2.1
```

### Étapes

1. Créer la topologie dans GNS3
2. Configurer le routeur avec les deux interfaces
3. Configurer les PCs avec les bonnes IP et passerelles
4. Tester la connectivité entre les deux réseaux
5. Exporter le projet

Cet exercice permet de mettre en pratique les notions de subnetting vues dans les cours précédents.
