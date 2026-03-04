# Définitions clés

---

## Modèles de référence réseau

**Modèle OSI (Open Systems Interconnection)** : Modèle de référence en 7 couches (physique, liaison, réseau, transport, session, présentation, application) décrivant les fonctions d'un système de communication réseau. Chaque couche offre des services à la couche supérieure et utilise ceux de la couche inférieure.

**Modèle TCP/IP (Transmission Control Protocol / Internet Protocol)** : Modèle pratique en 4 couches (accès réseau, internet, transport, application) sur lequel repose l'internet. Simplification du modèle OSI.

**Encapsulation** : Mécanisme par lequel chaque couche ajoute son en-tête (et éventuellement un pied) aux données reçues de la couche supérieure avant de les transmettre à la couche inférieure.

**PDU (Protocol Data Unit)** : Unité de données propre à chaque couche OSI. Trame (couche 2), paquet (couche 3), segment (couche 4), message (couche application).

---

## Couche physique et liaison (L1/L2)

**MAC (Media Access Control)** : Adresse physique unique sur 48 bits identifiant une interface réseau. Utilisée pour les communications au sein d'un même segment réseau.

**Ethernet** : Standard de communication en réseau local définissant le câblage, le format des trames et les mécanismes d'accès au médium.

**Switch** : Equipement de couche 2 commutant les trames en fonction des adresses MAC. Maintient une table MAC pour diriger le trafic uniquement vers le port de destination.

**VLAN (Virtual Local Area Network)** : Segmentation logique d'un réseau physique au niveau de la couche 2. Isole le trafic entre groupes d'équipements, limitant la propagation latérale en cas de compromission. Configuré via 802.1Q (tag VLAN dans la trame).

**Trunk** : Lien entre équipements transportant le trafic de plusieurs VLANs simultanément, identifiés par leur tag 802.1Q.

**STP (Spanning Tree Protocol)** : Protocole évitant les boucles réseau en désactivant logiquement les liens redondants tout en maintenant la redondance physique.

**ARP (Address Resolution Protocol)** : Protocole résolvant une adresse IP en adresse MAC sur un réseau local. Cible d'attaques (ARP spoofing / ARP poisoning).

---

## Couche réseau (L3)

**Adresse IP (Internet Protocol)** : Identifiant logique d'une interface réseau. IPv4 sur 32 bits (notation décimale pointée), IPv6 sur 128 bits (notation hexadécimale).

**Sous-réseau (subnet)** : Division d'un espace d'adressage IP en blocs plus petits. Défini par un masque (ex : /24 = 255.255.255.0). Permet de structurer et segmenter un réseau.

**CIDR (Classless Inter-Domain Routing)** : Notation compacte d'un réseau IP sous la forme adresse/préfixe (ex : 192.168.1.0/24). Remplace le découpage classful (classes A/B/C).

**Routeur** : Equipement de couche 3 acheminant les paquets entre différents réseaux en fonction de leur adresse IP de destination et d'une table de routage.

**Table de routage** : Table associant des préfixes réseau à des interfaces de sortie ou des passerelles. Alimentée statiquement ou par des protocoles de routage dynamiques.

**Routage statique** : Routes configurées manuellement par un administrateur. Simple et prévisible, mais ne s'adapte pas aux pannes.

**Routage dynamique** : Routes apprises automatiquement via des protocoles (OSPF, BGP, EIGRP). S'adapte aux changements de topologie.

**OSPF (Open Shortest Path First)** : Protocole de routage interne (IGP) à état de lien. Calcule le plus court chemin via l'algorithme de Dijkstra. Converge rapidement, adapté aux réseaux d'entreprise.

**BGP (Border Gateway Protocol)** : Protocole de routage inter-domaines (EGP) utilisé sur internet pour échanger des routes entre systèmes autonomes (AS). Protocole de routage d'internet.

**NAT (Network Address Translation)** : Mécanisme traduisant des adresses IP privées en adresse publique au niveau du routeur/pare-feu. Permet de mutualiser une adresse publique et masque la topologie interne.

**ICMP (Internet Control Message Protocol)** : Protocole de couche 3 utilisé pour les messages de contrôle et d'erreur réseau (ping, traceroute, destination unreachable, TTL exceeded).

**TTL (Time To Live)** : Champ du paquet IP décrémenté à chaque saut. Quand il atteint 0, le paquet est abandonné et un message ICMP est renvoyé. Evite les boucles infinies.

---

## Couche transport (L4)

**TCP (Transmission Control Protocol)** : Protocole de transport orienté connexion, fiable, avec contrôle de flux et de congestion. Etablissement par handshake 3 voies (SYN, SYN-ACK, ACK). Utilisé quand la fiabilité prime sur la latence.

**UDP (User Datagram Protocol)** : Protocole de transport sans connexion, non fiable, sans garantie d'ordre ou de livraison. Faible latence, utilisé pour DNS, voix, vidéo, jeux en ligne.

**Port** : Identifiant numérique (0-65535) distinguant les services sur un même hôte. Ports bien connus (0-1023) réservés aux services standards (80/HTTP, 443/HTTPS, 22/SSH, 53/DNS).

**Socket** : Combinaison d'une adresse IP et d'un port identifiant un point de communication. Une connexion TCP est identifiée par le quadruplet (IP src, port src, IP dst, port dst).

**Handshake TCP** : Séquence d'établissement d'une connexion TCP en 3 étapes : SYN (client), SYN-ACK (serveur), ACK (client). La fermeture utilise FIN/ACK.

---

## Protocoles applicatifs

**DNS (Domain Name System)** : Protocole résolvant des noms de domaine en adresses IP (et inversement). Fonctionne en UDP/53 (et TCP/53 pour les grosses réponses). Architecture hiérarchique : résolveur, serveur récursif, serveurs racine, TLD, authoritative.

**DHCP (Dynamic Host Configuration Protocol)** : Protocole attribuant automatiquement des adresses IP et paramètres réseau (passerelle, DNS, masque) aux hôtes. Echange en 4 étapes : Discover, Offer, Request, Acknowledge.

**HTTP/HTTPS (HyperText Transfer Protocol / HTTP Secure)** : Protocole de transfert hypertexte. HTTPS = HTTP over TLS. Modèle requête/réponse sans état (stateless).

**SSH (Secure Shell)** : Protocole chiffré d'administration à distance remplaçant Telnet. Authentification par mot de passe ou clé asymétrique. Port 22.

**FTP / SFTP / FTPS (File Transfer Protocol / SSH File Transfer Protocol / FTP Secure)** : Protocoles de transfert de fichiers. FTP en clair (à éviter), SFTP via SSH, FTPS via TLS.

**SMTP / IMAP / POP3 (Simple Mail Transfer Protocol / Internet Message Access Protocol / Post Office Protocol 3)** : Protocoles de messagerie. SMTP pour l'envoi, IMAP pour l'accès synchronisé, POP3 pour le téléchargement local.

**SNMP (Simple Network Management Protocol)** : Protocole de supervision réseau permettant de collecter des métriques et de configurer des équipements à distance. SNMPv3 ajoute authentification et chiffrement.

**NTP (Network Time Protocol)** : Protocole de synchronisation d'horloge réseau. Essentiel pour la cohérence des journaux, l'authentification Kerberos et la validité des certificats.

**LDAP (Lightweight Directory Access Protocol)** : Protocole d'accès à un annuaire (ex : Active Directory). Utilisé pour l'authentification et la gestion des identités centralisée.

---

## Infrastructure réseau

**Pare-feu (firewall)** : Equipement ou logiciel filtrant le trafic réseau selon des règles définissant ce qui est autorisé ou bloqué. Peut être stateless, stateful, applicatif (L7), ou NGFW.

**Pare-feu stateful** : Pare-feu maintenant une table d'état des connexions. Autorise automatiquement le trafic de retour des connexions établies, contrairement au pare-feu stateless.

**NGFW (Next-Generation Firewall)** : Pare-feu combinant filtrage stateful, inspection applicative (L7), prévention d'intrusion (IPS) et identification des utilisateurs.

**DMZ (Demilitarized Zone)** : Zone réseau isolée entre le réseau interne et internet, hébergeant les services accessibles depuis l'extérieur tout en les séparant du SI interne.

**Proxy** : Intermédiaire entre un client et un serveur. Peut filtrer le contenu, mettre en cache, anonymiser ou inspecter le trafic. Le reverse proxy expose des serveurs internes vers l'extérieur.

**Load balancer** : Equipement répartissant le trafic entrant entre plusieurs serveurs backend pour assurer disponibilité et performance.

**IDS / IPS (Intrusion Detection System / Intrusion Prevention System)** : Systèmes de détection (IDS) ou de prévention (IPS) des intrusions. L'IDS analyse le trafic et alerte, l'IPS peut bloquer activement. Modes : signature, anomalie, comportemental.

**WAF (Web Application Firewall)** : Pare-feu applicatif filtrant le trafic HTTP/HTTPS pour protéger les applications web contre les attaques (injection SQL, XSS, etc.).

**Bastion** : Serveur durci servant de point d'entrée unique et contrôlé pour l'administration des systèmes d'une infrastructure. Réduit la surface d'attaque accessible de l'extérieur.

**VPN (Virtual Private Network)** : Tunnel chiffré établi sur un réseau non sûr permettant de relier des réseaux distants ou des utilisateurs à un réseau privé. Protocoles : IPsec, OpenVPN, WireGuard.

**IPsec (Internet Protocol Security)** : Suite de protocoles sécurisant les communications IP au niveau de la couche réseau (L3). Modes : transport (payload seul) et tunnel (paquet IP entier). Composants : AH (intégrité), ESP (confidentialité + intégrité), IKE (négociation des clés).

**QoS (Quality of Service)** : Mécanismes priorisant certains types de trafic (voix, vidéo) pour garantir leurs exigences de latence, gigue et bande passante.

**SD-WAN (Software-Defined Wide Area Network)** : Architecture de WAN pilotée par logiciel, découplant la gestion du réseau du matériel. Permet de gérer plusieurs liens WAN (MPLS, internet, 4G) de manière centralisée et dynamique.

---

## Administration système et infrastructure

**Active Directory (AD)** : Service d'annuaire Microsoft centralisant l'authentification, les autorisations et la gestion des politiques (GPO) dans un environnement Windows. Basé sur LDAP et Kerberos.

**GPO (Group Policy Object)** : Objets de stratégie de groupe appliquant des configurations et restrictions sur les machines et utilisateurs d'un domaine Active Directory.

**Kerberos** : Protocole d'authentification réseau basé sur des tickets. Le KDC (Key Distribution Center) émet un TGT (Ticket Granting Ticket), puis des tickets de service. Evite la transmission des mots de passe sur le réseau.

**RADIUS (Remote Authentication Dial-In User Service)** : Protocole AAA centralisé (authentification, autorisation, comptabilité). Utilisé pour les accès VPN, Wi-Fi 802.1X et équipements réseau.

**802.1X** : Standard IEEE d'authentification au niveau du port réseau. Impose une authentification avant l'accès au réseau (LAN ou Wi-Fi). S'appuie sur EAP (Extensible Authentication Protocol) et RADIUS.

**IPAM (IP Address Management)** : Outil de gestion centralisée des adresses IP, des plages DHCP et des zones DNS d'une infrastructure.

**Hyperviseur** : Logiciel créant et gérant des machines virtuelles en abstrayant les ressources matérielles. Type 1 (bare-metal : VMware ESXi, Hyper-V), type 2 (hosted : VirtualBox).

**Conteneur** : Unité d'exécution légère isolant une application et ses dépendances sans virtualiser un OS complet. Partage le noyau de l'hôte. Exemples : Docker, Podman.

**IaC (Infrastructure as Code)** : Gestion et provisionnement de l'infrastructure via du code versionné (Terraform, Ansible), permettant reproductibilité, auditabilité et automatisation.

**HA (High Availability - haute disponibilité)** : Architecture éliminant les points de défaillance uniques (SPOF - Single Point of Failure) pour garantir la continuité de service. Repose sur la redondance et le basculement automatique.

**Clustering** : Regroupement de plusieurs serveurs en un ensemble logique pour assurer la haute disponibilité ou la répartition de charge.

**Backup / Sauvegarde** : Copie des données permettant leur restauration en cas de perte. Types : complète, incrémentale (depuis la dernière sauvegarde), différentielle (depuis la dernière complète).

**RTO (Recovery Time Objective)** : Durée maximale acceptable d'interruption d'un service après un incident.

**RPO (Recovery Point Objective)** : Perte de données maximale acceptable, exprimée en durée.

**RAID (Redundant Array of Independent Disks)** : Technique combinant plusieurs disques pour améliorer les performances (RAID 0), la tolérance aux pannes (RAID 1, 5, 6) ou les deux (RAID 10).

**Monitoring / supervision** : Surveillance en continu des équipements et services pour détecter les pannes, les dégradations de performance et les anomalies. Outils : Nagios, Zabbix, Prometheus, Dynatrace.

---

## Sécurité des infrastructures

**Surface d'attaque** : Ensemble des points d'entrée potentiels qu'un attaquant peut exploiter pour compromettre un système. La réduire est un objectif fondamental du hardening.

**Hardening** : Processus de réduction de la surface d'attaque en désactivant les services inutiles, en appliquant les correctifs et en renforçant les configurations par défaut.

**Segmentation réseau** : Division d'un réseau en zones de confiance isolées pour limiter la propagation latérale. Mise en oeuvre via VLANs, pare-feux et ACLs.

**Zero Trust** : Modèle de sécurité fondé sur "ne jamais faire confiance, toujours vérifier". Chaque accès est authentifié, autorisé et audité quelle que soit la localisation de l'entité.

**ACL (Access Control List)** : Liste de règles définissant quel trafic est autorisé ou refusé sur une interface réseau ou un système de fichiers.

**TLS (Transport Layer Security)** : Protocole cryptographique assurant confidentialité et intégrité des communications. Successeur de SSL (Secure Sockets Layer). Fonctionne par négociation (handshake) puis chiffrement symétrique de session.

**DNSSEC (Domain Name System Security Extensions)** : Extension de DNS ajoutant des signatures cryptographiques aux enregistrements pour garantir leur authenticité et intégrité, contre le DNS poisoning.

**Patch management** : Processus de gestion du cycle de vie des correctifs de sécurité : identification, qualification, test, déploiement et vérification.

**SIEM (Security Information and Event Management)** : Plateforme centralisant, corrélant et analysant les journaux d'événements pour détecter les incidents et faciliter la réponse.

**SOC (Security Operations Center)** : Equipe et infrastructure dédiées à la surveillance, détection, analyse et réponse aux incidents de sécurité en continu.

---

## Cryptographie (notions clés)

**Chiffrement symétrique** : Même clé pour chiffrer et déchiffrer. Rapide, adapté aux grands volumes. Exemples : AES (Advanced Encryption Standard), 3DES. Problème principal : distribution sécurisée de la clé.

**Chiffrement asymétrique** : Paire de clés liées : clé publique (chiffrement / vérification) et clé privée (déchiffrement / signature). Résout le problème de distribution de clé. Exemples : RSA (Rivest-Shamir-Adleman), ECC (Elliptic Curve Cryptography).

**Chiffrement hybride** : La clé symétrique de session est échangée via un canal asymétrique, puis les données sont chiffrées symétriquement. Utilisé dans TLS.

**Fonction de hachage** : Fonction à sens unique produisant un condensat de taille fixe. Propriétés : déterministe, résistance aux collisions, effet avalanche. Exemples : SHA-256, SHA-3 (Secure Hash Algorithm).

**Signature numérique** : Condensat du message chiffré avec la clé privée de l'émetteur. Garantit intégrité, authenticité et non-répudiation.

**PKI (Public Key Infrastructure)** : Infrastructure gérant le cycle de vie des certificats numériques. Composants : AC (Autorité de Certification) racine, AC intermédiaire, CRL (Certificate Revocation List), OCSP (Online Certificate Status Protocol).

**Certificat X.509** : Standard définissant le format des certificats de clé publique. Contient la clé publique, l'identité du titulaire, la période de validité et la signature de l'AC émettrice.

---

## Contrôle d'accès et identité

**AAA (Authentication, Authorization, Accounting)** : Authentification (qui es-tu ?), Autorisation (que peux-tu faire ?), Accounting (qu'as-tu fait ?). Modèle fondamental de la gestion des accès.

**MFA (Multi-Factor Authentication)** : Authentification combinant au moins deux facteurs de nature différente (connaissance, possession, inhérence).

**SSO (Single Sign-On)** : Authentification unique donnant accès à plusieurs services. Protocoles : SAML (Security Assertion Markup Language), OAuth 2.0, OIDC (OpenID Connect).

**RBAC (Role-Based Access Control)** : Droits associés à des rôles, les utilisateurs reçoivent des rôles. Simplifie l'administration à grande échelle.

**Principe du moindre privilège** : Chaque entité ne dispose que des droits strictement nécessaires à l'exercice de ses fonctions.

**IAM (Identity and Access Management)** : Ensemble des processus et outils gérant les identités numériques et leurs droits d'accès.

---

## Gouvernance et conformité

**PSSI (Politique de Sécurité du Système d'Information)** : Document cadre définissant les objectifs, règles et responsabilités en matière de sécurité au sein d'une organisation.

**SMSI (Système de Management de la Sécurité de l'Information)** : Ensemble de processus permettant de gérer la sécurité de l'information de manière systématique. Normalisé par ISO 27001.

**ISO 27001 (International Organization for Standardization)** : Norme internationale définissant les exigences pour établir, mettre en oeuvre, maintenir et améliorer un SMSI.

**RGPD (Règlement Général sur la Protection des Données)** : Règlement européen encadrant le traitement des données personnelles. Principes : licéité, minimisation, exactitude, limitation de durée, intégrité, confidentialité, responsabilité.

**Analyse de risque** : Identification, évaluation et priorisation des risques. Risque = Probabilité x Impact. Traitements : acceptation, réduction, transfert, suppression.

**PCA / PRA (Plan de Continuité d'Activité / Plan de Reprise d'Activité)** : Le PCA maintient les fonctions essentielles pendant un incident, le PRA organise la restauration après incident.

**Audit de sécurité** : Evaluation formelle de la conformité et de l'efficacité des contrôles de sécurité par rapport à une référence définie.

---

## Menaces principales

**Vulnérabilité** : Faiblesse dans un système susceptible d'être exploitée pour compromettre sa sécurité.

**CVE (Common Vulnerabilities and Exposures)** : Identifiant standardisé pour les vulnérabilités connues publiquement. Format : CVE-ANNEE-NUMERO.

**CVSS (Common Vulnerability Scoring System)** : Score de criticité d'une vulnérabilité de 0 à 10, standardisé pour faciliter la priorisation des correctifs.

**Ransomware** : Logiciel malveillant chiffrant les données et exigeant une rançon pour la clé de déchiffrement.

**Phishing** : Ingénierie sociale par message frauduleux visant à obtenir des informations sensibles ou faire exécuter une action malveillante.

**DoS / DDoS (Denial of Service / Distributed Denial of Service)** : Attaque visant à rendre un service indisponible par saturation. La version distribuée mobilise un botnet.

**MitM (Man-in-the-Middle)** : Attaquant s'interposant entre deux parties communicantes pour intercepter ou modifier les échanges.

**Lateral movement** : Technique permettant à un attaquant de se déplacer au sein d'un réseau compromis pour atteindre d'autres systèmes.

**APT (Advanced Persistent Threat)** : Attaque ciblée, sophistiquée et durable menée par un acteur disposant de ressources importantes. Caractérisée par la discrétion et la persistance.
