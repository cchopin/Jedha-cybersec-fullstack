# Rapport d'analyse DNS - jedha.co

 **Date** : 22 décembre 2025
 **Analyste** : C. Chopin
 **Outil** : Wireshark 4.6.2
 **Fichier de capture** : edew.pcapng

 ---

 ## 1. Objectif

 Capturer et analyser le trafic DNS du domaine `jedha.co` afin d'extraire des informations sur son infrastructure, ses services et sa configuration de sécurité.

 ---

 ## 2. Méthodologie

 - **Interface réseau** : en0 (Wi-Fi/Ethernet)
 - **Filtre de capture** : `udp port 53`
 - **Serveur DNS interrogé** : 1.1.1.1 (Cloudflare Public DNS)
 - **Commandes utilisées** : `dig jedha.co [A|AAAA|MX|NS|TXT]`

 ---

 ## 3. Résultats de l'analyse

 ### 3.1 Adresses IP (Enregistrements A et AAAA)

 | Type | Adresse IP | Fournisseur | TTL |
 |------|------------|-------------|-----|
 | A | 104.26.2.30 | Cloudflare | 300s |
 | A | 104.26.3.30 | Cloudflare | 300s |
 | A | 172.67.73.113 | Cloudflare | 300s |
 | AAAA | 2606:4700:20::681a:21e | Cloudflare | 300s |
 | AAAA | 2606:4700:20::681a:31e | Cloudflare | 300s |
 | AAAA | 2606:4700:20::ac43:4971 | Cloudflare | 300s |

 **Observation** : Le site jedha.co est hébergé derrière le CDN Cloudflare, qui assure la protection DDoS, le cache et la distribution géographique du contenu.

 ### 3.2 Serveurs de Noms Autoritaires (NS)

 | Serveur | TTL |
 |---------|-----|
 | damon.ns.cloudflare.com | 86400s (24h) |
 | tricia.ns.cloudflare.com | 86400s (24h) |

 **Observation** : La gestion DNS est déléguée à Cloudflare. Le TTL élevé (24h) indique une configuration stable.

 ### 3.3 Serveurs Mail (MX)

 | Priorité | Serveur | Service |
 |----------|---------|---------|
 | 1 | aspmx.l.google.com | Google Workspace |
 | 5 | alt1.aspmx.l.google.com | Google Workspace |
 | 5 | alt2.aspmx.l.google.com | Google Workspace |
 | 10 | alt3.aspmx.l.google.com | Google Workspace |
 | 10 | alt4.aspmx.l.google.com | Google Workspace |

 **Observation** : Les emails de jedha.co sont gérés par Google Workspace. La configuration multi-serveurs avec priorités assure la redondance.

 ### 3.4 Enregistrements TXT

 | Type | Contenu | Usage |
 |------|---------|-------|
 | SPF | `v=spf1 include:hubspotemail.net include:_spf.google.com include:spf.mailjet.com ?all` | Authentification email |
 | DKIM | Clé RSA 1024 bits | Signature cryptographique des emails |
 | Google Site Verification | 3 tokens différents | Vérification propriété domaine |
 | OpenAI Verification | `dv-ksmYIJoHszK6ONkwizn1llwL` | Intégration API OpenAI |
 | Stripe Verification | Token de vérification | Intégration paiement Stripe |

 **Observation** :
 - La politique SPF autorise l'envoi d'emails via Google, HubSpot et Mailjet
 - DKIM est configuré pour signer les emails sortants
 - Le domaine est vérifié auprès de Google, OpenAI et Stripe

 ---

 ## 4. Analyse des temps de réponse

 | Requête | Temps de réponse |
 |---------|------------------|
 | A | 95 ms |
 | MX | 39 ms |
 | NS | 40 ms |
 | TXT | 42 ms |
 | AAAA | 38 ms |

 **Observation** : Les temps de réponse sont excellents (<100ms), grâce à la proximité des serveurs Cloudflare DNS.

 ---

 ## 5. Synthèse de l'infrastructure

 ```
                     ┌─────────────────┐
                     │   jedha.co      │
                     └────────┬────────┘
                              │
             ┌────────────────┼────────────────┐
             │                │                │
             ▼                ▼                ▼
     ┌───────────────┐ ┌───────────────┐ ┌───────────────┐
     │  Cloudflare   │ │    Google     │ │   Services    │
     │  CDN + DNS    │ │   Workspace   │ │   Tiers       │
     └───────────────┘ └───────────────┘ └───────────────┘
     • Protection DDoS  • Email          • HubSpot (CRM)
     • Cache            • Calendrier     • Mailjet (Email)
     • SSL/TLS          • Drive          • Stripe (Paiement)
                                         • OpenAI (IA)
 ```

 ---

 ## 6. Conclusions

 ### Points clés
 1. **Hébergement** : Cloudflare CDN avec 3 IPs IPv4 et 3 IPs IPv6
 2. **Email** : Google Workspace avec redondance (5 serveurs MX)
 3. **Sécurité Email** : SPF + DKIM configurés correctement
 4. **Intégrations** : HubSpot, Mailjet, Stripe, OpenAI

 ### Observations de sécurité
 - Protection Cloudflare active (masquage IP origine)
 - SPF configuré (prévention spoofing)
 - DKIM configuré (authentification emails)
 - 
 SPF utilise `?all` (neutral) au lieu de `-all` (strict)

 ### Anomalies détectées
 - Aucune anomalie majeure dans les TTL ou les temps de résolution
 - Configuration DNS standard et bien structurée

 ---

 ## 7. Annexes

 ### Commandes utilisées
 ```bash
 dig jedha.co A
 dig jedha.co AAAA
 dig jedha.co MX
 dig jedha.co NS
 dig jedha.co TXT
 ```

 ### Filtre Wireshark
 ```
 udp port 53
 ```
