# 09 - Securite Windows

**Duree :** 8 jours
**Modules :** 8 chapitres | 28 cours | 19 exercices/projets

---

## Objectifs

Maitriser la securite des environnements Windows, de l'architecture systeme a Active Directory, en passant par la detection d'intrusions et la conception d'infrastructure.

---

## Sommaire

### Chapitre 1 - Prise en main de Windows 

| # | Fichier | Type | Sujet |
|---|---------|------|-------|
| 01 | `01_Outils_administration_Windows.md` | Cours | Arborescence NTFS, commandes systeme, outils d'administration |
| 02 | `02_Utilisateurs_et_groupes.md` | Cours | Comptes locaux, groupes, modele RBAC, permissions |
| 03 | `03_Stockage_et_permissions.md` | Cours | Volumes, partitions, permissions NTFS |
| 04 | `04_Planificateur_de_taches.md` | Cours | Taches planifiees, scripts automatises |
| 05 | `05_Implementation_serveur_NovaTech.md` | Exercice | Implementation complete d'un serveur NovaTech |
| 06 | `06_Audit_manuel.md` | Exercice | Audit de securite manuel d'une machine Windows |

### Chapitre 2 - Windows Kernel Executive 

| # | Fichier | Type | Sujet |
|---|---------|------|-------|
| 07 | `07_Processus_et_services.md` | Cours | Processus, threads, DLL, services, svchost.exe |
| 08 | `08_Mode_noyau_vs_mode_utilisateur.md` | Cours | Kernel hybride, protection rings, syscalls |
| 09 | `09_Registre_Windows.md` | Cours | Structure du registre, cles racines, hives |
| 10 | `10_Gestionnaire_objets_et_ACL.md` | Cours | Object Manager, DACL, SACL, SDDL, audit |
| 11 | `11_Abus_de_services.md` | Exercice | Exploitation de services Windows mal configures |
| 12 | `12_Persistence_malware.md` | Exercice | Techniques de persistence via le registre et les services |

### Chapitre 3 - Pilotes et gestion memoire 

| # | Fichier | Type | Sujet |
|---|---------|------|-------|
| 13 | `13_Pilotes_Windows.md` | Cours | Drivers, pile de pilotes, signatures, PnP Manager |
| 14 | `14_Gestion_memoire.md` | Cours | RAM, memoire virtuelle, page tables, pagefile |
| 15 | `15_Pilotes_malveillants.md` | Exercice | Analyse de pilotes utilises comme vecteurs d'attaque |
| 16 | `16_Analyse_memoire.md` | Exercice | Forensique memoire avec ProcDump et Strings |
| 17 | `17_Introduction_injections_DLL.md` | Exercice | Techniques d'injection DLL |

### Chapitre 4 - Securite Windows 

| # | Fichier | Type | Sujet |
|---|---------|------|-------|
| 18 | `18_Jetons_acces_LSASS_SRM.md` | Cours | Access tokens, privileges, LSASS, SRM |
| 19 | `19_Winlogon.md` | Cours | Processus de connexion, Credential Providers, persistence |
| 20 | `20_SAM.md` | Cours | Base SAM, hashes NTLM, Mimikatz, protections |
| 21 | `21_Surveillance_Windows.md` | Cours | Event Viewer, audit, Sysinternals, ProcMon |
| 22 | `22_Phantom_Menace.md` | Exercice | Investigation de menaces fantomes |
| 23 | `23_Real_Menace.md` | Exercice | Investigation de menaces reelles |
| 24 | `24_Windows_Box.md` | Exercice | Exploitation d'une machine Windows |
| 25 | `25_Exploit_Suggester.md` | Exercice | Utilisation d'outils de suggestion d'exploits |

### Chapitre 5 - Introduction a Active Directory 

| # | Fichier | Type | Sujet |
|---|---------|------|-------|
| 26 | `26_Installation_Active_Directory.md` | Cours | GNS3, Windows Server 2022, installation AD DS |
| 27 | `27_Architecture_AD_concepts.md` | Cours | Forests, Trees, Domains, OUs, Domain Controllers |
| 28 | `28_Gestion_utilisateurs_groupes_AD.md` | Cours | Utilisateurs domaine, groupes, modele AGDLP |
| 29 | `29_Strategies_groupe_GPO.md` | Cours | GPO, ordre LSDOU, GPMC, Group Policy Preferences |
| 30 | `30_AD_pour_StellarTech.md` | Exercice | Deploiement d'un AD complet pour StellarTech |

### Chapitre 6 - Reseau dans Active Directory 

| # | Fichier | Type | Sujet |
|---|---------|------|-------|
| 31 | `31_DHCP_avec_Active_Directory.md` | Cours | Installation DHCP, scopes, haute disponibilite |
| 32 | `32_DNS_avec_Active_Directory.md` | Cours | DNS dans AD, enregistrements SRV, CNAME |
| 33 | `33_VPN_dans_Active_Directory.md` | Cours | IKEv2, MS-CHAPv2, RRAS, NPS |
| 34 | `34_Portail_interne_StellarTech.md` | Exercice | Mise en place d'un portail interne |

### Chapitre 7 - Securite et surveillance AD 

| # | Fichier | Type | Sujet |
|---|---------|------|-------|
| 35 | `35_Authentification_AD.md` | Cours | NTLM (challenge-response), Kerberos (tickets, KDC) |
| 36 | `36_Erreurs_configuration_AD.md` | Cours | Misconfigurations, delegations, DCSync, Kerberoasting |
| 37 | `37_Surveillance_detection_AD.md` | Cours | Sysmon, PingCastle, BloodHound |
| 38 | `38_Empoisonnement_LLMNR.md` | Exercice | Attaque par empoisonnement LLMNR |
| 39 | `39_Relais_NTLM.md` | Exercice | Attaque par relais NTLM |
| 40 | `40_Pass_the_Hash.md` | Exercice | Attaque Pass the Hash |
| 41 | `41_Kerberoasting.md` | Exercice | Attaque Kerberoasting |
| 42 | `42_Golden_et_Silver_Tickets.md` | Exercice | Forge de tickets Kerberos |

### Chapitre 8 - Projet Nova Syndicate 

| # | Fichier | Type | Sujet |
|---|---------|------|-------|
| 43 | `43_Principes_conception_infrastructure.md` | Cours | Physique/virtuel/cloud, 4 piliers de conception |
| 44 | `44_Analyse_besoins_client.md` | Cours | Exigences fonctionnelles/non-fonctionnelles, red flags |
| 45 | `45_Continuite_activite_reprise_apres_sinistre.md` | Cours | BCA, PRA, RTO, RPO |
| 46 | `46_Bonnes_pratiques_infrastructure.md` | Cours | RBAC, VLANs, monitoring, automatisation, documentation |
| 47 | `47_Projet_Nova_Syndicate.md` | Projet | Conception d'infrastructure complete |
