# 09 - Sécurité Windows

**Durée :** 8 jours  
**Modules :** 8 chapitres | 28 cours | 19 exercices/projets

---

## Objectifs

Maîtriser la sécurité des environnements Windows, de l'architecture système à Active Directory, en passant par la détection d'intrusions et la conception d'infrastructure.

---

## Sommaire

### Chapitre 1 - Prise en main de Windows

| # | Fichier | Type | Sujet |
|---|---------|------|-------|
| 01 | `01_Outils_administration_Windows.md` | Cours | Arborescence NTFS, commandes système, outils d'administration |
| 02 | `02_Utilisateurs_et_groupes.md` | Cours | Comptes locaux, groupes, modèle RBAC, permissions |
| 03 | `03_Stockage_et_permissions.md` | Cours | Volumes, partitions, permissions NTFS |
| 04 | `04_Planificateur_de_taches.md` | Cours | Tâches planifiées, scripts automatisés |
| 05 | `05_Implementation_serveur_NovaTech.md` | Exercice | Implémentation complète d'un serveur NovaTech |
| 06 | `06_Audit_manuel.md` | Exercice | Audit de sécurité manuel d'une machine Windows |

**Boxes HTB associées :**
| Box | Difficulté | Lien | Pertinence |
|-----|-----------|------|------------|
| Blue | Easy | [hackthebox.com/machines/blue](https://www.hackthebox.com/machines/blue) | Exploitation EternalBlue (MS17-010), énumération SMB et administration Windows de base |
| Legacy | Easy | [hackthebox.com/machines/legacy](https://www.hackthebox.com/machines/legacy) | Exploitation SMB (MS08-067), énumération de services Windows fondamentaux |
| Jerry | Easy | [hackthebox.com/machines/jerry](https://www.hackthebox.com/machines/jerry) | Credentials par défaut sur Tomcat, énumération de services et modèle de permissions |
| Devel | Easy | [hackthebox.com/machines/devel](https://www.hackthebox.com/machines/devel) | Configuration par défaut FTP/IIS, élévation de privilèges Windows basique |

---

### Chapitre 2 - Windows Kernel Executive

| # | Fichier | Type | Sujet |
|---|---------|------|-------|
| 07 | `07_Processus_et_services.md` | Cours | Processus, threads, DLL, services, svchost.exe |
| 08 | `08_Mode_noyau_vs_mode_utilisateur.md` | Cours | Kernel hybride, protection rings, syscalls |
| 09 | `09_Registre_Windows.md` | Cours | Structure du registre, clés racines, hives |
| 10 | `10_Gestionnaire_objets_et_ACL.md` | Cours | Object Manager, DACL, SACL, SDDL, audit |
| 11 | `11_Abus_de_services.md` | Exercice | Exploitation de services Windows mal configurés |
| 12 | `12_Persistence_malware.md` | Exercice | Techniques de persistance via le registre et les services |

**Boxes HTB associées :**
| Box | Difficulté | Lien | Pertinence |
|-----|-----------|------|------------|
| Return | Easy | [hackthebox.com/machines/return](https://www.hackthebox.com/machines/return) | Abus du groupe Server Operators pour modifier les binaires de services et escalader les privilèges |
| Optimum | Easy | [hackthebox.com/machines/optimum](https://www.hackthebox.com/machines/optimum) | Exploitation de services vulnérables et escalade kernel (MS16-032) |
| Bastard | Medium | [hackthebox.com/machines/bastard](https://www.hackthebox.com/machines/bastard) | Abus de SeImpersonatePrivilege et JuicyPotato, frontière kernel/user mode |
| Resolute | Medium | [hackthebox.com/machines/resolute](https://www.hackthebox.com/machines/resolute) | Abus du groupe DnsAdmins pour charger une DLL malveillante dans le service DNS |

---

### Chapitre 3 - Pilotes et gestion mémoire

| # | Fichier | Type | Sujet |
|---|---------|------|-------|
| 13 | `13_Pilotes_Windows.md` | Cours | Drivers, pile de pilotes, signatures, PnP Manager |
| 14 | `14_Gestion_memoire.md` | Cours | RAM, mémoire virtuelle, page tables, pagefile |
| 15 | `15_Pilotes_malveillants.md` | Exercice | Analyse de pilotes utilisés comme vecteurs d'attaque |
| 16 | `16_Analyse_memoire.md` | Exercice | Forensique mémoire avec ProcDump et Strings |
| 17 | `17_Introduction_injections_DLL.md` | Exercice | Techniques d'injection DLL |

**Boxes HTB associées :**
| Box | Difficulté | Lien | Pertinence |
|-----|-----------|------|------------|
| Blackfield | Hard | [hackthebox.com/machines/blackfield](https://www.hackthebox.com/machines/blackfield) | Analyse forensique d'un dump mémoire LSASS, extraction de credentials |
| Arctic | Easy | [hackthebox.com/machines/arctic](https://www.hackthebox.com/machines/arctic) | Escalade via exploit kernel (MS10-059), vulnérabilités de pilotes kernel |
| Bastard | Medium | [hackthebox.com/machines/bastard](https://www.hackthebox.com/machines/bastard) | Token impersonation et exploits kernel, frontière kernel/user mode |

---

### Chapitre 4 - Sécurité Windows

| # | Fichier | Type | Sujet |
|---|---------|------|-------|
| 18 | `18_Jetons_acces_LSASS_SRM.md` | Cours | Access tokens, privilèges, LSASS, SRM |
| 19 | `19_Winlogon.md` | Cours | Processus de connexion, Credential Providers, persistance |
| 20 | `20_SAM.md` | Cours | Base SAM, hashes NTLM, Mimikatz, protections |
| 21 | `21_Surveillance_Windows.md` | Cours | Event Viewer, audit, Sysinternals, ProcMon |
| 22 | `22_Phantom_Menace.md` | Exercice | Investigation de menaces fantômes |
| 23 | `23_Real_Menace.md` | Exercice | Investigation de menaces réelles |
| 24 | `24_Windows_Box.md` | Exercice | Exploitation d'une machine Windows |
| 25 | `25_Exploit_Suggester.md` | Exercice | Utilisation d'outils de suggestion d'exploits |

**Boxes HTB associées :**
| Box | Difficulté | Lien | Pertinence |
|-----|-----------|------|------------|
| Blackfield | Hard | [hackthebox.com/machines/blackfield](https://www.hackthebox.com/machines/blackfield) | Dump LSASS, extraction de hashes NTLM, ASREPRoasting et dump NTDS.dit |
| Sauna | Easy | [hackthebox.com/machines/sauna](https://www.hackthebox.com/machines/sauna) | AS-REP Roasting, DCSync, extraction de hashes NTLM depuis LSASS |
| Cascade | Medium | [hackthebox.com/machines/cascade](https://www.hackthebox.com/machines/cascade) | Extraction de credentials LDAP, déchiffrement de registre TightVNC, AD Recycle Bin |
| Granny | Easy | [hackthebox.com/machines/granny](https://www.hackthebox.com/machines/granny) | Exploitation WebDAV avec token impersonation, abus de jetons d'accès Windows |

---

### Chapitre 5 - Introduction à Active Directory

| # | Fichier | Type | Sujet |
|---|---------|------|-------|
| 26 | `26_Installation_Active_Directory.md` | Cours | GNS3, Windows Server 2022, installation AD DS |
| 27 | `27_Architecture_AD_concepts.md` | Cours | Forests, Trees, Domains, OUs, Domain Controllers |
| 28 | `28_Gestion_utilisateurs_groupes_AD.md` | Cours | Utilisateurs domaine, groupes, modèle AGDLP |
| 29 | `29_Strategies_groupe_GPO.md` | Cours | GPO, ordre LSDOU, GPMC, Group Policy Preferences |
| 30 | `30_AD_pour_StellarTech.md` | Exercice | Déploiement d'un AD complet pour StellarTech |

**Boxes HTB associées :**
| Box | Difficulté | Lien | Pertinence |
|-----|-----------|------|------------|
| Forest | Easy | [hackthebox.com/machines/forest](https://www.hackthebox.com/machines/forest) | Énumération LDAP anonyme, découverte utilisateurs/groupes, AS-REP Roasting et abus ACL |
| Active | Easy | [hackthebox.com/machines/active](https://www.hackthebox.com/machines/active) | Exposition de mots de passe GPP (Group Policy Preferences) et Kerberoasting |
| Support | Easy | [hackthebox.com/machines/support](https://www.hackthebox.com/machines/support) | Énumération LDAP, analyse des groupes, Resource Based Constrained Delegation |
| Timelapse | Easy | [hackthebox.com/machines/timelapse](https://www.hackthebox.com/machines/timelapse) | Authentification par certificat, abus LAPS, énumération SMB et groupes AD |

---

### Chapitre 6 - Réseau dans Active Directory

| # | Fichier | Type | Sujet |
|---|---------|------|-------|
| 31 | `31_DHCP_avec_Active_Directory.md` | Cours | Installation DHCP, scopes, haute disponibilité |
| 32 | `32_DNS_avec_Active_Directory.md` | Cours | DNS dans AD, enregistrements SRV, CNAME |
| 33 | `33_VPN_dans_Active_Directory.md` | Cours | IKEv2, MS-CHAPv2, RRAS, NPS |
| 34 | `34_Portail_interne_StellarTech.md` | Exercice | Mise en place d'un portail interne |

**Boxes HTB associées :**
| Box | Difficulté | Lien | Pertinence |
|-----|-----------|------|------------|
| Intelligence | Medium | [hackthebox.com/machines/intelligence](https://www.hackthebox.com/machines/intelligence) | Manipulation de records DNS dans AD pour intercepter des requêtes authentifiées |
| Resolute | Medium | [hackthebox.com/machines/resolute](https://www.hackthebox.com/machines/resolute) | Abus du groupe DnsAdmins pour charger une DLL malveillante dans le service DNS |
| Monteverde | Medium | [hackthebox.com/machines/monteverde](https://www.hackthebox.com/machines/monteverde) | Exploitation Azure AD Connect, énumération SMB et intégration de services réseau AD |

---

### Chapitre 7 - Sécurité et surveillance AD

| # | Fichier | Type | Sujet |
|---|---------|------|-------|
| 35 | `35_Authentification_AD.md` | Cours | NTLM (challenge-response), Kerberos (tickets, KDC) |
| 36 | `36_Erreurs_configuration_AD.md` | Cours | Misconfigurations, délégations, DCSync, Kerberoasting |
| 37 | `37_Surveillance_detection_AD.md` | Cours | Sysmon, PingCastle, BloodHound |
| 38 | `38_Empoisonnement_LLMNR.md` | Exercice | Attaque par empoisonnement LLMNR |
| 39 | `39_Relais_NTLM.md` | Exercice | Attaque par relais NTLM |
| 40 | `40_Pass_the_Hash.md` | Exercice | Attaque Pass the Hash |
| 41 | `41_Kerberoasting.md` | Exercice | Attaque Kerberoasting |
| 42 | `42_Golden_et_Silver_Tickets.md` | Exercice | Forge de tickets Kerberos |

**Boxes HTB associées :**
| Box | Difficulté | Lien | Pertinence |
|-----|-----------|------|------------|
| Active | Easy | [hackthebox.com/machines/active](https://www.hackthebox.com/machines/active) | Kerberoasting classique : exposition GPP puis Kerberoasting du SPN Administrator |
| Forest | Easy | [hackthebox.com/machines/forest](https://www.hackthebox.com/machines/forest) | AS-REP Roasting, abus ACL guidé par BloodHound (WriteDACL) et attaque DCSync |
| Sauna | Easy | [hackthebox.com/machines/sauna](https://www.hackthebox.com/machines/sauna) | AS-REP Roasting, credential dumping, DCSync et découverte AutoLogon |
| Sizzle | Insane | [hackthebox.com/machines/sizzle](https://www.hackthebox.com/machines/sizzle) | Vol de hash NTLM via SCF sur partage SMB, abus de certificats, Kerberoasting et DCSync |

---

### Chapitre 8 - Projet Nova Syndicate

| # | Fichier | Type | Sujet |
|---|---------|------|-------|
| 43 | `43_Principes_conception_infrastructure.md` | Cours | Physique/virtuel/cloud, 4 piliers de conception |
| 44 | `44_Analyse_besoins_client.md` | Cours | Exigences fonctionnelles/non-fonctionnelles, red flags |
| 45 | `45_Continuite_activite_reprise_apres_sinistre.md` | Cours | BCA, PRA, RTO, RPO |
| 46 | `46_Bonnes_pratiques_infrastructure.md` | Cours | RBAC, VLANs, monitoring, automatisation, documentation |
| 47 | `47_Projet_Nova_Syndicate.md` | Projet | Conception d'infrastructure complète |

**Boxes HTB associées :**
| Box | Difficulté | Lien | Pertinence |
|-----|-----------|------|------------|
| Timelapse | Easy | [hackthebox.com/machines/timelapse](https://www.hackthebox.com/machines/timelapse) | LAPS pour la sécurité d'infrastructure, authentification par certificat, gestion de backups |
| Monteverde | Medium | [hackthebox.com/machines/monteverde](https://www.hackthebox.com/machines/monteverde) | Intégration Azure AD Connect, gestion de comptes de service et bonnes pratiques de stockage de credentials |
| Cascade | Medium | [hackthebox.com/machines/cascade](https://www.hackthebox.com/machines/cascade) | AD Recycle Bin, récupération d'objets supprimés, gestion multi-couches de credentials |
