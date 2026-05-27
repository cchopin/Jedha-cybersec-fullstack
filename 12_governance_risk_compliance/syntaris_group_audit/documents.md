# Dossier Syntaris Group, résumés des sources

Synthèse en français des cinq documents fournis pour l'étude de cas. Chaque résumé reprend les faits utiles à l'audit (maturité NIST, conformité RGPD, risques). Les éléments directement exploitables comme constats d'audit sont signalés.

---

## Document 0, profil général de l'entreprise

**Nature.** Fiche d'identité de Syntaris Group.

**L'essentiel.** Fintech européenne d'identité numérique et de paiement, fondée en 2017 à Paris, orientée cloud. Elle combine apprentissage automatique, cybersécurité et conformité dès la conception pour des clients de la banque, du e-commerce et du mobile.

**Présence et implantation.** Siège à Paris, bureaux à Dublin (R&D et sécurité cloud), Toronto (développement commercial Amérique du Nord) et Barcelone (support client). Traitement des données sur AWS Europe (Francfort et Paris), un cloud privé OVH à Roubaix, et un reliquat de systèmes hérités sur GCP US-East.

**Chiffres clés.** 284 salariés, 42 M€ de revenu récurrent annuel, croissance de +37%/an sur trois ans, environ 280 millions d'appels d'API par mois, plus de 1 100 clients B2B dans 27 pays. Répartition du revenu : 61% UE, 27% Amérique du Nord, 12% reste du monde.

**Organisation.** Huit départements, dont Ingénierie et DevOps (94 personnes), Sécurité et Conformité (18), et Juridique et Vie privée (11, qui porte les responsabilités DPO).

**Produits.** Quatre briques sur la plateforme Syntaris Identity Cloud :
- IDTrust : vérification d'identité avec OCR, biométrie, détection du vivant, scoring de fraude par IA.
- SecurePay Gateway : API de paiement conforme PCI, tokenisation, 3DSecure 2.x, détection de fraude temps réel.
- VaultLock : stockage sécurisé et contrôle d'accès, chiffrement AES-256 au repos, masquage dynamique, RBAC, journalisation d'audit.
- RegFlow : automatisation de conformité RGPD/PSD2, gestion des demandes des personnes (DSR), gestion du consentement.

**Posture sécurité et conformité.** Détient ISO 27001 (valide jusqu'en 2026), PCI-DSS niveau 1 pour SecurePay, DPO interne nommé, DPIA réalisées sur tout nouveau produit. Outils : Microsoft Defender ATP, SIEM Wazuh, AWS GuardDuty et CloudTrail, Tenable.io, simulations GoPhish. Sur 24 mois : une mauvaise configuration interne (2023, sans fuite), zéro compromission externe confirmée, deux exercices rançongiciel simulés en 2024.

**Données et obligations.** Traite identité (nom, téléphone, email, ID national), biométrie (scan facial pour IDTrust) et données financières (tokens, IBAN, métadonnées de paiement). Responsable de traitement pour ses services hébergés, sous-traitant pour certaines offres en marque blanche. Obligations : RGPD, PIPEDA au Canada, possible examen au titre du cadre de protection des données UE-États-Unis.

**Constats d'audit à retenir.** Données biométriques sensibles à grande échelle (enjeu RGPD art. 5 et 25). Reliquat GCP hérité (dette technique). Empilement multi-réglementaire à coordonner.

---

## Document 1, infrastructure technique

**Nature.** Description de l'architecture et de la pile technique.

**Modèle général.** Infrastructure hybride mêlant cloud et systèmes sur site pour répondre aux contraintes réglementaires et de latence.

**Cloud.** Production majoritairement sur AWS (régions Irlande et Francfort) : microservices, API, pipelines d'inférence ML, stockage, tableaux de bord clients. Conteneurs Docker orchestrés par EKS, infrastructure gérée via Terraform, déploiements via GitLab CI/CD et Argo CD. Systèmes hérités encore sur GCP US-East (tableaux de bord internes, anciens pipelines), migration vers AWS en cours mais inachevée. Cloud privé OpenStack chez OVH Roubaix pour les clients à contrainte de résidence des données (instances VaultLock et RegFlow isolées pour la santé, le public et la banque).

**Architecture applicative.** Microservices FastAPI (Python) et Node.js communiquant en REST et gRPC, derrière une API Gateway partagée. Authentification par OAuth2 et JWT. Auth0 pour les flux clients, Azure AD avec synchronisation hybride vers un Active Directory sur site pour le personnel interne. MFA imposé pour les accès administrateur.

**Données.** PostgreSQL (AWS RDS multi-AZ) pour le transactionnel, MongoDB Atlas pour le sans-schéma. Kafka et Flink pour le streaming temps réel, stockage long terme sur S3. Entraînement des modèles ML dans des environnements de laboratoire isolés (air-gapped) avec PyTorch et TensorFlow.

**Sur site (Paris et Barcelone), critique pour la sécurité et la conformité.**
- Domaine Active Directory hybride avec ADFS et GPO.
- Zone de gestion des accès à privilèges (PAM) avec coffre CyberArk, jump servers et provisionnement juste-à-temps pour les DevOps.
- Laboratoire bac à sable d'analyse de malware sur VMware ESXi avec stockage vSAN.
- Sauvegardes restic et BorgBackup sur baies ZFS chiffrées LUKS, certaines déconnectées du réseau une partie de la journée pour réduire le risque rançongiciel.
- Imagerie SCCM pour Windows et Munki pour Mac.
- Deux passerelles VPN héritées (Cisco ASA) maintenues pour des clients financiers exigeant des tunnels à IP fixe.

**Sécurité opérationnelle.** SIEM Wazuh, Sysmon, IDS Suricata, AWS GuardDuty. Logs centralisés sur une pile ELK, avec des délais de corrélation dus à l'ingestion multi-sources. Alertes routées via PagerDuty, règles gérées par le SOC de Dublin. Chaîne DevSecOps avec Trivy, SonarQube et Open Policy Agent (scan d'images, SAST, application de politiques). Secrets dans HashiCorp Vault.

**Failles signalées dans le document.** Les environnements Cuckoo de bac à sable sont hors du flux de gestion des correctifs. Les étapes de nettoyage des données avant entraînement ML ne sont pas systématiquement documentées. Les DSR sont gérées par email et suivi manuel, ce qui ne passe pas à l'échelle. Les CIS Benchmarks couvrent le cloud, mais certains systèmes sur site (GCP hérité, VPN) ne sont pas durcis.

**Constats d'audit à retenir.** Protection technique mature (PAM, MFA, chiffrement, DevSecOps) = points forts NIST Protect. Dette technique VPN et GCP, Cuckoo hors patch, sanitisation ML non documentée, DSR manuels = écarts directs.

---

## Document 2, historique des incidents

**Nature.** Journal interne confidentiel de sept incidents et une note sur l'évolution de la détection (2019-2025).

**Incident 1, fuite d'identifiants GitLab (mars 2020).** Un ingénieur junior commit un fichier .env avec des identifiants MongoDB en dur dans un dépôt privé accessible à 28 employés et 5 prestataires. Repéré en revue de merge request, secret purgé et identifiants tournés en ~4h. Pas d'accès non autorisé constaté, base de staging sans données clients. A conduit à intégrer un scanner de secrets et à mettre à jour la checklist d'intégration des développeurs.

**Incident 2, retard de traitement des DSR (oct.-déc. 2021).** Une campagne d'un groupe de défense des droits génère 37 demandes (DSR) via des clients de Syntaris. Traitement manuel par Juridique et Ingénierie. **Quatre cas dépassent le délai RGPD de 30 jours** (problèmes de transfert d'email, congés de fin d'année, responsabilités floues). La **CNIL adresse une demande écrite** suite à une plainte. Pas d'amende, mais engagement écrit à améliorer la traçabilité. Aucune automatisation, suivi sur tableur partagé.

**Incident 3, simulation de phishing (juillet 2022).** Email piégé envoyé à 81 personnes du support. **17 clics (21%)**, 3 saisies d'identifiants. A révélé un manque de sensibilisation. Suivi d'une campagne de formation, marquage des emails externes, désactivation des protocoles d'authentification hérités. Test refait six mois après : **7% de clics**, aucune saisie.

**Incident 4, échec de confinement en bac à sable (mars 2023).** Analyse d'un rançongiciel dans le bac à sable Cuckoo sur ESXi. Une mauvaise segmentation VLAN laisse le binaire communiquer avec son C2 par DNS. Wazuh détecte mais l'alerte est mal taguée (faible confiance) dans Logstash. **L'activité continue trois jours** avant d'être repérée par hasard lors d'une enquête de bande passante. Hôte isolé et réinstallé, pas de propagation. Constat : aucun mécanisme de rollback ni de playbook pour les menaces issues du lab. Suite à l'incident, labs fermés temporairement, règles pare-feu réécrites, ajout d'un interrupteur physique de coupure réseau.

**Incident 5, exercice rançongiciel sur table (octobre 2024).** Exercice red team/blue team simulant une intrusion via macro Excel : mouvement latéral, vol d'identifiants LSASS, persistance par tâche planifiée, exfiltration vers un faux bucket S3. SOC de Dublin, Juridique et Communication de Paris, deux observateurs externes. **Playbooks exécutés avec succès** : comptes désactivés, VM isolée, triage en 2h, divulgations légales fictives en 24h. Cité comme point de maturité à l'audit ISO 27001 2025. Premier test transverse Juridique/IT/Communication.

**Incident 6, vulnérabilité VPN hérité (oct. 2024, en cours).** CVE critique (RCE) sur les appliances Cisco ASA. **Deux appareils encore en production** pour des clients bancaires exigeant des connexions IPsec persistantes. Patch bloqué par dépendance contractuelle. En mars 2025, appareils toujours en ligne avec mesures compensatoires (règles pare-feu, signatures IDS, redémarrages planifiés). Suivi en CMDB et SIEM. Aucun plan de décommissionnement validé. Classé « risque stratégique à options de remédiation contraintes ».

**Incident 7, blocage MFA pendant une astreinte (janvier 2025).** Un ingénieur de support est bloqué hors du portail admin (token MFA expiré, règle Auth0 mal configurée, contact de secours injoignable 2h). Empêche le déploiement d'un correctif sur un service de paiement dégradé. Accès finalement rétabli manuellement. Constat : seulement deux ingénieurs habilités aux resets d'urgence, pas de procédure de secours hors bande documentée. Suite : doc d'astreinte mise à jour, politique PAM étendue au provisionnement de token hors ligne.

**Note sur l'évolution de la détection (2019-2025).** Détection passée d'un mode réactif (CloudTrail, alertes CloudWatch basiques, vigilance individuelle) à un SIEM consolidé Wazuh/ELK ingérant Sysmon, CloudTrail, flux VPC, événements GitLab et Suricata. Progression souvent réactive aux incidents plutôt que planifiée. Limites encore présentes en 2025 : **SOC limité aux heures ouvrées (8h-18h CET)**, réponse hors heures en best-effort, endpoints Mac sans télémétrie complète, bruit des bac à sable, règles cloud et sur site écrites séparément (dérive et doublons), corrélation inter-plateformes limitée. État jugé en interne « fonctionnel mais perfectible ».

**Constats d'audit à retenir.** Respond mature (incident 5). Govern faible et Detect inégal (incidents 4, 6, 7 et note détection). DSR = faiblesse RGPD récurrente (incident 2). VPN = risque haut non résolu (incident 6).

---

## Document 3, entretien des dirigeants

**Nature.** Transcription d'un entretien (15 mars 2025) avec quatre dirigeants : Sophie Renaud (COO), Nathan Tremblay (CTO), Lila Park (responsable Juridique et Vie privée), Derek Walsh (directeur Sécurité plateforme).

**Mission et culture.** La COO résume : « nous vendons de la confiance, pas seulement des API ». La cybersécurité est censée être intégrée tôt dans les discussions produit et client. Réalité de la fintech : si l'onboarding d'un client échoue, ça remonte vite.

**Gouvernance, point sensible.** **Pas de CISO dédié** : responsabilité partagée entre l'équipe de Derek et le comité exécutif. Derek reporte au CTO mais est associé à tous les deals, revues fournisseurs et audits. Tabletops trimestriels, snapshot cyber au conseil tous les 6 mois. Derek préside une Security Guild transverse (ingénieurs, PM, RH). Le CTO admet que des choses passent entre les mailles (VLAN du bac à sable, calendrier de migration GCP), qualifiées de dette technique plutôt que de négligence.

**Gestion du risque.** Alignement déclaré sur ISO 27005, intégré au processus DPIA. Triage pratique « par impact sur la confiance » plutôt que par scoring de tableur. Registre des risques avec propriétaires par unité, mis à jour plutôt trimestriellement. Derek catégorise le risque en connu/inconnu et visible/invisible : les VPN Cisco sont connus et surveillés, la vraie peur ce sont les dépendances indirectes (bibliothèques tierces). **Appétence faible pour toute perte de données client ou échec de conformité** ; tolérance variable pour les interruptions de service (panne UI mineure tolérable, panne de tokenisation un jour de forte charge inacceptable).

**Politiques.** Politiques formelles (IAM, codage sécurisé, accès distant, risque tiers, réponse à incident) alignées ISO, dans Confluence, revue trimestrielle théorique. Le CTO note que les ingénieurs s'appuient plus sur les checklists et les règles CI/CD que sur les politiques. Formation à rafraîchir (exemples qui citent encore la fuite British Airways de 2018).

**Tiers.** Évaluation des fournisseurs critiques tous les 12 mois. Visibilité bonne sur les fournisseurs de premier rang, faible sur les indirects (outils SaaS choisis par les RH). Demandes de SLA de notification de violation amorcées. Exemple cité : un partenaire hors service une heure suite à une expiration de certificat TLS.

**Apprentissage des incidents.** Post-mortems pour tout incident P1, actions dans Jira. Ajout de la catégorie « menace issue du lab » après l'incident bac à sable. Reconnaissance que le traitement manuel des DSR ne passe plus à l'échelle (intégration prévue dans VaultLock v2). Souhait du CTO de retirer GCP d'ici la fin d'année. Boutade de Derek : « ne me demandez pas de remplacer les VPN, j'ai déjà perdu ce combat deux fois ».

**Constats d'audit à retenir.** Confirme l'absence de CISO (Govern). Confirme l'appétence faible sur données/conformité (utile pour justifier que le VPN dépasse l'appétence). Confirme la conscience interne des faiblesses (DSR, VPN, GCP, tiers indirects).

---

## Document 4, gestion des tiers et de la chaîne d'approvisionnement

**Nature.** Note interne sur la gestion des fournisseurs (mise à jour février 2025).

**Périmètre.** **37 fournisseurs actifs** couvrant infrastructure cloud, traitement de données, outillage développeur, conformité et support. Catégories : infrastructure (AWS, GCP, OVH), sources KYC et vérification d'identité (Onfido, Ariadnext, IN Groupe), paiement (Stripe, Worldline), outillage (GitLab, Sentry, DockerHub), sécurité (Tenable, Wazuh Cloud, CrowdStrike), conformité (OneTrust, Auth0), productivité (Notion, Slack, Zoom, Office365). **19 fournisseurs ont accès à des données personnelles**, **12 sont jugés critiques**.

**Gouvernance.** Onboarding et suivi partagés entre Juridique, Achats, Sécurité plateforme et les unités métier. Registre tenu dans Airtable. **Pas de plateforme GRC centralisée** : suivi manuel via Airtable, Confluence et dossiers de contrats SharePoint.

**Classification du risque.** Trois niveaux : Tier 1 (accès aux données sensibles ou à l'infrastructure de sécurité), Tier 2 (pas d'accès direct mais disponibilité critique), Tier 3 (faible impact). Les Tier 1 subissent une revue de due diligence, une revue juridique du DPA, la documentation des SLA de notification, la revue des certifications et la vérification de la localisation des données. Tier 2 et 3 : validation allégée. **Pas de pentest ni d'audit obligatoire des fournisseurs**, revues surtout documentaires et passives.

**Contrôles contractuels.** Clauses habituelles pour les Tier 1 : notification de violation sous 72h, chiffrement au repos et en transit, droit d'audit (rarement exercé), suppression des données en fin de contrat, divulgation des sous-traitants. **Sept contrats restent en termes hérités** (antérieurs à 2021, sans formulation RGPD à jour ni délimitation claire responsable/sous-traitant), à renouveler dans les 9 mois.

**Surveillance.** **Aucune solution automatisée de monitoring** des fournisseurs (type SecurityScorecard ou Bitsight). Bulletins de sécurité reçus par email, revus mensuellement en « vendor huddle ». Watchlist Confluence de 6 fournisseurs sous surveillance (fiabilité d'API, CVE non corrigées dans des SDK, divulgations tardives). Réassessments Tier 1 annuels mais à fréquence variable. Aucun exercice sur table impliquant une violation chez un tiers.

**Offboarding.** Checklist documentée dans SharePoint (suppression des données, déprovisionnement, export des logs, archivage du contrat). Exécution inconstante constatée aux audits 2022 et 2023, surtout pour les Tier 2. Cas d'un outil de développement ayant conservé des tokens d'accès deux mois après la fin du contrat. Pas de mécanisme centralisé de vérification.

**Exemples récents.** Oct. 2022 : panne d'un fournisseur KYC (certificats TLS expirés), onboarding interrompu 90 min pour quatre clients. Mars 2023 : SDK d'analytics dans RegFlow contenant une sous-dépendance vulnérable à une injection XSS, sans possibilité de confirmer un usage abusif. Déc. 2024 : contrat avec un fournisseur cloud Tier 1 expiré par erreur lors d'une réorganisation, perte temporaire de données de monitoring hors production.

**Améliorations prévues 2025-2026.** Tableau de bord de risque fournisseur en remplacement d'Airtable, suivi automatisé des DPA et alertes de renouvellement, évaluation de services de monitoring tiers, alignement sur les attentes NIST CSF 2.0 GV.SC pour les fournisseurs à haut risque, intégration des fournisseurs aux playbooks de réponse à incident.

**Constats d'audit à retenir.** GV.SC immature : pas de plateforme GRC, pas de pentest tiers, suivi manuel, 7 contrats obsolètes, offboarding inconstant, aucun monitoring automatisé. Pile directement liée aux exigences NIS2 et DORA sur la chaîne de tiers.

---

## Tableau de correspondance, source vers constat

| Source | Constats majeurs | Fonctions NIST / articles RGPD |
|---|---|---|
| Doc 0 profil | Biométrie sensible, multi-réglementaire, GCP hérité | GV.OC, RGPD art. 5/25 |
| Doc 1 infra | Protection mature, dette VPN/GCP, DSR manuels, Cuckoo hors patch | PR.AA/DS/PS, ID.RA, RGPD art. 32 |
| Doc 2 incidents | Respond mature, Detect inégal, DSR récurrents, VPN non résolu | RS, DE, GV, RGPD art. 33 |
| Doc 3 interview | Pas de CISO, appétence faible, faiblesses connues | GV.RR, GV.RM |
| Doc 4 tiers | GV.SC immature, 7 contrats obsolètes, pas de monitoring | GV.SC, NIS2/DORA |
