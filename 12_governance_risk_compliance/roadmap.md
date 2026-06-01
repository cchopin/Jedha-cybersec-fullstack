# Fiche de ressources: MOOCs et formations gratuits en cybersécurité

Cette fiche recense des ressources de formation gratuites, limitées aux sources officielles (ANSSI, CNIL, Club EBIOS) et aux plateformes d'entraînement reconnues. 


## Réglementaire et gouvernance

### MOOC Découvrez EBIOS Risk Manager
- Source: Club EBIOS et ANSSI
- Lien: https://lms.club-ebios.org/formations/ebiosrm
- Format: formation en ligne en autonomie, environ 35 leçons réparties en 13 modules. Certification validée par l'ANSSI, délivrée sous réserve de réussite au test final.
- Contenu: méthode d'analyse de risque déroulée en cinq ateliers (cadrage et socle de sécurité, sources de risque, scénarios stratégiques, scénarios opérationnels, traitement du risque), illustrée par une étude de cas continue.
- Positionnement: méthode de référence en France pour l'analyse de risque, mobilisable pour l'application des cadres NIS2 et DORA.

### Atelier RGPD
- Source: CNIL
- Lien: https://atelier-rgpd.cnil.fr (page de présentation: https://www.cnil.fr/fr/comprendre-le-rgpd/le-mooc-de-la-cnil)
- Format: formation en ligne gratuite et ouverte à tous, environ vingt heures réparties en cinq à six modules. Attestation délivrée par module sous condition de réussite aux quiz.
- Contenu: notions clés du RGPD, principes de protection des données, responsabilités des acteurs et des sous-traitants, rôle du délégué à la protection des données, registre des traitements, analyse d'impact, notification des violations.
- Positionnement: référence officielle sur la protection des données personnelles, complémentaire des cadres NIS2 et DORA.

### SecNumacadémie
- Source: ANSSI
- Lien: https://secnumacademie.gouv.fr
- Statut: plateforme historique en refonte et fermée depuis fin février 2026. Nouvelle version annoncée courant 2026, avec des parcours déclinés par niveau de maîtrise et des modules thématiques, dont un consacré à la directive NIS2 et à la gestion de crise.
- Contenu (version historique): quatre modules de fondamentaux (panorama de la sécurité des systèmes d'information, authentification, sécurité sur Internet, sécurité du poste de travail et nomadisme).
- Positionnement: ressource de sensibilisation aux fondamentaux, à reconsulter à la réouverture pour les nouveaux modules.

### Guides et ressources ANSSI
- Source: ANSSI
- Lien: https://cyber.gouv.fr et https://messervices.cyber.gouv.fr
- Nature: documentation de référence, hors format MOOC.
- Contenu: guide d'hygiène informatique, recommandations relatives à l'authentification multifacteur, à la sécurisation d'un site web et à l'interconnexion d'un SI à Internet. Les portails MesServicesCyber et MonEspaceNIS2 permettent de vérifier l'assujettissement à NIS2 et de suivre les obligations.
- Positionnement: référentiel utilisé pour évaluer les écarts du socle de sécurité lors d'une analyse de risque.

## Technique et blue team

### LetsDefend
- Nature: plateforme d'entraînement défensif (SOC simulé), rattachée à Hack The Box.
- Lien: https://letsdefend.io
- Format: plusieurs modules gratuits avec attestation, reste de la plateforme en abonnement.
- Contenu gratuit: fondamentaux du SOC, analyse d'e-mails de phishing, Linux pour la défense, détection d'attaques web, mise en place d'un laboratoire d'analyse de malware.
- Positionnement: investigation d'incidents dans un environnement de SOC simulé, orientée pratique.

### TryHackMe
- Nature: plateforme de laboratoires en navigateur.
- Lien: https://tryhackme.com
- Format: nombreuses rooms gratuites, parcours SOC Level 1 et 2 partiellement gratuits.
- Contenu: triage d'alertes, analyse de logs Windows, prise en main de Splunk, Suricata et Zeek, réponse à incident, room dédiée à Wazuh.
- Positionnement: montée en compétence progressive sur les outils de supervision et de détection courants.

### CyberDefenders
- Nature: plateforme de challenges défensifs.
- Lien: https://cyberdefenders.org
- Format: challenges gratuits de forensics et de détection.
- Contenu: investigations sur traces d'attaques réelles, analyse de captures réseau et d'artefacts système.
- Positionnement: entraînement orienté forensics et réponse à incident (DFIR).

## Complément

### Class Central, modules blue et purple
- Nature: agrégateur de cours en ligne.
- Lien: https://www.classcentral.com
- Format: micro-modules gratuits, souvent assortis d'une attestation.
- Contenu: prise en main d'outils open source (Wazuh, Wireshark, Snort, Suricata, Splunk, Autopsy, Security Onion).
- Positionnement: complément ciblé pour la prise en main d'un outil isolé.

## Parcours type

1. MOOC EBIOS Risk Manager: socle méthodologique de gouvernance, format court, certifiant.
2. Atelier RGPD de la CNIL: volet protection des données personnelles, pouvant être suivi en parallèle.
3. Mise en pratique en laboratoire local (Wazuh), appuyée sur les rooms TryHackMe ou les modules gratuits LetsDefend.
4. Guides ANSSI en référence continue, et SecNumacadémie à sa réouverture pour le module NIS2.
