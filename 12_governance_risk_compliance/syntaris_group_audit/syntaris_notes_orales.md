# Notes orales, audit Syntaris Group


---

## Slide 1, titre 

Bonjour. Je vous présente les conclusions de l'audit de cybersécurité de Syntaris Group, mené en tant que consultant externe. La mission portait sur deux volets : une évaluation de maturité selon le cadre NIST CSF 2.0, et une revue de conformité au RGPD. J'ai travaillé à partir de cinq sources : le profil de l'entreprise, l'architecture technique, l'historique des incidents, l'entretien des dirigeants et l'inventaire des tiers.

---

## Slide 2, profil de l'entreprise 

Quelques mots de contexte, parce qu'ils déterminent tout le reste. Syntaris est une fintech d'identité et de paiement, fondée en 2017, 284 salariés, 42 millions d'euros de revenu, en forte croissance. Elle traite environ 280 millions d'appels d'API par mois pour 1 100 clients.

Le point crucial pour un audit, c'est la nature des données : non seulement de l'identité et du financier, mais aussi de la biométrie, avec le scan facial du produit IDTrust. La biométrie est une donnée sensible au sens du RGPD, ce qui relève le niveau d'exigence.

Côté cadre, l'entreprise cumule RGPD, PCI-DSS niveau 1, PIPEDA au Canada, et détient déjà ISO 27001. Donc une base de conformité existante, mais un empilement d'obligations à coordonner.

[Transition] Voyons maintenant la synthèse de l'audit.

---

## Slide 3, résumé exécutif 

Le message principal tient en une phrase : Syntaris est solide sur la protection et la réponse à incident, mais fragile sur la gouvernance et la gestion de ses tiers.

Trois risques métier ressortent, et ils ne sont pas théoriques, ils sont tous documentés par des faits.

Premier risque, le plus grave : deux VPN Cisco ASA exposés à une vulnérabilité critique permettant l'exécution de code à distance, divulguée en octobre 2024 et toujours non corrigée. La raison est contractuelle, des clients bancaires imposent ces tunnels, mais le risque reste exploitable.

Deuxième risque : la gestion des demandes RGPD, les DSR, encore faite par email à la main. Ça a déjà coûté quatre dépassements du délai légal en 2021 et une enquête de la CNIL. Pas d'amende, mais un engagement écrit à s'améliorer.

Troisième risque : une détection inégale. Le SOC ne couvre que les heures ouvrées, les postes Mac n'ont pas de télémétrie complète, et la corrélation d'alertes reste limitée. L'incident de la sandbox en 2023 l'a montré, une alerte est restée trois jours sans escalade.

Enfin, l'applicabilité du RGPD est totale : Syntaris est responsable de traitement et parfois sous-traitant, et le traitement de biométrie à grande échelle impose le plus haut niveau de diligence. J'y reviens en détail.

---

## Slide 4, maturité NIST 

Voici l'évaluation de maturité, sur une échelle de 1 à 5, état actuel en orange, cible en bleu.

[Laisser deux secondes pour que le radar soit lu]

La lecture est en trois temps. En vert, Protect et Respond sont les fonctions les plus matures. Pour Protect, on a du PAM avec CyberArk, du MFA, du chiffrement AES-256, une vraie chaîne DevSecOps. Pour Respond, l'exercice de crise du quatrième trimestre 2024 a été cité comme un point fort lors de l'audit ISO 27001, avec un triage en deux heures.

En rouge, Govern et Detect, c'est là que l'écart est le plus marqué. Pour Govern, il n'y a pas de CISO dédié, la responsabilité est partagée entre le directeur sécurité, qui reporte au CTO, et le comité exécutif. C'est un flou qui pose problème en cas d'incident grave. Et la gestion des 37 tiers est immature. Pour Detect, c'est l'angle mort horaire et la couverture incomplète.

En orange, Identify et Recover : un bon socle, mais avec des points ouverts, la CVE du VPN côté Identify, et un plan de reprise à formaliser hors production côté Recover.

La cible que je propose, 4 sur 5 partout, est réaliste, ce n'est pas la perfection, c'est un niveau géré et piloté.

---

## Slide 5, recommandations 

J'ai priorisé les recommandations en trois niveaux.

En haute priorité, trois actions. Un, traiter le VPN Cisco, soit le décommissionner soit l'isoler, ce qui suppose de négocier la migration avec les clients bancaires. Deux, industrialiser les DSR en les intégrant directement dans VaultLock version 2, avec un suivi traçable, pour garantir le délai de 30 jours. Trois, nommer un CISO avec une autorité claire, ce qui résout le problème de gouvernance qu'on a vu.

En priorité moyenne, deux actions structurelles : étendre la couverture du SOC au-delà des heures ouvrées et aux postes Mac, et centraliser la gestion des tiers sur une vraie plateforme GRC tout en mettant à jour les sept contrats encore en termes hérités.

En priorité basse, documenter la sanitisation des données avant l'entraînement des modèles, et rafraîchir le contenu de formation, qui cite encore l'incident British Airways de 2018.

Chaque action est rattachée à une référence NIST ou RGPD, à une équipe responsable et à un impact attendu. C'est volontairement actionnable.

---

## Slide 6, section RGPD 

Le focus RGPD porte sur les quatre articles demandés.

Article 5, les principes : globalement tenus sur l'exactitude et la conservation, mais la minimisation mérite d'être questionnée sur la biométrie. A-t-on vraiment besoin de toutes ces données faciales, et pour combien de temps ?

Article 25, la protection des données dès la conception : Syntaris la revendique, avec des analyses d'impact sur chaque nouveau produit. À nuancer toutefois, car la sanitisation avant entraînement des modèles n'est pas documentée, donc le principe n'est pas tracé partout.

Article 32, la sécurité : c'est le mieux couvert, chiffrement, pseudonymisation, contrôle d'accès, tests réguliers. Le seul vrai angle mort, c'est encore le VPN vulnérable.

Article 33, la notification sous 72 heures : la clause existe dans les contrats avec les tiers, mais l'incident DSR de 2021 a révélé une faiblesse de traçabilité interne. En clair, l'entreprise pourrait avoir du mal à prouver qui a fait quoi et quand.

D'où les améliorations en bas de slide : automatiser et tracer les DSR, formaliser un plan de notification avec preuves, documenter la base légale de la biométrie, et confirmer le rôle et les moyens du DPO existant.

---

## Slide 7, conclusion 

Pour conclure. Syntaris a une base solide, il ne faut pas l'oublier : protection et réponse matures, deux certifications, une vraie culture de retour d'expérience après incident.

Mais trois chantiers sont immédiats et à plus fort effet de levier : le VPN vulnérable, l'industrialisation des DSR, et la nomination d'un CISO.

La trajectoire est claire : on part d'une maturité moyenne de 3,1 sur 5, la cible réaliste est 4,0. Et un bénéfice supplémentaire : renforcer la gouvernance et la détection prépare aussi l'entreprise aux exigences de NIS2 et de DORA, qui s'imposent au secteur financier.

Je suis à votre disposition pour vos questions.

---

## Questions probables et réponses préparées

**Pourquoi ne pas avoir mis Respond à 5 ?**
Parce qu'un seul tabletop réussi ne suffit pas. La maturité 4 reflète une pratique gérée et mesurée ; le 5 supposerait une amélioration continue démontrée sur la durée, notamment des playbooks pour les menaces issues du lab, qui n'existaient pas avant 2023.

**Le VPN est un risque contractuel, que faire concrètement ?**
À court terme, maintenir les mesures compensatoires déjà en place (règles de pare-feu, signatures IDS, redémarrages planifiés). À moyen terme, ouvrir la négociation de migration avec les clients concernés, car le risque résiduel d'une RCE non corrigée dépasse l'appétence affichée par la direction pour les données clients.

**Syntaris est déjà ISO 27001, pourquoi un score Govern aussi bas ?**
ISO 27001 certifie un système de management, pas l'absence de tout écart. L'absence de CISO dédié et l'immaturité de la gestion des tiers sont des constats de gouvernance compatibles avec une certification, mais qui limitent la note sur la fonction Govern du NIST.

**Différence entre appétence et tolérance ici ?**
L'appétence de Syntaris est faible pour toute perte de données clients ou tout manquement de conformité, c'est explicite dans l'entretien. La tolérance opérationnelle est plus souple sur les interruptions de service mineures, mais nulle pour une panne de tokenisation en période de forte charge. Le VPN non corrigé est précisément un cas où le risque dépasse l'appétence déclarée.

**Et NIS2 et DORA, ça s'applique vraiment ?**
DORA vise le secteur financier et ses prestataires informatiques critiques, ce qui correspond au profil de Syntaris et de ses clients. NIS2 dépend de la qualification exacte de l'entité. Les deux renforcent les exigences sur la gestion du risque, la notification d'incident et la chaîne de tiers, soit exactement les fonctions où Syntaris a le plus de marge de progression.
