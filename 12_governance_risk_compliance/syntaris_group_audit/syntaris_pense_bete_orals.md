# Pense-bête oral, audit Syntaris

---

## 1. Titre (20 s)
- Audit cyber, rôle = consultant externe
- 2 volets : maturité NIST CSF 2.0 + conformité RGPD
- Basé sur **5 docs** : profil, infra, incidents, interview dirigeants, tiers

---

## 2. Profil entreprise (45 s)
- Fintech identité + paiement, **284 salariés**, **42 M€**, croissance **+37%/an**
- **280 M appels API/mois**, **1 100 clients**
- Clé : données **biométriques** (scan facial IDTrust) = données sensibles RGPD → exigence ++
- Empilement réglementaire : RGPD + PCI-DSS + PIPEDA + déjà ISO 27001


---

## 3. Résumé exécutif (1 min)
**Phrase clé : solides sur Protect/Respond, fragiles sur Govern et tiers**

3 risques (tous factuels, pas théoriques) :
1. **VPN Cisco ASA** : CVE critique RCE, non corrigée depuis **oct. 2024**, raison contractuelle (clients banque)
2. **DSR manuels** par email : **4 dépassements** du délai en 2021 → **enquête CNIL** (pas d'amende mais engagement écrit)
3. **Détection inégale** : SOC heures ouvrées only, Mac sans télémétrie, sandbox 2023 = alerte ignorée **3 jours**

- RGPD applicable à 100% : responsable de traitement + parfois sous-traitant
- Biométrie à grande échelle = diligence max

---

## 4. Maturité NIST (1 min 30) - slide radar
*Laisser 2 s pour lire le radar*
- Échelle **1 à 5**, orange = actuel, bleu = cible

3 groupes :
- VERT **Protect + Respond** = top : PAM CyberArk, MFA, AES-256 / tabletop Q4 2024 cité à l'audit ISO, triage en **2h**
- ROUGE **Govern + Detect** = écart max : **pas de CISO**, resp. partagée (flou), **37 tiers** mal gérés, angle mort horaire
- ORANGE **Identify + Recover** = bon socle mais CVE VPN + PRA à formaliser

- Cible **4/5** partout = réaliste (géré/piloté, pas la perfection)

---

## 5. Recommandations (1 min 30) - tableau
**Haute** (3) :
- VPN : décommissionner/isoler + négocier migration clients
- DSR : intégrer dans VaultLock v2, traçable, délai **30 j**
- Nommer un **CISO** (règle le pb Govern)

**Moyenne** (2) :
- SOC : étendre hors heures ouvrées + Mac
- Tiers : plateforme GRC + MAJ des **7 contrats** hérités

**Basse** (2) :
- Doc sanitisation données ML
- Rafraîchir formation (cite encore BA 2018)

→ chaque action = réf NIST/RGPD + équipe + impact

---

## 6. RGPD (1 min 30) - 4 articles
- **Art. 5** principes : OK exactitude/conservation, MAIS minimisation à questionner sur biométrie
- **Art. 25** privacy by design : revendiqué (DPIA), à nuancer (sanitisation ML pas documentée)
- **Art. 32** sécurité : le mieux couvert (chiffrement, pseudo, RBAC), angle mort = VPN
- **Art. 33** notif 72h : clause dans contrats tiers, MAIS faiblesse traçabilité interne (incident DSR)

Améliorations : automatiser DSR / plan notif avec preuves / base légale biométrie / confirmer DPO

---

## 7. Conclusion (45 s)
- Ne pas oublier : **base solide** (protect+respond, 2 certifs, culture post-mortem)
- 3 chantiers immédiats = VPN, DSR, CISO
- Trajectoire : **3,1 → 4,0**
- Bonus : renforce aussi vers **NIS2 + DORA** (secteur financier)


---

## Questions/Réponses

**Pourquoi Respond pas à 5 ?**
1 seul tabletop réussi =/= amélioration continue prouvée. Playbooks lab absents avant 2023.

**VPN = risque contractuel, on fait quoi ?**
Court terme = mesures compensatoires déjà en place (pare-feu, IDS, reboots). Moyen terme = négocier migration, car RCE non corrigée > appétence direction.

**Déjà ISO 27001, pourquoi Govern bas ?**
ISO certifie un système de management, pas zéro écart. Pas de CISO + tiers immatures = constats compatibles avec la certif mais qui plombent la note Govern NIST.

**Appétence vs tolérance ?**
Appétence faible pour perte données clients / non-conformité (explicite dans l'interview). Tolérance souple sur petites coupures, nulle sur panne tokenisation en forte charge. VPN = cas où risque > appétence.

**NIS2 / DORA s'appliquent ?**
DORA = secteur financier + prestataires IT critiques = profil Syntaris. NIS2 selon qualification. Les 2 renforcent risque + notif + tiers = pile où Syntaris a le plus de marge.

---
