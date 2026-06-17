# Module 8 - Bonnes pratiques

Objectif : transformer tout ce qui précède en réflexes. Ce module est la synthèse opérationnelle de la formation.

---

## 1. Le bon état d'esprit

Copilot est un **collègue junior rapide** : utile, productif, jamais infaillible. L'utilisateur est le senior qui relit, valide et porte la responsabilité. Cette image résume l'essentiel des bonnes pratiques.

- Il **accélère la frappe**, pas le jugement.
- Il **propose**, l'humain **décide**.
- Le code committé engage celui qui le valide, pas « l'IA ».

---

## 2. Workflow type

1. **Cadrer** : objectif clair, contexte ciblé (`#file`), contraintes (langage, bibliothèque, format).
2. **Choisir le mode** : complétion / inline / chat / agent selon l'ampleur ([module 1](01_usage.md)).
3. **Choisir le modèle** : économe par défaut (GPT-5 mini / GPT-5.4 mini), capable si nécessaire (GPT-5.4 / GPT-5.5) - voir [module 2](02_economie_tokens.md).
4. **Générer**.
5. **Relire et comprendre** chaque ligne - `/explain` sur ce qui n'est pas clair.
6. **Tester** : exécution, cas limites, linter, SAST.
7. **Committer** un diff assumé.

---

## 3. Faire travailler le contexte pour soi

Le contexte sépare un usage amateur d'un usage professionnel :
- `copilot-instructions.md` pour le socle projet ([module 4](04_instructions.md)).
- `*.instructions.md` ciblés pour des règles par type de fichier.
- Prompt files pour les tâches répétitives.
- Agents personnalisés en lecture seule pour les analyses récurrentes ([module 5](05_agents.md)).
- Références `#file` précises plutôt que `#codebase` à l'aveugle.

Investir une heure dans ces fichiers fait gagner des semaines de reformulations.

---

## 4. Anti-patterns à bannir

| Anti-pattern | Pourquoi c'est mauvais | À la place |
|--------------|------------------------|-----------|
| `Tab` sans lire | Du code non compris est committé | Lire, `/explain` si besoin |
| Prompt vague reformulé cinq fois | Consommation + temps perdus | Objectif + contexte + contraintes dès le départ |
| `@workspace`/`#codebase` systématique | Coût élevé, réponses diluées | Cibler `#file` quand l'emplacement est connu |
| Modèle lourd pour tâche triviale | Quota mensuel gaspillé | Modèle économe par défaut |
| Secret/donnée réelle dans un prompt | Fuite, non-conformité | Données fictives, exclusions |
| Agent mode sur dépôt non commité | Perte de travail possible | Branche dédiée, diff relu |
| Conversation fleuve | Contexte pollué, coût | `/clear` entre sujets |

---

## 5. Revue du code généré (grille)

Avant de committer du code produit par Copilot :

- [ ] Chaque ligne est **comprise**.
- [ ] La **logique** est correcte, y compris les cas limites.
- [ ] Les **API/bibliothèques** utilisées existent et sont à la bonne version.
- [ ] **Sécurité** : entrées validées, pas d'injection, pas de secret, crypto correcte.
- [ ] Les **dépendances** ajoutées sont légitimes et nécessaires.
- [ ] Le code respecte les **conventions** du projet.
- [ ] Des **tests** couvrent le comportement.
- [ ] Linter et SAST passent.

---

## 6. Bonnes pratiques d'équipe

- Versionner les fichiers de contexte (`copilot-instructions.md`, instructions, prompts, agents) pour un usage homogène.
- Partager les **prompt files** et **agents** utiles plutôt que chacun les réinvente.
- Maintenir les protections d'organisation : **content exclusion** et **filtre de code public** ([module 7](07_securite.md)).
- En revue de pull request, le réviseur humain reste maître : le code généré se relit comme le reste, voire davantage.
- Signaler en équipe les hallucinations marquantes : cela construit une culture commune.

---

## 7. Carte mémoire (à afficher)

```
AVANT      objectif clair · contexte ciblé · contraintes · modèle adapté
PENDANT    bon mode · pas de secret · pas de donnée réelle
APRÈS      lire · comprendre · tester · assumer le commit
JAMAIS     Tab sans lire · secret dans un prompt · agent mode sans branche
```

---

## Exercices

1. **Workflow complet** : prendre une vraie petite tâche et dérouler les sept étapes du §2, en notant à chaque étape la décision (mode, modèle, contexte).
2. **Grille de revue** : appliquer la checklist du §5 à un bout de code généré récemment. Combien de cases auraient été cochées en cas de commit direct ?
3. **Kit d'équipe** : préparer pour un projet le trio `copilot-instructions.md` + un prompt file utile + un agent en lecture seule, puis le présenter à un collègue.
4. **Chasse aux anti-patterns** : sur une journée, relever ses propres anti-patterns du §4 et en corriger au moins deux.
5. **Affichage** : adapter la carte mémoire du §7 au contexte de l'équipe et la diffuser.

---

## Pour aller plus loin

- [Module 9 - Cas pratique](09_cas_pratique.md) pour mettre en application l'ensemble sur une tâche réelle.
- [Module 4 - Instructions](04_instructions.md) pour industrialiser le contexte.
- [Module 5 - Agents](05_agents.md) pour créer des agents personnalisés.
- [Annexe - Notre configuration](annexe_configuration.md) pour l'état réel des fonctionnalités.
- Documentation officielle GitHub Copilot (fonctionnalités, facturation, content exclusion) - à reconsulter régulièrement, l'outil évolue vite.
