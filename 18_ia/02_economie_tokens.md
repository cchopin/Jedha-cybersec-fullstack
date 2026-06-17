# Module 2 - Économie de tokens et de coût

Objectif : comprendre ce qui consomme la limite mensuelle de Copilot et adopter des réflexes qui réduisent la consommation sans dégrader le résultat.

---

## 1. Token, contexte, requête : de quoi parle-t-on ?

- **Token** : unité de découpage du texte (environ 4 caractères, ou trois quarts d'un mot en anglais). Le code, les fichiers joints, l'historique de conversation et la réponse sont tous comptés en tokens.
- **Fenêtre de contexte** : quantité de tokens que le modèle peut traiter d'un coup (prompt + fichiers + historique). Dans la configuration de l'organisation, elle est de **272K** tokens (visible dans la barre du chat). Au-delà, le contenu le plus ancien est tronqué.
- **Requête** : un envoi au modèle. Elle décompte la **limite mensuelle** du plan.

Deux leviers de coût : **le volume de tokens** envoyés et reçus, et **le modèle** qui les traite.

---

## 2. Suivre sa consommation

La consommation se consulte sur la page des paramètres Copilot :

**https://github.com/settings/copilot/features**

On y trouve la section **Usage** : la **limite mensuelle** (« Monthly Limit »), le pourcentage déjà consommé et la **date de réinitialisation** (réinitialisation mensuelle). C'est l'endroit de référence pour savoir où en est le quota avant la fin du cycle.

Le plan de l'organisation est **GitHub Copilot Business**. Atteindre la limite suspend l'accès aux fonctionnalités premium jusqu'à la réinitialisation : d'où l'intérêt de consommer juste.

---

## 3. Ce qui fait gonfler la consommation

| Cause | Pourquoi ça coûte | Réflexe |
|-------|-------------------|---------|
| Conversation interminable | Tout l'historique est renvoyé à chaque message | `/clear` au changement de sujet |
| `@workspace` / `#codebase` systématique | Copilot indexe et envoie beaucoup de fichiers | Cibler avec `#file` quand l'emplacement est connu |
| Gros fichiers joints inutilement | Tokens d'entrée multipliés | Sélectionner la portion utile, pas le fichier entier |
| Modèle lourd pour tâche triviale | Coût plus élevé pour un résultat identique | Modèle économe pour le simple (voir §4) |
| Agent mode pour une micro-tâche | Multiples allers-retours | Inline chat suffit souvent |
| Reformuler cinq fois un prompt flou | Cinq requêtes au lieu d'une | Soigner le premier prompt (contexte + objectif) |

> La **revue de code Copilot** (Copilot code review, activée dans l'organisation) est une fonctionnalité utile mais qui consomme plus qu'une requête simple : à employer à bon escient.

---

## 4. Choisir le bon modèle

Règle simple : **commencer économe, monter en puissance uniquement si nécessaire.** Dans l'organisation, seuls les modèles OpenAI GPT-5.x sont disponibles.

| Type de tâche | Modèle |
|---------------|--------|
| Complétion, boilerplate, renommage, regex simple | **GPT-5 mini** |
| Génération de code courante, tests unitaires | **GPT-5.4 mini** |
| Code non trivial, refactor, debug | **GPT-5.4** |
| Raisonnement complexe, architecture, analyse de sécurité | **GPT-5.5** |

Employer GPT-5.5 pour compléter une boucle `for` revient à payer cher un résultat identique à celui d'un modèle mini.

> La barre du chat affiche aussi un **niveau d'effort** (ex. « Medium »). Un effort plus élevé améliore le raisonnement mais consomme davantage : à réserver aux tâches qui le justifient.

---

## 5. Écrire des prompts économes (et efficaces)

Un bon prompt réduit le coût **et** améliore la réponse ; les deux vont ensemble.

**Structure d'un prompt efficace :**
1. **Objectif** clair et unique : « génère un test pour `parse_date` » plutôt que « occupe-toi des tests ».
2. **Contexte ciblé** : `#file` précis plutôt que `#codebase`.
3. **Contraintes** : langage, style, bibliothèque imposée, format de sortie attendu.
4. **Exemple** si le format compte (entrée → sortie attendue).

**À éviter :**
- Les prompts vagues qui imposent des reformulations.
- Recoller tout un fichier dans le chat alors qu'il peut être référencé avec `#file`.
- Conserver une conversation de quarante messages pour une nouvelle question sans rapport.

---

## 6. Réflexes quotidiens

- `/clear` entre deux sujets sans rapport.
- Préférer l'**inline chat** (contexte = sélection) au **chat panneau** quand la tâche est locale.
- Référencer (`#file`) plutôt que copier-coller.
- Laisser un **modèle économe par défaut**, monter ponctuellement.
- Surveiller la consommation sur https://github.com/settings/copilot/features.

---

## Exercices

1. **Consommation** : ouvrir https://github.com/settings/copilot/features, relever le pourcentage consommé et la date de réinitialisation. Identifier l'activité de la semaine qui pèse le plus.
2. **Modèle** : poser la même demande simple (« écris une fonction qui inverse une chaîne ») avec GPT-5 mini puis GPT-5.5. Comparer résultat et temps. Conclure sur le bon choix pour ce type de tâche.
3. **Contexte ciblé** : poser une question en `#codebase`, noter la longueur de la réponse, puis la reposer en ciblant le bon `#file`. Comparer.
4. **Prompt** : reprendre un prompt vague ayant nécessité plusieurs reformulations. Le réécrire avec la structure objectif / contexte / contraintes et vérifier qu'une seule requête suffit.
5. **Hygiène de session** : travailler dix minutes dans une seule longue conversation, puis recommencer en utilisant `/clear` à chaque changement de sujet. Noter la différence de pertinence.
