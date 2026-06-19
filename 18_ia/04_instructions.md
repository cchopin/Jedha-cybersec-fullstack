# Module 4 - Prompting, instructions et pré-prompts

Objectif : savoir formuler ce qu'on demande à Copilot - du prompt ponctuel bien construit au contexte permanent figé dans des fichiers. La qualité du prompt et du contexte est le premier facteur de qualité des réponses.

---

## 1. Techniques de prompting efficace

Un bon prompt n'est pas une question vague, c'est une **spécification courte**. Quatre techniques couvrent l'essentiel des besoins.

### 1.1 Être spécifique : objectif + contexte + contraintes

Donner l'objectif, le contexte ciblé et les contraintes (langage, bibliothèque, format de sortie).

> À éviter : « écris une fonction de validation »
> Préférer : « Écris une fonction Python qui valide un IBAN français (longueur, clé de contrôle mod 97). Type hints, docstring, lève `ValueError` si invalide. »

### 1.2 Donner un exemple (*few-shot*)

Quand le format compte, fournir un ou deux exemples entrée → sortie. Le modèle calque le format bien plus fidèlement qu'avec une description.

> « Normalise ces numéros de téléphone au format E.164.
> Exemple : `06 12 34 56 78` → `+33612345678` ; `01.23.45.67.89` → `+33123456789`. »

### 1.3 Piloter par le commentaire (*comment-driven*)

En complétion, écrire d'abord un commentaire d'intention clair, puis la signature : Copilot complète à partir de l'intention. Plus le commentaire est précis, meilleure est la suggestion.

```python
# Découpe une liste en lots de taille n maximum, sans perdre d'élément.
def chunk(items: list, n: int) -> list[list]:
    ...
```

### 1.4 Décomposer et itérer

- **Décomposer** : une grosse tâche en plusieurs prompts simples et vérifiables, plutôt qu'un prompt monolithique. C'est aussi plus économe (voir [module 2](02_economie_tokens.md)).
- **Itérer** : si la réponse n'est pas bonne, **affiner le prompt** (ajouter une contrainte, un exemple) plutôt que de répéter la même demande. Repartir au propre avec `/clear` quand le sujet change.

> Ces techniques valent pour le prompt du moment. Pour ne **pas avoir à les répéter** à chaque session, on fige le contexte récurrent dans des fichiers - c'est l'objet du reste du module.

---

## 2. Les trois familles de personnalisation

| Mécanisme | Déclenchement | Pour quoi |
|-----------|---------------|-----------|
| **Instructions** (`copilot-instructions.md`, `*.instructions.md`, `AGENTS.md`) | Automatique, injecté à chaque requête | Contexte permanent du projet |
| **Prompt files** (`*.prompt.md`) | Manuel, invoqués explicitement | Tâches répétitives réutilisables |
| **Agents** (`*.agent.md`) | Manuel, agent sélectionné | Rôle + périmètre d'outils (voir [module 5](05_agents.md)) |

Distinction clé : **les instructions s'appliquent toujours**, tandis que les prompts et agents se **déclenchent à la demande**.

---

## 3. Instructions de dépôt : `copilot-instructions.md`

Le fichier central. Emplacement :

```
<racine-du-dépôt>/
└── .github/
    └── copilot-instructions.md
```

Son contenu est **injecté automatiquement dans chaque interaction de chat** pour toute personne travaillant sur ce dépôt. C'est le socle commun de l'équipe.

**Ce qui doit y figurer :**
- Pile technique avec **versions** (« Python 3.12, FastAPI, SQLAlchemy 2.x »).
- Conventions : nommage, structure des dossiers, style de code.
- Commandes de build et de test (« tests : `pytest`, lint : `ruff check` »).
- Règles non négociables (« toute fonction publique a un docstring », « pas de `print`, utiliser le logger »).

**Ce qui ne doit PAS y figurer :** secrets, tokens, données sensibles (le fichier est versionné et lu en continu).

**Exemple :**

```markdown
# Instructions projet

## Stack
- Python 3.12, FastAPI, SQLAlchemy 2.x, Pydantic v2
- Tests : pytest. Lint/format : ruff.

## Conventions
- Fonctions et variables en snake_case, classes en PascalCase.
- Toute fonction publique : type hints + docstring (style Google).
- Logging via `app.logger`, jamais de `print`.
- Gestion d'erreur explicite, pas de `except:` nu.

## À éviter
- Pas de nouvelle dépendance sans justification.
- Pas de secret en dur : variables d'environnement uniquement.
```

> Pour la revue de code Copilot sur une pull request, le fichier lu est celui de la **branche de base**, pas de la branche de la pull request.

---

## 4. Instructions ciblées : `*.instructions.md` avec `applyTo`

Pour appliquer des règles à certains fichiers seulement, on crée des fichiers dédiés dans `.github/instructions/`, avec un en-tête `applyTo` (motif glob).

```
.github/instructions/tests.instructions.md
```

```markdown
---
applyTo: "**/*.test.ts"
---

- Utiliser Vitest, pas Jest.
- Un `describe` par fonction testée.
- Nommer les cas en français : `it("rejette un e-mail sans @")`.
```

Le bloc ne s'active que lorsque Copilot travaille sur un fichier correspondant au glob. Utile pour des règles spécifiques (tests, migrations, composants front) sans alourdir les instructions globales.

---

## 5. `AGENTS.md`

Fichier d'instructions « always-on » devenu un standard reconnu par plusieurs outils d'IA (pas uniquement Copilot). Placé à la racine, il joue un rôle proche de `copilot-instructions.md`. Intérêt : **un seul fichier de contexte partagé entre les différents assistants** de l'équipe. En cas d'usage simultané des deux fichiers, éviter de dupliquer la même information.

---

## 6. Prompt files : `*.prompt.md`

Pour les tâches **répétitives**, le prompt est figé dans un fichier réutilisable.

```
.github/prompts/revue-securite.prompt.md
```

```markdown
---
mode: agent
description: Revue de sécurité d'un fichier
---

Analyser le fichier ciblé et signaler :
- injections (SQL, commande, chemin) ;
- secrets en dur ;
- gestion d'erreur absente ou trop large ;
- entrées non validées.

Pour chaque point : ligne, gravité (faible/moyenne/élevée), correctif proposé.
Ne rien inventer : en cas de doute, le signaler.
```

Le prompt s'invoque ensuite dans le chat par son nom. Avantage : toute l'équipe lance **la même** revue, formulée de façon identique, sans la réécrire à chaque fois.

---

## 7. Spec-driven development : la spécification guide l'IA

Au-delà du prompt et des instructions, une pratique structurante : le **spec-driven development** (SDD), ou développement piloté par la spécification. Le principe : on **écrit d'abord la spécification** (objectif, comportement attendu, contraintes, critères d'acceptation), puis l'IA s'appuie sur ce document comme source de vérité pour générer le code.

L'idée clé : la **documentation du projet n'est pas un sous-produit, c'est le point de départ**. Une spec claire et versionnée :
- **guide l'IA** : elle cadre la génération bien mieux qu'une suite de prompts isolés, et limite les dérives (hallucination, hors-sujet) ;
- **sert de prémisse à la documentation finale** : la spec rédigée en amont devient la base de la doc du projet, au lieu d'être reconstituée après coup.

En pratique, la spec rejoint la logique des fichiers de contexte de ce module : un document de référence, stable et partagé, qui oriente chaque génération. On décrit *ce qui doit être fait et pourquoi* ; l'IA propose le *comment*, qu'on relit.

> À retenir : prompts (le moment), instructions (le décor permanent), **spec (l'intention de référence du projet)**. Les trois se complètent.

---

## 8. Hiérarchie : quelle source l'emporte ?

Lorsque plusieurs sources de contexte coexistent, l'ordre général est :

1. Le **prompt** saisi (le plus prioritaire).
2. L'**agent** sélectionné, le cas échéant.
3. Les **instructions** (`*.instructions.md` ciblées, puis `copilot-instructions.md` / `AGENTS.md`).
4. Le contexte implicite (fichiers ouverts, sélection).

En pratique : les instructions posent le décor permanent, le prompt précise la demande du moment.

---

## Exercices

1. **Spécifier vs vague** : poser une demande volontairement vague (« écris une fonction de validation »), noter le résultat. La reposer en version spécifiée (objectif + contexte + contraintes). Comparer.
2. **Few-shot** : demander une transformation de format (ex. normalisation de dates ou de numéros) d'abord sans exemple, puis avec deux exemples entrée → sortie. Mesurer l'écart de fidélité au format.
3. **Comment-driven** : écrire un commentaire d'intention précis suivi d'une signature de fonction, et observer la complétion. Recommencer avec un commentaire vague. Comparer.
4. **Socle projet** : créer un `.github/copilot-instructions.md` pour un projet (stack + versions, conventions, commandes de test). Ouvrir le chat, demander une nouvelle fonction et vérifier qu'elle respecte les conventions sans les avoir rappelées.
5. **Ciblage** : ajouter un `.github/instructions/tests.instructions.md` avec un `applyTo` sur les fichiers de test et une règle de nommage. Demander un test et vérifier que la règle s'applique.
6. **Prompt file** : transformer le prompt de revue de sécurité ci-dessus en `*.prompt.md`, puis le lancer sur un fichier. Comparer avec une demande tapée à la main.
7. **Sans / avec** : poser la même demande de génération dans un projet sans instructions, puis avec. Mesurer ce qui n'a plus eu besoin d'être précisé.
8. **Hygiène** : relire le `copilot-instructions.md` et vérifier l'absence de toute donnée sensible.
9. **Spec-driven** : avant de coder une petite fonctionnalité, rédiger d'abord une courte spec (objectif, comportement, contraintes, critères d'acceptation). Demander la génération à partir de cette spec, puis vérifier ce qui a été cadré sans avoir eu à le repréciser.
