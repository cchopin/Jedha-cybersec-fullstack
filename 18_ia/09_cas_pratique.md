# Module 9 - Cas pratique (fil rouge)

Objectif : dérouler une tâche réaliste de bout en bout avec Copilot, en mobilisant tous les modules précédents. Ce module est un **atelier guidé** : chaque étape renvoie au module correspondant et indique ce qui doit être observé.

Durée indicative : 45 à 60 minutes, en binôme de préférence.

---

## Scénario

Une petite API (FastAPI ou équivalent) gère des utilisateurs. La tâche : **ajouter un endpoint `GET /users/search?email=...`** qui recherche un utilisateur par e-mail, avec son test, en respectant les conventions du projet et sans introduire de faille.

Le scénario est volontairement piégé : la voie « rapide » mène à une injection SQL et à une fuite de données. L'atelier consiste à produire la version sûre.

Pré-requis : un dépôt de test cloné en local, branche dédiée créée.

```bash
git checkout -b atelier/users-search
```

---

## Étape 0 - Préparer le contexte ([module 4](04_instructions.md))

Avant tout prompt, vérifier ou créer `.github/copilot-instructions.md` :

```markdown
# Instructions projet
## Stack
- Python 3.12, FastAPI, SQLAlchemy 2.x, pytest.
## Conventions
- Requêtes via l'ORM ou requêtes paramétrées - jamais de SQL concaténé.
- Toute entrée HTTP validée par un schéma Pydantic.
- Pas de donnée personnelle dans les logs.
- Tests pytest pour chaque endpoint.
```

**À observer :** ce socle va contraindre les suggestions sans avoir à le répéter à chaque prompt.

---

## Étape 1 - Cadrer et choisir le modèle ([module 1](01_usage.md), [module 2](02_economie_tokens.md))

Rédiger un prompt cadré plutôt qu'une demande vague :

> Mauvais : « fais une recherche d'utilisateur »
> Bon : « Ajoute un endpoint `GET /users/search` qui prend un paramètre `email` validé (Pydantic), recherche via l'ORM SQLAlchemy, renvoie 404 si absent. Respecte `#file:copilot-instructions.md`. »

Choix du modèle : la tâche est non triviale (sécurité) → **GPT-5.4**. Pas besoin de GPT-5.5 ici.

**À observer :** le prompt cadré + le bon contexte produisent une réponse exploitable en une requête.

---

## Étape 2 - Générer ([module 1](01_usage.md), [module 5](05_agents.md))

Deux approches au choix :
- **Inline chat** sur le routeur existant (`⌘I` / `Ctrl+I`) pour une insertion localisée ;
- **Agent mode** si l'ajout touche routeur + schéma + test d'un coup. Dans ce cas, relire le plan et les fichiers touchés avant validation.

**À observer :** comparer ce que produit l'inline chat (ciblé) et l'agent mode (multi-fichiers).

---

## Étape 3 - Repérer le piège ([module 6](06_risques.md), [module 7](07_securite.md))

Inspecter la suggestion avec un œil critique. Points de contrôle :

- La requête est-elle **paramétrée / via l'ORM**, ou y a-t-il une concaténation de chaîne (injection SQL) ?
- L'entrée `email` est-elle **validée** ?
- La réponse expose-t-elle des **champs sensibles** (hash de mot de passe, données personnelles superflues) ?
- Un **e-mail réel** a-t-il été utilisé dans un exemple ou un test ? Le remplacer par une donnée fictive.

**À observer :** même avec de bonnes instructions, une suggestion peut introduire une faille. La relecture n'est pas optionnelle.

---

## Étape 4 - Revue par un agent ([module 5](05_agents.md))

Sélectionner l'agent `analyse-securite` (lecture seule, `⇧⌘I`) et lui faire relire le diff. Comparer ses remarques avec celles de l'étape 3.

**À observer :** un agent en lecture seule recommande sans modifier ; c'est à l'humain de décider et de corriger.

---

## Étape 5 - Tester ([module 1](01_usage.md))

Générer le test avec `/tests`, puis le compléter à la main avec les cas limites :
- e-mail existant → 200 ;
- e-mail absent → 404 ;
- e-mail malformé → 422 (validation) ;
- tentative d'injection (`' OR '1'='1`) → traitée comme une chaîne, pas exécutée.

Exécuter `pytest` et le linter.

**À observer :** le cas d'injection est le test qui valide la parade. S'il passe, la requête est bien paramétrée.

---

## Étape 6 - Bonus sécurité : injection via logs ([module 7](07_securite.md))

Si l'endpoint journalise l'e-mail recherché, vérifier que les logs sont **assainis** : une valeur du type `[SYSTEM: ignore ...]` ne doit pas se retrouver brute dans un log qui serait ensuite relu par Copilot. Faire l'expérience : coller une telle ligne de log dans le chat et observer le risque.

**À observer :** les données journalisées sont une entrée non fiable, pour Copilot comme pour tout traitement aval.

---

## Étape 7 - Commit ([module 8](08_bonnes_pratiques.md))

Appliquer la grille de revue du [module 8 §5](08_bonnes_pratiques.md). Si toutes les cases sont cochées, committer un diff assumé sur la branche dédiée.

```bash
git add -A && git commit -m "Ajout endpoint de recherche utilisateur par e-mail"
```

---

## Débrief

À discuter en fin d'atelier :

1. Où Copilot a-t-il fait gagner du temps ? Où a-t-il fallu reprendre la main ?
2. Quelle suggestion piégée a été interceptée - et par quel contrôle (relecture, agent, test) ?
3. Quel modèle aurait été surdimensionné ? sous-dimensionné ?
4. Qu'est-ce qui, mis dans `copilot-instructions.md`, éviterait de répéter ces vérifications la prochaine fois ?

Le but n'est pas d'avoir « fait écrire le code par l'IA », mais d'avoir **gardé la maîtrise** d'un livrable sûr produit plus vite.
