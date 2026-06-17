# Module 1 - Usage de Copilot dans l'IDE

Objectif : connaître les différentes façons d'utiliser Copilot dans VS Code et savoir laquelle choisir selon la tâche.

---

## 1. Les quatre modes d'usage

Copilot n'est pas une fonctionnalité unique, mais plusieurs surfaces d'interaction. Les confondre fait perdre du temps.

| Mode | Où | Pour quoi |
|------|-----|-----------|
| **Complétion** (ghost text) | Directement dans l'éditeur | Compléter la ligne ou le bloc en cours pendant la frappe |
| **Inline chat** (`⌘I` / `Ctrl+I`) | Dans l'éditeur, sur une sélection | Modifier ou expliquer un bout de code précis sans quitter le fichier |
| **Chat** (panneau latéral) | Panneau Copilot Chat | Questions, génération, raisonnement multi-fichiers |
| **Agent mode** | Panneau de chat, mode « Agent » | Tâches multi-étapes autonomes (édition de plusieurs fichiers, exécution de commandes) |

L'agent mode est **activé** dans l'organisation (voir [annexe](annexe_configuration.md)).

### Complétion (ghost text)

Le texte grisé qui apparaît pendant la frappe. `Tab` pour accepter, `Esc` pour rejeter, `Alt+]` / `Alt+[` pour naviguer entre les suggestions.

Usage adapté : code répétitif, boilerplate, tests à partir d'un nom de fonction explicite, complétion d'un pattern déjà amorcé.

Limite : la suggestion s'appuie sur le fichier courant et quelques fichiers ouverts. Plus le code environnant est clair (noms explicites, commentaire d'intention au-dessus), meilleure est la suggestion.

### Inline chat

`⌘I` (macOS) / `Ctrl+I` (Windows/Linux) sur une sélection. L'interaction reste dans le fichier ; Copilot propose une modification sous forme de diff, à accepter ou rejeter.

Usage adapté : « refactorer cette fonction », « ajouter la gestion d'erreur », « traduire ce commentaire », « expliquer cette ligne ».

### Chat (panneau)

Conversation classique. C'est l'endroit du travail sur plusieurs fichiers, des explications d'architecture, de la génération d'un nouveau composant.

### Agent mode

Le mode le plus puissant et le plus coûteux. L'utilisateur décrit un objectif (« ajouter un endpoint `/health` avec son test ») ; Copilot planifie, édite plusieurs fichiers, lance des commandes du terminal, lit les erreurs et itère.

À utiliser quand la tâche traverse plusieurs fichiers. **Point de vigilance** : l'agent peut exécuter des commandes ; ses actions doivent être relues avant validation (voir [module 6](06_risques.md)).

---

## 2. Slash commands

Dans le chat (panneau ou inline), des raccourcis cadrent l'intention :

| Commande | Effet |
|----------|-------|
| `/explain` | Explique le code sélectionné |
| `/fix` | Propose une correction d'un bug ou d'une erreur |
| `/tests` | Génère des tests pour la sélection |
| `/doc` | Génère de la documentation ou des commentaires |
| `/new` | Échafaude un nouveau projet ou fichier |
| `/clear` | Vide la conversation en cours (réinitialise le contexte) |

`/clear` est important : repartir d'une conversation propre évite que d'anciens échanges polluent le contexte (et la consommation - voir [module 2](02_economie_tokens.md)).

---

## 3. Donner du contexte : références `#` et participants `@`

C'est le levier le plus sous-estimé. Copilot répond mieux lorsqu'on lui désigne explicitement le contexte plutôt que de le laisser deviner.

### Références `#`

| Référence | Contexte ajouté |
|-----------|-----------------|
| `#file` | Un fichier précis |
| `#selection` | La sélection courante dans l'éditeur |
| `#editor` | Le fichier actif visible |
| `#terminalLastCommand` | La dernière commande et sa sortie |
| `#codebase` | Recherche élargie dans le dépôt (Copilot identifie les fichiers pertinents) |

Exemple : `Pourquoi #file:auth.py rejette ce token ? Comparer avec #file:token_utils.py`

### Participants `@`

| Participant | Spécialité |
|-------------|-----------|
| `@workspace` | Connaît la structure du projet ouvert |
| `@vscode` | Questions sur VS Code lui-même |
| `@terminal` | Questions sur le shell et les commandes |

Exemple : `@workspace où est défini le middleware d'authentification ?`

**Règle pratique** : plus la référence est précise (`#file` ciblé), moins Copilot consomme de contexte et plus la réponse est juste. `#codebase` et `@workspace` sont puissants mais coûteux - à réserver aux cas où l'emplacement recherché est inconnu.

---

## 4. Choisir le modèle (model picker)

En bas du panneau de chat, un sélecteur permet de changer de modèle. **Dans l'organisation, seuls les modèles OpenAI GPT-5.x sont activés** ; les modèles Anthropic Claude et Google Gemini sont désactivés (voir [annexe](annexe_configuration.md)).

| Modèle disponible | Profil | Usage conseillé |
|-------------------|--------|-----------------|
| **GPT-5 mini** | Rapide, économe | Complétion, boilerplate, tâches simples |
| **GPT-5.4 mini** | Rapide, économe | Génération courante, tests simples |
| **GPT-5.4** | Capable | Code non trivial, refactor, debug |
| **GPT-5.5** | Le plus capable | Raisonnement complexe, architecture, analyse de sécurité |

Le choix du modèle a un impact direct sur le **coût** (limite mensuelle) et la **qualité**. Voir [module 2](02_economie_tokens.md).

---

## 5. Quel mode pour quelle tâche ?

| Tâche | Mode conseillé |
|-------|----------------|
| Compléter une ligne, du boilerplate | Complétion |
| Refactorer une fonction visible | Inline chat |
| Comprendre du code inconnu | Chat + `/explain` ou `#file` |
| Générer des tests | `/tests` (inline ou chat) |
| Créer une feature sur plusieurs fichiers | Agent mode |
| Question sur le projet | Chat + `@workspace` |

---

## 6. Quand ne PAS utiliser Copilot

Savoir refuser l'assistance fait partie de la maîtrise. Cas où Copilot est à éviter ou à encadrer fortement :

- **Code de sécurité critique** (cryptographie, authentification, contrôle d'accès) : utilisable pour dégrossir, mais la logique doit être conçue et validée par un humain compétent, jamais déléguée.
- **Manipulation de données réelles / sensibles** : ne pas exposer de données personnelles ou de secrets au contexte (voir [module 7](07_securite.md)).
- **Tâche non comprise par l'auteur** : si on est incapable de juger la sortie, on n'est pas en mesure de l'assumer. Apprendre d'abord, générer ensuite.
- **Dépôt non fiable** : ne pas activer le chat/agent sur un projet externe avant d'en avoir inspecté le contenu (voir [module 7](07_securite.md)).
- **Quand c'est plus lent** : pour une modification triviale et évidente, taper directement est souvent plus rapide que formuler un prompt.

Règle simple : Copilot est un accélérateur pour ce qu'on **sait déjà juger**, pas un substitut à la compétence sur ce qu'on ne maîtrise pas.

---

## Exercices

1. **Complétion** : écrire un commentaire `# fonction qui valide une adresse e-mail (RFC simplifiée)` puis le nom de la fonction, et laisser Copilot compléter. Observer la qualité avec et sans le commentaire d'intention.
2. **Inline chat** : sélectionner une fonction existante, faire `⌘I` / `Ctrl+I`, demander « ajoute la gestion des cas d'erreur et un docstring ». Accepter ou rejeter le diff.
3. **Références** : dans le chat, poser une question en ciblant deux fichiers précis avec `#file`, puis la reposer avec `#codebase`. Comparer la pertinence et la longueur des réponses.
4. **Agent mode** : sur un projet de test, demander « ajoute un endpoint `/version` qui renvoie la version du package, avec son test ». Observer les étapes, les fichiers touchés et les commandes proposées avant validation.
5. **Modèle** : poser une même demande simple successivement avec GPT-5 mini puis GPT-5.5, et comparer résultat et temps de réponse.
