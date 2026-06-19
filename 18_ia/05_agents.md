# Module 5 - Agents

Objectif : maîtriser les agents Copilot - distinguer l'**agent mode** (capacité autonome de Copilot) des **agents personnalisés** (profils définis par l'équipe), savoir en créer, et cadrer leur périmètre d'action.

Ce module est autonome : il contient tout le nécessaire pour comprendre et créer un agent.

---

## 1. Deux notions distinctes

| | Agent mode | Agent personnalisé |
|---|-----------|--------------------|
| Nature | Un **mode** de Copilot qui agit en plusieurs étapes | Un **profil** (nom, instructions, outils) défini par l'équipe |
| Emplacement | Sélecteur de mode dans le chat | Fichier `.github/agents/*.agent.md` |
| Effet | Édite plusieurs fichiers, lance des commandes, itère sur les erreurs | Remplace le prompt système par celui défini, restreint les outils |
| Déclenchement | Activation du mode | Sélection de l'agent dans la liste |

Les deux se combinent : un agent personnalisé peut s'exécuter en agent mode avec un périmètre d'outils limité. Dans l'organisation, l'**agent mode est activé** (voir [annexe](annexe_configuration.md)).

> **Vocabulaire.** Le terme varie d'un outil à l'autre : ce que Copilot appelle « agent (personnalisé) » correspond, dans d'autres écosystèmes, à ce qu'on nomme « skill » (par exemple chez Anthropic / Claude). Même idée : un profil de capacité réutilisable, avec instructions et périmètre. Ne pas se laisser perdre par le vocabulaire d'un fournisseur à l'autre.

---

## 2. Agent mode

L'utilisateur décrit un **objectif**, non une suite d'instructions. Copilot :

1. planifie les étapes ;
2. lit les fichiers utiles (`#codebase`) ;
3. édite plusieurs fichiers ;
4. lance des commandes (tests, build) ;
5. lit les erreurs et corrige.

**Quand l'utiliser** : tâche traversant plusieurs fichiers (« ajoute un endpoint + son test + sa doc »), migration mécanique, correction d'une suite de tests cassés.

**Points de vigilance :**
- L'agent peut **exécuter des commandes** : ses actions doivent être relues avant validation, en particulier les commandes destructives ou réseau. La barre du chat affiche un niveau d'approbation (« Default Approvals ») qui gouverne ce qui requiert une confirmation manuelle.
- Il **consomme davantage** (allers-retours, outils) : à éviter pour une micro-tâche (voir [module 2](02_economie_tokens.md)).
- La responsabilité du diff final reste humaine : relecture et tests obligatoires (voir [module 6](06_risques.md)).

> Doc officielle : [Agent mode dans le chat VS Code](https://code.visualstudio.com/docs/copilot/chat/chat-agent-mode).

> La connexion à des serveurs **MCP** étendrait les actions de l'agent à des outils externes, mais le **MCP est désactivé** dans l'organisation (voir [annexe](annexe_configuration.md)).

### Travailler sur une branche dédiée (et finir en PR)

L'agent mode agit dans le **répertoire et la branche courants** : il faut donc s'assurer **avant de lancer** qu'on est au bon endroit.

1. **Créer/basculer sur une branche dédiée** : `git checkout -b feat/ma-tache`. Une tâche = une branche, jamais directement sur `main`.
2. **Vérifier la branche active** avant de lancer : `git branch --show-current` (ou l'indicateur de branche en bas à gauche de VS Code).
3. **Partir d'un arbre propre** : ne pas lancer l'agent avec des changements non commités importants - il les mélangerait à son travail. Au besoin, `git stash` d'abord.
4. **Relire avant de committer** : examiner le `git diff` complet, puis committer. L'agent **ne pousse pas en direct** : la branche part en **pull request** pour relecture humaine et CI.
5. **Isoler plusieurs agents/tâches en parallèle** : un **worktree** Git dédié par tâche (`git worktree add ../tache-x feat/tache-x`) évite que deux exécutions se marchent dessus.

> Garde-fou complémentaire : bloquer les commandes Git destructives (`git push`, `git reset`, `git clean`) via la deny-list d'auto-approbation, pour qu'elles exigent toujours une confirmation (voir [module 3](03_configuration.md)). Risques associés détaillés au [module 6](06_risques.md).

---

## 3. Qu'est-ce qu'un agent personnalisé ?

Un agent personnalisé est un **profil de comportement** : un nom, une description, des instructions système et une liste d'outils autorisés. Lorsqu'il est sélectionné dans le chat, il remplace le prompt système par défaut de Copilot par celui qui a été défini.

Concrètement, cela permet :
- d'adopter un **rôle précis** (analyste sécurité, relecteur, rédacteur…) ;
- de **contraindre le périmètre d'outils** (lecture seule, ou écriture également) ;
- d'imposer des **règles de format et de ton** ;
- éventuellement d'imposer un **modèle** parmi ceux disponibles.

L'usage le plus simple est manuel : on sélectionne un agent et il reste actif jusqu'à changement. VS Code permet toutefois d'aller plus loin avec les **subagents** (un agent peut en appeler un autre) et les **handoffs** (transitions guidées d'un agent vers un autre) - voir §6.

---

## 4. Créer un agent

### Emplacement du fichier

```
<racine-du-dépôt>/
└── .github/
    └── agents/
        └── mon-agent.agent.md
```

VS Code détecte automatiquement les fichiers `*.agent.md` placés dans `.github/agents/` à la racine du dépôt ouvert. Aucune configuration supplémentaire n'est requise. Doc officielle : [Custom agents](https://code.visualstudio.com/docs/agent-customization/custom-agents) (VS Code).

### Syntaxe

```markdown
---
name: nom-de-l-agent
description: Une ligne affichée dans le sélecteur. Être précis - c'est ce qui aide à choisir le bon agent.
model: GPT-5.4              # optionnel - retirer la ligne pour utiliser le modèle actif du chat
tools: ['search', 'edit']  # restreindre les outils réduit les risques et le coût
user-invocable: true       # l'agent apparaît dans le menu (valeur par défaut)
---

Instructions système. Tout ce qui suit l'en-tête constitue le prompt système de l'agent.

Décrire :
- le rôle de l'agent (ce qu'il est, pas seulement ce qu'il fait) ;
- ce qu'il produit (format de sortie attendu) ;
- ce qu'il ne fait pas (limites explicites).
```

### Principaux champs de l'en-tête

| Champ | Rôle |
|-------|------|
| `name` | Identifiant affiché dans le menu (nom du fichier si omis) |
| `description` | Une ligne d'aide affichée dans le chat |
| `tools` | Liste des outils autorisés pour cet agent |
| `model` | Modèle(s) à utiliser ; le modèle actif du chat par défaut |
| `agents` | Liste des subagents que cet agent peut appeler (`*` pour tous, `[]` pour aucun) |
| `handoffs` | Transitions guidées vers d'autres agents (voir §6) |
| `user-invocable` | Visibilité dans le menu d'agents (défaut `true`) |
| `disable-model-invocation` | Empêche d'être appelé **comme subagent** par un autre agent (défaut `false`) |
| `target` | Périmètre : `vscode` ou `github-copilot` |
| `mcp-servers` | Serveurs MCP accessibles (sans objet ici, MCP désactivé) |

### Outils (`tools`)

Les outils sont désignés par des **identifiants nommés** (outils intégrés, tool sets, outils d'extensions). Exemples : `search`, `search/codebase`, `search/usages`, `edit`, `read/terminalLastCommand`, `web/fetch`, `agent` (nécessaire pour appeler des subagents). Dans le corps du fichier, un outil se référence avec la syntaxe **`#tool:<nom>`** (par ex. `#tool:web/fetch`).

> La liste exacte des outils disponibles dépend de la version de VS Code et des extensions installées. Le plus simple pour la découvrir : la commande **`Chat: New Custom Agent`** (palette `⇧⌘P`), qui propose un sélecteur d'outils.

Pour un agent d'analyse ou de revue, se limiter aux outils de **lecture/recherche** (`search`, `search/codebase`) sans `edit` : **restreindre les outils est le premier levier de sécurité** - un agent sans `edit` ni outil d'exécution ne peut rien casser.

### Modèle

Le champ `model` est optionnel et accepte le **nom tel qu'affiché** dans le sélecteur. Dans l'organisation, seuls les modèles **OpenAI GPT-5.x** sont disponibles (`GPT-5 mini`, `GPT-5.4 mini`, `GPT-5.4`, `GPT-5.5`). En l'absence de ce champ, l'agent utilise le modèle actif dans le chat. Privilégier un modèle économe pour les agents simples (voir [module 2](02_economie_tokens.md)).

### Garder l'agent court

Un fichier d'agent doit rester **concis et focalisé : viser 200 lignes maximum**. Un agent trop long se dilue, devient difficile à maintenir, et l'IA en suit moins fidèlement les consignes.

Au-delà, c'est généralement le signe qu'on y a glissé du **contexte général du projet** (conventions, stack, règles transverses) qui n'a pas sa place dans un agent : ce contenu va dans les **fichiers d'instructions « always-on »** (`AGENTS.md`, `copilot-instructions.md` - voir [module 4](04_instructions.md)), partagés par tous les agents et tout le chat. L'agent ne garde que ce qui est **propre à son rôle**.

> Certains outils disposent en plus d'un fichier **mémoire** dédié pour ce contexte durable ; chez Copilot, **Copilot Memory est désactivé** dans l'organisation (voir [annexe](annexe_configuration.md)) - on s'appuie donc sur les fichiers d'instructions.

---

## 5. Sélectionner un agent dans VS Code

Dans le panneau Copilot Chat :

1. Ouvrir le sélecteur d'agent - clic sur le mode actif en bas du chat, ou raccourci **`⇧⌘I`**.
2. La liste affiche les agents disponibles (par exemple : `analyse-securite`, `cadrage`, `optimisation-cout`, `redaction-rapport`, `redaction-recommandations`, `revue-code`), ainsi que l'entrée **« Configure Custom Agents… »** pour les gérer.
3. Sélectionner l'agent voulu. L'agent et le modèle actifs s'affichent dans la barre du bas, avec le niveau d'effort et la taille de la fenêtre de contexte (ex. `GPT-5.4 · Medium · 272K`).

Autres accès : taper **`/agents`** dans le chat ouvre le menu « Configure Custom Agents » ; la commande **`Chat: New Custom Agent`** (palette `⇧⌘P`) crée un nouvel agent avec un sélecteur d'outils.

L'agent sélectionné reste actif jusqu'à changement manuel. Pour empêcher qu'un agent soit visible dans ce menu, mettre `user-invocable: false` ; pour l'empêcher d'être appelé **comme subagent** par un autre agent, mettre `disable-model-invocation: true`.

> **Sur les conversations longues, l'IA peut « se perdre »** : oublier son rôle, mélanger les consignes, se mettre à halluciner. Réflexe simple : lui **demander de relire son agent** (« relis tes instructions d'agent et reprends ») pour la recadrer, ou repartir au propre avec `/clear`.

---

## 6. Aller plus loin : subagents et handoffs

VS Code permet de composer plusieurs agents. Deux mécanismes, à connaître mais à utiliser avec parcimonie :

- **Subagents** : un agent peut en appeler un autre pour déléguer une sous-tâche. Cela nécessite l'outil `agent` dans `tools` et le champ `agents` listant les agents appelables (`['analyse-securite']`, `*` pour tous, `[]` pour aucun). Un agent qui ne doit jamais être appelé par un autre porte `disable-model-invocation: true`.
- **Handoffs** : transitions *guidées* d'un agent vers un autre, présentées sous forme de boutons. Chaque handoff définit un `label`, l'`agent` cible et un `prompt` à transmettre (et `send: true` pour l'envoyer automatiquement).

```yaml
handoffs:
  - label: Lancer l'analyse de sécurité
    agent: analyse-securite
    prompt: Analyse le code produit ci-dessus.
    send: false
```

Cas d'usage typique : un agent `cadrage` qui propose, en fin de réponse, un handoff vers un agent d'implémentation, puis vers `analyse-securite`. **Précaution** : chaque maillon ajoute des appels (coût) et de l'autonomie (risque) - réserver ces chaînes à des workflows bien rodés, et garder la relecture humaine entre les étapes sensibles.

---

## 7. Exemples d'agents utiles en équipe

| Agent | Outils | Rôle |
|-------|--------|------|
| `analyse-securite` | `['search', 'search/codebase']` | Applique une grille d'analyse de sécurité, sans rien modifier |
| `revue-code` | `['search', 'search/codebase']` | Relit un diff selon les conventions du projet |
| `cadrage` | `['search']` | Aide à structurer une tâche avant implémentation |
| `redaction-rapport` | `['search', 'edit']` | Produit un rapport à partir d'éléments du dépôt |
| `redaction-recommandations` | `['search', 'edit']` | Formalise des recommandations |
| `optimisation-cout` | `['search', 'search/codebase']` | Analyse et propose des pistes d'optimisation |

Les agents d'analyse et de revue restent **en lecture seule** : ils observent et recommandent, ils ne touchent pas au code.

### Exemple complet : agent de revue de sécurité

```markdown
---
name: analyse-securite
description: Relecture de sécurité en lecture seule - signale vulnérabilités et mauvais usages.
model: GPT-5.5
tools: ['search', 'search/codebase']
---

Rôle : analyste sécurité. Relire le code fourni et signaler, sans rien modifier :
- injections (SQL, commande, chemin) ;
- secrets en dur ;
- entrées non validées ;
- gestion d'erreur trop large ;
- usage de crypto faible ou obsolète.

Format de sortie : un tableau (fichier, ligne, gravité faible/moyenne/élevée, problème, correctif proposé).
Ne jamais proposer de modification directe. En cas de doute, le signaler plutôt que d'affirmer.
```

---

## 8. Choisir la bonne approche

| Besoin | Solution |
|--------|----------|
| Une tâche multi-fichiers ponctuelle | Agent mode, prompt direct |
| La même analyse refaite souvent, à l'identique | Agent personnalisé (lecture seule) |
| Limiter ce que l'IA peut toucher | Agent personnalisé avec `tools` restreints |
| Réutiliser un prompt sans changer de rôle | Prompt file (voir [module 4](04_instructions.md)) |

---

## Exercices

1. **Agent mode** : sur un projet de test, demander une feature traversant deux ou trois fichiers. Observer le plan, les fichiers touchés et les commandes avant validation.
2. **Création** : créer un agent `analyse-securite` en lecture seule (`tools: ['search', 'search/codebase']`) à partir de l'exemple ci-dessus, via la commande `Chat: New Custom Agent` ou directement dans `.github/agents/`. Le sélectionner (`⇧⌘I`) et le lancer sur un fichier. Vérifier qu'il ne propose aucune modification.
3. **Périmètre** : comparer le comportement d'un même rôle sans puis avec l'outil `edit`. Noter la différence de risque (lecture seule vs capacité de modifier).
4. **Sélecteur** : ouvrir le sélecteur d'agent, repérer les agents existants et l'entrée « Configure Custom Agents… ». Identifier dans la barre du bas le modèle, l'effort et la fenêtre de contexte actifs.
5. **Décision** : pour trois tâches récurrentes de l'équipe, déterminer ce qui relève de l'agent mode, d'un agent personnalisé ou d'un simple prompt file.
6. **Discipline Git** : avant une tâche en agent mode, créer une branche dédiée (`git checkout -b feat/test`), vérifier la branche active, lancer la tâche, puis relire le `git diff` complet avant tout commit. Constater que rien n'a touché `main`.
