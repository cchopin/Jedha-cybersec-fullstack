# Module 3 - Configuration

Objectif : savoir régler Copilot dans VS Code, et distinguer ce qui relève du poste de travail de ce qui est imposé par l'organisation.

---

## 1. Trois niveaux de réglage

VS Code expose les réglages à trois niveaux, du plus large au plus précis :

| Niveau | Fichier | Portée |
|--------|---------|--------|
| Utilisateur | `settings.json` (global) | Tous les projets de la machine |
| Espace de travail | `.vscode/settings.json` | Le projet courant (versionnable, partagé avec l'équipe) |
| Organisation | Paramètres GitHub Copilot | Imposé par l'administration, prioritaire |

Réflexe d'équipe : les réglages qui doivent valoir pour **tout le monde sur le projet** vont dans `.vscode/settings.json` (versionné). Les préférences personnelles vont dans le `settings.json` utilisateur. Les paramètres d'organisation, eux, ne se modifient pas côté poste - ils se consultent sur https://github.com/settings/copilot/features (voir [annexe](annexe_configuration.md)).

Accès rapide : `⌘,` / `Ctrl+,` puis rechercher « copilot », ou éditer le JSON via la palette (`Preferences: Open User Settings (JSON)`).

---

## 2. Réglages utiles côté poste

```jsonc
{
  // Activer/désactiver la complétion par langage
  "github.copilot.enable": {
    "*": true,
    "plaintext": false,
    "markdown": false,
    "yaml": true,
    // couper Copilot sur les fichiers sensibles
    "dotenv": false
  },

  // Suggestions inline
  "github.copilot.inlineSuggest.enable": true,

  // Langue des réponses du chat
  "github.copilot.chat.localeOverride": "fr"
}
```

Points clés :
- **Désactiver par langage** : utile pour couper la complétion sur des fichiers où elle n'apporte rien ou risque d'exposer des données (`.env`, fichiers de secrets, notes).
- **Suspension rapide** : l'icône Copilot dans la barre d'état permet de suspendre la complétion d'un clic (utile en pair programming, en démo ou en réunion partagée).

---

## 3. Exclure du contenu (content exclusion)

Réglage central pour la sécurité : il empêche Copilot de **lire** certains fichiers ou chemins comme contexte, donc de les envoyer au modèle ou de s'en inspirer.

Ce contrôle se configure côté **organisation ou dépôt**, par l'administration GitHub. Les chemins exclus ne sont jamais utilisés comme contexte, ni en complétion, ni en chat.

Contenu typiquement exclu :
- Fichiers de secrets : `.env`, `*.pem`, `*.key`, `secrets/**`.
- Données clients, dumps, jeux de données réels.
- Code confidentiel à ne pas voir réutilisé.

> Détail développé au [module 7 - Sécurité](07_securite.md). À retenir ici : la content exclusion est une **barrière de configuration**, à demander à l'administration plutôt qu'à reposer sur la seule discipline individuelle.

---

## 4. Intégration MCP (Model Context Protocol)

Le **MCP** est un protocole standard qui connecte l'agent mode à des **serveurs externes** fournissant outils et données : accès à une base, à une API interne, à un système de tickets, mais aussi des **connecteurs métier** (SharePoint, messagerie, Excel/Office, Google Drive…).

> **Dans l'organisation, « MCP servers in Copilot » est désactivé** (voir [annexe](annexe_configuration.md)). Toute cette section est fournie à titre d'information et de préparation : la connexion de serveurs MCP n'est pas disponible en l'état. En cas d'activation ultérieure par l'administration, les précautions ci-dessous s'appliquent.

### 4.1 La valeur : au-delà du code, des usages métier

L'intérêt du MCP ne se limite pas au développement. Les **connecteurs vers les outils bureautiques** ouvrent des cas d'usage pour des **métiers hors IT** :
- interroger en langage naturel un corpus de documents SharePoint (« retrouve la dernière version de la procédure X ») ;
- résumer ou trier une boîte mail, préparer des réponses ;
- extraire, croiser et mettre en forme des données depuis des classeurs Excel.

C'est là une grande partie du potentiel - et, symétriquement, du risque : ces connecteurs donnent à l'IA un **accès direct à des données d'entreprise**, souvent sensibles, bien au-delà du seul code source.

### 4.2 Les risques : chaque serveur élargit la surface d'attaque

Un serveur MCP **étend la surface d'action** de Copilot : à traiter comme une **dépendance de sécurité** à part entière, au même titre qu'une bibliothèque tierce.

**Serveurs externes (tiers).**
- Code tiers exécuté sur le poste : un serveur malveillant ou compromis peut exfiltrer des données, lire des fichiers ou injecter des instructions dans le contexte (prompt injection - voir [module 7](07_securite.md)).
- Chaîne d'approvisionnement : un paquet installé (`npx`, etc.) peut être piégé ou détourné (typosquatting), comme toute dépendance.

**Serveurs internes.** Un serveur développé en interne n'est **pas sûr par défaut**. Monté vite, sans revue, il peut être une vraie **passoire** : droits trop larges, authentification absente, journalisation insuffisante, exposition de plus de données que nécessaire. « Interne » ne vaut pas « de confiance » - un serveur interne se revoit aussi.

**Connecteurs (SharePoint, mail, Excel…).** Plus la valeur métier est forte, plus l'accès est large : un connecteur mail ou SharePoint peut exposer **toute** la boîte ou tout l'espace documentaire. Périmètre, comptes de service et habilitations doivent être cadrés au plus juste (**moindre privilège**).

### 4.3 Structure d'une configuration (pour mémoire)

```jsonc
// .vscode/mcp.json
{
  "servers": {
    "mon-serveur": {
      "command": "npx",
      "args": ["-y", "@exemple/mcp-server"]
    }
  }
}
```

### 4.4 Précautions si le MCP venait à être activé
- N'installer que des serveurs **de confiance**, validés par l'équipe ou l'administration (internes comme externes).
- Appliquer le **moindre privilège** : périmètre, comptes de service et habilitations réduits au strict nécessaire, en particulier pour les connecteurs métier.
- Aucun credential en clair : variables d'environnement ou gestionnaire de secrets.
- Relire les actions de l'agent passant par un outil MCP (lecture/écriture, réseau) avant validation.

---

## 5. Encadrer l'agent : approbations, commandes interdites et droits

L'agent mode **exécute des commandes** et **édite des fichiers**. VS Code permet de cadrer ce qu'il peut faire **sans confirmation** et ce qui doit rester **interdit ou validé manuellement**. Ces réglages sont des entrées de `settings.json`, plaçables aux niveaux vus au [§1](#1-trois-niveaux-de-réglage).

### 5.1 Commandes terminal : auto-approuver le sûr, bloquer le dangereux

Le réglage `chat.tools.terminal.autoApprove` associe des motifs de commandes à `true` (auto-approuvé) ou `false` (confirmation toujours requise). Les motifs entre `/.../` sont des expressions régulières. **Règle d'or : le `false` l'emporte** - si une commande correspond à un motif `false`, elle ne sera jamais auto-approuvée, quels que soient les `true`.

```jsonc
"chat.tools.terminal.autoApprove": {
  // auto-approuver des commandes sûres (lecture seule)
  "/^git (status|diff|log|show)\\b/": true,
  "ls": true,
  "cat": true,
  "pwd": true,

  // toujours demander / bloquer le destructif
  "rm": false,
  "rmdir": false,
  "/rm\\s+-rf/": false,
  "kill": false,
  "chmod": false,
  "/^git (push|reset|clean)\\b/": false
}
```

Points clés :
- `false` ne **supprime pas** la commande : il force une **confirmation manuelle**. L'humain reste la barrière sur les actions sensibles.
- Par défaut le motif est testé sur chaque **sous-commande** ; pour matcher la **ligne complète**, utiliser la forme objet avec `matchCommandLine`.
- **Ne pas activer** `chat.tools.global.autoApprove: true` (mode « tout approuver ») : il **ignore les deny lists**.
- Côté organisation, la policy `ChatToolsTerminalEnableAutoApprove` peut désactiver entièrement l'auto-approbation.

### 5.2 Droits de lecture et d'écriture sur les fichiers

VS Code n'a pas de « permission par dossier » de type `chmod` ; on obtient l'équivalent en combinant trois leviers :

- **Écriture (edits)** - `chat.tools.edits.autoApprove` accepte des **globs** : auto-approuver l'édition tout en **protégeant** des chemins.

```jsonc
"chat.tools.edits.autoApprove": {
  "**": true,
  "**/.env": false,
  "**/secrets/**": false,
  "infra/**": false
}
```

- **Aucune écriture du tout** - retirer l'outil `edit` de l'agent : il devient strictement lecture seule (voir [module 5](05_agents.md)).
- **Lecture** - la **content exclusion** ([§3](#3-exclure-du-contenu-content-exclusion)) empêche l'agent de **lire** certains chemins (secrets, données). C'est le pendant « read » des réglages ci-dessus.

### 5.3 Accès internet et téléchargements

> **Aujourd'hui, « Copilot can search the web » est désactivé** côté organisation (voir [annexe](annexe_configuration.md)) : l'agent **n'a pas d'accès internet**.

S'il venait à être activé, le réflexe est de **valider tout téléchargement** :
- `chat.tools.urls.autoApprove` contrôle les domaines/URLs que l'agent peut récupérer sans confirmation - **ne pas auto-approuver de domaines larges** ; laisser la confirmation manuelle par défaut.
- Traiter avec méfiance toute commande de téléchargement ou d'installation (`curl`, `wget`, `npm install` d'un paquet inconnu) : risque de **dépendance piégée / slopsquatting** (voir [module 6](06_risques.md)) et de chaîne d'approvisionnement (cf. MCP, [§4](#4-intégration-mcp-model-context-protocol)). Les bloquer via la deny-list du [§5.1](#51-commandes-terminal--auto-approuver-le-sûr-bloquer-le-dangereux) tant que ce n'est pas maîtrisé.

### 5.4 Où placer ces règles : global vs local

Les mêmes règles peuvent valoir **partout** (global) ou **pour un seul projet** (local). C'est le choix de **fichier** qui le détermine :

| Portée | Où | Pour quoi (fonctionnel) | Comment (technique) |
|--------|----|-----|-----|
| **Globale** (tous mes projets) | `settings.json` utilisateur | Mes garde-fous personnels (« jamais de `rm` auto-approuvé ») | `chat.tools.*` dans les réglages utilisateur |
| **Locale** (ce projet, partagée) | `.vscode/settings.json` (versionné) | Règles d'équipe propres au dépôt | mêmes clés, committées avec le projet |
| **Organisation** (imposée) | Paramètres GitHub Copilot / policies | Socle non contournable | géré par l'administration, **prioritaire** |

Le même principe vaut pour les **règles de contexte** (instructions) : une convention générale va dans `copilot-instructions.md` / `AGENTS.md` (global au projet), une règle ciblée dans `.github/instructions/*.instructions.md` avec `applyTo` (locale à un type de fichier) - voir [module 4](04_instructions.md). En résumé : on décrit **la règle** (fonctionnel), puis on choisit **le fichier selon la portée** (technique).

---

## 6. Configuration d'équipe : ce qu'on versionne

À committer dans le dépôt pour bénéfice collectif :

- `.vscode/settings.json` - activation par langage, locale.
- `.github/copilot-instructions.md` - instructions de projet (voir [module 4](04_instructions.md)).
- `.github/instructions/*.instructions.md`, `.github/prompts/*.prompt.md`, `.github/agents/*.agent.md`.
- `.vscode/extensions.json` recommandant les extensions Copilot.

À **ne pas** committer : credentials, toute configuration contenant des secrets.

---

## 7. Dépannage

Symptômes courants et premières vérifications :

| Symptôme | Causes probables / vérifications |
|----------|----------------------------------|
| Aucune suggestion inline | Extension désactivée, langage coupé dans `github.copilot.enable`, complétion suspendue (icône barre d'état) |
| « Not signed in » / pas de réponse | Session GitHub expirée → se reconnecter ; vérifier l'accès à l'organisation sur https://github.com/settings/copilot/features |
| Le chat répond mais pas sur le bon projet | Mauvais workspace ouvert ; préciser le contexte avec `#file` / `@workspace` |
| Une fonctionnalité attendue est absente | Désactivée côté organisation (CLI, MCP, recherche web…) - voir [annexe](annexe_configuration.md) |
| Un fichier semble ignoré | Couvert par la content exclusion ou coupé par langage (comportement attendu sur les fichiers sensibles) |
| Réponses qui se bloquent / quota | **Limite mensuelle atteinte** → vérifier l'Usage sur la page des paramètres ([module 2](02_economie_tokens.md)) |
| Derrière un proxy d'entreprise | Vérifier la configuration proxy de VS Code et l'accès réseau aux domaines GitHub/Copilot |

Avant d'escalader : redémarrer la fenêtre VS Code (`Developer: Reload Window`) résout une bonne partie des cas. Les logs de l'extension (sortie « GitHub Copilot ») aident au diagnostic.

---

## Exercices

1. **Par langage** : dans `.vscode/settings.json` d'un projet de test, désactiver Copilot pour `markdown` et `dotenv`. Vérifier que la complétion ne se déclenche plus dans un `.env`.
2. **Suspension rapide** : repérer l'icône Copilot dans la barre d'état, suspendre puis réactiver la complétion. Réflexe utile avant un partage d'écran.
3. **Locale** : passer les réponses du chat en français via `localeOverride`, puis vérifier.
4. **Exclusion** : lister les chemins du projet à exclure (secrets, données) et rédiger la demande à transmettre à l'administration GitHub pour la content exclusion.
5. **Paramètres d'organisation** : ouvrir https://github.com/settings/copilot/features et identifier trois fonctionnalités désactivées qui ne seront donc pas disponibles dans l'IDE.
6. **Dépannage** : couper volontairement Copilot pour un langage, constater l'absence de suggestion, puis diagnostiquer et rétablir. Repérer la sortie « GitHub Copilot » dans le panneau de logs.
7. **Deny-list** : dans `chat.tools.terminal.autoApprove`, auto-approuver `ls`/`git status` et passer `rm` et `git push` à `false`. Lancer une tâche en agent mode et vérifier que les commandes bloquées exigent bien une confirmation manuelle.
8. **Protection de fichiers** : via `chat.tools.edits.autoApprove`, protéger `**/.env` et `secrets/**` (`false`). Demander à l'agent de modifier un de ces fichiers et constater la demande de validation.
9. **Global vs local** : poser une même règle (ex. `rm` non auto-approuvé) une fois dans le `settings.json` utilisateur, une fois dans `.vscode/settings.json`. Expliquer la différence de portée et laquelle l'emporte en cas de conflit avec l'organisation.
