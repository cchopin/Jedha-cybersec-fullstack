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

Le **MCP** permet de connecter l'agent mode à des serveurs externes fournissant des outils supplémentaires (accès à une base, à une API interne, à un système de tickets, etc.).

> **Dans l'organisation, « MCP servers in Copilot » est désactivé** (voir [annexe](annexe_configuration.md)). Cette section est donc fournie à titre d'information : la connexion de serveurs MCP n'est pas disponible en l'état. En cas d'activation ultérieure par l'administration, les précautions ci-dessous s'appliquent.

Structure d'une configuration MCP (pour mémoire) :

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

Précautions si le MCP venait à être activé :
- Un serveur MCP **étend la surface d'action** de Copilot : à traiter comme une dépendance de sécurité.
- N'installer que des serveurs **de confiance**, validés par l'équipe ou l'administration.
- Aucun credential en clair ; utiliser des variables d'environnement ou un gestionnaire de secrets.

---

## 5. Configuration d'équipe : ce qu'on versionne

À committer dans le dépôt pour bénéfice collectif :

- `.vscode/settings.json` - activation par langage, locale.
- `.github/copilot-instructions.md` - instructions de projet (voir [module 4](04_instructions.md)).
- `.github/instructions/*.instructions.md`, `.github/prompts/*.prompt.md`, `.github/agents/*.agent.md`.
- `.vscode/extensions.json` recommandant les extensions Copilot.

À **ne pas** committer : credentials, toute configuration contenant des secrets.

---

## 6. Dépannage

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
