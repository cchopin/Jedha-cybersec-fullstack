# Annexe - Notre configuration

État réel de la configuration Copilot de l'organisation, relevé sur **https://github.com/settings/copilot/features**. Cette annexe sert de référence aux modules : les exemples de modèles, l'agent mode, le MCP et le filtre de code public y sont calés.

---

## Plan et accès

| Élément | Valeur |
|---------|--------|
| Plan | **GitHub Copilot Business** |
| Organisation | (organisation interne) |
| Accès | Activé par l'administration de l'organisation |

---

## Usage / limite

- Une **limite mensuelle** s'applique (« Monthly Limit »), avec **réinitialisation mensuelle**.
- Le pourcentage consommé et la date de réinitialisation se consultent sur la page des paramètres.
- Voir [module 2 - Économie de tokens](02_economie_tokens.md).

---

## Fonctionnalités

| Fonctionnalité | État |
|----------------|------|
| Editor preview features | Activé |
| **Copilot Agent Mode in IDE Chat** | Activé |
| Copilot Chat in the IDE | Activé |
| Copilot Chat in GitHub.com | Activé |
| Copilot code review | Activé |
| Dashboard Entry Point | Activé |
| Bring Your Own Language Model Key (VS Code) | Activé |
| Copilot Spaces - Individual Access | Activé |
| Semantic indexing for Non-GitHub Repositories (Preview) | Désactivé |
| Copilot CLI | Désactivé |
| Copilot in GitHub Desktop | Désactivé |
| Copilot Chat in GitHub Mobile | Désactivé |
| Copilot can search the web | Désactivé |
| **MCP servers in Copilot** | Désactivé |
| Copilot cloud agent | Désactivé |
| Copilot Memory (Preview) | Désactivé |
| Copilot-generated commit messages | Désactivé |
| Copilot Spaces | Désactivé |
| Copilot Spaces - Individual Sharing | Désactivé |

Implications pratiques :
- L'**agent mode est disponible** dans le chat de l'IDE (voir [module 5](05_agents.md)).
- Le **MCP est indisponible** : pas de connexion à des outils externes pour le moment (voir [module 3](03_configuration.md)).
- Pas de **CLI**, pas de **recherche web**, pas de **Copilot dans GitHub Desktop / Mobile** : l'usage est centré sur l'**IDE**.
- **BYOK activé** : possibilité d'utiliser une clé d'un fournisseur tiers dans VS Code - à n'employer qu'en connaissance de cause (confidentialité, voir [module 7](07_securite.md)).

---

## Modèles

Seuls les modèles **OpenAI GPT-5.x** sont activés. Les familles Anthropic Claude et Google Gemini sont désactivées.

| Modèle | État | Profil |
|--------|------|--------|
| OpenAI **GPT-5 mini** | Activé | Rapide, économe |
| OpenAI **GPT-5.4 mini** | Activé | Rapide, économe |
| OpenAI **GPT-5.4** | Activé | Capable |
| OpenAI **GPT-5.5** | Activé | Le plus capable |
| Anthropic Claude Sonnet 4 / 4.5 / 4.6 | Désactivé | - |
| Anthropic Claude Haiku 4.5 | Désactivé | - |
| Anthropic Claude Opus 4.5 / 4.6 / 4.7 / 4.8 | Désactivé | - |
| Google Gemini 2.5 Pro / 3.1 Pro | Désactivé | - |
| Google Gemini 3.5 Flash / 3 Flash | Désactivé | - |
| xAI Grok Code Fast 1 | Désactivé | - |

Choix de modèle conseillé : voir [module 2 - §4](02_economie_tokens.md). La barre du chat indique le modèle actif, le niveau d'effort et la fenêtre de contexte (ex. `GPT-5.4 · Medium · 272K`).

---

## Confidentialité

| Réglage | État |
|---------|------|
| **Suggestions matching public code** | **Blocked** (filtre de code public actif) |

Le filtre de code public est **activé** : les suggestions correspondant à du code public connu sont bloquées. Protection à maintenir (voir [module 6](06_risques.md) et [module 7](07_securite.md)).

---

## Synthèse pour l'équipe

- Usage **IDE uniquement** (VS Code), agent mode disponible.
- Modèles **GPT-5.x** exclusivement : raisonner « mini pour le simple, GPT-5.4/5.5 pour le complexe ».
- **MCP, CLI, recherche web, Memory : indisponibles.**
- Protections en place : **filtre de code public actif**, plan **Business**.
- Surveiller la **limite mensuelle** sur https://github.com/settings/copilot/features.
