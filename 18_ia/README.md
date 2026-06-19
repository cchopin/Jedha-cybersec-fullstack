# Formation - GitHub Copilot pour développeurs

Formation interne destinée à une équipe technique (développeurs, profils techniques) utilisant **GitHub Copilot dans l'IDE** (VS Code), sans la version CLI.

L'objectif n'est pas d'apprendre à « dialoguer avec une IA », mais d'intégrer Copilot dans un flux de travail professionnel : produire plus vite, sans dégrader la qualité, sans fuite de données, et en gardant la maîtrise de ce qui est livré.

---

## Public et prérequis

- **Public** : développeurs et profils techniques, à l'aise avec VS Code, Git et la ligne de commande.
- **Prérequis** :
  - VS Code installé et à jour.
  - Extensions **GitHub Copilot** et **GitHub Copilot Chat** installées, connectées à un compte disposant d'une licence active.
  - Un dépôt Git de test disponible pour les exercices.

> **Contexte de l'organisation.** Cette formation est calée sur la configuration réelle de l'organisation (plan **GitHub Copilot Business**). Les modèles disponibles, l'état de l'agent mode, du MCP, de la CLI et du filtre de code public reflètent cette configuration. Le détail figure en [annexe - Notre configuration](annexe_configuration.md). En cas d'évolution côté administration, c'est cette annexe qu'il faut mettre à jour en premier.

---

## Parcours

La formation est organisée en **trois niveaux progressifs**, suivis d'une synthèse, d'un atelier fil rouge et d'une annexe de référence. Parcours complet : environ une demi-journée. Chaque module peut aussi se consulter seul comme fiche de référence.

Le fil conducteur : **débuter → professionnaliser → sécuriser → consolider.**

### Niveau 1 - Prise en main
*Savoir s'en servir, sans exploser le quota.*

| # | Module | Contenu |
|---|--------|---------|
| 1 | [Usage dans l'IDE](01_usage.md) | Complétion, chat, inline, agent mode, slash commands, références `#`/`@`, choix du modèle, quand ne pas l'utiliser |
| 2 | [Économie de tokens et coût](02_economie_tokens.md) | Contexte, limite mensuelle, suivi de consommation, choix du modèle, prompts économes |

### Niveau 2 - Industrialisation
*Passer d'un usage improvisé à un usage d'équipe.*

| # | Module | Contenu |
|---|--------|---------|
| 3 | [Configuration](03_configuration.md) | Réglages VS Code, exclusion de contenu, MCP, encadrement de l'agent (commandes interdites, droits, téléchargements), règles globales vs locales |
| 4 | [Prompting, instructions et pré-prompts](04_instructions.md) | Techniques de prompting (few-shot, comment-driven), `copilot-instructions.md`, `*.instructions.md`, prompt files, `AGENTS.md`, spec-driven development |
| 5 | [Agents](05_agents.md) | Agent mode et agents personnalisés : création, périmètre d'outils, branche/PR, exemples |

### Niveau 3 - Maîtrise des risques
*Le cœur cyber : qualité, sécurité, conformité.*

| # | Module | Contenu |
|---|--------|---------|
| 6 | [Risques](06_risques.md) | Hallucinations, code non sécurisé, propriété intellectuelle, dépendance, tests en trompe-l'œil |
| 7 | [Sécurité](07_securite.md) | Secrets, RGPD, filtre code public, injection de prompt, dépôt non fiable, injection via logs, réflexe incident, OWASP Top 10 LLM |

### Synthèse et application

| # | Module | Contenu |
|---|--------|---------|
| 8 | [Bonnes pratiques](08_bonnes_pratiques.md) | Workflow type, anti-patterns, checklists, revue du code généré, revue PR Copilot |
| 9 | [Cas pratique (fil rouge)](09_cas_pratique.md) | Atelier guidé de bout en bout, mobilisant tous les modules |
| A | [Annexe - Notre configuration](annexe_configuration.md) | État réel des fonctionnalités et modèles activés dans l'organisation |

Chaque module se termine par un ou plusieurs **exercices** à réaliser dans l'IDE ; le module 9 est un atelier complet.

---

## Règles d'or (à retenir avant tout le reste)

1. **Copilot propose, l'humain décide.** Chaque ligne committée engage celui qui la valide.
2. **Aucun secret dans un prompt.** Mot de passe, token, clé, donnée client : jamais dans le chat ni dans un fichier ouvert pendant une session.
3. **Tout code généré est relu et testé** comme s'il provenait d'un développeur junior.
4. **Le contexte fait la qualité.** Un bon prompt avec le bon contexte vaut dix reformulations.
5. **Le bon modèle pour la bonne tâche.** Le modèle le plus lourd n'est pas justifié pour renommer une variable.

---

## Suivi de consommation et paramètres

La consommation de la limite mensuelle et l'ensemble des paramètres activés par l'organisation se consultent sur la page :

**https://github.com/settings/copilot/features**

C'est la source de référence pour savoir ce qui est réellement disponible (voir l'[annexe](annexe_configuration.md)).

---

## Ressources officielles

Pour approfondir au-delà de cette formation :

- **GitHub Docs - Best practices** : https://docs.github.com/en/copilot/get-started/best-practices
- **GitHub Docs - Prompt engineering** : https://docs.github.com/en/copilot/concepts/prompting/prompt-engineering
- **VS Code - Best practices for AI** : https://code.visualstudio.com/docs/copilot/guides/prompt-engineering-guide
- **VS Code - Custom agents** : https://code.visualstudio.com/docs/agent-customization/custom-agents
- **VS Code - Custom instructions** : https://code.visualstudio.com/docs/agent-customization/custom-instructions
- **Microsoft Learn - GH-300 (Copilot Fundamentals + certification)** : https://learn.microsoft.com/en-us/training/courses/gh-300t00
- **github/awesome-copilot** (instructions, prompts et agents prêts à l'emploi) : https://github.com/github/awesome-copilot
- **OWASP Top 10 for LLM Applications** : https://genai.owasp.org/llm-top-10/

> Ces ressources évoluent vite. En cas de divergence avec la formation, la **doc officielle fait foi** - et l'[annexe](annexe_configuration.md) reflète, elle, l'état réel de notre organisation.
