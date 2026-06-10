# Guide — Agents personnalisés GitHub Copilot (VS Code)

---

## 1. C'est quoi un agent ?

Un agent Copilot est un profil de comportement : un nom, une description, des instructions système et une liste d'outils autorisés. Quand tu sélectionnes un agent dans le chat Copilot, il remplace le prompt système par défaut de Copilot par le tien.

Ce que ça change concrètement :
- Le modèle adopte un rôle précis (analyste sécurité, relecteur, rédacteur…).
- Il est contraint à un périmètre d'outils (lecture seule, ou écriture aussi).
- Il suit des règles de format et de ton définies par toi.
- Il peut utiliser un modèle différent de celui par défaut (GPT-4o, GPT-4.1, o3…).

Ce que ça ne fait pas : un agent ne déclenche pas d'enchaînement automatique. Il n'appelle pas d'autres agents. La chaîne reste manuelle.

---

## 2. Créer un agent

### Emplacement du fichier

```
<racine-du-dépôt>/
└── .github/
    └── agents/
        └── mon-agent.agent.md
```

VS Code détecte automatiquement les fichiers `*.agent.md` dans `.github/agents/` à la racine du dépôt ouvert dans l'explorateur. Pas besoin de configuration supplémentaire. Le dossier `.github/agents/` peut aussi être placé dans `ProjetsGit/` si tous tes projets sont ouverts depuis là.

### Syntaxe

```markdown
---
name: nom-de-lagent
description: Une ligne affichée dans le sélecteur d'agent. Sois précis — c'est ce qui aide à choisir le bon.
model: gpt-4.1          # optionnel — supprime la ligne pour utiliser le modèle actif dans le chat
tools: ["read", "search"]  # restreindre les outils réduit les risques et le coût
disable-model-invocation: true  # l'agent ne se déclenche pas automatiquement
---

Instructions système. Tout ce qui suit le frontmatter est le prompt système de l'agent.

Décris :
- Le rôle de l'agent (ce qu'il est, pas ce qu'il fait).
- Ce qu'il produit (format de sortie attendu).
- Ce qu'il ne fait pas (limites explicites).
```

### Valeurs possibles pour `tools`

| Valeur | Ce que ça permet |
|--------|-----------------|
| `read` | Lire des fichiers du dépôt |
| `search` | Recherche dans le dépôt |
| `edit` | Modifier des fichiers existants |
| `create` | Créer de nouveaux fichiers |
| `run` | Exécuter des commandes (terminal) |

Pour les agents d'analyse et de revue : `["read", "search"]` suffit. Donner `edit` ou `create` uniquement aux agents qui produisent un livrable.

### Modèles disponibles (Copilot)

| Identifiant | Usage conseillé |
|-------------|----------------|
| `gpt-5-mini` | Analyse de sécurité, raisonnement sur surface large  |


---

## 3. Changer d'agent dans VS Code

Dans le panneau Copilot Chat :

1. Cliquer sur le nom de l'agent actif en bas du chat (ou `⇧⌘I`).
2. Sélectionner l'agent voulu dans la liste.
3. Le modèle et l'agent actifs s'affichent en bas de la fenêtre de chat.

L'agent reste actif jusqu'à ce que tu en changes manuellement. **Il n'y a pas de déclenchement automatique** (c'est l'effet de `disable-model-invocation: true`).

---

## 4. Ce qu'on peut espérer comme gain

### Gains réels

- **Cohérence** : le même agent produit toujours le même type de sortie, quel que soit l'utilisateur.
- **Périmètre contrôlé** : un agent `read`-only ne peut pas modifier le code, même accidentellement.
- **Coût maîtrisé** : un agent léger sur un modèle économique coûte 5 à 10× moins qu'un modèle de raisonnement sur une tâche simple.
- **Qualité de la sortie** : un prompt système bien écrit évite les reformulations inutiles, le remplissage et les réponses génériques.

### Limites à ne pas sous-estimer

- L'agent n'a pas de mémoire entre les sessions. Chaque conversation repart de zéro.
- Il ne voit que ce que tu lui envoies ou ce qu'il lit dans le dépôt via ses outils. Il ne fait pas de corrélation automatique entre projets.
- La qualité dépend du prompt système. Un agent mal rédigé est pire que Copilot par défaut car il introduit des contraintes sans apporter de valeur.
- Pas de chaîne automatique : si tu veux que l'analyse sécurité alimente le rapport, tu dois copier-coller ou résumer toi-même entre les deux agents.

---

## 5. Chaîner des agents

Il n'y a pas d'automatisme. La chaîne est manuelle et c'est voulu : tu gardes le contrôle à chaque étape.

### Flux type pour une analyse sécurité

```
1. @cadrage          → reformule la demande, propose le plan, recommande quel agent et quel modèle
2. @analyse-securite → findings : liste avec CWE, CVSS, localisation
3. @redaction-rapport → rapport Markdown structuré à partir des findings
4. @redaction-recommandations → plan de remédiation priorisé
```

### Comment passer d'un agent à l'autre

Deux approches :

**Option A — Résumé manuel**
À la fin de l'étape N, demande à l'agent de produire un résumé structuré. Copie ce résumé, change d'agent, colle-le en contexte dans le nouveau chat.

**Option B — Fichier intermédiaire**
Demande à l'agent de rédaction (`edit` ou `create` activé) d'écrire un fichier dans le dépôt (ex. `findings.md`). L'agent suivant lit ce fichier via son outil `read`.

### Ce qu'il faut éviter

- Enchaîner sans vérifier la sortie intermédiaire. Chaque agent hérite des erreurs du précédent.
- Utiliser un modèle de raisonnement avancé à chaque étape. Réserver `o3` à l'analyse, pas à la rédaction.

---

## 6. Pre-prompts utiles

Ces instructions s'intègrent directement dans le corps d'un agent `.agent.md`. À adapter ou combiner selon le besoin.

### Comportement général (anti-patterns Copilot)

```
Ne reformule pas la demande. Commence directement par la réponse.
Pas d'emojis. Pas de félicitations, de "bien sûr", "absolument", "excellente question".
Si ma proposition est incorrecte ou sous-optimale, dis-le clairement avant de proposer une alternative.
Si une information manque pour répondre correctement, pose la question plutôt que de combler avec une hypothèse.
Ne produis pas de variantes non demandées.
```

### Rigueur et précision

```
Distingue ce qui est certain de ce qui est probable. Marque explicitement les hypothèses.
Préfère un exemple concret à un principe abstrait.
Ne sur-évalue pas la sévérité d'un risque pour paraître exhaustif.
Si plusieurs options existent, présente le compromis et recommande-en une. Ne laisse pas le choix sans avis.
```

### Lecture seule — agent d'analyse

```
Tu ne modifies pas le code. Si tu identifies une correction, décris-la sans l'appliquer.
Ne produis pas de finding si tu n'as pas vérifié la localisation exacte dans le code.
Un finding sans preuve doit être marqué "à confirmer", pas affirmé.
```

### Économie de tokens et d'appels

```
N'ouvre un fichier que si la réponse en dépend directement.
Évite les appels d'outils en cascade. Une lecture ciblée vaut mieux qu'une recherche large suivie de plusieurs ouvertures.
Si la tâche est trop complexe pour cet agent, dis-le et oriente vers l'agent adapté plutôt que d'engager un traitement long.
```

### Challenge et esprit critique

```
Si je te propose une architecture ou une décision, identifie les points faibles avant de valider.
Ne te contente pas de confirmer ce que je dis. Si tu détectes une incohérence, signale-la.
Si la correction proposée ne réduit pas le risque de manière significative, dis-le.
```

---

## Annexe — Structure des fichiers agents déployés

```
ProjetsGit/
└── .github/
    └── agents/
        ├── cadrage.agent.md
        ├── analyse-securite.agent.md
        ├── revue-code.agent.md
        ├── redaction-rapport.agent.md
        ├── redaction-recommandations.agent.md
        └── optimisation-cout.agent.md
```
