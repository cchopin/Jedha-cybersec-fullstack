# Module 6 - Risques

Objectif : identifier ce qui peut mal tourner avec Copilot afin de le détecter et de l'éviter. Ce module traite des risques de **qualité et de fiabilité** ; la fuite de données et la sécurité des secrets relèvent du [module 7](07_securite.md).

---

## 1. Hallucination et code plausible mais faux

Copilot génère le code **le plus probable**, pas le plus correct. Il produit du code qui *paraît* juste : bonne syntaxe, bons noms, logique parfois erronée.

Formes courantes :
- **API inventées** : méthode ou paramètre inexistant dans la bibliothèque.
- **Versions mélangées** : syntaxe d'une v1 appliquée à une bibliothèque en v2.
- **Logique subtilement fausse** : erreur d'indice, condition inversée, cas limite ignoré.
- **Dépendances fantômes** : import d'un package inexistant (vecteur de *slopsquatting* - voir [module 7](07_securite.md)).

**Parade :** ne jamais committer sans avoir lu et compris. Pour une API inconnue, vérification dans la documentation officielle, pas auprès de Copilot.

---

## 2. Code non sécurisé par défaut

Copilot reproduit les patterns de son corpus d'entraînement, y compris les mauvais. Il peut proposer spontanément :
- des requêtes SQL concaténées (injection) ;
- des entrées utilisateur non validées ;
- du chiffrement faible ou des algorithmes obsolètes (MD5, DES) ;
- des secrets en dur dans l'exemple ;
- une gestion d'erreur trop large masquant les fautes.

**Parade :** traiter toute sortie comme du code d'un développeur junior pressé. Relecture avec un œil sécurité, passage du linter et des outils SAST habituels (le code généré ne dispense pas de la CI).

---

## 3. Propriété intellectuelle et licence

- Copilot peut reproduire des extraits ressemblant à du code public, parfois sous licence contraignante (GPL, etc.).
- Le **filtre de code public** (« Suggestions matching public code ») bloque les suggestions correspondant à du code public connu. **Il est activé (Blocked) dans l'organisation** (voir [annexe](annexe_configuration.md)) - une protection en place qu'il faut maintenir.
- Le code généré n'est pas « original » au sens où son originalité serait garantie : pour du code destiné à être publié ou propriétaire, la vigilance reste de mise.

---

## 4. Biais d'automatisation et dépendance

Le risque le plus insidieux est humain :
- **Acceptation réflexe** : valider par `Tab` sans lire, au motif que « ça compile ».
- **Perte de compétence** : déléguer au point de ne plus savoir faire ni juger.
- **Fausse confiance** : un code bien présenté inspire confiance indépendamment de sa justesse.

**Parade :** garder la main. Copilot accélère la frappe, pas le jugement. Pour ce qui n'est pas compris, demander `/explain` avant d'accepter.

---

## 5. Risques spécifiques à l'agent mode

L'agent mode **exécute des actions**. Risques additionnels :
- Commandes destructives (`rm`, reset, drop) lancées en cours de tâche.
- Effets de bord non désirés sur plusieurs fichiers.

**Parade :** relire le plan et les commandes avant validation, s'appuyer sur le niveau d'approbation (« Default Approvals »), travailler sur une branche dédiée, ne pas lancer l'agent mode sur un dépôt comportant des changements non commités importants. Conserver la possibilité de revenir en arrière (`git`).

---

## 6. Tableau de synthèse

| Risque | Signe | Parade |
|--------|-------|--------|
| Hallucination | API/paramètre inconnu, « compile » mais échoue | Lire, comprendre, vérifier la doc |
| Code non sécurisé | SQL concaténé, crypto faible, entrée non validée | Revue sécurité + linter + SAST |
| Licence/IP | Bloc ressemblant à du code public | Filtre code public maintenu activé |
| Dépendance | `Tab` sans lecture | Garder la main, `/explain` |
| Agent mode | Commande destructive proposée | Branche dédiée, relecture avant validation |

---

## Exercices

1. **Chasse à l'hallucination** : demander à Copilot d'utiliser une bibliothèque bien connue et chercher une méthode ou un paramètre inventé. Vérifier dans la documentation officielle.
2. **Code non sécurisé** : demander « une fonction qui récupère un utilisateur par son id depuis la base » sans préciser de protection. Vérifier si la requête est paramétrée ; sinon, faire corriger et observer.
3. **Cas limite** : faire générer une fonction de découpage/parsing, puis la tester sur des entrées limites (vide, très long, caractères spéciaux). Noter ce qui casse.
4. **Explain avant accept** : prendre une suggestion non entièrement comprise, lancer `/explain`, puis décider en connaissance de cause.
5. **Agent mode maîtrisé** : avant de lancer une tâche en agent mode, créer une branche dédiée. Après coup, examiner le `git diff` complet avant tout commit.
