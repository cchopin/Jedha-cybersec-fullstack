# Le processus Winlogon

**Module** : sécurité Windows -- authentification interactive

---

## Objectifs du module

À l'issue de ce module, les compétences suivantes seront acquises :

- Comprendre le rôle de winlogon.exe dans le processus de connexion interactive
- Identifier les étapes du flux d'authentification Windows
- Connaître les clés de registre associées à Winlogon et leurs risques de sécurité
- Détecter les techniques de persistence exploitant Winlogon

---

## 1. Présentation de winlogon.exe

### 1.1 Rôle et caractéristiques

**winlogon.exe** est un processus système critique responsable de la gestion de la connexion et de la déconnexion interactive sous Windows. Il constitue le point d'entrée de la session utilisateur et orchestre l'ensemble du processus d'authentification.

Caractéristiques principales :

| Caractéristique | Valeur |
|---|---|
| **Emplacement** | `C:\Windows\System32\winlogon.exe` |
| **Compte d'exécution** | SYSTEM |
| **Session** | Une instance par session interactive (Session 1, 2, etc.) |
| **Session 0** | Aucune instance dans la Session 0 (réservée aux services) |
| **Criticité** | Processus protégé -- le tuer provoque un BSOD (Blue Screen of Death) |

> **À noter** : chaque session interactive (connexion locale, RDP, etc.) possède sa propre instance de winlogon.exe. En revanche, la Session 0, réservée aux services depuis Windows Vista, n'en possède pas car elle n'est pas interactive.

### 1.2 Responsabilités

winlogon.exe assure les fonctions suivantes :

1. **Capture de la Secure Attention Sequence (SAS)** : interception de la combinaison `Ctrl+Alt+Del`, qui est traitée directement par le noyau et ne peut pas être interceptée par un processus utilisateur classique
2. **Passerelle vers les Credential Providers** : affichage de l'interface de saisie des identifiants via les Credential Providers (mot de passe, carte à puce, biométrie, etc.)
3. **Transmission des credentials à LSASS** : les identifiants saisis sont transmis à LSASS pour validation
4. **Lancement de userinit.exe** : après authentification réussie, winlogon.exe lance userinit.exe avec le token créé par LSASS
5. **Gestion du verrouillage/déverrouillage** : verrouillage de la station (`Win+L`) et déverrouillage via la SAS
6. **Gestion du cycle de vie de la session** : déconnexion, fermeture de session, arrêt du système

### 1.3 Évolution historique : de GINA aux Credential Providers

Dans les versions antérieures à Windows Vista, winlogon.exe utilisait une DLL appelée **GINA** (Graphical Identification and Authentication) pour gérer l'interface de connexion. Par défaut, Windows chargeait `msgina.dll`.

Ce modèle présentait un problème majeur : un attaquant pouvait remplacer la GINA par une DLL malveillante qui interceptait les credentials en clair avant de les transmettre au système.

À partir de Windows Vista, Microsoft a remplacé GINA par le modèle des **Credential Providers**, qui offre une architecture plus modulaire et sécurisée. Plusieurs Credential Providers peuvent coexister (mot de passe, carte à puce, Windows Hello), et leur remplacement est plus contrôlé.

---

## 2. Flux de connexion interactive

### 2.1 Séquence détaillée

Le processus de connexion interactive suit les étapes suivantes :

```
1. L'utilisateur appuie sur Ctrl+Alt+Del (Secure Attention Sequence)
       |
       v
2. winlogon.exe capture la SAS via le noyau
       |
       v
3. winlogon.exe affiche l'interface de connexion (Credential Provider)
       |
       v
4. L'utilisateur saisit ses identifiants
       |
       v
5. winlogon.exe transmet les credentials à LSASS
       |
       v
6. LSASS valide les credentials :
   - Compte local : vérification contre la base SAM
   - Compte domaine : vérification contre le contrôleur de domaine (Kerberos/NTLM)
       |
       v
7. LSASS crée un Access Token pour l'utilisateur
       |
       v
8. winlogon.exe lance userinit.exe avec ce token
       |
       v
9. userinit.exe exécute les scripts de connexion et lance explorer.exe
       |
       v
10. explorer.exe (le shell Windows) est prêt, l'utilisateur voit le Bureau
```

### 2.2 Arbre de processus résultant

Après connexion, l'arbre de processus typique est le suivant :

```
winlogon.exe (SYSTEM)
  └── userinit.exe (utilisateur) [se termine rapidement]
        └── explorer.exe (utilisateur)
              ├── notepad.exe
              ├── chrome.exe
              └── ... (processus lancés par l'utilisateur)
```

> **À noter** : userinit.exe se termine peu après avoir lancé explorer.exe. C'est pourquoi explorer.exe apparaît souvent comme un processus "orphelin" dans les outils d'analyse -- son processus parent n'existe plus.

---

## 3. Clés de registre Winlogon

### 3.1 Emplacement

Les paramètres de configuration de Winlogon sont stockés dans la clé de registre suivante :

```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
```

Pour afficher le contenu de cette clé :

```powershell
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
```

### 3.2 Clés importantes

| Clé | Valeur par défaut | Description |
|---|---|---|
| **Shell** | `explorer.exe` | Programme lancé comme shell utilisateur après connexion |
| **Userinit** | `C:\Windows\system32\userinit.exe,` | Programme lancé par winlogon.exe après authentification (la virgule finale est normale) |
| **Notify** | *(variable)* | DLL de notification chargées par winlogon.exe (obsolète depuis Vista, mais encore présente) |

### 3.3 Vecteurs d'attaque

Ces clés de registre sont des cibles privilégiées pour les attaquants car elles permettent une **persistence** fiable et une exécution automatique à chaque connexion utilisateur.

**Modification de la clé Shell** :

Un attaquant peut remplacer ou compléter la valeur de `Shell` pour exécuter un programme malveillant à la place ou en plus d'explorer.exe :

```
Shell = "explorer.exe, C:\malware\backdoor.exe"
```

Dans ce cas, l'utilisateur voit son Bureau normalement (explorer.exe se lance), mais la backdoor s'exécute également en arrière-plan.

**Modification de la clé Userinit** :

De la même manière, la clé `Userinit` peut être modifiée pour charger un exécutable malveillant :

```
Userinit = "C:\Windows\system32\userinit.exe, C:\malware\payload.exe"
```

**Détection** :

Pour vérifier l'intégrité de ces clés, la commande suivante peut être utilisée :

```powershell
$winlogon = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
Write-Output "Shell    : $($winlogon.Shell)"
Write-Output "Userinit : $($winlogon.Userinit)"
```

Les valeurs attendues sont :
- `Shell` : `explorer.exe`
- `Userinit` : `C:\Windows\system32\userinit.exe,`

Toute déviation par rapport à ces valeurs doit être investiguée.

> **Bonne pratique** : dans un contexte de surveillance, les outils comme **Autoruns** (Sysinternals) permettent de visualiser facilement toutes les entrées de démarrage automatique, y compris les clés Winlogon. C'est un des premiers contrôles à effectuer lors d'un audit de sécurité.

---

## Pour aller plus loin

- [Microsoft -- Winlogon and Credential Providers](https://learn.microsoft.com/en-us/windows/win32/secauthn/winlogon-and-credential-providers)
- [Microsoft -- Credential Providers in Windows](https://learn.microsoft.com/en-us/windows/win32/secauthn/credential-providers-in-windows)
- [MITRE ATT&CK -- Winlogon Helper DLL (T1547.004)](https://attack.mitre.org/techniques/T1547/004/)
- [Sysinternals -- Autoruns](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns)
