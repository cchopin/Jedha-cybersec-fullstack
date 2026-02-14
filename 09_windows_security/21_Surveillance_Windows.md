# Surveillance et monitoring Windows

**Module** : sécurité Windows -- détection et investigation

---

## Objectifs du module

À l'issue de ce module, les compétences suivantes seront acquises :

- Utiliser l'Event Viewer pour analyser les journaux de sécurité Windows
- Identifier les Event IDs critiques pour la détection d'incidents
- Configurer les politiques d'audit pour améliorer la visibilité
- Maîtriser les outils Sysinternals essentiels pour l'investigation

---

## 1. L'Event Viewer (Observateur d'événements)

### 1.1 Présentation

L'**Event Viewer** (`eventvwr.msc`) est l'outil intégré de Windows pour consulter les journaux d'événements du système. Il centralise les logs de connexion, d'utilisation de privileges, de démarrage de services, d'installations logicielles, d'échecs d'audit et de nombreux autres événements de sécurité.

Pour l'ouvrir :

```powershell
eventvwr.msc
```

Ou via PowerShell pour interroger directement les logs :

```powershell
Get-EventLog -LogName Security -Newest 20
```

### 1.2 Les journaux principaux

| Journal | Emplacement | Contenu |
|---|---|---|
| **Application** | `Application` | Événements générés par les applications (erreurs, avertissements) |
| **Security** | `Security` | Événements d'audit : connexions, accès aux objets, modifications de privileges |
| **System** | `System` | Événements du système d'exploitation : démarrage de services, erreurs matérielles |
| **Setup** | `Setup` | Événements liés à l'installation de Windows et des mises à jour |
| **Windows Defender** | `Microsoft-Windows-Windows Defender/Operational` | Détections, mises à jour de signatures, actions correctives |

> **Bonne pratique** : le journal **Security** est le plus important pour la cybersécurité. Il nécessite cependant que les politiques d'audit soient correctement configurées pour générer les événements pertinents.

---

## 2. Event IDs critiques

### 2.1 Tableau de référence

Les Event IDs suivants sont les plus importants à connaître pour la détection d'incidents de sécurité :

| Event ID | Catégorie | Description |
|---|---|---|
| **4624** | Connexion | Ouverture de session réussie |
| **4625** | Connexion | Échec d'ouverture de session |
| **4634** | Connexion | Fermeture de session |
| **4672** | Connexion | Privileges spéciaux assignés à une nouvelle session (connexion administrateur) |
| **4688** | Processus | Création d'un nouveau processus |
| **4697** | Service | Installation d'un nouveau service |
| **1102** | Audit | Le journal d'audit a été effacé |

### 2.2 Détails des événements clés

**Event ID 4624 -- Logon Success**

Cet événement est généré à chaque connexion réussie. Le champ **Logon Type** indique la méthode de connexion :

| Logon Type | Description |
|---|---|
| **2** | Interactive (connexion locale au clavier) |
| **3** | Network (accès à un partage réseau, SMB) |
| **4** | Batch (tâche planifiée) |
| **5** | Service (démarrage d'un service Windows) |
| **7** | Unlock (déverrouillage de la station) |
| **8** | NetworkCleartext (connexion réseau avec mot de passe en clair, ex. IIS Basic Auth) |
| **9** | NewCredentials (RunAs avec /netonly) |
| **10** | RemoteInteractive (connexion RDP) |
| **11** | CachedInteractive (connexion avec credentials mis en cache, hors réseau) |

**Event ID 4625 -- Logon Failure**

Cet événement enregistre chaque tentative de connexion échouée. Le champ **Status** et **Sub Status** indiquent la raison de l'échec :

| Status Code | Description |
|---|---|
| `0xC000006D` | Nom d'utilisateur ou mot de passe incorrect |
| `0xC000006A` | Mot de passe incorrect (nom d'utilisateur valide) |
| `0xC0000234` | Compte verrouillé |
| `0xC0000072` | Compte désactivé |
| `0xC000006F` | Connexion en dehors des heures autorisées |

**Event ID 4672 -- Special Privileges Assigned**

Cet événement est généré lorsqu'un utilisateur se connecte avec des privileges d'administration. Il est systématiquement associé à un Event ID 4624 pour les connexions administrateur.

**Event ID 1102 -- Audit Log Cleared**

Cet événement est généré lorsqu'un utilisateur efface le journal de sécurité. C'est un indicateur très fort de compromission : un attaquant efface souvent les logs pour couvrir ses traces.

### 2.3 Séquence suspecte typique

La séquence d'Event IDs suivante est caractéristique d'une intrusion :

```
4624  -> Connexion réussie (souvent Logon Type 3 ou 10)
4672  -> Privileges spéciaux assignés (l'attaquant a des droits admin)
4688  -> Création de processus (exécution d'outils malveillants)
4697  -> Installation d'un service (persistence ou exécution de code)
1102  -> Effacement du journal d'audit (nettoyage des traces)
```

Pour rechercher cette séquence en PowerShell :

```powershell
# Rechercher les connexions réussies des dernières 24 heures
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4624, 4672, 4688, 4697, 1102
    StartTime = (Get-Date).AddDays(-1)
} | Format-Table TimeCreated, Id, Message -AutoSize
```

> **À noter** : l'Event ID 1102 est particulièrement significatif. Dans un environnement de production, l'effacement du journal de sécurité n'est presque jamais légitime. Sa détection doit déclencher une investigation immédiate.

---

## 3. Configuration des politiques d'audit

### 3.1 Via secpol.msc

Les politiques d'audit déterminent quels événements sont enregistrés dans le journal de sécurité. Par défaut, de nombreuses catégories ne sont pas auditées.

Pour configurer les politiques d'audit :

```
secpol.msc > Local Policies > Audit Policy
```

Catégories d'audit disponibles :

| Catégorie | Description | Recommandation |
|---|---|---|
| **Audit account logon events** | Connexions avec validation par un contrôleur de domaine | Success, Failure |
| **Audit account management** | Création, modification, suppression de comptes | Success, Failure |
| **Audit logon events** | Connexions locales et réseau | Success, Failure |
| **Audit object access** | Accès aux fichiers, registre, etc. | Failure (au minimum) |
| **Audit policy change** | Modification des politiques de sécurité | Success, Failure |
| **Audit privilege use** | Utilisation de privileges sensibles | Success, Failure |
| **Audit process tracking** | Création et terminaison de processus | Success |
| **Audit system events** | Événements système (démarrage, arrêt) | Success, Failure |

### 3.2 Via auditpol en ligne de commande

L'outil `auditpol` offre un contrôle plus granulaire que `secpol.msc` :

```cmd
:: Afficher la configuration actuelle
auditpol /get /category:*

:: Activer l'audit des connexions (succès et échecs)
auditpol /set /subcategory:"Logon" /success:enable /failure:enable

:: Activer l'audit de la création de processus
auditpol /set /subcategory:"Process Creation" /success:enable

:: Activer l'audit de l'installation de services
auditpol /set /subcategory:"Security System Extension" /success:enable
```

> **Bonne pratique** : pour que l'Event ID 4688 inclue la ligne de commande complète du processus créé (très utile en investigation), activer le paramètre suivant : `Computer Configuration > Administrative Templates > System > Audit Process Creation > Include command line in process creation events`.

---

## 4. Logs Windows Defender

Windows Defender génère ses propres logs, consultables dans l'Event Viewer sous :

```
Applications and Services Logs > Microsoft > Windows > Windows Defender > Operational
```

Event IDs importants de Windows Defender :

| Event ID | Description |
|---|---|
| **1006** | Le moteur antimalware a détecté un logiciel malveillant |
| **1007** | Action effectuée pour protéger le système contre un malware |
| **1008** | Échec de l'action de remédiation |
| **1116** | Détection d'un logiciel malveillant ou potentiellement indésirable |
| **1117** | Action effectuée suite à une détection |
| **5001** | La protection en temps réel est désactivée |

Pour interroger ces logs en PowerShell :

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" -MaxEvents 20 |
    Format-Table TimeCreated, Id, Message -AutoSize -Wrap
```

---

## 5. Outils Sysinternals

### 5.1 Présentation

La suite **Sysinternals** est un ensemble d'outils gratuits développés par Mark Russinovich et maintenus par Microsoft. Ces outils sont indispensables pour l'analyse de sécurité et l'investigation sur les systèmes Windows.

Ils peuvent être téléchargés depuis [https://learn.microsoft.com/en-us/sysinternals/](https://learn.microsoft.com/en-us/sysinternals/) ou exécutés directement depuis le partage réseau `\\live.sysinternals.com\tools\`.

### 5.2 Process Explorer

**Process Explorer** (`procexp.exe`) est une version avancée du Gestionnaire des tâches. Il offre les fonctionnalités suivantes :

| Fonctionnalité | Description |
|---|---|
| **Arbre de processus** | Affichage hiérarchique parent/enfant des processus |
| **Détails du processus** | DLLs chargées, handles ouverts, threads, connexions réseau |
| **Vérification VirusTotal** | Soumission des hashes de processus à VirusTotal pour détection |
| **Recherche de handles/DLLs** | Trouver quel processus utilise un fichier ou une DLL spécifique |
| **Informations de sécurité** | Compte d'exécution, privileges, intégrité de chaque processus |

> **Bonne pratique** : dans Process Explorer, activer la colonne "VirusTotal" (`Options > VirusTotal.com > Check VirusTotal.com`) pour identifier rapidement les processus suspects.

### 5.3 Autoruns

**Autoruns** (`autoruns.exe`) affiche la liste exhaustive de tous les programmes configurés pour s'exécuter automatiquement au démarrage du système ou à la connexion utilisateur. Il couvre :

- Les clés de registre Run/RunOnce
- Les clés Winlogon (Shell, Userinit)
- Les tâches planifiées
- Les services
- Les drivers
- Les extensions du navigateur
- Et bien d'autres emplacements

C'est l'outil de référence pour détecter les mécanismes de persistence d'un malware.

### 5.4 ProcDump

**ProcDump** (`procdump.exe`) permet de capturer un dump mémoire d'un processus en cours d'exécution. Bien qu'il soit un outil légitime, il est souvent utilisé par les attaquants pour dumper la mémoire de LSASS (cf. module sur la SAM).

```cmd
:: Dump complet de la mémoire d'un processus
procdump.exe -ma lsass.exe C:\temp\lsass.dmp

:: Dump déclenché par une condition (ex. CPU > 90%)
procdump.exe -ma -c 90 monapp.exe C:\temp\monapp.dmp
```

### 5.5 Strings

**Strings** (`strings.exe`) extrait les chaînes de caractères lisibles depuis un fichier binaire. Utile pour l'analyse préliminaire d'un exécutable suspect :

```cmd
strings.exe suspect.exe | findstr /i "http password cmd powershell"
```

### 5.6 ProcMon (Process Monitor)

**ProcMon** (`procmon.exe`) capture l'activité système en temps réel avec un niveau de détail extrême. Il enregistre :

| Type d'activité | Exemples |
|---|---|
| **Fichiers** | Ouverture, lecture, écriture, suppression de fichiers |
| **Registre** | Lecture, écriture, suppression de clés et valeurs de registre |
| **Processus** | Création et terminaison de processus et threads |
| **Réseau** | Connexions TCP/UDP, envoi et réception de données |
| **DLLs** | Chargement et déchargement de bibliothèques |

ProcMon génère un volume considérable de données. Il est donc essentiel d'utiliser ses filtres pour cibler l'analyse :

```
Filter > Filter... >
  Process Name - is - malware.exe - Include
  Operation - is - WriteFile - Include
```

> **À noter** : ProcMon est particulièrement utile pour comprendre le comportement d'un malware en environnement contrôlé (sandbox). Il permet de voir exactement quels fichiers sont créés, quelles clés de registre sont modifiées et quelles connexions réseau sont établies.

### 5.7 Handle

**handle.exe** permet de lister les handles (descripteurs) ouverts par un processus, c'est-à-dire les fichiers, clés de registre, pipes et autres objets auxquels un processus accède.

```cmd
:: Lister tous les handles d'un processus
handle.exe -p lsass.exe

:: Trouver quel processus utilise un fichier spécifique
handle.exe "C:\Windows\System32\config\SAM"
```

---

## 6. Synthèse : workflow d'investigation

Lors d'un incident de sécurité, un workflow typique d'investigation sur une machine Windows combine les outils présentés dans ce module :

```
1. Event Viewer (eventvwr.msc)
   -> Analyser les Event IDs de sécurité (4624, 4625, 4672, 4688, 4697, 1102)
   -> Identifier les connexions suspectes et les processus créés

2. Autoruns
   -> Vérifier les mécanismes de persistence (registre, services, tâches planifiées)

3. Process Explorer
   -> Examiner les processus en cours d'exécution
   -> Vérifier les hashes sur VirusTotal

4. ProcMon
   -> Capturer l'activité en temps réel d'un processus suspect
   -> Identifier les fichiers créés, les clés de registre modifiées

5. Strings
   -> Analyser les chaînes de caractères dans les exécutables suspects

6. handle.exe
   -> Identifier les fichiers verrouillés ou accédés par un processus suspect
```

---

## Pour aller plus loin

- [Microsoft -- Windows Security Event Log Reference](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/security-auditing-overview)
- [Microsoft -- Sysinternals Suite](https://learn.microsoft.com/en-us/sysinternals/)
- [SANS -- Windows Event Log Cheat Sheet](https://www.sans.org/posters/windows-forensic-analysis/)
- [Microsoft -- Advanced Audit Policy Configuration](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings)
- [Ultimate IT Security -- Windows Security Log Encyclopedia](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)
