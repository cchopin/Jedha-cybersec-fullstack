# Planification de tâches sous Windows

**Module** : administration Windows 
---

## Objectifs du module

À l'issue de ce module, les compétences suivantes seront acquises :

- Comprendre le rôle du Planificateur de tâches et ses cas d'usage en administration et en sécurité
- Écrire et exécuter des scripts PowerShell via PowerShell ISE
- Créer, modifier et supprimer des tâches planifiées en PowerShell
- Créer des tâches planifiées via l'interface graphique (Task Scheduler)
- Identifier les risques de sécurité liés aux tâches planifiées

> **Prérequis** : avoir suivi les modules précédents de la section "Windows Security".

---

## 1. Introduction aux tâches planifiées

### 1.1 Principe

Le **Planificateur de tâches** (Task Scheduler) est l'équivalent Windows de **cron** sous Linux. Il permet d'exécuter automatiquement des programmes ou des scripts selon un déclencheur défini : horaire récurrent, événement système, ouverture de session, démarrage de la machine, etc.

En administration système, les tâches planifiées servent typiquement au nettoyage de dossiers temporaires, aux sauvegardes périodiques, à la collecte de journaux, à l'application de mises à jour ou encore à la rotation de mots de passe.

### 1.2 Intérêt en cybersécurité

Les tâches planifiées sont un vecteur de **persistence** très répandu chez les attaquants. Un malware peut créer une tâche planifiée pour se relancer automatiquement après un redémarrage, exécuter des scripts malveillants à intervalles réguliers ou encore exfiltrer des données à des heures creuses.

La maîtrise de cet outil est donc indispensable aussi bien pour l'administration que pour la détection de compromissions.

---

## 2. PowerShell ISE

### 2.1 Présentation

**PowerShell ISE** (Integrated Scripting Environment) est l'éditeur de scripts intégré à Windows. Il offre un environnement de développement dédié à PowerShell avec coloration syntaxique, auto-complétion, volet de console intégré et débogage pas à pas.

Pour l'ouvrir : rechercher "PowerShell ISE" dans le menu Démarrer, ou exécuter `powershell_ise.exe`. Pour les opérations nécessitant des droits élevés, l'ouvrir en tant qu'administrateur.

### 2.2 Pourquoi l'utiliser ?

La console PowerShell classique est adaptée aux commandes ponctuelles, mais devient vite limitante pour les scripts de plusieurs lignes. PowerShell ISE permet de rédiger, tester et déboguer des scripts dans un environnement confortable avant de les déployer.

> **Alternative** : Visual Studio Code avec l'extension PowerShell offre une expérience encore plus riche (IntelliSense, intégration Git, terminal multiple). C'est l'éditeur recommandé par Microsoft pour le développement PowerShell moderne, mais PowerShell ISE reste disponible nativement sur toutes les machines Windows sans installation supplémentaire.

### 2.3 Script d'exemple

Le script suivant servira de fil conducteur pour le reste du module. Il nettoie les dossiers temporaires du système en supprimant les fichiers datant de plus de 7 jours :

```powershell
# Définition des dossiers à nettoyer
# $env:<VARIABLE> récupère dynamiquement le chemin des dossiers système
$tempFolders = @(
    "$env:TEMP",
    "$env:windir\Temp",
    "C:\Windows\Prefetch"
)

# Ajout des dossiers Temp de chaque profil utilisateur (nécessite des droits administrateur)
$userTemp = Get-ChildItem -Path "C:\Users" -Directory | ForEach-Object {
    "$($_.FullName)\AppData\Local\Temp"
}
$tempFolders += $userTemp

# Suppression des fichiers de plus de 7 jours
foreach ($folder in $tempFolders) {
    if (Test-Path $folder) {
        # Récupère le contenu du dossier (récursif)
        # Filtre uniquement les fichiers (pas les dossiers) modifiés il y a plus de 7 jours
        # Supprime les fichiers correspondants
        Get-ChildItem -Path $folder -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object { !$_.PSIsContainer -and $_.LastWriteTime -lt (Get-Date).AddDays(-7) } |
        Remove-Item -Force -ErrorAction SilentlyContinue
    }
}

# Journalisation de l'exécution
$logPath = "C:\Scripts\temp-cleanup-log.txt"
Add-Content -Path $logPath -Value "Nettoyage Temp exécuté le $(Get-Date)"
```

Ce script doit être enregistré sous `C:\Users\jedha-student\Desktop\temp-cleanup.ps1` pour les exercices qui suivent.

**Analyse du script** :

- `$env:TEMP` et `$env:windir` sont des **variables d'environnement** qui pointent respectivement vers le dossier temporaire de l'utilisateur courant et vers le répertoire Windows. L'utilisation de ces variables rend le script portable d'une machine à l'autre.
- `Get-ChildItem -Recurse -Force` parcourt récursivement le dossier, y compris les fichiers cachés et système.
- `-ErrorAction SilentlyContinue` empêche le script de s'interrompre si un fichier est verrouillé ou inaccessible.
- `!$_.PSIsContainer` filtre les dossiers pour ne conserver que les fichiers.
- `(Get-Date).AddDays(-7)` calcule la date d'il y a 7 jours. Tout fichier dont la dernière modification (`LastWriteTime`) est antérieure à cette date sera supprimé.

---

## 3. Création de tâches planifiées en PowerShell

La création d'une tâche planifiée en PowerShell repose sur trois éléments :

1. **Un déclencheur** (trigger) : la condition qui provoque l'exécution
2. **Une action** : le programme ou script à exécuter
3. **L'enregistrement** : le nom, la description et les options de la tâche

### 3.1 Exemple complet

```powershell
# 1. Définir le déclencheur : tous les dimanches à 3h du matin
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 3am

# 2. Définir l'action : exécuter le script de nettoyage via PowerShell
$action = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument "-File 'C:\Users\jedha-student\Desktop\temp-cleanup.ps1'"

# 3. Enregistrer la tâche
Register-ScheduledTask `
    -TaskName "WeeklyTempCleanup" `
    -Trigger $trigger `
    -Action $action `
    -Description "Nettoyage hebdomadaire des dossiers temporaires"
```

Une fois exécuté, la tâche apparaît dans le Planificateur de tâches (interface graphique) et sera déclenchée chaque dimanche à 3h.

### 3.2 Paramètres de déclenchement (New-ScheduledTaskTrigger)

| Paramètre | Fonction | Exemple |
|---|---|---|
| `-Daily` | Exécution quotidienne | `-Daily -At 6am` |
| `-Weekly` | Exécution hebdomadaire | `-Weekly -DaysOfWeek Monday,Friday -At 8am` |
| `-Once` | Exécution unique | `-Once -At "2025-03-01 10:00"` |
| `-AtStartup` | Au démarrage de la machine | `-AtStartup` |
| `-AtLogOn` | À l'ouverture de session | `-AtLogOn` |
| `-DaysOfWeek` | Jours de la semaine (combinable) | `-DaysOfWeek Sunday` |
| `-At` | Heure d'exécution | `-At "18:30"` ou `-At 3am` |

> **À noter** : il est possible de définir plusieurs déclencheurs pour une même tâche. Il suffit de créer un tableau de triggers et de le passer au paramètre `-Trigger` lors de l'enregistrement :
>
> ```powershell
> $trigger1 = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 3am
> $trigger2 = New-ScheduledTaskTrigger -AtStartup
> Register-ScheduledTask -TaskName "MaTache" -Trigger @($trigger1, $trigger2) -Action $action
> ```

### 3.3 Paramètres d'action (New-ScheduledTaskAction)

| Paramètre | Fonction | Exemple |
|---|---|---|
| `-Execute` | Programme à lancer | `"powershell.exe"`, `"notepad.exe"` |
| `-Argument` | Arguments de la ligne de commande | `"-File script.ps1"` |
| `-WorkingDirectory` | Répertoire de travail (optionnel) | `"C:\Scripts"` |

### 3.4 Paramètres d'enregistrement (Register-ScheduledTask)

| Paramètre | Fonction |
|---|---|
| `-TaskName` | Nom de la tâche (obligatoire) |
| `-Action` | Objet action (issu de `New-ScheduledTaskAction`) |
| `-Trigger` | Objet trigger ou tableau de triggers |
| `-Description` | Description libre |
| `-TaskPath` | Dossier de classement dans le Planificateur (ex. `\CustomTasks\`) |
| `-Principal` | Définit le contexte d'exécution (voir section 3.5) |
| `-Settings` | Options avancées (voir section 3.6) |

### 3.5 Contexte d'exécution (New-ScheduledTaskPrincipal)

Ce paramètre définit **qui** exécute la tâche et avec **quel niveau de privilèges** :

```powershell
$principal = New-ScheduledTaskPrincipal `
    -UserId "DOMAIN\Username" `
    -LogonType Password `
    -RunLevel Highest
```

| Paramètre | Valeurs | Description |
|---|---|---|
| `-UserId` | Nom d'utilisateur, `SYSTEM`, `LOCAL SERVICE`, `NETWORK SERVICE` | Compte sous lequel la tâche s'exécute |
| `-LogonType` | `Password`, `S4U`, `ServiceAccount`, `Interactive` | Mode d'authentification |
| `-RunLevel` | `Highest`, `Limited` | `Highest` = privilèges administrateur, `Limited` = privilèges standard |

Détail des types de connexion :

| LogonType | Comportement |
|---|---|
| `Password` | Utilise les identifiants stockés (nécessite un mot de passe enregistré) |
| `S4U` | Pas de mot de passe requis, mais nécessite une session interactive ouverte |
| `ServiceAccount` | Pour les comptes système (SYSTEM, LOCAL SERVICE, etc.) |
| `Interactive` | Exécution dans le contexte de la session utilisateur active |

> **Point de sécurité** : les tâches configurées avec `-LogonType Password` stockent les identifiants de manière chiffrée dans le système. Cependant, un attaquant disposant de privilèges élevés peut potentiellement les extraire. Préférer `-UserId "SYSTEM"` avec `-LogonType ServiceAccount` lorsque c'est possible, ou utiliser des comptes de service dédiés (gMSA en environnement Active Directory).

### 3.6 Options avancées (New-ScheduledTaskSettingsSet)

```powershell
$settings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 5) `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 30)
```

| Paramètre | Fonction |
|---|---|
| `-StartWhenAvailable` | Exécute la tâche dès que possible si le déclencheur a été manqué (machine éteinte) |
| `-AllowStartIfOnBatteries` | Autorise l'exécution sur batterie |
| `-DontStopIfGoingOnBatteries` | Ne pas interrompre la tâche en cas de passage sur batterie |
| `-RestartCount` / `-RestartInterval` | Nombre de tentatives et délai entre chaque tentative en cas d'échec |
| `-ExecutionTimeLimit` | Durée maximale d'exécution avant interruption automatique |
| `-MultipleInstances` | Comportement si la tâche est déjà en cours : `IgnoreNew`, `Queue`, `StopExisting` |

Pour intégrer le principal et les settings à l'enregistrement :

```powershell
Register-ScheduledTask `
    -TaskName "WeeklyTempCleanup" `
    -Trigger $trigger `
    -Action $action `
    -Principal $principal `
    -Settings $settings `
    -Description "Nettoyage hebdomadaire des dossiers temporaires"
```

### 3.7 Administration des tâches existantes

| Cmdlet | Fonction | Exemple |
|---|---|---|
| `Get-ScheduledTask` | Lister toutes les tâches | `Get-ScheduledTask` |
| `Get-ScheduledTaskInfo` | Statut, dernière/prochaine exécution | `Get-ScheduledTaskInfo -TaskName "WeeklyTempCleanup"` |
| `Disable-ScheduledTask` | Désactiver une tâche | `Disable-ScheduledTask -TaskName "WeeklyTempCleanup"` |
| `Enable-ScheduledTask` | Réactiver une tâche | `Enable-ScheduledTask -TaskName "WeeklyTempCleanup"` |
| `Set-ScheduledTask` | Modifier une tâche (trigger, action, settings) | `Set-ScheduledTask -TaskName "WeeklyTempCleanup" -Trigger $newTrigger` |
| `Unregister-ScheduledTask` | Supprimer une tâche | `Unregister-ScheduledTask -TaskName "WeeklyTempCleanup" -Confirm:$false` |

Quelques commandes utiles pour l'audit :

```powershell
# Lister toutes les tâches actives avec leur prochaine exécution
Get-ScheduledTask | Where-Object { $_.State -eq "Ready" } |
    ForEach-Object { Get-ScheduledTaskInfo -TaskName $_.TaskName } |
    Select-Object TaskName, LastRunTime, NextRunTime

# Lister les tâches créées par un utilisateur spécifique
Get-ScheduledTask | Where-Object { $_.Principal.UserId -like "*jedha*" }

# Lister les tâches exécutées avec des privilèges élevés
Get-ScheduledTask | Where-Object { $_.Principal.RunLevel -eq "Highest" }

# Exporter la liste complète des tâches en CSV
Get-ScheduledTask | Select-Object TaskName, State, TaskPath,
    @{N='UserId';E={$_.Principal.UserId}},
    @{N='RunLevel';E={$_.Principal.RunLevel}} |
    Export-Csv -Path "C:\audit_tasks.csv" -NoTypeInformation
```

---

## 4. Création via l'interface graphique (Task Scheduler)

### 4.1 Accès

Plusieurs méthodes pour ouvrir le Planificateur de tâches :

- Rechercher "Task Scheduler" ou "Planificateur de tâches" dans le menu Démarrer
- Exécuter `taskschd.msc` via `Win + R`
- Depuis la console Gestion de l'ordinateur (`compmgmt.msc`) > Planificateur de tâches

### 4.2 Création d'une tâche

1. Dans le volet de droite, cliquer sur **"Créer une tâche..."** (et non "Créer une tâche de base" qui est plus limité)
2. **Onglet Général** : nommer la tâche, ajouter une description, définir le compte d'exécution et le niveau de privilèges
3. **Onglet Déclencheurs** : cliquer sur "Nouveau" pour ajouter un ou plusieurs déclencheurs (planification, événement, démarrage, etc.)
4. **Onglet Actions** : cliquer sur "Nouveau", choisir "Démarrer un programme", indiquer `powershell.exe` dans le champ Programme et `-File "C:\chemin\script.ps1"` dans le champ Arguments
5. **Onglet Conditions** : paramètres liés à l'alimentation, au réseau et à l'inactivité
6. **Onglet Paramètres** : options d'exécution (comportement en cas d'échec, instances multiples, etc.)

> **Conseil** : la correspondance entre l'interface graphique et les cmdlets PowerShell est directe. L'onglet "Déclencheurs" correspond à `New-ScheduledTaskTrigger`, l'onglet "Actions" à `New-ScheduledTaskAction`, l'onglet "Général" à `New-ScheduledTaskPrincipal`, et les onglets "Conditions"/"Paramètres" à `New-ScheduledTaskSettingsSet`.

### 4.3 Consultation et gestion

Le volet central du Planificateur de tâches affiche la liste des tâches avec leur statut, leur dernière exécution et leur prochain déclenchement. Un double-clic sur une tâche permet de consulter et modifier l'ensemble de sa configuration.

La **bibliothèque du Planificateur de tâches** (volet de gauche) organise les tâches en arborescence. Les tâches système de Windows se trouvent sous `Microsoft\Windows\`. Les tâches personnalisées apparaissent à la racine ou dans les dossiers définis via `-TaskPath`.

---

## 5. Tâches planifiées et sécurité

### 5.1 Vecteur de persistence

Les tâches planifiées figurent parmi les techniques de persistence les plus utilisées par les attaquants (référencée comme **T1053.005** dans le framework MITRE ATT&CK). Un malware peut créer une tâche planifiée pour se relancer après chaque redémarrage, exécuter périodiquement un script de collecte de données ou télécharger et exécuter des charges utiles depuis un serveur distant.

### 5.2 Indicateurs de compromission

Lors d'un audit ou d'une investigation, les éléments suivants doivent attirer l'attention :

- Tâches planifiées avec des noms génériques ou imitant des tâches système légitimes
- Tâches exécutant des scripts depuis des emplacements inhabituels (`%TEMP%`, `%APPDATA%`, dossiers utilisateur)
- Tâches configurées pour s'exécuter en tant que `SYSTEM` avec le niveau `Highest`
- Tâches créées récemment dont l'origine est inconnue
- Tâches dont l'action fait appel à `powershell.exe` avec des arguments encodés en base64 (`-EncodedCommand`)

### 5.3 Outils de détection

Plusieurs outils permettent de surveiller et auditer les tâches planifiées :

- **Autoruns** (Sysinternals) : affiche toutes les tâches planifiées avec la possibilité de vérifier les signatures numériques
- **Sysmon** (événement ID 1 combiné à la surveillance du processus `schtasks.exe`) : détecte la création de nouvelles tâches
- **Journaux d'événements Windows** : le journal `Microsoft-Windows-TaskScheduler/Operational` enregistre la création, la modification et l'exécution des tâches
- **PowerShell** : les commandes d'audit présentées en section 3.7 permettent un inventaire rapide

---

## Récapitulatif des cmdlets

| Cmdlet | Fonction |
|---|---|
| `New-ScheduledTaskTrigger` | Définir le déclencheur (quand) |
| `New-ScheduledTaskAction` | Définir l'action (quoi) |
| `New-ScheduledTaskPrincipal` | Définir le contexte d'exécution (qui, avec quels droits) |
| `New-ScheduledTaskSettingsSet` | Définir les options avancées |
| `Register-ScheduledTask` | Enregistrer la tâche |
| `Get-ScheduledTask` | Lister les tâches |
| `Get-ScheduledTaskInfo` | Consulter le statut et l'historique d'exécution |
| `Set-ScheduledTask` | Modifier une tâche |
| `Enable-ScheduledTask` / `Disable-ScheduledTask` | Activer / désactiver une tâche |
| `Unregister-ScheduledTask` | Supprimer une tâche |

---

## Pour aller plus loin

- [PowerShell create a scheduled task (YouTube)](https://www.youtube.com/results?search_query=PowerShell+create+scheduled+task)
- [How to use Task Scheduler in Windows (YouTube)](https://www.youtube.com/results?search_query=How+to+use+Task+Scheduler+in+Windows)
- [Scheduled Tasks in PowerShell (YouTube)](https://www.youtube.com/results?search_query=Scheduled+Tasks+in+PowerShell)
- [ScheduledTasks Module - Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/)
- [T1053.005 - Scheduled Task - MITRE ATT&CK](https://attack.mitre.org/techniques/T1053/005/)
- [Autoruns - Sysinternals (Microsoft)](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns)
