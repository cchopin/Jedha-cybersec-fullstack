# NovaTech Server Implementation - Solution complète

---

## 1. Architecture et planification

### 1.1 Modèle RBAC

Le principe : les permissions sont attribuées à des **groupes** (rôles), jamais directement à des utilisateurs. Chaque utilisateur est ensuite affecté au(x) groupe(s) correspondant à ses fonctions.

| Groupe | Membres | Rôle |
|---|---|---|
| `SalesTeam` | Alice, Bob | Lecture/écriture sur Sales |
| `MarketingTeam` | Clara, Dave | Lecture/écriture sur Marketing, lecture seule sur Sales |
| `FinanceTeam` | Eve, Frank | Contrôle total sur Finance |
| `ITAdmins` | Grace, Henry | Contrôle total sur tous les dossiers, gestion des utilisateurs et tâches planifiées |

### 1.2 Arborescence des dossiers

```
C:\NovaTechData\
├── Sales\
├── Marketing\
└── Finance\

C:\Logs\
```

### 1.3 Matrice de permissions NTFS

| Dossier | SalesTeam | MarketingTeam | FinanceTeam | ITAdmins |
|---|---|---|---|---|
| `C:\NovaTechData\Sales` | Modify | Read | Aucun | FullControl |
| `C:\NovaTechData\Marketing` | Aucun | Modify | Aucun | FullControl |
| `C:\NovaTechData\Finance` | Aucun | Aucun | FullControl | FullControl |

### 1.4 Stratégie de tâches planifiées

| Tâche | Fréquence | Heure | Script | Sortie |
|---|---|---|---|---|
| Rapport quotidien d'utilisation des fichiers | Quotidienne | 19h00 | `C:\Scripts\daily-report.ps1` | `C:\Logs\daily-report.txt` |

---

## 2. Implémentation

> **Important** : toutes les commandes ci-dessous doivent être exécutées dans un PowerShell lancé en tant qu'administrateur.

### 2.1 Politique de mots de passe

À exécuter en premier, avant la création des utilisateurs :

```powershell
# Longueur minimale : 12 caractères
net accounts /MINPWLEN:12

# Changement obligatoire tous les 30 jours
net accounts /MAXPWAGE:30

# 3 mots de passe uniques avant réutilisation
net accounts /UNIQUEPW:3

# Vérification
net accounts
```

### 2.2 Création des groupes

```powershell
net localgroup SalesTeam /add
net localgroup MarketingTeam /add
net localgroup FinanceTeam /add
net localgroup ITAdmins /add
```

### 2.3 Création des utilisateurs et affectation aux groupes

```powershell
# --- Sales ---
net user Alice * /add
net user Bob * /add
net localgroup SalesTeam Alice /add
net localgroup SalesTeam Bob /add

# --- Marketing ---
net user Clara * /add
net user Dave * /add
net localgroup MarketingTeam Clara /add
net localgroup MarketingTeam Dave /add

# --- Finance ---
net user Eve * /add
net user Frank * /add
net localgroup FinanceTeam Eve /add
net localgroup FinanceTeam Frank /add

# --- IT ---
net user Grace * /add
net user Henry * /add
net localgroup ITAdmins Grace /add
net localgroup ITAdmins Henry /add

# Ajouter ITAdmins au groupe Administrators local pour les droits d'administration
net localgroup Administrators Grace /add
net localgroup Administrators Henry /add
```

> **Vérification** : pour confirmer l'appartenance aux groupes :
>
> ```powershell
> net localgroup SalesTeam
> net localgroup MarketingTeam
> net localgroup FinanceTeam
> net localgroup ITAdmins
> ```

### 2.4 Création de l'arborescence

```powershell
# Dossiers de données
New-Item -Path "C:\NovaTechData\Sales" -ItemType Directory -Force
New-Item -Path "C:\NovaTechData\Marketing" -ItemType Directory -Force
New-Item -Path "C:\NovaTechData\Finance" -ItemType Directory -Force

# Dossiers pour les scripts et les logs
New-Item -Path "C:\Scripts" -ItemType Directory -Force
New-Item -Path "C:\Logs" -ItemType Directory -Force
```

### 2.5 Configuration des permissions NTFS

La stratégie consiste à :

1. **Désactiver l'héritage** sur `C:\NovaTechData` pour partir d'une base propre
2. **Supprimer les permissions par défaut** (sauf SYSTEM et Administrators)
3. **Appliquer les permissions spécifiques** par groupe selon la matrice

```powershell
# ============================================================
# Étape 1 : Désactiver l'héritage sur le dossier racine
# ============================================================

$acl = Get-Acl "C:\NovaTechData"
# Désactive l'héritage et convertit les permissions héritées en permissions explicites
$acl.SetAccessRuleProtection($true, $true)
Set-Acl "C:\NovaTechData" $acl

# ============================================================
# Étape 2 : Nettoyer les permissions existantes sur chaque dossier
# Conserver uniquement SYSTEM et Administrators
# ============================================================

$folders = @(
    "C:\NovaTechData\Sales",
    "C:\NovaTechData\Marketing",
    "C:\NovaTechData\Finance"
)

foreach ($folder in $folders) {
    $acl = Get-Acl $folder

    # Désactiver l'héritage et convertir en permissions explicites
    $acl.SetAccessRuleProtection($true, $true)

    # Supprimer toutes les règles sauf SYSTEM et Administrators
    $acl.Access | Where-Object {
        $_.IdentityReference -notmatch "SYSTEM" -and
        $_.IdentityReference -notmatch "Administrators"
    } | ForEach-Object {
        $acl.RemoveAccessRule($_)
    }

    Set-Acl $folder $acl
}

# ============================================================
# Étape 3 : Appliquer les permissions par groupe
# ============================================================

# --- Sales ---
$acl = Get-Acl "C:\NovaTechData\Sales"

# SalesTeam : Modify
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "SalesTeam", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow"
)
$acl.AddAccessRule($rule)

# MarketingTeam : Read (lecture seule sur Sales)
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "MarketingTeam", "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow"
)
$acl.AddAccessRule($rule)

# ITAdmins : FullControl
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "ITAdmins", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
)
$acl.AddAccessRule($rule)

Set-Acl "C:\NovaTechData\Sales" $acl

# --- Marketing ---
$acl = Get-Acl "C:\NovaTechData\Marketing"

# MarketingTeam : Modify
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "MarketingTeam", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow"
)
$acl.AddAccessRule($rule)

# ITAdmins : FullControl
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "ITAdmins", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
)
$acl.AddAccessRule($rule)

Set-Acl "C:\NovaTechData\Marketing" $acl

# --- Finance ---
$acl = Get-Acl "C:\NovaTechData\Finance"

# FinanceTeam : FullControl
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "FinanceTeam", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
)
$acl.AddAccessRule($rule)

# ITAdmins : FullControl
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "ITAdmins", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
)
$acl.AddAccessRule($rule)

Set-Acl "C:\NovaTechData\Finance" $acl
```

> **Vérification** : pour confirmer les permissions appliquées :
>
> ```powershell
> Get-Acl "C:\NovaTechData\Sales" | Format-List
> Get-Acl "C:\NovaTechData\Marketing" | Format-List
> Get-Acl "C:\NovaTechData\Finance" | Format-List
> ```
>
> Ou avec le module NTFSSecurity (s'il est installé) :
>
> ```powershell
> Get-NTFSAccess -Path "C:\NovaTechData\Sales"
> Get-NTFSAccess -Path "C:\NovaTechData\Marketing"
> Get-NTFSAccess -Path "C:\NovaTechData\Finance"
> ```

### 2.6 Script de rapport quotidien

Créer le fichier `C:\Scripts\daily-report.ps1` :

```powershell
# ============================================================
# Script : Rapport quotidien d'utilisation des fichiers
# Objectif : scanner chaque dossier départemental et compter
#            le nombre de fichiers modifiés dans la journée
# Sortie : C:\Logs\daily-report.txt
# ============================================================

$reportPath = "C:\Logs\daily-report.txt"
$today = (Get-Date).Date
$departments = @(
    @{ Name = "Sales";     Path = "C:\NovaTechData\Sales" },
    @{ Name = "Marketing"; Path = "C:\NovaTechData\Marketing" },
    @{ Name = "Finance";   Path = "C:\NovaTechData\Finance" }
)

# En-tête du rapport
$header = @"
============================================================
  NOVATECH - Rapport quotidien d'utilisation des fichiers
  Date : $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
============================================================
"@

Add-Content -Path $reportPath -Value $header

# Analyse de chaque dossier départemental
foreach ($dept in $departments) {
    if (Test-Path $dept.Path) {
        # Récupérer les fichiers modifiés aujourd'hui
        $modifiedFiles = Get-ChildItem -Path $dept.Path -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -ge $today }

        $count = ($modifiedFiles | Measure-Object).Count
        $totalSize = ($modifiedFiles | Measure-Object -Property Length -Sum).Sum
        $totalSizeKB = if ($totalSize) { [math]::Round($totalSize / 1KB, 2) } else { 0 }

        $entry = @"

Département : $($dept.Name)
  Dossier         : $($dept.Path)
  Fichiers modifiés aujourd'hui : $count
  Taille totale des modifications : $totalSizeKB Ko
"@

        # Lister les fichiers modifiés s'il y en a
        if ($count -gt 0) {
            $entry += "`n  Détail :"
            foreach ($file in $modifiedFiles) {
                $entry += "`n    - $($file.Name) ($([math]::Round($file.Length / 1KB, 2)) Ko) - modifié à $($file.LastWriteTime.ToString('HH:mm:ss'))"
            }
        }

        Add-Content -Path $reportPath -Value $entry
    }
    else {
        Add-Content -Path $reportPath -Value "`nDépartement : $($dept.Name) - ERREUR : dossier introuvable ($($dept.Path))"
    }
}

# Pied de rapport
Add-Content -Path $reportPath -Value "`n============================================================`n"
```

### 2.7 Tâche planifiée pour le rapport quotidien

```powershell
# Déclencheur : tous les jours à 19h00
$trigger = New-ScheduledTaskTrigger -Daily -At "7:00PM"

# Action : exécuter le script de rapport
$action = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument "-ExecutionPolicy Bypass -File C:\Scripts\daily-report.ps1" `
    -WorkingDirectory "C:\Scripts"

# Contexte d'exécution : compte SYSTEM avec privilèges élevés
$principal = New-ScheduledTaskPrincipal `
    -UserId "SYSTEM" `
    -LogonType ServiceAccount `
    -RunLevel Highest

# Options : relancer si manqué, limiter à 15 minutes d'exécution
$settings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 15) `
    -RestartCount 2 `
    -RestartInterval (New-TimeSpan -Minutes 5)

# Enregistrement
Register-ScheduledTask `
    -TaskName "NovaTech-DailyFileReport" `
    -Trigger $trigger `
    -Action $action `
    -Principal $principal `
    -Settings $settings `
    -Description "Rapport quotidien du nombre de fichiers modifiés par département" `
    -TaskPath "\NovaTech\"
```

> **Vérification** :
>
> ```powershell
> # Confirmer que la tâche est enregistrée
> Get-ScheduledTask -TaskName "NovaTech-DailyFileReport"
>
> # Tester manuellement le script
> powershell.exe -ExecutionPolicy Bypass -File C:\Scripts\daily-report.ps1
>
> # Vérifier le rapport généré
> type C:\Logs\daily-report.txt
> ```

---

## 3. Vérification globale

Script de vérification rapide de l'ensemble de l'implémentation :

```powershell
Write-Host "=== POLITIQUE DE COMPTES ===" -ForegroundColor Cyan
net accounts

Write-Host "`n=== GROUPES ET MEMBRES ===" -ForegroundColor Cyan
foreach ($group in @("SalesTeam", "MarketingTeam", "FinanceTeam", "ITAdmins")) {
    Write-Host "`n--- $group ---" -ForegroundColor Yellow
    net localgroup $group
}

Write-Host "`n=== PERMISSIONS NTFS ===" -ForegroundColor Cyan
foreach ($folder in @("C:\NovaTechData\Sales", "C:\NovaTechData\Marketing", "C:\NovaTechData\Finance")) {
    Write-Host "`n--- $folder ---" -ForegroundColor Yellow
    (Get-Acl $folder).Access | Format-Table IdentityReference, FileSystemRights, AccessControlType -AutoSize
}

Write-Host "`n=== TÂCHES PLANIFIÉES ===" -ForegroundColor Cyan
Get-ScheduledTask -TaskPath "\NovaTech\" | Format-Table TaskName, State -AutoSize
```

---

## 4. Diagramme d'architecture

```
                    ┌─────────────────────────┐
                    │      ITAdmins           │
                    │   Grace, Henry          │
                    │   FullControl partout   │
                    └────────┬────────────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
    ┌─────────▼──────┐ ┌────▼────────┐ ┌───▼──────────┐
    │ Sales          │ │ Marketing   │ │ Finance      │
    │ C:\...\Sales   │ │ C:\...\Mkt  │ │ C:\...\Fin   │
    └─────────┬──────┘ └────┬────────┘ └───┬──────────┘
              │             │              │
    ┌─────────▼──────┐ ┌────▼────────┐ ┌───▼──────────┐
    │ SalesTeam      │ │ MarketTeam  │ │ FinanceTeam  │
    │ Alice, Bob     │ │ Clara, Dave │ │ Eve, Frank   │
    │ Modify         │ │ Modify      │ │ FullControl  │
    └────────────────┘ │ + Read on   │ └──────────────┘
                       │   Sales     │
                       └─────────────┘

    ┌─────────────────────────────────────────────────┐
    │ Tâche planifiée : NovaTech-DailyFileReport      │
    │ Fréquence : quotidienne à 19h00                 │
    │ Script : C:\Scripts\daily-report.ps1            │
    │ Sortie : C:\Logs\daily-report.txt               │
    │ Contexte : SYSTEM                               │
    └─────────────────────────────────────────────────┘

    ┌─────────────────────────────────────────────────┐
    │ Politique de comptes                            │
    │ Longueur min. : 12 | Expiration : 30 jours      │
    │ Historique : 3 mots de passe uniques            │
    └─────────────────────────────────────────────────┘
```
