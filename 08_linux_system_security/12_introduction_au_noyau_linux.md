# Introduction au noyau Linux

**Durée : 15 min**

## Ce que vous allez apprendre dans ce cours

Maintenant que vous êtes familier avec les bases d'un système Linux, parlons un peu du noyau Linux et de ses composants.

---

## Le cas de touch file.txt

Souvenez-vous du premier jour quand nous avons parlé de ce qui se passe quand vous exécutez `touch file.txt` ? Il est temps de regarder d'un peu plus près ce qui se passe au niveau du noyau Linux pendant ce processus !

![Diagramme touch file.txt](assets/touch_file.png)

### Composants du noyau impliqués

Exécuter cette commande implique ces composants du noyau :

| Composant | Rôle dans touch file.txt |
|-----------|-------------------------|
| **System Call Interface (SCI)** | Point d'entrée dans le noyau depuis l'espace utilisateur. C'est ainsi que les applications userspace demandent des services (ex: création de fichier, gestion de processus). Ici, le shell appelle `fork()` pour créer le processus touch qui appelle ensuite `open()`. |
| **Process Management** | Responsable de tout ce qui concerne la création, gestion et terminaison des processus. Contient le gestionnaire de signaux et l'ordonnanceur de processus. Ici, l'ordonnanceur place le nouveau processus touch dans la file d'exécution et décide quand il obtient du temps CPU. |
| **Virtual File System (VFS)** | Fournit une interface commune pour interagir avec différents systèmes de fichiers. C'est ce qui permet à Linux de supporter différents systèmes de fichiers de manière uniforme. Ici, le VFS interprète le syscall, vérifie l'existence du fichier et le route vers l'implémentation appropriée. C'est aussi le composant qui vérifie les permissions. |
| **Linux Security Modules (LSM)** | SELinux ou AppArmor peuvent imposer des vérifications supplémentaires pendant les opérations comme la création de fichier, mais ils ne sont pas toujours activés. |
| **Device Drivers** | Modules du noyau qui communiquent avec le matériel. Chaque interaction matérielle (comme le disque ou le réseau) est routée via un pilote. |

---

## Autres composants importants du noyau

Comme vous pouvez le voir, il y a beaucoup à considérer quand on regarde les internes du noyau Linux. Voici les autres composants importants :

| Composant | Description |
|-----------|-------------|
| **Memory Management** | Gère la mémoire physique et virtuelle. Inclut la pagination, le swapping, et assure que chaque processus a un espace mémoire isolé. |
| **Inter-process Communication (IPC)** | Fournit des mécanismes pour que les processus communiquent et se synchronisent entre eux (ex: signaux, pipes, mémoire partagée). |
| **Network Stack** | Gère toutes les opérations liées au réseau, des transmissions de paquets bas niveau aux protocoles haut niveau comme TCP/IP. |

### Schéma des composants

```
+--------------------------------------------------+
|                 Espace Utilisateur               |
|  (Applications, Shell, Bibliothèques)            |
+--------------------------------------------------+
                        |
                   System Calls
                        |
+--------------------------------------------------+
|                   Noyau Linux                    |
|                                                  |
|  +------------+  +------------+  +------------+  |
|  |  Process   |  |   Memory   |  |    VFS     |  |
|  | Management |  | Management |  |            |  |
|  +------------+  +------------+  +------------+  |
|                                                  |
|  +------------+  +------------+  +------------+  |
|  |    IPC     |  |  Network   |  |    LSM     |  |
|  |            |  |   Stack    |  |            |  |
|  +------------+  +------------+  +------------+  |
|                                                  |
|  +------------------------------------------+    |
|  |           Device Drivers                 |    |
|  +------------------------------------------+    |
+--------------------------------------------------+
                        |
+--------------------------------------------------+
|                    Matériel                      |
|  (CPU, RAM, Disques, Réseau, Périphériques)      |
+--------------------------------------------------+
```

---

## Pourquoi connaître le noyau ?

Bien qu'il soit très improbable que vous ayez à modifier ces composants, il est toujours bon d'être conscient de leur existence au cas où vous auriez à résoudre un problème spécifique.

Dans les leçons suivantes, nous nous concentrerons sur la façon dont vous interagissez avec le noyau en tant qu'utilisateur/administrateur pour le protéger :

| Sujet | Description |
|-------|-------------|
| **Versionnage et patching** | Comment maintenir votre noyau à jour et sécurisé |
| **Modules du noyau** | Comment les modules étendent les fonctionnalités du noyau |
| **Linux Security Modules** | Comment SELinux et AppArmor ajoutent une couche de sécurité |

---

## Glossaire des sigles et définitions

| Sigle/Terme | Définition |
|-------------|------------|
| **Kernel** | Noyau - Composant central du système d'exploitation |
| **SCI** | System Call Interface - Interface d'appels système |
| **VFS** | Virtual File System - Système de fichiers virtuel |
| **LSM** | Linux Security Modules - Modules de sécurité Linux |
| **IPC** | Inter-Process Communication - Communication inter-processus |
| **Process Management** | Gestion des processus par le noyau |
| **Memory Management** | Gestion de la mémoire par le noyau |
| **Device Driver** | Pilote de périphérique |
| **Scheduler** | Ordonnanceur - Décide quel processus obtient du temps CPU |
| **Syscall** | System Call - Appel système |

---

## Ressources

- The Linux Kernel Documentation - kernel.org

### Ressources pratiques - TryHackMe / HackTheBox

| Plateforme | Room/Lab | Description |
|------------|----------|-------------|
| TryHackMe | [Linux Fundamentals Part 1](https://tryhackme.com/room/linuxfundamentalspart1) | Introduction à Linux |
| TryHackMe | [Linux Privilege Escalation](https://tryhackme.com/room/linprivesc) | Exploits noyau pour l'élévation de privilèges |
| TryHackMe | [Dirty Pipe](https://tryhackme.com/room/dvdirtypipe) | CVE-2022-0847 - Vulnérabilité noyau |
