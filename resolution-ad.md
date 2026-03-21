# Jonction d'un client Windows 10 à un domaine Active Directory

**Environnement :** Windows Server 2019 (DC) + Windows 10 (client)  
**Domaine :** `lab.local` | **DC :** `PC4` (`192.168.248.137`) | **Client :** `CLT-MOI-01` (`192.168.248.138`)

---

## Symptomes initiaux

- Erreur lors de la jonction au domaine : `Le nom DNS n'existe pas (0x0000232B RCODE_NAME_ERROR)`
- Le ping et le `nslookup lab.local` fonctionnaient entre les deux machines
- Les dossiers `_tcp`, `_udp`, `_sites` étaient absents de la zone DNS `lab.local`
- Seul `_msdcs` était présent dans la zone
- `nltest /sc_query:lab.local` retournait `ERROR_NO_SUCH_DOMAIN` depuis le DC lui-même

---

## Diagnostic pas à pas

### Étape 1 - Vérification de Netlogon et des SRV

```cmd
net stop netlogon
net start netlogon
nslookup -type=SRV _ldap._tcp.lab.local
```

Résultat : `Non-existent domain`. Les enregistrements SRV Kerberos/LDAP n'étaient pas enregistrés.

### Étape 2 - Analyse avec dcdiag

```cmd
dcdiag /test:registerindns /dnsdomain:lab.local /fix
dcdiag /test:dns /v > C:\dcdiag_dns.txt
findstr /i "fail erreur error" C:\dcdiag_dns.txt
```

Erreurs relevées :
- `Pas de connectivité LDAP`
- `Serveurs DNS non valides`
- `_ldap._tcp.LAB.local failed on the DNS server 192.168.248.137`
- `Error details: 9003 - Le nom DNS n'existe pas`

### Étape 3 - Vérification de l'état du DC

```cmd
echo %LOGONSERVER%         -> \\PC4
echo %USERDNSDOMAIN%       -> LAB.LOCAL
nltest /sc_query:lab.local -> ERROR_NO_SUCH_DOMAIN
netdom query fsmo          -> OK, tous les rôles sur PC4.lab.local
repadmin /showrepl         -> OK, IS_GC confirmé
dsquery server -domain lab.local -> CN=PC4 trouvé
```

Conclusion : AD était sain, le problème était uniquement au niveau de Netlogon et du DNS.

### Étape 4 - Vérification du fichier netlogon.log

```
C:\Windows\debug\netlogon.log
```

Le fichier faisait 3 octets (vide). Netlogon démarrait mais n'écrivait rien, confirmant qu'il ne s'authentifiait jamais auprès d'AD.

---

## Causes identifiées

1. **Zone DNS mal configurée lors de la première promotion**
   - La zone s'appelait `LAB.local` (avec majuscule) au lieu de `lab.local`
   - Deux noeuds DNS (`PC4` et `PC4.LAB.local`) dans la console, signe de corruption

2. **Zone non intégrée à Active Directory**
   - Le type était "Principal" au lieu de "Intégré à Active Directory"
   - Les mises à jour dynamiques sécurisées ne fonctionnaient pas correctement

3. **Dépendance circulaire**
   - Netlogon avait besoin des SRV pour s'authentifier via Kerberos
   - Mais il ne pouvait pas enregistrer les SRV sans être authentifié

---

## Solution appliquée

### Étape 1 - Rétrograder le DC

```powershell
Uninstall-ADDSDomainController `
  -DemoteOperationMasterRole `
  -ForceRemoval `
  -LocalAdministratorPassword (ConvertTo-SecureString "MotDePasse" -AsPlainText -Force)
```

### Étape 2 - Re-promouvoir proprement

DNS de la carte réseau pointé sur `127.0.0.1` avant la promotion.

```powershell
Install-ADDSForest `
  -DomainName "lab.local" `
  -DomainNetbiosName "LAB" `
  -InstallDns:$true `
  -SafeModeAdministratorPassword (ConvertTo-SecureString "MotDePasse" -AsPlainText -Force) `
  -Force:$true
```

La zone était désormais `lab.local` en minuscules et intégrée à AD, mais les SRV ne s'enregistraient toujours pas (dépendance circulaire persistante).

### Étape 3 - Enregistrement manuel des SRV

Lecture du fichier de référence :

```powershell
type C:\Windows\System32\config\netlogon.dns
```

Injection manuelle des enregistrements principaux :

```cmd
dnscmd /RecordAdd lab.local _ldap._tcp      SRV 0 100 389  pc4.lab.local.
dnscmd /RecordAdd lab.local _kerberos._tcp  SRV 0 100 88   pc4.lab.local.
dnscmd /RecordAdd lab.local _gc._tcp        SRV 0 100 3268 pc4.lab.local.
dnscmd /RecordAdd lab.local _kerberos._udp  SRV 0 100 88   pc4.lab.local.
dnscmd /RecordAdd lab.local _kpasswd._tcp   SRV 0 100 464  pc4.lab.local.
dnscmd /RecordAdd lab.local _kpasswd._udp   SRV 0 100 464  pc4.lab.local.
```

Vérification depuis le DC :

```powershell
nslookup -type=SRV _ldap._tcp.lab.local
# -> pc4.lab.local / 192.168.248.137 / port 389
```

### Étape 4 - Jonction du client au domaine

Depuis `CLT-MOI-01` (PowerShell) :

```powershell
Add-Computer -DomainName "lab.local" -Server "pc4.lab.local" -Credential (Get-Credential) -Restart
```

> Le paramètre `-Server` est indispensable ici pour contourner la découverte automatique du DC qui échouait malgré les SRV correctement enregistrés.

Identifiants utilisés : `LAB\Administrateur`

---

## Vérification finale

Depuis le DC :

```powershell
Get-ADComputer -Filter * | Select-Object Name
# -> CLT-MOI-01 doit apparaître
```

Depuis le client (après redémarrage) :

```powershell
(Get-WmiObject Win32_ComputerSystem).Domain
# -> lab.local
```

Connexion sur l'écran Windows avec `LAB\Administrateur` doit fonctionner.

---

## Points à retenir

- Lors de la promotion d'un DC, la carte réseau doit pointer sur `127.0.0.1` (ou sa propre IP), jamais sur un DNS externe
- La zone DNS doit être de type **Intégré à Active Directory**, pas "Principal"
- En cas de blocage de Netlogon, le fichier `C:\Windows\System32\config\netlogon.dns` contient la liste exacte des SRV à injecter manuellement via `dnscmd`
- `netlogon.log` vide après démarrage du service = Netlogon ne s'authentifie pas, chercher une dépendance circulaire DNS
- Le paramètre `-Server` dans `Add-Computer` permet de cibler un DC précis et contourne les problèmes de découverte automatique
