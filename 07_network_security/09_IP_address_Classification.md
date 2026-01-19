# IP address classification

## Part 1: IPv4 classification

For each IPv4 address below, specify its class (A, B, C, D, or E), determine whether it is private or public, and mention any special usage (loopback, multicast, experimental, etc.) if applicable.

| Adresse | Type | Classe | Détail |
|---------|------|--------|--------|
| 10.0.45.2 | PRIVATE | A | RFC 1918 - Classe A privée |
| 172.20.10.5 | PRIVATE | B | RFC 1918 - Classe B privée |
| 192.168.100.200 | PRIVATE | C | RFC 1918 - Classe C privée |
| 8.8.4.4 | PUBLIC | A | Adresse publique routable |
| 203.0.113.15 | DOCUMENTATION | C | RFC 5737 - TEST-NET-3 |
| 127.0.0.1 | LOOPBACK | A | Adresse de bouclage |
| 224.5.6.7 | MULTICAST | D | Classe D - Multicast |
| 240.0.0.1 | RESERVED | E | Classe E - Expérimental |
| 169.254.1.1 | LINK_LOCAL | B | APIPA (auto-configuration) |
| 198.51.100.25 | DOCUMENTATION | C | RFC 5737 - TEST-NET-2 |

### Vérification avec NetProbe

```bash
./NetProbe classify 10.0.45.2
```

Sortie :
```
╔══════════════════════════════════════════════════════════════════════════════╗
║                            ANALYSE IPv4                                      ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ Adresse saisie   : 10.0.45.2                                                 ║
║ Type             : Privée (RFC 1918)                                         ║
║ Classe           : A                                                         ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ INFORMATIONS RÉSEAU (masque par défaut classe A)                             ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ Adresse réseau   : 10.0.0.0                                                  ║
║ Masque           : 255.0.0.0                                                 ║
║ Broadcast        : 10.255.255.255                                            ║
║ Nb hôtes         : 16777214                                                  ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

```bash
./NetProbe classify 8.8.4.4
```

Sortie :
```
╔══════════════════════════════════════════════════════════════════════════════╗
║                            ANALYSE IPv4                                      ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ Adresse saisie   : 8.8.4.4                                                   ║
║ Type             : Publique                                                  ║
║ Classe           : A                                                         ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---

## Part 2: IPv6 classification

For each IPv6 address below, determine whether it is public or private and identify its specific usage (loopback, link-local, unique local, etc.).

| Adresse | Type | Détail |
|---------|------|--------|
| 2001:db8::ff00:42:8329 | DOCUMENTATION | RFC 3849 - Documentation |
| fe80::1 | LINK_LOCAL | RFC 4291 - Link-Local |
| fc00::1234:abcd | PRIVATE | RFC 4193 - Unique Local Address |
| ::1 | LOOPBACK | Adresse de bouclage IPv6 |
| 2001:4860:4860::8888 | PUBLIC | Adresse publique routable |
| ff02::1 | MULTICAST | RFC 4291 - Multicast |
| fd12:3456:789a::1 | PRIVATE | RFC 4193 - Unique Local Address |
| ::ffff:192.168.1.1 | INVALIDE | Adresse IP invalide (format non supporté) |

### Vérification IPv6 avec NetProbe

```bash
./NetProbe classify fe80::1
```

Sortie :
```
╔══════════════════════════════════════════════════════════════════════════════╗
║                            ANALYSE IPv6                                      ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ Adresse saisie   : fe80::1                                                   ║
║ Type             : Link-Local (RFC 4291)                                     ║
║ Forme complète   : fe80:0000:0000:0000:0000:0000:0000:0001                    ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

```bash
./NetProbe info 2001:db8::ff00:42:8329/64
```

Sortie :
```
╔══════════════════════════════════════════════════════════════════════════════╗
║                            ANALYSE IPv6                                      ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ Adresse saisie   : 2001:db8::ff00:42:8329/64                                 ║
║ Type             : Documentation (RFC 3849)                                  ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ INFORMATIONS RÉSEAU                                                          ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ Adresse réseau   : 2001:db8::                                                ║
║ Préfixe          : /64                                                       ║
╚══════════════════════════════════════════════════════════════════════════════╝
```
