# Network Address: 192.168.10.0/24

## Exercise 1: Basic Subnetting

Divide this network into 4 equal subnets.

Sous-reseau 1
   Reseau:      192.168.10.0/26
   Masque:      255.255.255.192
   Broadcast:   192.168.10.63
   Plage:       192.168.10.1 - 192.168.10.62
   Nb d'hotes:  62

Sous-reseau 2
  Reseau:      192.168.10.64/26
  Masque:      255.255.255.192
  Broadcast:   192.168.10.127
  Plage:       192.168.10.65 - 192.168.10.126
  Nb d'hotes:  62

Sous-reseau 3
  Reseau:      192.168.10.128/26
  Masque:      255.255.255.192
  Broadcast:   192.168.10.191
  Plage:       192.168.10.129 - 192.168.10.190
  Nb d'hotes:  62

Sous-reseau 4
  Reseau:      192.168.10.192/26
  Masque:      255.255.255.192
  Broadcast:   192.168.10.255
  Plage:       192.168.10.193 - 192.168.10.254
  Nb d'hotes:  62

### Vérification avec NetProbe

```bash
./NetProbe info 192.168.10.0/26
```

Sortie :
```
╔══════════════════════════════════════════════════════════════════════════════╗
║                            ANALYSE IPv4                                      ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ Adresse saisie   : 192.168.10.0/26                                           ║
║ Type             : Privée (RFC 1918)                                         ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ INFORMATIONS RÉSEAU                                                          ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ Adresse réseau   : 192.168.10.0                                              ║
║ Masque           : 255.255.255.192                                           ║
║ Broadcast        : 192.168.10.63                                             ║
║ Plage hôtes      : 192.168.10.1 - 192.168.10.62                              ║
║ Nb hôtes         : 62                                                        ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

## Exercise 2: Variable-Length Subnetting (VLSM)

You need to create subnets for different departments based on their IP address requirements:

    IT Department: 50 devices
    HR Department: 25 devices
    Sales Department: 10 devices
    Logistics Department: 5 devices

IT
 Reseau:      192.168.10.0/26
 Masque:      255.255.255.192
 Broadcast:   192.168.10.63
 Plage:       192.168.10.1 - 192.168.10.62
 Nb d'hotes:  62

HR
 Reseau:      192.168.10.64/27
 Masque:      255.255.255.224
 Broadcast:   192.168.10.95
 Plage:       192.168.10.65 - 192.168.10.94
 Nb d'hotes:  30

Sales
 Reseau:      192.168.10.96/28
 Masque:      255.255.255.240
 Broadcast:   192.168.10.111
 Plage:       192.168.10.97 - 192.168.10.110
 Nb d'hotes:  14

Logistics
 Reseau:      192.168.10.112/29
 Masque:      255.255.255.248
 Broadcast:   192.168.10.119
 Plage:       192.168.10.113 - 192.168.10.118
 Nb d'hotes:  6

### Vérification VLSM avec NetProbe

```bash
./NetProbe vlsm 192.168.10.0/24
# Entrer : IT=50, HR=25, Sales=10, Logistics=5
```

Sortie :
```
╔══════════════════════════════════════════════════════════════════════════════╗
║                           VLSM - 192.168.10.0/24                             ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  #  │ Département  │ Réseau              │ Masque          │ Hôtes │ Demandé ║
║─────┼──────────────┼─────────────────────┼─────────────────┼───────┼─────────║
║  1  │ IT           │ 192.168.10.0/26     │ 255.255.255.192 │   62  │   50    ║
║  2  │ HR           │ 192.168.10.64/27    │ 255.255.255.224 │   30  │   25    ║
║  3  │ Sales        │ 192.168.10.96/28    │ 255.255.255.240 │   14  │   10    ║
║  4  │ Logistics    │ 192.168.10.112/29   │ 255.255.255.248 │    6  │    5    ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ Espace libre: 192.168.10.120 - 192.168.10.255 (136 adresses)                 ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

# Part 2: IPv6 Subnetting
 
 ## Exercise 3: Splitting into /56 Subnets
 
Sous-reseau 1
Reseau:      2001:db8:abcd:0:0:0:0:0/52
 
Sous-reseau 2
Reseau:      2001:db8:abcd:1000:0:0:0:0/52

Sous-reseau 3
Reseau:      2001:db8:abcd:2000:0:0:0:0/52

Sous-reseau 4
Reseau:      2001:db8:abcd:3000:0:0:0:0/52

Sous-reseau 5
Reseau:      2001:db8:abcd:4000:0:0:0:0/52

Sous-reseau 6
Reseau:      2001:db8:abcd:5000:0:0:0:0/52

Sous-reseau 7
Reseau:      2001:db8:abcd:6000:0:0:0:0/52

Sous-reseau 8
Reseau:      2001:db8:abcd:7000:0:0:0:0/52

Sous-reseau 9
Reseau:      2001:db8:abcd:8000:0:0:0:0/52

Sous-reseau 10
Reseau:      2001:db8:abcd:9000:0:0:0:0/52

Sous-reseau 11
Reseau:      2001:db8:abcd:a000:0:0:0:0/52

Sous-reseau 12
Reseau:      2001:db8:abcd:b000:0:0:0:0/52

Sous-reseau 13
Reseau:      2001:db8:abcd:c000:0:0:0:0/52

Sous-reseau 14
Reseau:      2001:db8:abcd:d000:0:0:0:0/52

Sous-reseau 15
Reseau:      2001:db8:abcd:e000:0:0:0:0/52
 
Sous-reseau 16
Reseau:      2001:db8:abcd:f000:0:0:0:0/52

## Exercise 4: Splitting into /64 Subnets

Sous-reseau 1
Reseau:      2001:db8:abcd:1000:0:0:0:0/59

Sous-reseau 2
Reseau:      2001:db8:abcd:1020:0:0:0:0/59

Sous-reseau 3
Reseau:      2001:db8:abcd:1040:0:0:0:0/59

Sous-reseau 4
Reseau:      2001:db8:abcd:1060:0:0:0:0/59

Sous-reseau 5
Reseau:      2001:db8:abcd:1080:0:0:0:0/59

Sous-reseau 6
Reseau:      2001:db8:abcd:10a0:0:0:0:0/59

Sous-reseau 7
Reseau:      2001:db8:abcd:10c0:0:0:0:0/59

Sous-reseau 8
Reseau:      2001:db8:abcd:10e0:0:0:0:0/59
