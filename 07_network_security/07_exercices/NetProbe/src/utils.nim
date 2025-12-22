# =============================================================================
# UTILS - Fonctions utilitaires partagées
# =============================================================================
#
# Ce module contient les fonctions de conversion et manipulation d'adresses IP
# utilisées par les autres modules de NetProbe.
#
# CONCEPTS RÉSEAU FONDAMENTAUX :
#
# 1. ADRESSE IPv4 (32 bits)
#    Une adresse IPv4 est composée de 4 octets (8 bits chacun), séparés par des points.
#    Chaque octet peut avoir une valeur de 0 à 255.
#
#    Exemple: 192.168.1.100
#      192      .168      .1        .100
#      11000000  10101000  00000001  01100100
#      ^^^^^^^^  ^^^^^^^^  ^^^^^^^^  ^^^^^^^^
#      octet 0   octet 1   octet 2   octet 3
#
#    Pour manipuler une IPv4 en calcul, on la convertit en un seul nombre uint32 :
#      192 << 24 = 11000000 00000000 00000000 00000000
#      168 << 16 = 00000000 10101000 00000000 00000000
#      1   << 8  = 00000000 00000000 00000001 00000000
#      100 << 0  = 00000000 00000000 00000000 01100100
#      ─────────────────────────────────────────────────
#      OR        = 11000000 10101000 00000001 01100100 = 3232235876
#
# 2. ADRESSE IPv6 (128 bits)
#    Une adresse IPv6 est composée de 8 groupes de 16 bits en hexadécimal.
#
#    Exemple: 2001:0db8:85a3:0000:0000:8a2e:0370:7334
#      2001  :0db8  :85a3  :0000  :0000  :8a2e  :0370  :7334
#      ^^^^   ^^^^   ^^^^   ^^^^   ^^^^   ^^^^   ^^^^   ^^^^
#      16bits 16bits 16bits 16bits 16bits 16bits 16bits 16bits
#      |_____________ high (64 bits) ___|___ low (64 bits) ___|
#
#    Notation compressée avec "::"
#      :: remplace une suite de groupes à 0
#      ::1         = 0000:0000:0000:0000:0000:0000:0000:0001 (loopback)
#      fe80::1     = fe80:0000:0000:0000:0000:0000:0000:0001
#
#    Stockage: comme 128 bits > 64 bits, on utilise 2 uint64 (high et low)
#
# 3. NOTATION CIDR
#    Le CIDR (Classless Inter-Domain Routing) indique la taille du réseau.
#    Format: adresse/préfixe
#
#    IPv4: préfixe de 0 à 32 (ex: 192.168.1.0/24)
#    IPv6: préfixe de 0 à 128 (ex: 2001:db8::/32)
#
#    Le préfixe indique combien de bits définissent la partie réseau :
#      IPv4 /24 → 24 bits réseau, 8 bits hôtes  → 254 adresses
#      IPv6 /64 → 64 bits réseau, 64 bits hôtes → 2^64 adresses
#
# 4. MASQUE DE SOUS-RÉSEAU
#    Le masque est un nombre avec des 1 pour la partie réseau
#    et des 0 pour la partie hôtes.
#
#    Préfixe → Masque :
#      /24 → 11111111.11111111.11111111.00000000 = 255.255.255.0
#      /16 → 11111111.11111111.00000000.00000000 = 255.255.0.0
#
#    CALCUL DU MASQUE IPv4 : 0xFFFFFFFF << (32 - préfixe)
#    ──────────────────────────────────────────────────────
#
#    Étape 1 : On part de 0xFFFFFFFF (32 bits tous à 1)
#      0xFFFFFFFF = 11111111 11111111 11111111 11111111
#
#    Étape 2 : On décale vers la gauche de (32 - préfixe) bits
#      Le décalage "pousse" des 0 à droite
#
#    Exemple avec /24 (préfixe = 24) :
#      32 - 24 = 8 bits à décaler
#      Avant:  11111111 11111111 11111111 11111111
#              ←←←←←←←← on pousse 8 zéros à droite
#      Après:  11111111 11111111 11111111 00000000
#              = 255.255.255.0
#
#    Exemple avec /16 (préfixe = 16) :
#      32 - 16 = 16 bits à décaler
#      Avant:  11111111 11111111 11111111 11111111
#              ←←←←←←←← on pousse 16 zéros à droite
#      Après:  11111111 11111111 00000000 00000000
#              = 255.255.0.0
#
#    Exemple avec /8 (préfixe = 8) :
#      32 - 8 = 24 bits à décaler
#      Avant:  11111111 11111111 11111111 11111111
#      Après:  11111111 00000000 00000000 00000000
#              = 255.0.0.0
#
#    Pourquoi ça marche ?
#      - Le préfixe indique combien de bits représentent le réseau
#      - Ces bits doivent être à 1 dans le masque
#      - Les bits restants (pour les hôtes) doivent être à 0
#      - En décalant à gauche, on garde les 1 à gauche et on met des 0 à droite
#
#    CALCUL DU MASQUE IPv6 : même principe sur 128 bits
#    ──────────────────────────────────────────────────────
#    Comme 128 bits > 64 bits (taille max d'un entier), on utilise 2 parties :
#      - Si préfixe ≤ 64 : seule la partie "high" a des 1
#      - Si préfixe > 64 : "high" = tous à 1, "low" partiellement
#
# 5. CALCUL DE L'ADRESSE RÉSEAU : IP AND masque
#    ──────────────────────────────────────────────────────
#    L'opération AND bit à bit garde uniquement les bits réseau.
#
#    Exemple : 192.168.5.42 dans le réseau /24
#      IP:      11000000 10101000 00000101 00101010 (192.168.5.42)
#      Masque:  11111111 11111111 11111111 00000000 (/24)
#               ──────────────────────────────────────
#      AND:     11000000 10101000 00000101 00000000 (192.168.5.0)
#
#    Le AND conserve les bits où le masque = 1, met à 0 les autres.
#    Résultat : la partie réseau de l'IP, avec les bits hôtes à 0.
#
# 6. CALCUL DE L'ADRESSE BROADCAST : réseau OR (NOT masque)
#    ──────────────────────────────────────────────────────
#    On met tous les bits hôtes à 1.
#
#    Exemple : réseau 192.168.5.0/24
#      Réseau:     11000000 10101000 00000101 00000000 (192.168.5.0)
#      Masque:     11111111 11111111 11111111 00000000
#      NOT masque: 00000000 00000000 00000000 11111111
#                  ──────────────────────────────────────
#      OR:         11000000 10101000 00000101 11111111 (192.168.5.255)
#
#    Le NOT inverse le masque (les 0 deviennent 1, les 1 deviennent 0).
#    Le OR avec le réseau met les bits hôtes à 1 → broadcast.
#
# 7. VÉRIFICATION D'APPARTENANCE À UN RÉSEAU
#    ──────────────────────────────────────────────────────
#    Une IP appartient à un réseau si : (IP AND masque) == (réseau AND masque)
#
#    Exemple : 192.168.5.42 appartient-elle à 192.168.0.0/16 ?
#      IP:      11000000 10101000 00000101 00101010 (192.168.5.42)
#      Masque:  11111111 11111111 00000000 00000000 (/16)
#               ──────────────────────────────────────
#      AND:     11000000 10101000 00000000 00000000 (192.168.0.0) ✓
#
#      Réseau:  11000000 10101000 00000000 00000000 (192.168.0.0)
#      Masque:  11111111 11111111 00000000 00000000
#               ──────────────────────────────────────
#      AND:     11000000 10101000 00000000 00000000 (192.168.0.0) ✓
#
#      Les deux AND sont égaux → l'IP appartient au réseau !
#
# =============================================================================

import strutils


## Convertit une adresse IPv4 string en nombre uint32.
##
## Paramètres:
##   - ip_str: adresse IPv4 sous forme de string (ex: "192.168.1.1")
##             accepte aussi le format CIDR (ex: "192.168.1.0/24")
##
## Retour: l'adresse sous forme de uint32
##
## Exemple:
##   echo ipv4_to_uint32("192.168.1.1")  # → 3232235777
##   echo ipv4_to_uint32("10.0.0.1")     # → 167772161
proc ipv4_to_uint32*(ip_str: string): uint32 =
  let ip = if '/' in ip_str: ip_str.split('/')[0] else: ip_str
  let parts = ip.split('.')
  for i, part in parts:
    let octet = uint32(parseInt(part))
    result = result or (octet shl (24 - i * 8))


## Convertit un nombre uint32 en adresse IPv4 string.
##
## Paramètres:
##   - ip_addr: adresse IPv4 sous forme de uint32
##
## Retour: l'adresse sous forme de string pointée
##
## Exemple:
##   echo uint32_to_ip(3232235777)  # → "192.168.1.1"
##   echo uint32_to_ip(0)           # → "0.0.0.0"
proc uint32_to_ip*(ip_addr: uint32): string =
  let octet1 = (ip_addr shr 24) and 0xFF
  let octet2 = (ip_addr shr 16) and 0xFF
  let octet3 = (ip_addr shr 8) and 0xFF
  let octet4 = ip_addr and 0xFF
  return $octet1 & "." & $octet2 & "." & $octet3 & "." & $octet4


## Extrait le préfixe CIDR d'une notation CIDR.
##
## Paramètres:
##   - cidr_str: notation CIDR (ex: "192.168.1.0/24")
##   - default_prefix: valeur par défaut si pas de préfixe
##
## Retour: le préfixe sous forme d'entier
##
## Exemple:
##   echo get_prefix("192.168.1.0/24", 32)  # → 24
##   echo get_prefix("192.168.1.1", 32)     # → 32 (défaut)
proc get_prefix*(cidr_str: string, default_prefix: int): int =
  if '/' in cidr_str:
    return parseInt(cidr_str.split('/')[1])
  return default_prefix


## Extrait l'adresse IP d'une notation CIDR.
##
## Paramètres:
##   - cidr_str: notation CIDR (ex: "192.168.1.0/24")
##
## Retour: l'adresse IP sans le préfixe
##
## Exemple:
##   echo get_ip_from_cidr("192.168.1.0/24")  # → "192.168.1.0"
##   echo get_ip_from_cidr("10.0.0.1")        # → "10.0.0.1"
proc get_ip_from_cidr*(cidr_str: string): string =
  if '/' in cidr_str:
    return cidr_str.split('/')[0]
  return cidr_str


## Convertit un préfixe CIDR en masque de sous-réseau uint32.
##
## Le masque est calculé en décalant 0xFFFFFFFF vers la gauche.
##
## Paramètres:
##   - prefix: le préfixe CIDR (0 à 32)
##
## Retour: le masque sous forme de uint32
##
## Exemple:
##   echo uint32_to_ip(prefix_to_mask(24))  # → "255.255.255.0"
##   echo uint32_to_ip(prefix_to_mask(16))  # → "255.255.0.0"
##   echo uint32_to_ip(prefix_to_mask(8))   # → "255.0.0.0"
proc prefix_to_mask*(prefix: int): uint32 =
  if prefix == 0:
    return 0'u32
  else:
    return 0xFFFFFFFF'u32 shl (32 - prefix)


## Vérifie si une adresse IPv4 appartient à un réseau.
##
## Utilise l'opération AND avec le masque pour comparer
## les parties réseau des deux adresses.
##
## Paramètres:
##   - ip_addr: adresse IPv4 en uint32
##   - network_cidr: notation CIDR du réseau (ex: "192.168.0.0/16")
##
## Retour: true si l'IP est dans le réseau
##
## Exemple:
##   let ip = ipv4_to_uint32("192.168.5.42")
##   echo is_in_network(ip, "192.168.0.0/16")  # → true
##   echo is_in_network(ip, "10.0.0.0/8")      # → false
proc is_in_network*(ip_addr: uint32, network_cidr: string): bool =
  let net_addr = ipv4_to_uint32(network_cidr)
  let prefix = get_prefix(network_cidr, 32)
  let mask = prefix_to_mask(prefix)
  return (ip_addr and mask) == (net_addr and mask)


# =============================================================================
# IPv6
# =============================================================================

type
  ## Représentation d'une adresse IPv6 sur 128 bits.
  ## Stockée en deux parties de 64 bits (high et low).
  IPv6Addr* = object
    high*: uint64   ## Bits 127-64 (4 premiers groupes)
    low*: uint64    ## Bits 63-0 (4 derniers groupes)


## Expanse une IPv6 compressée en forme complète (8 groupes).
##
## La notation :: représente une séquence de zéros consécutifs.
##
## Paramètres:
##   - ip_str: adresse IPv6 (peut être compressée)
##
## Retour: adresse IPv6 avec 8 groupes explicites
##
## Exemple:
##   echo expand_ipv6("::1")      # → "0:0:0:0:0:0:0:1"
##   echo expand_ipv6("fe80::1")  # → "fe80:0:0:0:0:0:0:1"
proc expand_ipv6*(ip_str: string): string =
  var ip_addr = ip_str
  if '/' in ip_addr:
    ip_addr = ip_addr.split('/')[0]

  if "::" in ip_addr:
    let parts = ip_addr.split("::")
    var left = if parts[0].len > 0: parts[0].split(':') else: @[]
    var right = if parts.len > 1 and parts[1].len > 0: parts[1].split(':') else: @[]
    let missing = 8 - left.len - right.len
    var expanded: seq[string] = @[]
    for p in left:
      expanded.add(p)
    for i in 0..<missing:
      expanded.add("0")
    for p in right:
      expanded.add(p)
    return expanded.join(":")
  else:
    return ip_addr


## Convertit une IPv6 string en IPv6Addr (2 x uint64).
##
## Paramètres:
##   - ip_str: adresse IPv6 (avec ou sans CIDR)
##
## Retour: structure IPv6Addr avec high et low
##
## Exemple:
##   let addr = ipv6_to_addr("2001:db8::1")
##   echo addr.high  # → partie haute 64 bits
proc ipv6_to_addr*(ip_str: string): IPv6Addr =
  let expanded = expand_ipv6(ip_str)
  let groups = expanded.split(':')

  # Les 4 premiers groupes → high (64 bits)
  for i in 0..3:
    let val = uint64(parseHexInt(groups[i]))
    result.high = result.high or (val shl (48 - i * 16))

  # Les 4 derniers groupes → low (64 bits)
  for i in 4..7:
    let val = uint64(parseHexInt(groups[i]))
    result.low = result.low or (val shl (48 - (i - 4) * 16))


## Convertit une IPv6Addr en string hexadécimale.
##
## Paramètres:
##   - ip_addr: adresse IPv6Addr
##
## Retour: adresse IPv6 sous forme de string
##
## Exemple:
##   let a = ipv6_to_addr("2001:db8::1")
##   echo addr_to_ipv6(a)  # → "2001:db8:0:0:0:0:0:1"
proc addr_to_ipv6*(ip_addr: IPv6Addr): string =
  var groups: seq[string] = @[]

  # Extraire les 4 groupes de high
  for i in 0..3:
    let val = (ip_addr.high shr (48 - i * 16)) and 0xFFFF
    # Strip only leading zeros, not trailing
    groups.add(toHex(val).strip(chars = {'0'}, leading = true, trailing = false))
    if groups[^1] == "":
      groups[^1] = "0"

  # Extraire les 4 groupes de low
  for i in 0..3:
    let val = (ip_addr.low shr (48 - i * 16)) and 0xFFFF
    # Strip only leading zeros, not trailing
    groups.add(toHex(val).strip(chars = {'0'}, leading = true, trailing = false))
    if groups[^1] == "":
      groups[^1] = "0"

  return groups.join(":").toLowerAscii()


## Calcule le masque IPv6 pour un préfixe donné.
##
## Retourne un tuple (high_mask, low_mask) représentant le masque 128 bits.
##
## Paramètres:
##   - prefix: le préfixe CIDR (0 à 128)
##
## Retour: tuple (high, low) du masque
##
## Exemple:
##   let (h, l) = prefix_to_mask_v6(64)
##   # h = 0xFFFFFFFFFFFFFFFF, l = 0
proc prefix_to_mask_v6*(prefix: int): (uint64, uint64) =
  if prefix == 0:
    return (0'u64, 0'u64)
  elif prefix <= 64:
    let high_mask = 0xFFFFFFFFFFFFFFFF'u64 shl (64 - prefix)
    return (high_mask, 0'u64)
  else:
    let low_bits = prefix - 64
    let low_mask = 0xFFFFFFFFFFFFFFFF'u64 shl (64 - low_bits)
    return (0xFFFFFFFFFFFFFFFF'u64, low_mask)


## Calcule l'adresse réseau IPv6 (applique le masque).
##
## Paramètres:
##   - ip_addr: adresse IPv6Addr
##   - prefix: préfixe CIDR
##
## Retour: adresse réseau IPv6Addr
proc get_network_v6*(ip_addr: IPv6Addr, prefix: int): IPv6Addr =
  let (high_mask, low_mask) = prefix_to_mask_v6(prefix)
  result.high = ip_addr.high and high_mask
  result.low = ip_addr.low and low_mask


## Additionne une valeur a une adresse IPv6.
##
## Gere le debordement de la partie low vers high.
##
## Parametres:
##   - ip_addr: adresse IPv6Addr de base
##   - value: valeur a ajouter (sur 64 bits max)
##
## Retour: nouvelle adresse IPv6Addr
proc add_to_ipv6*(ip_addr: IPv6Addr, value: uint64): IPv6Addr =
  let new_low = ip_addr.low + value
  # Verifier le debordement
  if new_low < ip_addr.low:
    # Debordement, incrementer high
    result.high = ip_addr.high + 1
    result.low = new_low
  else:
    result.high = ip_addr.high
    result.low = new_low


## Vérifie si une IPv6 appartient à un réseau.
##
## Paramètres:
##   - ip_addr: adresse IPv6 en IPv6Addr
##   - network_cidr: notation CIDR du réseau
##
## Retour: true si l'IP est dans le réseau
##
## Exemple:
##   let ip = ipv6_to_addr("fe80::1234")
##   echo is_in_network_v6(ip, "fe80::/10")  # → true
proc is_in_network_v6*(ip_addr: IPv6Addr, network_cidr: string): bool =
  let net_addr = ipv6_to_addr(network_cidr)
  let prefix = get_prefix(network_cidr, 128)

  if prefix == 0:
    return true
  elif prefix <= 64:
    let (high_mask, _) = prefix_to_mask_v6(prefix)
    return (ip_addr.high and high_mask) == (net_addr.high and high_mask)
  else:
    let (high_mask, low_mask) = prefix_to_mask_v6(prefix)
    return (ip_addr.high and high_mask) == (net_addr.high and high_mask) and
           (ip_addr.low and low_mask) == (net_addr.low and low_mask)
