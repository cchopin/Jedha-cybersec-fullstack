import std/strutils

type
  NetworkKind* = enum
    LOOPBACK, PRIVATE, LINK_LOCAL, MULTICAST, RESERVED, SPECIAL, BROADCAST, CGNAT, DOCUMENTATION, PUBLIC

  NetworkInfo* = object
    kind*: NetworkKind
    detail*: string
    historicClass*: string

  # IPv6 = 128 bits = 2 x 64 bits
  IPv6Addr = object
    high*: uint64
    low*: uint64

# Plages IPv4 connues avec leur classification
const ipv4Ranges = [
  ("127.0.0.0/8", LOOPBACK, "Adresse de bouclage"),
  ("10.0.0.0/8", PRIVATE, "RFC 1918 - Classe A privee"),
  ("172.16.0.0/12", PRIVATE, "RFC 1918 - Classe B privee"),
  ("192.168.0.0/16", PRIVATE, "RFC 1918 - Classe C privee"),
  ("169.254.0.0/16", LINK_LOCAL, "APIPA (auto-configuration)"),
  ("224.0.0.0/4", MULTICAST, "Classe D - Multicast"),
  ("240.0.0.0/4", RESERVED, "Classe E - Experimental"),
  ("0.0.0.0/8", SPECIAL, "Reseau this"),
  ("255.255.255.255/32", BROADCAST, "Broadcast limite"),
  ("100.64.0.0/10", CGNAT, "RFC 6598 - Carrier-Grade NAT"),
  ("192.0.2.0/24", DOCUMENTATION, "RFC 5737 - TEST-NET-1"),
  ("198.51.100.0/24", DOCUMENTATION, "RFC 5737 - TEST-NET-2"),
  ("203.0.113.0/24", DOCUMENTATION, "RFC 5737 - TEST-NET-3"),
]

# Plages IPv6 connues avec leur classification
const ipv6Ranges = [
  ("::1/128", LOOPBACK, "Adresse de bouclage IPv6"),
  ("fc00::/7", PRIVATE, "RFC 4193 - Unique Local Address"),
  ("fe80::/10", LINK_LOCAL, "RFC 4291 - Link-Local"),
  ("ff00::/8", MULTICAST, "RFC 4291 - Multicast"),
  ("::/128", SPECIAL, "Adresse non specifiee"),
  ("::ffff:0:0/96", SPECIAL, "IPv4-mapped IPv6"),
  ("2001:db8::/32", DOCUMENTATION, "RFC 3849 - Documentation"),
  ("2001::/32", RESERVED, "RFC 4380 - Teredo"),
  ("2002::/16", RESERVED, "RFC 3056 - 6to4"),
  ("64:ff9b::/96", RESERVED, "RFC 6052 - NAT64"),
]

# =============================================================================
# IPv4
# =============================================================================
#
# Une adresse IPv4 = 32 bits = 4 octets (0-255 chacun)
#
# Exemple: 192.168.1.1
#   192      .168      .1        .1
#   11000000  10101000  00000001  00000001
#   ^^^^^^^^  ^^^^^^^^  ^^^^^^^^  ^^^^^^^^
#   octet 0   octet 1   octet 2   octet 3
#
# On combine les 4 octets en un seul nombre uint32:
#   192 << 24 = 11000000 00000000 00000000 00000000
#   168 << 16 = 00000000 10101000 00000000 00000000
#   1   << 8  = 00000000 00000000 00000001 00000000
#   1   << 0  = 00000000 00000000 00000000 00000001
#   ────────────────────────────────────────────────
#   OR        = 11000000 10101000 00000001 00000001 = 3232235777
#
# =============================================================================

# Convertit une IPv4 string en nombre uint32
# Exemple: "192.168.1.1" → 3232235777
proc ipv4ToUint32(ipCidr: string): uint32 =
  let ip = if '/' in ipCidr: ipCidr.split('/')[0] else: ipCidr
  let parts = ip.split('.')
  for i, part in parts:
    let octet = uint32(parseInt(part))
    result = result or (octet shl (24 - i * 8))

# Extrait le masque CIDR d'une adresse
proc getCidr(ipCidr: string, defaultCidr: int): int =
  if '/' in ipCidr:
    return parseInt(ipCidr.split('/')[1])
  return defaultCidr

# Vérifie si une IPv4 appartient à un réseau
#
# Le CIDR indique combien de bits sont fixes (la partie réseau):
#   /8  → 255.0.0.0       → 0xFF000000 → on garde 1 octet
#   /16 → 255.255.0.0     → 0xFFFF0000 → on garde 2 octets
#   /24 → 255.255.255.0   → 0xFFFFFF00 → on garde 3 octets
#
# Le masque sert de "pochoir": on compare seulement la partie réseau
#   (ip AND masque) == (réseau AND masque)
#
# Exemple: 192.168.5.42 est-il dans 192.168.0.0/16 ?
#   192.168.5.42  AND 255.255.0.0 = 192.168.0.0
#   192.168.0.0   AND 255.255.0.0 = 192.168.0.0
#   → égaux, donc oui!
#
# Comment fabriquer le masque:
#   0xFFFFFFFF = tous les bits à 1 (en hexa: FF.FF.FF.FF = 255.255.255.255)
#   shl = décalage à gauche, pousse des 0 à droite
#   0xFFFFFFFF shl (32 - 16) = 0xFFFFFFFF shl 16 = 0xFFFF0000 = 255.255.0.0
#
proc isInNetworkV4(ip: uint32, network: string): bool =
  let netIp = ipv4ToUint32(network)
  let cidr = getCidr(network, 32)
  let mask = if cidr > 0: 0xFFFFFFFF'u32 shl (32 - cidr) else: 0'u32
  return (ip and mask) == (netIp and mask)

# Retourne la classe historique (A, B, C, D, E) basée sur le premier octet
proc getHistoricClassV4(ipUint32: uint32): string =
  let firstOctet = (ipUint32 shr 24) and 0xFF
  if firstOctet < 128:
    return "A"
  elif firstOctet < 192:
    return "B"
  elif firstOctet < 224:
    return "C"
  elif firstOctet < 240:
    return "D"
  else:
    return "E"

# =============================================================================
# IPv6
# =============================================================================
#
# Une adresse IPv6 = 128 bits = 8 groupes de 16 bits (en hexadécimal)
#
# Exemple: 2001:0db8:85a3:0000:0000:8a2e:0370:7334
#   2001  :0db8  :85a3  :0000  :0000  :8a2e  :0370  :7334
#   ^^^^   ^^^^   ^^^^   ^^^^   ^^^^   ^^^^   ^^^^   ^^^^
#   16bits 16bits 16bits 16bits 16bits 16bits 16bits 16bits
#   |_____________ high (64 bits) ___|___ low (64 bits) ___|
#
# Notation compressée avec "::"
#   :: remplace une suite de groupes à 0
#   ::1         = 0000:0000:0000:0000:0000:0000:0000:0001 (loopback)
#   fe80::1     = fe80:0000:0000:0000:0000:0000:0000:0001
#   2001:db8::1 = 2001:0db8:0000:0000:0000:0000:0000:0001
#
# Stockage: comme 128 bits > 64 bits (uint64), on utilise 2 uint64:
#   high = les 4 premiers groupes (bits 127-64)
#   low  = les 4 derniers groupes (bits 63-0)
#
# =============================================================================

# Expanse une IPv6 compressée en forme complète (8 groupes)
proc expandIPv6(ip: string): string =
  var ipAddr = ip
  if '/' in ipAddr:
    ipAddr = ipAddr.split('/')[0]

  # Gérer le cas ::
  if "::" in ipAddr:
    let parts = ipAddr.split("::")
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
    return ipAddr

# Convertit une IPv6 string en IPv6Addr (2 x uint64)
proc ipv6ToAddr(ipCidr: string): IPv6Addr =
  let expanded = expandIPv6(ipCidr)
  let groups = expanded.split(':')

  # Les 4 premiers groupes → high (64 bits)
  for i in 0..3:
    let val = uint64(parseHexInt(groups[i]))
    result.high = result.high or (val shl (48 - i * 16))

  # Les 4 derniers groupes → low (64 bits)
  for i in 4..7:
    let val = uint64(parseHexInt(groups[i]))
    result.low = result.low or (val shl (48 - (i - 4) * 16))

# Vérifie si une IPv6 appartient à un réseau
#
# Même principe que IPv4, mais sur 128 bits:
#   /64  → masque sur high uniquement (cas le plus courant)
#   /48  → masque partiel sur high
#   /128 → adresse exacte (comme /32 en IPv4)
#
# Exemple: fe80::1234 est-il dans fe80::/10 ?
#   fe80 en binaire = 1111 1110 1000 0000
#   /10 = on garde les 10 premiers bits
#   Masque: 1111 1111 1100 0000 ... (0xFFC0...)
#   fe80 AND masque = fe80 AND ffc0 = fe80 ✓
#
# Cas selon le CIDR:
#   - cidr <= 64: le masque touche uniquement "high"
#   - cidr > 64:  "high" doit matcher entièrement + masque partiel sur "low"
#
proc isInNetworkV6(ip: IPv6Addr, network: string): bool =
  let netIp = ipv6ToAddr(network)
  let cidr = getCidr(network, 128)

  if cidr == 0:
    return true
  elif cidr <= 64:
    # Masque uniquement sur high
    let mask = 0xFFFFFFFFFFFFFFFF'u64 shl (64 - cidr)
    return (ip.high and mask) == (netIp.high and mask)
  else:
    # Masque sur high (complet) + low (partiel)
    let lowBits = cidr - 64
    let lowMask = 0xFFFFFFFFFFFFFFFF'u64 shl (64 - lowBits)
    return ip.high == netIp.high and (ip.low and lowMask) == (netIp.low and lowMask)

# =============================================================================
# Classification
# =============================================================================

# Détecte si c'est une IPv6
proc isIPv6(ip: string): bool =
  return ':' in ip

# Classifie une IPv4
proc classifyIPv4(ip: string): NetworkInfo =
  let ipUint32 = ipv4ToUint32(ip)

  for (network, kind, detail) in ipv4Ranges:
    if isInNetworkV4(ipUint32, network):
      return NetworkInfo(
        kind: kind,
        detail: detail,
        historicClass: getHistoricClassV4(ipUint32)
      )

  return NetworkInfo(
    kind: PUBLIC,
    detail: "Adresse publique routable",
    historicClass: getHistoricClassV4(ipUint32)
  )

# Classifie une IPv6
proc classifyIPv6(ip: string): NetworkInfo =
  let ipAddr = ipv6ToAddr(ip)

  for (network, kind, detail) in ipv6Ranges:
    if isInNetworkV6(ipAddr, network):
      return NetworkInfo(
        kind: kind,
        detail: detail,
        historicClass: "N/A (IPv6)"
      )

  return NetworkInfo(
    kind: PUBLIC,
    detail: "Adresse publique routable",
    historicClass: "N/A (IPv6)"
  )

# Classifie une IP (IPv4 ou IPv6)
proc classifyIP*(ip: string): NetworkInfo =
  if isIPv6(ip):
    return classifyIPv6(ip)
  else:
    return classifyIPv4(ip)