# =============================================================================
# CLASSIFY - Classification des adresses IP
# =============================================================================
#
# Ce module détermine le type et l'usage d'une adresse IP :
# privée, publique, loopback, multicast, etc.
#
# TYPES DE RÉSEAUX :
#
# 1. LOOPBACK (boucle locale)
#    IPv4: 127.0.0.0/8 (typiquement 127.0.0.1)
#    IPv6: ::1
#    Usage: communication interne à la machine
#
# 2. PRIVATE (réseaux privés RFC 1918)
#    IPv4: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
#    IPv6: fc00::/7 (Unique Local Address)
#    Usage: réseaux locaux, non routables sur Internet
#
# 3. LINK_LOCAL (auto-configuration)
#    IPv4: 169.254.0.0/16 (APIPA)
#    IPv6: fe80::/10
#    Usage: communication sur le même segment réseau
#
# 4. MULTICAST (diffusion groupe)
#    IPv4: 224.0.0.0/4 (Classe D)
#    IPv6: ff00::/8
#    Usage: envoi à plusieurs destinataires simultanément
#
# 5. PUBLIC (adresses routables)
#    Toutes les autres adresses
#    Usage: communication sur Internet
#
# CLASSES HISTORIQUES IPv4 :
#   Les classes A, B, C, D, E sont obsolètes depuis le CIDR (1993)
#   mais restent utiles pour la culture réseau :
#
#   Classe A: 0.0.0.0   - 127.255.255.255 (premier bit = 0)
#   Classe B: 128.0.0.0 - 191.255.255.255 (premiers bits = 10)
#   Classe C: 192.0.0.0 - 223.255.255.255 (premiers bits = 110)
#   Classe D: 224.0.0.0 - 239.255.255.255 (premiers bits = 1110) - Multicast
#   Classe E: 240.0.0.0 - 255.255.255.255 (premiers bits = 1111) - Expérimental
#
# =============================================================================

import std/strutils
import utils


type
  ## Types de réseaux reconnus.
  NetworkKind* = enum
    LOOPBACK,       ## Adresse de bouclage (127.x.x.x, ::1)
    PRIVATE,        ## Réseau privé RFC 1918
    LINK_LOCAL,     ## Auto-configuration APIPA / link-local
    MULTICAST,      ## Diffusion multicast (Classe D)
    RESERVED,       ## Réservé / expérimental
    SPECIAL,        ## Usage spécial (0.0.0.0, etc.)
    BROADCAST,      ## Diffusion broadcast
    CGNAT,          ## Carrier-Grade NAT (opérateurs)
    DOCUMENTATION,  ## Plages de documentation (RFC 5737)
    PUBLIC          ## Adresse publique routable

  ## Informations de classification d'une adresse IP.
  NetworkInfo* = object
    kind*: NetworkKind          ## Type de réseau
    detail*: string             ## Description détaillée
    historic_class*: string     ## Classe historique (A, B, C, D, E)


# Plages IPv4 connues avec leur classification
const ipv4_ranges = [
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
const ipv6_ranges = [
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
# Fonctions internes IPv4
# =============================================================================

## Retourne la classe historique (A, B, C, D, E) basée sur le premier octet.
##
## Paramètres:
##   - ip_addr: adresse IPv4 en uint32
##
## Retour: lettre de la classe (A, B, C, D ou E)
proc get_historic_class_v4(ip_addr: uint32): string =
  let first_octet = (ip_addr shr 24) and 0xFF
  if first_octet < 128:
    return "A"
  elif first_octet < 192:
    return "B"
  elif first_octet < 224:
    return "C"
  elif first_octet < 240:
    return "D"
  else:
    return "E"


## Classifie une adresse IPv4.
##
## Paramètres:
##   - ip_str: adresse IPv4 sous forme de string
##
## Retour: NetworkInfo avec le type, détail et classe historique
proc classify_ipv4(ip_str: string): NetworkInfo =
  let ip_addr = ipv4_to_uint32(ip_str)

  for (network, kind, detail) in ipv4_ranges:
    if is_in_network(ip_addr, network):
      return NetworkInfo(
        kind: kind,
        detail: detail,
        historic_class: get_historic_class_v4(ip_addr)
      )

  return NetworkInfo(
    kind: PUBLIC,
    detail: "Adresse publique routable",
    historic_class: get_historic_class_v4(ip_addr)
  )


# =============================================================================
# Fonctions internes IPv6
# =============================================================================

## Classifie une adresse IPv6.
##
## Paramètres:
##   - ip_str: adresse IPv6 sous forme de string
##
## Retour: NetworkInfo avec le type et détail
proc classify_ipv6(ip_str: string): NetworkInfo =
  let ip_addr = ipv6_to_addr(ip_str)

  for (network, kind, detail) in ipv6_ranges:
    if is_in_network_v6(ip_addr, network):
      return NetworkInfo(
        kind: kind,
        detail: detail,
        historic_class: "N/A (IPv6)"
      )

  return NetworkInfo(
    kind: PUBLIC,
    detail: "Adresse publique routable",
    historic_class: "N/A (IPv6)"
  )


# =============================================================================
# Fonction publique
# =============================================================================

## Détecte si une adresse est IPv6 (contient ':').
proc is_ipv6*(ip_str: string): bool =
  return ':' in ip_str


## Classifie une adresse IP (IPv4 ou IPv6).
##
## Détermine automatiquement le type d'adresse et retourne
## ses informations de classification.
##
## Paramètres:
##   - ip_str: adresse IP sous forme de string
##
## Retour: NetworkInfo avec le type, détail et classe historique
##
## Exemple:
##   let info = classify_ip("192.168.1.1")
##   echo info.kind      # → PRIVATE
##   echo info.detail    # → "RFC 1918 - Classe C privee"
##
##   let info2 = classify_ip("8.8.8.8")
##   echo info2.kind     # → PUBLIC
proc classify_ip*(ip_str: string): NetworkInfo =
  if is_ipv6(ip_str):
    return classify_ipv6(ip_str)
  else:
    return classify_ipv4(ip_str)
