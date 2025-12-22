# =============================================================================
# VALIDATE - Validation des adresses IP
# =============================================================================
#
# Ce module vérifie si une chaîne représente une adresse IP valide.
# Il supporte IPv4, IPv6, avec ou sans notation CIDR.
#
# FORMATS SUPPORTÉS :
#
# 1. IPv4 simple
#    Format: X.X.X.X où X est un nombre de 0 à 255
#    Exemples: 192.168.1.1, 10.0.0.1, 255.255.255.255
#
# 2. IPv4 avec CIDR
#    Format: X.X.X.X/Y où Y est un nombre de 0 à 32
#    Exemples: 192.168.1.0/24, 10.0.0.0/8, 172.16.0.0/12
#
# 3. IPv6 simple
#    Format: 8 groupes de 4 chiffres hexadécimaux séparés par :
#    Forme complète: 2001:0db8:85a3:0000:0000:8a2e:0370:7334
#    Forme compressée: 2001:db8::1, ::1, fe80::1
#
# 4. IPv6 avec CIDR
#    Format: adresse_ipv6/Y où Y est un nombre de 0 à 128
#    Exemples: 2001:db8::/32, fe80::/10, ::1/128
#
# VALIDATION :
#   Les regex vérifient que chaque octet/groupe est dans les bornes valides
#   et que la notation est correctement formée.
#
# =============================================================================

import std/nre
import std/options


type
  ## Types d'adresses IP reconnus par le validateur.
  ##
  ## - invalid: la chaîne n'est pas une adresse IP valide
  ## - ipv4: adresse IPv4 simple (ex: 192.168.1.1)
  ## - ipv4_cidr: adresse IPv4 avec préfixe CIDR (ex: 192.168.1.0/24)
  ## - ipv6: adresse IPv6 simple (ex: ::1)
  ## - ipv6_cidr: adresse IPv6 avec préfixe CIDR (ex: 2001:db8::/32)
  IPKind* = enum
    invalid, ipv4, ipv4_cidr, ipv6, ipv6_cidr


# Regex pour IPv4 simple (ex: 192.168.1.1)
# Chaque octet: 0-255
let ipv4_regex = re"^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$"

# Regex pour IPv4 avec masque CIDR (ex: 192.168.1.0/24)
# Préfixe: 0-32
let ipv4_cidr_regex = re"^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])/(3[0-2]|[1-2]?[0-9])$"

# Regex pour IPv6 simple
# Supporte la notation compressée avec ::
let ipv6_regex = re"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::$|^([0-9a-fA-F]{1,4}:){1,7}:$|^::[0-9a-fA-F]{1,4}(:[0-9a-fA-F]{1,4}){0,6}$|^([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}$|^([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}$|^([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}$|^([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}$|^[0-9a-fA-F]{1,4}:(:[0-9a-fA-F]{1,4}){1,6}$"

# Regex pour IPv6 avec masque CIDR (ex: 2001:db8::/32)
# Préfixe: 0-128
let ipv6_cidr_regex = re"^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|::|(([0-9a-fA-F]{1,4}:){1,7})?:|(([0-9a-fA-F]{1,4}:){1,6})?:[0-9a-fA-F]{1,4}|(([0-9a-fA-F]{1,4}:){1,5})?(:[0-9a-fA-F]{1,4}){1,2}|(([0-9a-fA-F]{1,4}:){1,4})?(:[0-9a-fA-F]{1,4}){1,3}|(([0-9a-fA-F]{1,4}:){1,3})?(:[0-9a-fA-F]{1,4}){1,4}|(([0-9a-fA-F]{1,4}:){1,2})?(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6}))/(12[0-8]|1[0-1][0-9]|[1-9]?[0-9])$"


## Détermine le type d'une adresse IP.
##
## Analyse la chaîne et retourne le type correspondant :
## IPv4, IPv4+CIDR, IPv6, IPv6+CIDR, ou invalid.
##
## Paramètres:
##   - ip_str: la chaîne à analyser
##
## Retour: le type IPKind correspondant
##
## Exemple:
##   echo get_ip_kind("192.168.1.1")      # → ipv4
##   echo get_ip_kind("192.168.1.0/24")   # → ipv4_cidr
##   echo get_ip_kind("::1")              # → ipv6
##   echo get_ip_kind("not an ip")        # → invalid
proc get_ip_kind*(ip_str: string): IPKind =
  if ip_str.match(ipv4_regex).isSome:
    return ipv4
  elif ip_str.match(ipv4_cidr_regex).isSome:
    return ipv4_cidr
  elif ip_str.match(ipv6_regex).isSome:
    return ipv6
  elif ip_str.match(ipv6_cidr_regex).isSome:
    return ipv6_cidr
  else:
    return invalid


## Vérifie si une chaîne est une adresse IP valide.
##
## Accepte tous les formats : IPv4, IPv6, avec ou sans CIDR.
##
## Paramètres:
##   - ip_str: la chaîne à vérifier
##
## Retour: true si l'adresse est valide
##
## Exemple:
##   echo is_valid_ip("192.168.1.1")    # → true
##   echo is_valid_ip("999.999.999.999") # → false
##   echo is_valid_ip("hello")          # → false
proc is_valid_ip*(ip_str: string): bool =
  return get_ip_kind(ip_str) != invalid
