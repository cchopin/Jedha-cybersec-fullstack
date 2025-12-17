import std/nre
import std/options

type
  IPKind* = enum
    invalid, ipv4, ipv4_cidr, ipv6, ipv6_cidr

# Regex pour IPv4 simple (ex: 192.168.1.1)
let ipv4Regex = re"^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$"
# Regex pour IPv4 avec masque CIDR (ex: 192.168.1.0/24)
let ipv4CidrRegex = re"^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])/(3[0-2]|[1-2]?[0-9])$"
# Regex pour IPv6 simple
let ipv6Regex = re"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::$|^([0-9a-fA-F]{1,4}:){1,7}:$|^::[0-9a-fA-F]{1,4}(:[0-9a-fA-F]{1,4}){0,6}$|^([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}$|^([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}$|^([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}$|^([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}$|^[0-9a-fA-F]{1,4}:(:[0-9a-fA-F]{1,4}){1,6}$"
# Regex pour IPv6 avec masque CIDR (ex: 2001:db8::/32)
let ipv6CidrRegex = re"^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|::|(([0-9a-fA-F]{1,4}:){1,7})?:|(([0-9a-fA-F]{1,4}:){1,6})?:[0-9a-fA-F]{1,4}|(([0-9a-fA-F]{1,4}:){1,5})?(:[0-9a-fA-F]{1,4}){1,2}|(([0-9a-fA-F]{1,4}:){1,4})?(:[0-9a-fA-F]{1,4}){1,3}|(([0-9a-fA-F]{1,4}:){1,3})?(:[0-9a-fA-F]{1,4}){1,4}|(([0-9a-fA-F]{1,4}:){1,2})?(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6}))/(12[0-8]|1[0-1][0-9]|[1-9]?[0-9])$"

# Retourne le type d'IP (avec ou sans masque CIDR)
proc getIPKind*(ip: string): IPKind =
  if ip.match(ipv4Regex).isSome:
    return ipv4
  elif ip.match(ipv4CidrRegex).isSome:
    return ipv4_cidr
  elif ip.match(ipv6Regex).isSome:
    return ipv6
  elif ip.match(ipv6CidrRegex).isSome:
    return ipv6_cidr
  else:
    return invalid

# Verifie si l'IP est valide (avec ou sans masque)
proc isValidIP*(ip: string): bool =
  return getIPKind(ip) != invalid
