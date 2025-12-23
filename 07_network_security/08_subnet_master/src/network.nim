# =============================================================================
# NETWORK - Fonctions de calcul reseau IPv4
# =============================================================================

import std/[strutils, math, random]

type
  NetworkClass* = enum
    ClassA = "A"
    ClassB = "B"
    ClassC = "C"
    ClassD = "D (Multicast)"
    ClassE = "E (Experimental)"

  NetworkType* = enum
    Private = "Privee"
    Public = "Publique"
    Loopback = "Loopback"
    LinkLocal = "Link-Local (APIPA)"
    Multicast = "Multicast"
    Broadcast = "Broadcast"
    Reserved = "Reservee"

  IPInfo* = object
    ip*: string
    octets*: array[4, int]
    valid*: bool
    networkClass*: NetworkClass
    networkType*: NetworkType


# =============================================================================
# Validation et parsing
# =============================================================================

proc parseIP*(ip_str: string): IPInfo =
  ## Parse une adresse IP et retourne ses informations
  result.ip = ip_str
  result.valid = false

  # Retirer le CIDR si present
  var ip = ip_str
  if '/' in ip:
    ip = ip.split('/')[0]

  let parts = ip.split('.')
  if parts.len != 4:
    return

  for i, part in parts:
    try:
      let octet = parseInt(part)
      if octet < 0 or octet > 255:
        return
      result.octets[i] = octet
    except:
      return

  result.valid = true

  # Determiner la classe
  let first = result.octets[0]
  if first < 128:
    result.networkClass = ClassA
  elif first < 192:
    result.networkClass = ClassB
  elif first < 224:
    result.networkClass = ClassC
  elif first < 240:
    result.networkClass = ClassD
  else:
    result.networkClass = ClassE

  # Determiner le type
  if first == 127:
    result.networkType = Loopback
  elif first == 10:
    result.networkType = Private
  elif first == 172 and result.octets[1] >= 16 and result.octets[1] <= 31:
    result.networkType = Private
  elif first == 192 and result.octets[1] == 168:
    result.networkType = Private
  elif first == 169 and result.octets[1] == 254:
    result.networkType = LinkLocal
  elif first >= 224 and first < 240:
    result.networkType = Multicast
  elif first >= 240:
    result.networkType = Reserved
  elif ip_str == "255.255.255.255":
    result.networkType = Broadcast
  else:
    result.networkType = Public


proc isValidIP*(ip_str: string): bool =
  ## Verifie si une IP est valide
  parseIP(ip_str).valid


# =============================================================================
# Calculs de masque
# =============================================================================

proc prefixToMask*(prefix: int): uint32 =
  ## Convertit un prefixe CIDR en masque uint32
  if prefix == 0:
    return 0'u32
  else:
    return 0xFFFFFFFF'u32 shl (32 - prefix)


proc maskToDecimal*(prefix: int): string =
  ## Convertit un prefixe en notation decimale
  let mask = prefixToMask(prefix)
  let o1 = (mask shr 24) and 0xFF
  let o2 = (mask shr 16) and 0xFF
  let o3 = (mask shr 8) and 0xFF
  let o4 = mask and 0xFF
  return $o1 & "." & $o2 & "." & $o3 & "." & $o4


proc hostCount*(prefix: int): int =
  ## Calcule le nombre d'hotes pour un prefixe
  if prefix >= 31:
    return 2 - (prefix - 30)  # /31 = 2, /32 = 1
  return (1 shl (32 - prefix)) - 2


proc subnetCount*(original_prefix, new_prefix: int): int =
  ## Calcule le nombre de sous-reseaux possibles
  return 1 shl (new_prefix - original_prefix)


# =============================================================================
# Calculs d'adresses
# =============================================================================

proc ipToUint32*(ip_str: string): uint32 =
  ## Convertit une IP string en uint32
  let info = parseIP(ip_str)
  if not info.valid:
    return 0
  for i in 0..3:
    result = result or (uint32(info.octets[i]) shl (24 - i * 8))


proc uint32ToIP*(addr_val: uint32): string =
  ## Convertit un uint32 en IP string
  let o1 = (addr_val shr 24) and 0xFF
  let o2 = (addr_val shr 16) and 0xFF
  let o3 = (addr_val shr 8) and 0xFF
  let o4 = addr_val and 0xFF
  return $o1 & "." & $o2 & "." & $o3 & "." & $o4


proc networkAddress*(ip_str: string, prefix: int): string =
  ## Calcule l'adresse reseau
  let ip = ipToUint32(ip_str)
  let mask = prefixToMask(prefix)
  return uint32ToIP(ip and mask)


proc broadcastAddress*(ip_str: string, prefix: int): string =
  ## Calcule l'adresse broadcast
  let ip = ipToUint32(ip_str)
  let mask = prefixToMask(prefix)
  let network = ip and mask
  return uint32ToIP(network or (not mask))


proc firstUsableIP*(ip_str: string, prefix: int): string =
  ## Calcule la premiere IP utilisable
  let network = ipToUint32(networkAddress(ip_str, prefix))
  return uint32ToIP(network + 1)


proc lastUsableIP*(ip_str: string, prefix: int): string =
  ## Calcule la derniere IP utilisable
  let broadcast = ipToUint32(broadcastAddress(ip_str, prefix))
  return uint32ToIP(broadcast - 1)


proc isInNetwork*(ip_str: string, network_cidr: string): bool =
  ## Verifie si une IP appartient a un reseau
  let parts = network_cidr.split('/')
  if parts.len != 2:
    return false
  let prefix = parseInt(parts[1])
  let mask = prefixToMask(prefix)
  let ip = ipToUint32(ip_str)
  let net = ipToUint32(parts[0])
  return (ip and mask) == (net and mask)


# =============================================================================
# Generation aleatoire
# =============================================================================

proc randomIP*(ipType: NetworkType = Public): string =
  ## Genere une IP aleatoire du type specifie
  case ipType
  of Private:
    let choice = rand(2)
    case choice
    of 0:  # 10.x.x.x
      return "10." & $rand(255) & "." & $rand(255) & "." & $rand(254)
    of 1:  # 172.16-31.x.x
      return "172." & $(16 + rand(15)) & "." & $rand(255) & "." & $rand(254)
    else:  # 192.168.x.x
      return "192.168." & $rand(255) & "." & $rand(254)
  of Loopback:
    return "127." & $rand(255) & "." & $rand(255) & "." & $rand(254)
  of LinkLocal:
    return "169.254." & $rand(255) & "." & $rand(254)
  of Multicast:
    return $(224 + rand(15)) & "." & $rand(255) & "." & $rand(255) & "." & $rand(255)
  else:  # Public ou autre
    var first = rand(223)
    # Eviter les plages privees
    while first == 10 or first == 127 or first == 0:
      first = rand(223)
    if first == 172:
      return "172." & $(rand(15)) & "." & $rand(255) & "." & $rand(254)
    elif first == 192:
      return "192." & $(rand(167)) & "." & $rand(255) & "." & $rand(254)
    else:
      return $first & "." & $rand(255) & "." & $rand(255) & "." & $rand(254)


proc randomPrefix*(): int =
  ## Genere un prefixe CIDR aleatoire (entre 8 et 30)
  return 8 + rand(22)


proc randomInvalidIP*(): string =
  ## Genere une IP invalide pour les questions
  let invalidType = rand(3)
  case invalidType
  of 0:  # Octet > 255
    return $rand(255) & "." & $(256 + rand(100)) & "." & $rand(255) & "." & $rand(255)
  of 1:  # Pas assez d'octets
    return $rand(255) & "." & $rand(255) & "." & $rand(255)
  of 2:  # Trop d'octets
    return $rand(255) & "." & $rand(255) & "." & $rand(255) & "." & $rand(255) & "." & $rand(255)
  else:  # Caracteres invalides
    return $rand(255) & "." & "abc" & "." & $rand(255) & "." & $rand(255)


proc randomCIDR*(ipType: NetworkType = Public): string =
  ## Genere un CIDR aleatoire
  return randomIP(ipType) & "/" & $randomPrefix()
