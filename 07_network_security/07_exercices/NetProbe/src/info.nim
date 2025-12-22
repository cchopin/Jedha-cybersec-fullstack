# =============================================================================
# INFO - Calcul des informations de sous-réseau
# =============================================================================
#
# Ce module calcule les informations complètes d'un sous-réseau à partir
# d'une notation CIDR : adresse réseau, broadcast, plage d'hôtes, etc.
#
# CALCULS DE SOUS-RÉSEAU IPv4 :
#
# 1. ADRESSE RÉSEAU
#    C'est la première adresse du sous-réseau, obtenue par AND entre
#    l'IP et le masque. Elle identifie le réseau.
#
# 2. ADRESSE DE BROADCAST
#    C'est la dernière adresse du sous-réseau, obtenue par OR entre
#    l'adresse réseau et le masque inversé.
#
# 3. PLAGE D'HÔTES
#    Les adresses utilisables vont de (Réseau + 1) à (Broadcast - 1)
#
# 4. NOMBRE D'HÔTES
#    Formule: 2^(32 - préfixe) - 2
#
# CALCULS DE SOUS-RÉSEAU IPv6 :
#
# En IPv6, les concepts sont différents :
# - Pas de broadcast (remplacé par multicast)
# - Réseaux énormes (2^64 hôtes pour un /64 standard)
# - On affiche principalement : réseau et préfixe
#
# =============================================================================

import strutils
import utils


type
  ## Informations complètes d'un sous-réseau IPv4.
  SubnetInfo* = object
    network*: string      ## Adresse réseau (ex: "192.168.1.0")
    broadcast*: string    ## Adresse de broadcast (ex: "192.168.1.255")
    mask*: string         ## Masque de sous-réseau (ex: "255.255.255.0")
    first_host*: string   ## Première adresse utilisable (ex: "192.168.1.1")
    last_host*: string    ## Dernière adresse utilisable (ex: "192.168.1.254")
    host_count*: int      ## Nombre d'hôtes possibles (ex: 254)
    prefix*: int          ## Préfixe CIDR (ex: 24)

  ## Informations d'un sous-réseau IPv6.
  SubnetInfoV6* = object
    network*: string      ## Adresse réseau (ex: "2001:db8::")
    prefix*: int          ## Préfixe CIDR (ex: 64)
    mask_high*: string    ## Masque partie haute (hex)
    mask_low*: string     ## Masque partie basse (hex)


## Calcule l'adresse de broadcast IPv4.
##
## Le broadcast est obtenu en mettant à 1 tous les bits hôtes :
## broadcast = réseau OR (NOT masque)
##
## Paramètres:
##   - network: adresse réseau en uint32
##   - mask: masque de sous-réseau en uint32
##
## Retour: adresse de broadcast en uint32
proc get_broadcast(network: uint32, mask: uint32): uint32 =
  return network or (not mask)


## Calcule le nombre d'hôtes utilisables dans un sous-réseau IPv4.
##
## Formule: 2^(32 - préfixe) - 2
## Cas spéciaux: /32 = 1 hôte, /31 = 2 hôtes
##
## Paramètres:
##   - prefix: le préfixe CIDR (0 à 32)
##
## Retour: nombre d'hôtes
proc get_host_count(prefix: int): int =
  if prefix == 32:
    return 1
  elif prefix == 31:
    return 2
  else:
    return (1 shl (32 - prefix)) - 2


## Calcule toutes les informations d'un sous-réseau IPv4.
##
## À partir d'une notation CIDR, calcule :
## - Adresse réseau
## - Adresse de broadcast
## - Masque de sous-réseau
## - Première et dernière IP utilisable
## - Nombre d'hôtes
##
## Paramètres:
##   - cidr_str: notation CIDR (ex: "192.168.1.0/24")
##
## Retour: structure SubnetInfo avec toutes les informations
##
## Exemple:
##   let info = get_subnet_info("192.168.1.0/24")
##   echo info.network     # → "192.168.1.0"
##   echo info.broadcast   # → "192.168.1.255"
##   echo info.host_count  # → 254
proc get_subnet_info*(cidr_str: string): SubnetInfo =
  let parts = cidr_str.split("/")
  let prefix = parseInt(parts[1])
  let ip_addr = ipv4_to_uint32(parts[0])
  let mask = prefix_to_mask(prefix)
  let network = ip_addr and mask
  let broadcast = get_broadcast(network, mask)
  let first_host = network + 1
  let last_host = broadcast - 1
  let host_count = get_host_count(prefix)

  return SubnetInfo(
    network: uint32_to_ip(network),
    broadcast: uint32_to_ip(broadcast),
    mask: uint32_to_ip(mask),
    first_host: uint32_to_ip(first_host),
    last_host: uint32_to_ip(last_host),
    host_count: host_count,
    prefix: prefix
  )


## Calcule les informations d'un sous-réseau IPv6.
##
## En IPv6, on calcule principalement l'adresse réseau.
## Le concept de broadcast n'existe pas (remplacé par multicast).
## Le nombre d'hôtes est généralement trop grand pour être pratique.
##
## Paramètres:
##   - cidr_str: notation CIDR IPv6 (ex: "2001:db8::/32")
##
## Retour: structure SubnetInfoV6
##
## Exemple:
##   let info = get_subnet_info_v6("fe80::/10")
##   echo info.network  # → "fe80:0:0:0:0:0:0:0"
##   echo info.prefix   # → 10
proc get_subnet_info_v6*(cidr_str: string): SubnetInfoV6 =
  let prefix = get_prefix(cidr_str, 128)
  let ip_addr = ipv6_to_addr(cidr_str)
  let network = get_network_v6(ip_addr, prefix)
  let (mask_high, mask_low) = prefix_to_mask_v6(prefix)

  return SubnetInfoV6(
    network: addr_to_ipv6(network),
    prefix: prefix,
    mask_high: toHex(mask_high),
    mask_low: toHex(mask_low)
  )
