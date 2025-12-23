# =============================================================================
# SUBNET - Division de reseaux en sous-reseaux et supernetting
# =============================================================================
#
# Ce module permet de diviser un reseau en sous-reseaux :
# - subnet_equal_parts : division en N parts egales (N = puissance de 2)
# - subnet_by_host_count : division avec un minimum d'hotes par sous-reseau
# - subnet_vlsm : division en sous-reseaux de tailles variables
#
# Et d'agreger plusieurs reseaux (supernetting / route summarization) :
# - supernet : combine plusieurs reseaux contigus en un super-reseau
#
# Supporte IPv4 et IPv6.
#
# SUPERNETTING (Route Summarization)
# ==================================
#
# Le supernetting est l'inverse du subnetting : on combine plusieurs
# petits reseaux en un seul grand reseau.
#
# Exemple : agreger ces 4 reseaux /24 :
#   192.168.0.0/24
#   192.168.1.0/24
#   192.168.2.0/24
#   192.168.3.0/24
#
# Etape 1 : Ecrire le 3eme octet en binaire (les 2 premiers sont identiques)
#   192.168.0.x → 00000000
#   192.168.1.x → 00000001
#   192.168.2.x → 00000010
#   192.168.3.x → 00000011
#
# Etape 2 : Trouver les bits communs (de gauche a droite)
#   Les 6 premiers bits sont identiques (000000xx)
#
# Etape 3 : Calculer le nouveau prefixe
#   8 (1er octet) + 8 (2eme) + 6 (bits communs du 3eme) = /22
#
# Resultat : 192.168.0.0/22 couvre les 4 reseaux
#
# =============================================================================

import std/[strutils, math, algorithm]
import utils
import info
from classify import is_ipv6


## Verifie si un nombre est une puissance de 2.
proc is_power_of_two(n: int): bool =
  return n > 0 and (n and (n - 1)) == 0


## Calcule le logarithme base 2 (nombre de bits).
proc log2_int(n: int): int =
  return int(ceil(log2(float(n))))


## Demande de sous-reseau pour VLSM.
type
  SubnetRequest* = object
    name*: string      ## Nom du departement/sous-reseau
    hosts_needed*: int ## Nombre d'hotes requis

  ## Sous-reseau avec son nom.
  NamedSubnet* = object
    name*: string
    info*: SubnetInfo

  ## Resultat d'une operation de subnetting.
  SubnetResult* = object
    success*: bool
    error*: string
    subnets*: seq[SubnetInfo]

  ## Resultat VLSM avec noms.
  VlsmResult* = object
    success*: bool
    error*: string
    subnets*: seq[NamedSubnet]

  ## Resultat d'une operation de subnetting IPv6.
  SubnetResultV6* = object
    success*: bool
    error*: string
    subnets*: seq[SubnetInfoV6]

  ## Sous-reseau IPv6 avec son nom.
  NamedSubnetV6* = object
    name*: string
    info*: SubnetInfoV6

  ## Resultat VLSM IPv6 avec noms.
  VlsmResultV6* = object
    success*: bool
    error*: string
    subnets*: seq[NamedSubnetV6]

  ## Resultat d'une operation de supernetting IPv4.
  SupernetResult* = object
    success*: bool
    error*: string
    supernet*: SubnetInfo        ## Le super-reseau resultant
    original_networks*: seq[string]  ## Les reseaux d'origine

  ## Resultat d'une operation de supernetting IPv6.
  SupernetResultV6* = object
    success*: bool
    error*: string
    supernet*: SubnetInfoV6      ## Le super-reseau resultant
    original_networks*: seq[string]  ## Les reseaux d'origine


## Divise un reseau en N sous-reseaux egaux.
##
## Le nombre de sous-reseaux doit etre une puissance de 2 (2, 4, 8, 16...).
##
## Parametres:
##   - cidr_str: notation CIDR du reseau (ex: "192.168.10.0/24")
##   - num_subnets: nombre de sous-reseaux souhaites (puissance de 2)
##
## Retour: SubnetResult avec la liste des sous-reseaux ou une erreur
##
## Exemple:
##   let result = subnet_equal_parts("192.168.10.0/24", 4)
##   if result.success:
##     for subnet in result.subnets:
##       echo subnet.network, "/", subnet.prefix
proc subnet_equal_parts*(cidr_str: string, num_subnets: int): SubnetResult =
  # Verifier que num_subnets est une puissance de 2
  if not is_power_of_two(num_subnets):
    return SubnetResult(
      success: false,
      error: "Le nombre de sous-reseaux doit etre une puissance de 2 (2, 4, 8, 16...)"
    )

  let original_prefix = get_prefix(cidr_str, 24)
  let bits_to_add = log2_int(num_subnets)
  let new_prefix = original_prefix + bits_to_add

  # Verifier que le nouveau prefixe est valide
  if new_prefix > 30:
    return SubnetResult(
      success: false,
      error: "Impossible : le prefixe resultant (/" & $new_prefix & ") depasse /30"
    )

  let network_addr = ipv4_to_uint32(cidr_str)
  let original_mask = prefix_to_mask(original_prefix)
  let base_network = network_addr and original_mask

  # Taille de chaque sous-reseau
  let subnet_size = 1'u32 shl (32 - new_prefix)

  var subnets: seq[SubnetInfo] = @[]
  for i in 0..<num_subnets:
    let subnet_network = base_network + (uint32(i) * subnet_size)
    let subnet_cidr = uint32_to_ip(subnet_network) & "/" & $new_prefix
    subnets.add(get_subnet_info(subnet_cidr))

  return SubnetResult(
    success: true,
    subnets: subnets
  )


## Divise un reseau avec une contrainte de nombre minimum d'hotes.
##
## Parametres:
##   - cidr_str: notation CIDR du reseau (ex: "192.168.10.0/24")
##   - num_subnets: nombre de sous-reseaux souhaites
##   - min_hosts: nombre minimum d'hotes utilisables par sous-reseau
##
## Retour: SubnetResult avec la liste des sous-reseaux ou une erreur
##
## Exemple:
##   let result = subnet_by_host_count("192.168.10.0/24", 4, 50)
##   if result.success:
##     for subnet in result.subnets:
##       echo subnet.network, " - ", subnet.host_count, " hotes"
proc subnet_by_host_count*(cidr_str: string, num_subnets: int, min_hosts: int): SubnetResult =
  # Calculer la taille de bloc necessaire (hotes + 2 pour reseau et broadcast)
  let addresses_needed = min_hosts + 2
  let bits_for_hosts = log2_int(addresses_needed)
  let new_prefix = 32 - bits_for_hosts

  # Verifier que le prefixe est valide
  if new_prefix < 1 or new_prefix > 30:
    return SubnetResult(
      success: false,
      error: "Le nombre d'hotes demande (" & $min_hosts & ") donne un prefixe invalide"
    )

  # Calculer la taille reelle du sous-reseau
  let subnet_size = 1'u32 shl bits_for_hosts
  let actual_hosts = int(subnet_size) - 2

  # Verifier que tout rentre dans le reseau original
  let original_prefix = get_prefix(cidr_str, 24)
  let original_size = 1'u32 shl (32 - original_prefix)
  let total_needed = uint32(num_subnets) * subnet_size

  if total_needed > original_size:
    return SubnetResult(
      success: false,
      error: "Impossible : " & $num_subnets & " sous-reseaux de " & $actual_hosts &
             " hotes (" & $total_needed & " adresses) ne rentrent pas dans /" &
             $original_prefix & " (" & $original_size & " adresses)"
    )

  let network_addr = ipv4_to_uint32(cidr_str)
  let original_mask = prefix_to_mask(original_prefix)
  let base_network = network_addr and original_mask

  var subnets: seq[SubnetInfo] = @[]
  for i in 0..<num_subnets:
    let subnet_network = base_network + (uint32(i) * subnet_size)
    let subnet_cidr = uint32_to_ip(subnet_network) & "/" & $new_prefix
    subnets.add(get_subnet_info(subnet_cidr))

  return SubnetResult(
    success: true,
    subnets: subnets
  )


## Divise un reseau en sous-reseaux de tailles variables (VLSM).
##
## Les sous-reseaux sont alloues du plus grand au plus petit
## pour optimiser l'utilisation de l'espace d'adressage.
##
## Parametres:
##   - cidr_str: notation CIDR du reseau (ex: "192.168.10.0/24")
##   - requests: liste des demandes (nom + nombre d'hotes)
##
## Retour: VlsmResult avec la liste des sous-reseaux nommes ou une erreur
##
## Exemple:
##   let requests = @[
##     SubnetRequest(name: "IT", hosts_needed: 50),
##     SubnetRequest(name: "HR", hosts_needed: 25)
##   ]
##   let result = subnet_vlsm("192.168.10.0/24", requests)
proc subnet_vlsm*(cidr_str: string, requests: seq[SubnetRequest]): VlsmResult =
  if requests.len == 0:
    return VlsmResult(
      success: false,
      error: "Aucune demande de sous-reseau"
    )

  # Trier les demandes du plus grand au plus petit
  var sorted_requests = requests
  sorted_requests.sort(proc(a, b: SubnetRequest): int =
    cmp(b.hosts_needed, a.hosts_needed)  # Ordre decroissant
  )

  # Calculer l'espace total disponible
  let original_prefix = get_prefix(cidr_str, 24)
  let original_size = 1'u32 shl (32 - original_prefix)
  let network_addr = ipv4_to_uint32(cidr_str)
  let original_mask = prefix_to_mask(original_prefix)
  let base_network = network_addr and original_mask

  # Calculer l'espace total necessaire
  var total_needed: uint32 = 0
  for req in sorted_requests:
    let addresses_needed = req.hosts_needed + 2
    let bits_for_hosts = log2_int(addresses_needed)
    let subnet_size = 1'u32 shl bits_for_hosts
    total_needed += subnet_size

  if total_needed > original_size:
    return VlsmResult(
      success: false,
      error: "Impossible : " & $total_needed & " adresses necessaires, " &
             "seulement " & $original_size & " disponibles dans /" & $original_prefix
    )

  # Allouer les sous-reseaux
  var subnets: seq[NamedSubnet] = @[]
  var current_addr = base_network

  for req in sorted_requests:
    let addresses_needed = req.hosts_needed + 2
    let bits_for_hosts = log2_int(addresses_needed)
    let new_prefix = 32 - bits_for_hosts
    let subnet_size = 1'u32 shl bits_for_hosts

    # Verifier que le prefixe est valide
    if new_prefix < 1 or new_prefix > 30:
      return VlsmResult(
        success: false,
        error: "Le nombre d'hotes demande pour '" & req.name &
               "' (" & $req.hosts_needed & ") donne un prefixe invalide"
      )

    let subnet_cidr = uint32_to_ip(current_addr) & "/" & $new_prefix
    subnets.add(NamedSubnet(
      name: req.name,
      info: get_subnet_info(subnet_cidr)
    ))

    current_addr += subnet_size

  return VlsmResult(
    success: true,
    subnets: subnets
  )


# =============================================================================
# Fonctions IPv6
# =============================================================================

## Divise un reseau IPv6 en N sous-reseaux egaux.
proc subnet_equal_parts_v6*(cidr_str: string, num_subnets: int): SubnetResultV6 =
  if not is_power_of_two(num_subnets):
    return SubnetResultV6(
      success: false,
      error: "Le nombre de sous-reseaux doit etre une puissance de 2 (2, 4, 8, 16...)"
    )

  let original_prefix = get_prefix(cidr_str, 64)
  let bits_to_add = log2_int(num_subnets)
  let new_prefix = original_prefix + bits_to_add

  if new_prefix > 126:
    return SubnetResultV6(
      success: false,
      error: "Impossible : le prefixe resultant (/" & $new_prefix & ") depasse /126"
    )

  let network_addr = ipv6_to_addr(cidr_str)
  let base_network = get_network_v6(network_addr, original_prefix)

  var subnets: seq[SubnetInfoV6] = @[]
  var current_addr = base_network

  for i in 0..<num_subnets:
    let subnet_cidr = addr_to_ipv6(current_addr) & "/" & $new_prefix
    subnets.add(get_subnet_info_v6(subnet_cidr))

    # Incrementer l'adresse pour le prochain sous-reseau
    # Les bits de sous-reseau peuvent etre dans high ou low
    if new_prefix <= 64:
      # Les bits de sous-reseau sont dans high
      let increment = 1'u64 shl (64 - new_prefix)
      current_addr.high = current_addr.high + increment
    else:
      # Les bits de sous-reseau sont dans low
      let increment = 1'u64 shl (128 - new_prefix)
      current_addr = add_to_ipv6(current_addr, increment)

  return SubnetResultV6(
    success: true,
    subnets: subnets
  )


## Divise un reseau IPv6 avec une contrainte de nombre minimum d'hotes.
proc subnet_by_host_count_v6*(cidr_str: string, num_subnets: int, min_hosts: int): SubnetResultV6 =
  let addresses_needed = min_hosts + 1  # IPv6 n'a pas de broadcast
  let bits_for_hosts = log2_int(addresses_needed)
  let new_prefix = 128 - bits_for_hosts

  if new_prefix < 1 or new_prefix > 126:
    return SubnetResultV6(
      success: false,
      error: "Le nombre d'hotes demande (" & $min_hosts & ") donne un prefixe invalide"
    )

  let original_prefix = get_prefix(cidr_str, 64)

  # Verifier que les sous-reseaux rentrent
  let total_bits_needed = bits_for_hosts + log2_int(num_subnets)
  let available_bits = 128 - original_prefix

  if total_bits_needed > available_bits:
    return SubnetResultV6(
      success: false,
      error: "Impossible : pas assez d'espace dans /" & $original_prefix &
             " pour " & $num_subnets & " sous-reseaux de " & $min_hosts & " hotes"
    )

  let network_addr = ipv6_to_addr(cidr_str)
  let base_network = get_network_v6(network_addr, original_prefix)

  var subnets: seq[SubnetInfoV6] = @[]
  var current_addr = base_network

  for i in 0..<num_subnets:
    let subnet_cidr = addr_to_ipv6(current_addr) & "/" & $new_prefix
    subnets.add(get_subnet_info_v6(subnet_cidr))

    # Incrementer l'adresse pour le prochain sous-reseau
    if new_prefix <= 64:
      let increment = 1'u64 shl (64 - new_prefix)
      current_addr.high = current_addr.high + increment
    else:
      let increment = 1'u64 shl (128 - new_prefix)
      current_addr = add_to_ipv6(current_addr, increment)

  return SubnetResultV6(
    success: true,
    subnets: subnets
  )


## Divise un reseau IPv6 en sous-reseaux de tailles variables (VLSM).
proc subnet_vlsm_v6*(cidr_str: string, requests: seq[SubnetRequest]): VlsmResultV6 =
  if requests.len == 0:
    return VlsmResultV6(
      success: false,
      error: "Aucune demande de sous-reseau"
    )

  # Trier les demandes du plus grand au plus petit
  var sorted_requests = requests
  sorted_requests.sort(proc(a, b: SubnetRequest): int =
    cmp(b.hosts_needed, a.hosts_needed)
  )

  let original_prefix = get_prefix(cidr_str, 64)
  let network_addr = ipv6_to_addr(cidr_str)
  let base_network = get_network_v6(network_addr, original_prefix)

  var subnets: seq[NamedSubnetV6] = @[]
  var current_addr = base_network

  for req in sorted_requests:
    let addresses_needed = req.hosts_needed + 1  # IPv6 n'a pas de broadcast
    let bits_for_hosts = log2_int(addresses_needed)
    let new_prefix = 128 - bits_for_hosts

    if new_prefix < 1 or new_prefix > 126:
      return VlsmResultV6(
        success: false,
        error: "Le nombre d'hotes demande pour '" & req.name &
               "' (" & $req.hosts_needed & ") donne un prefixe invalide"
      )

    let subnet_cidr = addr_to_ipv6(current_addr) & "/" & $new_prefix

    subnets.add(NamedSubnetV6(
      name: req.name,
      info: get_subnet_info_v6(subnet_cidr)
    ))

    # Incrementer l'adresse pour le prochain sous-reseau
    if new_prefix <= 64:
      let increment = 1'u64 shl (64 - new_prefix)
      current_addr.high = current_addr.high + increment
    else:
      let increment = 1'u64 shl (128 - new_prefix)
      current_addr = add_to_ipv6(current_addr, increment)

  return VlsmResultV6(
    success: true,
    subnets: subnets
  )


# =============================================================================
# Supernetting / Route Summarization
# =============================================================================

## Compte le nombre de bits a 0 depuis la gauche (leading zeros).
##
## Cette fonction est utilisee pour determiner le prefixe commun
## entre plusieurs adresses lors du supernetting.
##
## Parametres:
##   - value: nombre uint32 a analyser
##
## Retour: nombre de bits a 0 depuis la gauche (0 a 32)
##
## Exemple:
##   count_leading_zeros(0x00FFFFFF) → 8 (premier octet a 0)
##   count_leading_zeros(0x0000FFFF) → 16 (deux premiers octets a 0)
proc count_leading_zeros(value: uint32): int =
  if value == 0:
    return 32
  var v = value
  var count = 0
  # Parcourir les bits depuis la gauche
  while (v and 0x80000000'u32) == 0:
    count += 1
    v = v shl 1
  return count


## Compte le nombre de bits a 0 depuis la gauche pour IPv6.
##
## Analyse les 128 bits (high puis low) pour trouver les leading zeros.
##
## Parametres:
##   - high: partie haute (64 bits)
##   - low: partie basse (64 bits)
##
## Retour: nombre de bits a 0 depuis la gauche (0 a 128)
proc count_leading_zeros_v6(high: uint64, low: uint64): int =
  if high == 0 and low == 0:
    return 128
  if high != 0:
    var v = high
    var count = 0
    while (v and 0x8000000000000000'u64) == 0:
      count += 1
      v = v shl 1
    return count
  else:
    # high est 0, compter dans low
    var v = low
    var count = 64  # Deja 64 bits a 0 dans high
    while (v and 0x8000000000000000'u64) == 0:
      count += 1
      v = v shl 1
    return count


## Agrege plusieurs reseaux IPv4 en un super-reseau (supernetting).
##
## Le supernetting (ou route summarization) permet de combiner plusieurs
## petits reseaux en un seul grand reseau, reduisant ainsi la taille
## des tables de routage.
##
## L'algorithme :
## 1. Convertit tous les reseaux en adresses uint32
## 2. Trouve les bits communs a toutes les adresses (XOR cumulatif)
## 3. Calcule le nouveau prefixe base sur les bits communs
## 4. Retourne le super-reseau
##
## Parametres:
##   - networks: liste des reseaux en notation CIDR (ex: ["192.168.0.0/24", "192.168.1.0/24"])
##
## Retour: SupernetResult avec le super-reseau ou une erreur
##
## Exemple:
##   let result = supernet(@["192.168.0.0/24", "192.168.1.0/24",
##                           "192.168.2.0/24", "192.168.3.0/24"])
##   # → 192.168.0.0/22
proc supernet*(networks: seq[string]): SupernetResult =
  if networks.len < 2:
    return SupernetResult(
      success: false,
      error: "Au moins 2 reseaux sont necessaires pour le supernetting"
    )

  # Convertir tous les reseaux en adresses de base
  var addresses: seq[uint32] = @[]
  var min_prefix = 32

  for cidr in networks:
    let prefix = get_prefix(cidr, 24)
    if prefix < min_prefix:
      min_prefix = prefix

    let ip_addr = ipv4_to_uint32(cidr)
    let mask = prefix_to_mask(prefix)
    let network_addr = ip_addr and mask
    addresses.add(network_addr)

  # Trouver les bits differents entre toutes les adresses (XOR cumulatif)
  # On part de la premiere adresse et on XOR avec toutes les autres
  var xor_result: uint32 = 0
  let base_addr = addresses[0]
  for i in 1..<addresses.len:
    xor_result = xor_result or (base_addr xor addresses[i])

  # Compter les leading zeros dans le XOR pour trouver le prefixe commun
  let common_prefix = count_leading_zeros(xor_result)

  # Le nouveau prefixe ne peut pas etre plus grand que le plus petit original
  let new_prefix = min(common_prefix, min_prefix)

  if new_prefix == 0:
    return SupernetResult(
      success: false,
      error: "Les reseaux n'ont pas de prefixe commun (trop differents)"
    )

  # Calculer l'adresse du super-reseau
  let supernet_mask = prefix_to_mask(new_prefix)
  let supernet_addr = base_addr and supernet_mask
  let supernet_cidr = uint32_to_ip(supernet_addr) & "/" & $new_prefix

  # Verifier que tous les reseaux sont couverts par le super-reseau
  for i, net_addr in addresses:
    if (net_addr and supernet_mask) != supernet_addr:
      return SupernetResult(
        success: false,
        error: "Le reseau " & networks[i] & " n'est pas couvert par le super-reseau calcule"
      )

  return SupernetResult(
    success: true,
    supernet: get_subnet_info(supernet_cidr),
    original_networks: networks
  )


## Agrege plusieurs reseaux IPv6 en un super-reseau (supernetting).
##
## Meme principe que pour IPv4, mais sur 128 bits.
##
## Parametres:
##   - networks: liste des reseaux en notation CIDR (ex: ["2001:db8::/48", "2001:db8:1::/48"])
##
## Retour: SupernetResultV6 avec le super-reseau ou une erreur
proc supernet_v6*(networks: seq[string]): SupernetResultV6 =
  if networks.len < 2:
    return SupernetResultV6(
      success: false,
      error: "Au moins 2 reseaux sont necessaires pour le supernetting"
    )

  # Convertir tous les reseaux en adresses IPv6
  var addresses: seq[IPv6Addr] = @[]
  var min_prefix = 128

  for cidr in networks:
    let prefix = get_prefix(cidr, 64)
    if prefix < min_prefix:
      min_prefix = prefix

    let ip_addr = ipv6_to_addr(cidr)
    let network_addr = get_network_v6(ip_addr, prefix)
    addresses.add(network_addr)

  # Trouver les bits differents (XOR cumulatif)
  var xor_high: uint64 = 0
  var xor_low: uint64 = 0
  let base_addr = addresses[0]

  for i in 1..<addresses.len:
    xor_high = xor_high or (base_addr.high xor addresses[i].high)
    xor_low = xor_low or (base_addr.low xor addresses[i].low)

  # Compter les leading zeros pour trouver le prefixe commun
  let common_prefix = count_leading_zeros_v6(xor_high, xor_low)

  # Le nouveau prefixe ne peut pas etre plus grand que le plus petit original
  let new_prefix = min(common_prefix, min_prefix)

  if new_prefix == 0:
    return SupernetResultV6(
      success: false,
      error: "Les reseaux n'ont pas de prefixe commun (trop differents)"
    )

  # Calculer l'adresse du super-reseau
  let supernet_addr = get_network_v6(base_addr, new_prefix)
  let supernet_cidr = addr_to_ipv6(supernet_addr) & "/" & $new_prefix

  # Verifier que tous les reseaux sont couverts
  let (high_mask, low_mask) = prefix_to_mask_v6(new_prefix)
  for i, net_addr in addresses:
    let addr_masked_high = net_addr.high and high_mask
    let addr_masked_low = net_addr.low and low_mask
    if addr_masked_high != supernet_addr.high or addr_masked_low != supernet_addr.low:
      return SupernetResultV6(
        success: false,
        error: "Le reseau " & networks[i] & " n'est pas couvert par le super-reseau calcule"
      )

  return SupernetResultV6(
    success: true,
    supernet: get_subnet_info_v6(supernet_cidr),
    original_networks: networks
  )
