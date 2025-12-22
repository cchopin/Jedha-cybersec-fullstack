# =============================================================================
# NETPROBE - Outil CLI d'analyse réseau
# =============================================================================
#
# NetProbe est un utilitaire en ligne de commande pour analyser et valider
# des adresses IP et des sous-réseaux.
#
# COMMANDES DISPONIBLES :
#
#   validate <ip>      Vérifie si une adresse IP est valide
#   classify <ip>      Détermine le type de réseau (privé, public, etc.)
#   info <cidr>        Affiche les informations complètes d'un sous-réseau
#   contains <cidr> <ip>  Vérifie si une IP appartient à un réseau
#
# EXEMPLES :
#
#   netprobe validate 192.168.1.1
#   netprobe classify 8.8.8.8
#   netprobe info 192.168.1.0/24
#   netprobe contains 10.0.0.0/8 10.5.3.2
#
# MODE INTERACTIF :
#   Après chaque commande, le programme propose de :
#   - Entrer une nouvelle adresse pour la même commande
#   - Changer de commande
#   - Quitter
#
# =============================================================================

import argparse
import std/os
import std/strutils
import std/rdstdin
from validate import get_ip_kind, is_valid_ip, IPKind
from classify import classify_ip, NetworkInfo, NetworkKind
from info import get_subnet_info, SubnetInfo, get_subnet_info_v6, SubnetInfoV6
from utils import ipv4_to_uint32, is_in_network, ipv6_to_addr, is_in_network_v6
from subnet import subnet_equal_parts, subnet_by_host_count, subnet_vlsm, SubnetResult, VlsmResult, SubnetRequest, NamedSubnet, subnet_equal_parts_v6, subnet_by_host_count_v6, subnet_vlsm_v6, SubnetResultV6, VlsmResultV6, NamedSubnetV6
from classify import is_ipv6

# Couleurs ANSI
const
  RESET = "\e[0m"
  BOLD = "\e[1m"
  GREEN = "\e[32m"
  RED = "\e[31m"
  YELLOW = "\e[33m"
  CYAN = "\e[36m"
  MAGENTA = "\e[35m"
  DIM = "\e[2m"

const BANNER = """
╔═══════════════════════════════════════════╗
║  ███╗   ██╗███████╗████████╗██████╗       ║
║  ████╗  ██║██╔════╝╚══██╔══╝██╔══██╗      ║
║  ██╔██╗ ██║█████╗     ██║   ██████╔╝      ║
║  ██║╚██╗██║██╔══╝     ██║   ██╔═══╝       ║
║  ██║ ╚████║███████╗   ██║   ██║   PROBE   ║
║  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝   v1.0    ║
╚═══════════════════════════════════════════╝
"""


## Affiche la bannière du programme.
proc show_banner() =
  echo CYAN, BANNER, RESET


## Retourne la couleur associée à un type de réseau.
proc kind_color(kind: NetworkKind): string =
  case kind
  of LOOPBACK: MAGENTA
  of PRIVATE: GREEN
  of LINK_LOCAL: YELLOW
  of MULTICAST: CYAN
  of RESERVED: RED
  of SPECIAL: YELLOW
  of BROADCAST: RED
  of CGNAT: YELLOW
  of DOCUMENTATION: CYAN
  of PUBLIC: BOLD


## Exécute la commande validate sur une adresse IP.
proc run_validate(ip_str: string) =
  let kind = get_ip_kind(ip_str)
  echo ""
  echo "  ", DIM, "Adresse: ", RESET, BOLD, ip_str, RESET
  echo "  ", DIM, "Status:  ", RESET,
    if kind == invalid: RED & "INVALIDE" & RESET
    else: GREEN & $kind & RESET
  echo ""


## Exécute la commande classify sur une adresse IP.
proc run_classify(ip_str: string) =
  if is_valid_ip(ip_str):
    let info = classify_ip(ip_str)
    let color = kind_color(info.kind)
    echo ""
    echo "  ", CYAN, "─────────────────────────────────────────", RESET
    echo "   Adresse:  ", BOLD, ip_str, RESET
    echo "   Type:     ", color, info.kind, RESET
    echo "   Classe:   ", info.historic_class
    echo "   Detail:   ", info.detail
    echo "  ", CYAN, "─────────────────────────────────────────", RESET
    echo ""
  else:
    echo ""
    echo "  ", RED, "Erreur: adresse IP invalide", RESET
    echo ""


## Exécute la commande info sur une notation CIDR (IPv4 ou IPv6).
proc run_info(cidr_str: string) =
  let kind = get_ip_kind(cidr_str)
  if kind == ipv4_cidr:
    let info = get_subnet_info(cidr_str)
    echo ""
    echo "  ", CYAN, "═══════════════════════════════════════════", RESET
    echo "  ", CYAN, "       INFORMATIONS RÉSEAU (IPv4)          ", RESET
    echo "  ", CYAN, "═══════════════════════════════════════════", RESET
    echo ""
    echo "   ", DIM, "CIDR:        ", RESET, BOLD, cidr_str, RESET
    echo "   ", DIM, "Masque:      ", RESET, info.mask
    echo ""
    echo "   ", DIM, "Réseau:      ", RESET, GREEN, info.network, RESET
    echo "   ", DIM, "Broadcast:   ", RESET, YELLOW, info.broadcast, RESET
    echo ""
    echo "   ", DIM, "Première IP: ", RESET, info.first_host
    echo "   ", DIM, "Dernière IP: ", RESET, info.last_host
    echo "   ", DIM, "Nb d'hôtes:  ", RESET, BOLD, info.host_count, RESET
    echo ""
    echo "  ", CYAN, "═══════════════════════════════════════════", RESET
    echo ""
  elif kind == ipv6_cidr:
    let info = get_subnet_info_v6(cidr_str)
    echo ""
    echo "  ", CYAN, "═══════════════════════════════════════════════════════", RESET
    echo "  ", CYAN, "              INFORMATIONS RÉSEAU (IPv6)               ", RESET
    echo "  ", CYAN, "═══════════════════════════════════════════════════════", RESET
    echo ""
    echo "   ", DIM, "CIDR:        ", RESET, BOLD, cidr_str, RESET
    echo "   ", DIM, "Préfixe:     ", RESET, "/", info.prefix
    echo ""
    echo "   ", DIM, "Réseau:      ", RESET, GREEN, info.network, RESET
    echo ""
    echo "   ", DIM, "Masque:      ", RESET
    echo "   ", DIM, "  high:      ", RESET, info.mask_high
    echo "   ", DIM, "  low:       ", RESET, info.mask_low
    echo ""
    echo "   ", DIM, "Note:        ", RESET, "Pas de broadcast en IPv6"
    echo ""
    echo "  ", CYAN, "═══════════════════════════════════════════════════════", RESET
    echo ""
  else:
    echo ""
    echo "  ", RED, "Erreur: notation CIDR invalide", RESET
    echo "  ", DIM, "Exemples: 192.168.1.0/24 ou 2001:db8::/32", RESET
    echo ""


## Exécute la commande contains pour vérifier l'appartenance à un réseau (IPv4 ou IPv6).
proc run_contains(cidr_str: string, ip_str: string) =
  let cidr_kind = get_ip_kind(cidr_str)
  let ip_kind = get_ip_kind(ip_str)

  # Vérifier la cohérence des types (IPv4 avec IPv4, IPv6 avec IPv6)
  if cidr_kind == ipv4_cidr and ip_kind == ipv4:
    # IPv4
    let ip_addr = ipv4_to_uint32(ip_str)
    let result = is_in_network(ip_addr, cidr_str)

    echo ""
    echo "  ", CYAN, "─────────────────────────────────────────", RESET
    echo "   Réseau:   ", BOLD, cidr_str, RESET
    echo "   Adresse:  ", BOLD, ip_str, RESET
    echo "   Résultat: ",
      if result: GREEN & "OUI - L'IP appartient au réseau" & RESET
      else: RED & "NON - L'IP n'appartient pas au réseau" & RESET
    echo "  ", CYAN, "─────────────────────────────────────────", RESET
    echo ""

  elif cidr_kind == ipv6_cidr and ip_kind == ipv6:
    # IPv6
    let ip_addr = ipv6_to_addr(ip_str)
    let result = is_in_network_v6(ip_addr, cidr_str)

    echo ""
    echo "  ", CYAN, "───────────────────────────────────────────────────────", RESET
    echo "   Réseau:   ", BOLD, cidr_str, RESET
    echo "   Adresse:  ", BOLD, ip_str, RESET
    echo "   Résultat: ",
      if result: GREEN & "OUI - L'IP appartient au réseau" & RESET
      else: RED & "NON - L'IP n'appartient pas au réseau" & RESET
    echo "  ", CYAN, "───────────────────────────────────────────────────────", RESET
    echo ""

  elif cidr_kind == ipv4_cidr and ip_kind == ipv6:
    echo ""
    echo "  ", RED, "Erreur: impossible de comparer IPv4 et IPv6", RESET
    echo "  ", DIM, "Le réseau est IPv4, l'adresse est IPv6", RESET
    echo ""

  elif cidr_kind == ipv6_cidr and ip_kind == ipv4:
    echo ""
    echo "  ", RED, "Erreur: impossible de comparer IPv6 et IPv4", RESET
    echo "  ", DIM, "Le réseau est IPv6, l'adresse est IPv4", RESET
    echo ""

  else:
    echo ""
    echo "  ", RED, "Erreur: notation invalide", RESET
    echo "  ", DIM, "CIDR attendu: 192.168.0.0/16 ou 2001:db8::/32", RESET
    echo "  ", DIM, "IP attendue: 192.168.1.1 ou 2001:db8::1", RESET
    echo ""


## Affiche les sous-reseaux generes.
proc display_subnets(result: SubnetResult) =
  if not result.success:
    echo ""
    echo "  ", RED, "Erreur: ", result.error, RESET
    echo ""
    return

  echo ""
  echo "  ", CYAN, "═══════════════════════════════════════════════════════════════════", RESET
  echo "  ", CYAN, "                      SOUS-RESEAUX GENERES                          ", RESET
  echo "  ", CYAN, "═══════════════════════════════════════════════════════════════════", RESET
  echo ""

  for i, subnet in result.subnets:
    echo "  ", YELLOW, "Sous-reseau ", i + 1, RESET
    echo "   ", DIM, "Reseau:      ", RESET, GREEN, subnet.network, "/", subnet.prefix, RESET
    echo "   ", DIM, "Masque:      ", RESET, subnet.mask
    echo "   ", DIM, "Broadcast:   ", RESET, subnet.broadcast
    echo "   ", DIM, "Plage:       ", RESET, subnet.first_host, " - ", subnet.last_host
    echo "   ", DIM, "Nb d'hotes:  ", RESET, BOLD, subnet.host_count, RESET
    echo ""

  echo "  ", CYAN, "═══════════════════════════════════════════════════════════════════", RESET
  echo ""


## Affiche les sous-reseaux IPv6 generes.
proc display_subnets_v6(result: SubnetResultV6) =
  if not result.success:
    echo ""
    echo "  ", RED, "Erreur: ", result.error, RESET
    echo ""
    return

  echo ""
  echo "  ", CYAN, "═══════════════════════════════════════════════════════════════════", RESET
  echo "  ", CYAN, "                   SOUS-RESEAUX IPv6 GENERES                        ", RESET
  echo "  ", CYAN, "═══════════════════════════════════════════════════════════════════", RESET
  echo ""

  for i, subnet in result.subnets:
    echo "  ", YELLOW, "Sous-reseau ", i + 1, RESET
    echo "   ", DIM, "Reseau:      ", RESET, GREEN, subnet.network, "/", subnet.prefix, RESET
    echo ""

  echo "  ", CYAN, "═══════════════════════════════════════════════════════════════════", RESET
  echo ""


## Execute la commande split pour diviser en parts egales.
proc run_split(cidr_str: string, num_subnets: int) =
  if is_ipv6(cidr_str):
    let result = subnet_equal_parts_v6(cidr_str, num_subnets)
    display_subnets_v6(result)
  else:
    let result = subnet_equal_parts(cidr_str, num_subnets)
    display_subnets(result)


## Execute la commande hosts pour diviser avec contrainte d'hotes.
proc run_hosts(cidr_str: string, num_subnets: int, min_hosts: int) =
  if is_ipv6(cidr_str):
    let result = subnet_by_host_count_v6(cidr_str, num_subnets, min_hosts)
    display_subnets_v6(result)
  else:
    let result = subnet_by_host_count(cidr_str, num_subnets, min_hosts)
    display_subnets(result)


## Affiche les sous-reseaux VLSM.
proc display_vlsm(result: VlsmResult) =
  if not result.success:
    echo ""
    echo "  ", RED, "Erreur: ", result.error, RESET
    echo ""
    return

  echo ""
  echo "  ", CYAN, "═══════════════════════════════════════════════════════════════════", RESET
  echo "  ", CYAN, "                    SOUS-RESEAUX VLSM GENERES                       ", RESET
  echo "  ", CYAN, "═══════════════════════════════════════════════════════════════════", RESET
  echo ""

  for ns in result.subnets:
    echo "  ", YELLOW, ns.name, RESET
    echo "   ", DIM, "Reseau:      ", RESET, GREEN, ns.info.network, "/", ns.info.prefix, RESET
    echo "   ", DIM, "Masque:      ", RESET, ns.info.mask
    echo "   ", DIM, "Broadcast:   ", RESET, ns.info.broadcast
    echo "   ", DIM, "Plage:       ", RESET, ns.info.first_host, " - ", ns.info.last_host
    echo "   ", DIM, "Nb d'hotes:  ", RESET, BOLD, ns.info.host_count, RESET
    echo ""

  echo "  ", CYAN, "═══════════════════════════════════════════════════════════════════", RESET
  echo ""


## Affiche les sous-reseaux VLSM IPv6.
proc display_vlsm_v6(result: VlsmResultV6) =
  if not result.success:
    echo ""
    echo "  ", RED, "Erreur: ", result.error, RESET
    echo ""
    return

  echo ""
  echo "  ", CYAN, "═══════════════════════════════════════════════════════════════════", RESET
  echo "  ", CYAN, "                 SOUS-RESEAUX VLSM IPv6 GENERES                     ", RESET
  echo "  ", CYAN, "═══════════════════════════════════════════════════════════════════", RESET
  echo ""

  for ns in result.subnets:
    echo "  ", YELLOW, ns.name, RESET
    echo "   ", DIM, "Reseau:      ", RESET, GREEN, ns.info.network, "/", ns.info.prefix, RESET
    echo ""

  echo "  ", CYAN, "═══════════════════════════════════════════════════════════════════", RESET
  echo ""


## Execute la commande vlsm.
proc run_vlsm(cidr_str: string, requests: seq[SubnetRequest]) =
  if is_ipv6(cidr_str):
    let result = subnet_vlsm_v6(cidr_str, requests)
    display_vlsm_v6(result)
  else:
    let result = subnet_vlsm(cidr_str, requests)
    display_vlsm(result)


## Affiche le menu interactif et retourne le choix de l'utilisateur.
proc show_interactive_menu(): string =
  echo ""
  echo "  ", CYAN, "┌─────────────────────────────────────────┐", RESET
  echo "  ", CYAN, "│", RESET, "  Que voulez-vous faire ?                ", CYAN, "│", RESET
  echo "  ", CYAN, "│", RESET, "  [1] Nouvelle adresse (même commande)   ", CYAN, "│", RESET
  echo "  ", CYAN, "│", RESET, "  [2] Changer de commande                ", CYAN, "│", RESET
  echo "  ", CYAN, "│", RESET, "  [q] Quitter                            ", CYAN, "│", RESET
  echo "  ", CYAN, "└─────────────────────────────────────────┘", RESET
  echo ""

  try:
    let choice = readLineFromStdin("  Votre choix: ")
    return choice.strip().toLowerAscii()
  except EOFError:
    return "q"


## Affiche le menu de sélection de commande.
proc show_command_menu(): string =
  echo ""
  echo "  ", CYAN, "┌─────────────────────────────────────────┐", RESET
  echo "  ", CYAN, "│", RESET, "  Choisissez une commande :             ", CYAN, "│", RESET
  echo "  ", CYAN, "│", RESET, "  [1] validate  - Valider une IP        ", CYAN, "│", RESET
  echo "  ", CYAN, "│", RESET, "  [2] classify  - Classifier une IP     ", CYAN, "│", RESET
  echo "  ", CYAN, "│", RESET, "  [3] info      - Infos sous-réseau     ", CYAN, "│", RESET
  echo "  ", CYAN, "│", RESET, "  [4] contains  - IP dans réseau ?      ", CYAN, "│", RESET
  echo "  ", CYAN, "│", RESET, "  [5] split     - Diviser en N parts    ", CYAN, "│", RESET
  echo "  ", CYAN, "│", RESET, "  [6] hosts     - Diviser par nb hotes  ", CYAN, "│", RESET
  echo "  ", CYAN, "│", RESET, "  [7] vlsm      - Tailles variables     ", CYAN, "│", RESET
  echo "  ", CYAN, "│", RESET, "  [q] Quitter                           ", CYAN, "│", RESET
  echo "  ", CYAN, "└─────────────────────────────────────────┘", RESET
  echo ""

  try:
    let choice = readLineFromStdin("  Votre choix: ")
    return choice.strip().toLowerAscii()
  except EOFError:
    return "q"


## Demande une entrée à l'utilisateur.
proc prompt_input(message: string): string =
  try:
    return readLineFromStdin("  " & message).strip()
  except EOFError:
    return ""


## Demande les informations VLSM a l'utilisateur.
proc prompt_vlsm_requests(): seq[SubnetRequest] =
  var requests: seq[SubnetRequest] = @[]

  let num_str = prompt_input("Nombre de departements: ")
  if num_str.len == 0:
    return requests

  let num_depts = parseInt(num_str)
  if num_depts <= 0:
    return requests

  echo ""
  for i in 1..num_depts:
    let name = prompt_input("Nom du departement " & $i & ": ")
    let hosts_str = prompt_input("Nombre de devices pour " & name & ": ")
    if name.len > 0 and hosts_str.len > 0:
      requests.add(SubnetRequest(name: name, hosts_needed: parseInt(hosts_str)))
    echo ""

  return requests


## Boucle interactive pour une commande donnée.
proc interactive_loop(command: string, initial_arg1: string, initial_arg2: string = "", initial_arg3: string = "", vlsm_requests: seq[SubnetRequest] = @[]) =
  var current_command = command
  var arg1 = initial_arg1
  var arg2 = initial_arg2
  var arg3 = initial_arg3
  var requests = vlsm_requests

  # Exécuter la commande initiale
  case current_command
  of "validate":
    run_validate(arg1)
  of "classify":
    run_classify(arg1)
  of "info":
    run_info(arg1)
  of "contains":
    run_contains(arg1, arg2)
  of "split":
    run_split(arg1, parseInt(arg2))
  of "hosts":
    run_hosts(arg1, parseInt(arg2), parseInt(arg3))
  of "vlsm":
    run_vlsm(arg1, requests)
  else:
    return

  # Boucle interactive
  while true:
    let choice = show_interactive_menu()

    case choice
    of "1":
      # Nouvelle adresse, même commande
      case current_command
      of "validate":
        arg1 = prompt_input("Adresse IP: ")
        if arg1.len > 0:
          run_validate(arg1)
      of "classify":
        arg1 = prompt_input("Adresse IP: ")
        if arg1.len > 0:
          run_classify(arg1)
      of "info":
        arg1 = prompt_input("Notation CIDR: ")
        if arg1.len > 0:
          run_info(arg1)
      of "contains":
        arg1 = prompt_input("Notation CIDR: ")
        arg2 = prompt_input("Adresse IP: ")
        if arg1.len > 0 and arg2.len > 0:
          run_contains(arg1, arg2)
      of "split":
        arg1 = prompt_input("Notation CIDR: ")
        arg2 = prompt_input("Nombre de sous-reseaux (2,4,8...): ")
        if arg1.len > 0 and arg2.len > 0:
          run_split(arg1, parseInt(arg2))
      of "hosts":
        arg1 = prompt_input("Notation CIDR: ")
        arg2 = prompt_input("Nombre de sous-reseaux: ")
        arg3 = prompt_input("Minimum d'hotes par sous-reseau: ")
        if arg1.len > 0 and arg2.len > 0 and arg3.len > 0:
          run_hosts(arg1, parseInt(arg2), parseInt(arg3))
      of "vlsm":
        arg1 = prompt_input("Notation CIDR: ")
        requests = prompt_vlsm_requests()
        if arg1.len > 0 and requests.len > 0:
          run_vlsm(arg1, requests)
      else:
        discard

    of "2":
      # Changer de commande
      let cmd_choice = show_command_menu()
      case cmd_choice
      of "1":
        current_command = "validate"
        arg1 = prompt_input("Adresse IP: ")
        if arg1.len > 0:
          run_validate(arg1)
      of "2":
        current_command = "classify"
        arg1 = prompt_input("Adresse IP: ")
        if arg1.len > 0:
          run_classify(arg1)
      of "3":
        current_command = "info"
        arg1 = prompt_input("Notation CIDR: ")
        if arg1.len > 0:
          run_info(arg1)
      of "4":
        current_command = "contains"
        arg1 = prompt_input("Notation CIDR: ")
        arg2 = prompt_input("Adresse IP: ")
        if arg1.len > 0 and arg2.len > 0:
          run_contains(arg1, arg2)
      of "5":
        current_command = "split"
        arg1 = prompt_input("Notation CIDR: ")
        arg2 = prompt_input("Nombre de sous-reseaux (2,4,8...): ")
        if arg1.len > 0 and arg2.len > 0:
          run_split(arg1, parseInt(arg2))
      of "6":
        current_command = "hosts"
        arg1 = prompt_input("Notation CIDR: ")
        arg2 = prompt_input("Nombre de sous-reseaux: ")
        arg3 = prompt_input("Minimum d'hotes par sous-reseau: ")
        if arg1.len > 0 and arg2.len > 0 and arg3.len > 0:
          run_hosts(arg1, parseInt(arg2), parseInt(arg3))
      of "7":
        current_command = "vlsm"
        arg1 = prompt_input("Notation CIDR: ")
        requests = prompt_vlsm_requests()
        if arg1.len > 0 and requests.len > 0:
          run_vlsm(arg1, requests)
      of "q":
        echo ""
        echo "  ", DIM, "Au revoir!", RESET
        echo ""
        return
      else:
        echo "  ", RED, "Choix invalide", RESET

    of "q":
      echo ""
      echo "  ", DIM, "Au revoir!", RESET
      echo ""
      return

    else:
      echo "  ", RED, "Choix invalide", RESET


when isMainModule:
  show_banner()

  let p = newParser("netprobe"):
    help("Utilitaire d'analyse réseau - IP validator & classifier")

    command("validate"):
      help("Verifie si l'adresse est valide (IPv4 ou IPv6)")
      arg("ip", help="Adresse IP a valider")
      run:
        interactive_loop("validate", opts.ip)

    command("classify"):
      help("Indique la classe, si l'adresse est publique/privee, et son usage special")
      arg("ip", help="Adresse IP a classifier")
      run:
        interactive_loop("classify", opts.ip)

    command("info"):
      help("Affiche les informations complètes du réseau")
      arg("cidr", help="Notation CIDR (ex: 192.168.1.0/24)")
      run:
        interactive_loop("info", opts.cidr)

    command("contains"):
      help("Vérifie si une IP appartient à un réseau")
      arg("cidr", help="Notation CIDR du réseau")
      arg("ip", help="Adresse IP à vérifier")
      run:
        interactive_loop("contains", opts.cidr, opts.ip)

    command("split"):
      help("Divise un réseau en N sous-réseaux égaux (N = puissance de 2)")
      arg("cidr", help="Notation CIDR du réseau")
      arg("num", help="Nombre de sous-réseaux (2, 4, 8, 16...)")
      run:
        interactive_loop("split", opts.cidr, opts.num)

    command("hosts"):
      help("Divise un réseau avec contrainte de nombre minimum d'hôtes")
      arg("cidr", help="Notation CIDR du réseau")
      arg("num", help="Nombre de sous-réseaux")
      arg("min_hosts", help="Nombre minimum d'hôtes par sous-réseau")
      run:
        interactive_loop("hosts", opts.cidr, opts.num, opts.min_hosts)

    command("vlsm"):
      help("Divise un réseau en sous-réseaux de tailles variables (VLSM)")
      arg("cidr", help="Notation CIDR du réseau")
      run:
        let requests = prompt_vlsm_requests()
        if requests.len > 0:
          interactive_loop("vlsm", opts.cidr, "", "", requests)

  try:
    if commandLineParams().len == 0:
      echo p.help
      quit(0)
    p.run(commandLineParams())
  except ShortCircuit as e:
    if e.flag == "argparse_help":
      echo p.help
      quit(0)
  except UsageError as e:
    echo "ERREUR: ", e.msg
    echo ""
    echo "Usage: netprobe <commande> <argument>"
    echo "Commandes: validate, classify, info, contains, split, hosts, vlsm"
    echo ""
    echo "Utilisez 'netprobe --help' pour plus d'informations"
    quit(1)
