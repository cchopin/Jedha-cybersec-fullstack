import argparse
import std/os
import std/strutils
from validate import getIPKind, isValidIP, IPKind
from classify import classifyIP, NetworkInfo, NetworkKind

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

proc showBanner() =
  echo CYAN, BANNER, RESET

# Couleur selon le type de réseau
proc kindColor(kind: NetworkKind): string =
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


when isMainModule:
  showBanner()

  let p = newParser("netprobe"):
    help("Utilitaire d'analyse réseau - IP validator & classifier")

    command("validate"):
      help("Verifie si l'adresse est valide (IPv4 ou IPv6)")
      arg("ip", help="Adresse IP a valider")
      run:
        let kind = getIPKind(opts.ip)
        echo ""
        echo "  ", DIM, "Adresse: ", RESET, BOLD, opts.ip, RESET
        echo "  ", DIM, "Status:  ", RESET,
          if kind == invalid: RED & "INVALIDE" & RESET
          else: GREEN & $kind & RESET
        echo ""

    command("classify"):
      help("Indique la classe, si l'adresse est publique/privee, et son usage special")
      arg("ip", help="Adresse IP a classifier")
      run:
        if isValidIP(opts.ip):
          let info = classifyIP(opts.ip)
          let color = kindColor(info.kind)
          echo ""
          echo "  ", CYAN, "─────────────────────────────────────────", RESET
          echo "   Adresse:  ", BOLD, opts.ip, RESET
          echo "   Type:     ", color, info.kind, RESET
          echo "   Classe:   ", info.historicClass
          echo "   Detail:   ", info.detail
          echo "  ", CYAN, "─────────────────────────────────────────", RESET
          echo ""
        else:
          echo ""
          echo "  ", RED, "Erreur: adresse IP invalide", RESET
          echo ""

    command("info"):
      help("Affiche les informations complètes du réseau")
      arg("cidr", help="Notation CIDR (ex: 192.168.1.0/24)")
      run:
        echo "TODO: info ", opts.cidr

    command("contains"):
      help("Vérifie si une IP appartient à un réseau")
      arg("cidr", help="Notation CIDR du réseau")
      arg("ip", help="Adresse IP à vérifier")
      run:
        echo "TODO: contains ", opts.cidr, " ", opts.ip

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
    echo "Commandes: validate, classify, info, contains"
    echo ""
    echo "Utilisez 'netprobe --help' pour plus d'informations"
    quit(1)
