# =============================================================================
# HELP - Aide et tutoriels avec schemas ASCII
# =============================================================================

import std/[strutils]
import display

# =============================================================================
# Contenu de l'aide par theme
# =============================================================================

proc helpValidation*() =
  ## Aide sur la validation d'adresses IP
  clearScreen()
  echo banner()
  echo categoryHeader("Validation d'adresses IPv4")

  let content = @[
    BOLD & "Une adresse IPv4 valide doit respecter :" & RESET,
    "",
    "  " & BRIGHT_GREEN & CHECK & RESET & " Exactement 4 octets separes par des points",
    "  " & BRIGHT_GREEN & CHECK & RESET & " Chaque octet entre 0 et 255",
    "  " & BRIGHT_GREEN & CHECK & RESET & " Que des chiffres (pas de lettres)",
    "",
    BOLD & "Exemples valides :" & RESET,
    "  " & BRIGHT_GREEN & "192.168.1.1" & RESET & "     " & DIM & "4 octets, tous entre 0-255" & RESET,
    "  " & BRIGHT_GREEN & "10.0.0.1" & RESET & "        " & DIM & "les zeros sont acceptes" & RESET,
    "  " & BRIGHT_GREEN & "255.255.255.0" & RESET & "   " & DIM & "valeurs maximales OK" & RESET,
    "",
    BOLD & "Exemples invalides :" & RESET,
    "  " & BRIGHT_RED & "192.168.1" & RESET & "       " & DIM & "seulement 3 octets" & RESET,
    "  " & BRIGHT_RED & "192.168.1.256" & RESET & "   " & DIM & "256 > 255" & RESET,
    "  " & BRIGHT_RED & "192.168.1.1.1" & RESET & "   " & DIM & "5 octets" & RESET,
    "  " & BRIGHT_RED & "192.168.a.1" & RESET & "     " & DIM & "contient une lettre" & RESET
  ]
  echo box(content, "", CYAN, 65)

  echo ""
  echo categoryHeader("Structure binaire")

  let binary = @[
    "Une adresse IP = 32 bits = 4 octets de 8 bits",
    "",
    "  " & BRIGHT_CYAN & "192" & RESET & "      .  " & BRIGHT_CYAN & "168" & RESET & "      .  " & BRIGHT_CYAN & "1" & RESET & "        .  " & BRIGHT_CYAN & "10" & RESET,
    "  " & YELLOW & "11000000" & RESET & " .  " & YELLOW & "10101000" & RESET & " .  " & YELLOW & "00000001" & RESET & " .  " & YELLOW & "00001010" & RESET,
    "  " & DIM & "---|----" & RESET & "    " & DIM & "---|----" & RESET & "    " & DIM & "---|----" & RESET & "    " & DIM & "---|----" & RESET,
    "  " & DIM & "128 64 32" & RESET & "   " & DIM & "128 64 32" & RESET & "   " & DIM & "128 64 32" & RESET & "   " & DIM & "128 64 32" & RESET,
    "",
    "Chaque bit a une valeur : 128, 64, 32, 16, 8, 4, 2, 1",
    "192 = 128 + 64 = " & YELLOW & "11" & RESET & "000000"
  ]
  echo box(binary, "", YELLOW, 65)

  waitForEnter()


proc helpClassification*() =
  ## Aide sur la classification des adresses
  clearScreen()
  echo banner()
  echo categoryHeader("Classification des adresses")

  let content = @[
    BOLD & "Types d'adresses IPv4 :" & RESET,
    "",
    BRIGHT_GREEN & "PRIVEES" & RESET & " (non routables sur Internet) :",
    "  " & BULLET & " 10.0.0.0    - 10.255.255.255   " & DIM & "(/8)" & RESET,
    "  " & BULLET & " 172.16.0.0  - 172.31.255.255   " & DIM & "(/12)" & RESET,
    "  " & BULLET & " 192.168.0.0 - 192.168.255.255  " & DIM & "(/16)" & RESET,
    "",
    BRIGHT_CYAN & "LOOPBACK" & RESET & " (interface locale) :",
    "  " & BULLET & " 127.0.0.0   - 127.255.255.255  " & DIM & "(/8)" & RESET,
    "  " & DIM & "127.0.0.1 = localhost" & RESET,
    "",
    BRIGHT_YELLOW & "LINK-LOCAL / APIPA" & RESET & " (auto-config sans DHCP) :",
    "  " & BULLET & " 169.254.0.0 - 169.254.255.255  " & DIM & "(/16)" & RESET,
    "",
    BRIGHT_MAGENTA & "MULTICAST" & RESET & " (diffusion groupe) :",
    "  " & BULLET & " 224.0.0.0   - 239.255.255.255  " & DIM & "(classe D)" & RESET,
    "",
    BRIGHT_WHITE & "PUBLIQUES" & RESET & " (routables sur Internet) :",
    "  " & BULLET & " Toutes les autres adresses"
  ]
  echo box(content, "", CYAN, 65)

  echo ""
  echo categoryHeader("Schema memotechnique")

  let memo = @[
    "  " & BRIGHT_GREEN & "10" & RESET & ".x.x.x        " & ARROW_RIGHT & "  Prive classe A",
    "  " & BRIGHT_GREEN & "172.16-31" & RESET & ".x.x  " & ARROW_RIGHT & "  Prive classe B",
    "  " & BRIGHT_GREEN & "192.168" & RESET & ".x.x    " & ARROW_RIGHT & "  Prive classe C",
    "  " & BRIGHT_CYAN & "127" & RESET & ".x.x.x        " & ARROW_RIGHT & "  Loopback",
    "  " & BRIGHT_YELLOW & "169.254" & RESET & ".x.x    " & ARROW_RIGHT & "  APIPA (pas de DHCP)",
    "  " & BRIGHT_MAGENTA & "224-239" & RESET & ".x.x.x  " & ARROW_RIGHT & "  Multicast"
  ]
  echo box(memo, "A RETENIR", YELLOW, 65)

  waitForEnter()


proc helpMasks*() =
  ## Aide sur les masques de sous-reseau
  clearScreen()
  echo banner()
  echo categoryHeader("Masques de sous-reseau")

  let content = @[
    BOLD & "Le masque separe la partie RESEAU de la partie HOTE" & RESET,
    "",
    "  IP:     192.168.  1 . 10",
    "  Masque: 255.255.255.  0",
    "          " & BRIGHT_GREEN & "----RESEAU----" & RESET & "  " & BRIGHT_CYAN & "HOTE" & RESET,
    "",
    BOLD & "Notation CIDR :" & RESET & " /N = N bits a 1 dans le masque",
    "",
    "  /24 = " & YELLOW & "11111111.11111111.11111111" & RESET & ".00000000",
    "       = 255.255.255.0",
    "",
    "  /16 = " & YELLOW & "11111111.11111111" & RESET & ".00000000.00000000",
    "       = 255.255.0.0"
  ]
  echo box(content, "", CYAN, 65)

  echo ""
  echo categoryHeader("Table des masques courants")

  let table = @[
    "  " & BOLD & "CIDR   Masque            Hotes" & RESET,
    "  " & DIM & "----------------------------------------" & RESET,
    "  /8    255.0.0.0         16,777,214",
    "  /16   255.255.0.0       65,534",
    "  /24   255.255.255.0     254",
    "  /25   255.255.255.128   126",
    "  /26   255.255.255.192   62",
    "  /27   255.255.255.224   30",
    "  /28   255.255.255.240   14",
    "  /29   255.255.255.248   6",
    "  /30   255.255.255.252   2",
    "",
    DIM & "Formule: Hotes = 2^(32-prefix) - 2" & RESET
  ]
  echo box(table, "REFERENCE", YELLOW, 65)

  waitForEnter()


proc helpNetwork*() =
  ## Aide sur le calcul d'adresse reseau
  clearScreen()
  echo banner()
  echo categoryHeader("Adresse reseau")

  let content = @[
    BOLD & "L'adresse reseau identifie le sous-reseau" & RESET,
    "",
    "C'est la " & BRIGHT_GREEN & "premiere adresse" & RESET & " du bloc (tous les bits hote a 0)",
    "",
    BOLD & "Calcul : IP AND Masque" & RESET,
    "",
    "  Exemple: 192.168.1." & BRIGHT_CYAN & "130" & RESET & "/24",
    "",
    "  IP:      11000000.10101000.00000001." & BRIGHT_CYAN & "10000010" & RESET,
    "  Masque:  11111111.11111111.11111111." & YELLOW & "00000000" & RESET,
    "           " & DIM & "-------- AND --------" & RESET,
    "  Reseau:  11000000.10101000.00000001." & BRIGHT_GREEN & "00000000" & RESET,
    "",
    "  = 192.168.1." & BRIGHT_GREEN & "0" & RESET
  ]
  echo box(content, "", CYAN, 65)

  echo ""
  echo categoryHeader("Operation AND bit a bit")

  let andOp = @[
    "  L'operation AND conserve le bit seulement si les DEUX sont a 1",
    "",
    "    1 AND 1 = " & BRIGHT_GREEN & "1" & RESET,
    "    1 AND 0 = " & BRIGHT_RED & "0" & RESET,
    "    0 AND 1 = " & BRIGHT_RED & "0" & RESET,
    "    0 AND 0 = " & BRIGHT_RED & "0" & RESET,
    "",
    "  " & ARROW_RIGHT & " Le masque \"efface\" les bits hote (met a 0)"
  ]
  echo box(andOp, "RAPPEL", YELLOW, 65)

  waitForEnter()


proc helpBroadcast*() =
  ## Aide sur le calcul d'adresse broadcast
  clearScreen()
  echo banner()
  echo categoryHeader("Adresse broadcast")

  let content = @[
    BOLD & "L'adresse broadcast atteint TOUS les hotes du reseau" & RESET,
    "",
    "C'est la " & BRIGHT_MAGENTA & "derniere adresse" & RESET & " du bloc (tous les bits hote a 1)",
    "",
    BOLD & "Calcul : Reseau OR (NOT Masque)" & RESET,
    "",
    "  Exemple: 192.168.1.0/24",
    "",
    "  Reseau:     11000000.10101000.00000001." & BRIGHT_GREEN & "00000000" & RESET,
    "  NOT Masque: 00000000.00000000.00000000." & YELLOW & "11111111" & RESET,
    "              " & DIM & "-------- OR ---------" & RESET,
    "  Broadcast:  11000000.10101000.00000001." & BRIGHT_MAGENTA & "11111111" & RESET,
    "",
    "  = 192.168.1." & BRIGHT_MAGENTA & "255" & RESET
  ]
  echo box(content, "", CYAN, 65)

  echo ""
  echo categoryHeader("Plage d'adresses utilisables")

  let range = @[
    "  Pour 192.168.1.0/24 :",
    "",
    "  " & DIM & "Reseau:    " & RESET & "192.168.1." & BRIGHT_GREEN & "0" & RESET & "     " & DIM & "(reserve)" & RESET,
    "  " & DIM & "Premier:   " & RESET & "192.168.1." & BRIGHT_CYAN & "1" & RESET & "     " & BRIGHT_CYAN & ARROW_LEFT & " Premier hote" & RESET,
    "  " & DIM & "..." & RESET,
    "  " & DIM & "Dernier:   " & RESET & "192.168.1." & BRIGHT_CYAN & "254" & RESET & "   " & BRIGHT_CYAN & ARROW_LEFT & " Dernier hote" & RESET,
    "  " & DIM & "Broadcast: " & RESET & "192.168.1." & BRIGHT_MAGENTA & "255" & RESET & "   " & DIM & "(reserve)" & RESET,
    "",
    "  " & ARROW_RIGHT & " 254 hotes utilisables (256 - 2)"
  ]
  echo box(range, "PLAGE", YELLOW, 65)

  waitForEnter()


proc helpBelonging*() =
  ## Aide sur l'appartenance a un reseau
  clearScreen()
  echo banner()
  echo categoryHeader("Appartenance a un reseau")

  let content = @[
    BOLD & "Pour verifier si une IP appartient a un reseau :" & RESET,
    "",
    "1. Calculer l'adresse reseau de l'IP testee",
    "2. Comparer avec l'adresse reseau donnee",
    "",
    BRIGHT_GREEN & "Exemple: 192.168.1.50 dans 192.168.1.0/24 ?" & RESET,
    "",
    "  IP testee: 192.168.1.50",
    "  Masque /24: 255.255.255.0",
    "  IP AND Masque = 192.168.1.0",
    "",
    "  192.168.1.0 == 192.168.1.0 " & BRIGHT_GREEN & CHECK & " OUI" & RESET,
    "",
    BRIGHT_RED & "Exemple: 192.168.2.50 dans 192.168.1.0/24 ?" & RESET,
    "",
    "  IP testee: 192.168.2.50",
    "  IP AND Masque = 192.168.2.0",
    "",
    "  192.168.2.0 != 192.168.1.0 " & BRIGHT_RED & CROSS_MARK & " NON" & RESET
  ]
  echo box(content, "", CYAN, 65)

  echo ""
  echo categoryHeader("Astuce rapide")

  let tip = @[
    "Pour /24 : seul le dernier octet peut varier",
    "Pour /16 : les 2 derniers octets peuvent varier",
    "Pour /8  : les 3 derniers octets peuvent varier",
    "",
    "  192.168.1.0/24 contient 192.168.1.0 a 192.168.1.255",
    "  192.168.0.0/16 contient 192.168.0.0 a 192.168.255.255",
    "  10.0.0.0/8    contient 10.0.0.0    a 10.255.255.255"
  ]
  echo box(tip, "ASTUCE", YELLOW, 65)

  waitForEnter()


proc helpSubnetting*() =
  ## Aide sur le subnetting
  clearScreen()
  echo banner()
  echo categoryHeader("Division en sous-reseaux (Subnetting)")

  let content = @[
    BOLD & "Diviser un reseau = emprunter des bits a la partie hote" & RESET,
    "",
    "  Original: 192.168.1.0/24",
    "            " & BRIGHT_GREEN & "NNNNNNNN.NNNNNNNN.NNNNNNNN" & RESET & "." & BRIGHT_CYAN & "HHHHHHHH" & RESET,
    "",
    "  Divise /26 (2 bits empruntes):",
    "            " & BRIGHT_GREEN & "NNNNNNNN.NNNNNNNN.NNNNNNNN" & RESET & "." & BRIGHT_YELLOW & "SS" & RESET & BRIGHT_CYAN & "HHHHHH" & RESET,
    "",
    "  " & BRIGHT_YELLOW & "S" & RESET & " = bits de sous-reseau",
    "  " & BRIGHT_CYAN & "H" & RESET & " = bits d'hote restants"
  ]
  echo box(content, "", CYAN, 65)

  echo ""
  echo categoryHeader("Formules essentielles")

  let formulas = @[
    BOLD & "Nombre de sous-reseaux :" & RESET,
    "  2^(bits empruntes) = 2^2 = " & BRIGHT_YELLOW & "4 sous-reseaux" & RESET,
    "",
    BOLD & "Nombre d'hotes par sous-reseau :" & RESET,
    "  2^(bits hote) - 2 = 2^6 - 2 = " & BRIGHT_CYAN & "62 hotes" & RESET,
    "",
    BOLD & "Taille de bloc (increment) :" & RESET,
    "  256 - valeur du masque = 256 - 192 = " & BRIGHT_GREEN & "64" & RESET
  ]
  echo box(formulas, "FORMULES", YELLOW, 65)

  echo ""
  echo categoryHeader("Exemple: 192.168.1.0/24 divise en 4")

  let example = @[
    "  /24 " & ARROW_RIGHT & " /26 (emprunter 2 bits pour avoir 4 sous-reseaux)",
    "",
    "  Sous-reseau 1: 192.168.1." & BRIGHT_GREEN & "0" & RESET & "/26   (0-63)",
    "  Sous-reseau 2: 192.168.1." & BRIGHT_GREEN & "64" & RESET & "/26  (64-127)",
    "  Sous-reseau 3: 192.168.1." & BRIGHT_GREEN & "128" & RESET & "/26 (128-191)",
    "  Sous-reseau 4: 192.168.1." & BRIGHT_GREEN & "192" & RESET & "/26 (192-255)",
    "",
    "  Chaque sous-reseau: 62 hotes utilisables"
  ]
  echo box(example, "EXEMPLE", MAGENTA, 65)

  waitForEnter()


proc helpClasses*() =
  ## Aide sur les classes historiques
  clearScreen()
  echo banner()
  echo categoryHeader("Classes historiques (Classful)")

  let content = @[
    BOLD & "Avant CIDR, les adresses etaient divisees en classes :" & RESET,
    "",
    "  " & BRIGHT_GREEN & "Classe A" & RESET & ": 0.0.0.0   - 127.255.255.255",
    "            Premier bit: " & YELLOW & "0" & RESET & "xxxxxxx",
    "            Masque par defaut: /8 (255.0.0.0)",
    "",
    "  " & BRIGHT_CYAN & "Classe B" & RESET & ": 128.0.0.0 - 191.255.255.255",
    "            Premiers bits: " & YELLOW & "10" & RESET & "xxxxxx",
    "            Masque par defaut: /16 (255.255.0.0)",
    "",
    "  " & BRIGHT_YELLOW & "Classe C" & RESET & ": 192.0.0.0 - 223.255.255.255",
    "            Premiers bits: " & YELLOW & "110" & RESET & "xxxxx",
    "            Masque par defaut: /24 (255.255.255.0)",
    "",
    "  " & BRIGHT_MAGENTA & "Classe D" & RESET & ": 224.0.0.0 - 239.255.255.255 (Multicast)",
    "  " & DIM & "Classe E" & RESET & ": 240.0.0.0 - 255.255.255.255 (Experimental)"
  ]
  echo box(content, "", CYAN, 65)

  echo ""
  echo categoryHeader("Identification rapide")

  let quick = @[
    "  " & BOLD & "Premier octet    Classe    Masque defaut" & RESET,
    "  " & DIM & "--------------------------------------------" & RESET,
    "  1 - 126         A         /8  (255.0.0.0)",
    "  128 - 191       B         /16 (255.255.0.0)",
    "  192 - 223       C         /24 (255.255.255.0)",
    "  224 - 239       D         (Multicast)",
    "  240 - 255       E         (Reserve)",
    "",
    DIM & "Note: 127.x.x.x = Loopback (pas vraiment classe A)" & RESET
  ]
  echo box(quick, "MEMENTO", YELLOW, 65)

  waitForEnter()


# =============================================================================
# Menu d'aide principal
# =============================================================================

proc showHelpMenu*() =
  ## Affiche le menu d'aide
  while true:
    clearScreen()
    echo banner()
    echo categoryHeader("Centre d'aide")

    let topics = @[
      menuItem(1, "Validation d'adresses IP"),
      menuItem(2, "Classification (public, prive, etc.)"),
      menuItem(3, "Masques de sous-reseau"),
      menuItem(4, "Adresse reseau (calcul)"),
      menuItem(5, "Adresse broadcast (calcul)"),
      menuItem(6, "Appartenance a un reseau"),
      menuItem(7, "Subnetting (division)"),
      menuItem(8, "Classes historiques A, B, C"),
      "",
      menuItem(0, "Retour au menu principal")
    ]

    echo box(topics, "SUJETS", BRIGHT_CYAN, 55)
    echo ""

    let choice = prompt("Choisissez un sujet")

    case choice
    of "1": helpValidation()
    of "2": helpClassification()
    of "3": helpMasks()
    of "4": helpNetwork()
    of "5": helpBroadcast()
    of "6": helpBelonging()
    of "7": helpSubnetting()
    of "8": helpClasses()
    of "0", "q", "": break
    else:
      echo error("Choix invalide")
      waitForEnter()
