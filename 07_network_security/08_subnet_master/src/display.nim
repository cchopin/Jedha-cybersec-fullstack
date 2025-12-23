# =============================================================================
# DISPLAY - Interface utilisateur avec couleurs et style
# =============================================================================

import std/[strutils, terminal]

# =============================================================================
# Couleurs ANSI
# =============================================================================

const
  # Reset
  RESET* = "\e[0m"

  # Styles
  BOLD* = "\e[1m"
  DIM* = "\e[2m"
  ITALIC* = "\e[3m"
  UNDERLINE* = "\e[4m"

  # Couleurs de texte
  BLACK* = "\e[30m"
  RED* = "\e[31m"
  GREEN* = "\e[32m"
  YELLOW* = "\e[33m"
  BLUE* = "\e[34m"
  MAGENTA* = "\e[35m"
  CYAN* = "\e[36m"
  WHITE* = "\e[37m"

  # Couleurs vives
  BRIGHT_RED* = "\e[91m"
  BRIGHT_GREEN* = "\e[92m"
  BRIGHT_YELLOW* = "\e[93m"
  BRIGHT_BLUE* = "\e[94m"
  BRIGHT_MAGENTA* = "\e[95m"
  BRIGHT_CYAN* = "\e[96m"
  BRIGHT_WHITE* = "\e[97m"

  # Fond
  BG_RED* = "\e[41m"
  BG_GREEN* = "\e[42m"
  BG_YELLOW* = "\e[43m"
  BG_BLUE* = "\e[44m"
  BG_MAGENTA* = "\e[45m"
  BG_CYAN* = "\e[46m"

# =============================================================================
# Caracteres de dessin (Box Drawing)
# =============================================================================

const
  # Coins
  TOP_LEFT* = "╭"
  TOP_RIGHT* = "╮"
  BOTTOM_LEFT* = "╰"
  BOTTOM_RIGHT* = "╯"

  # Lignes
  HORIZONTAL* = "─"
  VERTICAL* = "│"

  # Jonctions
  T_DOWN* = "┬"
  T_UP* = "┴"
  T_RIGHT* = "├"
  T_LEFT* = "┤"
  CROSS* = "┼"

  # Double ligne
  D_HORIZONTAL* = "═"
  D_VERTICAL* = "║"
  D_TOP_LEFT* = "╔"
  D_TOP_RIGHT* = "╗"
  D_BOTTOM_LEFT* = "╚"
  D_BOTTOM_RIGHT* = "╝"

  # Symboles
  CHECK* = "✓"
  CROSS_MARK* = "✗"
  STAR* = "★"
  STAR_EMPTY* = "☆"
  ARROW_RIGHT* = "→"
  ARROW_LEFT* = "←"
  BULLET* = "•"
  DIAMOND* = "◆"
  CIRCLE* = "●"
  CIRCLE_EMPTY* = "○"


# =============================================================================
# Fonctions d'affichage
# =============================================================================

proc clearScreen*() =
  ## Efface l'ecran
  stdout.write("\e[2J\e[H")


proc moveCursor*(row, col: int) =
  ## Deplace le curseur
  stdout.write("\e[" & $row & ";" & $col & "H")


proc hideCursor*() =
  stdout.write("\e[?25l")


proc showCursor*() =
  stdout.write("\e[?25h")


# =============================================================================
# Helpers de couleur
# =============================================================================

proc colored*(text: string, color: string): string =
  ## Colore un texte
  return color & text & RESET


proc bold*(text: string): string =
  ## Met en gras
  return BOLD & text & RESET


proc success*(text: string): string =
  ## Texte vert (succes)
  return BRIGHT_GREEN & text & RESET


proc error*(text: string): string =
  ## Texte rouge (erreur)
  return BRIGHT_RED & text & RESET


proc warning*(text: string): string =
  ## Texte jaune (avertissement)
  return BRIGHT_YELLOW & text & RESET


proc info*(text: string): string =
  ## Texte cyan (info)
  return BRIGHT_CYAN & text & RESET


proc highlight*(text: string): string =
  ## Texte magenta (mise en valeur)
  return BRIGHT_MAGENTA & BOLD & text & RESET


proc dim*(text: string): string =
  ## Texte attenue
  return DIM & text & RESET


# =============================================================================
# Boites et cadres
# =============================================================================

proc horizontalLine*(width: int, color: string = ""): string =
  ## Ligne horizontale
  result = color
  for i in 0..<width:
    result.add(HORIZONTAL)
  if color != "":
    result.add(RESET)


proc box*(content: seq[string], title: string = "", color: string = CYAN, width: int = 60): string =
  ## Cree une boite autour du contenu
  var maxLen = width - 4
  for line in content:
    let cleanLen = line.replace(RESET, "").replace(BOLD, "")
                       .replace(RED, "").replace(GREEN, "")
                       .replace(YELLOW, "").replace(BLUE, "")
                       .replace(CYAN, "").replace(MAGENTA, "")
                       .replace(BRIGHT_RED, "").replace(BRIGHT_GREEN, "")
                       .replace(BRIGHT_YELLOW, "").replace(BRIGHT_BLUE, "")
                       .replace(BRIGHT_CYAN, "").replace(BRIGHT_MAGENTA, "")
                       .replace(DIM, "").len
    if cleanLen > maxLen:
      maxLen = cleanLen

  let innerWidth = maxLen + 2

  # Ligne du haut avec titre
  result = color & TOP_LEFT
  if title != "":
    let titleLen = title.len
    let leftPad = (innerWidth - titleLen - 2) div 2
    let rightPad = innerWidth - titleLen - 2 - leftPad
    for i in 0..<leftPad:
      result.add(HORIZONTAL)
    result.add(" " & RESET & BOLD & title & RESET & color & " ")
    for i in 0..<rightPad:
      result.add(HORIZONTAL)
  else:
    for i in 0..<innerWidth:
      result.add(HORIZONTAL)
  result.add(TOP_RIGHT & RESET & "\n")

  # Contenu
  for line in content:
    result.add(color & VERTICAL & RESET & " " & line)
    # Calculer le padding (approximatif car codes ANSI)
    var cleanLen = 0
    var inEscape = false
    for c in line:
      if c == '\e':
        inEscape = true
      elif inEscape and c == 'm':
        inEscape = false
      elif not inEscape:
        cleanLen += 1
    let padding = innerWidth - cleanLen - 1
    for i in 0..<padding:
      result.add(" ")
    result.add(color & VERTICAL & RESET & "\n")

  # Ligne du bas
  result.add(color & BOTTOM_LEFT)
  for i in 0..<innerWidth:
    result.add(HORIZONTAL)
  result.add(BOTTOM_RIGHT & RESET)


proc doubleBox*(content: seq[string], title: string = "", color: string = YELLOW, width: int = 60): string =
  ## Cree une boite double (plus visible)
  var maxLen = width - 4
  for line in content:
    var cleanLen = 0
    var inEscape = false
    for c in line:
      if c == '\e':
        inEscape = true
      elif inEscape and c == 'm':
        inEscape = false
      elif not inEscape:
        cleanLen += 1
    if cleanLen > maxLen:
      maxLen = cleanLen

  let innerWidth = maxLen + 2

  # Ligne du haut
  result = color & D_TOP_LEFT
  if title != "":
    let titleLen = title.len
    let leftPad = (innerWidth - titleLen - 2) div 2
    let rightPad = innerWidth - titleLen - 2 - leftPad
    for i in 0..<leftPad:
      result.add(D_HORIZONTAL)
    result.add(" " & RESET & BOLD & color & title & RESET & color & " ")
    for i in 0..<rightPad:
      result.add(D_HORIZONTAL)
  else:
    for i in 0..<innerWidth:
      result.add(D_HORIZONTAL)
  result.add(D_TOP_RIGHT & RESET & "\n")

  # Contenu
  for line in content:
    result.add(color & D_VERTICAL & RESET & " " & line)
    var cleanLen = 0
    var inEscape = false
    for c in line:
      if c == '\e':
        inEscape = true
      elif inEscape and c == 'm':
        inEscape = false
      elif not inEscape:
        cleanLen += 1
    let padding = innerWidth - cleanLen - 1
    for i in 0..<padding:
      result.add(" ")
    result.add(color & D_VERTICAL & RESET & "\n")

  # Ligne du bas
  result.add(color & D_BOTTOM_LEFT)
  for i in 0..<innerWidth:
    result.add(D_HORIZONTAL)
  result.add(D_BOTTOM_RIGHT & RESET)


# =============================================================================
# Barres de progression
# =============================================================================

proc progressBar*(current, total: int, width: int = 30,
                  fillChar: string = "█", emptyChar: string = "░",
                  color: string = GREEN): string =
  ## Barre de progression
  let percentage = if total > 0: (current * 100) div total else: 0
  let filled = (current * width) div total
  let empty = width - filled

  result = color
  for i in 0..<filled:
    result.add(fillChar)
  result.add(DIM)
  for i in 0..<empty:
    result.add(emptyChar)
  result.add(RESET & " " & $percentage & "%")


proc xpBar*(current, max: int, level: int): string =
  ## Barre d'XP stylisee
  let percentage = if max > 0: (current * 100) div max else: 0
  let barWidth = 25
  let filled = (current * barWidth) div max

  result = BRIGHT_YELLOW & "Lv." & $level & " " & RESET
  result.add(YELLOW & "[" & RESET)
  result.add(BRIGHT_YELLOW)
  for i in 0..<filled:
    result.add("▰")
  result.add(DIM)
  for i in 0..<(barWidth - filled):
    result.add("▱")
  result.add(RESET & YELLOW & "]" & RESET)
  result.add(" " & $current & "/" & $max & " XP")


# =============================================================================
# Elements de menu
# =============================================================================

proc menuItem*(index: int, text: string, selected: bool = false): string =
  ## Element de menu
  if selected:
    result = BRIGHT_CYAN & BOLD & " " & ARROW_RIGHT & " "
    result.add("[" & $index & "] " & text & RESET)
  else:
    result = "   [" & BRIGHT_YELLOW & $index & RESET & "] " & text


proc menuHeader*(text: string): string =
  ## En-tete de menu
  result = "\n" & BOLD & BRIGHT_MAGENTA & "  " & DIAMOND & " " & text & RESET & "\n"


# =============================================================================
# Affichage des resultats
# =============================================================================

proc showCorrect*(message: string = "Bonne reponse !") =
  ## Affiche un message de reussite
  echo ""
  echo BRIGHT_GREEN & BOLD & "  " & CHECK & " " & message & RESET
  echo ""


proc showIncorrect*(message: string, explanation: string = "") =
  ## Affiche un message d'erreur avec explication
  echo ""
  echo BRIGHT_RED & BOLD & "  " & CROSS_MARK & " " & message & RESET
  if explanation != "":
    echo ""
    echo YELLOW & "  " & ARROW_RIGHT & " Explication: " & RESET & explanation
  echo ""


proc showInfo*(message: string) =
  ## Affiche un message d'information
  echo BRIGHT_CYAN & "  " & BULLET & " " & RESET & message


proc showWarning*(message: string) =
  ## Affiche un avertissement
  echo BRIGHT_YELLOW & "  " & BULLET & " " & RESET & message


# =============================================================================
# En-tetes et bannieres
# =============================================================================

proc banner*(): string =
  ## Banniere du jeu
  result = BRIGHT_CYAN & """
   ____        _                _   __  __           _
  / ___| _   _| |__  _ __   ___| |_|  \/  | __ _ ___| |_ ___ _ __
  \___ \| | | | '_ \| '_ \ / _ \ __| |\/| |/ _` / __| __/ _ \ '__|
   ___) | |_| | |_) | | | |  __/ |_| |  | | (_| \__ \ ||  __/ |
  |____/ \__,_|_.__/|_| |_|\___|\__|_|  |_|\__,_|___/\__\___|_|
""" & RESET
  result.add(DIM & "                    Maitriser IPv4 avec style !" & RESET & "\n")


proc categoryHeader*(name: string, icon: string = STAR): string =
  ## En-tete de categorie
  result = "\n" & BRIGHT_MAGENTA & BOLD
  result.add("  " & icon & " " & name & " " & icon)
  result.add(RESET & "\n")
  result.add(MAGENTA & "  " & horizontalLine(name.len + 6) & RESET & "\n")


# =============================================================================
# Stats et scores
# =============================================================================

proc statLine*(label: string, value: string, color: string = BRIGHT_WHITE): string =
  ## Ligne de statistique
  result = "  " & DIM & label & ": " & RESET & color & value & RESET


proc rankDisplay*(rank: string, color: string): string =
  ## Affiche un rang avec style
  result = color & BOLD & "[" & rank & "]" & RESET


proc badgeDisplay*(name: string, unlocked: bool = true): string =
  ## Affiche un badge
  if unlocked:
    result = BRIGHT_YELLOW & STAR & " " & RESET & name
  else:
    result = DIM & STAR_EMPTY & " " & name & RESET


# =============================================================================
# Input stylise
# =============================================================================

proc prompt*(message: string): string =
  ## Demande une entree utilisateur
  stdout.write(BRIGHT_CYAN & message & RESET & " " & ARROW_RIGHT & " ")
  stdout.flushFile()
  result = stdin.readLine()


proc promptChoice*(message: string, choices: seq[string]): int =
  ## Demande un choix parmi plusieurs options
  echo ""
  echo BRIGHT_CYAN & message & RESET
  for i, choice in choices:
    echo menuItem(i + 1, choice)
  echo ""
  stdout.write(YELLOW & "Votre choix: " & RESET)
  stdout.flushFile()
  try:
    result = parseInt(stdin.readLine()) - 1
    if result < 0 or result >= choices.len:
      result = -1
  except:
    result = -1


proc waitForEnter*(message: string = "Appuyez sur Entree pour continuer...") =
  ## Attend que l'utilisateur appuie sur Entree
  echo ""
  stdout.write(DIM & message & RESET)
  stdout.flushFile()
  discard stdin.readLine()
