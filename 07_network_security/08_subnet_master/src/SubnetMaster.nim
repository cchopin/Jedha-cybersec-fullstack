# =============================================================================
# SUBNET MASTER - Application d'entrainement au reseau IPv4
# =============================================================================
#
# Un outil interactif pour maitriser les concepts de sous-reseau IPv4 :
# - 8 categories de questions
# - Systeme de progression avec XP et niveaux
# - Badges et achievements
# - Classement par categorie
#
# Compilation : nim c -d:release SubnetMaster.nim
#
# =============================================================================

import std/[random, strutils, os, sequtils, tables]
import display, network, profile, questions, help

# =============================================================================
# Configuration
# =============================================================================

const
  VERSION = "1.0.0"
  QUESTIONS_PER_SESSION = 10


# =============================================================================
# Variables globales
# =============================================================================

var
  currentProfile: Profile
  currentStreak: int = 0


# =============================================================================
# Menu principal
# =============================================================================

proc showMainMenu() =
  ## Affiche le menu principal
  clearScreen()
  echo banner()
  displayMiniProfile(currentProfile)

  let menuItems = @[
    "Entrainement libre (toutes categories)",
    "Entrainement par categorie",
    "Aide & Tutoriels",
    "Voir mon profil",
    "Changer de nom",
    "Quitter"
  ]

  echo box(menuItems.mapIt(menuItem(menuItems.find(it) + 1, it)), "MENU PRINCIPAL", BRIGHT_CYAN)


proc showCategoryMenu(): string =
  ## Affiche le menu de selection de categorie
  clearScreen()
  echo banner()

  var lines: seq[string] = @[]
  for i, cat in CATEGORIES:
    let stats = currentProfile.categories.getOrDefault(cat, CategoryStats())
    let rankStr = rankColor(stats.rank) & rankIcon(stats.rank) & " " & $stats.rank & RESET
    let catName = CATEGORY_NAMES.getOrDefault(cat, cat)
    lines.add(menuItem(i + 1, catName & " " & DIM & "[" & RESET & rankStr & DIM & "]" & RESET))

  lines.add("")
  lines.add(menuItem(9, "Retour au menu principal"))

  echo box(lines, "CATEGORIES", BRIGHT_MAGENTA)
  echo ""

  let choice = prompt("Choisissez une categorie")
  try:
    let idx = parseInt(choice) - 1
    if idx >= 0 and idx < CATEGORIES.len:
      return CATEGORIES[idx]
  except:
    discard

  return ""


# =============================================================================
# Session d'entrainement
# =============================================================================

proc displaySessionHeader(questionNum, total, correct, streak, xp: int, category: string) =
  ## Affiche le bandeau de stats en haut
  let pct = if questionNum > 1: (correct * 100) div (questionNum - 1) else: 0
  let pctColor = if pct >= 70: BRIGHT_GREEN elif pct >= 50: YELLOW else: RED

  # Barre de progression style niveau
  let barWidth = 15
  let filled = ((questionNum - 1) * barWidth) div total
  var progressBar = BRIGHT_CYAN
  for i in 0..<barWidth:
    if i < filled:
      progressBar.add("▰")
    else:
      progressBar.add(DIM & "▱" & BRIGHT_CYAN)
  progressBar.add(RESET)

  echo ""
  echo CYAN & "  ╭" & HORIZONTAL.repeat(66) & "╮" & RESET
  echo CYAN & "  │" & RESET &
       "  " & BRIGHT_WHITE & BOLD & "Q" & $questionNum & "/" & $total & RESET &
       "  " & progressBar &
       "   " & DIM & "Score:" & RESET & BRIGHT_GREEN & $correct & "/" & $(questionNum-1) & RESET &
       "   " & DIM & "Taux:" & RESET & pctColor & $pct & "%" & RESET &
       "   " & DIM & "Serie:" & RESET & BRIGHT_YELLOW & $streak & RESET &
       "   " & DIM & "XP:" & RESET & BRIGHT_MAGENTA & "+" & $xp & RESET
  echo CYAN & "  ╰" & HORIZONTAL.repeat(66) & "╯" & RESET
  echo ""


proc runTrainingSession(category: string = "") =
  ## Lance une session d'entrainement
  clearScreen()
  echo banner()

  let sessionCategory = if category == "": "Toutes categories" else: CATEGORY_NAMES.getOrDefault(category, category)
  echo categoryHeader("Session: " & sessionCategory)
  echo ""
  echo info("Repondez a " & $QUESTIONS_PER_SESSION & " questions.")
  echo info("Tapez 'q' pour quitter la session.")
  echo ""
  waitForEnter("Appuyez sur Entree pour commencer...")

  var sessionCorrect = 0
  var sessionTotal = 0
  var sessionXP = 0

  for i in 1..QUESTIONS_PER_SESSION:
    clearScreen()

    # Afficher le bandeau de stats
    displaySessionHeader(i, QUESTIONS_PER_SESSION, sessionCorrect, currentStreak, sessionXP, category)

    # Generer la question
    let question = if category == "":
      generateRandomQuestion()
    else:
      generateQuestion(category)

    # Afficher la categorie et question
    let catName = CATEGORY_NAMES.getOrDefault(question.category, question.category)
    echo BRIGHT_MAGENTA & BOLD & "  " & DIAMOND & " " & catName & RESET
    echo MAGENTA & "  " & HORIZONTAL.repeat(catName.len + 4) & RESET
    echo ""
    echo "  " & question.text.replace("\n", "\n  ")

    # Afficher les choix si QCM
    case question.questionType
    of YesNo:
      echo ""
      echo DIM & "  Repondez par " & RESET & BRIGHT_CYAN & "Oui" & RESET & DIM & " ou " & RESET & BRIGHT_CYAN & "Non" & RESET
    of MultipleChoice:
      echo ""
      for j, choice in question.choices:
        echo "    " & BRIGHT_YELLOW & "[" & $(j + 1) & "]" & RESET & " " & choice
      echo ""
      echo DIM & "  Entrez le numero ou la reponse" & RESET
    of FreeText:
      echo ""
      echo DIM & "  Entrez votre reponse (ex: 192.168.1.0)" & RESET

    echo ""

    # Demander la reponse
    var answer = ""
    while true:
      answer = prompt("  Votre reponse")
      if answer.strip().len > 0:
        break
      echo warning("  Entrez une reponse (ou 'q' pour quitter)")

    let correct = checkAnswer(question, answer)

    if answer.toLower() == "q":
      echo ""
      echo warning("Session interrompue.")
      waitForEnter()
      break

    sessionTotal += 1

    # Calculer XP gagne
    var xpGained = if correct: XP_CORRECT else: XP_WRONG

    # Traiter la reponse
    if correct:
      sessionCorrect += 1
      currentStreak += 1

      if currentStreak > 0 and currentStreak mod 5 == 0:
        xpGained += XP_PERFECT_BONUS
        showCorrect("Bravo ! +" & $XP_CORRECT & " XP + " & $XP_PERFECT_BONUS & " bonus serie!")
        echo BRIGHT_YELLOW & "  " & STAR & " Serie de " & $currentStreak & " ! " & STAR & RESET
      else:
        showCorrect("Bravo ! +" & $XP_CORRECT & " XP")
    else:
      currentStreak = 0
      showIncorrect("Mauvaise reponse. +" & $XP_WRONG & " XP", question.explanation)
      echo ""
      echo "  " & DIM & "Bonne reponse: " & RESET & BRIGHT_GREEN & question.correctAnswer & RESET

    sessionXP += xpGained

    # Enregistrer la reponse
    let (_, leveledUp, newBadges) = recordAnswer(
      currentProfile,
      question.category,
      correct,
      currentStreak
    )

    # Notifications
    if leveledUp:
      echo ""
      echo BRIGHT_YELLOW & BOLD & "  " & STAR & " NIVEAU " & $currentProfile.level & " ATTEINT ! " & STAR & RESET

    for badge in newBadges:
      echo ""
      echo BRIGHT_MAGENTA & "  " & DIAMOND & " Nouveau badge : " & badge & " " & DIAMOND & RESET

    # Toujours attendre avant de passer a la suite (y compris derniere question)
    if i < QUESTIONS_PER_SESSION:
      waitForEnter()
    else:
      waitForEnter("Appuyez sur Entree pour voir les resultats...")

  # Resume de session
  clearScreen()
  echo banner()
  echo categoryHeader("Fin de session")

  let percentage = if sessionTotal > 0: (sessionCorrect * 100) div sessionTotal else: 0

  var summaryLines = @[
    "",
    "Questions repondues: " & BRIGHT_CYAN & $sessionTotal & RESET,
    "Bonnes reponses: " & BRIGHT_GREEN & $sessionCorrect & RESET,
    "Taux de reussite: " & (if percentage >= 80: BRIGHT_GREEN elif percentage >= 50: YELLOW else: RED) & $percentage & "%" & RESET,
    "XP gagne: " & BRIGHT_MAGENTA & "+" & $sessionXP & RESET,
    ""
  ]

  if percentage == 100:
    summaryLines.add(BRIGHT_YELLOW & STAR & " PARFAIT ! " & STAR & RESET)
  elif percentage >= 80:
    summaryLines.add(BRIGHT_GREEN & "Excellent travail !" & RESET)
  elif percentage >= 50:
    summaryLines.add(YELLOW & "Pas mal, continuez a vous entrainer !" & RESET)
  else:
    summaryLines.add(RED & "Revoyez les bases et reessayez !" & RESET)

  echo doubleBox(summaryLines, "RESULTATS", BRIGHT_YELLOW)
  waitForEnter()


# =============================================================================
# Gestion du profil
# =============================================================================

proc changeName() =
  ## Change le nom du joueur
  clearScreen()
  echo banner()
  echo categoryHeader("Changer de nom")

  echo "  Nom actuel: " & BRIGHT_CYAN & currentProfile.name & RESET
  echo ""
  let newName = prompt("Nouveau nom")

  if newName.strip().len > 0:
    currentProfile.name = newName.strip()
    saveProfile(currentProfile)
    echo ""
    echo success("Nom change en '" & currentProfile.name & "'")
  else:
    echo ""
    echo warning("Nom inchange.")

  waitForEnter()


# =============================================================================
# Programme principal
# =============================================================================

proc main() =
  # Initialiser le generateur aleatoire
  randomize()

  # Charger le profil
  currentProfile = loadProfile()

  # Si nouveau joueur, demander le nom
  if currentProfile.totalAnswered == 0 and currentProfile.name == "Joueur":
    clearScreen()
    echo banner()
    echo ""
    echo box(@[
      "",
      BRIGHT_WHITE & "Bienvenue dans SubnetMaster !" & RESET,
      "",
      "Maitrisez l'adressage IPv4 en vous entrainant",
      "sur 8 categories de questions.",
      "",
      "Gagnez de l'XP, montez de niveau,",
      "et debloquez des badges !",
      ""
    ], "BIENVENUE", BRIGHT_CYAN)
    echo ""
    let name = prompt("Entrez votre nom")
    if name.strip().len > 0:
      currentProfile.name = name.strip()
      saveProfile(currentProfile)

  # Boucle principale
  while true:
    showMainMenu()
    echo ""
    let choice = prompt("Votre choix")

    case choice
    of "1":
      runTrainingSession()
    of "2":
      let category = showCategoryMenu()
      if category != "":
        runTrainingSession(category)
    of "3":
      showHelpMenu()
    of "4":
      displayProfile(currentProfile)
    of "5":
      changeName()
    of "6", "q", "quit", "exit":
      clearScreen()
      echo banner()
      echo ""
      echo box(@[
        "",
        "Merci d'avoir joue a SubnetMaster !",
        "",
        "XP total: " & BRIGHT_YELLOW & $currentProfile.xp & RESET,
        "Niveau: " & BRIGHT_CYAN & $currentProfile.level & RESET,
        "",
        DIM & "A bientot !" & RESET,
        ""
      ], "AU REVOIR", BRIGHT_MAGENTA)
      echo ""
      break
    else:
      echo ""
      echo error("Choix invalide.")
      waitForEnter()


when isMainModule:
  main()
