# =============================================================================
# PROFILE - Gestion du profil, XP, niveaux et badges
# =============================================================================

import std/[json, os, tables, strutils, times, algorithm]
import display

# =============================================================================
# Types
# =============================================================================

type
  CategoryRank* = enum
    Debutant = "Debutant"
    Apprenti = "Apprenti"
    Competent = "Competent"
    Expert = "Expert"
    Maitre = "Maitre"

  Badge* = object
    id*: string
    name*: string
    description*: string
    unlocked*: bool
    unlockedAt*: string  # Date ISO

  CategoryStats* = object
    answered*: int        ## Questions repondues
    correct*: int         ## Bonnes reponses
    rank*: CategoryRank   ## Rang dans cette categorie
    bestStreak*: int      ## Meilleure serie (interne, non affiche)

  Profile* = object
    name*: string
    xp*: int
    level*: int
    totalAnswered*: int
    totalCorrect*: int
    categories*: Table[string, CategoryStats]
    badges*: seq[Badge]
    createdAt*: string
    lastPlayedAt*: string


# =============================================================================
# Constantes
# =============================================================================

const
  XP_PER_LEVEL* = 100       ## XP necessaire par niveau
  XP_CORRECT* = 15          ## XP par bonne reponse
  XP_WRONG* = 3             ## XP par mauvaise reponse (encouragement)
  XP_PERFECT_BONUS* = 5     ## Bonus pour 5 bonnes reponses d'affilee

  # Seuils pour les rangs (pourcentage de bonnes reponses + minimum de questions)
  RANK_THRESHOLDS* = [
    (0, 0, Debutant),      # Moins de 5 questions
    (5, 50, Apprenti),     # 5+ questions, 50%+
    (15, 70, Competent),   # 15+ questions, 70%+
    (30, 85, Expert),      # 30+ questions, 85%+
    (50, 95, Maitre)       # 50+ questions, 95%+
  ]

  # Liste des categories
  CATEGORIES* = [
    "validation",    # L'IP est-elle valide ?
    "classification", # Publique, privee, etc.
    "mask",          # Calcul de masque
    "network",       # Adresse reseau
    "broadcast",     # Adresse broadcast
    "belonging",     # L'IP appartient-elle au reseau ?
    "subnetting",    # Division en sous-reseaux
    "classes"        # Classes historiques A, B, C
  ]

  CATEGORY_NAMES* = {
    "validation": "Validation d'IP",
    "classification": "Classification",
    "mask": "Masques de sous-reseau",
    "network": "Adresse reseau",
    "broadcast": "Adresse broadcast",
    "belonging": "Appartenance au reseau",
    "subnetting": "Division en sous-reseaux",
    "classes": "Classes historiques"
  }.toTable

  # Definition des badges
  BADGE_DEFINITIONS* = [
    ("first_answer", "Premiere reponse", "Repondre a votre premiere question"),
    ("perfect_10", "Sans faute x10", "10 bonnes reponses consecutives"),
    ("level_5", "Niveau 5", "Atteindre le niveau 5"),
    ("level_10", "Niveau 10", "Atteindre le niveau 10"),
    ("validation_master", "Maitre Validation", "Rang Maitre en Validation"),
    ("classification_master", "Maitre Classification", "Rang Maitre en Classification"),
    ("mask_master", "Maitre Masques", "Rang Maitre en Masques"),
    ("network_master", "Maitre Reseau", "Rang Maitre en Adresse reseau"),
    ("broadcast_master", "Maitre Broadcast", "Rang Maitre en Broadcast"),
    ("belonging_master", "Maitre Appartenance", "Rang Maitre en Appartenance"),
    ("subnetting_master", "Maitre Subnetting", "Rang Maitre en Subnetting"),
    ("classes_master", "Maitre Classes", "Rang Maitre en Classes"),
    ("all_categories", "Polyvalent", "Au moins Competent dans toutes les categories"),
    ("centurion", "Centurion", "100 questions repondues"),
    ("perfectionist", "Perfectionniste", "90% de bonnes reponses sur 50+ questions")
  ]


# =============================================================================
# Gestion du profil
# =============================================================================

proc getProfilePath(): string =
  ## Retourne le chemin du fichier profil
  let configDir = getConfigDir() / "subnetmaster"
  if not dirExists(configDir):
    createDir(configDir)
  return configDir / "profile.json"


proc newProfile*(name: string): Profile =
  ## Cree un nouveau profil
  result = Profile(
    name: name,
    xp: 0,
    level: 1,
    totalAnswered: 0,
    totalCorrect: 0,
    categories: initTable[string, CategoryStats](),
    badges: @[],
    createdAt: $now(),
    lastPlayedAt: $now()
  )

  # Initialiser les categories
  for cat in CATEGORIES:
    result.categories[cat] = CategoryStats(
      answered: 0,
      correct: 0,
      rank: Debutant,
      bestStreak: 0
    )

  # Initialiser les badges
  for (id, name, desc) in BADGE_DEFINITIONS:
    result.badges.add(Badge(
      id: id,
      name: name,
      description: desc,
      unlocked: false,
      unlockedAt: ""
    ))


proc saveProfile*(profile: Profile) =
  ## Sauvegarde le profil
  var j = %*{
    "name": profile.name,
    "xp": profile.xp,
    "level": profile.level,
    "totalAnswered": profile.totalAnswered,
    "totalCorrect": profile.totalCorrect,
    "createdAt": profile.createdAt,
    "lastPlayedAt": profile.lastPlayedAt,
    "categories": %*{},
    "badges": %*[]
  }

  for cat, stats in profile.categories:
    j["categories"][cat] = %*{
      "answered": stats.answered,
      "correct": stats.correct,
      "rank": $stats.rank,
      "bestStreak": stats.bestStreak
    }

  for badge in profile.badges:
    j["badges"].add(%*{
      "id": badge.id,
      "name": badge.name,
      "description": badge.description,
      "unlocked": badge.unlocked,
      "unlockedAt": badge.unlockedAt
    })

  writeFile(getProfilePath(), $j)


proc loadProfile*(): Profile =
  ## Charge le profil ou en cree un nouveau
  let path = getProfilePath()
  if not fileExists(path):
    return newProfile("Joueur")

  try:
    let j = parseJson(readFile(path))
    result = Profile(
      name: j["name"].getStr("Joueur"),
      xp: j["xp"].getInt(0),
      level: j["level"].getInt(1),
      totalAnswered: j["totalAnswered"].getInt(0),
      totalCorrect: j["totalCorrect"].getInt(0),
      createdAt: j["createdAt"].getStr($now()),
      lastPlayedAt: j["lastPlayedAt"].getStr($now()),
      categories: initTable[string, CategoryStats](),
      badges: @[]
    )

    # Charger les categories
    for cat in CATEGORIES:
      if j["categories"].hasKey(cat):
        let c = j["categories"][cat]
        result.categories[cat] = CategoryStats(
          answered: c["answered"].getInt(0),
          correct: c["correct"].getInt(0),
          rank: parseEnum[CategoryRank](c["rank"].getStr("Debutant")),
          bestStreak: c["bestStreak"].getInt(0)
        )
      else:
        result.categories[cat] = CategoryStats(rank: Debutant)

    # Charger les badges
    for badge in j["badges"]:
      result.badges.add(Badge(
        id: badge["id"].getStr(),
        name: badge["name"].getStr(),
        description: badge["description"].getStr(),
        unlocked: badge["unlocked"].getBool(false),
        unlockedAt: badge["unlockedAt"].getStr("")
      ))

    # Ajouter les badges manquants (nouvelles versions)
    for (id, name, desc) in BADGE_DEFINITIONS:
      var found = false
      for badge in result.badges:
        if badge.id == id:
          found = true
          break
      if not found:
        result.badges.add(Badge(id: id, name: name, description: desc))

  except:
    return newProfile("Joueur")


# =============================================================================
# Calculs de rang
# =============================================================================

proc calculateRank*(answered, correct: int): CategoryRank =
  ## Calcule le rang en fonction des stats
  if answered < 5:
    return Debutant

  let percentage = (correct * 100) div answered

  # Parcourir les seuils du plus haut au plus bas
  for i in countdown(RANK_THRESHOLDS.high, 0):
    let (minAnswered, minPercent, rank) = RANK_THRESHOLDS[i]
    if answered >= minAnswered and percentage >= minPercent:
      return rank

  return Debutant


proc rankColor*(rank: CategoryRank): string =
  ## Retourne la couleur associee au rang
  case rank
  of Debutant: return DIM
  of Apprenti: return GREEN
  of Competent: return CYAN
  of Expert: return BRIGHT_YELLOW
  of Maitre: return BRIGHT_MAGENTA


proc rankIcon*(rank: CategoryRank): string =
  ## Retourne l'icone associee au rang
  case rank
  of Debutant: return CIRCLE_EMPTY
  of Apprenti: return CIRCLE
  of Competent: return STAR_EMPTY
  of Expert: return STAR
  of Maitre: return DIAMOND


# =============================================================================
# Systeme d'XP et de niveau
# =============================================================================

proc xpForLevel*(level: int): int =
  ## XP necessaire pour atteindre un niveau
  return level * XP_PER_LEVEL


proc xpToNextLevel*(profile: Profile): int =
  ## XP restant pour le prochain niveau
  return xpForLevel(profile.level) - (profile.xp mod XP_PER_LEVEL)


proc xpInCurrentLevel*(profile: Profile): int =
  ## XP accumule dans le niveau actuel
  return profile.xp mod XP_PER_LEVEL


proc checkLevelUp*(profile: var Profile): bool =
  ## Verifie si le joueur monte de niveau
  let needed = xpForLevel(profile.level)
  let current = xpInCurrentLevel(profile)
  if current >= needed:
    profile.level += 1
    return true
  return false


# =============================================================================
# Systeme de badges
# =============================================================================

proc unlockBadge*(profile: var Profile, badgeId: string): bool =
  ## Debloque un badge et retourne true si c'etait nouveau
  for i, badge in profile.badges:
    if badge.id == badgeId and not badge.unlocked:
      profile.badges[i].unlocked = true
      profile.badges[i].unlockedAt = $now()
      return true
  return false


proc checkBadges*(profile: var Profile, currentStreak: int): seq[string] =
  ## Verifie et debloque les badges, retourne la liste des nouveaux badges
  var newBadges: seq[string] = @[]

  # Premier reponse
  if profile.totalAnswered >= 1:
    if profile.unlockBadge("first_answer"):
      newBadges.add("Premiere reponse")

  # 10 bonnes reponses consecutives
  if currentStreak >= 10:
    if profile.unlockBadge("perfect_10"):
      newBadges.add("Sans faute x10")

  # Niveaux
  if profile.level >= 5:
    if profile.unlockBadge("level_5"):
      newBadges.add("Niveau 5")
  if profile.level >= 10:
    if profile.unlockBadge("level_10"):
      newBadges.add("Niveau 10")

  # Maitrise par categorie
  let masterBadges = {
    "validation": "validation_master",
    "classification": "classification_master",
    "mask": "mask_master",
    "network": "network_master",
    "broadcast": "broadcast_master",
    "belonging": "belonging_master",
    "subnetting": "subnetting_master",
    "classes": "classes_master"
  }.toTable

  for cat, badgeId in masterBadges:
    if profile.categories[cat].rank == Maitre:
      if profile.unlockBadge(badgeId):
        newBadges.add("Maitre " & CATEGORY_NAMES[cat])

  # Polyvalent (Competent partout)
  var allCompetent = true
  for cat in CATEGORIES:
    if profile.categories[cat].rank < Competent:
      allCompetent = false
      break
  if allCompetent:
    if profile.unlockBadge("all_categories"):
      newBadges.add("Polyvalent")

  # Centurion (100 questions)
  if profile.totalAnswered >= 100:
    if profile.unlockBadge("centurion"):
      newBadges.add("Centurion")

  # Perfectionniste (90% sur 50+)
  if profile.totalAnswered >= 50:
    let percentage = (profile.totalCorrect * 100) div profile.totalAnswered
    if percentage >= 90:
      if profile.unlockBadge("perfectionist"):
        newBadges.add("Perfectionniste")

  return newBadges


# =============================================================================
# Mise a jour apres une reponse
# =============================================================================

proc recordAnswer*(profile: var Profile, category: string, correct: bool, currentStreak: int): tuple[xpGained: int, leveledUp: bool, newBadges: seq[string]] =
  ## Enregistre une reponse et retourne les recompenses
  profile.lastPlayedAt = $now()
  profile.totalAnswered += 1

  # XP de base
  var xpGained = if correct: XP_CORRECT else: XP_WRONG
  if correct:
    profile.totalCorrect += 1

    # Bonus pour serie
    if currentStreak > 0 and currentStreak mod 5 == 0:
      xpGained += XP_PERFECT_BONUS

  profile.xp += xpGained

  # Mise a jour de la categorie
  if profile.categories.hasKey(category):
    profile.categories[category].answered += 1
    if correct:
      profile.categories[category].correct += 1
    if currentStreak > profile.categories[category].bestStreak:
      profile.categories[category].bestStreak = currentStreak

    # Recalculer le rang
    let stats = profile.categories[category]
    profile.categories[category].rank = calculateRank(stats.answered, stats.correct)

  # Verifier le niveau
  let leveledUp = checkLevelUp(profile)

  # Verifier les badges
  let newBadges = checkBadges(profile, currentStreak)

  # Sauvegarder
  saveProfile(profile)

  return (xpGained, leveledUp, newBadges)


# =============================================================================
# Affichage du profil
# =============================================================================

proc displayProfile*(profile: Profile) =
  ## Affiche le profil complet
  clearScreen()
  echo banner()

  # En-tete du profil
  let percentage = if profile.totalAnswered > 0:
    (profile.totalCorrect * 100) div profile.totalAnswered
  else: 0

  var header = @[
    BOLD & BRIGHT_WHITE & profile.name & RESET,
    "",
    xpBar(xpInCurrentLevel(profile), xpForLevel(profile.level), profile.level),
    "",
    statLine("Questions", $profile.totalAnswered, BRIGHT_CYAN),
    statLine("Bonnes reponses", $profile.totalCorrect & " (" & $percentage & "%)", BRIGHT_GREEN)
  ]
  echo box(header, "PROFIL", BRIGHT_CYAN)

  # Classement par categorie
  echo categoryHeader("Classement par categorie")

  var catLines: seq[string] = @[]
  for cat in CATEGORIES:
    if profile.categories.hasKey(cat):
      let stats = profile.categories[cat]
      let pct = if stats.answered > 0: (stats.correct * 100) div stats.answered else: 0
      let rankStr = rankColor(stats.rank) & rankIcon(stats.rank) & " " & $stats.rank & RESET
      catLines.add(CATEGORY_NAMES[cat] & ": " & rankStr & DIM & " (" & $stats.correct & "/" & $stats.answered & ", " & $pct & "%)" & RESET)
  echo box(catLines, "", MAGENTA)

  # Badges
  echo categoryHeader("Badges")
  var badgeLines: seq[string] = @[]
  var unlockedCount = 0
  for badge in profile.badges:
    if badge.unlocked:
      unlockedCount += 1
      badgeLines.add(BRIGHT_YELLOW & STAR & " " & RESET & badge.name & DIM & " - " & badge.description & RESET)
  if badgeLines.len == 0:
    badgeLines.add(DIM & "Aucun badge debloque pour l'instant" & RESET)

  let badgeTitle = "Badges (" & $unlockedCount & "/" & $profile.badges.len & ")"
  echo box(badgeLines, badgeTitle, YELLOW)

  waitForEnter()


proc displayMiniProfile*(profile: Profile) =
  ## Affiche un mini profil (pour le menu)
  let percentage = if profile.totalAnswered > 0:
    (profile.totalCorrect * 100) div profile.totalAnswered
  else: 0

  echo ""
  echo "  " & BRIGHT_CYAN & profile.name & RESET & " | " & xpBar(xpInCurrentLevel(profile), xpForLevel(profile.level), profile.level)
  echo "  " & DIM & "Questions: " & RESET & $profile.totalAnswered & DIM & " | Reussite: " & RESET & $percentage & "%"
  echo ""
