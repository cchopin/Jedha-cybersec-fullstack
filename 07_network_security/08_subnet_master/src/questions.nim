# =============================================================================
# QUESTIONS - Generation et gestion des questions
# =============================================================================

import std/[random, strutils, sequtils, algorithm, tables]
import network, display, profile

# =============================================================================
# Types
# =============================================================================

type
  QuestionType* = enum
    YesNo           # Oui/Non
    MultipleChoice  # QCM a 4 choix
    FreeText        # Reponse libre

  Question* = object
    category*: string
    text*: string
    questionType*: QuestionType
    choices*: seq[string]
    correctAnswer*: string
    explanation*: string
    ip*: string
    prefix*: int


# =============================================================================
# Generateurs de questions par categorie
# =============================================================================

proc genValidationQuestion*(): Question =
  ## Genere une question de validation d'IP
  result.category = "validation"
  result.questionType = YesNo

  let isValid = rand(1) == 0
  if isValid:
    result.ip = randomIP()
    result.correctAnswer = "oui"
    result.explanation = "Cette IP est valide : 4 octets entre 0 et 255, separes par des points."
  else:
    result.ip = randomInvalidIP()
    result.correctAnswer = "non"
    # Determiner pourquoi c'est invalide
    let parts = result.ip.split('.')
    if parts.len < 4:
      result.explanation = "Invalide : seulement " & $parts.len & " octets (il en faut 4)."
    elif parts.len > 4:
      result.explanation = "Invalide : " & $parts.len & " octets (il en faut exactement 4)."
    else:
      for p in parts:
        try:
          let val = parseInt(p)
          if val > 255:
            result.explanation = "Invalide : l'octet '" & p & "' depasse 255."
            break
          elif val < 0:
            result.explanation = "Invalide : l'octet '" & p & "' est negatif."
            break
        except:
          result.explanation = "Invalide : '" & p & "' n'est pas un nombre."
          break

  result.text = "L'adresse IP suivante est-elle valide ?\n\n  " & highlight(result.ip) & "\n"
  result.choices = @["Oui", "Non"]


proc genClassificationQuestion*(): Question =
  ## Genere une question de classification (publique, privee, etc.)
  result.category = "classification"
  result.questionType = MultipleChoice

  # Choisir un type aleatoire
  let types = [Private, Public, Loopback, LinkLocal]
  let targetType = types[rand(types.len - 1)]

  result.ip = randomIP(targetType)
  let info = parseIP(result.ip)

  result.correctAnswer = $info.networkType
  result.text = "Quel est le type de cette adresse IP ?\n\n  " & highlight(result.ip) & "\n"

  # Generer les choix (incluant la bonne reponse)
  var choices = @[$Private, $Public, $Loopback, $LinkLocal]
  choices.shuffle()
  result.choices = choices

  # Explication
  case info.networkType
  of Private:
    if info.octets[0] == 10:
      result.explanation = "Plage privee 10.0.0.0/8 (classe A privee)."
    elif info.octets[0] == 172:
      result.explanation = "Plage privee 172.16.0.0/12 (classe B privee)."
    else:
      result.explanation = "Plage privee 192.168.0.0/16 (classe C privee)."
  of Public:
    result.explanation = "Cette IP n'appartient a aucune plage reservee, elle est donc publique."
  of Loopback:
    result.explanation = "Plage loopback 127.0.0.0/8, utilisee pour tester la pile TCP/IP locale."
  of LinkLocal:
    result.explanation = "Plage link-local 169.254.0.0/16 (APIPA), auto-configuree sans DHCP."
  else:
    result.explanation = "Type special."


proc genMaskQuestion*(): Question =
  ## Genere une question sur les masques
  result.category = "mask"

  let questionStyle = rand(1)
  result.prefix = 8 + rand(22)  # /8 a /30

  if questionStyle == 0:
    # Prefixe -> Masque decimal
    result.questionType = MultipleChoice
    result.text = "Quel est le masque de sous-reseau pour /" & $result.prefix & " ?\n"
    result.correctAnswer = maskToDecimal(result.prefix)

    var choices = @[result.correctAnswer]
    # Generer des masques proches mais faux
    for delta in [-2, -1, 1, 2]:
      let fakePrefix = result.prefix + delta
      if fakePrefix >= 8 and fakePrefix <= 30:
        let fakeMask = maskToDecimal(fakePrefix)
        if fakeMask notin choices:
          choices.add(fakeMask)
    choices.shuffle()
    result.choices = choices[0..min(3, choices.len-1)]

    result.explanation = "/" & $result.prefix & " signifie " & $result.prefix & " bits a 1, soit " & result.correctAnswer & "."

  else:
    # Masque decimal -> Prefixe
    result.questionType = MultipleChoice
    let mask = maskToDecimal(result.prefix)
    result.text = "Quel prefixe CIDR correspond au masque " & mask & " ?\n"
    result.correctAnswer = "/" & $result.prefix

    var choices = @[result.correctAnswer]
    for delta in [-2, -1, 1, 2]:
      let fakePrefix = result.prefix + delta
      if fakePrefix >= 8 and fakePrefix <= 30:
        choices.add("/" & $fakePrefix)
    choices = choices.deduplicate()
    choices.shuffle()
    result.choices = choices[0..min(3, choices.len-1)]

    result.explanation = mask & " a " & $result.prefix & " bits a 1, donc /" & $result.prefix & "."


proc genNetworkQuestion*(): Question =
  ## Genere une question sur l'adresse reseau
  result.category = "network"
  result.questionType = FreeText

  result.ip = randomIP()
  result.prefix = randomPrefix()
  let cidr = result.ip & "/" & $result.prefix
  let network = networkAddress(result.ip, result.prefix)

  result.text = "Quelle est l'adresse reseau pour " & highlight(cidr) & " ?\n"
  result.correctAnswer = network

  let mask = maskToDecimal(result.prefix)
  result.explanation = "Adresse reseau = IP AND Masque\n" &
                       "  " & result.ip & " AND " & mask & " = " & network & "\n" &
                       "  On conserve les " & $result.prefix & " premiers bits."


proc genBroadcastQuestion*(): Question =
  ## Genere une question sur l'adresse broadcast
  result.category = "broadcast"
  result.questionType = FreeText

  result.ip = randomIP()
  result.prefix = randomPrefix()
  let cidr = result.ip & "/" & $result.prefix
  let broadcast = broadcastAddress(result.ip, result.prefix)

  result.text = "Quelle est l'adresse de broadcast pour " & highlight(cidr) & " ?\n"
  result.correctAnswer = broadcast

  let network = networkAddress(result.ip, result.prefix)
  result.explanation = "Broadcast = Adresse reseau OR (NOT Masque)\n" &
                       "  On met tous les bits hotes a 1.\n" &
                       "  Reseau: " & network & " " & ARROW_RIGHT & " Broadcast: " & broadcast


proc genBelongingQuestion*(): Question =
  ## Genere une question d'appartenance a un reseau
  result.category = "belonging"
  result.questionType = YesNo

  # Generer un reseau
  let netIP = randomIP()
  result.prefix = randomPrefix()
  let network = networkAddress(netIP, result.prefix)
  let cidr = network & "/" & $result.prefix

  # 50% de chances que l'IP soit dans le reseau
  let isInNetwork = rand(1) == 0
  if isInNetwork:
    # Generer une IP dans le reseau
    let netStart = ipToUint32(network)
    let hostBits = 32 - result.prefix
    let maxOffset = (1'u32 shl hostBits) - 2  # Exclure reseau et broadcast
    let offset = uint32(rand(int(maxOffset) - 1)) + 1
    result.ip = uint32ToIP(netStart + offset)
    result.correctAnswer = "oui"
  else:
    # Generer une IP hors du reseau
    result.ip = randomIP()
    # S'assurer qu'elle n'est pas dans le reseau
    while isInNetwork(result.ip, cidr):
      result.ip = randomIP()
    result.correctAnswer = "non"

  result.text = "L'adresse " & highlight(result.ip) & " appartient-elle au reseau " & highlight(cidr) & " ?\n"
  result.choices = @["Oui", "Non"]

  let testNetwork = networkAddress(result.ip, result.prefix)
  if result.correctAnswer == "oui":
    result.explanation = "Oui ! " & result.ip & " AND masque = " & testNetwork & " = adresse reseau."
  else:
    result.explanation = "Non. " & result.ip & " AND masque = " & testNetwork & " != " & network & "."


proc genSubnettingQuestion*(): Question =
  ## Genere une question de subnetting
  result.category = "subnetting"
  result.questionType = MultipleChoice

  let questionStyle = rand(2)

  case questionStyle
  of 0:
    # Combien de sous-reseaux avec X bits empruntes
    let bitsBorrowed = 1 + rand(4)  # 1 a 5 bits
    let numSubnets = 1 shl bitsBorrowed

    result.text = "Combien de sous-reseaux peut-on creer en empruntant " &
                  highlight($bitsBorrowed & " bit(s)") & " ?\n"
    result.correctAnswer = $numSubnets

    var choices = @[result.correctAnswer]
    choices.add($(numSubnets div 2))
    choices.add($(numSubnets * 2))
    choices.add($(numSubnets + 2))
    choices = choices.deduplicate()
    choices.shuffle()
    result.choices = choices[0..min(3, choices.len-1)]

    result.explanation = "Avec " & $bitsBorrowed & " bit(s) emprunte(s): 2^" &
                         $bitsBorrowed & " = " & $numSubnets & " sous-reseaux."

  of 1:
    # Combien d'hotes avec un prefixe
    result.prefix = 20 + rand(10)  # /20 a /30
    let hosts = hostCount(result.prefix)

    result.text = "Combien d'hotes utilisables dans un reseau /" & $result.prefix & " ?\n"
    result.correctAnswer = $hosts

    var choices = @[result.correctAnswer]
    choices.add($(hosts + 2))  # Piege: oubli de soustraire 2
    choices.add($(hosts div 2))
    choices.add($(hosts * 2))
    choices = choices.deduplicate()
    choices.shuffle()
    result.choices = choices[0..min(3, choices.len-1)]

    let totalAddresses = 1 shl (32 - result.prefix)
    result.explanation = "2^" & $(32 - result.prefix) & " = " & $totalAddresses &
                         " adresses - 2 (reseau + broadcast) = " & $hosts & " hotes."

  else:
    # Quel prefixe pour N hotes
    let targetHosts = @[14, 30, 62, 126, 254, 510][rand(5)]
    var neededPrefix = 32
    for p in countdown(30, 8):
      if hostCount(p) >= targetHosts:
        neededPrefix = p
        break

    result.text = "Quel prefixe minimum pour avoir au moins " &
                  highlight($targetHosts & " hotes") & " ?\n"
    result.correctAnswer = "/" & $neededPrefix

    var choices = @[result.correctAnswer]
    for delta in [-2, -1, 1, 2]:
      let fakePrefix = neededPrefix + delta
      if fakePrefix >= 8 and fakePrefix <= 30:
        choices.add("/" & $fakePrefix)
    choices = choices.deduplicate()
    choices.shuffle()
    result.choices = choices[0..min(3, choices.len-1)]

    result.explanation = "/" & $neededPrefix & " donne " & $hostCount(neededPrefix) &
                         " hotes (2^" & $(32 - neededPrefix) & " - 2)."


proc genClassesQuestion*(): Question =
  ## Genere une question sur les classes historiques
  result.category = "classes"
  result.questionType = MultipleChoice

  let questionStyle = rand(1)

  if questionStyle == 0:
    # Quelle classe pour cette IP
    result.ip = randomIP()
    let info = parseIP(result.ip)

    result.text = "A quelle classe historique appartient " & highlight(result.ip) & " ?\n"
    result.correctAnswer = $info.networkClass

    result.choices = @["A", "B", "C", "D (Multicast)"]

    case info.networkClass
    of ClassA:
      result.explanation = "Classe A : premier octet 0-127 (1er bit a 0).\n" &
                           "  " & $info.octets[0] & " < 128, donc classe A."
    of ClassB:
      result.explanation = "Classe B : premier octet 128-191 (2 premiers bits: 10).\n" &
                           "  128 <= " & $info.octets[0] & " < 192, donc classe B."
    of ClassC:
      result.explanation = "Classe C : premier octet 192-223 (3 premiers bits: 110).\n" &
                           "  192 <= " & $info.octets[0] & " < 224, donc classe C."
    of ClassD:
      result.explanation = "Classe D (Multicast) : premier octet 224-239.\n" &
                           "  224 <= " & $info.octets[0] & " < 240, donc classe D."
    of ClassE:
      result.explanation = "Classe E (Experimental) : premier octet 240-255.\n" &
                           "  " & $info.octets[0] & " >= 240, donc classe E."

  else:
    # Quel masque par defaut pour cette classe
    let targetClass = [ClassA, ClassB, ClassC][rand(2)]
    case targetClass
    of ClassA:
      result.ip = $(rand(126)) & ".0.0.0"
      result.correctAnswer = "255.0.0.0"
    of ClassB:
      result.ip = $(128 + rand(63)) & ".0.0.0"
      result.correctAnswer = "255.255.0.0"
    else:
      result.ip = $(192 + rand(31)) & ".0.0.0"
      result.correctAnswer = "255.255.255.0"

    result.text = "Quel est le masque par defaut (classful) pour " & highlight(result.ip) & " ?\n"
    result.choices = @["255.0.0.0", "255.255.0.0", "255.255.255.0", "255.255.255.128"]

    case targetClass
    of ClassA:
      result.explanation = "Classe A : masque /8 par defaut = 255.0.0.0"
    of ClassB:
      result.explanation = "Classe B : masque /16 par defaut = 255.255.0.0"
    else:
      result.explanation = "Classe C : masque /24 par defaut = 255.255.255.0"


# =============================================================================
# Generation aleatoire par categorie
# =============================================================================

proc generateQuestion*(category: string): Question =
  ## Genere une question pour la categorie specifiee
  case category
  of "validation":
    return genValidationQuestion()
  of "classification":
    return genClassificationQuestion()
  of "mask":
    return genMaskQuestion()
  of "network":
    return genNetworkQuestion()
  of "broadcast":
    return genBroadcastQuestion()
  of "belonging":
    return genBelongingQuestion()
  of "subnetting":
    return genSubnettingQuestion()
  of "classes":
    return genClassesQuestion()
  else:
    return genValidationQuestion()


proc generateRandomQuestion*(): Question =
  ## Genere une question aleatoire
  let categories = CATEGORIES
  return generateQuestion(categories[rand(categories.len - 1)])


# =============================================================================
# Verification des reponses
# =============================================================================

proc normalizeAnswer*(answer: string): string =
  ## Normalise une reponse pour comparaison
  result = answer.strip().toLower()
  # Normaliser oui/non
  if result in ["o", "y", "yes", "oui", "1", "true", "vrai"]:
    result = "oui"
  elif result in ["n", "no", "non", "0", "false", "faux"]:
    result = "non"


proc checkAnswer*(question: Question, userAnswer: string): bool =
  ## Verifie si la reponse est correcte
  let normalized = normalizeAnswer(userAnswer)
  let expected = normalizeAnswer(question.correctAnswer)

  # Pour les QCM, accepter aussi le numero ou la premiere lettre
  if question.questionType == MultipleChoice:
    for i, choice in question.choices:
      if normalizeAnswer(choice) == expected:
        if normalized == $(i + 1) or normalized == choice[0..0].toLower():
          return true

  return normalized == expected


# =============================================================================
# Affichage des questions
# =============================================================================

proc displayQuestion*(question: Question, questionNum: int) =
  ## Affiche une question de maniere stylisee
  echo ""
  let catName = CATEGORY_NAMES.getOrDefault(question.category, question.category)
  echo categoryHeader(catName, DIAMOND)

  echo BRIGHT_WHITE & "Question " & $questionNum & RESET
  echo ""
  echo question.text
  echo ""

  case question.questionType
  of YesNo:
    echo DIM & "Repondez par " & RESET & BRIGHT_CYAN & "Oui" & RESET & DIM & " ou " & RESET & BRIGHT_CYAN & "Non" & RESET
  of MultipleChoice:
    for i, choice in question.choices:
      let marker = if normalizeAnswer(choice) == normalizeAnswer(question.correctAnswer):
        ""  # Ne pas reveler!
      else:
        ""
      echo "  " & BRIGHT_YELLOW & "[" & $(i + 1) & "]" & RESET & " " & choice
    echo ""
    echo DIM & "Entrez le numero ou la reponse" & RESET
  of FreeText:
    echo DIM & "Entrez votre reponse (ex: 192.168.1.0)" & RESET


proc askQuestion*(question: Question, questionNum: int): tuple[answer: string, correct: bool] =
  ## Pose une question et recupere la reponse
  displayQuestion(question, questionNum)
  echo ""

  var answer = ""
  while true:
    answer = prompt("Votre reponse")
    if answer.strip().len > 0:
      break
    # Reponse vide, redemander
    echo warning("Entrez une reponse (ou 'q' pour quitter)")

  let correct = checkAnswer(question, answer)

  return (answer, correct)
