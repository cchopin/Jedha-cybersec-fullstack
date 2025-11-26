#!/usr/bin/python3
import os

HOST = "0.0.0.0"
PORT = 8443  # Port HTTPS pour le développement (443 nécessite root)
PUBLIC_DIR = "public"

# Configuration SSL/TLS
CERT_FILE = os.path.join(os.path.dirname(__file__), "cert.pem")
KEY_FILE = os.path.join(os.path.dirname(__file__), "key.pem")


HTTP_STATUS = {
    200: {
        "status": "OK",
        "message": "Requête traitée avec succès",
        "colors": ('#2ed573', '#20bf6b')
    },
    400: {
        "status": "Bad Request",
        "message": "La requête est malformée ou contient des données invalides.",
        "colors": ('#ffa502', '#ff7f00')
    },
    401: {
        "status": "Unauthorized",
        "message": "Une authentification est requise pour accéder à cette ressource.",
        "colors": ('#ff9f43', '#ee8c35')
    },
    403: {
        "status": "Forbidden",
        "message": "L'accès à cette ressource est interdit.",
        "colors": ('#ff4757', '#ff3344')
    },
    404: {
        "status": "Not Found",
        "message": "La ressource demandée n'a pas été trouvée sur ce serveur.",
        "colors": ('#ff6b6b', '#ee5a5a')
    },
    405: {
        "status": "Method Not Allowed",
        "message": "La méthode HTTP utilisée n'est pas autorisée pour cette ressource.",
        "colors": ('#ff6348', '#ff5030')
    },
    500: {
        "status": "Internal Server Error",
        "message": "Le serveur a rencontré une erreur interne lors du traitement de la requête.",
        "colors": ('#7b2cbf', '#5a1a9e')
    },
    502: {
        "status": "Bad Gateway",
        "message": "Le serveur a reçu une réponse invalide du serveur en amont.",
        "colors": ('#5f27cd', '#4a1fa8')
    },
    503: {
        "status": "Service Unavailable",
        "message": "Le service est temporairement indisponible.",
        "colors": ('#341f97', '#2c1a7a')
    }
}

http_code = {code: data["status"] for code, data in HTTP_STATUS.items()}

MIME_type = {
    ".html": "text/html",
    ".css": "text/css",
    ".js": "application/javascript",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".gif": "image/gif",
    ".txt": "application/octet-stream"
}
