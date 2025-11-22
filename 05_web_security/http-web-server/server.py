#!/usr/bin/env python3
import socket
import signal
import sys
import threading
import config
import http_handler
from datetime import datetime
from typing import Optional


server_socket: Optional[socket.socket] = None


def shutdown_handler(signum, frame):
    print("\nArrêt du serveur...")
    if server_socket:
        server_socket.close()
    sys.exit(0)


def _accept_connections(local_server_socket):
    while True:
        try:
            client_socket, client_address = local_server_socket.accept()

            print(f"[{datetime.now().strftime('%H:%M:%S')}] Connexion de {client_address[0]}:{client_address[1]}")

            client_thread = threading.Thread(
                target=http_handler.handle_client,
                args=(client_socket,)
            )
            client_thread.daemon = True
            client_thread.start()

        except OSError:
            break
        except Exception as e:
            print(f"Erreur lors de l'acceptation de connexion: {e}")


def start_server():
    global server_socket

    # Logger le démarrage du serveur
    print(f"PyServ - Serveur HTTP Python")
    print(f"Démarrage sur {config.HOST}:{config.PORT}")
    print(f"Dossier public: {config.PUBLIC_DIR}")
    print("-" * 40)

    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((config.HOST, config.PORT))
        server_socket.listen(5)

        print(f"Serveur en écoute sur http://{config.HOST}:{config.PORT}")

        _accept_connections(server_socket)

    except KeyboardInterrupt:
        print("\nInterruption clavier détectée")
    except Exception as e:
        print(f"Erreur serveur: {e}")
    finally:
        if server_socket:
            server_socket.close()


if __name__ == "__main__":
    signal.signal(signal.SIGINT, shutdown_handler)

    try:
        start_server()
    except KeyboardInterrupt:
        print("\nArrêt du serveur par l'utilisateur")
    except Exception as e:
        print(f"Erreur fatale: {e}")
