# NetSpyC2

NetSpyC2 is a Python-based Command & Control (C2) server created for educational purposes, security research, and controlled laboratory environments.  
The project demonstrates how encrypted client-server communication, session management, and secure file transfer can be implemented at the application protocol level using Python.

NetSpyC2 does **not rely on external TLS stacks**. Instead, it implements its own cryptographic handshake and encrypted channel using modern primitives.

---

## Key Features

- Custom TCP-based C2 server
- Application-level handshake validation
- RSA 2048-bit key pair generated at runtime
- RSA-OAEP used for secure AES key exchange
- AES-GCM for authenticated, per-session encryption
- Multiple concurrent client sessions
- Interactive operator console
- Encrypted remote command execution
- Encrypted file upload and download
- SHA-256 integrity verification for file transfers
- Dynamic host and port rebinding
- Persistent logging to file and console

---

## Cryptographic Design

NetSpyC2 establishes secure communication in the following steps:

1. Client connects to the server via TCP.
2. Server sends an identification banner.
3. Client responds with a predefined handshake string.
4. Server sends its RSA public key to the client.
5. Client generates a random AES key and encrypts it using the server’s RSA public key.
6. Server decrypts the AES key using its private RSA key.
7. All further communication uses AES-GCM with a unique nonce per message.

Each connected client maintains its own independent encrypted session.

---

## Requirements

- Python 3.8 or higher
- `cryptography` Python package

Install dependencies:

```bash
pip install cryptography
```

---

## Running the Server

Start the C2 server:

```bash
python3 NetSpy2.py
```

Default configuration:

- Host: `0.0.0.0`
- Port: `4444`

The server generates a fresh RSA key pair at startup.

---

## Operator Console Commands

Available commands in the NetSpyC2 console:

- `help` – Display the help menu  
- `list` – List all active client sessions  
- `select <ID>` – Interact with a specific client  
- `info` – Display server logs  
- `rsa keys` – Show RSA public and private keys  
- `set host <HOST>` – Change listening host  
- `set port <PORT>` – Change listening port  
- `banner` – Display banner  
- `exit` – Shutdown server

Any unrecognized command is executed locally on the server.

---

## Client Session Commands

Inside a selected session:

- `get <file>` – Download file from client  
- `put <file>` – Upload file to client  
- Any other command is executed remotely on the client

All file transfers are encrypted and verified using SHA-256.

---

## Logging

Logs are written to:

```
NetSpyC2Server.log
```

---

## Project Structure

```
.
├── NetSpy2.py
├── banner.py
├── colores.py
├── NetSpyC2Server.log
└── README.md
```

---

## Intended Use

This project is intended for educational, research, and controlled lab use only.  
Unauthorized use against systems you do not own or have permission to test is prohibited.

---

## License

Creative Commons Attribution–NonCommercial–ShareAlike 4.0 International (CC BY-NC-SA 4.0)

You may modify and redistribute this project for non-commercial purposes only, provided that you preserve this license and give proper attribution.

---

## Disclaimer

This software is provided for educational and research purposes only.  
Use only on systems and networks you own or have explicit authorization.
# NetSpy
# NetSpy
