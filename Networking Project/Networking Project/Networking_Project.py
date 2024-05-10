import socket
import json
import time
import ipaddress
from datetime import datetime
from threading import Thread, Lock
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.serialization import load_pem_public_key, PublicFormat, Encoding
from cryptography.hazmat.backends import default_backend
from os import urandom

# Global variables
peer_dictionary = {}
peer_lock = Lock()
log_file_path = "chat_history.log"

# Helper functions
def log_message(action, username, ip, message, secure):
    with open(log_file_path, 'a') as file:
        file.write(f"{datetime.now()} - {action} - {username} ({ip}) - {'Encrypted' if secure else 'Unencrypted'}: {message}\n")

def generate_dh_parameters():
    return dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())

def generate_dh_keys(parameters):
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

def get_local_ip():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]

def get_broadcast_address(ip, subnet_mask):
    network = ipaddress.ip_network(f"{ip}/{subnet_mask}", strict=False)
    return str(network.broadcast_address)

def serialize_public_key(public_key):
    try:
        serialized_key = public_key.public_bytes(encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo)
        return serialized_key
    except Exception as e:
        print(f"Failed to serialize public key: {e}")
        return None

def deserialize_public_key(peer_public_key_bytes):
    try:
        public_key = load_pem_public_key(peer_public_key_bytes, backend=default_backend())
        return public_key
    except Exception as e:
        print(f"Failed to deserialize public key: {e}")
        return None

def broadcast_presence(username, broadcast_address):
    local_ip = get_local_ip()
    message = json.dumps({"username": username, "ip": local_ip})
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        while True:
            sock.sendto(message.encode('utf-8'), (broadcast_address, 6000))
            time.sleep(8)

def listen_for_announcements():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', 6000))
        while True:
            data, addr = sock.recvfrom(1024)
            payload = json.loads(data.decode('utf-8'))
            username, ip = payload['username'], addr[0]
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            with peer_lock:
                peer_dictionary[username] = (ip, timestamp)

def handle_chat_session(conn, derived_key):
    try:
        print("Session started. Waiting for messages...")
        while True:
            data = conn.recv(1024)
            if not data:
                print("No more data received.")
                break
            if derived_key:
                message = decrypt_message(derived_key, data)
                print(f"Decrypted message: {message}")
            else:
                print(f"Received plain text message: {data.decode('utf-8')}")
    except Exception as e:
        print(f"Error during chat session: {e}")
    finally:
        conn.close()
        print("Connection closed.")

        
def receive_full_message(sock):
    data = b''
    try:
        while True:
            part = sock.recv(1024)
            if not part:
                break
            data += part
    except Exception as e:
        print(f"Error receiving data: {e}")
    return data

def tcp_server(private_key):
    host = get_local_ip()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, 6001))
        s.listen()
        while True:
            conn, addr = s.accept()
            with conn:
                print(f"Connection established with {addr}")
                peer_public_key_bytes = receive_full_message(conn)
                peer_public_key = deserialize_public_key(peer_public_key_bytes)
                if peer_public_key is None:
                    print("Failed to deserialize peer's public key")
                    continue
                derived_key = compute_shared_secret(private_key, peer_public_key)
                if derived_key is None:
                    print("Failed to compute shared secret")
                    continue
                handle_chat_session(conn, derived_key)

def tcp_client(server_ip, message, secure, public_key, private_key):
    port = 6001
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            print("Connecting to server...")
            s.connect((server_ip, port))
            
            # Serialize and send the public key
            public_key_bytes = serialize_public_key(public_key)
            if public_key_bytes is None:
                print("Failed to serialize public key.")
                return
            
            print("Sending public key...")
            s.sendall(public_key_bytes)

            # Receive and deserialize the server's public key
            print("Receiving server's public key...")
            server_public_key_bytes = receive_full_message(s)
            if not server_public_key_bytes:
                print("No public key received from server.")
                return

            server_public_key = deserialize_public_key(server_public_key_bytes)
            if server_public_key is None:
                print("Failed to deserialize server's public key.")
                return

            # Compute the shared secret for encryption
            print("Computing shared secret...")
            derived_key = compute_shared_secret(private_key, server_public_key)
            if derived_key is None:
                print("Failed to compute shared secret.")
                return

            # Encrypt the message if secure is True, otherwise send plain text
            if secure:
                print("Encrypting message...")
                encrypted_message = encrypt_message(derived_key, message)
                s.sendall(encrypted_message)
                print("Encrypted message sent.")
            else:
                print("Sending plain message...")
                s.sendall(message.encode())
                print("Plain message sent.")

    except Exception as e:
        print(f"An error occurred in tcp_client: {e}")
    finally:
        print("Returning to main menu...")

def compute_shared_secret(private_key, peer_public_key):
    try:
        shared_key = private_key.exchange(peer_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=None, 
            info=b'handshake data', backend=default_backend()
        ).derive(shared_key)
        return derived_key
    except Exception as e:
        print(f"Failed to compute shared secret: {e}")
        return None

def encrypt_message(key, plaintext):
    iv = urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = PKCS7(algorithms.AES.block_size * 8).padder()
    padded_plaintext = padder.update(plaintext.encode()) + padder.finalize()
    return iv + encryptor.update(padded_plaintext) + encryptor.finalize()

def decrypt_message(key, iv_ciphertext):
    iv, ciphertext = iv_ciphertext[:16], iv_ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = PKCS7(algorithms.AES.block_size * 8).unpadder()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext.decode()

def list_users():
    now = datetime.now()
    print("\nKnown users and their statuses:")
    with peer_lock:
        for username, (ip, timestamp) in peer_dictionary.items():
            last_seen = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
            time_diff = (now - last_seen).total_seconds()
            if time_diff <= 10:
                status = "Online"
            elif time_diff <= 900:
                status = "Away"
            else:
                status = "Offline"
            print(f"{username} ({status}) at {ip}")
            
def handle_chat():
    peer = input("Enter the username of the peer to chat with: ")
    with peer_lock:
        if peer in peer_dictionary:
            peer_info = peer_dictionary[peer]
            if (datetime.now() - datetime.strptime(peer_info[1], '%Y-%m-%d %H:%M:%S')).total_seconds() <= 10:
                message = input("Enter your message: ")
                secure = input("Secure chat (yes/no)? ").lower() == 'yes'
                tcp_client(peer_info[0], message, secure, public_key, private_key)
            else:
                print("Peer is offline or away.")
        else:
            print("Peer not found.")
            
def main_menu():
    print("\nAvailable commands:")
    print("  users - List all known users and their status")
    print("  chat - Start a chat session")
    print("  exit - Exit the program")

if __name__ == "__main__":
    local_ip = get_local_ip()
    subnet_mask = '255.255.255.0'
    broadcast_address = get_broadcast_address(local_ip, subnet_mask)
    username = input("Enter your username: ")
    parameters = generate_dh_parameters()
    private_key, public_key = generate_dh_keys(parameters)

    broadcast_thread = Thread(target=broadcast_presence, args=(username, broadcast_address))
    broadcast_thread.start()
    listen_thread = Thread(target=listen_for_announcements)
    listen_thread.start()
    tcp_server_thread = Thread(target=tcp_server, args=(parameters, private_key))
    tcp_server_thread.start()

    while True:
        main_menu()
        command = input("\nEnter command: ").strip().lower()
        if command == 'users':
            list_users()
        elif command == 'chat':
            handle_chat()
        elif command == 'exit':
            print("Exiting...")
            break
        else: 
            print("Invalid command. Please try again.")
            