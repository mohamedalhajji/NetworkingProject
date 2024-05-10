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

# Generate Diffie-Hellman parameters and keys
def generate_dh_parameters():
    return dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())

def generate_dh_keys(parameters):
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

def get_local_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            return ip
    except Exception as e:
        print(f"Error obtaining local IP: {e}")
        return None

def get_broadcast_address(ip, subnet_mask):
    network = ipaddress.ip_network(f"{ip}/{subnet_mask}", strict=False)
    return str(network.broadcast_address)

def serialize_public_key(public_key):
    try:
        serialized_key = public_key.public_bytes(encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo)
        print("Public key serialized successfully.")
        return serialized_key
    except Exception as e:
        print(f"Failed to serialize public key: {e}")
        return None

def deserialize_public_key(peer_public_key_bytes):
    try:
        public_key = load_pem_public_key(peer_public_key_bytes, backend=default_backend())
        print("Public key deserialized successfully.")
        return public_key
    except Exception as e:
        print(f"Failed to deserialize public key: {e}")
        return None

def broadcast_presence(username, broadcast_address):
    local_ip = get_local_ip()
    if local_ip is None:
        print("Could not get local IP, exiting")
        return
    message = json.dumps({"username": username, "ip": local_ip})
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        while True:
            sock.sendto(message.encode('utf-8'), (broadcast_address, 6000))
            print(f"Broadcasted presence to {broadcast_address}: {message}")
            time.sleep(8)

def listen_for_announcements():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', 6000))
        print("Listening for peer announcements on UDP port 6000")
        while True:
            data, addr = sock.recvfrom(1024)
            payload = json.loads(data.decode('utf-8'))
            username, ip = payload['username'], addr[0]
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            with peer_lock:
                peer_dictionary[username] = (ip, timestamp)
            print(f"Received announcement from {username} at {ip}")

def handle_chat_session(conn, derived_key):
    try:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            try:
                message = decrypt_message(derived_key, data)
                print(f"Decrypted message: {message}")
            except Exception as e:
                print(f"Received plain text message: {data.decode('utf-8')}")
    except Exception as e:
        print(f"An error occurred during the chat session: {e}")
    finally:
        conn.close()

def tcp_server(parameters, private_key):
    host = get_local_ip()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, 6001))
        s.listen()
        print(f"Listening for chat on {host}:6001")
        while True:
            conn, addr = s.accept()
            with conn:
                print(f"Connection established with {addr}")
                peer_public_key_bytes = conn.recv(1024)
                peer_public_key = deserialize_public_key(peer_public_key_bytes)
                derived_key = compute_shared_secret(private_key, peer_public_key)
                handle_chat_session(conn, derived_key)

def tcp_client(server_ip, message, secure, public_key, private_key):
    port = 6001
    public_key_bytes = serialize_public_key(public_key)
    if public_key_bytes is None:
        print("Public key serialization failed. Exiting.")
        return
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server_ip, port))
        s.sendall(public_key_bytes)
        print("Public key sent successfully.")
        received_data = b""
        try:
            while True:
                part = s.recv(4096)
                if not part:
                    break
                received_data += part
        except Exception as e:
            print(f"Error receiving data: {e}")
            return
        if not received_data:
            print("No data received for server public key.")
            return
        server_public_key = deserialize_public_key(received_data)
        if server_public_key is None:
            print("Deserialization of server's public key failed. Exiting.")
            return
        derived_key = compute_shared_secret(private_key, server_public_key)
        if derived_key is None:
            print("Error computing shared secret.")
            return
        print("Shared secret computed successfully.")
        if secure:
            message = encrypt_message(derived_key, message)
            s.sendall(message.encode())
        else:
            s.sendall(message.encode())
        print("Message sent.")

def compute_shared_secret(private_key, peer_public_key):
    if peer_public_key is None:
        print("Invalid peer public key.")
        return None
    try:
        shared_key = private_key.exchange(peer_public_key)
        derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data', backend=default_backend()).derive(shared_key)
        return derived_key
    except Exception as e:
        print(f"Error computing shared secret: {e}")
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
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = PKCS7(algorithms.AES.block_size * 8).unpadder()
    return unpadder.update(padded_plaintext) + unpadder.finalize()

def main_menu():
    print("\nAvailable commands:")
    print("  users - List all known users and their status")
    print("  chat - Start a chat session")
    print("  exit - Exit the program")

def list_users():
    now = datetime.now()
    for username, (ip, timestamp) in peer_dictionary.items():
        last_seen = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
        if (now - last_seen).total_seconds() > 900:
            status = "Offline"
        elif (now - last_seen).total_seconds() <= 10:
            status = "Online"
        else:
            status = "Away"
        print(f"{username} ({status}) at {ip}")

peer_dictionary = {}
peer_lock = Lock()

if __name__ == "__main__":
    local_ip = get_local_ip()
    if local_ip:
        subnet_mask = '255.255.255.0'
        broadcast_address = get_broadcast_address(local_ip, subnet_mask)
        print(f"Local IP Address: {local_ip}")
        print(f"Broadcast Address: {broadcast_address}")
    else:
        print("Failed to determine local IP address.")
        exit(1)

    username = input("Enter your username: ")
    parameters = generate_dh_parameters()
    private_key, public_key = generate_dh_keys(parameters)
    public_key_bytes = serialize_public_key(public_key)

    broadcast_thread = Thread(target=broadcast_presence, args=(username, broadcast_address))
    broadcast_thread.start()

    listen_thread = Thread(target=listen_for_announcements)
    listen_thread.start()

    tcp_server_thread = Thread(target=tcp_server, args=(parameters, private_key))
    tcp_server_thread.start()

    while True:
        main_menu()
        command = input("Enter command: ").strip().lower()
        if command == 'users':
            list_users()
        elif command == 'chat':
            peer = input("Enter the username of the peer to chat with: ")
            with peer_lock:
                if peer in peer_dictionary:
                    peer_info = peer_dictionary[peer]
                    last_seen = datetime.strptime(peer_info[1], '%Y-%m-%d %H:%M:%S')
                    if (datetime.now() - last_seen).total_seconds() <= 10:
                        message = input("Enter your message: ")
                        secure = input("Secure chat (yes/no)? ").lower() == 'yes'
                        tcp_client(peer_info[0], message, secure, public_key, private_key)
                    else:
                        print("Peer is offline or away.")
        elif command == 'exit':
            print("Exiting...")
            break
        else:
            print("Unknown command. Please try again.")