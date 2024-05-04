import socket
import json
import time
import ipaddress
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.padding import PKCS7
from os import urandom

from threading import Thread
from threading import Lock

def generate_dh_parameters():
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    return parameters

def generate_dh_keys(parameters):
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

peer_dictionary = {}
peer_lock = Lock()

def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    )

def get_local_ip():
    """ Get the local IP address of the computer. """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # Google's DNS server
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception as e:
        print(f"Error obtaining local IP: {e}")
        return None

def get_broadcast_address(local_ip, subnet_mask):
    """ Calculate the broadcast address based on the local IP and subnet mask. """
    ip = ipaddress.IPv4Address(local_ip)
    net = ipaddress.IPv4Network(str(ip) + '/' + subnet_mask, strict=False)
    return str(net.broadcast_address)

def broadcast_presence(username, subnet_mask):
    """ Broadcast the presence of the user to the network. """
    local_ip = get_local_ip()
    if local_ip is None:
        print("Could not get local IP, exiting")
        return
    
    broadcast_ip = get_broadcast_address(local_ip, subnet_mask)
    message = json.dumps({"username": username, "ip": local_ip})
    broadcast_address = (broadcast_ip, 6000)
    
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        while True:
            try:
                sock.sendto(message.encode('utf-8'), broadcast_address)
                print(f"Broadcasted presence: {message}")
                time.sleep(8)
            except KeyboardInterrupt:
                print("Broadcasting stopped")
                break
            except Exception as e:
                print(f"Error broadcasting presence: {e}")
                break

def listen_for_announcements():
    local_ip = get_local_ip()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', 6000))
        while True:
            data, addr = sock.recvfrom(1024)
            if addr[0] != local_ip:
                payload = json.loads(data.decode('utf-8'))
                username = payload['username']
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                with peer_lock:
                    peer_dictionary[username] = (addr[0], timestamp)
                print(f"Received announcement from {username} at {addr[0]}")

def tcp_server(parameters, private_key):
    host = get_local_ip()
    port = 6001
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen()
        print(f"Listening for chat on {host}:{port}")
        while True:
            conn, addr = s.accept()
            with conn:
                peer_public_key_bytes = conn.recv(1024)
                derived_key = compute_shared_secret(private_key, peer_public_key_bytes, parameters)
                while True:
                    data = conn.recv(1024)
                    if not data:
                        break
                    try:
                        data = decrypt_message(derived_key, data)
                        print(f"Received message from {addr[0]}: {data}")
                    except Exception as e:
                        print("Could not decrypt, showing raw message")

def tcp_client(server_ip, message, secure, public_key_bytes, parameters, private_key):
    port = 6001
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server_ip, port))
        s.sendall(public_key_bytes)
        server_public_key_bytes = s.recv(1024)
        derived_key = compute_shared_secret(private_key, server_public_key_bytes, parameters)
        if secure:
            try:
                message = encrypt_message(derived_key, message)
            except Exception as e:
                print(f"Error during message encryption: {e}")
                return
        s.sendall(message.encode())
        print("Message sent")

def encrypt_message(key, plaintext):
    iv = urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    padder = PKCS7(algorithms.AES.block_size * 8).padder()
    padded_plaintext = padder.update(plaintext.encode()) + padder.finalize()
    
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    return iv + ciphertext


def decrypt_message(key, iv_ciphertext):
    iv = iv_ciphertext[:16]
    ciphertext = iv_ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    unpadder = PKCS7(algorithms.AES.block_size * 8).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext.decode()


def compute_shared_secret(private_key, peer_public_key_bytes, parameters):
    peer_public_key = load_pem_public_key(peer_public_key_bytes, backend=default_backend())
    shared_key = private_key.exchange(peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # Suitable for AES-256
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_key)
    return derived_key

def main_menu():
    print("\nAvailable commands:")
    print("  users - List all known users and their status")
    print("  chat - Start a chat session")
    print("  exit - Exit the program")
    print("")

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

if __name__ == "__main__":
    subnet_mask = '24'  # CIDR notation
    username = input("Enter your username: ")
    parameters = generate_dh_parameters()
    private_key, public_key = generate_dh_keys(parameters)
    public_key_bytes = serialize_public_key(public_key)

    broadcast_thread = Thread(target=broadcast_presence, args=(username, subnet_mask))
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
                        tcp_client(peer_info[0], message, secure, public_key_bytes, parameters, private_key)
                    else:
                        print("Peer is offline or away.")
                else:
                    print("Peer not found.")
        elif command == 'exit':
            print("Exiting...")
            break
        else:
            print("Unknown command. Please try again.")