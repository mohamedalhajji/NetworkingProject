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
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from os import urandom
import base64

# Configuration
BROADCAST_PORT = 6000
TCP_PORT = 8000

# Global variables
peer_dictionary = {}
peer_lock = Lock()
log_file_path = "chat_history.log"
current_user = None

# Generate DH parameters once and share them between devices
dh_parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
serialized_dh_parameters = dh_parameters.parameter_bytes(encoding=serialization.Encoding.PEM, format=serialization.ParameterFormat.PKCS3)

# Helper functions for DH Key Exchange
def generate_dh_keypair():
    private_key = dh_parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

def compute_shared_secret(private_key, peer_public_key):
    try:
        shared_secret = private_key.exchange(peer_public_key)
        return shared_secret
    except Exception as e:
        print(f"Error computing shared secret: {e}")
        return None

def serialize_key(public_key):
    try:
        serialized_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return serialized_key.decode('utf-8')
    except Exception as e:
        print(f"Error serializing public key: {e}")
        return None

def deserialize_key(key_data):
    try:
        key_bytes = key_data.encode('utf-8')
        public_key = serialization.load_pem_public_key(key_bytes, backend=default_backend())
        return public_key
    except Exception as e:
        print(f"Error deserializing public key: {e}")
        return None

def encrypt_message(key, plaintext):
    iv = urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext.encode()) + padder.finalize()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode('utf-8')

def decrypt_message(key, iv_ciphertext):
    data = base64.b64decode(iv_ciphertext.encode('utf-8'))
    iv, ciphertext = data[:16], data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext.decode()

def log_message(action, username, ip, message, secure):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')  # Format without milliseconds
    with open(log_file_path, 'a') as file:
        file.write(f"{timestamp} - {action} - {username} ({ip}) - {'Encrypted' if secure else 'Unencrypted'}: {message}\n")

def get_local_ip():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]

def get_broadcast_address(ip, subnet_mask):
    network = ipaddress.ip_network(f"{ip}/{subnet_mask}", strict=False)
    return str(network.broadcast_address)

# Helper functions for Socket Communication
def send_message(sock, message):
    try:
        message_length = len(message)
        sock.sendall(str(message_length).encode().ljust(10))
        sock.sendall(message.encode())
    except Exception as e:
        print(f"Error in send_message: {e}")

def receive_message(sock):
    try:
        length_str = sock.recv(10).decode().strip()
        if not length_str:
            return None
        message_length = int(length_str)
        message = sock.recv(message_length).decode()
        return message
    except Exception as e:
        print(f"Error in receive_message: {e}")
        return None

# Broadcast Presence
def service_announcer(username, broadcast_address):
    local_ip = get_local_ip()
    message = json.dumps({"username": username, "ip": local_ip})
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        while True:
            sock.sendto(message.encode('utf-8'), (broadcast_address, BROADCAST_PORT))
            time.sleep(8)

# Listen for Announcements
def peer_discovery():
    last_status = {}

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', BROADCAST_PORT))
        while True:
            data, addr = sock.recvfrom(1024)
            payload = json.loads(data.decode('utf-8'))
            username, ip = payload['username'], addr[0]
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            with peer_lock:
                if username == current_user:
                    continue  # Skip updates for the current user

                if username in peer_dictionary:
                    peer_dictionary[username] = (ip, timestamp)
                else:
                    peer_dictionary[username] = (ip, timestamp)

                last_seen = datetime.strptime(peer_dictionary[username][1], '%Y-%m-%d %H:%M:%S')
                time_diff = (datetime.now() - last_seen).total_seconds()

                # Determine status
                if time_diff <= 10:
                    status = "Online"
                elif time_diff <= 900:
                    status = "Away"
                else:
                    status = "Offline"

                # Print status only if it has changed
                if username not in last_status or last_status[username] != status:
                    last_status[username] = status
                    print(f"{username} is {status.lower()}")

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('0.0.0.0', TCP_PORT))
    server_socket.listen(5)

    while True:
        client_socket, addr = server_socket.accept()
        client_handler = Thread(target=chat_receiver, args=(client_socket, addr))
        client_handler.start()

# Communicate With Peer
def chat_initiator(peer_ip):
    secure_flag = input("Secure chat (yes/no)? ").strip().lower() == 'yes'
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.settimeout(10)
        client_socket.connect((peer_ip, TCP_PORT))

        # Send the secure flag to the server
        client_socket.sendall(b'1' if secure_flag else b'0')

        if secure_flag:
            # Generate a DH keypair and serialize the public key
            private_key, public_key = generate_dh_keypair()
            
            # Serialize and send public key to server
            serialized_public_key = serialize_key(public_key)
            if serialized_public_key is None:
                print("Failed to serialize public key")
                return
            
            # Send the public key using the helper function
            send_message(client_socket, serialized_public_key)

            # Receive and deserialize the peer's public key
            server_public_key_data = receive_message(client_socket)
            if not server_public_key_data:
                print("Failed to receive server's public key")
                return
            server_public_key = deserialize_key(server_public_key_data)
            if server_public_key is None:
                print("Failed to deserialize server's public key")
                return
            
            # Receive a number from the user
            number = input("Enter a number to generate shared key: ")
            send_message(client_socket, json.dumps({"key": number}))

            # Receive the server's number
            server_number_data = receive_message(client_socket)
            if not server_number_data:
                print("Failed to receive server's number")
                return
            server_number = json.loads(server_number_data)['key']

            # Compute the shared secret and derive the encryption key
            shared_secret = compute_shared_secret(private_key, server_public_key)
            if shared_secret is None:
                print("Failed to compute shared secret. Terminating connection.")
                return
            combined_key_data = shared_secret + number.encode() + server_number.encode()
            derived_key = HKDF(
                algorithm=hashes.SHA256(), length=32, salt=None, 
                info=b'handshake data', backend=default_backend()
            ).derive(combined_key_data)

            # Allow user to type and send encrypted messages
            while True:
                message = input("Enter your message (type 'exit' to end chat): ")
                if message.lower() == 'exit':
                    break
                encrypted_message = encrypt_message(derived_key, message)
                send_message(client_socket, json.dumps({"encrypted_message": encrypted_message}))
                log_message("Sent", current_user, peer_ip, message, True)
                print(f"{current_user}: {message}")
        else:
            # Allow user to type and send unencrypted messages
            while True:
                message = input("Enter your message (type 'exit' to end chat): ")
                if message.lower() == 'exit':
                    break
                send_message(client_socket, json.dumps({"unencrypted_message": message})) 
                log_message("Sent", current_user, peer_ip, message, False)
                print(f"{current_user}: {message}")
    except Exception as e:
        print(f"Error in chat_initiator: {e}")
    finally:
        client_socket.close()

# Handle Client
def chat_receiver(client_socket, addr):
    try:
        # Receive the secure flag from the client
        secure_flag = client_socket.recv(1).decode()
        secure = secure_flag == '1'
        print(f"Client has chosen {'secure' if secure else 'unsecure'} chat")

        if secure:
            # Use global DH parameters
            private_key, public_key = generate_dh_keypair()

            # Serialize and send public key to client
            serialized_public_key = serialize_key(public_key)
            if serialized_public_key is None:
                print("Failed to serialize public key")
                return

            # Send the public key using the helper function
            send_message(client_socket, serialized_public_key)

            # Receive client's public key using the helper function
            client_public_key_data = receive_message(client_socket)
            if not client_public_key_data:
                print("Failed to receive client's public key")
                return
            client_public_key = deserialize_key(client_public_key_data)
            if client_public_key is None:
                print("Failed to deserialize client's public key")
                return

            # Receive the client's number
            client_number_data = receive_message(client_socket)
            if not client_number_data:
                print("Failed to receive client's number")
                return
            client_number = json.loads(client_number_data)['key']

            # Send a number back to the client
            number = input("Enter a number to generate shared key: ")
            send_message(client_socket, json.dumps({"key": number}))

            # Compute shared secret
            shared_secret = compute_shared_secret(private_key, client_public_key)
            if shared_secret is None:
                print("Failed to compute shared secret. Terminating connection.")
                return
            combined_key_data = shared_secret + client_number.encode() + number.encode()
            derived_key = HKDF(
                algorithm=hashes.SHA256(), length=32, salt=None, 
                info=b'handshake data', backend=default_backend()
            ).derive(combined_key_data)

        # Communicate securely or unsecurely based on the flag
        while True:
            iv_ciphertext = receive_message(client_socket)
            if not iv_ciphertext:
                break
            if secure:
                message = decrypt_message(derived_key, json.loads(iv_ciphertext)['encrypted_message'])
            else:
                message = json.loads(iv_ciphertext)['unencrypted_message']
            with peer_lock:
                username = next((name for name, info in peer_dictionary.items() if info[0] == addr[0]), addr[0])
            print(f"{username}: {message}")
            log_message("Received", username, addr[0], message, secure)
    except Exception as e:
        print(f"Error in chat_receiver: {e}")
    finally:
        client_socket.close()

# Main Application
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
            if username == current_user:
                print(f"(You), {username} ({status}) at {ip}")
            else:
                print(f"{username} ({status}) at {ip}")

def display_chat_history():
    print("\nChat History:")
    try:
        with open(log_file_path, 'r') as file:
            for line in file:
                print(line.strip())
    except FileNotFoundError:
        print("No chat history found.")

def handle_chat():
    peer_username = input("Enter the username of the peer to chat with: ")
    with peer_lock:
        if peer_username in peer_dictionary:
            peer_ip = peer_dictionary[peer_username][0]
            chat_initiator(peer_ip)
        else:
            print("Peer not found. Try again.")

def main():
    global current_user
    local_ip = get_local_ip()
    subnet_mask = '255.255.255.0'
    broadcast_address = get_broadcast_address(local_ip, subnet_mask)
    current_user = input("Enter your username: ")

    # Start broadcasting presence
    broadcast_thread = Thread(target=service_announcer, args=(current_user, broadcast_address))
    broadcast_thread.daemon = True
    broadcast_thread.start()

    # Start listening for announcements
    listen_thread = Thread(target=peer_discovery)
    listen_thread.daemon = True
    listen_thread.start()

    # Start the server
    server_thread = Thread(target=start_server)
    server_thread.daemon = True
    server_thread.start()

    # Main loop
    while True:
        print("\nAvailable commands:")
        print("  Users - List all known users and their status")
        print("  Chat - Start a chat session")
        print("  History - Display chat history")
        print("  Exit - Exit the program")
        command = input("\nEnter command: ").strip().lower()
        if command == 'users':
            list_users()
        elif command == 'chat':
            handle_chat()
        elif command == 'history':
            display_chat_history()
        elif command == 'exit':
            print("Exiting...")
            break
        else:
            print("Invalid command. Please try again.")

if __name__ == "__main__":
    main()