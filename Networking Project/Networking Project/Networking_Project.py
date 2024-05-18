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
import os
import threading

# Constants
BROADCAST_PORT = 6000  # Port for broadcast announcements
TCP_PORT = 6001        # Port for TCP chat

# Global Variables
peer_dictionary = {}                # Dictionary to store known peers
peer_lock = Lock()                  # Lock to synchronize access to peer_dictionary
log_file_path = "chat_history.log"  # Path to the chat history log file
current_user = None                 # Username of the current user
last_status = {}                    # Dictionary to store the last known status of peers

# Diffie-Hellman Parameters
p = int('''32236799076123020532986389244469020186824276531494491208261987658301048447140395642093591160919531289806076703643002372441192875471874523369977675790673355217361798947704408990676070716614736652983702905633081773067137786283657482830369153577612948994614168479332338571836176901233993518997561596428478449250616828204469490860028038222261904288838006351083402664824298969677390329232619489456731726871715524577728344933741980547579637405293168583844938131124356251831237454721605832955571904971223304322300454690959527709130963810258241341188741687566648849962889823596661474344460344157842930453376073979582896090039''')
g = 2  # Generator
dh_parameters = dh.DHParameterNumbers(p, g).parameters(backend=default_backend())

# Diffie-Hellman key exchange
def generate_dh_keypair(parameters):
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

# Compute the shared secret
def compute_shared_secret(private_key, peer_public_key):
    try:
        shared_secret = private_key.exchange(peer_public_key)
        return shared_secret
    except Exception as e:
        print(f"Error computing shared secret: {e}")
        return None

# Serialize the public key
def serialize_key(public_key):
    try:
        serialized_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return base64.b64encode(serialized_key).decode('utf-8')
    except Exception as e:
        print(f"Error serializing public key: {e}")
        return None

# Deserialize the public key
def deserialize_key(key_data):
    try:
        key_bytes = base64.b64decode(key_data.encode('utf-8'))
        public_key = serialization.load_pem_public_key(key_bytes, backend=default_backend())
        return public_key
    except Exception as e:
        print(f"Error deserializing public key: {e}")
        return None

# Encrypt the message
def encrypt_message(key, plaintext):
    iv = urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext.encode()) + padder.finalize()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    result = base64.b64encode(iv + ciphertext).decode('utf-8')
    return result

# Decrypt the message
def decrypt_message(key, iv_ciphertext):
    try:
        data = base64.b64decode(iv_ciphertext.encode('utf-8'))
        iv, ciphertext = data[:16], data[16:]
        
        # Ensure ciphertext length is a multiple of the block size
        if len(ciphertext) % algorithms.AES.block_size != 0:
            raise ValueError("Ciphertext length is not a multiple of the block size.")
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        unpadder = PKCS7(algorithms.AES.block_size).unpadder()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        return plaintext.decode()
    except Exception as e:
        print(f"Error in decrypt_message: {e}")
        return None

# Log Chat Messages
def log_message(action, username, ip, message, secure):
    with open(log_file_path, 'a') as file:
        file.write(f"{datetime.now()} - {action} - {username} ({ip}) - {'Encrypted' if secure else 'Unencrypted'}: {message}\n")

# Get the local IP address
def get_local_ip():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]

# Get the broadcast address from an IP and subnet mask
def get_broadcast_address(ip, subnet_mask):
    network = ipaddress.ip_network(f"{ip}/{subnet_mask}", strict=False)
    return str(network.broadcast_address)

# Send a message to a socket
def send_message(sock, message):
    try:
        message_length = len(message)
        sock.sendall(str(message_length).encode().ljust(10))
        sock.sendall(message.encode())
    except Exception as e:
        print(f"Error in send_message: {e}")

# Receive a message from a socket
def receive_message(sock):
    try:
        length_str = sock.recv(10).decode().strip()
        if not length_str:
            return None
        message_length = int(length_str)
        chunks = []
        bytes_recd = 0
        while bytes_recd < message_length:
            chunk = sock.recv(min(message_length - bytes_recd, 2048))
            if not chunk:
                raise RuntimeError("Socket connection broken")
            chunks.append(chunk)
            bytes_recd += len(chunk)
        message = b''.join(chunks).decode()
        return message
    except Exception as e:
        print(f"Error in receive_message: {e}")
        return None

# Broadcast the service announcement
def service_announcer(username, broadcast_address):
    local_ip = get_local_ip()
    message = json.dumps({"username": username, "ip": local_ip})
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        while True:
            sock.sendto(message.encode('utf-8'), (broadcast_address, BROADCAST_PORT))
            time.sleep(8)

# Listen for peer announcements
def peer_discovery():
    global last_status
    while True:
        data, addr = recv_broadcast()
        if data:
            payload = json.loads(data.decode('utf-8'))
            username, ip = payload['username'], addr[0]
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            with peer_lock:
                peer_dictionary[username] = (ip, timestamp)
                now = datetime.now()
                last_seen = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
                time_diff = (now - last_seen).total_seconds()
                if time_diff <= 10:
                    status = "Online"
                elif time_diff <= 900:
                    status = "Away"
                else:
                    status = "Offline"
                if username in last_status:
                    if last_status[username] != status:
                        last_status[username] = status
                        if username != current_user:  # Don't print information about yourself
                            print_status(username, status)
                else:
                    last_status[username] = status
                    if username != current_user:  # Don't print information about yourself
                        print_status(username, status)
        time.sleep(1)

def recv_broadcast():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', BROADCAST_PORT))
        sock.settimeout(1)  # Set a timeout for non-blocking
        try:
            data, addr = sock.recvfrom(1024)
            return data, addr
        except socket.timeout:
            return None, None

def print_status(username, status):
    with threading.Lock():
        # Move the cursor to the right side of the console
        print(f"\033[1;50H{username} is now {status}")
        print("\033[7;0H", end="")  # Move cursor back to the command area

def clear_screen():
    # Clear the console screen
    os.system('cls' if os.name == 'nt' else 'clear')

def display_commands():
    # Display the available commands
    print("\nAvailable commands:")
    print("  Users - List all known users and their status")
    print("  Chat - Start a chat session")
    print("  History - Display chat history")
    print("  Exit - Exit the program")

def chat_receiver(client_socket, addr):
    try:
        # Receive the secure flag from the client
        secure_flag = client_socket.recv(1).decode()
        secure = secure_flag == '1'
        print(f"Client has chosen {'secure' if secure else 'unsecure'} chat")

        if secure:
            # Receive the number from the client
            client_number_data = receive_message(client_socket)
            client_number_json = json.loads(client_number_data)
            client_number = client_number_json["number"]

            # Prompt the receiver to enter a number for secure chat initiation
            receiver_number = input("Enter a number to complete the secure chat initiation: ")

            # Send the receiver's number to the client
            send_message(client_socket, json.dumps({"number": receiver_number}))

            # Generate a DH keypair and serialize the public key
            private_key, public_key = generate_dh_keypair(dh_parameters)
            serialized_public_key = serialize_key(public_key)
            send_message(client_socket, json.dumps({"key": serialized_public_key}))

            # Receive the client's public key
            client_key_data = receive_message(client_socket)
            client_public_key = deserialize_key(json.loads(client_key_data)["key"])

            # Use the numbers and DH key exchange to generate a shared key
            shared_secret = compute_shared_secret(private_key, client_public_key)
            derived_key = HKDF(
                algorithm=hashes.SHA256(), length=32, salt=None,
                info=(client_number + receiver_number).encode(),  # Use both numbers in key derivation
                backend=default_backend()
            ).derive(shared_secret)

        # Communicate securely or unsecurely based on the flag
        while True:
            iv_ciphertext = receive_message(client_socket)
            if not iv_ciphertext:
                break
            if secure:
                message = decrypt_message(derived_key, iv_ciphertext)
            else:
                message = json.loads(iv_ciphertext).get('unencrypted_message')
            username = [k for k, v in peer_dictionary.items() if v[0] == addr[0]][0]
            print(f"Received message from {username}: {message}")
            log_message("Received", "Peer", addr[0], message, secure)
    except Exception as e:
        print(f"Error in chat_receiver: {e}")
    finally:
        client_socket.close()

def start_server():
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('0.0.0.0', TCP_PORT))
        server_socket.listen(5)

        while True:
            client_socket, addr = server_socket.accept()
            client_handler = Thread(target=chat_receiver, args=(client_socket, addr))
            client_handler.start()
    except Exception as e:
        print(f"Error in start_server: {e}")

def chat_initiator(peer_ip):
    secure_flag = input("Secure chat (yes/no)? ").strip().lower() == 'yes'
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.settimeout(10)
        client_socket.connect((peer_ip, TCP_PORT))

        # Send the secure flag to the server
        client_socket.sendall(b'1' if secure_flag else b'0')

        if secure_flag:
            # Get the number from the user
            number = input("Enter a number to initiate the secure chat: ")

            # Send the number to the peer
            send_message(client_socket, json.dumps({"number": number}))

            # Receive the peer's number
            peer_number_data = receive_message(client_socket)
            peer_number_json = json.loads(peer_number_data)
            peer_number = peer_number_json["number"]

            # Generate a DH keypair and serialize the public key
            private_key, public_key = generate_dh_keypair(dh_parameters)
            serialized_public_key = serialize_key(public_key)
            send_message(client_socket, json.dumps({"key": serialized_public_key}))

            # Receive the peer's public key
            peer_key_data = receive_message(client_socket)
            peer_public_key = deserialize_key(json.loads(peer_key_data)["key"])

            # Use the numbers and DH key exchange to generate a shared key
            shared_secret = compute_shared_secret(private_key, peer_public_key)
            derived_key = HKDF(
                algorithm=hashes.SHA256(), length=32, salt=None,
                info=b'handshake data', backend=default_backend()
            ).derive(shared_secret)

            # Allow the user to type and send encrypted messages
            while True:
                message = input("Enter your message (type 'exit' to end chat): ")
                if message.lower() == 'exit':
                    break
                encrypted_message = encrypt_message(derived_key, message)
                
                # Check if the encrypted message length is correct before sending
                if len(base64.b64decode(encrypted_message.encode('utf-8'))) % algorithms.AES.block_size != 0:
                    raise ValueError("Encrypted message length is not a multiple of the block size.")
                
                send_message(client_socket, json.dumps({"encrypted_message": encrypted_message}))
                log_message("Sent", "You", peer_ip, encrypted_message, True)
                print(f"Successfully sent encrypted message")
        else:
            # Allow user to type and send unencrypted messages
            while True:
                message = input("Enter your message (type 'exit' to end chat): ")
                if message.lower() == 'exit':
                    break
                send_message(client_socket, json.dumps({"unencrypted_message": message}))
                log_message("Sent", "You", peer_ip, message, False)
                print(f"Sent unencrypted message: {message}")
    except Exception as e:
        print(f"Error in chat_initiator: {e}")
    finally:
        client_socket.close()

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
        clear_screen()
        display_commands()
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