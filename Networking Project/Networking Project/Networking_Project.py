import socket
import json
import time
import ipaddress
from datetime import datetime
from threading import Thread, Lock
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from os import urandom
import base64
import os
from pyDes import des

# Configuration
BROADCAST_PORT = 6000
TCP_PORT = 6001

# Global variables
peer_dictionary = {}
peer_lock = Lock()
log_file_path = "chat_history.log"
current_user = None
last_status = {}

# Generate DH parameters once and use them for both key pairs
parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())

def generate_dh_keypair(parameters):
    """Generate a Diffie-Hellman keypair."""
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

def compute_shared_secret(private_key, peer_public_key):
    """Compute the shared secret using a private key and a peer's public key."""
    return private_key.exchange(peer_public_key)

def serialize_key(public_key):
    """Serialize a public key to a base64-encoded string."""
    serialized_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return base64.b64encode(serialized_key).decode('utf-8')

def deserialize_key(key_data):
    """Deserialize a base64-encoded public key string."""
    key_bytes = base64.b64decode(key_data.encode('utf-8'))
    public_key = serialization.load_pem_public_key(key_bytes, backend=default_backend())
    return public_key

def encrypt_message(key, plaintext):
    """Encrypt a plaintext message using DES."""
    des_cipher = des()
    ciphertext = des_cipher.encrypt(key, plaintext)
    return base64.b64encode(ciphertext).decode('utf-8')

def decrypt_message(key, ciphertext):
    """Decrypt an encrypted message using DES."""
    try:
        ciphertext = base64.b64decode(ciphertext.encode('utf-8'))
        des_cipher = des()
        plaintext = des_cipher.decrypt(key, ciphertext)
        return plaintext.decode()
    except Exception as e:
        print(f"Error decrypting message: {e}")
        return None

def log_message(action, username, ip, message, secure):
    """Log a message to the chat history log file."""
    with open(log_file_path, 'a') as file:
        file.write(f"{datetime.now()} - {action} - {username} ({ip}) - {'Encrypted' if secure else 'Unencrypted'}: {message}\n")

def get_local_ip():
    """Get the local IP address of the current machine."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]

def get_broadcast_address(ip, subnet_mask):
    """Get the broadcast address for a given IP address and subnet mask."""
    network = ipaddress.ip_network(f"{ip}/{subnet_mask}", strict=False)
    return str(network.broadcast_address)

def send_message(sock, message):
    """Send a message over a socket."""
    try:
        message_length = len(message)
        sock.sendall(str(message_length).encode().ljust(10))
        sock.sendall(message.encode())
    except Exception as e:
        print(f"Error in send_message: {e}")

def receive_message(sock):
    """Receive a message over a socket."""
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

def service_announcer(username, broadcast_address):
    """Broadcast presence of the user to the network."""
    local_ip = get_local_ip()
    message = json.dumps({"username": username, "ip": local_ip})
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        while True:
            try:
                sock.sendto(message.encode('utf-8'), (broadcast_address, BROADCAST_PORT))
            except Exception as e:
                print(f"Error sending broadcast message: {e}")
            time.sleep(8)

def recv_broadcast():
    """Receive broadcast messages."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(('', BROADCAST_PORT))
        sock.settimeout(1)
        try:
            data, addr = sock.recvfrom(1024)
            return data, addr
        except socket.timeout:
            return None, None
        except Exception as e:
            print(f"Error receiving broadcast: {e}")
            return None, None

def peer_discovery():
    """Discover peers by receiving broadcast messages."""
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
                        if username != current_user:        # Don't print information about yourself
                            print_status(username, status)
                else:
                    last_status[username] = status
                    if username != current_user:            # Don't print information about yourself
                        print_status(username, status)
        time.sleep(1)

def print_status(username, status):
    """Print the status of a user."""
    with Lock():
        print("\033[s", end="")                         # Save the cursor position
        print(f"\033[1;50H{username} is now {status}")  # Move the cursor to the right side of the console
        print("\033[u", end="")                         # Restore the cursor position
        print("")                                       # Move to the command line

def clear_screen():
    """Clear the console screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def display_commands():
    """Display the available commands."""
    print("\nAvailable commands:")
    print("  Users - List all known users and their status")
    print("  Chat - Start a chat session")
    print("  History - Display chat history")
    print("  Exit - Exit the program")
    print("\nEnter command: ", end="")

def start_server():
    """Start the TCP server to listen for incoming chat connections."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('0.0.0.0', TCP_PORT))
    server_socket.listen(5)

    while True:
        client_socket, addr = server_socket.accept()
        client_handler = Thread(target=chat_receiver, args=(client_socket, addr))
        client_handler.start()

def chat_initiator(peer_ip):
    """Initiate a chat session with a peer."""
    secure_flag = input("Secure chat (yes/no)? ").strip().lower() == 'yes'
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.settimeout(10)
        client_socket.connect((peer_ip, TCP_PORT))

        # Send the secure flag to the server
        client_socket.sendall(b'1' if secure_flag else b'0')

        if secure_flag:
            # Prompt the user to enter a number
            user_number = input("Enter a number for key generation: ").strip()

            # Send the user's number to the peer
            send_message(client_socket, json.dumps({"key": user_number}))

            # Receive the peer's number
            peer_number_json = receive_message(client_socket)
            peer_number_data = json.loads(peer_number_json)
            peer_number = peer_number_data["key"]

            private_key, public_key = generate_dh_keypair(parameters)
            serialized_public_key = serialize_key(public_key)
            send_message(client_socket, serialized_public_key)

            peer_public_key_data = receive_message(client_socket)
            peer_public_key = deserialize_key(peer_public_key_data)

            # Compute the shared secret using only the DH mechanism
            shared_secret = compute_shared_secret(private_key, peer_public_key)
            derived_key = HKDF(
                algorithm=hashes.SHA256(), length=8, salt=None,
                info=(user_number + peer_number).encode(), backend=default_backend()
            ).derive(shared_secret)

            while True:
                message = input("Enter your message (type 'exit' to end chat): ")
                if message.lower() == 'exit':
                    break
                encrypted_message = encrypt_message(derived_key, message)
                send_message(client_socket, json.dumps({"encrypted_message": encrypted_message}))
                log_message("Sent", "You", peer_ip, message, True)
                print(f"Sent encrypted message: {encrypted_message}")
        else:
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

def chat_receiver(client_socket, addr):
    """Handle incoming chat messages."""
    try:
        secure_flag = client_socket.recv(1).decode()
        secure = secure_flag == '1'
        print(f"Client has chosen {'secure' if secure else 'unsecure'} chat")

        if secure:
            # Prompt the peer to enter a number
            user_number = input("Enter a number for key generation: ").strip()

            # Receive the peer's number
            peer_number_json = receive_message(client_socket)
            peer_number_data = json.loads(peer_number_json)
            peer_number = peer_number_data["key"]

            # Send the user's number to the peer
            send_message(client_socket, json.dumps({"key": user_number}))

            private_key, public_key = generate_dh_keypair(parameters)
            serialized_public_key = serialize_key(public_key)
            if serialized_public_key is None:
                print("Failed to serialize public key")
                return
            send_message(client_socket, serialized_public_key)

            client_public_key_data = receive_message(client_socket)
            if not client_public_key_data:
                print("Failed to receive client's public key")
                return
            client_public_key = deserialize_key(client_public_key_data)
            if client_public_key is None:
                print("Failed to deserialize client's public key")
                return

            # Compute the shared secret using only the DH mechanism
            shared_secret = compute_shared_secret(private_key, client_public_key)
            derived_key = HKDF(
                algorithm=hashes.SHA256(), length=8, salt=None,
                info=(user_number + peer_number).encode(), backend=default_backend()
            ).derive(shared_secret)

        while True:
            iv_ciphertext = receive_message(client_socket)
            if not iv_ciphertext:
                break
            if secure:
                message = decrypt_message(derived_key, iv_ciphertext)
            else:
                message = iv_ciphertext.strip()
            username = [k for k, v in peer_dictionary.items() if v[0] == addr[0]]
            if username:
                username = username[0]
                print(f"{username}: {message}")
                log_message("Received", username, addr[0], message, secure)
            else:
                print(f"Unknown user: {message}")
    except Exception as e:
        print(f"Error in chat_receiver: {e}")
    finally:
        client_socket.close()

def list_users():
    """List all known users and their status."""
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
    """Display the chat history from the log file."""
    print("\nChat History:")
    try:
        with open(log_file_path, 'r') as file:
            lines = file.readlines()
            if not lines:
                print("No chat history found.")
            for line in lines:
                print(line.strip())
    except FileNotFoundError:
        print("No chat history file found.")
    except Exception as e:
        print(f"Error reading chat history: {e}")

def handle_chat():
    """Handle the chat command to start a chat session."""
    peer_username = input("Enter the username of the peer to chat with: ")
    with peer_lock:
        if peer_username in peer_dictionary:
            peer_ip = peer_dictionary[peer_username][0]
            chat_initiator(peer_ip)
        else:
            print("Peer not found. Try again.")

def main():
    """Main function to run the peer-to-peer chat application."""
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
        command = input().strip().lower()
        if command == 'users':
            clear_screen()
            display_commands()
            list_users()
            input("\nPress Enter to return to the main menu.")
        elif command == 'chat':
            handle_chat()
        elif command == 'history':
            clear_screen()
            display_commands()
            display_chat_history()
            input("\nPress Enter to return to the main menu.")
        elif command == 'exit':
            print("Exiting...")
            break
        else:
            print("Invalid command. Please try again.")

if __name__ == "__main__":
    main()
