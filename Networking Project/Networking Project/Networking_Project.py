import socket
import json
import time
import ipaddress

def get_local_ip():
    """ Get the local IP address of the computer. """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80)) # Google's DNS server
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
        print("could not get local IP, exiting")
        return
    
    broadcast_ip = get_broadcast_address(local_ip, subnet_mask)
    message = json.dumps({"username": username, "ip": local_ip})
    broadcast_address = (broadcast_ip, 6000)
    
    # Create a UDP socket
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        # set the socket to broadcast and allow it to be reused
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        while True:
            try:
                # Send the message
                sock.sendto(message.encode('utf-8'), broadcast_address)
                print(f"Broadcasted presence: {message}")
                time.sleep(8)
            except KeyboardInterrupt:
                print("Broadcasting stopped")
                break
            except Exception as e:
                print(f"Error broadcasting presence: {e}")
                break

if __name__ == "__main__":
    subnet_mask = '24'  # CIDR notation
    username = input("Enter your username: ")
    broadcast_presence(username, subnet_mask)
