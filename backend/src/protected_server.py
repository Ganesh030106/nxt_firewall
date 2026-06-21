import socket
import threading
import datetime

# Configuration
BIND_IP = "0.0.0.0"
BIND_PORT = 8080

def handle_client(client_socket):
    """
    Handles a single connection like a real web server.
    Returns a standard HTTP 200 OK response.
    """
    try:
        request = client_socket.recv(1024).decode('utf-8', errors='ignore')
        
        # Log the connection (simulating server access logs)
        if request:
            first_line = request.split('\n')[0]
            # Print less to keep console clean, but enough to show it's alive
            # print(f"[SERVER] 📥 Received: {first_line}")

        # Standard HTTP Response (The "Protected" Content)
        http_response = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html\r\n"
            "Server: Sentinel-Protected-Gateway/1.0\r\n"
            "\r\n"
            "<html>"
            "<head><title>Secure Corporate Portal</title></head>"
            "<body style='font-family: sans-serif; text-align: center; padding: 50px;'>"
            "<h1 style='color: #45a29e;'>🔒 Protected Corporate Gateway</h1>"
            "<p>If you can see this, the Firewall allowed your connection.</p>"
            "<p><i>Sentinel-X Active Defense</i></p>"
            "</body>"
            "</html>"
        )
        
        client_socket.sendall(http_response.encode('utf-8'))
        client_socket.close()
        
    except Exception as e:
        # print(f"[SERVER] Error handling client: {e}")
        pass

def start_protected_server():
    """Starts the 'Real' socket listener."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((BIND_IP, BIND_PORT))
    server.listen(100) # Support up to 100 simultaneous connections
    
    print(f"\n[INFO] Protected Corporate Gateway running on Port {BIND_PORT}")
    print(f"[INFO] Sentinel-X is monitoring traffic to this port...\n")

    while True:
        try:
            client, addr = server.accept()
            client_handler = threading.Thread(target=handle_client, args=(client,))
            client_handler.start()
        except Exception:
            pass