import socket
import threading
import base64

# Store valid usernames and passwords
VALID_USERS = {"user1": "password1", "user2": "password2"}

# List of URLs or domains to block (dangerous websites)
blocked_urls = [
    "example.com",
    "malware.com",
    "phishing.com",
    "dangerous-site.com",
    "illegal-downloads.com",
]

# Function to check if a URL is blocked
def is_blocked(url):
    for blocked_url in blocked_urls:
        if blocked_url in url:
            return True
    return False

# Function to handle the client's request
def handle_client(client_socket):
    request = client_socket.recv(1024).decode('utf-8')
    
    # Extract the Authorization header from the request
    headers = request.split("\n")
    auth_header = None
    for header in headers:
        if header.startswith("Authorization:"):
            auth_header = header.split()[2]

    # Check for basic authentication
    if auth_header:
        auth_decoded = base64.b64decode(auth_header).decode('utf-8')
        username, password = auth_decoded.split(":")
        
        # Validate credentials
        if VALID_USERS.get(username) == password:
            print(f"Authenticated: {username}")
        else:
            print(f"Authentication failed for {username}")
            client_socket.send(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
            client_socket.close()
            return
    else:
        print("No authentication provided")
        client_socket.send(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
        client_socket.close()
        return

    # Extract the requested URL from the request line
    request_line = headers[0]
    url = request_line.split(' ')[1]
    
    # Check if the requested URL is in the blocked list
    if is_blocked(url):
        print(f"Blocked request to {url}")
        # Send a "403 Forbidden" response if the URL is blocked
        client_socket.send(b"HTTP/1.1 403 Forbidden\r\n\r\nBlocked by Hamidou Proxy!\r\n")
    else:
        # Continue processing the request normally (here, you can add forwarding logic)
        print(f"Request allowed: {url}")
        client_socket.send(b"HTTP/1.1 200 OK\r\n\r\nRequest Passed Through the Proxy!\r\n")

    client_socket.close()

# Main server loop
def start_proxy():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 8080))  # Listen on all available interfaces
    server.listen(5)
    
    print("Proxy server is running on port 8080...")

    while True:
        client_socket, addr = server.accept()
        print(f"Accepted connection from {addr}")
        
        client_handler = threading.Thread(target=handle_client, args=(client_socket,))
        client_handler.start()

if __name__ == "__main__":
    start_proxy()
