import socket
import threading
from datetime import datetime
import requests
import sqlite3
from flask import Flask, render_template

# API Keys
VIRUSTOTAL_API_KEY = "915e7a71b85055b79d04b25afa3043b005ceeb01a57d342d2422ac182e3b79d2"
ABUSEIPDB_API_KEY = "10bb1170089d1dfb559defbb6b259fffa4ac90579b93fad1aefb7b4e862b562c452ce9901bcee213"

# Database file
DB_FILE = 'honeypot.db'

# Flask app setup for the web-based dashboard
app = Flask(__name__)

def setup_database():
    """Sets up the SQLite database and creates a table for logging."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS logs (
                        id INTEGER PRIMARY KEY,
                        timestamp TEXT,
                        service TEXT,
                        ip TEXT,
                        request TEXT)''')
    conn.commit()
    conn.close()

def log_request(service, client_ip, request):
    """Logs the request to the database and checks IP reputation."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO logs (timestamp, service, ip, request) VALUES (?, ?, ?, ?)", 
                   (str(datetime.now()), service, client_ip, request))
    conn.commit()
    conn.close()
    
    # Check IP reputation
    check_abuseipdb(client_ip)

# Get logs for the dashboard
def get_logs():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM logs ORDER BY timestamp DESC")
    logs = cursor.fetchall()
    conn.close()
    return logs

@app.route('/')
def index():
    logs = get_logs()
    return render_template('index.html', logs=logs)

# Function to simulate an HTTP honeypot
def http_honeypot():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("0.0.0.0", 8080))  # HTTP port
    server_socket.listen(5)
    print("HTTP Honeypot running on port 8080")

    while True:
        client_socket, client_address = server_socket.accept()
        request = client_socket.recv(1024).decode('utf-8')
        log_request("HTTP", client_address[0], request)
        client_socket.send("HTTP/1.1 200 OK\r\n\r\nFake Web Server".encode('utf-8'))
        client_socket.close()

# Function to simulate an SSH honeypot (on port 2222 instead of 22)
def ssh_honeypot():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("0.0.0.0", 2222))  # SSH port changed to 2222
    server_socket.listen(5)
    print("SSH Honeypot running on port 2222")

    while True:
        client_socket, client_address = server_socket.accept()
        log_request("SSH", client_address[0], "SSH connection attempt")
        client_socket.close()

# Function to simulate an FTP honeypot
def ftp_honeypot():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("0.0.0.0", 21))  # FTP port
    server_socket.listen(5)
    print("FTP Honeypot running on port 21")

    while True:
        client_socket, client_address = server_socket.accept()
        log_request("FTP", client_address[0], "FTP connection attempt")
        client_socket.close()

# AbuseIPDB IP Reputation Check
def check_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        'Key': ABUSEIPDB_API_KEY,
        'Accept': 'application/json'
    }
    params = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }
    
    response = requests.get(url, headers=headers, params=params)
    
    if response.status_code == 200:
        data = response.json()
        if data['data']['abuseConfidenceScore'] > 50:
            print(f"WARNING: {ip} has a high abuse score on AbuseIPDB!")
        else:
            print(f"{ip} is clean on AbuseIPDB.")
    else:
        print("Failed to get a response from AbuseIPDB.")

# Main function to start honeypot services
if __name__ == "__main__":
    # Set up the database
    setup_database()

    # Start HTTP, SSH, and FTP honeypots in different threads
    http_thread = threading.Thread(target=http_honeypot)
    ssh_thread = threading.Thread(target=ssh_honeypot)
    ftp_thread = threading.Thread(target=ftp_honeypot)

    http_thread.start()
    ssh_thread.start()
    ftp_thread.start()

    # Start the Flask web server for the dashboard without debug mode
    flask_thread = threading.Thread(target=lambda: app.run(debug=False, host='0.0.0.0', port=5000))
    flask_thread.start()

    http_thread.join()
    ssh_thread.join()
    ftp_thread.join()
