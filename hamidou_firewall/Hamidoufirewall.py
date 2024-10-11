import socket
import struct
import threading
import requests
import time
from app import firewall_logs, run_app  # Importing the Flask app components

# File to store logs
LOG_FILE = "firewall_log.txt"

# Store the state of each connection
CONNECTION_STATES = {}

# Define possible TCP states
SYN_SENT = "SYN_SENT"
SYN_RECEIVED = "SYN_RECEIVED"
ESTABLISHED = "ESTABLISHED"
FIN = "FIN"

# VirusTotal API Key
VIRUSTOTAL_API_KEY = "915e7a71b85055b79d04b25afa3043b005ceeb01a57d342d2422ac182e3b79d2"

# AbuseIPDB API Key
ABUSEIPDB_API_KEY = "10bb1170089d1dfb559defbb6b259fffa4ac90579b93fad1aefb7b4e862b562c452ce9901bcee213"

# Function to log events to a file and to the Flask app's logs
def log_event(event):
    with open(LOG_FILE, "a") as log_file:
        log_file.write(event + "\n")
    firewall_logs.append(event)  # Add log to the Flask app's logs
    print(event)  # Optionally print to console as well

# Function to track stateful connections
def track_connection_state(src_ip, dest_ip, flags):
    connection_key = (src_ip, dest_ip)

    # If SYN is sent, mark the connection as SYN_SENT
    if flags == 0x02:  # SYN flag
        CONNECTION_STATES[connection_key] = SYN_SENT
        log_event(f"SYN packet received from {src_ip} to {dest_ip}: Connection state = {SYN_SENT}")
    
    # If SYN-ACK is received, move to SYN_RECEIVED state
    elif flags == 0x12:  # SYN-ACK flag
        if CONNECTION_STATES.get(connection_key) == SYN_SENT:
            CONNECTION_STATES[connection_key] = SYN_RECEIVED
            log_event(f"SYN-ACK received from {src_ip} to {dest_ip}: Connection state = {SYN_RECEIVED}")
    
    # If ACK is received after SYN-ACK, move to ESTABLISHED
    elif flags == 0x10:  # ACK flag
        if CONNECTION_STATES.get(connection_key) == SYN_RECEIVED:
            CONNECTION_STATES[connection_key] = ESTABLISHED
            log_event(f"ACK received from {src_ip} to {dest_ip}: Connection state = {ESTABLISHED}")
    
    # If FIN is received, mark the connection as FIN
    elif flags == 0x01:  # FIN flag
        if CONNECTION_STATES.get(connection_key) == ESTABLISHED:
            CONNECTION_STATES[connection_key] = FIN
            log_event(f"FIN received from {src_ip} to {dest_ip}: Connection state = {FIN}")

# VirusTotal Hash Reputation Search
def check_virustotal(ip):
    url = f"https://www.virustotal.com/vtapi/v2/ip-address/report"
    params = {'apikey': VIRUSTOTAL_API_KEY, 'ip': ip}
    response = requests.get(url, params=params)
    
    if response.status_code == 200:
        data = response.json()
        if data['response_code'] == 1:
            if data.get('positives', 0) > 0:
                log_event(f"WARNING: {ip} is flagged by VirusTotal as malicious!")
            else:
                log_event(f"{ip} is clean on VirusTotal.")
        else:
            log_event(f"No VirusTotal information found for {ip}")
    elif response.status_code == 204:
        log_event(f"No content from VirusTotal for IP: {ip}.")
    else:
        log_event(f"Failed to connect to VirusTotal: {response.status_code}")

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
            log_event(f"WARNING: {ip} has a high abuse score on AbuseIPDB!")
        else:
            log_event(f"{ip} is clean on AbuseIPDB.")
    else:
        log_event(f"Failed to get a response from AbuseIPDB: {response.status_code}")

# Function to parse and inspect packets
def handle_packet(packet):
    ip_header = packet[0:20]
    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

    # Extract IP addresses
    src_ip = socket.inet_ntoa(iph[8])
    dest_ip = socket.inet_ntoa(iph[9])

    # Extract the TCP header
    tcp_header = packet[20:40]
    tcph = struct.unpack('!HHLLBBHHH', tcp_header)

    # Extract flags from the TCP header
    flags = tcph[5]

    # Track connection state based on TCP flags
    track_connection_state(src_ip, dest_ip, flags)

    # Block packets that are not part of an established connection
    if (src_ip, dest_ip) in CONNECTION_STATES and CONNECTION_STATES[(src_ip, dest_ip)] != ESTABLISHED:
        log_event(f"Blocking packet from {src_ip} to {dest_ip}: Connection not established.")
        return

    # Check IP reputation with VirusTotal and AbuseIPDB
    check_virustotal(src_ip)
    check_abuseipdb(src_ip)

# Main function to start packet sniffing
def start_firewall():
    # Open a raw socket to sniff all incoming packets
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    sniffer.bind(("0.0.0.0", 0))

    log_event("Firewall is running... Press Ctrl+C to stop.")

    # Capture and process packets
    while True:
        packet, addr = sniffer.recvfrom(65535)
        packet_handler = threading.Thread(target=handle_packet, args=(packet,))
        packet_handler.start()

if __name__ == "__main__":
    try:
        # Start the Flask app in a separate thread
        flask_thread = threading.Thread(target=run_app)
        flask_thread.daemon = True
        flask_thread.start()

        # Start the firewall
        start_firewall()
    except KeyboardInterrupt:
        log_event("\nFirewall stopped.")
