Project Overview
The Hamidou Honeypot is a simple multi-protocol honeypot designed to attract and log malicious activity. It supports HTTP, SSH, and FTP protocols, providing a lightweight trap for unauthorized access attempts. The honeypot logs every request and stores it in a SQLite database (honeypot.db) and also includes threat intelligence integration using VirusTotal and AbuseIPDB to flag known malicious IP addresses.

Features
HTTP Honeypot: Listens on port 8080 and logs HTTP requests.
SSH Honeypot: Mimics an SSH server on port 2222 and logs connection attempts.
FTP Honeypot: Mimics an FTP server on port 21, logging connection attempts.
Threat Intelligence: Uses VirusTotal and AbuseIPDB APIs to check and flag IP addresses of attackers.
Logging: All events are logged in a SQLite database (honeypot.db) and can be viewed using a simple Flask web dashboard.
How It Works
HTTP requests: The honeypot responds with a basic HTTP response and logs all requests.
SSH and FTP connections: Fake SSH and FTP services capture connection attempts, logging credentials used and connection details.
Threat Intelligence Integration: Checks IPs using VirusTotal and AbuseIPDB and flags malicious ones in the logs.
Web Dashboard: View logs via the Flask web dashboard running on port 5000.
Installation
Clone the repository:


git clone https://github.com/yourusername/hamidou-honeypot.git
cd hamidou-honeypot
Install the necessary dependencies:


pip install -r requirements.txt
Add your API keys for VirusTotal and AbuseIPDB in the script:

VirusTotal: You need to insert your API key in the VIRUSTOTAL_API_KEY variable.
AbuseIPDB: Add your API key in the ABUSEIPDB_API_KEY variable.
Run the honeypot:


sudo python hamidou.honeypot.py
Usage
HTTP Honeypot: It listens on port 8080. Any HTTP request made to this port is logged in the database.

Test it using curl:

curl http://localhost:8080
SSH Honeypot: The SSH honeypot runs on port 2222. Any SSH connection attempts will be logged.

Test it using telnet:

telnet localhost 2222
FTP Honeypot: The FTP honeypot listens on port 21. All FTP connection attempts are logged.

Test it using telnet:
bash
Copier le code
telnet localhost 21
Web Dashboard: The Flask app provides a web dashboard to view logged requests. It runs on port 5000.

Open a browser and navigate to:
arduino
Copier le code
http://localhost:5000
Threat Intelligence
The honeypot checks each attacker's IP against two services:

VirusTotal: It queries VirusTotal to see if the attacker's IP is known for malicious activity.
AbuseIPDB: It checks the IP's reputation score using AbuseIPDB, warning about high abuse scores.
