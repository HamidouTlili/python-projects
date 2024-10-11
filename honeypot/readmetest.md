Testing the Honeypot
Test HTTP Requests: You can use curl or a web browser to send requests to the HTTP honeypot running on port 8080.

Example using curl:


curl http://localhost:8080
After running this, check the logs in the Flask dashboard (http://localhost:5000) to see if the HTTP request was recorded.

Simulate SSH Attacks: Use a tool like telnet or a legitimate SSH client to connect to port 2222, the fake SSH service.

Example using telnet:


telnet localhost 2222
This should trigger an entry in your logs for an SSH connection attempt. You can view it on the web dashboard or in honeypot.db.

Simulate FTP Attacks: Try connecting to port 21 using an FTP client or telnet. This will mimic an FTP attack.

Example using telnet:


telnet localhost 21
Check the logs in the web dashboard for the connection attempt.

View Logs in the Flask Dashboard: After simulating attacks, open your web browser and navigate to the Flask web dashboard to see all recorded logs:

arduino
Copier le code
http://localhost:5000
Check IP Reputation: The honeypot will automatically check the attacker's IP against VirusTotal and AbuseIPDB. If the IP is flagged as malicious, a warning will appear in the logs:

Example: WARNING: 192.168.0.1 is flagged by VirusTotal as malicious!
Simulating Real Attacks
Nmap: You can use nmap to simulate a port scan on your honeypot.

nmap -A localhost
This scan should trigger various log entries in the database.

Metasploit: You can launch specific attack modules using Metasploit against the honeypot, mimicking real-world exploits.

Wireshark: Use Wireshark to monitor all traffic going to and from your honeypot. You can inspect packets and verify that the honeypot is capturing all traffic correctly.

Exposing the Honeypot to the Internet
To test your honeypot in a real-world scenario, you can expose it to the internet, but this is risky. Ensure that you run this honeypot in an isolated environment, like a virtual machine, to prevent potential security risks.

Port Forwarding: Set up port forwarding on your router to expose the honeypot's ports (8080, 21, 2222) to the outside world.
Monitor Logs: Continuously monitor logs in the honeypot.db or the Flask dashboard for incoming attacks.
Troubleshooting
If the honeypot fails to bind to certain ports (e.g., SSH on port 22), ensure no other service (like OpenSSH) is running on that port.
Use a tool like netstat or ss to check which services are using specific ports:

sudo ss -tuln
