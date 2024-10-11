Hamidou Port Scanner
Overview
The Hamidou Port Scanner is a simple Python-based tool to scan a range of ports on a target IP address or domain. It supports concurrent scanning for improved performance and integrates Nmap functionality to provide service details for open ports.

Features
Scan a range of ports on a target IP or domain.
Display open ports.
Integrates with Nmap to identify services and their versions on open ports.
Requirements
Python 3.x
nmap library
Install the required dependencies using the following command:


pip install python-nmap
How to Use
Running the Script:

Run the Python script and provide the target IP or domain, along with the start and end ports to scan:

python hamidoport.py
Example output:


Enter the target IP or domain: google.com
Enter the start port: 80
Enter the end port: 443
Open Ports:
Port 80 is open
Port 443 is open
Using Nmap Integration:

If you want to use Nmap to gather service details on the open ports, the script includes a function to achieve that. This will display services and versions running on the open ports.

License
This project is licensed under the MIT License.
