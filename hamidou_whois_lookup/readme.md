Hamidou WHOIS Lookup
Overview
The Hamidou WHOIS Lookup project is a simple Python script that performs WHOIS lookups for domain names. It retrieves information such as the domain registrar, creation date, expiration date, name servers, registrant country, and registrant organization. This can be useful for gathering details about domain ownership and registration status.

Features
WHOIS Lookup: Retrieve and display detailed information about a domain, including:
Domain name
Registrar information
Creation and expiration dates
Name servers
Registrant country and organization
Requirements
Python 3.x
whois Python library
You can install the required dependencies with:

pip install python-whois
How to Use
Running the Script:

Run the script using the following command:


python hamidowhois.py
Performing a WHOIS Lookup:

When prompted, enter the domain name you want to look up. The script will perform a WHOIS query and display the results.


Enter the domain to lookup: google.com
Example output:


WHOIS Lookup Results:
Domain Name: ['GOOGLE.COM', 'google.com']
Registrar: MarkMonitor, Inc.
Creation Date: [datetime.datetime(1997, 9, 15, 4, 0), datetime.datetime(1997, 9, 15, 7, 0, tzinfo=datetime.timezone.utc)]
Expiration Date: [datetime.datetime(2028, 9, 14, 4, 0), datetime.datetime(2028, 9, 13, 7, 0, tzinfo=datetime.timezone.utc)]
Name Servers: NS1.GOOGLE.COM, NS2.GOOGLE.COM, NS3.GOOGLE.COM, NS4.GOOGLE.COM, ns4.google.com, ns1.google.com, ns2.google.com, ns3.google.com
Registrant Country: US
Registrant Organization: Google LLC
Error Handling
The script has basic error handling for failed WHOIS lookups. If a lookup fails, an error message will be displayed:


Error performing WHOIS lookup: <error message>
Example Usage
Enter a domain name when prompted to receive the registration details.

Review the output to see the domain information, including the registrar, dates, and name servers.

License
This project is licensed under the MIT License.
