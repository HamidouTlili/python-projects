Hamidou Proxy Server
Hamidou Proxy Server is a simple, multi-threaded proxy server built in Python. It provides basic authentication and URL filtering to block access to certain websites. This project can be further extended to provide additional features like logging, keyword-based filtering, time-based filtering, etc.

Features
Basic Authentication: Supports authentication using a username and password.
URL Filtering: Blocks access to specific dangerous websites (e.g., malware or phishing sites).
Multithreading: Handles multiple client connections simultaneously using threads.
Customizable Block List: Easily update the list of blocked URLs.
Requirements
Python 3.x
Basic understanding of networking and Python
Setup
Install Dependencies
No external libraries are required for this project, only the built-in Python libraries such as socket, threading, and base64.

How to Run
Clone the repository (or copy the script) to your local machine:

bash
Copier le code
git clone https://github.com/HamidouTlili/hamidou-proxy-server.git
cd hamidou-proxy-server
Run the Proxy Server:

bash
Copier le code
python Hamidouproxy_server.py
Configure your browser or terminal to use the proxy:

For a web browser: Go to your browser’s proxy settings and configure it to use localhost:8080.
For the terminal: Use curl to test requests.
bash
Copier le code
curl -x http://localhost:8080 http://example.com
How to Authenticate
When making a request through the proxy server, the client must provide a valid username and password via the Authorization header. Currently, the server supports these user credentials:

Username: user1

Password: password1

Username: user2

Password: password2

If the credentials are invalid or missing, the server will return a 407 Proxy Authentication Required response.

URL Filtering
The server has a predefined list of dangerous websites that are blocked. These websites can be customized by modifying the blocked_urls list in the script.

By default, the following URLs are blocked:

example.com
malware.com
phishing.com
dangerous-site.com
illegal-downloads.com
When a blocked URL is accessed, the server will return a 403 Forbidden response.

Test the Proxy
You can test the proxy server using curl or a browser:

bash
Copier le code
curl -x http://localhost:8080 http://google.com  # Should pass
curl -x http://localhost:8080 http://malware.com  # Should block
Customization
Add or Remove Users
To add more valid users, modify the VALID_USERS dictionary:

python
Copier le code
VALID_USERS = {"newuser": "newpassword", ...}
Update the Block List
To add or remove URLs from the block list, edit the blocked_urls list:

python
Copier le code
blocked_urls = [
    "new-blocked-site.com",
    ...
]
Change the Proxy Port
To run the proxy on a different port, modify the following line in the script:

python
Copier le code
server.bind(("0.0.0.0", <your-port>))
Future Enhancements
Time-based Filtering: Block specific websites during certain times.
Keyword-based Filtering: Block websites based on keywords in the URL.
Logging: Log all requests made through the proxy for analysis.
Contributing
Feel free to submit issues or pull requests for additional features or improvements.

License
This project is licensed under the MIT License. You are free to use, modify, and distribute this software.
