import nmap
import socket
from concurrent.futures import ThreadPoolExecutor

# Function to check if a port is open
def scan_port(ip, port):
    try:
        # Create a new socket and attempt to connect to the port
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))  # 0 if port is open
        if result == 0:
            return f"Port {port} is open"
        else:
            return None
    except Exception as e:
        return None
    finally:
        sock.close()

# Function to scan a range of ports
def port_scanner(ip, port_range):
    open_ports = []
    
    with ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(lambda port: scan_port(ip, port), range(port_range[0], port_range[1] + 1))

    # Collect results
    for result in results:
        if result:
            open_ports.append(result)

    return open_ports

if __name__ == "__main__":
    target_ip = input("Enter the target IP or domain: ")
    start_port = int(input("Enter the start port: "))
    end_port = int(input("Enter the end port: "))

    open_ports = port_scanner(target_ip, (start_port, end_port))
    
    if open_ports:
        print("Open Ports:")
        for port in open_ports:
            print(port)
    else:
        print("No open ports found.")
def scan_with_nmap(ip, ports):
    nm = nmap.PortScanner()
    nm.scan(ip, arguments=f'-p {",".join(map(str, ports))} -sV')
    
    for host in nm.all_hosts():
        print(f"Host: {host}")
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                service = nm[host][proto][port]
                print(f"Port {port}: {service['product']} {service['version']}")
