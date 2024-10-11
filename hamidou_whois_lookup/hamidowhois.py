import whois

# Function to perform a WHOIS lookup
def whois_lookup(domain):
    try:
        domain_info = whois.whois(domain)
        print("\nWHOIS Lookup Results:")
        print(f"Domain Name: {domain_info.domain_name}")
        print(f"Registrar: {domain_info.registrar}")
        print(f"Creation Date: {domain_info.creation_date}")
        print(f"Expiration Date: {domain_info.expiration_date}")
        print(f"Name Servers: {', '.join(domain_info.name_servers)}")
        print(f"Registrant Country: {domain_info.country}")
        print(f"Registrant Organization: {domain_info.org}")
    except Exception as e:
        print(f"Error performing WHOIS lookup: {e}")

if __name__ == "__main__":
    domain = input("Enter the domain to lookup: ")
    whois_lookup(domain)
