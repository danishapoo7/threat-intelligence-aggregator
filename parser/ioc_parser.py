import re

IP_PATTERN = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
DOMAIN_PATTERN = r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"
URL_PATTERN = r"https?://[^\s]+"
HASH_PATTERN = r"\b[a-fA-F0-9]{32,64}\b"

def parse_iocs(data):

    ips = set()
    domains = set()
    urls = set()
    hashes = set()

    for line in data:

        # extract URL
        url_match = re.findall(URL_PATTERN, line)
        urls.update(url_match)

        # extract IP
        ip_match = re.findall(IP_PATTERN, line)
        ips.update(ip_match)

        # extract domain
        domain_match = re.findall(DOMAIN_PATTERN, line)
        domains.update(domain_match)

        # extract hash
        hash_match = re.findall(HASH_PATTERN, line)
        hashes.update(hash_match)

    return {
        "ips": list(ips),
        "domains": list(domains),
        "urls": list(urls),
        "hashes": list(hashes)
    }