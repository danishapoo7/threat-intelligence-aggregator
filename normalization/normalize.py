from datetime import datetime
import ipaddress

def normalize_iocs(iocs, ioc_type, source, category):

    normalized = []

    timestamp = datetime.utcnow().isoformat()

    for value in iocs:

        if ioc_type == "IP":
            try:
                value = str(ipaddress.ip_address(value))
            except:
                continue

        normalized.append({
            "type": ioc_type,
            "value": value,
            "source": source,
            "timestamp": timestamp,
            "category": category
        })

    return normalized