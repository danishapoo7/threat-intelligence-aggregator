def generate_blocklist(iocs, filename):

    with open(filename, "w") as f:
        for ioc in iocs:
            f.write(ioc + "\n")