from collections import Counter
from scoring.score import calculate_score

def correlate_iocs(iocs):

    counter = Counter(iocs)

    results = []

    for ioc, count in counter.items():

        score, level = calculate_score(count, "ip")

        results.append({
            "ioc": ioc,
            "count": count,
            "score": score,
            "severity": level
        })

    return results