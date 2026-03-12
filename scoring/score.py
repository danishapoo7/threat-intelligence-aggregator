def calculate_score(count, ioc_type):

    weights = {
        "ip": 5,
        "domain": 4,
        "url": 3,
        "hash": 5
    }

    score = count * weights.get(ioc_type, 1)

    if score >= 20:
        level = "HIGH"
    elif score >= 10:
        level = "MEDIUM"
    else:
        level = "LOW"

    return score, level