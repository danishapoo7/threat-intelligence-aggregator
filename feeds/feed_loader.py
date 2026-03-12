import requests
import csv
from .feed_sources import FEEDS


def load_feeds():

    all_data = []

    for url in FEEDS:

        try:

            response = requests.get(
                url,
                timeout=10,
                headers={"User-Agent":"ThreatIntelAggregator"}
            )

            # limit large feeds
            text = response.text.splitlines()[:5000]

            if "json" in url:

                data = response.json()

                if isinstance(data, dict):
                    for item in data.get("data",[]):
                        all_data.append(str(item))

            elif "csv" in url:

                reader = csv.reader(text)

                for row in reader:
                    all_data.append(" ".join(row))

            else:

                all_data.extend(text)

        except Exception as e:

            print("Error loading feed:",url,e)

    return all_data