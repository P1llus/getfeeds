import pprint
import requests
import json
from OTXv2 import OTXv2
from collections import defaultdict
from datetime import datetime, timedelta

"""
    File name: getfeeds.py
    Author: Marius Iversen
    Date created: 9/11/2016
    Date last modified: 9/11/2016
    Python Version: 2.7.12
"""

# Initate the list that will store all the information to be printed out later
d = defaultdict(list)


# Function to grab files from the internet
def download_file(url):
    r = requests.get(url)
    return r.content


# AlienVault Feed
def get_alienvault():
    # Define API Key for AlienVault OTX
    otx = OTXv2("aec68b3658767656b3d93aced4c8f2ea11232c1e2e46acb078692a30a028a174")

    # get current time, - the amount of days you want to look back
    mtime = (datetime.now() - timedelta(days=62)).isoformat()

    # Get the different feeds and store them in memory
    pulses = otx.getsince(mtime)

    # Populate the list with the returned results from OTX
    for index, pulseshit in enumerate(pulses):
        for pulse in pulses[index]['indicators']:
            if pulse['type'] == 'IPv4':
                d['alienvaultip'].append(pulse['indicator'])
            elif pulse['type'] == 'URL':
                d['alienvaulturl'].append(pulse['indicator'])
            elif pulse['type'] == 'domain':
                d['alienvaultdomain'].append(pulse['indicator'])
    return d


# Malc0de feed
def get_malc0de():
    url = 'http://malc0de.com/bl/IP_Blacklist.txt'
    results = download_file(url).splitlines()
    for result in results:
        result = result.lstrip().rstrip()
        if not result.startswith('//') and len(result) > 0:
            d['malc0deips'].append(result)
    return d


def main():
    get_malc0de()
    get_alienvault()
    print d['malc0deips']
    print d['alienvaultip']

if __name__ == "__main__":
    main()

