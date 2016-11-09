from OTXv2 import OTXv2, IndicatorTypes
from collections import defaultdict
import pprint
from datetime import datetime, timedelta
"""
    File name: getfeeds.py
    Author: Marius Iversen
    Date created: 9/11/2016
    Date last modified: 9/11/2016
    Python Version: 2.7.12
"""

# Define API Key for AlienVault OTX
otx = OTXv2("aec68b3658767656b3d93aced4c8f2ea11232c1e2e46acb078692a30a028a174")

mtime = (datetime.now() - timedelta(days=62)).isoformat()
# Get the different feeds and store them in memory

pulses = otx.getsince(mtime)

d = defaultdict(list)

for index, pulseshit in enumerate(pulses):
    for pulse in pulses[index]['indicators']:
        if pulse['type'] == 'IPv4':
            d['IPv4'].append(pulse['indicator'])
        elif pulse['type'] == 'URL':
            d['URL'].append(pulse['indicator'])
        elif pulse['type'] == 'domain':
            d['domain'].append(pulse['indicator'])

pp = pprint.PrettyPrinter(indent=4)

pp.pprint (['IPv4'])
pp.pprint (d['URL'])
pp.pprint (d['domain'])
