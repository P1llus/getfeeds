#!/usr/bin/env python2

"""
Intelligence feeds script | Made by Marius Iversen
"""

import requests
import re

from OTXv2 import OTXv2
from collections import defaultdict
from datetime import datetime, timedelta

# Defines the list that is going to populate the different feeds
d = defaultdict(list)

# Your API key for OTX. If you do not have any, please comment out
# "get_alienvault" in the main function.
otx = OTXv2("OTXAPIKEY")

# Amount of days old feeds you want to get returned (Alienvault OTX only)
days = 10

# Feeds
malc0de = 'http://malc0de.com/bl/IP_Blacklist.txt'
talosintel = 'http://www.talosintelligence.com/feeds/ip-filter.blf'
mdlip = 'http://www.malwaredomainlist.com/hostslist/ip.txt'
mdldomain = 'http://www.malwaredomainlist.com/hostslist/hosts.txt'
tornodes = 'https://check.torproject.org/exit-addresses'
ransomwaretracker = 'https://ransomwaretracker.abuse.ch/feeds/csv/'
bambeip = 'https://osint.bambenekconsulting.com/feeds/c2-ipmasterlist.txt'
bambedomain = 'http://osint.bambenekconsulting.com/feeds/c2-dommasterlist.txt'


def download_file(url):
    """
    Download the feeds specified
    :param url: The location of the source to download
    :return The content of the request
    """

    r = requests.get(url)
    return r.content

def ipgrabber(results):
    """
    Runs a regular expression on a object to find all the ip addresses
    :param results: The results that should be filtered
    :return: Only the IP addresses from the object it filtered out
    """

    ip = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', results)
    return ip

def get_source(url, key):
    """
    Formats and appends IP addresses to the belonging list
    :param url: The variable at the top storing the url
    :param key: The key to be used in the list generation
    """
    for line in download_file(url).splitlines():
        if len(line) > 0:
            ips = ipgrabber(line.lstrip().rstrip())
            if ips:
                for ip in ips:
                    d[key].append(ip)

def write_list(f, key, name):
    f.write("".join("{}\t[{}]\n".format(t, name) for t in d[key]))

def get_alienvault(days):
    """
    Gets the information from Alienvault OTX
    :param days: How many days the reslts from the feed can be
    """

    pulses = otx.getsince((datetime.now() - timedelta(days=days)).isoformat())
    mappings = {'IPv4': 'alienvaultip', 'URL': 'alienvaulturl',
                'domain': 'alienvaultdomain'}
    for index, feeds in enumerate(pulses):
        for pulse in pulses[index]['indicators']:
            t = pulse['type']
            if t in mappings:
                d[mappings[t]].append(pulse['indicator'])

def get_malc0de():
    """
    Gets the information from the Malc0de Feed
    """

    get_source(malc0de, 'malc0deip')

def get_talosintel():
    """
    Gets the information from the TalosIntel Feed
    """

    get_source(talosintel, 'talosintelip')

def get_malwaredomainlist():
    """
    Gets the information from the MDL Feed
    """

    get_source(mdlip, 'malwaredomainlistip')
    domains = download_file(mdldomain).splitlines()
    for domain in domains:
        domain = domain.lstrip('127.0.0.1  , ').rstrip()
        if not domain.startswith('#') and not domain.startswith(
                'localhost') and len(domain) > 0:
            d['malwaredomainlistdomain'].append(domain)

def get_tornodes():
    """
    Gets the information from the Torproject overview
    """

    get_source(tornodes, 'tornodeip')

def get_ransomwaretracker():
    """
    Gets the information from the RansomewareTracker Feed
    """

    get_source(ransomwaretracker, 'ransomwaretrackerip')
    domains = download_file(ransomwaretracker).splitlines()
    for domain in domains:
        if re.search(r'\"online\"', domain):
            for url in re.findall(r',\"\w+\.\w+\"', domain):
                url = re.sub(',"', '\"', url)
                url = re.sub('"', '', url)
                d['ransomewaretrackerdomain'].append(url)

def get_bambenek():
    """
    Gets the information from the RansomewareTracker Feed
    """

    get_source(bambeip, 'bambenekip')
    domains = download_file(bambedomain).splitlines()
    for domain in domains:
        if not domain.startswith('#') \
                and not domain.startswith('localhost') and len(domain) > 0:
            url = domain.split(",")[0]
            d['bambenekdomain'].append(url)

# Executes the downloading and parsing of feeds
def main():
    get_malc0de()
    #get_alienvault(days)
    get_talosintel()
    get_malwaredomainlist()
    get_tornodes()
    get_bambenek()
    get_ransomwaretracker()

    # Export IP Addresses to txt file, tagged with their sources
    with open("iplist.txt", "w") as f:
        write_list(f, 'ransomwaretrackerip', 'Ransomewaretracker')
        write_list(f, 'bambenekip', 'Bambenek')
        write_list(f, 'alienvaultip', 'AlienVault')
        write_list(f, 'malc0deip', 'Malc0de')
        write_list(f, 'talosintelip', 'TalosIntel')
        write_list(f, 'malwaredomainlistip', 'MalwareDomainList')
        write_list(f, 'tornodeip', 'TornodeIP')
        f.close()

        # Export domains to txt file, tagged with their sources
    with open("domainlist.txt", "w") as f:
        write_list(f, 'ransomwaretrackerdomain', 'Ransomewaretracker')
        write_list(f, 'bambenekdomain', 'Bambenek')
        write_list(f, 'alienvaultdomain', 'AlienVault')
        write_list(f, 'malwaredomainlistdomain', 'MalwareDomainList')
        f.close()

if __name__ == "__main__":
    main()