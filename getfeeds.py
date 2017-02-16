#!/usr/bin/env python3

"""
Script that gathers information from open source Threat Intelligence feeds| Made by Marius Iversen
"""

import re
import requests
from OTXv2 import OTXv2

from collections import defaultdict
from datetime import datetime, timedelta

d = defaultdict(list)

#CONFIGURATION

# Your API key for OTX. If you do not wish to use this, please comment out
# "get_alienvault" in the main function at the bottom.
otx = OTXv2("XXX")

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

# If a new feed is added, please provide a function for this feed as well. The reason this is done, is that
# all feeds have different formats when returned.


# Define the main class
class getFeeds(object):
    def download_file(self, url):
        """
        Download the feeds specified
        :param url: The location of the source to download
        :return The content of the request
        """

        r = requests.get(url)
        return r.text

    def ipgrabber(self, results):
        """
        Runs a regular expression on a object to find all the ip addresses
        :param results: The results that should be filtered
        :return: Only the IP addresses from the object it filtered out
        """

        ip = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', results)
        return ip

    def get_source(self, url, key):
        """
        Formats and appends IP addresses to the belonging list
        :param url: The variable at the top storing the url
        :param key: The key to be used in the list generation
        :return: A formated version of a ip list
        """

        for line in self.download_file(url).splitlines():
            if len(line) > 0:
                ips = self.ipgrabber(line.lstrip().rstrip())
                if ips:
                    for ip in ips:
                        d[key].append(ip)

    def write_list(self, f, key, name):
        """
        Writes different lists to the txt files mentioned
        :param f: The open file
        :param key: The key used in the list, for example "malc0deip"
        :param name: The name you want to have after the IP's or domains in the
        output file
        :return: Writing the list to a file in the supported format.
        """

        f.write("".join("{}\t[{}]\n".format(t, name) for t in d[key]))

    def get_alienvault(self, days):
        """
        Gets the information from Alienvault OTX
        :param days: How many days the reslts from the feed can be
        :return: List of IP addresses and domains from the specific feed
        """

        pulses = otx.getsince((datetime.now() - timedelta(days=days)).isoformat())
        mappings = {'IPv4': 'alienvaultip', 'URL': 'alienvaulturl',
                    'domain': 'alienvaultdomain'}
        for index, feeds in enumerate(pulses):
            for pulse in pulses[index]['indicators']:
                t = pulse['type']
                if t in mappings:
                    d[mappings[t]].append(pulse['indicator'])

    def get_malc0de(self):
        """
        Gets the information from the Malc0de Feed
        :return: List of IP addresses and domains from the specific feed
        """

        self.get_source(malc0de, 'malc0deip')

    def get_talosintel(self):
        """
        Gets the information from the TalosIntel Feed
        :return: List of IP addresses and domains from the specific feed
        """

        self.get_source(talosintel, 'talosintelip')

    def get_malwaredomainlist(self):
        """
        Gets the information from the MDL Feed
        :return: List of IP addresses and domains from the specific feed
        """

        self.get_source(mdlip, 'malwaredomainlistip')
        domains = self.download_file(mdldomain).splitlines()
        for domain in domains:
            domain = domain.lstrip('127.0.0.1  , ').rstrip()
            if not domain.startswith('#') and not domain.startswith(
                    'localhost') and len(domain) > 0:
                d['malwaredomainlistdomain'].append(domain)

    def get_tornodes(self):
        """
        Gets the information from the Torproject overview
        :return: List of IP addresses and domains from the specific feed
        """

        self.get_source(tornodes, 'tornodeip')

    def get_ransomwaretracker(self):
        """
        Gets the information from the RansomewareTracker Feed
        :return: List of IP addresses and domains from the specific feed
        """

        self.get_source(ransomwaretracker, 'ransomwaretrackerip')
        domains = self.download_file(ransomwaretracker).splitlines()
        for domain in domains:
            if re.search(r'\"online\"', domain):
                for url in re.findall(r',\"\w+\.\w+\"', domain):
                    url = re.sub(',"', '\"', url)
                    url = re.sub('"', '', url)
                    d['ransomewaretrackerdomain'].append(url)

    def get_bambenek(self):
        """
        Gets the information from the RansomewareTracker Feed
        :return: List of IP addresses and domains from the specific feed
        """

        self.get_source(bambeip, 'bambenekip')
        domains = self.download_file(bambedomain).splitlines()
        for domain in domains:
            if not domain.startswith('#') \
                    and not domain.startswith('localhost') and len(domain) > 0:
                url = domain.split(",")[0]
                d['bambenekdomain'].append(url)

    # Executes the feeds that you want, please comment out feeds that is not needed.
    def main(self):
        self.get_malc0de()
        #self.get_alienvault(days)
        self.get_talosintel()
        self.get_malwaredomainlist()
        self.get_tornodes()
        self.get_bambenek()
        self.get_ransomwaretracker()

        # Export IP Addresses to a txt file, tagged with their sources.
        with open("iplist.txt", "w") as f:
            self.write_list(f, 'ransomwaretrackerip', 'Ransomewaretracker')
            self.write_list(f, 'bambenekip', 'Bambenek')
            self.write_list(f, 'alienvaultip', 'AlienVault')
            self.write_list(f, 'malc0deip', 'Malc0de')
            self.write_list(f, 'talosintelip', 'TalosIntel')
            self.write_list(f, 'malwaredomainlistip', 'MalwareDomainList')
            self.write_list(f, 'tornodeip', 'TornodeIP')
            f.close()

        # Export domains to txt file, tagged with their sources
        with open("domainlist.txt", "w") as f:
            self.write_list(f, 'ransomwaretrackerdomain', 'Ransomewaretracker')
            self.write_list(f, 'bambenekdomain', 'Bambenek')
            self.write_list(f, 'alienvaultdomain', 'AlienVault')
            self.write_list(f, 'malwaredomainlistdomain', 'MalwareDomainList')
            f.close()

# Execute main class when script is run
if __name__ == "__main__":
    feed = getFeeds()
    feed.main()