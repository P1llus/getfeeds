import requests
import re
from OTXv2 import OTXv2
from collections import defaultdict
from datetime import datetime, timedelta

"""
    File name: getfeeds.py
    Author: Marius Iversen
    Date created: 9/11/2016
    Date last modified: 10/11/2016
    Python Version: 2.7.12
"""

# Initate the list that will store all the information to be printed out later
d = defaultdict(list)


# Function to grab files from the internet
def download_file(url):
    r = requests.get(url)
    return r.content


# Function you can use to grab only IP's from different types of data
def ipgrabber(results):
    ip = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', results)
    return ip


# AlienVault Feed | IP, Domain and URL
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


# Malc0de feed | IP
def get_malc0de():
    url = 'http://malc0de.com/bl/IP_Blacklist.txt'
    results = download_file(url).splitlines()
    for result in results:
        if len(result) > 0:
            ip = ipgrabber(result.lstrip().rstrip())
            if ip:
                d['malc0deip'].append(result)
    return d


#Cisco TalosIntel(Old Snort feed) | IP
def get_talosintel():
    url = 'http://www.talosintelligence.com/feeds/ip-filter.blf'
    results = download_file(url).splitlines()
    for result in results:
        if len(result) > 0:
            ip = ipgrabber(result.lstrip().rstrip())
            if ip:
                d['talosintelip'].append(result)
    return d


# MalwareDomainList Feed | IP and Domain
def get_malwaredomainlist():
    url = 'http://www.malwaredomainlist.com/hostslist/ip.txt'
    url2 = 'http://www.malwaredomainlist.com/hostslist/hosts.txt'
    results = download_file(url).splitlines()
    results2 = download_file(url2).splitlines()
    for result in results:
        if len(result) > 0:
            ip = ipgrabber(result.lstrip().rstrip())
            if ip:
                d['malwaredomainlistip'].append(result)
    for result in results2:
        result = result.lstrip('127.0.0.1  , ').rstrip()
        if not result.startswith('#') and not result.startswith('localhost') and len(result) > 0:
            d['malwaredomainlistdomain'].append(result)
    return d


# Grab all TOR exit nodes
def get_tornodes():
    url = 'https://check.torproject.org/exit-addresses'
    results = download_file(url).splitlines()
    for result in results:
        if len(results) > 0:
            ip = ipgrabber(result.lstrip().rstrip())
            if ip:
                d['tornodeip'].append(ip)
    return d


# RansomewareTracker Feed | IP and Domain
def get_ransomwaretracker():
    url = 'https://ransomwaretracker.abuse.ch/feeds/csv/'
    results = download_file(url).splitlines()
    for result in results:
        if len(result) > 0:
            ip = ipgrabber(result.lstrip().rstrip())
            for singleip in ip:
                d['ransomwaretrackerip'].append(singleip)
    for result in results:
        if re.search(r'\"online\"', result):
            for url in re.findall(r',\"\w+\.\w+\"', result):
                url = re.sub(',"', '\"', url)
                url = re.sub('"', '', url)
                d['ransomewaretrackerdomain'].append(url)
    return d


# Bambenek security feed | IP and Domain
def get_bambenek():
    url = 'https://osint.bambenekconsulting.com/feeds/c2-ipmasterlist.txt'
    url2 = 'http://osint.bambenekconsulting.com/feeds/c2-dommasterlist.txt'
    results = download_file(url).splitlines()
    results2 = download_file(url2).splitlines()
    for result in results:
        if len(result) > 0:
            ip = ipgrabber(result.lstrip().rstrip())
            if ip:
                d['bambenekip'].append(ip)
    for result in results2:
        if not result.startswith('#') and not result.startswith('localhost') and len(result) > 0:
            url = result.split(",")[0]
            d['bambenekdomain'].append(url)
    return d


# Main function, that will run all our definitions and create the list
def main():
    #get_malc0de()
    #get_alienvault()
    #get_talosintel()
    #get_malwaredomainlist()
    #get_tornodes()
    #get_bambenek()
    get_ransomwaretracker()
    print "RansomwareTracker IP list is", len(d['ransomwaretrackerip']), " lines long"
    print "RansomwareTracker Domain list is", len(d['ransomewaretrackerdomain']), " lines long"
    print "Babenek Domain list is", len(d['bambenekdomain']), " lines long"
    print "Bambenek IP list is", len(d['bambenekip']), " lines long"
    print "Tor IP list is",len(d['tornodeip']), " lines long"
    print "AlienVault IP list is",len(d['alienvaultip']), " lines long"
    print "AlienVault URL list is", len(d['alienvaulturl']), " lines long"
    print "AlienVault Domain list is", len(d['alienvaultdomain']), " lines long"
    print "Malc0deIP list is",len(d['malc0deip']), " lines long"
    print "TalosintelIP list is",len(d['talosintelip']), " lines long"
    print "MDLIPs list is",len(d['malwaredomainlistip']), " lines long"
    print "MDLDomains list is" ,len(d['malwaredomainlistdomain'])," lines long"
    print [s + "\thello" for s in d['ransomwaretrackerip']]

if __name__ == "__main__":
    main()

