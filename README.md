### Malware Intelligence feed script

This is a script that is designed to gather intelligence from several security feeds, and save them locally, for use with SIEMS, firewalls, or other security products.

#### Installation
```
git clone https://github.com/P1llus/getfeeds

pip install -r requirements.txt
```

#### Description
```
This script has been made for use with ArcSight SIEM, though the output format (.txt)
 would support anything that supports reading sources from files.

Having this script run in a crontab, on the ArcSight connector, 
and have the Connector parse the file every interval you choose, 
would be the easiest solution.
```
