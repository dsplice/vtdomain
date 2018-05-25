#!/usr/bin/env python
"""This scritp takes a Virustotal API key, a file of domains to search for,
and an optional rate argument to search for VT results against the domains."""

__author__ = 'Derek Armstrong'
__email__ = 'derek.v.armstrong@gmail.com'
__version__ = '0.0.2'
__date__ = '05/25/2018'
__copyright__ = 'Copyright 2018, Derek Armstrong'
__license__ = 'Apache'
__maintainer__ = 'Derek Armstrong'
__status__ = 'Prototype'

# VT SCAN EULA
# ------------
# By using the upload/ scan API, you consent to virustotal
# Terms of Service (https://www.virustotal.com/en/about/terms-of-service/)
# and allow VirusTotal to share this file with the security community.
# See virustotal Privacy Policy (https://www.virustotal.com/en/about/privacy/) for details.
#

import json
import time
import argparse
import sys

try:
    import requests
except ImportError:
    print("[Warning] request module is missing. requests module is required in order to \
	upload new files for scan.  You can install it by running: pip install requests.")
    sys.exit(1)

def retr_domain_detect_score(apikey, vtdomain):
    """Takes apikey and domain to search VirusTotal with.  Returns float score"""
    params = {'apikey': apikey, 'domain': vtdomain}
    vturl = 'https://www.virustotal.com/vtapi/v2/domain/report'
    try:
        response = requests.get(vturl,
                                params=params,
                                proxies=None,
                                timeout=30)
    except NameError:
        print("An Unknown Request Error Occurred", file=sys.stderr)
        return -1

    if response.status_code == 200:
        totalpos = 0
        totalall = 0
        resmap = json.loads(response.text)
        if resmap["verbose_msg"] == "Domain not found":
            return 0
        urldetected = resmap["detected_urls"]
        for result in urldetected:
            totalpos += result["positives"]
            totalall += result["total"]
        if totalall == 0:
            return 0
        return totalpos / totalall * 1000
    else:
        print("An Error Occurred", file=sys.stderr)
        return -1


if __name__ == "__main__":
    PARSER = argparse.ArgumentParser(description="Search for URL detections in \
	Virustotal for given domains.")
    PARSER.add_argument("api", help="Your VirusTotal API Key", type=str)
    PARSER.add_argument("file", help="File with a list of domains to scan, type=str")
    PARSER.add_argument("--rate",
                        help="Enter in your API key rate (requests/minute)",
                        type=int,
                        default=4)
    ARGS = PARSER.parse_args()
    APIKEY = ARGS.api
    RATE = ARGS.rate
    FILE = ARGS.file

    if (APIKEY and RATE and FILE):
        SLEEP = 60/RATE
        try:
            FD = open(FILE, 'r')
        except FileNotFoundError:
            print("Could not read from file {0}".format(FILE), file=sys.stderr)
        else:
            for domain in FD:
                score = retr_domain_detect_score(APIKEY, domain.strip())
                print("{0}, {1:.3f}".format(domain.strip(), score))
                time.sleep(SLEEP)
        FD.close()
    else:
        print(ARGS)
