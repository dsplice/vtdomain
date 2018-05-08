#!/usr/bin/env python

__author__ = 'Derek Armstrong'
__email__ = 'derek.v.armstrong@gmail.com'
__version__ = '0.0.1'
__date__ = '05/08/2018'
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

import json, time, argparse, sys
try:
    import requests
except ImportError:
    print("[Warning] request module is missing. requests module is required in order to upload new files for scan.  You can install it by running: pip install requests.")
    sys.exit(1)

def retr_domain_detect_score(apikey, domain):
    params = {'apikey': apikey, 'domain': domain}
    vturl = 'https://www.virustotal.com/vtapi/v2/domain/report'
    try:
        response = requests.get(vturl,
                                params=params,
                                proxies=None,
                                timeout=30)
    except:
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
        return (totalpos / totalall * 1000)

    if response.status_code == 204:
        print("Rate Limit Exceeded", file=sys.stderr)
        return -1

    if response.status_code == 400:
        print("Bad Request", file=sys.stderr)
        return -1

    if response.status_code == 403:
        print("Forbidden", file=sys.stderr)
        return -1

    else:
        print("An Unknown Error Occurred", file=sys.stderr)
        return -1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Search for URL detections in Virustotal for given domains.")
    parser.add_argument("api", help="Your VirusTotal API Key", type=str)
    parser.add_argument("file", help="File with a list of domains to scan, type=str")
    parser.add_argument("--rate", help="Enter in your API key rate (requests/minute", type=int, default=4)
    args = parser.parse_args()
    apikey = args.api
    rate = args.rate
    file = args.file

    if (apikey and rate and file):
        sleep = 60/rate
        try:
            f = open(file, 'r')
        except:
            print("Could not read from file {0}".format(file), file=sys.stderr)
        else:
            for domain in f:
                score = retr_domain_detect_score(apikey, domain.strip())
                print("{0}, {1:.3f}".format(domain.strip(), score))
                time.sleep(sleep)
        f.close()
    else:
        print(args)