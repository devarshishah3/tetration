# =================================================================================

from tetpyclient import RestClient
import tetpyclient
import json
import requests.packages.urllib3
import sys
import os
import argparse
import time
import dns.resolver, dns.reversename

# =================================================================================

# See reason below -- why verify=False param is used
requests.packages.urllib3.disable_warnings()

# ====================================================================================
# GLOBALS
# ------------------------------------------------------------------------------------

TETRATION_API_URL = "https://172.17.0.4"
TETRATION_API_CRED_PATH = 'perseus-admin.json'
TETRATION_HOST_NAME_USER_ANNOTATION = 'Hostname'
TETRATION_SCOPE_NAME = 'Default'
TETRATION_SEARCH_LIMIT = 10

parser = argparse.ArgumentParser(description='Tetration API Demo Script')
parser.add_argument('--url', help='Tetration URL', required=False)
parser.add_argument('--credential', help='Path to Tetration json credential file', required=False)
parser.add_argument('--annotation', help='User Annotation Field for tracking hostname', required=False)
parser.add_argument('--scope', help='Target scope for DNS resolution', required=False)
parser.add_argument('--limit', help='Results limit for inventory search', required=False)
args = parser.parse_args()

TETRATION_API_URL = args.url if args.url else TETRATION_API_URL
TETRATION_API_CRED_PATH = args.credential if args.credential else TETRATION_API_CRED_PATH
TETRATION_HOST_NAME_USER_ANNOTATION = args.annotation if args.annotation else TETRATION_HOST_NAME_USER_ANNOTATION
TETRATION_SCOPE_NAME = args.scope if args.scope else TETRATION_SCOPE_NAME
TETRATION_SEARCH_LIMIT = args.limit if args.limit else TETRATION_SEARCH_LIMIT

'''
====================================================================================
Class Constructor
------------------------------------------------------------------------------------
'''


def CreateRestClient():
    rc = RestClient(TETRATION_API_URL,
                    credentials_file=TETRATION_API_CRED_PATH, verify=False)
    return rc


'''
====================================================================================
Upload User Annotation CSV
------------------------------------------------------------------------------------
'''


def GetUnnamedHosts(rc,offset):
    req_payload = {
        "filter": {
            "type": "or",
            "filters": [
                {
                    "type": "eq",
                    "field": "hostname",
                    "value": ""
                },
                {
                    "type": "eq",
                    "field": "user_" + TETRATION_HOST_NAME_USER_ANNOTATION,
                    "value": ""
                }
            ]
        },
        "scopeName": TETRATION_SCOPE_NAME,
        "limit": TETRATION_SEARCH_LIMIT,
        "offset": offset if offset else ""
    }
    resp = rc.post('/inventory/search',json_body=json.dumps(req_payload))
    if resp.status_code != 200:
        print resp.status_code
        print resp.text
        exit(0)
    else:
        return resp.json()

def ResolveUnnamedHosts(inventoryList):
    resolved_hosts = []
    for host in inventoryList:
        print host["ip"]
        try:
            addr = dns.reversename.from_address(host["ip"])
            host_name = str(dns.resolver.query(addr,"PTR")[0])
            host.update({"user_" + TETRATION_HOST_NAME_USER_ANNOTATION: host_name })
            resolved_hosts.append(host)
        except:
            print("Couldn't resolve IP: {ip}".format(ip=host["ip"]))
            continue
    print json.dumps(resolved_hosts,sort_keys=True,indent=4)
    return resolved_hosts

def SendAnnotationUpdates(rc,resolved_hosts):
    for host in resolved_hosts:
        user_annotations = dict([(k,v) for k,v in host.items() if k.startswith(('ip', 'vrf', 'user_')) ])
        print user_annotations
        """
        Jeff: user_annotations now contains just ip,vrf,user annotations

        ToDo: Write these values to a csv and send to tetration via the python sdk
        """

def main():
    rc = CreateRestClient()
    offset = ''
    while True:
        print("Getting offset: {offset}".format(offset=offset))
        unnamed_hosts = GetUnnamedHosts(rc,offset)
        resolved_hosts = ResolveUnnamedHosts(unnamed_hosts["results"])
        SendAnnotationUpdates(rc,resolved_hosts)
        offset = unnamed_hosts["offset"]
        if offset is None:
            break
        time.sleep(10)

if __name__ == "__main__":
    main()
