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
import csv

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
TETRATION_SEARCH_LIMIT = 20

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
Get Hosts with empty hostnames
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
        print(resp.status_code)
        print(resp.text)
        exit(0)
    else:
        return resp.json()

'''
====================================================================================
Resolve empty hostnames by IP Address
------------------------------------------------------------------------------------
'''
def ResolveUnnamedHosts(inventoryList):
    resolved_hosts = []
    for host in inventoryList:
        try:
            addr = dns.reversename.from_address(host["ip"])
            host_name = str(dns.resolver.query(addr,"PTR")[0])
            host.update({"user_" + TETRATION_HOST_NAME_USER_ANNOTATION: host_name[:-1] })
            resolved_hosts.append(host)
        except:
            print("Couldn't resolve IP: {ip}".format(ip=host["ip"]))
            continue
    return resolved_hosts

'''
====================================================================================
Create annotation csv and push to Tetration
------------------------------------------------------------------------------------
'''
def SendAnnotationUpdates(rc,resolved_hosts):
    user_annotations = []
    headerFlag = 0

    for host in resolved_hosts:
        row = dict([(k if not k.startswith('user_') else k.split('user_')[1],v) for k,v in host.items() if k.startswith(('ip', 'vrf_name', 'user_'))])
        row['IP'] = row.pop('ip')
        row['VRF'] = row.pop('vrf_name')
        user_annotations.append(row)
        if headerFlag == 0:
            headers = [key for key in row if key != 'IP' and key != 'VRF']
            headers.insert(0,'VRF')
            headers.insert(0,'IP')
    with open('annotations.csv', 'wb') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=headers)
        writer.writeheader()
        writer.writerows(user_annotations)

    file_path = 'annotations.csv'
    keys = ['IP', 'VRF']

    req_payload = [tetpyclient.MultiPartOption(key='X-Tetration-Key', val=keys), tetpyclient.MultiPartOption(key='X-Tetration-Oper', val='add')]
    resp = rc.upload(file_path, '/assets/cmdb/upload', req_payload)
    if resp.status_code != 200:
        print("Error posting annotations to Tetration cluster")
    else:
        print("Successfully posted annotations to Tetration cluster")

def main():
    rc = CreateRestClient()
    offset = ''
    while True:
        print("Getting offset: {offset}".format(offset=offset))
        unnamed_hosts = GetUnnamedHosts(rc,offset)
        resolved_hosts = ResolveUnnamedHosts(unnamed_hosts["results"])
        SendAnnotationUpdates(rc,resolved_hosts)
        try:
            offset = unnamed_hosts["offset"]
        except:
            break
        time.sleep(2)

if __name__ == "__main__":
    main()
