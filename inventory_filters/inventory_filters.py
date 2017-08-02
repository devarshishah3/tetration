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

parser = argparse.ArgumentParser(description='Tetration API Demo Script')
parser.add_argument('--url', help='Tetration URL', required=True)
parser.add_argument('--credential', help='Path to Tetration json credential file', required=True)
parser.add_argument('--csv', help='Path to CSV File', required=True)
args = parser.parse_args()

'''
====================================================================================
Class Constructor
------------------------------------------------------------------------------------
'''
def CreateRestClient():
    rc = RestClient(args.url,
                    credentials_file=args.credential, verify=False)
    return rc

def GetApplicationScopes(rc):
    resp = rc.get('/app_scopes')

    if resp.status_code != 200:
        print("Failed to retrieve app scopes")
        print(resp.status_code)
        print(resp.text)
    else:
        return resp.json()

def GetAppScopeId(scopes,name):
    try:
        return [scope["id"] for scope in scopes if scope["name"] == name][0]
    except:
        print("App Scope {name} not found".format(name=name))

def CreateInventoryFilters(rc,scopes):
    inventoryDict = {}
    with open(args.csv) as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            if row['Comment'] not in inventoryDict:
                inventoryDict[row['Comment']] = {}
                inventoryDict[row['Comment']]['app_scope_id'] = GetAppScopeId(scopes,row['ParentScope'])
                inventoryDict[row['Comment']]['name'] = row['Comment']
                inventoryDict[row['Comment']]['primary'] = row['Restricted'].lower()
                inventoryDict[row['Comment']]['query'] = {
                    "type" : "or",
                    "filters" : []
                }
            if inventoryDict[row['Comment']]['app_scope_id'] != GetAppScopeId(scopes,row['ParentScope']):
                print("Parent scope for {network} does not match previous definition".format(network=row['Network']))
                continue
            inventoryDict[row['Comment']]['query']['filters'].append({
                "type": "subnet",
                "field": "ip",
                "value": row['Network']
            })

    print(json.dumps(inventoryDict,sort_keys=True,indent=4))
    return inventoryDict

def PushInventoryFilters(rc,inventoryFilters):
    for inventoryFilter in inventoryFilters:
        req_payload = inventoryFilters[inventoryFilter]
        resp = rc.post('/filters/inventories', json_body=json.dumps(req_payload))
        if resp.status_code != 200:
            print("Error pushing InventorFilter")
            print(resp.status_code)
            print(resp.text)
        else:
            print("Inventory Filters successfully pushed for " + inventoryFilters[inventoryFilter]["name"])


def main():
    rc = CreateRestClient()
    scopes = GetApplicationScopes(rc)
    inventoryFilters = CreateInventoryFilters(rc,scopes)
    PushInventoryFilters(rc,inventoryFilters)

if __name__ == "__main__":
    main()
