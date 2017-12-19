import logging
#logging.basicConfig(level=logging.DEBUG)

from infoblox_client import connector
import yaml
import json
import tetration
import csv
import argparse
import sys
import requests
from requests.auth import HTTPBasicAuth
import netaddr

# Read in settings
settings = yaml.load(open('settings.yml'))
# Connect to infoblox
conn = connector.Connector(settings['infoblox'])
# Connect to tetration   
rc = tetration.CreateRestClient(settings['tetration'])

def PrettyPrint(target):
    print json.dumps(target,sort_keys=True,indent=4)

def create_filter_csv(filename):
    # Get defined networks
    networks = conn.get_object('network')
    # Find networks with a comment defined
    network_list = [network for network in networks if 'comment' in network]
    with open(filename, "wb") as csv_file:
        writer = csv.writer(csv_file, delimiter=',')
        writer.writerow('Network,Comment,ParentScope,Restricted'.split(','))
        for line in network_list:
            writer.writerow([line["network"],line["comment"],'Default','TRUE'])

def create_ea_csv(filename):
    networks = conn.get_object('network')
    with open(filename, "wb") as csv_file:
        writer = csv.writer(csv_file, delimiter=',')
        writer.writerow('Network View,Network,Comment'.split(','))
        for line in networks:
            writer.writerow([line["network_view"],line["network"],line["comment"] if "comment" in line else ''])

def import_extensible_attributes(filename,eaName,eaValue):
    networks = []
    with open(filename, "rb") as csvFile:
            reader = csv.DictReader(csvFile)
            for row in reader:
                networks.append(row)
    url = 'https://' + settings["infoblox"]["host"] + '/wapi/v' + settings["infoblox"]["wapi_version"] + '/'
    s = requests.Session()
    s.auth = HTTPBasicAuth(settings["infoblox"]["username"],settings["infoblox"]["password"])
    s.verify = False
    s.headers['Content-Type'] = 'application/json'
    
    for network in networks:
        netObj = conn.get_object('network',{'network': network["Network"],'network_view': network["Network View"]})
        req_payload = {
            "extattrs": {
                eaName: {
                    "descendants_action":{
                        "option_with_ea": "RETAIN",
                        "option_without_ea": "INHERIT"
                    },
                    "value": eaValue
                }
            }
        }
        resp = s.put(url + netObj[0]["_ref"],data=json.dumps(req_payload))
        if resp.status_code != 200:
            print("Error while applying extensible attribute: " + eaName)
        else:
            print("Extensible attribute: " + eaName + " added to addresses in" + network["Network"])

def create_network_filters(params):
    # Get Scopes
    scopes = tetration.GetApplicationScopes(rc)
    # Get defined networks
    networks = []
    networks = conn.get_object('network',{'network_view': params["view"]} if params["view"] != '' else None)
    print networks
    if networks is None:
        print("No networks were found in network view: " + params["view"])
        return
    # Find networks with a comment defined
    network_list = [network for network in networks if 'comment' in network]
    # Create API Query for creating inventory filters
    if params["type"].lower() == 'api':
        inventoryFilters = tetration.CreateInventoryFiltersFromApi(rc,scopes,network_list,params['apiParams'])
    else:
        inventoryFilters = tetration.CreateInventoryFiltersFromCsv(rc,scopes,params['csvParams'])
    PrettyPrint(inventoryFilters)
    # Push Filters to Tetration
    tetration.PushInventoryFilters(rc,inventoryFilters)

def annotate_hosts(params):
    hosts = []
    # Read hosts from networks listed in csv
    if params["type"] == 'csv':
        with open(params["csvParams"]["importFilename"], "rb") as csvFile:
            reader = csv.DictReader(csvFile)
            for row in reader:
                hosts.extend(conn.get_object('ipv4address',{'network': row["Network"], 'names~': '.*', '_return_fields': 'network,network_view,names,ip_address,extattrs'}))
                # PrettyPrint(hosts)
    # Read all hosts with a name defined
    else:
        networks = conn.get_object('network',{'network_view': params["view"]} if params["view"] != '' else None)
        for network in [network["network"] for network in networks]:
            host_obj = conn.get_object('ipv4address',{'network': network,'names~': '.*', '_return_fields': 'network,network_view,names,ip_address,extattrs'} if params["view"] == '' else {'network': network, 'names~': '.*', '_return_fields': 'network,network_view,names,ip_address,extattrs','network_view': params["view"]})
            if host_obj is not None:
                hosts.extend(host_obj)
    tetration.AnnotateHosts(rc,hosts,params)

def main():
    parser = argparse.ArgumentParser(description='Tetration Infoblox Integration Script')
    parser.add_argument('--createFilterCsv', help='Filename for creating Filter Csv')
    parser.add_argument('--createEaCsv', help='Filename for creating extensible attributes csv')
    parser.add_argument('--importEaCsv', help='Filename for importing extensible attributes from csv')
    parser.add_argument('--importEaName', help='Extensible attribute name')
    parser.add_argument('--importEaValue', help='Extensible attribute value to be applied to network(s)')
    args = parser.parse_args()

    # Create CSV for defining inventory filters
    if args.createFilterCsv is not None:
        create_filter_csv(args.createFilterCsv)

    if args.createEaCsv is not None:
        create_ea_csv(args.createEaCsv)

    if args.importEaCsv is not None:
        if args.importEaName is None:
            print("Extensible attribute name required (--importEaName)")
            return
        import_extensible_attributes(args.importEaCsv,args.importEaName,args.importEaValue)

    if not len(sys.argv) > 1:
        # Iterate through actions from settings file
        for action,value in ((action,value) for action,value in (settings['actions']).iteritems() if value["enabled"] == True):
            globals()[action](value)

if __name__ == "__main__":
    main()
