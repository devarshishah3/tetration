#!/opt/ipnb/bin/python
"""
    Exploring ADM results with OpenAPI
"""
__author__ = "Abhishek R. Singh <abhishsi@tetrationanalytics.com>"
__date__ = "21 Aug 2017"
__version__ = "1.0"
__credits__ = "Guido van Rossum, for an excellent programming language."

import atexit
import getopt
import inspect
import os
import pydoc
import readline
import rlcompleter  # pylint: disable=W0611
import StringIO
import shlex
import subprocess
import sys
import traceback

readline.parse_and_bind("tab: complete")

import copy
import datetime as dt
import json
import matplotlib
import pandas as pd
import requests.packages.urllib3

requests.packages.urllib3.disable_warnings()


class ModGlobals:
    """
    Global variables used in this module
    """
    def __init__(self):
        self.verbose = 0
        self.slicing_interval = None
        self.progname = None
        self.rest_client = None
        self.myws = None


def test(a, b, c):
    print "a: %s, b: %s, c: %s" % (a, b, c)

def require_cluster_connect():
    if mod_globals.rest_client is None:
        raise Usage("need to use cluster_connect first")


def require_adm_select():
    if mod_globals.myws is None:
        raise Usage("need to set adm workspace")


class Filter():
    """Primitive filter"""
    primitive_ops = ["eq", "ne", "lt", "lte", "gt", "gte", "in", "regex", "subnet", "contains", "range"]

    def __init__(self, field, op, value, validate):
        assert op in self.primitive_ops, "operator {} undefined".format(op)
        self.op = op
        self.field = field
        self.value = value
        self.validate = validate

    def build(self, table):
        inventory_dims, flow_dims = (mod_globals.inventory_dims, mod_globals.flow_dims)

        if self.validate:
            assert self.field in {"inventory": inventory_dims,
                                  "flow": flow_dims}[table], (self.field, {"inventory": inventory_dims,
                                                                            "flow": flow_dims}[table])
        return {"type" : self.op, "field": self.field, self.value_clause(self.op): self.value}

    def value_clause(self, op):
        if op == "in":
            return "values"
        return "value"

class Query():
    """Query is a complex filter"""
    complex_ops = ["and", "or", "not"]

    def __init__(self, op, verbose=True, validate=True):
        assert op in self.complex_ops, "operator {} undefined".format(op)
        self.op = op
        self.filters = []
        self.endtime = dt.datetime.now()
        self.starttime = None
        self.verbose = verbose
        self.validate = validate

    def set_starttime(self, starttime):
        self.starttime = starttime
        return self

    def set_endtime(self, endtime):
        self.endtime = endtime
        return self

    def add(self, field, op, value):
        self.filters.append(Filter(field, op, value, self.validate))
        return self

    def addq(self, q):
        self.filters.append(q)
        return self

    def build(self, table):
        fstr = {"type": self.op}
        if self.op == "not":
            assert len(self.filters) == 1, "not MUST have ONE filter"
            fstr.update({"filter": self.filters[0].build(table)})
        else:
            fstr.update({"filters": [f.build(table) for f in self.filters]})
        return fstr

    def run(self, kind="inventory", limit=20, **kwargs):
        return {"inventory": self.run_inventory, "flow": self.run_flow}[kind](limit, **kwargs)

    def run_inventory(self, limit, **kwargs):
        inv_cols = ["host_name", "os", "iface_name", "ip", "netmask", "vrf_id", "vrf_name", "tags_scope_name", "host_uuid"]

        req_payload = {"filter": self.build("inventory"), "limit": limit}
        if self.verbose: print json.dumps(req_payload)

        resp = mod_globals.rest_client.post('/{}/search'.format("inventory"), json_body=json.dumps(req_payload))
        if self.verbose: print resp.status_code
        try:
            parsed_resp = json.loads(resp.content)
        except:
            raise Usage(resp.content)
        df = pd.DataFrame(parsed_resp["results"])
        #print json.dumps(parsed_resp, indent=4, sort_keys=True)
        if "offset" in parsed_resp:
            if self.verbose: print(parsed_resp["offset"])
        else:
            if self.verbose: print "found {} entries".format(len(df))
        if len(df):
            df["host_uuid"] = df["host_uuid"].apply(lambda row: row[:8] if row else row)
            return df[inv_cols].sort_values(["host_name", "host_uuid"]).reset_index(drop=True)
        else:
            return df

    def get_flow_cols(self):
        return ["vrf_name", "src_address", "src_hostname", "src_port", "dst_address", "dst_hostname", "dst_port", "proto",
                   "fwd_pkts", "rev_pkts", "fwd_bytes", "rev_bytes"]

    def run_flow(self, limit, **kwargs):
        import datetime as dt

        d_format = "%Y-%m-%dT%H:%M:%S-0700"
        col_cols = [u'bandwidth_bytes_per_second',
                    u'dst_address', ##
                    u'dst_enforcement_epg_name',
                    u'dst_hostname', ##
                    u'dst_is_internal',
                    u'dst_port', ##
                    u'dst_scope_name',
                    u'fwd_ack_count', #
                    u'fwd_allzero_count',
                    u'fwd_bytes', ##
                    u'fwd_cwr_count', u'fwd_ece_count', u'fwd_fin_count', u'fwd_finnoack_count',
                    u'fwd_nc_count', u'fwd_network_latency_usec', u'fwd_null_count', u'fwd_pingdeath_count',
                    u'fwd_pkts', ##
                    u'fwd_psh_count', u'fwd_rst_count', u'fwd_syn_count', u'fwd_synfin_count', #
                    u'fwd_synrst_count', u'fwd_tiny_count', u'fwd_urg_count', u'fwd_xmas_count',
                    u'proto', ##
                    u'rev_ack_count', u'rev_allzero_count',
                    u'rev_bytes', ##
                    u'rev_cwr_count', u'rev_ece_count',
                    u'rev_fin_count', u'rev_finnoack_count', u'rev_nc_count', u'rev_network_latency_usec',
                    u'rev_null_count', u'rev_pingdeath_count',
                    u'rev_pkts', ##
                    u'rev_psh_count', u'rev_rst_count',
                    u'rev_syn_count', u'rev_synfin_count', u'rev_synrst_count', u'rev_tiny_count', u'rev_urg_count',
                    u'rev_xmas_count',
                    u'server_app_latency_usec', u'server_stack_latency_usec',
                    u'src_address', ##
                    u'src_enforcement_epg_name',
                    u'src_hostname', ##
                    u'src_is_internal',
                    u'src_port', ##
                    u'src_scope_name', u'srtt_available', u'srtt_usec', u'start_timestamp',
                    u'timestamp', u'total_network_latency_usec', u'total_perceived_latency_usec',
                    u'vrf_name' ##
                   ]

        col_cols = ["vrf_name", "src_address", "src_hostname", "src_port", "dst_address", "dst_hostname", "dst_port", "proto",
                   "fwd_pkts", "rev_pkts", "fwd_bytes", "rev_bytes"]

        now = self.endtime
        then = self.starttime if self.starttime is not None else (now - dt.timedelta(days=1))

        req_payload = {"filter": self.build("flow"),
                       "limit": limit,
                       "t0": then.strftime(d_format),
                       "t1": now.strftime(d_format)}
        if self.verbose: print req_payload

        resp = mod_globals.rest_client.post('/flowsearch', json_body=json.dumps(req_payload))
        if self.verbose: print resp.status_code
        try:
            parsed_resp = json.loads(resp.content)
        except:
            raise Usage(resp.content)
        df = pd.DataFrame(parsed_resp["results"])
        #print json.dumps(parsed_resp, indent=4, sort_keys=True)
        if "offset" in parsed_resp:
            if self.verbose: print(parsed_resp["offset"])
        else:
            if self.verbose: print "found {} entries".format(len(df))
        if len(df):
            return df#[col_cols]#.sort(columns=["host_name", "host_uuid"]).reset_index(drop=True)
        else:
            return df
        return df


def vrf_name(vrf_id):
    #print "got vrf_id", vrf_id
    vrf_id = int(vrf_id)
    return mod_globals.vrfdf[mod_globals.vrfdf["vrf_id"] == vrf_id]["name"].to_dict().values()[0]


def flat_print(df):
    for i in range(len(df)):
        print "="*40, i, "="*40
        for c in df.columns:
            print "%-24s: %s" % (c, df.iloc[i][c])

def json_print(df):
    for i in range(len(df)):
        print ("="*40, i, "="*40)
        print (json.dumps(json.loads(df.iloc[i].to_json()), indent=2))

def print_by_n(label, values, n=4):
    names = list(values)
    names.sort()
    if len(names) == 0:
        print "%-16s:" % (label)
    else:
        print "%-16s:\n" % (label)
        for i in range((len(names) + n-1)/n):
            print "\t%s" % ("".join(map(lambda x: "%-24s" % x, names[n*i:n*(i+1)])))
    print "\n"

def json_dumps(val):
    print json.dumps(val, indent=2)

def flatten_dict(result, field):
    if result.has_key(field):
        resultcopy = copy.deepcopy(result)
        value = resultcopy[field]
        del resultcopy[field]
        resultcopy.update(dict([("%s.%s" % (field, k), v) for (k, v) in value.items()]))
        yield resultcopy
    else:
        yield result

def flatten_list(result, field):
    if result.has_key(field):
        resultcopy = copy.deepcopy(result)
        value = resultcopy[field]
        del resultcopy[field]
        for v in value:
            ret = copy.deepcopy(resultcopy)
            ret.update({field: v})
            yield ret
    else:
        yield result

def filter_cols(result, filter_out_cols):
    for f in filter_out_cols:
        if result.has_key(f):
            del result[f]

def parse_policies(result):
    filter_out_cols = ["consumer_filter_id", "provider_filter_id"]
    for row1 in result["default_policies"]:
        for row2 in flatten_list(row1, "l4_params"):
            for row3 in flatten_dict(row2, "l4_params"):
                ret = row3
                ret["l4_params.port"] = ",".join(map(str, set(ret["l4_params.port"])))
                ret["protocol"] = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(ret["l4_params.proto"], ret["l4_params.proto"])
                filter_cols(ret, filter_out_cols)
                yield ret

def parse_filters(results):
    filter_out_cols = ["id", "parent_app_scope.id"]
    for result in results:
        for row in flatten_dict(result, "parent_app_scope"):
            #for row2 in flatten_dict(row, "query"):
                #for row3 in flatten_list(row2, "query.filters"):
                #    for row4 in flatten_dict(row3, "query.filters"):
                #        for row5 in flatten_list(row4, "query.filters.filters"):
                #            for row6 in flatten_dict(row5, "query.filters.filters"):
                                ret = row
                                filter_cols(ret, filter_out_cols)
                                yield ret
def parse_clusters(results):
    for row in results:
        for row2 in flatten_list(row, "nodes"):
            for row3 in flatten_dict(row2, "nodes"):
                for row4 in flatten_dict(row3, "parent_application"):
                    del row4["id"]
                    if row4.has_key("parent_application.id"):
                        del row4["parent_application.id"]
                    yield row4

def get_filter(name, verbose=False):
    f = mod_globals.filterdf[mod_globals.filterdf["name"] == name]["query"].to_dict().values()[0]
    if verbose:
        json_dumps(f)
    return f


def make_flow_filter(f, dirn):
    #print "got", f
    if isinstance(f, list):
        for a in f:
            make_flow_filter(a, dirn)
        return

    if f.get("field", None) == "ip":
        f["field"] = dirn + "_address"
    if f.get("field", None) == "host_name":
        f["field"] = dirn + "_hostname"

    if 0:
        if f.get("field", "") in ["user_Tenant", "user_ACI-Fabric", "user_ANP", "user_EPG"]:
            f["field"] = "src_port"
            f["type"] = "ne"
            f["value"] = "-1"
    if f.get("field", "")[:4] == "user":
        f["field"] = "user_" + dirn + f["field"][4:]

    if f.has_key("filters"):
        make_flow_filter(f["filters"], dirn)

def make_query(f, verbose=False):
    def build_query(q, f, verbose):
        #print "got", json_dumps(f)
        if f.has_key("field"):  # simple
            if f["field"] == "vrf_id":
                f["field"] = "vrf_name"
                f["value"] = vrf_name(f["value"])
            if q is None:
                q = Query("and", verbose=verbose, validate=True)
            q.add(f["field"], f["type"], f["value"])
            return q
        else:  # complex
            q1 = Query(f["type"], verbose=verbose, validate=True)
            for item in f["filters"]:
                build_query(q1, item, verbose)
            if q is None:
                q = q1
            else:
                q.addq(q1)
            return q

    q = build_query(None, f, verbose)
    return q

def find_distinct(query, fname, start_time, end_time, max_cnt, verbose=False):
    if max_cnt <= 0:
        return set()

    end1 = start_time + dt.timedelta(days=1)
    end = end_time if end1 > end_time else end1
    if False:
        print """{"start"="%s", "end"="%s", "proposed"="%s", "actual"="%s"}""" % (start_time, end_time, end1, end)
    df = (query
          .set_starttime(start_time)
          .set_endtime(end)
          .run("flow", limit=1000))
    if len(df) == 0:
        if end != end_time:
            return find_distinct(query, fname, start_time + dt.timedelta(days=1), end_time, max_cnt, verbose)
        else:
            return set()

    #display(df)
    distinct = set(df[fname].tolist())

    q = Query("or", verbose=verbose, validate=True)
    for d in distinct:
        #print fname, d
        q.add(fname, "eq", d)

    return distinct.union(find_distinct(Query("and", verbose)
     .addq(query)
     .addq(Query("not", verbose=verbose, validate=True)
           .addq(q)), fname, start_time, end_time, max_cnt - len(distinct), verbose))

def filter_members(name, filter_is_client, protocol, port, cluster_members, t0, t1, max_cnt, verbose=False):
    if filter_is_client:
        filter_dirn = "src"
        filter_addr = "src_address"
        cluster_address = "dst_address"
    else:
        filter_dirn = "dst"
        filter_addr = "dst_address"
        cluster_address = "src_address"

    f = copy.deepcopy(get_filter(name, False))
    make_flow_filter(f, filter_dirn)
    if verbose: print json_dumps(f)
    flow_query = make_query(f, verbose=verbose)

    if verbose: print name, ":", protocol, port
    policy_query = (Query("and", verbose=verbose, validate=True)
                    .add("proto", "eq", protocol).add("dst_port", "eq", port))

    cluster_query = Query("or", verbose=verbose, validate=True)
    for m in cluster_members:
        cluster_query.add(cluster_address, "eq", m)

    field_query = Query("not", verbose=verbose, validate=True)
    field_query.add(filter_addr, "eq", "")

    members = list(find_distinct(Query("and", verbose=verbose, validate=True)
                                        .addq(flow_query)
                                        .addq(field_query)
                                        .addq(policy_query)
                                        .addq(cluster_query),
                                        filter_addr,
                                        t0, t1, max_cnt, verbose))
    print_by_n(name + "(%s%s)" % (len(members), "+" if len(members) >= 100 else ""), members)


# globals
mod_globals = ModGlobals()  # pylint: disable=C0103


def cluster_members(name, verbose=True):
    """
    Shows members of an adm cluster
        Usage: cluster_members <name>
    """
    require_adm_select()
    members = mod_globals.clustersdf[mod_globals.clustersdf["name"] == name]["nodes.ip"].tolist()
    if verbose:
        print_by_n(name, members)
    return members


def show_nodes(policy_idx, max_cnt = 100, verbose=False):
    """
    Expand nodes for ADM policy at given index
        Usage: show_nodes <policy_idx>
    """
    require_adm_select()
    policy_idx = int(policy_idx)
    t0 = mod_globals.t0
    t1 = mod_globals.t1
    policy = mod_globals.policydf.iloc[policy_idx]

    if policy["ctype"] == "cluster":
        cluster_members(policy["consumer_filter_name"])
    else:
        filter_members(policy["consumer_filter_name"], True,
                       policy["protocol"], policy["l4_params.port"],
                       cluster_members(policy["provider_filter_name"], False), t0, t1, max_cnt, verbose)

    if policy["ptype"] == "cluster":
        cluster_members(policy["provider_filter_name"])
    else: # ptype is filter
        filter_members(policy["provider_filter_name"], False,
                       policy["protocol"], policy["l4_params.port"],
                       cluster_members(policy["consumer_filter_name"], False), t0, t1, max_cnt, verbose)


def show_all_nodes():
    """
    Expand nodes for all ADM generated policies
    """
    import time
    for i in mod_globals.policydf.index[:]:
        print "*"*40, i, "*"*40
        flat_print(mod_globals.policydf[i:i+1][mod_globals.cols])
        show_nodes(i)


def cluster_connect(where, api_key, api_secret):
    """
    Connect to cluster
        Usage: cluster_connect westvleteren.insbu.net <api-key> <api-secret>
    """
    print("Doc link: https://{}/documentation/ui/openapi/api_inventorysearch.html".format(where))

    API_ENDPOINT="https://{}".format(where)
    from tetpyclient.tetpyclient import RestClient
    mod_globals.rest_client = RestClient(API_ENDPOINT, api_key=api_key, api_secret=api_secret, verify=False)
    mod_globals.inventory_dims = json.loads(mod_globals.rest_client.get('/openapi/v1/inventory/search/dimensions').content) + ["vrf_name"]
    mod_globals.flow_dims = json.loads(mod_globals.rest_client.get('/openapi/v1/flowsearch/dimensions').content) + ["vrf_name"]

    rc = mod_globals.rest_client.get("/vrfs")
    mod_globals.vrfdf = pd.DataFrame(json.loads(rc.content))


def show_nodes_for(src, dst, protocol, port, max_cnt="100", verbose="False"):
    """
    Expand cluster/filter members in adm policy
        Usage: show_nodes_for <src-filter> <dst-filter> <protocol> <port> [max_cnt] [verbose]
    """
    require_adm_select()
    t0 = mod_globals.t0
    t1 = mod_globals.t1

    verbose = False if verbose == "False" else True
    max_cnt = int(max_cnt)

    def is_adm_generated(name):
        return name not in mod_globals.set_filters

    if is_adm_generated(src):
        cluster_members(src, False)
    else:
        filter_members(src, True, protocol, port, cluster_members(dst, False), t0, t1, max_cnt, verbose)

    if is_adm_generated(dst):
        cluster_members(dst)
    else: # ptype is filter
        filter_members(dst, False, protocol, port, cluster_members(src, False), t0, t1, max_cnt, verbose)


def show_groupings():
    """
    Shows internal and external ADM clusters as well as filters
    """
    require_adm_select()

    print_by_n("iclusters", mod_globals.set_inclusters, 1)
    print_by_n("oclusters", mod_globals.set_outclusters, 1)
    print_by_n("filters", mod_globals.set_filters, 1)


def show_absolute_policies():
    """
    Shows absolute policies for workspace
    """
    require_adm_select()
    flat_print(pd.DataFrame(mod_globals.result["absolute_policies"]))#[["action", "consumer_filter_name", "provider_filter_name", "l4_params"]]


def show_adm_policies_intra():
    """
    Shows (filtered) intra cluster policies generated by ADM
    """
    require_adm_select()
    flat_print(mod_globals.policydf[
        (mod_globals.policydf["ctype"] == "cluster") &
        (mod_globals.policydf["ptype"] == "cluster") &
        (mod_globals.policydf["cctype"] == "in") &
        (mod_globals.policydf["pctype"] == "in")
    ][mod_globals.clustercols])


def show_adm_policies(*args):
    """
    Shows policies generated by ADM
        Usage show_adm_policies [index]
    """
    require_adm_select()
    if len(args) > 0:
        i = int(args[0])
        flat_print(mod_globals.policydf.iloc[i:i+1][mod_globals.cols])
    else:
        flat_print(mod_globals.policydf[mod_globals.cols])


def set_adm_workspace(index, t0, t1):
    """
    Selects adm workspace by index. Use show_adm_workspace to find index to use. The time range of adm run needs to be specified
        Usage: set_adm_workspace <name> 201708261600 201708272020
    """
    require_cluster_connect()
    index = int(index)

    batch_format = "%Y%m%d%H%M"
    mod_globals.t0 = dt.datetime.strptime(t0, batch_format)
    mod_globals.t1 = dt.datetime.strptime(t1, batch_format)

    rc = mod_globals.rest_client.get('/openapi/v1/applications')
    result = json.loads(rc.content)
    mod_globals.admdf = pd.DataFrame(result)

    mod_globals.myws = mod_globals.admdf.iloc[index:index+1]
    flat_print(mod_globals.myws)
    mod_globals.myws

    rc = mod_globals.rest_client.get('/openapi/v1/applications/{}/details'.format(mod_globals.myws["id"].to_dict().values()[0]))
    mod_globals.result = json.loads(rc.content)
    mod_globals.result0 = copy.deepcopy(mod_globals.result) # take a backup, so we can iterate on the code below

    mod_globals.result = copy.deepcopy(mod_globals.result0)
    mod_globals.policydf = pd.DataFrame(parse_policies(mod_globals.result))
    mod_globals.set_consumers = set(mod_globals.policydf["consumer_filter_name"].to_dict().values())
    mod_globals.set_providers = set(mod_globals.policydf["provider_filter_name"].to_dict().values())
    mod_globals.cols = ["consumer_filter_name", "provider_filter_name", "action", "protocol", "l4_params.port", "priority"]

    mod_globals.filterdf = pd.DataFrame(parse_filters(mod_globals.result["inventory_filters"]))
    mod_globals.set_filters = set(mod_globals.filterdf["name"].to_dict().values())

    mod_globals.clustersdf = pd.DataFrame(parse_clusters(mod_globals.result["clusters"]))

    mod_globals.set_clusters = set(mod_globals.clustersdf["name"].to_dict().values())
    mod_globals.set_inclusters = set(mod_globals.clustersdf[mod_globals.clustersdf["external"] == False]["name"].to_dict().values())
    mod_globals.set_outclusters = set(mod_globals.clustersdf[mod_globals.clustersdf["external"] == True]["name"].to_dict().values())

    mod_globals.policydf["ctype"] = mod_globals.policydf["consumer_filter_name"].apply(lambda x: "filters" if x in mod_globals.set_filters else "cluster")
    mod_globals.policydf["ptype"] = mod_globals.policydf["provider_filter_name"].apply(lambda x: "filters" if x in mod_globals.set_filters else "cluster")
    mod_globals.policydf["cctype"] = mod_globals.policydf["consumer_filter_name"].apply(lambda x: "in" if x in mod_globals.set_inclusters else "out")
    mod_globals.policydf["pctype"] = mod_globals.policydf["provider_filter_name"].apply(lambda x: "in" if x in mod_globals.set_inclusters else "out")

    mod_globals.cols = ["ctype", "consumer_filter_name", "ptype", "provider_filter_name", "action", "protocol", "l4_params.port", "priority"]
    mod_globals.clustercols = copy.copy(mod_globals.cols)
    mod_globals.clustercols.remove("ctype")
    mod_globals.clustercols.remove("ptype")


def show_app_meta():
    """
    Show meta info for currently selected ADM app
    """
    require_adm_select()
    result = mod_globals.result
    def fetch_json_field(json_obj, k):
        for t in k.split("."):
            json_obj = json_obj[t]
        return json_obj

    print "%-20s: %s" % ("created", dt.datetime.fromtimestamp(result["created_at"]))
    meta_fields = ["version", "primary", "catch_all_action", "vrf.name", "vrf.id",
                   "app_scope_id", "id", "name", "author", "description"]
    for k in meta_fields:
        print "%-20s: %s" % (k, fetch_json_field(result, k))


def show_vrfs(*args):
    """
    Shows VRFs in use
    """
    require_cluster_connect()
    flat_print(mod_globals.vrfdf)


def show_adm_workspaces(*args):
    """
    Shows ADM workspaces
    """
    require_cluster_connect()
    rc = mod_globals.rest_client.get('/openapi/v1/applications')
    result = json.loads(rc.content)
    mod_globals.admdf = pd.DataFrame(result)
    flat_print(mod_globals.admdf)


def ip2inventory(*args):
    """
    list inventory items for IPs: e.g. ip2inventory 1.1.1.1 1.1.1.2 ...
    """
    require_cluster_connect()
    num_ips = 0
    q = Query("or", verbose=False)
    for ips in args:
        for ip in ips.split():
            q.add("ip_address", "eq", ip)
            num_ips += 1
    flat_print(q.run("inventory", limit=num_ips))


def help(*args):  # pylint: disable=W0622
    """
    Provide auto-help on functions that have a help string and dont start
    with _ (underscore)
    """
    if len(args) == 0:
        all_functions = [x for x in sys.modules[__name__].__dict__.values() if
                         inspect.isfunction(x) and x.__name__ not in
                         ["main", "onecmd", "cli", "help"]
                         and not x.__name__.startswith("_")]
    else:
        all_functions = [x for x in sys.modules[__name__].__dict__.values() if
                         inspect.isfunction(x) and
                         [a for a in args if x.__name__.startswith(a)]]
    if 0:
        print [x.__name__ for x in all_functions]

    doc_strings = [(i.__name__, i.__doc__) for i in all_functions]
    doc_strings.sort(key=lambda x: x[0], reverse=0)
    # must have doc_string to get printed.
    doc_strings = ['  %-16s\t%s\n' % (i, j) for i, j in doc_strings if
                   j is not None]

    print "".join(doc_strings)
h = help  # pylint: disable=C0103


def onecmd(cmd):
    """
    Call a function based on cmd extraction. Also allows piping of commands.
    """
    if not cmd.strip():
        return
    if not cmd or cmd[0] == "#":
        return  # handle comments
    if cmd == "q":
        raise Usage("Come again, bye !!\n")

    # look for output modifiers
    cmd = cmd.split("|")

    # the main thing, without modifiers
    args = shlex.split(cmd[0])

    bak = sys.stdout
    sys.stdout = StringIO.StringIO()

    if 0:
        print args[0]

    try:
        eval("%s%s" % (args[0], tuple(args[1:])))
    except Usage, err:
        if err.msg:
            print "***", err.msg
    except:
        print sys.exc_info()
        traceback.print_exc(file=sys.stderr)

    ostr = sys.stdout.getvalue()
    sys.stdout = bak

    debug = 0
    use_pager = 0
    if cmd[1:]:  # output modifier processing
        add_nl = 0
        for outmod in cmd[1:]:
            if debug:
                # pylint: disable=C0323
                print >>sys.stderr, "processing OM", outmod
            outmod = shlex.split(outmod)

            # this will make sure only last pager request will persist
            use_pager = 0
            if outmod[0].strip() in ["more", "less"]:
                use_pager = 1
            if debug:
                # pylint: disable=C0323
                print >>sys.stderr, "pager:", use_pager, outmod[0].strip(),
                print >>sys.stderr, outmod

            mypipe = subprocess.Popen(outmod, bufsize=0, stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE)
            ostr = mypipe.communicate(ostr)[0]
            add_nl = 1

        if add_nl:
            ostr += "\n"

    # use_pager = 1 # force paging, since there is always a flurry
    if use_pager:
        pydoc.pager(ostr)
    else:
        sys.stdout.write(ostr)

    if debug:
        # pylint: disable=C0323
        print >>sys.stderr, "final output:", len(ostr)


def cli(prompt):
    """
    Provide a cli with a prompt to read user commands
    """
    while 1:
        try:
            instr = raw_input("%s> " % prompt).strip()
        except KeyboardInterrupt:
            continue

        onecmd(instr)


class Usage(Exception):
    """
    Exception class for this module. Used instead of sys.exit(n)
    """
    def __init__(self, msg=""):
        Exception.__init__(self, msg)
        self.msg = msg

    def __str__(self):
        return self.msg


def _usage():
    """
    Prints usage of this program
    """
    global mod_globals

    # pylint: disable=C0323
    print >>sys.stderr, "Usage: " + mod_globals.progname + \
        " [-v <verbose>] <filename>"


def main(argv=None):
    """
    Argument parsing and main glue logic
    """
    global mod_globals

    try:
        if argv is None:
            argv = sys.argv

        mod_globals.progname = argv[0]
        prompt = mod_globals.progname.rsplit("/", 1)[-1].split(".", 1)[0]
        # main starts here

        try:
            optlist, args = getopt.getopt(argv[1:], 'v:')
        except getopt.GetoptError, cause:
            _usage()
            raise Usage(cause)

        # default values go here

        for opt in optlist:
            (option, value) = opt
            if option == "-v":
                mod_globals.verbose = int(value, 0)
            elif option == "-s":
                mod_globals.slicing_interval = int(value, 0)
            else:
                _usage()
                raise Usage("Unknown switch: %s %s" % (option, value))

        try:
            atexit.register(readline.write_history_file,
                            os.path.join(os.environ["HOME"],
                                         ".%s_history" % prompt))
            readline.read_history_file(os.path.join(os.environ["HOME"],
                                       ".%s_history" % prompt))
        except:  # pylint: disable=W0702
            if 0:
                print sys.exc_info()
                traceback.print_exc(file=sys.stderr)

        if not args:
            cli(prompt)
        else:
            onecmd(" ".join(args))
        return 0

    except Usage, err:
        if err.msg:
            print "***", err.msg
        return 1

if __name__ == '__main__':
    sys.exit(main())
