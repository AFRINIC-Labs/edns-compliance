#
# Desc: Script for Testing EDNS Compliance of African NameServers & ccTLDs
#
# Import needed modules
import re, ast, socket, subprocess
import requests, json
import dns.resolver
import psycopg2
import pandas as pd
from pathlib import Path
from bs4 import BeautifulSoup
print('Program Starts Here\nModules imported successfully!')

# Define DB connection details and object
db_connection = psycopg2.connect(user="postgres", password="****", host="127.0.0.1", port="5432", database="afrinic_db")
db_connection.autocommit = True
db_cursor = db_connection.cursor()

# Define function to get the list of files to be download from AFRINIC FTP
def get_files(url, ext='', params={}):
    response = requests.get(url, params=params)
    if response.ok:
        response_text = response.text
    else:
        return response.raise_for_status()
    soup = BeautifulSoup(response_text, 'html.parser')
    outfiles = [url + node.get('href') for node in soup.find_all('a') if node.get('href').endswith(ext)]
    return outfiles


# Define function to download zones files content and segragate record types
def process_zones(infiles: list, outfile_suffix='zoneslists', outdir='.'):
    odir = Path.cwd() / outdir

    nsfilepath4 = open(str(odir / outfile_suffix) + '.ns4', 'w')
    nsfilepath6 = open(str(odir / outfile_suffix) + '.ns6', 'w')

    dsfilepath4 = open(str(odir / outfile_suffix) + '.ds4', 'w')
    dsfilepath6 = open(str(odir / outfile_suffix) + '.ds6', 'w')

    for zone in infiles:
        if zone.endswith('ip6.arpa-AFRINIC'):
            r = requests.get(zone).content
            for line in r.decode('utf-8').split('\n'):
                if re.search('arpa.         NS        ', line):
                    nsfilepath6.write(line.replace("         NS        ", ",NS,") + '\n')
                elif re.search('arpa.         DS        ', line):
                    dsfilepath6.write(line.replace("         DS        ", ",DS,") + '\n')
        else:
            r = requests.get(zone).content
            for line in r.decode('utf-8').split('\n'):
                if re.search('arpa.         NS        ', line):
                    nsfilepath4.write(line.replace("         NS        ", ",NS,") + '\n')
                elif re.search('arpa.         DS        ', line):
                    dsfilepath4.write(line.replace("         DS        ", ",DS,") + '\n')
    return [nsfilepath4, nsfilepath6, dsfilepath4, dsfilepath6]

# Define a function to resolver nameserver into ipv4.
def ns_resolver(ns: str):
    try:
        res = socket.getaddrinfo(ns, None, socket.AF_INET)[0][4][0]
    except Exception:
        res = 'Failed'
    return res

# Define a function to specify the resolution methods to be used.
def ns_resolverV6(ns: str):
    try:
        res = socket.getaddrinfo(ns, None, socket.AF_INET6)[0][4][0]
    except Exception:
        res = 'Failed'
    return res

# Define function to get the list of African countries
def get_african_countries():
    url = 'http://country.io/continent.json'
    open('country.json', 'w').write(requests.get(url, allow_redirects=True).content.decode("utf-8"))
    all_countries = json.load(open('country.json', 'r'))
    af_cc = list()
    for k, v in all_countries.items():
        if v == "AF": af_cc.append(k)
        else: pass
    return af_cc

# Define the function to extract list of NS for each ccTLDs
def domain_ns_retrieval(domain: str):
    try:
        res = [ns.__str__() for ns in dns.resolver.query(domain, 'NS')]
    except Exception:
        res = 'U'
    return res

# Define Function to insert data into DB
def db_insert_func(data_list: list, tabname: str, columns: list):
    try:
        data = data_list.__str__().replace('[', '').replace(']', '')
        cols = columns.__str__().replace('[', '').replace(']', '').replace("'", "")
        sql_statement = """INSERT INTO {}({}) VALUES({})""".format(tabname, cols, data)
        db_cursor.execute(sql_statement)
        res = True
    except Exception:
        res = False
    return res


# Define function to get ASN from Ripe web API
def get_asn_ripe(ip_addr: str):
    try:
        ripe_url = 'https://stat.ripe.net/data/network-info/data.json?sourceapp=afrinic-internship-research&resource='
        get_request = requests.get(ripe_url + ip_addr).content
        get_req = json.loads(get_request)
        if get_req['data']['asns']:
            result = get_req['data']['asns'][0]
        else:
            result = "Unknown"
    except KeyError:
        result = "Unknown"
    return result


# Define EDNS Tests list
edns_test_dict = {'dns_plain': ['dig', '+norec', '+noedns', 'soa'],
    'edns_plain': ['dig', '+norec', '+edns=0', 'soa'],
    'edns_unknw': ['dig', '+norec', '+edns=100', '+noednsneg', 'soa'],
    'edns_unknwopt': ['dig', '+norec', '+ednsopt=100', 'soa'],
    'edns_unknwflag': ['dig', '+norec', '+ednsflags=0x80', 'soa'],
    'edns_dnssec': ['dig', '+norec', '+dnssec', 'soa'],
    'edns_trunc': ['dig', '+norec', '+dnssec', '+bufsize=512', '+ignore', 'dnskey'],
    'edns_unknwveropt': ['dig', '+norec', '+edns=100', '+noednsneg', '+ednsopt=100', 'soa']}

# Define function to execute dig command
def run_dig_cmd(cmd: list):
    status = None
    edns_version = None
    result = subprocess.run(cmd, stdout=subprocess.PIPE).stdout.decode('utf-8').split(';;')
    for line in result:
        if re.search('status:', line):
            status = line.split(',')[1].split(':')[1].strip()
        elif re.search('EDNS: version: 0', line):
            edns_version = 0
    return status, edns_version, result

# Define function to run tests on NS
def run_ednsComp_test(ns: str, df, cc: bool = False):
    if cc:
        zone = df[df[1].str.match(ns)].iloc[0][0]
    else: zone = df[df['NameServer'].str.match(ns)].iloc[0][0]
    # Reset results vars
    dns_plain, edns_plain, edns_unknw, edns_unknwopt, edns_unknwflag, edns_dnssec, edns_trunc, edns_unknwveropt = 0, 0, 0, 0, 0, 0, 0, 0
    # Test DNS plain resolution first
    dns_plain = 1 if run_dig_cmd(edns_test_dict['dns_plain'] + [zone, '@' + ns])[0] == 'NOERROR' else 0
    if dns_plain:
        # Test EDNS plain resolution first
        edns_plain = 1 if run_dig_cmd(edns_test_dict['edns_plain'] + [zone, '@' + ns])[0:2] == ('NOERROR', 0) else 0
        if edns_plain:
            edns_unknw = 1 if run_dig_cmd(edns_test_dict['edns_unknw'] + [zone, '@' + ns])[0:2] == ('BADVERS', 0) else 0
            edns_unknwopt = 1 if run_dig_cmd(edns_test_dict['edns_unknwopt'] + [zone, '@' + ns])[0:2] == ('NOERROR', 0) else 0
            edns_unknwflag = 1 if run_dig_cmd(edns_test_dict['edns_unknwflag'] + [zone, '@' + ns])[0:2] == ('NOERROR', 0) else 0
            edns_dnssec = 1 if run_dig_cmd(edns_test_dict['edns_dnssec'] + [zone, '@' + ns])[0:2] == ('NOERROR', 0) else 0
            edns_trunc = 1 if run_dig_cmd(edns_test_dict['edns_trunc'] + [zone, '@' + ns])[0:2] == ('NOERROR', 0) else 0
            edns_unknwveropt = 1 if run_dig_cmd(edns_test_dict['edns_unknwveropt'] + [zone, '@' + ns])[0:2] == ('BADVERS', 0) else 0
    return [ns, dns_plain, edns_plain, edns_unknw, edns_unknwopt, edns_unknwflag, edns_dnssec, edns_trunc, edns_unknwveropt]


if __name__ == '__main__':
    base_url = 'http://ftp.afrinic.net/pub/zones/'
    ext = '-AFRINIC'
    zone_files = get_files(base_url, ext)
    print('Number of zones files to be donwnloaded: {}'.format(zone_files.__len__()))
    seg_list = process_zones(zone_files, outfile_suffix='zoneslists')
    seg_liststr = [i.name for i in seg_list]
    print("Below is the list of output files:\n{}".format('\n'.join(seg_liststr)))

    ########################### Load NS Ipv4 & list into pandas DataFrames ###########################
    headers = ['Reverse', 'Type', 'NameServer']
    # For IPv4
    pdata = pd.read_csv("../data/zoneslists.ns4", delimiter=',', names=headers, dtype=str, encoding='utf-8').drop_duplicates()
    pdata['ip_type'] = 'v4'
    # For IPv6
    pdata6 = pd.read_csv("../data/zoneslists.ns6", delimiter=',', names=headers, dtype=str, encoding='utf-8').drop_duplicates()
    pdata6['ip_type'] = 'v6'

    ########################### Insert Reverse Zone lists into DB ###########################
    ## Ipv4
    for i in pdata.iterrows():
        db_insert_func(
            data_list=ast.literal_eval(i[1].tolist().__str__()),
            tabname='edns_reverse',
            columns=['reverse_ns', 'ns_type', 'nameserver', 'ip_type'])
    ## Ipv6
    for i in pdata6.iterrows():
        db_insert_func(
            data_list=ast.literal_eval(i[1].tolist().__str__()),
            tabname='edns_reverse',
            columns=['reverse_ns', 'ns_type', 'nameserver', 'ip_type'])

    # Resolve list and Insert into DB
    ns_unique = pdata.NameServer.unique()
    ns_unique6 = pdata6.NameServer.unique()

    ## Ipv4
    for ns in ns_unique:
        db_insert_func(
            data_list=[ns, ns_resolver(ns), ns_resolverV6(ns), get_asn_ripe(ns_resolver(ns))],
            tabname='ns_resolution',
            columns=['name_server', 'ns_ip', 'ns_ipv6', 'asn'] )
    ## Ipv6
    for ns in ns_unique6:
        db_insert_func(
            data_list=[ns, ns_resolver(ns), ns_resolverV6(ns), get_asn_ripe(ns_resolver(ns))],
            tabname='ns_resolution',
            columns=['name_server', 'ns_ip', 'ns_ipv6', 'asn'] )


    ########################### Execution of EDNS Compliance test on the Lisf of Unique Nameservers identified ###########################
    ## Ipv4
    for ns in ns_unique:
        db_insert_func(
                data_list=run_ednsComp_test(ns, pdata),
                tabname='edns_tests',
                columns=['ns', 'dns_plain', 'edns_plain', 'edns_unknw', 'edns_unknwopt', 'edns_unknwflag', 'edns_dnssec', 'edns_trunc', 'edns_unknwveropt'] )
    ## Ipv6
    for ns in ns_unique6:
        db_insert_func(
                data_list=run_ednsComp_test(ns, pdata6),
                tabname='edns_tests',
                columns=['ns', 'dns_plain', 'edns_plain', 'edns_unknw', 'edns_unknwopt', 'edns_unknwflag', 'edns_dnssec', 'edns_trunc', 'edns_unknwveropt'] )

    ########################### Retrieval country codes and their respective NS & insert in DB ###########################
    data_list = []
    for cc in get_african_countries():
        for ns in domain_ns_retrieval(cc):
            db_insert_func(
                data_list=[cc, ns, ns_resolver(ns), ns_resolverV6(ns), get_asn_ripe(ns_resolver(ns))],
                tabname='cctld_ns_resolution',
                columns=['countrycode', 'name_server', 'ns_ip', 'ns_ipv6', 'asn'])
            data_list.append([cc, ns])

    # Test EDNS Compliance for the ccTLD Name Server
    cctld_df = pd.DataFrame.from_records(data_list)

    for ns in cctld_df[1].unique():
        db_insert_func(
                data_list=run_ednsComp_test(ns, cctld_df, cc=True),
                tabname='cctld_edns_tests',
                columns=['ns', 'dns_plain', 'edns_plain', 'edns_unknw', 'edns_unknwopt', 'edns_unknwflag', 'edns_dnssec', 'edns_trunc', 'edns_unknwveropt'] )

    print('Program Execution completed, please check in the Database for results')
