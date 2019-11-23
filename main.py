#
# Desc: Script for Testing EDNS Compliance of African NameServers & ccTLDs
#
# Import needed modules
import os, re, ast, socket, subprocess, requests, json
import datetime as DT
import dns.resolver
import psycopg2
import pandas as pd
from pathlib import Path
from bs4 import BeautifulSoup
print('Program Starts Here --- \nModules imported successfully!')

# Define DB connection details and object

# Get current for for appropriate "mconf" file path parsing
current_path = Path(os.getcwd())
conf_file = current_path / ".db.conf"

# Define my DB Connection details from Config file
with open(conf_file, 'r') as data_file:
    DB_PARAMS = json.load(data_file)['afrinic_db_remote']

# Instantiate DB connection objects
db_connection = psycopg2.connect(user=DB_PARAMS['USER'],
        password=DB_PARAMS['PASSWD'],
        host=DB_PARAMS['HOST'],
        port=DB_PARAMS['PORT'],
        database=DB_PARAMS['DB'])
db_connection.autocommit = True
db_cursor = db_connection.cursor()

# Define Todays Date:
today_date = DT.datetime.today().strftime('%Y-%m-%d')

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
    open('data/country.json', 'w').write(requests.get(url, allow_redirects=True).content.decode("utf-8"))
    all_countries = json.load(open('country.json', 'r'))
    af_cc = list()
    for k, v in all_countries.items():
        if v == "AF": af_cc.append(k)  # Get African countries only
        else: pass
    return af_cc

# Define the function to extract list of NS for each ccTLDs
def domain_ns_retrieval(domain: str):
    try:
        res = [ns.__str__() for ns in dns.resolver.query(domain + '.', 'NS')]
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

# Define function to get country of the IP from Ripe web API
def get_country_ripe(ip_addr: str):
    try:
        ripe_url = 'https://stat.ripe.net/data/rir-geo/data.json?sourceapp=afrinic-internship-research&resource='
        get_request = requests.get(ripe_url + ip_addr).content
        get_req = json.loads(get_request)
        if get_req['data']['located_resources']:
            result = get_req['data']['located_resources'][0]['location']
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
    'edns_unknwveropt': ['dig', '+norec', '+edns=100', '+noednsneg', '+ednsopt=100', 'soa'],
    'edns_tcp': ['dig', '+norec', '+tcp', 'soa']}

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
    dns_plain, edns_plain, edns_unknw, edns_unknwopt, edns_unknwflag, edns_dnssec, edns_trunc, edns_unknwveropt, edns_tcp = 0, 0, 0, 0, 0, 0, 0, 0, 0
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
            edns_tcp = 1 if run_dig_cmd(edns_test_dict['edns_tcp'] + [zone, '@' + ns])[0:2] == ('NOERROR', 0) else 0
    return [ns, dns_plain, edns_plain, edns_unknw, edns_unknwopt, edns_unknwflag, edns_dnssec, edns_trunc, edns_unknwveropt, edns_tcp]



if __name__ == '__main__':
    print("---------------------------- START EXECUTION ----------------------------")
    print("    ---------------------------- START:: Download Reverse zone files & format in destination files ----------------------------")
    base_url = 'http://ftp.afrinic.net/pub/zones/'
    ext = '-AFRINIC'
    zone_files = get_files(base_url, ext)
    print('Number of zones files to be donwnloaded: {}'.format(zone_files.__len__()))
    seg_list = process_zones(zone_files, outfile_suffix='zoneslists', outdir='data')
    seg_liststr = [i.name for i in seg_list]
    print("Below is the list of output files:\n{}".format('\n'.join(seg_liststr)))
    print("    ---------------------------- END:: Download Reverse zone files & format in destination files ----------------------------")

    ########################### Load NS Ipv4 & list into pandas DataFrames ###########################
    print("    ---------------------------- START:: Load NS Ipv4 & list into pandas DataFrames ----------------------------")
    headers = ['Reverse', 'Type', 'NameServer']
    # For IPv4
    pdata = pd.read_csv("data/zoneslists.ns4", delimiter=',', names=headers, dtype=str, encoding='utf-8').drop_duplicates()
    pdata['ip_type'] = 'v4'
    # For IPv6
    pdata6 = pd.read_csv("data/zoneslists.ns6", delimiter=',', names=headers, dtype=str, encoding='utf-8').drop_duplicates()
    pdata6['ip_type'] = 'v6'
    print("    ---------------------------- END:: Load NS Ipv4 & list into pandas DataFrames ----------------------------")

    ########################### Insert Reverse Zone lists into DB ###########################
    print("    ---------------------------- START:: Insert Reverse Zone lists into DB ----------------------------")
    # Insert Reverse Zone lists into DB
    ## Ipv4
    for i in pdata.iterrows():
        db_insert_func(data_list=[today_date] + ast.literal_eval(i[1].tolist().__str__()), tabname='edns_reverse', columns=['exec_date', 'reverse_ns', 'ns_type', 'nameserver', 'ip_type'])

    ## Ipv6
    for i in pdata6.iterrows():
        db_insert_func(data_list=[today_date] + ast.literal_eval(i[1].tolist().__str__()), tabname='edns_reverse', columns=['exec_date', 'reverse_ns', 'ns_type', 'nameserver', 'ip_type'])

    # Resolve list and Insert into DB
    ns_unique = pdata.NameServer.unique()
    ns_unique6 = pdata6.NameServer.unique()

    ## Ipv4
    for ns in ns_unique:
        ns_ip, ns_ipv6 = ns_resolver(ns), ns_resolverV6(ns)
        asnv4, asnv6, ccv4, ccv6 = get_asn_ripe(ns_ip), get_asn_ripe(ns_ipv6), get_country_ripe(ns_ip), get_country_ripe(ns_ipv6)
        db_insert_func(
            data_list=[today_date, ns, ns_ip, ns_ipv6, asnv4, asnv6, ccv4, ccv6, 'v4'],
            tabname='ns_resolution',
            columns=['exec_date', 'name_server', 'ns_ip', 'ns_ipv6', 'asnv4', 'asnv6', 'ccv4', 'ccv6', 'ip_type'] )

    ## Ipv6
    for ns in ns_unique6:
        ns_ip, ns_ipv6 = ns_resolver(ns), ns_resolverV6(ns)
        asnv4, asnv6, ccv4, ccv6 = get_asn_ripe(ns_ip), get_asn_ripe(ns_ipv6), get_country_ripe(ns_ip), get_country_ripe(ns_ipv6)
        db_insert_func(
            data_list=[today_date, ns, ns_ip, ns_ipv6, asnv4, asnv6, ccv4, ccv6, 'v6'],
            tabname='ns_resolution',
            columns=['exec_date', 'name_server', 'ns_ip', 'ns_ipv6', 'asnv4', 'asnv6', 'ccv4', 'ccv6', 'ip_type'] )

    print("    ---------------------------- END:: Insert Reverse Zone lists into DB ----------------------------")


    ########################### Execution of EDNS Compliance test on the Lisf of Unique Nameservers identified ###########################
    print("    ---------------------------- START:: Execution of EDNS Compliance test on the Lisf of Unique Nameservers identified ----------------------------")
    # Execution of EDNS Compliance test on the Lisf of Unique Nameservers identified
    # Ipv4
    for ns in ns_unique:
        db_insert_func(
                data_list=[today_date] + run_ednsComp_test(ns, pdata) + ['v4'],
                tabname='edns_tests',
                columns=['exec_date', 'ns', 'dns_plain', 'edns_plain', 'edns_unknw', 'edns_unknwopt', 'edns_unknwflag', 'edns_dnssec', 'edns_trunc', 'edns_unknwveropt', 'edns_tcp', 'ip_type'] )
    # Ipv6
    for ns in ns_unique6:
        db_insert_func(
                data_list=[today_date] + run_ednsComp_test(ns, pdata6) + ['v6'],
                tabname='edns_tests',
                columns=['exec_date', 'ns', 'dns_plain', 'edns_plain', 'edns_unknw', 'edns_unknwopt', 'edns_unknwflag', 'edns_dnssec', 'edns_trunc', 'edns_unknwveropt', 'edns_tcp', 'ip_type'] )

    print("    ---------------------------- END:: Execution of EDNS Compliance test on the Lisf of Unique Nameservers identified ----------------------------")
