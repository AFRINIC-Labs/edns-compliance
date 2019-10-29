import argparse
import re, socket, subprocess, requests, json
import datetime as DT
import dns.resolver
import pandas as pd

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


# Define the function to extract list of NS for each ccTLDs
def domain_ns_retrieval(domain: str):
    try:
        res = [ns.__str__() for ns in dns.resolver.query(domain.strip() + '.', 'NS')]
    except Exception:
        res = 'U'
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
    # Define Todays Date:
    today_date = DT.datetime.today().strftime('%Y-%m-%d')

    # Instantiate ArgParser & Get the number from argment
    parser = argparse.ArgumentParser(description='Get the Subscriber CEI score')

    # Get Input files containing zones (one on each line with no quotes)
    parser.add_argument('--file',
        action='store',
        dest='file',
        help='Input file containing zones (one on each line with no quotes)',
        type=str,
        required=True)

    # Get all agurment to proper list
    my_args = parser.parse_args()

    infile = my_args.file

    # Read infile
    print("------------- Reading file: {} -------------".format(infile))
    inzone_list = open(infile, 'r').readlines()

    # Retrieval country codes and their respective NS & insert in DB
    ns_list = []
    data, nsdata = [], []
    for cc in inzone_list:
        for ns in domain_ns_retrieval(cc):
            ns_ip, ns_ipv6 = ns_resolver(ns), ns_resolverV6(ns)
            asnv4, asnv6, ccv4, ccv6 = get_asn_ripe(ns_ip), get_asn_ripe(ns_ipv6), get_country_ripe(ns_ip), get_country_ripe(ns_ipv6)

            data.append([today_date, cc, ns, ns_ip, ns_ipv6, asnv4, asnv6, ccv4, ccv6])
            ns_list.append([cc, ns])
    # Create the pandas Data Frame
    df_all = pd.DataFrame(data, columns=['exec_date', 'countrycode', 'name_server', 'ns_ip', 'ns_ipv6', 'asnv4', 'asnv6', 'ccv4', 'ccv6']) 


    # Test EDNS Compliance for the ccTLD nameServer
    cctld_df = pd.DataFrame.from_records(ns_list)

    for ns in cctld_df[1].unique(): nsdata.append([today_date] + run_ednsComp_test(ns, cctld_df, cc=True))

    df_ns = pd.DataFrame(nsdata, columns=['exec_date', 'ns', 'dns_plain', 'edns_plain', 'edns_unknw', 'edns_unknwopt', 'edns_unknwflag', 'edns_dnssec', 'edns_trunc', 'edns_unknwveropt', 'edns_tcp'])


    outfiles = [today_date + '_zones_ns_list.csv', today_date + '_ns_edns_compliance_results.csv' ]

    #### Dump results to CSV
    df_all.to_csv(outfiles[0])
    df_ns.to_csv(outfiles[1])

    print("Output files are: \n\t{} \n\t{} ".format(outfiles[0], outfiles[1]))
    print('------------- END of the Scripts -------------')
