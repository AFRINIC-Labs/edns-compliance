#
# Desc: Script for Testing EDNS Compliance of African NameServers
#
# Import needed modules
import os
import re
import socket
import requests
from bs4 import BeautifulSoup
from pathlib import Path

import dns

import pandas as pd
import pandas_profiling
import numpy as np

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
def process_zones(infiles: list, outfile_suffix='zoneslists', outdir='data'):
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

# Define a function to specify the resolution methods to be used.
def ns_resolver(ns):
    try:
        res = socket.gethostbyname(ns)
    except:
        res = 'Failed'
    return res

# Execution of main code
if __name__ == '__main__':
    base_url = 'http://ftp.afrinic.net/pub/zones/'
    ext = '-AFRINIC'
    zone_files = get_files(base_url, ext)
    print('Number of zones files to be downloaded: {}'.format(zone_files.__len__()))
    seg_list = process_zones(zone_files, outfile_suffix='zoneslists')
    seg_liststr = [i.name for i in seg_list]
    print("Below is the list of output files:\n{}".format('\n'.join(seg_liststr)))
