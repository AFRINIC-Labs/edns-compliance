# Survey of EDNS non-compliant domains from AFRINIC reverse DNS and secondary DNS zones
A survey of EDNS compliant DNS servers in Africa.

## Survey consits of two parts:

- **EDNS compliancy for AFRINIC reverse DNS servers for prefixes delegated to members**
- **EDNS compliancy for ccTLD (Country Code Top Level Domain) in Africa**

## Results expected:

- AfriNIC:
  - Name Servers Ip capabilities
  - Name Servers eDNS Compliance


Below is the list of test used for eDNS compliance:

- dns_plain
- edns_plain
- edns_unknw
- edns_unknwopt
- edns_unknwflag
- edns_dnssec
- edns_trunc
- edns_unknwveropt
- edns_tcp

### To run the survey, please follow hte steps below:

- Copy `.db.conf.sample` to `.db.conf`. (*keep in the home dir*)
- Populate `.db.conf` with the database credentials & details
- Load the `db.sql` to create the needed tables
- Execute the `main.py` script to perform survey and populate the database
- Execute the `ns_main.py` script to perform survey on **ccTLDs** and populate the database


### To run the survey on a specific list of zones, please follow hte steps below:

- Prepare your input file with the list of zones *(one on each line with no quotes)*
- Change firectory to `scripts`
- Execute the script usung the below syntax
```bash
python3 zone_ns_processing.py --file /path/to/infile
```
- The result will be in csv files with the below names:
  - `YYYY-MM-DD_zones_ns_list.csv`
  - `YYYY-MM-DD_ns_edns_compliance_results.csv`


#### To be added later when ready :)

- To launch the webserver to run the below command:

```bash
python3 manage.py runserver ip-address:port
```

&copy; AfriNIC Ltd. 2019-2020
