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

### To run the survey, please follow hte steps below:
- Load the `db.sql` to create the needed tables
- Execute the `main.py` script to perform survey and populate the database
  
#### To be added later when ready :)
- To launch the webserver to run the below command:
```bash
python3 manage.py runserver ip-address:port
``` 
&copy; AfriNIC Ltd. 2019
