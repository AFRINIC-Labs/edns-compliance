# Afrinic EDNS-Compliance Survey 
A survey of EDNS compliant DNS servers in Africa.

## Survey consits of two parts:
- **AfriNIC registered Name Servers with their eDNS compliance status**
- **ccTLD (Country Code Top Level Domain) Name Servers with their eDNS compliance status**

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