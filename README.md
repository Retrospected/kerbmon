KerbMon
=================
KerbMon pulls the current state of the Service Principal Name (SPN) records of your domain(s) and stores it in a SQLite3 database. In a subsequent execution, KerbMon will compare the newly retrieved SPN's with the records in the database and check for newly added SPN's or SPN's of which the sAMAccount has a changed password by comparing the pwdLastSet attribute in LDAP.

In case any difference has been detected, KerbMon will retrieve the Ticket Granting Service (TGS) ticket(s) (TGS-REQ) of these SPN's from the DC and store it to your disk.

In addition KerbMon has the option to automatically perform a basic dictionary attack based on John the Ripper.

For more information regarding the Kerberoast attack refer to [the research](http://www.irongeek.com/i.php?page=videos/derbycon4/t120-attacking-microsoft-kerberos-kicking-the-guard-dog-of-hades-tim-medin) of Tim Medin (@timmedin).

Quick Start
---------------
Clone the master branch, install the requirements and run.

```
git clone https://github.com/Retrospected/kerbmon; cd kerbmon
pip3 install -r requirements
python3 kerbmon.py -h
```

Usage
---------------

```
usage: kerbmon.py [-h] [-credentials CREDENTIALS] [-k] [-aesKey hex key]
                  [-domainsfile DOMAINSFILE] [-dbfile DBFILE]
                  [-crack wordlist] [-outputfile OUTPUTFILE] [-debug]

Continously query domains for SPNs that are running. Monitor for changes and
pull latest TGS tickets

optional arguments:
  -h, --help            show this help message and exit
  -credentials CREDENTIALS
                        domain/username[:password]
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME) based on target parameters.
                        If valid credentials cannot be found, it will use the
                        ones specified in the command line
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256
                        bits)
  -domainsfile DOMAINSFILE
                        File with domains (FQDN) per line to test
  -dbfile DBFILE        SQLite3 DB file to use as a database
  -crack wordlist       Automatically attempt to crack the TGS service
                        ticket(s) using a dictionary attack with the provided
                        wordlist (using John the Ripper)
  -outputfile OUTPUTFILE
                        Output file to write new or changed SPNs to. A date and timestamp
                        will be appended to the filename.
  -debug                Turn DEBUG output ON
```

Credits
==========
- Tim Medin (@timmedin): For [his research](http://www.irongeek.com/i.php?page=videos/derbycon4/t120-attacking-microsoft-kerberos-kicking-the-guard-dog-of-hades-tim-medin) of the kerberoast attack
- Alberto Solino (@agsolino): For building a kerberoast module based on the Impacket framework. This script is heavily based on his work on GetUserSPNs
- @skelsec: For his initial https://github.com/skelsec/PyKerberoast project
- SecureAuthCorp: For their work on the [Impacket](https://github.com/SecureAuthCorp/impacket) project
