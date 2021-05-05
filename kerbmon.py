#!/usr/bin/env python

# Author:
#  @__Retrospect
#
# Description:
#    This module will implement finding Service Principal Names in a continuous way

import argparse
import sys
import os
import sqlite3

from impacket.examples.utils import parse_credentials
from impacket.ldap import ldap, ldapasn1

class Database:
    def __init__(self,db_file):
        self.db_file=db_file

    def connect_database(self):
        self.conn = sqlite3.connect(self.db_file)
        self.cursor = self.conn.cursor()

    def create_database(self):
        self.connect_database()

        sql_spn_table = """ CREATE TABLE IF NOT EXISTS spn_table (
                                        id integer PRIMARY KEY AUTOINCREMENT,
                                        domain text NOT NULL,
                                        servicePrincipalName text NOT NULL,
                                        sAMAccountName text NOT NULL,
                                        pwdLastSet date NOT NULL
                                    ); """

        if self.cursor is not None:
            self.create_table(sql_spn_table)

    def commit(self):
        self.conn.commit()

    def create_table(self, create_table_sql):
        """ create a table from the create_table_sql statement
        :param conn: Connection object
        :param create_table_sql: a CREATE TABLE statement
        :return:
        """
        try:
            self.cursor.execute(create_table_sql)
        except Error as e:
            print(e)


def harvester(authDomain, username, password, targetDomain):
    target = targetDomain

    # Create the baseDN
    domainParts = targetDomain.split('.')
    baseDN = ''
    for i in domainParts:
        baseDN += 'dc=%s,' % i
    # Remove last ','
    baseDN = baseDN[:-1]

    # Not sure about this one, we didn't make this configurable
    kdcHost = None

    # Connect to LDAP
    try:
        ldapConnection = ldap.LDAPConnection('ldap://%s' % target, baseDN, kdcHost)
        ldapConnection.login(username, password, authDomain)
    except ldap.LDAPSessionError as e:
        if str(e).find('strongerAuthRequired') >= 0:
            # We need to try SSL
            ldapConnection = ldap.LDAPConnection('ldaps://%s' % target, baseDN, kdcHost)
            ldapConnection.login(username, password, authDomain)
        else:
            raise

    # Building the search filter
    searchFilter = "(&(servicePrincipalName=*)(UserAccountControl:1.2.840.113556.1.4.803:=512)" \
                       "(!(UserAccountControl:1.2.840.113556.1.4.803:=2))(!(objectCategory=computer)))"

    try:
        resp = ldapConnection.search(searchFilter=searchFilter,
                                     attributes=['servicePrincipalName', 'sAMAccountName',
                                                 'pwdLastSet', 'MemberOf', 'userAccountControl', 'lastLogon'],
                                     sizeLimit=100000)
    except ldap.LDAPSearchError as e:
        if e.getErrorString().find('sizeLimitExceeded') >= 0:
            # We reached the sizeLimit, process the answers we have already and that's it. Until we implement
            # paged queries
            resp = e.getAnswers()
            pass
        else:
            raise

    answers = []

    for item in resp:
        if isinstance(item, ldapasn1.SearchResultEntry) is not True:
            continue
        mustCommit = False
        sAMAccountName =  ''
        memberOf = ''
        SPNs = []
        pwdLastSet = ''
        userAccountControl = 0
        lastLogon = 'N/A'
        delegation = ''
        try:
            for attribute in item['attributes']:
                if str(attribute['type']) == 'sAMAccountName':
                    sAMAccountName = str(attribute['vals'][0])
                    mustCommit = True
                elif str(attribute['type']) == 'userAccountControl':
                    userAccountControl = str(attribute['vals'][0])
                    if int(userAccountControl) & UF_TRUSTED_FOR_DELEGATION:
                        delegation = 'unconstrained'
                    elif int(userAccountControl) & UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION:
                        delegation = 'constrained'
                elif str(attribute['type']) == 'memberOf':
                    memberOf = str(attribute['vals'][0])
                elif str(attribute['type']) == 'pwdLastSet':
                    if str(attribute['vals'][0]) == '0':
                        pwdLastSet = '<never>'
                    else:
                        pwdLastSet = str(datetime.fromtimestamp(getUnixTime(int(str(attribute['vals'][0])))))
                elif str(attribute['type']) == 'lastLogon':
                    if str(attribute['vals'][0]) == '0':
                        lastLogon = '<never>'
                    else:
                        lastLogon = str(datetime.fromtimestamp(getUnixTime(int(str(attribute['vals'][0])))))
                elif str(attribute['type']) == 'servicePrincipalName':
                    for spn in attribute['vals']:
                        SPNs.append(str(spn))

            if mustCommit is True:
                if int(userAccountControl) & UF_ACCOUNTDISABLE:
                    pass
                else:
                    for spn in SPNs:
                        answers.append([spn, sAMAccountName, memberOf, pwdLastSet, lastLogon, delegation])
        except Exception as e:
            print('Skipping item, cannot process due to error %s' % str(e))
            pass

        return answers

@staticmethod
def getUnixTime(t):
    t -= 116444736000000000
    t /= 10000000
    return t

if __name__ == "__main__":

    #required args: db file, creds, target-domain file, outputfile

    parser = argparse.ArgumentParser(add_help =  True, description = "Continously query domains for SPNs that are running. Monitor for changes and pull latest TGS tickets")
    parser.add_argument('-credentials', action='store', help='domain/username[:password]')
    parser.add_argument('-domainsfile', help='File with domains (FQDN) per line to test')
    parser.add_argument('-dbfile', help='File to store state in sqlite3 db')
    parser.add_argument('-outputfile', action='store', help='Output file to write new SPNs to')

    options = parser.parse_args()

    authDomain, username, password = parse_credentials(options.credentials)
    db = Database(options.dbfile)

    try:
        print("Authenticating with domain: "+authDomain)
        print("With username: "+username)
        print("Loading domains from file: "+options.domainsfile)
        print("Storing state in: "+options.dbfile)
        print("Outputting results in: "+options.outputfile)

        if not os.path.exists(options.dbfile):
            print("*** DATABASE NOT FOUND")
            db.create_database()
            print("*** DATABASE CREATED")
        else:
            print("*** DATABASE FOUND")
            db.connect_database()

        with open(options.domainsfile) as fi:
            domains = [line.strip() for line in fi]

        while(True):
            # first iterate all domains searching for:
            # - changed pw's
            # - new spn's

            for targetDomain in domains:
                print(" ** Starting enumerating domain: "+targetDomain)
                # dict format:
                # [?]
                domainAnswers = harvester(authDomain, username, password, targetDomain)
                print(domainAnswers)
                print(" ** Finished enumerating domain: "+targetDomain)

#            executer = GetUserSPNs(username, password, userDomain, domain, option)
#            executer.run()

    except Exception as e:
        print(e)
