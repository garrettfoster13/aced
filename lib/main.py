from distutils.command.build import build
from ldap3.protocol.formatters.formatters import format_sid
from ldap3.protocol.formatters.formatters import format_uuid_le
from impacket.smbconnection import SMBConnection
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech
from impacket.examples.utils import parse_credentials, parse_target
from impacket.examples import logger
from impacket import version
from binascii import unhexlify
from ldap3 import ANONYMOUS
import argparse
from getpass import getpass
import base64
import logging
import time
import ldap3
import json
import ssl
import sys
import os
from .response import Response, ACCESS_ALLOWED_OBJECT_ACE, ACCESS_ALLOWED_ACE, ACE
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
from .sid import KNOWN_SIDS, name_from_sid

show_banner = '''

          _____
         |A .  | _____
         | /.\ ||A ^  | _____
         |(_._)|| / \ ||A _  | _____
         |  |  || \ / || ( ) ||A_ _ |
         |____V||  .  ||(_'_)||( v )|
                |____V||  |  || \ / |
                       |____V||  .  |
                              |____V|
                                     v1.0

        Parse and log a target principal's DACL.
                                    @garrfoster
'''

def arg_parse():
    parser = argparse.ArgumentParser(add_help=True, description="Tool to enumerate a single target's DACL in Active Directory")

    auth_group = parser.add_argument_group("Authentication")
    optional_group = parser.add_argument_group("Optional Flags")

    auth_group.add_argument(
        'target',
        action='store',
        help='[[domain/username[:password]@]<address>',
        type=target_type
        )

    auth_group.add_argument(
        '-ldaps',
        action="store_true",
        help='Use LDAPS isntead of LDAP')

    optional_group.add_argument(
        ""
        "-dc-ip",
        help = "IP address or FQDN of domain controller",
        required=False
        )
    optional_group.add_argument(
        "-k", "--kerberos",
        action="store_true",
        help='Use Kerberos authentication. Grabs credentials from ccache file '
        '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the '
        'ones specified in the command line'
        )
    
    optional_group.add_argument(
        "-no-pass",
        action="store_true",
        help="don't ask for password (useful for -k)"
    )
    
    optional_group.add_argument(
        "-hashes",
        metavar="LMHASH:NTHASH",
        help="LM and NT hashes, format is LMHASH:NTHASH",
    )

    optional_group.add_argument(
        '-aes',
        action="store",
        metavar="hex key",
        help='AES key to use for Kerberos Authentication (128 or 256 bits)'
        )
   #need to fix this 
    optional_group.add_argument(
        "-debug",
        action="store_true",
        help="Enable verbose logging.",
        required=False
        )

    optional_group.add_argument(
        "-no-smb",
        action="store_true",
        help="Do not resolve DC hostname through SMB. Requires a FQDN with -dc-ip.")


    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()
    args.userdomain = args.target[0]
    args.username = args.target[1]
    args.password = args.target[2]
    args.address = args.target[3]

    args.lmhash = ""
    args.nthash = ""
    if args.hashes:
        args.lmhash, args.nthash = args.hashes.split(':')

    if not (args.password or args.lmhash or args.nthash or args.aes or args.no_pass):
        args.password = getpass("Password:")

    return args

def target_type(target):
    domain, username, password, address = parse_target(target)

    if username == "":
        raise argparse.ArgumentTypeError("Username must be specified")

    if domain == "":
        raise argparse.ArgumentTypeError(
            "Domain of user '{}' must be specified".format(username)
        )

    if address == "":
        raise argparse.ArgumentTypeError(
            "Target address (hostname or IP) must be specified"
        )

    return domain, username, password, address

def get_dn(domain):
    components = domain.split('.')
    base = ''
    for comp in components:
        base += f',DC={comp}'
    
    return base[1:]

def get_machine_name(domain_controller, domain):
    if domain_controller is not None:
        s = SMBConnection(domain_controller, domain_controller)
    else:
        s = SMBConnection(domain, domain)
    try:
        s.login('', '')
    except Exception:
        if s.getServerName() == '':
            raise Exception('Error while anonymous logging into %s' % domain)
    else:
        s.logoff()
    return s.getServerName()

def init_ldap_connection(target, tls_version, domain, username, password, lmhash, nthash, domain_controller, kerberos, hashes, aesKey):
    user = '%s\\%s' % (domain, username)
    if tls_version is not None:
        use_ssl = True
        port = 636
        tls = ldap3.Tls(validate=ssl.CERT_NONE, version=tls_version)
    else:
        use_ssl = False
        port = 389
        tls = None
    logging.info(f'Binding to {target}')
    ldap_server = ldap3.Server(target, get_info=ldap3.ALL, port=port, use_ssl=use_ssl, tls=tls)
    if kerberos:
        ldap_session = ldap3.Connection(ldap_server)
        ldap_session.bind()
        ldap3_kerberos_login(ldap_session, target, username, password, domain, lmhash, nthash, aesKey, kdcHost=domain_controller)
    elif hashes is not None:
        if lmhash == "":
            lmhash = "aad3b435b51404eeaad3b435b51404ee"
        ldap_session = ldap3.Connection(ldap_server, user=user, password=lmhash + ":" + nthash, authentication=ldap3.NTLM, auto_bind=True)
    elif username == '' and password == '':
        logging.debug('Performing anonymous bind')
        ldap_session = ldap3.Connection(ldap_server, authentication=ANONYMOUS, auto_bind=True)
    else:
        ldap_session = ldap3.Connection(ldap_server, user=user, password=password, authentication=ldap3.NTLM, auto_bind=True)

    return ldap_server, ldap_session

def init_ldap_session(domain, username, password, lmhash, nthash, kerberos, domain_controller, ldaps, hashes, aesKey, no_smb):
    if kerberos:
        if no_smb:
            logging.info(f'Setting connection target to {domain_controller} without SMB connection')
            target = domain_controller
        else:
            target = get_machine_name(domain_controller, domain)
    else:
        if domain_controller is not None:
            target = domain_controller
        else:
            target = domain

    if ldaps:
        logging.info('Targeting LDAPS')
        try:
            return init_ldap_connection(target, ssl.PROTOCOL_TLSv1_2, domain, username, password, lmhash, nthash, domain_controller, kerberos, hashes, aesKey)
        except ldap3.core.exceptions.LDAPSocketOpenError:
            return init_ldap_connection(target, ssl.PROTOCOL_TLSv1, domain, username, password, lmhash, nthash, domain_controller, kerberos, hashes, aesKey)
    else:
        return init_ldap_connection(target, None, domain, username, password, lmhash, nthash, domain_controller, kerberos, hashes, aesKey)

def ldap3_kerberos_login(connection, target, user, password, domain='', lmhash='', nthash='', aesKey='', kdcHost=None, TGT=None, TGS=None, useCache=True):
    from pyasn1.codec.ber import encoder, decoder
    from pyasn1.type.univ import noValue
    """
    logins into the target system explicitly using Kerberos. Hashes are used if RC4_HMAC is supported.
    :param string user: username
    :param string password: password for the user
    :param string domain: domain where the account is valid for (required)
    :param string lmhash: LMHASH used to authenticate using hashes (password is not used)
    :param string nthash: NTHASH used to authenticate using hashes (password is not used)
    :param string aesKey: aes256-cts-hmac-sha1-96 or aes128-cts-hmac-sha1-96 used for Kerberos authentication
    :param string kdcHost: hostname or IP Address for the KDC. If None, the domain will be used (it needs to resolve tho)
    :param struct TGT: If there's a TGT available, send the structure here and it will be used
    :param struct TGS: same for TGS. See smb3.py for the format
    :param bool useCache: whether or not we should use the ccache for credentials lookup. If TGT or TGS are specified this is False
    :return: True, raises an Exception if error.
    """

    if lmhash != '' or nthash != '':
        if len(lmhash) % 2:
            lmhash = '0' + lmhash
        if len(nthash) % 2:
            nthash = '0' + nthash
        try:  # just in case they were converted already
            lmhash = unhexlify(lmhash)
            nthash = unhexlify(nthash)
        except TypeError:
            pass

    # Importing down here so pyasn1 is not required if kerberos is not used.
    from impacket.krb5.ccache import CCache
    from impacket.krb5.asn1 import AP_REQ, Authenticator, TGS_REP, seq_set
    from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
    from impacket.krb5 import constants
    from impacket.krb5.types import Principal, KerberosTime, Ticket
    import datetime

    if TGT is not None or TGS is not None:
        useCache = False

    if useCache:
        try:
            ccache = CCache.loadFile(os.getenv('KRB5CCNAME'))
        except Exception as e:
            # No cache present
            print(e)
            pass
        else:
            # retrieve domain information from CCache file if needed
            if domain == '':
                domain = ccache.principal.realm['data'].decode('utf-8')
                logging.debug('Domain retrieved from CCache: %s' % domain)

            logging.debug('Using Kerberos Cache: %s' % os.getenv('KRB5CCNAME'))
            principal = 'ldap/%s@%s' % (target.upper(), domain.upper())

            creds = ccache.getCredential(principal)
            if creds is None:
                # Let's try for the TGT and go from there
                principal = 'krbtgt/%s@%s' % (domain.upper(), domain.upper())
                creds = ccache.getCredential(principal)
                if creds is not None:
                    TGT = creds.toTGT()
                    logging.debug('Using TGT from cache')
                else:
                    logging.debug('No valid credentials found in cache')
            else:
                TGS = creds.toTGS(principal)
                logging.debug('Using TGS from cache')

            # retrieve user information from CCache file if needed
            if user == '' and creds is not None:
                user = creds['client'].prettyPrint().split(b'@')[0].decode('utf-8')
                logging.debug('Username retrieved from CCache: %s' % user)
            elif user == '' and len(ccache.principal.components) > 0:
                user = ccache.principal.components[0]['data'].decode('utf-8')
                logging.debug('Username retrieved from CCache: %s' % user)

    # First of all, we need to get a TGT for the user
    userName = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    if TGT is None:
        if TGS is None:
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, password, domain, lmhash, nthash, aesKey, kdcHost)
    else:
        tgt = TGT['KDC_REP']
        cipher = TGT['cipher']
        sessionKey = TGT['sessionKey']

    if TGS is None:
        serverName = Principal('ldap/%s' % target, type=constants.PrincipalNameType.NT_SRV_INST.value)
        tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(serverName, domain, kdcHost, tgt, cipher, sessionKey)
    else:
        tgs = TGS['KDC_REP']
        cipher = TGS['cipher']
        sessionKey = TGS['sessionKey']

        # Let's build a NegTokenInit with a Kerberos REQ_AP

    blob = SPNEGO_NegTokenInit()

    # Kerberos
    blob['MechTypes'] = [TypesMech['MS KRB5 - Microsoft Kerberos 5']]

    # Let's extract the ticket from the TGS
    tgs = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
    ticket = Ticket()
    ticket.from_asn1(tgs['ticket'])

    # Now let's build the AP_REQ
    apReq = AP_REQ()
    apReq['pvno'] = 5
    apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)

    opts = []
    apReq['ap-options'] = constants.encodeFlags(opts)
    seq_set(apReq, 'ticket', ticket.to_asn1)

    authenticator = Authenticator()
    authenticator['authenticator-vno'] = 5
    authenticator['crealm'] = domain
    seq_set(authenticator, 'cname', userName.components_to_asn1)
    now = datetime.datetime.utcnow()

    authenticator['cusec'] = now.microsecond
    authenticator['ctime'] = KerberosTime.to_asn1(now)

    encodedAuthenticator = encoder.encode(authenticator)

    # Key Usage 11
    # AP-REQ Authenticator (includes application authenticator
    # subkey), encrypted with the application session key
    # (Section 5.5.1)
    encryptedEncodedAuthenticator = cipher.encrypt(sessionKey, 11, encodedAuthenticator, None)

    apReq['authenticator'] = noValue
    apReq['authenticator']['etype'] = cipher.enctype
    apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator

    blob['MechToken'] = encoder.encode(apReq)

    request = ldap3.operation.bind.bind_operation(connection.version, ldap3.SASL, user, None, 'GSS-SPNEGO',
                                                  blob.getData())

    # Done with the Kerberos saga, now let's get into LDAP
    if connection.closed:  # try to open connection if closed
        connection.open(read_server_info=False)

    connection.sasl_in_progress = True
    response = connection.post_send_single_response(connection.send('bindRequest', request, None))
    connection.sasl_in_progress = False
    if response[0]['result'] != 0:
        raise Exception(response)

    connection.bound = True

    return True

class magic:
    _separator = '--------------------'
    # bofhound expects some attributes in a certain format
    _base64_attributes = ['nTSecurityDescriptor', 'msDS-GenerationId', 'auditingPolicy', 'dSASignature', 'mS-DS-CreatorSID',
    'logonHours', 'schemaIDGUID']
    _raw_attributes = ['whenCreated', 'whenChanged', 'dSCorePropagationData', 'accountExpires', 'badPasswordTime', 'pwdLastSet',
    'lastLogonTimestamp', 'lastLogon', 'lastLogoff', 'maxPwdAge', 'minPwdAge', 'creationTime', 'lockOutObservationWindow',
    'lockoutDuration']
    _bracketed_attributes = ['objectGUID']
    _ignore_attributes = ['userCertificate']
        
    def __init__(self, ldap_server, ldap_session, domain, logs_dir):
        self.ldap_server = ldap_server
        self.ldap_session = ldap_session
        self.search_base = get_dn(domain)
        self.attributes =  ['*', 'ntsecuritydescriptor']
        self.FORCE_CHANGE_PASSWORD = "00299570-246d-11d0-a768-00aa006e0529"
        self.WRITE_SPN = self.resolve_key("(cn=Service-Principal-Name)")
        self.WRITE_KEY = self.resolve_key("(cn=ms-DS-Key-Credential-Link)")
        self.GET_CHANGES = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
        self.GET_CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
        self.ALLOWED_TO_ACT = "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79"
        self.WRITE_MEMBER = "bf9679c0-0de6-11d0-a285-00aa003049e2"
        self.ADD_ALLOWED_TO_ACT = "4c164200-20c0-11d0-a768-00aa006e0529"
        self.logs_dir = logs_dir

    def _prep_log(self):
        ts = time.strftime('%Y%m%d')
        self.filename = f'{self.logs_dir}/aced_{ts}.log'

    def _printlog(self, line, log=False):
        with open(self.filename, 'a') as f:
            f.write(f'{line}\n')

    def fetch_users(self, ldap_session, search_target, logs_dir):
        try:
            controls = ldap3.protocol.microsoft.security_descriptor_control(sdflags=0x07)
            ldap_session.extend.standard.paged_search(self.search_base, search_target, attributes=self.attributes, controls=controls, paged_size=500, generator=False)
        except ldap3.core.exceptions.LDAPAttributeError as e:
            print()
            logging.critical(f'Error: {str(e)}')
            exit()
        
        self._prep_log()  
        for entry in ldap_session.entries:
            self._printlog(self._separator)
            json_entry = json.loads(entry.entry_to_json())
            attributes = json_entry['attributes'].keys()
            user = Response()
            #what attributes we want to show the user
            for attr in attributes:
                if attr == 'nTSecurityDescriptor':
                    secdesc = (entry[attr].value)
                    user.security_descriptor.fromString(secdesc)
                elif attr == 'description':
                    user.description = (entry[attr].value)
                elif attr == 'dNSHostName':
                    user.dnshostname = (entry[attr].value)
            yield user
            
            for attr in attributes:
                try:
                    value = self._get_formatted_value(entry, attr)
                except:
                    value = None
                    logging.debug(f'Error formatting value of attribute {attr}: {entry[attr].value}')
                if value is not None:
                    self._printlog(f'{attr}: {value}')
        self._printlog(f'Retrieved {len(self.ldap_session.entries)} results total', log=True)
    
    def _get_formatted_value(self, entry, attr):
        if attr in self._ignore_attributes:
            return None
        
        # sid encoding can be funny, use ldap3 func to handle and return
        if attr == 'objectSid':
            return format_sid(entry[attr][0])

        if attr in self._raw_attributes:
            val = entry[attr].raw_values[0].decode('utf-8')
        elif type(entry[attr].value) is list:
            if type(entry[attr].value[0]) is bytes:
                strings = [val.decode('utf-8') for val in entry[attr].value]
                val = ', '.join(strings)
            else:
                val = ', '.join(entry[attr].value)
        elif attr in self._base64_attributes:
            val = base64.b64encode(entry[attr].value).decode('utf-8')
        elif attr in self._bracketed_attributes:
            if attr == 'objectGUID':
                val = format_uuid_le(entry[attr].value)[1:-1]
            else:
                val = entry[attr].value[1:-1]
        else:
            val = entry[attr].value

        if type(val) is bytes:
            try:
                val = val.decode('utf-8')
            except UnicodeDecodeError as e:
                logging.debug(f'Unable to decode {attr} as utf-8')
                raise(UnicodeDecodeError)

        return val                

    def resolve_key(self, key):
        guid = ""
        guid_filter = key
        search_base = "CN=Schema,CN=Configuration,{}".format(self.search_base)

        try:
            self.ldap_session.search(search_base, guid_filter, attributes = '*')
        except ldap3.core.exceptions.LDAPAttributeError as e:
                    print()
                    logging.critical(f'Error: {str(e)}')
                    exit()

        for entry in self.ldap_session.entries:
            json_entry = json.loads(entry.entry_to_json())
            attributes = json_entry['attributes'].keys()
            for attr in attributes:
                if attr == 'schemaIDGUID':
                    guid = guid_to_string(entry[attr].value)
        return guid
            
    def print_user(self, user, sids_resolver):
        owner_sid = user.owner_sid.formatCanonical()
        owner_domain, owner_name = sids_resolver.get_name_from_sid(owner_sid)
        if user.description:
            print("Description: {}".format(user.description))
        if user.dnshostname:
            print("DNS Hostnae: {}".format(user.dnshostname))
        print("Owner SID: {} {}\{}".format(user.owner_sid.formatCanonical(), owner_domain, owner_name))

        #write perms
        write_owner_sids = set()
        write_dacl_sids = set()
        writespn_property_sids = set()
        writekeycred_property_sids = set()
        addself_property_sids = set()
        writemember_property_sids = set()
        allowedtoact_property_sids = set()

        #generic perms
        genericall_property_sids = set()
        genericwrite_property_sids = set()

        # Extended perms
        changepass_property_sids = set()
        allextended_property_sids = set()
        getchanges_property_sids = set()
        getchanges_all_property_sids = set()

        #RBCD
        rbcd_property_sids = set()


        for ace in user.dacl.aces:
            #ACE type 0x05
            if ace["TypeName"] == "ACCESS_ALLOWED_OBJECT_ACE":
                ace = ace["Ace"]
                mask = ace["Mask"]
                sid = ace["Sid"].formatCanonical()

                if ace.hasFlag(ace.ACE_OBJECT_TYPE_PRESENT):
                    #check generics first
                    if mask.hasPriv(ACCESS_MASK.GENERIC_ALL):
                        genericall_property_sids.add(sid)
                    elif mask.hasPriv(ACCESS_MASK.GENERIC_WRITE):
                        genericwrite_property_sids.add(sid)
                    elif mask.hasPriv(ACCESS_MASK.WRITE_OWNER):
                        write_owner_sids.add(sid)
                    elif mask.hasPriv(ACCESS_MASK.WRITE_DACL):
                        write_dacl_sids.add(sid)

                    # ForceChangePassword
                    elif guid_to_string(ace["ObjectType"]) == self.FORCE_CHANGE_PASSWORD:
                        changepass_property_sids.add(sid)
                    # getchanges
                    elif guid_to_string(ace["ObjectType"]) == self.GET_CHANGES:
                        getchanges_property_sids.add(sid)
                    # getchangesall
                    elif guid_to_string(ace["ObjectType"]) == self.GET_CHANGES_ALL:
                        getchanges_all_property_sids.add(sid)
                    elif mask.hasPriv(ace.ADS_RIGHT_DS_WRITE_PROP):
                        #whisker
                        if guid_to_string(ace["ObjectType"]) == self.WRITE_KEY:
                            writekeycred_property_sids.add(sid)
                        #targeted kerberoast
                        elif guid_to_string(ace["ObjectType"]) == self.WRITE_SPN:
                            writespn_property_sids.add(sid)
                        # add user to group
                        if guid_to_string(ace["ObjectType"]) == self.WRITE_MEMBER:
                            writemember_property_sids.add(sid)
                        #RBCD
                        elif guid_to_string(ace["ObjectType"]) == self.ADD_ALLOWED_TO_ACT:
                            rbcd_property_sids.add(sid)
                    #need to get this working
                    # elif mask.hasPriv(ace.ADS_RIGHT_DS_READ_PROP):
                    # 	if guid_to_string(ace["ObjectType"]) == READ_LAPS:
                    # 		readlaps_property_sids.add(sid)

                    # add self to group
                    elif mask.hasPriv(ace.ADS_RIGHT_DS_SELF):
                        if guid_to_string(ace["ObjectType"]) == self.WRITE_MEMBER:
                            addself_property_sids.add(sid)
                # empty objecttype but ADS_RIGHT true means it applies to all objects
                if not ace.hasFlag(ace.ACE_OBJECT_TYPE_PRESENT):
                    # all extended rights
                    if mask.hasPriv(ace.ADS_RIGHT_DS_CONTROL_ACCESS):
                        allextended_property_sids.add(sid)
                    # generic write
                    elif mask.hasPriv(ace.ADS_RIGHT_DS_WRITE_PROP):
                        genericwrite_property_sids.add(sid)

            #ACE type 0x00
            elif ace["TypeName"] == "ACCESS_ALLOWED_ACE":
                ace = ace["Ace"]
                mask = ace["Mask"]
                sid = ace["Sid"].formatCanonical()
                if mask.hasPriv(ACCESS_MASK.GENERIC_ALL):
                    genericall_property_sids.add(sid)
                if mask.hasPriv(ACCESS_MASK.GENERIC_WRITE):
                    genericwrite_property_sids.add(sid)
                if mask.hasPriv(ACCESS_MASK.WRITE_OWNER):
                    write_owner_sids.add(sid)
                if mask.hasPriv(ACCESS_MASK.WRITE_DACL):
                    write_dacl_sids.add(sid)
                if mask.hasPriv(ACCESS_MASK.ADS_RIGHT_DS_CONTROL_ACCESS):
                    allextended_property_sids.add(sid)
		# print the stuff
        print("  Interesting Permissions:")
        print("    Principals that can change target's password:")
        if len(changepass_property_sids) > 0:
            print_sids(changepass_property_sids, sids_resolver, offset=6)
        else:
            print("      No entries found.")

        print("    Principals that can modify the SPN attribute:")
        if len(writespn_property_sids) > 0:
            print_sids(writespn_property_sids, sids_resolver, offset=6)
        else:
            print("      No entries found.")

        print("    Principals that can modify the msDS-KeyCredentialLink attribute:")
        if len(writekeycred_property_sids) > 0:
            print_sids(writekeycred_property_sids, sids_resolver, offset=6)
        else:
            print("      No entries found.")

        print("    Principals with AllExtendedRights:")
        if len(allextended_property_sids) > 0:
            print_sids(allextended_property_sids, sids_resolver, offset=6)
        else:
            print("      No entries found.")

        print("    Principals with ms-DS-Allowed-To-Act-On-Behalf-Of-Other-Identity (RBCD):")
        if len(rbcd_property_sids) > 0:
            print_sids(rbcd_property_sids, sids_resolver, offset=6)
        else:
            print("      No entries found.")
        print("")

        # DCSYNC
        if (len(getchanges_property_sids) > 0) or (len(getchanges_all_property_sids) > 0):
            print("  DCSYNC Rights:")
            print("    Principals with GetChanges:")
            if len(getchanges_property_sids) > 0:
                print_sids(getchanges_property_sids, sids_resolver, offset=6)
            if len(getchanges_all_property_sids) > 0:
                print("    Principals with GetChangesAll:")
            print_sids(getchanges_all_property_sids, sids_resolver, offset=6)
        print ("")

        # write permissions
        print("  Write Permissions:")
        print("    Principals with Write Owner:")
        print_sids(write_owner_sids, sids_resolver, offset=6)

        print("    Principals with write DACL:")
        print_sids(write_dacl_sids, sids_resolver, offset=6)
        print("")

        # group permissionsa
        if (len(writemember_property_sids) > 0) or (len(addself_property_sids) > 0):
            print("  Group Permissions:")
            print("   Principals that can add members to group:")
            if len(writemember_property_sids) > 0:
                print_sids(writemember_property_sids, sids_resolver, offset=6)
            else: print("      No entries found.")
            print("    Principals that can add themself to group:")
            if len(addself_property_sids) > 0:
                print_sids(addself_property_sids, sids_resolver, offset=6)
            else: print("      No entries found.")
        print("")

        # generic permissions
        if (len(genericwrite_property_sids) > 0) or (len(genericall_property_sids) > 0):
            print("  Generic Permissions:")
            print("    Principals with Generic Write:")
            if len(genericwrite_property_sids) > 0:
                print_sids(genericwrite_property_sids, sids_resolver, offset=6)
            else:
                print("      No entries found.")
            print("    Principals with Generic All:")
            if len(genericall_property_sids) > 0:
                print_sids(genericall_property_sids, sids_resolver, offset=6)
            else:
                print("      No entries found.")
        print("")

#ignoresids = ["S-1-3-0", "S-1-5-18", "S-1-5-10", "S-1-1-0"]
def print_sids(sids, sids_resolver, offset=0):
	blanks = " " * offset
	msg = []
	ignoresids = ["S-1-3-0", "S-1-5-18", "S-1-5-10"]
	for sid in sids:
		if sid not in ignoresids:
			domain, name = sids_resolver.get_name_from_sid(sid)
			msg.append("{} {}\{}".format(sid, domain, name))
	print("\n".join(["{}{}".format(blanks, line) for line in msg]))

def guid_to_string(guid):
    return "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}".format(
        guid[3], guid[2], guid[1], guid[0],
        guid[5], guid[4],
        guid[7], guid[6],
        guid[8], guid[9],
        guid[10], guid[11], guid[12], guid[13], guid[14], guid[15]
    )

def ldap_get_name_from_sid(search_base,ldap_session, sid):
    if type(sid) is not str:
        sid = sid.formatCanonical()

    search_filter = "(objectsid={})".format(sid)
    try:
        ldap_session.search(search_base,search_filter, attributes = '*')
    except ldap3.core.exceptions.LDAPAttributeError as e:
                print()
                logging.critical(f'Error: {str(e)}')
                exit()
    for entry in ldap_session.entries:
        json_entry = json.loads(entry.entry_to_json())
        attributes = json_entry['attributes'].keys()
        for attr in attributes:
            if attr == 'sAMAccountName':
                name = (entry[attr].value)
                return name

def ldap_get_domain_from_sid(search_base, ldap_session, sid):
    if type(sid) is not str:
        sid = sid.formatCanonical()

    search_filter = "(objectsid={})".format(sid)
    try:
        ldap_session.search(search_base, search_filter, attributes = '*')
    except ldap3.core.exceptions.LDAPAttributeError as e:
                print()
                logging.critical(f'Error: {str(e)}')
                exit()
    for entry in ldap_session.entries:
        json_entry = json.loads(entry.entry_to_json())
        attributes = json_entry['attributes'].keys()
        for attr in attributes:
            if attr == 'name':
                return str(entry[attr].value)

                name = ".".join([x.lstrip("DC=") for x in value.split(",")])
                return 


def bofhound_logging():
	# check for first time usage
	home = os.path.expanduser('~')
	aced_dir = f'{home}/.aced'
	logs_dir = f'{aced_dir}/logs'

	if not os.path.isdir(aced_dir):
		logging.info('First time usage detected')
		logging.info(f'Aced output will be logged to {logs_dir}')
		os.mkdir(aced_dir)
		print()

	if not os.path.isdir(logs_dir):
		os.mkdir(logs_dir)
	return logs_dir



def main():
    print(show_banner)
    args = arg_parse()
    debug = args.debug

    if debug:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    logger.init()
    logs_dir = bofhound_logging()
    try:
        ldap_server, ldap_session = init_ldap_session(domain=args.userdomain,
        username=args.username,
        password=args.password,
        lmhash=args.lmhash,
        nthash=args.nthash,
        kerberos=args.kerberos,
        domain_controller=args.dc_ip,
        aesKey=args.aes,
        no_smb=args.no_smb,
        hashes=args.hashes,
        ldaps=args.ldaps
        )
    except ldap3.core.exceptions.LDAPSocketOpenError as e: 
        if 'invalid server address' in str(e):
            logging.critical(f'Invalid server address - {args.userdomain}')
        else:
            logging.critical('Error connecting to LDAP server')
            print()
            print(e)
        exit()
    except ldap3.core.exceptions.LDAPBindError as e:
        logging.critical(f'Error: {str(e)}')
        exit()
    domain=args.userdomain
    sids_resolver = SidsResolver(ldap_server, ldap_session, domain)
    build_filter = input ("Enter target sAMAccountName or distinguishedName: ").lower()
    ldapsearch=magic(ldap_server, ldap_session, domain, logs_dir) 
    while True:
        if "dc=" in build_filter:
            search = "(distinguishedName={})".format(build_filter)
            ldap_filter=search
            logging.info(f'Searching for: {build_filter}')
        elif build_filter == "exit":
            logging.info(f'User entered exit. Stopping session.')
            logging.info(f'Results written to {logs_dir}')
            break
        else:
            search = "(sAMAccountName={})".format(build_filter)
            ldap_filter = search
            logging.info(f'Searching for: {build_filter}')

        test = list(ldapsearch.fetch_users(ldap_session, ldap_filter, logs_dir))
        if not test:
            logging.info (f'Target {build_filter} not found.')
            build_filter = input ("Enter target sAMAccountName or distinguishedName: ").lower()
        else:
            for user in test:
                ldapsearch.print_user(user, sids_resolver)
                build_filter = input ("Enter target sAMAccountName or distinguishedName: ").lower()

class SidsResolver:

    def __init__(self, ldap_server, ldap_session, domain):
        self.ldap_server = ldap_server
        self.ldap_session = ldap_session
        self.search_base = get_dn(domain)
        self.cached_sids = {}
        self.domain_sids = {}

    def get_name_from_sid(self, sid):
        if type(sid) is not str:
            sid = sid.formatCanonical()

        try:
            return ("BUILTIN", KNOWN_SIDS[sid])
        except KeyError:
            pass

        try:
            return self.cached_sids[sid]
        except KeyError:
            pass

        domain_sid = "-".join(sid.split("-")[:-1])
        domain = self.get_domain_from_sid(domain_sid)


        name = ldap_get_name_from_sid(self.search_base, self.ldap_session, sid)
        self.cached_sids[sid] = (domain, name)

        return (domain, name)

    def get_domain_from_sid(self, sid):
        try:
            return self.domain_sids[sid]
        except KeyError:
            pass

        name = ldap_get_domain_from_sid(self.search_base, self.ldap_session, sid)
        self.domain_sids[sid] = name
        return name

#thanks dirkjan
class ACCESS_MASK:
    # Flag constants

    # These constants are only used when WRITING
    # and are then translated into their actual rights
    SET_GENERIC_READ        = 0x80000000
    SET_GENERIC_WRITE       = 0x04000000
    SET_GENERIC_EXECUTE     = 0x20000000
    SET_GENERIC_ALL         = 0x10000000
    # When reading, these constants are actually represented by
    # the following for Active Directory specific Access Masks
    # Reference: https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2
    GENERIC_READ            = 0x00020094
    GENERIC_WRITE           = 0x00020028
    GENERIC_EXECUTE         = 0x00020004
    GENERIC_ALL             = 0x000F01FF

    # These are actual rights (for all ACE types)
    MAXIMUM_ALLOWED         = 0x02000000
    ACCESS_SYSTEM_SECURITY  = 0x01000000
    SYNCHRONIZE             = 0x00100000
    WRITE_OWNER             = 0x00080000
    WRITE_DACL              = 0x00040000
    READ_CONTROL            = 0x00020000
    DELETE                  = 0x00010000

    # ACE type specific mask constants (for ACCESS_ALLOWED_OBJECT_ACE)
    # Note that while not documented, these also seem valid
    # for ACCESS_ALLOWED_ACE types
    ADS_RIGHT_DS_CONTROL_ACCESS         = 0x00000100
    ADS_RIGHT_DS_CREATE_CHILD           = 0x00000001
    ADS_RIGHT_DS_DELETE_CHILD           = 0x00000002
    ADS_RIGHT_DS_READ_PROP              = 0x00000010
    ADS_RIGHT_DS_WRITE_PROP             = 0x00000020
    ADS_RIGHT_DS_SELF                   = 0x00000008

    def __init__(self, mask):
        self.mask = mask

    def has_priv(self, priv):
        return self.mask & priv == priv

    def set_priv(self, priv):
        self.mask |= priv

    def remove_priv(self, priv):
        self.mask ^= priv

    def __repr__(self):
        out = []
        for name, value in iteritems(vars(ACCESS_MASK)):
            if not name.startswith('_') and type(value) is int and self.has_priv(value):
                out.append(name)
        return "<ACCESS_MASK RawMask=%d Flags=%s>" % (self.mask, ' | '.join(out))


if __name__ == '__main__':
    main()
