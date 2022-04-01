#! /usr/bin/python3

import argparse
from getpass import getpass
import base64
import sys
import binascii

from impacket.examples.utils import parse_credentials, parse_target
from impacket.uuid import string_to_bin, bin_to_string

from .ldap import connect_ldap, get_base_dn, search_ldap, ldap_results, security_descriptor_control, SR_SECURITY_DESCRIPTOR, ACCESS_ALLOWED_OBJECT_ACE
from .response import Response
from .sid import KNOWN_SIDS, name_from_sid
import traceback

EXTRIGHTS_GUID_MAPPING = {
    "GetChanges": string_to_bin("1131F6AA-9C07-11D1-F79F-00C04FC2DCD2"),
    "GetChangesAll": string_to_bin("1131F6AD-9C07-11D1-F79F-00C04FC2DCD2"),
    "WriteMember": string_to_bin("BF9679C0-0DE6-11D0-A285-00AA003049E2"),
    "UserForceChangePassword": string_to_bin("00299570-246D-11D0-A768-00AA006E05299"),
    "AllowedToAct": string_to_bin("3F78C3E5-F79A-46BD-A0B8-9D18116DDC79"),
}


def arg_parse():
	parser = argparse.ArgumentParser(add_help=True, description="Tool to enumerate LDAP")

	auth_group = parser.add_argument_group("Domain Settings")

	auth_group.add_argument(
		'target',
		action='store',
		help='[[domain/username[:password]@]<targetname or address',
		type=target_type
		)

	auth_group.add_argument(
		"-dc", "--dc-ip",
		help = "IP address of domain controller"
		)

	auth_group.add_argument(
		"-k", "--kerberos",
		action="store_true",
		help='Use Kerberos authentication. Retrieves credentials from ccache file '
		'(KRB5CCNAME) based on the target parameters. If valid credentials cannot be found, it will use the '
		'ones specified on the command line'
		)

	auth_group.add_argument(
		"-n", "--no-pass",
		action="store_true",
		help="Don't ask for password. (useful for -k)"
		)

	auth_group.add_argument(
		"--aes",
		action="store_true",
		help="AES key to use for Kerberos Authentication (128 or 256 bits"
		)

	auth_group.add_argument(
		"--hashes",
		help="LM and NT hashes, format is LMHASH:NTHASH"
		)

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
		args.lmhash, args.nthash = args.hashes.split(":")

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


def target_creds_type(target):
    (userdomain, username, password) = parse_credentials(target)

    if username == "":
        raise argparse.ArgumentTypeError("Username should be be specified")

    if userdomain == "":
        raise argparse.ArgumentTypeError(
            "Domain of user '{}' should be be specified".format(username)
        )

    return (userdomain, username, password or '', '')

def fetch_users(ldap_conn, domain):

	user_filter = "(&(!(objectClass=Computer))(objectClass=Person)(sAMAccountName=administrator))"
	search_base = "{}".format(get_base_dn(domain))

	resp = search_ldap(
		ldap_conn,
		user_filter,
		search_base,
		#attributes=["samaccountname","ntsecuritydescriptor"],
		controls = security_descriptor_control(sdflags=0x05))
	
	for item in ldap_results(resp):
		#print (item)
		user = Response()
		for attribute in item['attributes']:
			at_type=str(attribute['type'])
			if at_type == 'sAMAccountName':
				user.samaccountname = str(attribute['vals'][0])
				#print(.samaccountname)
			elif at_type == 'nTSecurityDescriptor':
				secdesc = attribute['vals'][0].asOctets()
				user.security_descriptor.fromString(secdesc)
	yield user

			
def print_user(user, sids_resolver):
	print ("Name: {}".format(user.samaccountname))
	owner_sid = user.owner_sid.formatCanonical()
	owner_domain, owner_name = sids_resolver.get_name_from_sid(owner_sid)
	print("Owner SID: {} {}\{}".format(user.owner_sid.formatCanonical(), owner_domain, owner_name))


	write_owner_sids = set()
	write_dacl_sids = set()
	write_property_sids = set()
	genericall_property_sids = set()
	changepass_property_sids = set()
	allextended_property_sids = set()
	idfwtftodowithtracebacks = []
	for ace in user.dacl.aces:
		try:
			if ace["TypeName"] == "ACCESS_ALLOWED_OBJECT_ACE":
				ace = ace["Ace"]
				mask = ace["Mask"]
				oid = ace["ObjectType"]
				sid = ace["Sid"].formatCanonical()
				flag = ace["Flags"]
				
			elif ace["TypeName"] == "ACCESS_ALLOWED_ACE":
				ace = ace["Ace"]
				mask = ace["Mask"]
				sid = ace["Sid"].formatCanonical()

			elif ace["TypeName"] == "ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_WRITE_PROP":
				ace = ace["Ace"]
				mask = ace["Mask"]
				# oid = ace.acedata.data.ObjectType[0]
				sid = ace["Sid"].formatCanonical()


			if mask.hasPriv(mask.GENERIC_WRITE) \
				or mask.hasPriv(ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_WRITE_PROP):
					write_property_sids.add(sid)
			
			if mask.hasPriv(mask.WRITE_DACL):
				write_dacl_sids.add(sid)

			if mask.hasPriv(mask.WRITE_OWNER):
				write_owner_sids.add(sid)

			if mask.hasPriv(mask.GENERIC_ALL):
				genericall_property_sids.add(sid)

			if mask.hasPriv(ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_CONTROL_ACCESS):
				allextended_property_sids.add(sid)

			if oid == EXTRIGHTS_GUID_MAPPING['UserForceChangePassword']:
				changepass_property_sids.add(sid)


		except Exception:
			idfwtftodowithtracebacks.append(traceback.format_exc())





	#interesting abusable permissions
	print("  Interesting Permissions:")
	print("    Principals that can change target's password:")
	if len(changepass_property_sids) == 0:
		print ("      *Null*\n")
	else:
		print_sids(changepass_property_sids, sids_resolver, offset=6)

	print("    Principals with AllExtendedRights (can do anything):")
	print_sids(allextended_property_sids, sids_resolver, offset=6)

	print("\n    Principals with Generic All:")
	print_sids(genericall_property_sids, sids_resolver, offset=6)

	print ("")
	print ("")



	print("  Write Permissions")
	print("    Principals with Write Owner:")
	print_sids(write_owner_sids, sids_resolver, offset=6)

	print("    Principals with write DACL:")
	print_sids(write_dacl_sids, sids_resolver, offset=6)

	print("    Principals with write Property:")
	print_sids(write_property_sids, sids_resolver, offset=6)

def print_sids(sids, sids_resolver, offset=0):
	blanks = " " * offset
	msg = []
	ignoresids = ["S-1-3-0", "S-1-5-18", "S-1-5-10", "S-1-1-0"]
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


def ldap_get_name_from_sid(ldap_conn, sid):
    if type(sid) is not str:
        sid = sid.formatCanonical()

    sid_filter = "(objectsid={})".format(sid)
    resp = search_ldap(ldap_conn, sid_filter)

    for item in ldap_results(resp):
        for attribute in item['attributes']:
            if str(attribute["type"]) == "sAMAccountName":
                name = str(attribute["vals"][0])
                return name

def ldap_get_domain_from_sid(ldap_conn, sid):
    if type(sid) is not str:
        sid = sid.formatCanonical()

    sid_filter = "(objectsid={})".format(sid)
    resp = search_ldap(ldap_conn, sid_filter)

    for item in ldap_results(resp):
        for attribute in item['attributes']:
            at_type = str(attribute["type"])
            if at_type == "name":
                return str(attribute["vals"][0])

                name = ".".join([x.lstrip("DC=") for x in value.split(",")])
                return 

def main():

	args = arg_parse()
	ldap_conn = connect_ldap(
		domain=args.userdomain,
		user=args.username,
		password=args.password,
		lmhash=args.lmhash,
		nthash=args.nthash,
		aesKey=args.aes,
		dc_ip=args.address,
		kerberos=args.kerberos
	)

	sids_resolver = SidsResolver(ldap_conn)
	domain = args.userdomain
	test=list(fetch_users(ldap_conn, domain))
	for user in test:
		print_user(user, sids_resolver)
	#for blah in test:
	#print_user(test, sids_resolver)
	# for secdesc in test:
	# 	print_user(secdesc, sids_resolver)
	# 	print ("")




class SidsResolver:

    def __init__(self, ldap_conn):
        self.ldap_conn = ldap_conn
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


        name = ldap_get_name_from_sid(self.ldap_conn, sid)
        self.cached_sids[sid] = (domain, name)

        return (domain, name)

    def get_domain_from_sid(self, sid):
        try:
            return self.domain_sids[sid]
        except KeyError:
            pass

        name = ldap_get_domain_from_sid(self.ldap_conn, sid)
        self.domain_sids[sid] = name
        return name




if __name__ == '__main__':
    main()