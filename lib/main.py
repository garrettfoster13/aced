#! /usr/bin/python3

import argparse
from getpass import getpass
import base64
import sys
import binascii

from impacket.examples.utils import parse_credentials, parse_target
from impacket.uuid import string_to_bin, bin_to_string

from .ldap import connect_ldap, get_base_dn, search_ldap, ldap_results, security_descriptor_control, SR_SECURITY_DESCRIPTOR, ACCESS_ALLOWED_OBJECT_ACE, ACCESS_ALLOWED_ACE
from .response import Response
from .sid import KNOWN_SIDS, name_from_sid
import traceback

EXTRIGHTS_GUID_MAPPING = {
    "GetChanges": string_to_bin("1131F6AA-9C07-11D1-F79F-00C04FC2DCD2"),
    "GetChangesAll": string_to_bin("1131F6AD-9C07-11D1-F79F-00C04FC2DCD2"),
    "WriteMember": string_to_bin("BF9679C0-0DE6-11D0-A285-00AA003049E2"),
    "UserForceChangePassword": string_to_bin("00299570-246D-11D0-A768-00AA006E05299"),
    "AllowedToAct": string_to_bin("3F78C3E5-F79A-46BD-A0B8-9D18116DDC79"),
    "WriteSPN": string_to_bin("F3A64788-5306-11D1-A9C5-0000F80367C1"),
}


def arg_parse():
	parser = argparse.ArgumentParser(add_help=True, description="Tool to enumerate a single target's DACL in Active Directory")

	auth_group = parser.add_argument_group("Authentication Settings")
	search_group = parser.add_argument_group("Search target")

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
	search_group.add_argument(
		"-principal",
		required=True,
		help="Account name to search for")

	if len(sys.argv) == 1:
		parser.print_help()
		sys.exit(1)

	#parse auth
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

def fetch_users(ldap_conn, domain, principal):

	user_filter = "(sAMAccountName={})".format(principal)
	search_base = "{}".format(get_base_dn(domain))
	print ()
	resp = search_ldap(
		ldap_conn,
		user_filter,
		search_base,
		controls = security_descriptor_control(sdflags=0x05))

	for item in ldap_results(resp):
		if not item:
			print("Principal Not Found")
			exit()
		else:
			user = Response()

			for attribute in item['attributes']:
				at_type=str(attribute['type'])
				if at_type == 'sAMAccountName':
					user.samaccountname = str(attribute['vals'][0])
				elif at_type == 'description':
					user.description = str(attribute['vals'][0])
				elif at_type == 'nTSecurityDescriptor':
					secdesc = attribute['vals'][0].asOctets()
					user.security_descriptor.fromString(secdesc)
			yield user

#objecttypes
FORCE_CHANGE_PASSWORD = "00299570-246d-11d0-a768-00aa006e0529"
WRITE_SPN = "f3a64788-5306-11d1-a9c5-0000f80367c1"
WRITE_KEY = "5b47d60f-6090-40b2-9f37-2a4de88f3063"
GET_CHANGES = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
GET_CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
ALLOWED_TO_ACT = "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79"
WRITE_MEMBER = "bf9679c0-0de6-11d0-a285-00aa003049e2"
			
def print_user(user, sids_resolver):
	print ("Name: {}".format(user.samaccountname))
	print ("Description: {}".format(user.description))
	owner_sid = user.owner_sid.formatCanonical()
	owner_domain, owner_name = sids_resolver.get_name_from_sid(owner_sid)
	print("Owner SID: {} {}\{}".format(user.owner_sid.formatCanonical(), owner_domain, owner_name))

	#write ACEs
	write_owner_sids = set()
	write_dacl_sids = set()
	writespn_property_sids = set()
	writekeycred_property_sids = set()
	addself_property_sids = set()
	writemember_property_sids = set()
	allowedtoact_property_sids = set()
	
	#generic ACEs
	genericall_property_sids = set()
	genericwrite_property_sids = set()

	# Extended Rights
	changepass_property_sids = set()
	allextended_property_sids = set()
	getchanges_property_sids = set()
	getchanges_all_property_sids = set()

	# Read
	readlaps_property_sids = set()

	for ace in user.dacl.aces:
		#ACE type 0x05
		if ace["TypeName"] == "ACCESS_ALLOWED_OBJECT_ACE":
			ace = ace["Ace"]
			mask = ace["Mask"]
			sid = ace["Sid"].formatCanonical()
			if ace.hasFlag(ace.ACE_OBJECT_TYPE_PRESENT):
				# ForceChangePassword
				if guid_to_string(ace["ObjectType"]) == FORCE_CHANGE_PASSWORD:
					changepass_property_sids.add(sid)
				# getchanges
				elif guid_to_string(ace["ObjectType"]) == GET_CHANGES:
					getchanges_property_sids.add(sid)
				# getchangesall
				elif guid_to_string(ace["ObjectType"]) == GET_CHANGES_ALL:
					getchanges_all_property_sids.add(sid)
				elif mask.hasPriv(ace.ADS_RIGHT_DS_WRITE_PROP):
					#whisker
					if guid_to_string(ace["ObjectType"]) == WRITE_KEY:
						writekeycred_property_sids.add(sid)
					#targeted kerberoast
					elif guid_to_string(ace["ObjectType"]) == WRITE_SPN:
						writespn_property_sids.add(sid)
					# add user to group
					elif guid_to_string(ace["ObjectType"]) == WRITE_MEMBER:
						writemember_property_sids.add(sid)
					#RBCD
					elif guid_to_string(ace["ObjectType"]) == ALLOWED_TO_ACT:
						allowedtoact_property_sids.add(sid)
				# elif mask.hasPriv(ace.ADS_RIGHT_DS_READ_PROP):
				# 	if guid_to_string(ace["ObjectType"]) == READ_LAPS:
				# 		readlaps_property_sids.add(sid)

				# add self to group
				elif mask.hasPriv(ace.ADS_RIGHT_DS_SELF):
					if guid_to_string(ace["ObjectType"]) == WRITE_MEMBER:
						addself_property_sids.add(sid)
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
			if mask.hasPriv(mask.GENERIC_ALL):
				genericall_property_sids.add(sid)
			if mask.hasPriv(mask.GENERIC_WRITE):
				genericwrite_property_sids.add(sid)
			if mask.hasPriv(mask.WRITE_OWNER):
				write_owner_sids.add(sid)
			if mask.hasPriv(mask.WRITE_DACL):
				write_dacl_sids.add(sid)

		else:
			continue


		# list of permissions we care about:
		# ReadLAPSPassword


		# Generic Write
		if mask.hasPriv(mask.GENERIC_WRITE):
			write_property_sids.add(sid)

		# #Write DACL
		if mask.hasPriv(mask.WRITE_DACL):
			write_dacl_sids.add(sid)

		# Write Owner
		if mask.hasPriv(mask.WRITE_OWNER):
			write_owner_sids.add(sid)

		# Generic All
		if mask.hasPriv(mask.GENERIC_ALL):
			genericall_property_sids.add(sid)

	print("\n  Interesting Permissions:")
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
	print("")

	if (len(getchanges_property_sids) > 0) or (len(getchanges_all_property_sids) > 0):
		print("  DCSYNC Rights:")
		print("    Principals with GetChanges:")
		if len(getchanges_property_sids) > 0:
			print_sids(getchanges_property_sids, sids_resolver, offset=6)
		if len(getchanges_all_property_sids) > 0:
			print("    Principals with GetChangesAll:")
		print_sids(getchanges_all_property_sids, sids_resolver, offset=6)

	# write permissions
	print("  Write Permissions:")
	print("    Principals with Write Owner:")
	print_sids(write_owner_sids, sids_resolver, offset=6)

	print("    Principals with write DACL:")
	print_sids(write_dacl_sids, sids_resolver, offset=6)
	print("")

	# group permissionsa

	print("  Group Permissions:")
	print("   Principals that can add members to group:")
	print_sids(writemember_property_sids, sids_resolver, offset=6)
	print("    Principals that can add themself to group:")
	print_sids(addself_property_sids, sids_resolver, offset=6)

	#



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
	principal = args.principal
	test=list(fetch_users(ldap_conn, domain, principal))

	if not test:
		print('Target principal "%s" not found.' % (principal))
		exit()
	else:
		for user in test:
			print_user(user, sids_resolver)


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