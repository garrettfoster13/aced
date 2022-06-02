#! /usr/bin/python3
import base64
from ldap3.protocol.formatters.formatters import format_uuid_le
from ldap3.protocol.formatters.formatters import format_sid
from impacket.ldap.ldaptypes import LDAP_SID
from impacket.ldap import ldap, ldapasn1
import logging
from impacket.examples import logger

import time

class logoutput:

    _separator = '--------------------'
    # bofhound expects some attributes in a certain format
    _base64_attributes = ['nTSecurityDescriptor', 'msDS-GenerationId', 'auditingPolicy', 'dSASignature', 'mS-DS-CreatorSID',
        'logonHours', 'schemaIDGUID']
    _raw_attributes = ['whenCreated', 'whenChanged', 'dSCorePropagationData', 'accountExpires', 'badPasswordTime', 'pwdLastSet',
        'lastLogonTimestamp', 'lastLogon', 'lastLogoff', 'maxPwdAge', 'minPwdAge', 'creationTime', 'lockOutObservationWindow',
        'lockoutDuration']
    _bracketed_attributes = ['objectGUID']
    _annoying_attributes = ['memberOf', 'member']
    _ignore_attributes = ['userCertificate', 'dNSHostName']
    
    def __init__(self, item, logs_dir):
        self.logs_dir = logs_dir
        self.item = item
        self._prep_log()


    def _prep_log(self):
        ts = time.strftime('%Y%m%d')
        self.filename = f'{self.logs_dir}/aced_{ts}.log'


    def _printlog(self, line):
        with open(self.filename, 'a') as f:
            f.write(f'{line}\n')
    
    def guid_to_string(self, guid):
        return "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}".format(
            guid[3], guid[2], guid[1], guid[0],
            guid[5], guid[4],
            guid[7], guid[6],
            guid[8], guid[9],
            guid[10], guid[11], guid[12], guid[13], guid[14], guid[15]
        )

    def query(self):
        at_type = ""
        self._printlog(self._separator)
        for attribute in self.item['attributes']:
            at_type = str(attribute['type'])
            if at_type in self._raw_attributes:
                val = (attribute['vals'][0])
                self._printlog("{}: {}".format(at_type, val))
            elif at_type in self._base64_attributes:
                entry = (attribute['vals'][0]).asOctets()
                val = base64.b64encode(entry)
                val = val.decode()
                self._printlog("{}: {}".format(at_type, val))
            elif at_type in self._bracketed_attributes:
                if at_type == 'objectGUID':
                    val = self.guid_to_string(attribute['vals'][0])
                    self._printlog("{}: {}".format(at_type, val))
            elif at_type == 'objectSid':
                entry = (attribute['vals'][0])
                val=format_sid(entry)
                self._printlog("{}: {}".format(at_type, val))
            elif at_type in self._annoying_attributes:
                x = str(attribute['vals'])
                y = "".join(x.splitlines())
                z = y.replace('SetOf: ', '').replace(' CN=',', CN=')
                self._printlog("{}: {}".format(at_type, z))
            elif at_type == 'objectClass':
                x = str(attribute['vals'])
                y = "".join(x.splitlines())
                z = y.replace('SetOf: ', '').replace(' ',', ')
                self._printlog("{}: {}".format(at_type, z))
            else:
                val = (attribute['vals'][0])
                self._printlog("{}: {}".format(at_type, val))
        self._printlog(f'Retrieved {len(self.item)} results total')
        