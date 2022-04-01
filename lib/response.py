
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR


class Response:

    def __init__(self):
        self.samaccountname = ""
        self.security_descriptor = SR_SECURITY_DESCRIPTOR()


    @property
    def owner_sid(self):
        return self.security_descriptor['OwnerSid']

    @property
    def dacl(self):
        return self.security_descriptor["Dacl"]

