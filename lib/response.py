

from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR, ACCESS_ALLOWED_OBJECT_ACE, ACCESS_ALLOWED_ACE, ACE


class Response:
    
    def __init__(self):
        self.security_descriptor = SR_SECURITY_DESCRIPTOR()
        self.dnshostname = ""
        self.objectsid = ""
        self.sAMAccountName = ""
        self.description = ""
        self.memberOf = ""
        self.members = ""



    @property
    def owner_sid(self):
        return self.security_descriptor['OwnerSid']
        print(self.owner_sid)

    @property
    def dacl(self):
        return self.security_descriptor["Dacl"]