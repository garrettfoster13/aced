
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR


class Response:
    
    def __init__(self):
        self.security_descriptor = SR_SECURITY_DESCRIPTOR()
        self.dnshostname = ""
        self.objectsid = ""
        self.sAMAccountName = ""
        self.description = ""
        self.memberOf = ""
        self.members = ""



    def query(self):
        for attribute in item['attributes']:
            print(attribute)

    @property
    def owner_sid(self):
        return self.security_descriptor['OwnerSid']
        print(self.owner_sid)

    @property
    def dacl(self):
        return self.security_descriptor["Dacl"]

    # def group_members(self):
    #     x = str(attribute['vals'])
    #     y = "".join(x.splitlines())
    #     z = y.replace('SetOf: ', '').replace(' CN=',', CN=')
    #     return self.memberOf



