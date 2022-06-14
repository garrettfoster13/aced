# Aced

Aced is a tool to parse and resolve a singe targeted Active Directory principal's DACL. Aced will parse for intresting inbound access allowed privileges against the targeted account, resolve the SIDS of the inbound permissions, and present that data to the operator. Additionally, the logging features of [pyldapsearch](https://github.com/fortalice/pyldapsearch) have been integrated with Aced to log the targeted principal's LDAP attributes locally which can then be parsed by pyldapsearch's companion tool [BOFHound](https://github.com/fortalice/bofhound) to ingest the collected data into BloodHound.

Tool to parse and resolve a single target Active Directory account's DACL.

## Usage

```
└─# python3 aced.py -h                             


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

usage: aced.py [-h] [-ldaps] [-dc-ip DC_IP] [-k] [-no-pass] [-hashes LMHASH:NTHASH] [-aes hex key] [-debug] [-no-smb] target

Tool to enumerate a single target's DACL in Active Directory

optional arguments:
  -h, --help            show this help message and exit

Authentication:
  target                [[domain/username[:password]@]<address>
  -ldaps                Use LDAPS isntead of LDAP

Optional Flags:
  -dc-ip DC_IP          IP address or FQDN of domain controller
  -k, --kerberos        Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid
                        credentials cannot be found, it will use the ones specified in the command line
  -no-pass              don't ask for password (useful for -k)
  -hashes LMHASH:NTHASH
                        LM and NT hashes, format is LMHASH:NTHASH
  -aes hex key          AES key to use for Kerberos Authentication (128 or 256 bits)
  -debug                Enable verbose logging.
  -no-smb               Do not resolve DC hostname through SMB. Requires a FQDN with -dc-ip.
```
# Use case?

I wrote Aced simply because I wanted a more targeted approach to query ACLs. Bloodhound is fantastic, however, it is extremely noisy. Bloodhound collects all the things while Aced collects a single thing providing the operator more control over how and what data is collected. There's a phrase the Navy Seals use: "slow is smooth and smooth is fast" and that's the approach I tried to take with this tool. You limit the case for detection by only querying for what LDAP wants to tell you and limit detections by not performing an action known as ["expensive ldap queries"](http://directoryadmin.blogspot.com/2019/10/hunting-bad-ldap-queries-on-your-dc.html). You have the option to ommit SMB connections for hostname resolution. You have the option to prefer LDAPS over LDAP. With the additional integration with BloodHound, the collected data can be stored in a familiar format that can be shared with a team.


