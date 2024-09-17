from OpenSSL.SSL import SysCallError
from impacket.ldap import ldap as ldap_impacket
from impacket.ldap import ldapasn1 as ldapasn1_impacket


# TO DO:
# Add Kerberos Authentication Method
# Consider how to handle non-standard ldap/ldaps ports
#   Currently do to how impacket works, it can only consider 389 and 636


# impacket uses the protos ldap and ldaps to determine the port
def get_ldap_info(host, use_ldaps=False):
    if use_ldaps:
        proto = "ldaps"
    else:
        proto = "ldap"
    ldap_url = f"{proto}://{host}"

    try:
        try:
            ldap_connection = ldap_impacket.LDAPConnection(ldap_url)
        except SysCallError as e:
            return [None, None, None]

        resp = ldap_connection.search(
            scope=ldapasn1_impacket.Scope("baseObject"),
            attributes=["defaultNamingContext", "dnsHostName"],
            sizeLimit=0,
        )
        for item in resp:
            if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                continue
            target = None
            target_domain = None
            base_dn = None
            try:
                for attribute in item["attributes"]:
                    if str(attribute["type"]) == "defaultNamingContext":
                        base_dn = str(attribute["vals"][0])
                        target_domain = sub(
                            ",DC=",
                            ".",
                            base_dn[base_dn.lower().find("dc=") :],
                            flags=I,
                        )[3:]
                    if str(attribute["type"]) == "dnsHostName":
                        target = str(attribute["vals"][0])
            except Exception as e:
                pass
    except OSError as e:
        return [None, None, None]
    return [target, target_domain, base_dn]



# The DN Base is used for authentication
# eg. BLOODY\Administrator for DC=bloody,DC=local
#     ^^^^^^                      ^^^^^^
def check_ldap_domain_password(host, username, password, domain, use_ldaps=False):
    ldap_info = get_ldap_info(host, use_ldaps=use_ldaps)
    base_dn = ldap_info[-1]

    if use_ldaps:
        proto = "ldaps"
    else:
        proto = "ldap"
    ldap_url = f"{proto}://{host}"

    try:
        ldapConnection = ldap_impacket.LDAPConnection(ldap_url, base_dn)
        ldapConnection.login(username, password, domain)
        return True
    except:
        return False

def check_ldap_domain_ntlm(host, username, ntlm_hash, domain, use_ldaps=False):
    ldap_info = get_ldap_info(host, use_ldaps=use_ldaps)
    base_dn = ldap_info[-1]

    if use_ldaps:
        proto = "ldaps"
    else:
        proto = "ldap"
    ldap_url = f"{proto}://{host}"

    if ntlm_hash.find(":") != -1:
        lmhash, nthash = ntlm_hash.split(":")
    else:
        nthash = ntlm_hash
        lmhash = "00000000000000000000000000000000"

    password = None

    try:
        ldapConnection = ldap_impacket.LDAPConnection(ldap_url, base_dn)
        ldapConnection.login(username, password, domain, lmhash, nthash)
        return True
    except:
        return False

