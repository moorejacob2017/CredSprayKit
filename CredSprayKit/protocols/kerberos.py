from impacket.krb5.types import Principal
from impacket.krb5 import constants
from impacket.krb5.kerberosv5 import getKerberosTGT
from impacket.krb5.kerberosv5 import getKerberosTGS
from impacket.krb5.ccache import CCache
from impacket.krb5.types import KerberosTime
from impacket.krb5.kerberosv5 import KerberosError

from binascii import unhexlify
#from impacket.ntlm import compute_lmhash, compute_nthash
#from impacket.krb5.crypto import _enctype_table
#import logging

#def getKerberosTGT(clientName, password, domain, lmhash, nthash, aesKey='', kdcHost=None, requestPAC=True, serverName=None, kerberoast_no_preauth=False)
def kerberos_auth_password(kdc_host, username, password, domain):
    try:
        userName = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        tgt, cipher, old_session_key, session_key = getKerberosTGT(userName, password, domain, unhexlify(''), unhexlify(''), kdcHost=kdc_host)
        return True
    except KerberosError as e:
        return False

def kerberos_auth_ntlm(kdc_host, username, ntlm_hash, domain):
    try:
        lmhash, nthash = ntlm_hash.split(':')
        nthash = unhexlify(nthash)
        lmhash = unhexlify(lmhash)
        userName = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        tgt, cipher, old_session_key, session_key = getKerberosTGT(userName, '', domain, lmhash, nthash, kdcHost=kdc_host)
        return True
    except KerberosError as e:
        return False
