from impacket.smbconnection import SMBConnection, SessionError
from impacket.smb import SMB_DIALECT
from impacket.nmb import NetBIOSError, NetBIOSTimeout
from impacket.krb5.kerberosv5 import SessionKeyDecryptionError
from impacket.krb5.types import KerberosException

import socket

# NOTE
# Testing on bloody, domain does not matter, probably required for kerberos


#methods = ["wmiexec", "atexec", "smbexec", "mmcexec"]


smb_error_status = [
    "STATUS_ACCOUNT_DISABLED",
    "STATUS_ACCOUNT_EXPIRED",
    "STATUS_ACCOUNT_RESTRICTION",
    "STATUS_INVALID_LOGON_HOURS",
    "STATUS_INVALID_WORKSTATION",
    "STATUS_LOGON_TYPE_NOT_GRANTED",
    "STATUS_PASSWORD_EXPIRED",
    "STATUS_PASSWORD_MUST_CHANGE",
    "STATUS_ACCESS_DENIED",
    "STATUS_NO_SUCH_FILE",
    "KDC_ERR_CLIENT_REVOKED",
    "KDC_ERR_PREAUTH_FAILED",
]

#SMBConnection
#def __init__(self, remoteName='', remoteHost='', myName=None, sess_port=nmb.SMB_SESSION_PORT, timeout=60, preferredDialect=None,
#                existingConnection=None, manualNegotiate=False):


def create_smbv1_conn(host, port, smb_timeout, kdc=""):
    try:
        conn = SMBConnection(
            host if not kdc else kdc,
            host if not kdc else kdc,
            None,
            port,
            #preferredDialect="SMB1",
            timeout=smb_timeout,
        )
        return conn
    except socket.error as e:
        if "Connection reset by peer" in str(e):
            print(f"SMBv1 might be disabled on {host if not kdc else kdc}")
        return None
    except (Exception, NetBIOSTimeout) as e:
        print(f"Error creating SMBv1 connection to {host if not kdc else kdc}: {e}")
        return None

def create_smbv3_conn(host, port, smb_timeout, kdc=""):
    try:
        conn = SMBConnection(
            host if not kdc else kdc,
            host if not kdc else kdc,
            None,
            port,
            #preferredDialect="SMB3",
            timeout=smb_timeout,
        )
        return conn
    except socket.error as e:
        if "Too many open files" in str(e):
            print(f"SMBv3 connection error on {host if not kdc else kdc}: {e}")
        return None
    except (Exception, NetBIOSTimeout) as e:
        print(f"Error creating SMBv3 connection to {host if not kdc else kdc}: {e}")
        return None

def create_smb_connection(host, port, kdc=""):
    smb_timeout = None
    conn = create_smbv1_conn(host, port, smb_timeout, kdc)
    if conn:
        return conn

    conn = create_smbv3_conn(host, port, smb_timeout, kdc)
    if conn:
        return conn

    return None

def get_host_n_domain_names(host, port):
    conn = create_smb_connection(host, port)
    try:
        conn.login("", "")
    except Exception as e:
        pass
    domain = conn.getServerDNSDomainName()
    hostname = conn.getServerName()
    conn.close()
    return (domain, hostname)

#-----------------------------------------------------------------------------------------------------------------------------


def check_smb_password(host, port, username, password, domain, kdc=""):
    # Re-connect since we logged off
    conn = create_smb_connection(host, port, kdc)
    try:
        conn.login(username, password, domain)
        conn.logoff()
        return True
    except SessionError as e:
        error, desc = e.getErrorString()
        if error not in smb_error_status:
            return False
    except (ConnectionResetError, NetBIOSTimeout, NetBIOSError) as e:
        return False
    except BrokenPipeError as e:
        return False


def check_smb_ntlm(host, port, username, ntlm_hash, domain, kdc=""):
    # Re-connect since we logged off
    conn = create_smb_connection(host, port, kdc)
    lmhash = ""
    nthash = ""
    if ntlm_hash.find(":") != -1:
        lmhash, nthash = ntlm_hash.split(":")
    else:
        nthash = ntlm_hash
        lmhash = "00000000000000000000000000000000"

    try:
        conn.login(username, "", domain, lmhash, nthash)

        # check https://github.com/byt3bl33d3r/CrackMapExec/issues/321
        #if self.args.continue_on_success and self.signing:
        #    try:
        #        self.conn.logoff()
        #    except:
        #        pass
        #    self.create_conn_obj()
        conn.logoff()
        return True
    except SessionError as e:
        error, desc = e.getErrorString()
        if error not in smb_error_status:
            return False
    except (ConnectionResetError, NetBIOSTimeout, NetBIOSError) as e:
        return False
    except BrokenPipeError as e:
        return False
