
from impacket import tds
import socket


# LOCAL_AUTH IS WINDOWS AUTH
def check_mssql_password(host, port, username, password, domain=None, local_auth=False):
    if isinstance(port, str):
        port = int(port)

    try:
        conn = tds.MSSQL(host, port)
        conn.connect()
    except socket.error as e:
        return None

    try:
        # this is to prevent a decoding issue in impacket/ntlm.py:617 where it attempts to decode the domain
        if not domain:
            domain = ""

        #def login(self, database, username, password='', domain='', hashes = None, useWindowsAuth = False)
        res = conn.login(None, username, password, domain, None, local_auth)
        if res is not True:
            #self.handle_mssql_reply()
            return False

        #domain = f"{domain}\\" if not self.args.local_auth else ""
        #out = f"{domain}{username}:{process_secret(password)} {self.mark_pwned()}"
        conn.disconnect()
        return True
    except BrokenPipeError as e:
        return False
    except Exception as e:
        return False
    return False


def check_mssql_ntlm(host, port, username, ntlm_hash, domain=None, local_auth=False):
    if isinstance(port, str):
        port = int(port)

    try:
        conn = tds.MSSQL(host, port)
        conn.connect()
    except socket.error as e:
        return None

    lmhash = ""
    nthash = ""
    if ntlm_hash.find(":") != -1:
        lmhash, nthash = ntlm_hash.split(":")
    else:
        nthash = ntlm_hash
        lmhash = "00000000000000000000000000000000"

    try:
        if not domain:
            domain = ""
        res = conn.login(
            None,
            username,
            "",
            domain,
            lmhash + ":" + nthash,
            local_auth,
        )
        if res is not True:
            #self.conn.printReplies()
            return False
        conn.disconnect()
        return True
    except BrokenPipeError as e:
        return False
    except Exception as e:
        return False
    return False


#mssqlclient.py bloody.local/Administrator:'P@$$w0rd!'@192.168.2.13 -k -dc-ip 192.168.2.13

def check_mssql_kerberos_password(host, port, username, password, domain, kdc_host):
    if isinstance(port, str):
        port = int(port)
    
    try:
        conn = tds.MSSQL(host, port)
        conn.connect()
    except socket.error as e:
        return None

    try:
        # this is to prevent a decoding issue in impacket/ntlm.py:617 where it attempts to decode the domain
        if not domain:
            domain = ""

        #kerberosLogin(database, username, password='', domain='', hashes=None, aesKey='', kdcHost=None, TGT=None, TGS=None, useCache=True)
        res = conn.kerberosLogin(None, username, password, domain, None, '', kdc_host, None, None, True)
        if res is not True:
            #self.handle_mssql_reply()
            return False

        #domain = f"{domain}\\" if not self.args.local_auth else ""
        #out = f"{domain}{username}:{process_secret(password)} {self.mark_pwned()}"
        conn.disconnect()
        return True
    except BrokenPipeError as e:
        return False
    except Exception as e:
        return False
    return False


def check_mssql_kerberos_ntlm(host, port, username, ntlm_hash, domain, kdc_host):
    if isinstance(port, str):
        port = int(port)

    try:
        conn = tds.MSSQL(host, port)
        conn.connect()
    except socket.error as e:
        return None

    lmhash = ""
    nthash = ""
    if ntlm_hash.find(":") != -1:
        lmhash, nthash = ntlm_hash.split(":")
    else:
        nthash = ntlm_hash
        lmhash = "00000000000000000000000000000000"

    try:
        # this is to prevent a decoding issue in impacket/ntlm.py:617 where it attempts to decode the domain
        if not domain:
            domain = ""

        #kerberosLogin(database, username, password='', domain='', hashes=None, aesKey='', kdcHost=None, TGT=None, TGS=None, useCache=True)
        res = conn.kerberosLogin(None, username, '', domain, lmhash+":"+nthash, '', kdc_host, None, None, True)
        if res is not True:
            #self.handle_mssql_reply()
            return False

        #domain = f"{domain}\\" if not self.args.local_auth else ""
        #out = f"{domain}{username}:{process_secret(password)} {self.mark_pwned()}"
        conn.disconnect()
        return True
    except BrokenPipeError as e:
        return False
    except Exception as e:
        return False
    return False