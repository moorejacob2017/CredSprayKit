

from impacket.uuid import uuidtup_to_bin
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5 import transport, epm
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_WINNT, RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, MSRPC_BIND, MSRPCBind, CtxItem, MSRPCHeader, SEC_TRAILER, MSRPCBindAck
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dcom.wmi import CLSID_WbemLevel1Login, IID_IWbemLevel1Login, WBEM_FLAG_FORWARD_ONLY, IWbemLevel1Login

MSRPC_UUID_PORTMAP = uuidtup_to_bin(('E1AF8308-5D1F-11C9-91A4-08002B14A0FA', '3.0'))

rpc_error_status = {
    "0000052F" : "STATUS_ACCOUNT_RESTRICTION",
    "00000533" : "STATUS_ACCOUNT_DISABLED",
    "00000775" : "STATUS_ACCOUNT_LOCKED_OUT",
    "00000701" : "STATUS_ACCOUNT_EXPIRED",
    "00000532" : "STATUS_PASSWORD_EXPIRED",
    "00000530" : "STATUS_INVALID_LOGON_HOURS",
    "00000531" : "STATUS_INVALID_WORKSTATION",
    "00000569" : "STATUS_LOGON_TYPE_NOT_GRANTED",
    "00000773" : "STATUS_PASSWORD_MUST_CHANGE",
    "00000005" : "STATUS_ACCESS_DENIED",
    "0000052E" : "STATUS_LOGON_FAILURE",
    "0000052B" : "STATUS_WRONG_PASSWORD",
    "00000721" : "RPC_S_SEC_PKG_ERROR"
}


def create_rpc_connection(host, port, rpc_timeout=10):
    try:
        rpctransport = transport.DCERPCTransportFactory(r'ncacn_ip_tcp:{0}[{1}]'.format(host, str(port)))
        rpctransport.set_credentials(username="", password="", domain="", lmhash="", nthash="", aesKey="")
        rpctransport.setRemoteHost(host)
        rpctransport.set_connect_timeout(rpc_timeout)
        dce = rpctransport.get_dce_rpc()
        dce.set_auth_type(RPC_C_AUTHN_WINNT)
        dce.connect()
        dce.bind(MSRPC_UUID_PORTMAP)
        dce.disconnect()
    except Exception as e:
        return None
    else:
        return rpctransport


def check_wmi_password(host, port, username, password, domain):
    conn = create_rpc_connection(host, port)
    try:
        conn.set_credentials(username=username, password=password, domain=domain, lmhash="", nthash="")
        dce = conn.get_dce_rpc()
        dce.set_auth_type(RPC_C_AUTHN_WINNT)
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        dce.connect()
        dce.bind(MSRPC_UUID_PORTMAP)
    except Exception as e:
        dce.disconnect()
    else:
        try:
            # Get data from rpc connection if got vaild creds
            entry_handle = epm.ept_lookup_handle_t()
            request = epm.ept_lookup()
            request['inquiry_type'] = 0x0
            request['object'] = NULL
            request['Ifid'] = NULL
            request['vers_option'] = 0x1
            request['entry_handle'] = entry_handle
            request['max_ents'] = 1
            resp = dce.request(request)
        except  Exception as e:
            dce.disconnect()
            error_msg = str(e).lower()
            for code in rpc_error_status.keys():
                if code in error_msg:
                    error_msg = rpc_error_status[code]
            return False
        else:
            dce.disconnect()
            #if self.username == "" and self.password == "":
            #    out += "(Default allow anonymous login)"
            return True

def check_wmi_ntlm(host, port, username, ntlm_hash, domain):
    conn = create_rpc_connection(host, port)

    if ntlm_hash.find(":") != -1:
        lmhash, nthash = ntlm_hash.split(":")
    else:
        nthash = ntlm_hash
        lmhash = "00000000000000000000000000000000"

    try:
        conn.set_credentials(username=username, password="", domain=domain, lmhash=lmhash, nthash=nthash)
        dce = conn.get_dce_rpc()
        dce.set_auth_type(RPC_C_AUTHN_WINNT)
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        dce.connect()
        dce.bind(MSRPC_UUID_PORTMAP)
    except Exception as e:
        dce.disconnect()
    else:
        try:
            # Get data from rpc connection if got vaild creds
            entry_handle = epm.ept_lookup_handle_t()
            request = epm.ept_lookup()
            request['inquiry_type'] = 0x0
            request['object'] = NULL
            request['Ifid'] = NULL
            request['vers_option'] = 0x1
            request['entry_handle'] = entry_handle
            request['max_ents'] = 1
            resp = dce.request(request)
        except  Exception as e:
            dce.disconnect()
            error_msg = str(e).lower()
            for code in rpc_error_status.keys():
                if code in error_msg:
                    error_msg = rpc_error_status[code]
            return False
        else:
            dce.disconnect()
            #if self.username == "" and self.password == "":
            #    out += "(Default allow anonymous login)"
            return True

