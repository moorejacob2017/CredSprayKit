from protocols.kerberos import *
from protocols.ftp import *
from protocols.ssh import *
from protocols.ldap import *
from protocols.smb import *
from protocols.rdp import *
from protocols.mssql import *
from protocols.winrm import *
from protocols.wmi import *



def check_cred_null_domain_password(target, cred):
    success = None
    if target.proto == "ftp":
        success = check_ftp_local_password(target.host, target.port, cred.username, cred.secret)
    elif target.proto == "ssh":
        success = check_ssh_local_password(target.host, target.port, cred.username, cred.secret)
    elif target.proto == "ldap":
        success = check_ldap_domain_password(target.host, cred.username, cred.secret, '', use_ldaps=False)
    elif target.proto == "smb":
        success = check_smb_password(target.host, target.port, cred.username, cred.secret, '')
    elif target.proto == "rdp":
        success = check_rdp_password(target.host, target.port, cred.username, cred.secret, domain='')
    elif target.proto == "mssql":
        success = check_mssql_password(target.host, target.port, cred.username, cred.secret, domain='', local_auth=True)
    elif target.proto == "winrm":
        success = check_winrm_password(target.host, target.port, cred.username, cred.secret, '', ignore_ssl_cert=True)
    #elif target.proto == "rpc":
    #    success = check_rpc_domain_password(host, port, cred.username, cred.secret, domain)
    #elif target.proto == "dcom":
    #    success = check_dcom_domain_password(host, port, cred.username, cred.secret, domain)
    elif target.proto == "wmi":
        success = check_wmi_password(target.host, target.port, cred.username, cred.secret, '')
    else:
        return None

    return success



def check_cred_null_domain_ntlm(target, cred):
    success = None
    if target.proto == "ldap":
        success = check_ldap_domain_ntlm(target.host, cred.username, cred.secret, '', use_ldaps=False)
    elif target.proto == "smb":
        success = check_smb_ntlm(target.host, target.port, cred.username, cred.secret, '')
    elif target.proto == "rdp":
        success = check_rdp_ntlm(target.host, target.port, cred.username, cred.secret, domain='')
    elif target.proto == "mssql":
        success = check_mssql_ntlm(target.host, target.port, cred.username, cred.secret, domain='', local_auth=True)
    elif target.proto == "winrm":
        success = check_winrm_ntlm(target.host, target.port, cred.username, cred.secret, '', ignore_ssl_cert=True)
    #elif target.proto == "rpc":
    #    success = check_rpc_domain_ntlm(host, port, cred.username, cred.secret, domain)
    #elif target.proto == "dcom":
    #    success = check_dcom_domain_ntlm(host, port, cred.username, cred.secret, domain)
    elif target.proto == "wmi":
        success = check_wmi_ntlm(target.host, target.port, cred.username, cred.secret, '')
    else:
        return None

    return success



def check_cred_local_password(target, cred):
    success = None
    if target.proto == "smb":
        success = check_smb_password(target.host, target.port, cred.username, cred.secret, target.hostname)
    elif target.proto == "rdp":
        success = check_rdp_password(target.host, target.port, cred.username, cred.secret)
    elif target.proto == "mssql":
        success = check_mssql_password(target.host, target.port, cred.username, cred.secret, domain=target.hostname, local_auth=False)
    elif target.proto == "winrm":
        success = check_winrm_password(target.host, target.port, cred.username, cred.secret, target.hostname, ignore_ssl_cert=True)
    #elif target.proto == "rpc":
    #    success = check_rpc_local_password(host, port, cred.username, cred.secret)
    #elif target.proto == "dcom":
    #    success = check_dcom_local_password(host, port, cred.username, cred.secret)
    elif target.proto == "wmi":
        success = check_wmi_ntlm(target.host, target.port, cred.username, cred.secret, target.hostname)
    else:
        return None

    return success



def check_cred_local_ntlm(target, cred):
    success = None
    if target.proto == "smb":
        success = check_smb_ntlm(target.host, target.port, cred.username, cred.secret, target.hostname)
    elif target.proto == "rdp":
        success = check_rdp_ntlm(target.host, target.port, cred.username, cred.secret)
    elif target.proto == "mssql":
        success = check_mssql_ntlm(target.host, target.port, cred.username, cred.secret, domain=target.hostname, local_auth=False)
    elif target.proto == "winrm":
        #success = check_winrm_ntlm(target.host, target.port, cred.username, cred.secret, '', ignore_ssl_cert=True)
        success = check_winrm_ntlm(target.host, target.port, cred.username, cred.secret, target.hostname, ignore_ssl_cert=True)
    #elif target.proto == "rpc":
    #    success = check_rpc_local_ntlm(host, port, cred.username, cred.secret)
    #elif target.proto == "dcom":
    #    success = check_dcom_local_ntlm(host, port, cred.username, cred.secret)
    elif target.proto == "wmi":
        success = check_wmi_ntlm(target.host, target.port, cred.username, cred.secret, '')
        #success = check_wmi_ntlm(target.host, target.port, cred.username, cred.secret, target.hostname)
    else:
        return None

    return success



def check_cred_domain_password(target, cred):
    success = None
    if target.proto == "kerberos":
        success = kerberos_auth_password(target.host, cred.username, cred.secret, target.domain)
    elif target.proto == "ldap":
        success = check_ldap_domain_password(target.host, cred.username, cred.secret, target.domain, use_ldaps=False)
    elif target.proto == "smb":
        success = check_smb_password(target.host, target.port, cred.username, cred.secret, target.domain)
    elif target.proto == "rdp":
        success = check_rdp_password(target.host, target.port, cred.username, cred.secret, domain=target.domain)
    elif target.proto == "mssql":
        success = check_mssql_password(target.host, target.port, cred.username, cred.secret, domain=target.domain, local_auth=False)
    elif target.proto == "winrm":
        success = check_winrm_password(target.host, target.port, cred.username, cred.secret, target.domain, ignore_ssl_cert=True)
    #elif target.proto == "rpc":
    #    success = check_rpc_domain_password(host, port, cred.username, cred.secret, domain)
    #elif target.proto == "dcom":
    #    success = check_dcom_domain_password(host, port, cred.username, cred.secret, domain)
    elif target.proto == "wmi":
        success = check_wmi_password(target.host, target.port, cred.username, cred.secret, target.domain)
    else:
        return None

    return success



def check_cred_domain_ntlm(target, cred):
    success = None
    if target.proto == "kerberos":
        success = kerberos_auth_ntlm(target.host, cred.username, cred.secret, target.domain)
    elif target.proto == "ldap":
        success = check_ldap_domain_ntlm(target.host, cred.username, cred.secret, target.domain, use_ldaps=False)
    elif target.proto == "smb":
        success = check_smb_ntlm(target.host, target.port, cred.username, cred.secret, target.domain)
    elif target.proto == "rdp":
        success = check_rdp_ntlm(target.host, target.port, cred.username, cred.secret, domain=target.domain)
    elif target.proto == "mssql":
        success = check_mssql_ntlm(target.host, target.port, cred.username, cred.secret, domain=target.domain, local_auth=False)
    elif target.proto == "winrm":
        success = check_winrm_ntlm(target.host, target.port, cred.username, cred.secret, target.domain, ignore_ssl_cert=True)
    #elif target.proto == "rpc":
    #    success = check_rpc_domain_ntlm(host, port, cred.username, cred.secret, domain)
    #elif target.proto == "dcom":
    #    success = check_dcom_domain_ntlm(host, port, cred.username, cred.secret, domain)
    elif target.proto == "wmi":
        success = check_wmi_ntlm(target.host, target.port, cred.username, cred.secret, target.domain)
    else:
        return None

    return success



def check_cred_kerberos_password(target, cred):
    success = None
    #if target.proto == "ldap":
    #    success = check_ldap_kerberos_password(target.host, cred.username, cred.secret, target.domain, use_ldaps=False)
    if target.proto == "smb":
        success = check_smb_password(target.host, target.port, cred.username, cred.secret, target.domain, kdc=target.kdc)
    #elif target.proto == "rdp":
    #    success = check_rdp_kerberos_password(host, port, cred.username, cred.secret, domain, kdc_host)
    elif target.proto == "mssql":
        success = check_mssql_kerberos_password(target.host, target.port, cred.username, cred.secret, target.domain, target.kdc)
    #elif target.proto == "winrm":
    #    success = check_winrm_kerberos_password(host, port, cred.username, cred.secret, domain, kdc_host)
    #elif target.proto == "rpc":
    #    success = check_rpc_kerberos_password(host, port, cred.username, cred.secret, domain, kdc_host)
    #elif target.proto == "dcom":
    #    success = check_dcom_kerberos_password(host, port, cred.username, cred.secret, domain, kdc_host)
    #elif target.proto == "wmi":
    #    success = check_wmi_kerberos_password(host, port, cred.username, cred.secret, domain, kdc_host)
    else:
        return None

    return success



def check_cred_kerberos_ntlm(target, cred):
    success = None
    #if target.proto == "ldap":
    #    success = check_ldap_kerberos_ntlm(target.host, cred.username, cred.secret, target.domain, use_ldaps=False)
    if target.proto == "smb":
        success = check_smb_ntlm(target.host, target.port, cred.username, cred.secret, target.domain, kdc=target.kdc)
    #elif target.proto == "rdp":
    #    success = check_rdp_kerberos_ntlm(host, port, cred.username, cred.secret, domain, kdc_host)
    elif target.proto == "mssql":
        success = check_mssql_kerberos_ntlm(target.host, target.port, cred.username, cred.secret, target.domain, target.kdc)
    #elif target.proto == "winrm":
    #    success = check_winrm_kerberos_ntlm(host, port, cred.username, cred.secret, domain, kdc_host)
    #elif target.proto == "rpc":
    #    success = check_rpc_kerberos_ntlm(host, port, cred.username, cred.secret, domain, kdc_host)
    #elif target.proto == "dcom":
    #    success = check_dcom_kerberos_ntlm(host, port, cred.username, cred.secret, domain, kdc_host)
    #elif target.proto == "wmi":
    #    success = check_wmi_kerberos_ntlm(host, port, cred.username, cred.secret, domain, kdc_host)
    else:
        return None

    return success


