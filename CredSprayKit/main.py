#!/usr/bin/python3
import argparse
import nmap
import os
import socket
import ipaddress


from Scanner import *
from CredSprayer import *


#-------------------------------------------------------------------------------------
# MAIN UTILS

def is_file(filepath):
    return os.path.isfile(filepath)

def parse_to_ip_list(input_arg):
    """
    Parse the input argument and return a list of individual IP addresses.

    :param input_arg: A string containing IPs, ranges, CIDRs, hostnames, FQDNs, or file paths.
    :return: A list of individual IP addresses.
    """
    ip_list = []

    # Check if the input is a file
    if os.path.isfile(input_arg):
        with open(input_arg, 'r') as file:
            lines = file.readlines()
            for line in lines:
                line = line.strip()
                if line:
                    ip_list.extend(parse_to_ip_list(line))
        return ip_list

    try:
        # Try to handle as an IP address, CIDR, or range
        if '-' in input_arg:
            # Handle IP range, e.g., "192.168.1.1-192.168.1.5"
            start_ip, end_ip = input_arg.split('-')
            start_ip = ipaddress.IPv4Address(start_ip.strip())
            end_ip = ipaddress.IPv4Address(end_ip.strip())
            for ip_int in range(int(start_ip), int(end_ip) + 1):
                ip_list.append(str(ipaddress.IPv4Address(ip_int)))
        elif '/' in input_arg:
            # Handle CIDR, e.g., "192.168.1.0/24"
            network = ipaddress.ip_network(input_arg, strict=False)
            ip_list.extend([str(ip) for ip in network.hosts()])
        else:
            # Handle single IP, e.g., "192.168.1.1"
            ip = ipaddress.ip_address(input_arg.strip())
            ip_list.append(str(ip))
    except ValueError:
        try:
            # Handle as a hostname or FQDN
            resolved_ip = socket.gethostbyname(input_arg)
            #ip_list.append(resolved_ip)
            ip_list.append(input_arg)
        except socket.gaierror:
            print(f"Warning: Unable to resolve {input_arg}")

    return ip_list

#-------------------------------------------------------------------------------------

# Auth Types:
# password
# hash
# kerberos (requires password + kdchost)

# crackmapexec ldap 192.168.227.122 -u '' -p '' --kdcHost 192.168.227.122 -k --users
# export KRB5CCNAME=/full/path/to/john.ccache; python3 psexec.py test.local/john@10.10.10.1 -k -no-pass





#-------------------------------------------------------------------------------------


default_conf = """
ftp:21
ssh:22
smb:445
kerberos:88
ldap:389
mssql:1433
mssql:4022
rdp:3389
winrm:5985
rpc:135
dcom:135
wmi:135
"""

def main():
    parser = argparse.ArgumentParser(
        description="A comprehensive password sprayer"
    )
    parser.add_argument("-T", "--target", type=str, required=True, help="IP, range, CIDR, hostname, FQDN, file containing a list of targets")
    parser.add_argument("-U", "--user", type=str, required=True, help="username or file containing usernames")
    parser.add_argument("-P", "--password", type=str, help="password or file containing passwords")
    parser.add_argument("-H", "--hash", type=str, help="ntlm hash or file containing ntlm hashes")
    parser.add_argument("-d", "--domain", type=str, help="domain to authenticate to", default="")
    parser.add_argument("-k", "--kdc", type=str, help="kerberos domain controller", default="")

    #parser.add_argument("-c", "--conf", type=str, help="PROTO:PORT comma seperated list or file", default="")

    #parser.add_argument("--null-domain-auth", type=str, help="", default=True)
    #parser.add_argument("--local-auth", type=str, help="", default=True)
    #parser.add_argument("--domain-auth", type=str, help="", default=True)

    #parser.add_argument("-o", "--output", type=str, help="output file")
    #parser.add_argument("-n", "--no-color", type=str, help="do not output in color", default=False)


    args = parser.parse_args()




    # USERNAMES
    usernames = []
    if is_file(args.user):
        with open(args.user, 'r') as uf:
            lines = uf.read().strip().split('\n')
        for line in lines:
            usernames.append(line.strip())
    else:
        usernames.append(args.user.strip())

    # PASSWORDS
    if args.password:
        passwords = []
        if is_file(args.password):
            with open(args.password, 'r') as uf:
                lines = uf.read().strip().split('\n')
            for line in lines:
                passwords.append(line.strip())
        else:
            passwords.append(args.password)

    # NTLM HASHES
    if args.hash:
        ntlm_hashes = []
        if is_file(args.hash):
            with open(args.hash, 'r') as uf:
                lines = uf.read().strip().split('\n')
            for line in lines:
                ntlm_hashes.append(line.strip())
        else:
            ntlm_hashes.append(args.hash.strip())

    #if args.domain:
    #    settings.domain = args.domain.strip()
    #if args.kdc:
    #    settings.kdc = args.kdc.strip()


    target_list = parse_to_ip_list(args.target)
    port_dict = parse_port_conf(default_conf)
    nmap_results = check_open_ports(target_list, list(port_dict.keys()))
    targets = nmap_to_targets(nmap_results, port_dict)

    creds = []
    for u in usernames:
        if args.password:
            for p in passwords:
                creds.append(PASSWORD(u, p))
        if args.hash:
            for h in ntlm_hashes:
                creds.append(NTLM(u, h))

    sprayer = CredSprayer(creds, targets, domain=args.domain.strip(), kdc=args.kdc.strip())
    sprayer.spray()


if __name__ == "__main__":
    main()
