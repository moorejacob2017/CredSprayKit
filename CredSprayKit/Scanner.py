import nmap
from TargetClass import *
from protocols.smb import *

protos = [
    "ftp",
    "ssh",
    "smb",
    "kerberos",
    "ldap",
    "mssql",
    "rdp",
    "winrm",
    "rpc",
    "dcom",
    "wmi",
]

def parse_port_conf(port_conf, is_file=False):
    if is_file:
        with open(port_conf, 'r') as port_conf_file:
            lines = port_conf_file.read().split('\n')
    else:
        lines = port_conf.split('\n')

    port_dict = {}
    for line in lines:
        sline = line.strip()

        if not sline == '' and not sline == '#' and ':' in sline:
            proto, port = sline.split(':')
            proto = proto.strip()

            port = int(port.strip())

            if proto in protos:
                if not port in port_dict.keys():
                    port_dict[port] = []

                if not proto in port_dict[port]:
                    port_dict[port].append(proto)

    return port_dict

# hosts: list
# ports: list
def check_open_ports(hosts, ports):
    nm = nmap.PortScanner()
    open_ports = {}
    for host in hosts:
        open_ports[host] = []
        nm.scan(host, arguments=f'-Pn -p {",".join(map(str, ports))} --open')
        if host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                # Add each open port to the list for the current host
                open_ports[host].extend(nm[host][proto].keys())
    return open_ports

def nmap_to_targets(nmap_results, port_dict):
    targets = []
    name_dict = {}

    # Get matching domain and hostnames via SMB
    for host in nmap_results.keys():
        if 445 in nmap_results[host]:
            name_dict[host] = get_host_n_domain_names(host, 445)

    for host in nmap_results.keys():
        for port in nmap_results[host]:
            for proto in port_dict[port]:
                if host in name_dict.keys():
                    dn, hn = name_dict[host]
                    targets.append(Target(host, port, proto, hn, dn))
                else:
                    targets.append(Target(host, port, proto))

    return targets

