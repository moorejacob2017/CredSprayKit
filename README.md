# CredSprayKit v0.0.1 Alpha
A comprehensive credential spraying solution

```
usage: main.py [-h] -T TARGET -U USER [-P PASSWORD] [-H HASH] [-d DOMAIN] [-k KDC]

A comprehensive password sprayer

options:
  -h, --help            show this help message and exit
  -T TARGET, --target TARGET
                        IP, range, CIDR, hostname, FQDN, file containing a list of targets
  -U USER, --user USER  username or file containing usernames
  -P PASSWORD, --password PASSWORD
                        password or file containing passwords
  -H HASH, --hash HASH  ntlm hash or file containing ntlm hashes
  -d DOMAIN, --domain DOMAIN
                        domain to authenticate to
  -k KDC, --kdc KDC     kerberos domain controller
```

### Current Default Proto/Port Conf
```
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
```

### Current Password Auths
| Protocol | Null Domain | Local/Hostname | Domain | Kerberos |
|:---------|:-----------:|:--------------:|:------:|:--------:|
| Kerberos |             |                |      X |          |
| FTP      |           X |                |        |          |
| SSH      |           X |                |        |          |
| LDAP     |           X |                |      X |          |
| SMB      |           X |              X |      X |        X |
| RDP      |           X |              X |      X |          |
| MSSQL    |           X |              X |      X |        X |
| WinRM    |           X |              X |      X |          |
| RPC      |             |                |        |          |
| DCOM     |             |                |        |          |
| WMI      |           X |              X |      X |          |

### Current NTLM Auths
| Protocol | Null Domain | Local/Hostname | Domain | Kerberos |
|:---------|:-----------:|:--------------:|:------:|:--------:|
| Kerberos |             |                |      X |          |
| FTP      |             |                |        |          |
| SSH      |             |                |        |          |
| LDAP     |           X |                |      X |          |
| SMB      |           X |              X |      X |        X |
| RDP      |           X |              X |      X |          |
| MSSQL    |           X |              X |      X |        X |
| WinRM    |           X |              X |      X |          |
| RPC      |             |                |        |          |
| DCOM     |             |                |        |          |
| WMI      |           X |              X |      X |          |