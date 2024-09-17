
import requests
from pypsrp.client import Client


def get_winrm_endpoint(host, port, http_timeout=10):
    endpoints = [
        f"https://{host}:{port}/wsman", # 5986
        f"http://{host}:{port}/wsman", # 5985
    ]

    for url in endpoints:
        try:
            res = requests.post(url, verify=False, timeout=http_timeout)
            return url
        except requests.exceptions.Timeout as e:
            pass
        except requests.exceptions.ConnectionError as e:
            pass
    return None


def check_winrm_password(host, port, username, password, domain, ignore_ssl_cert=True):
    endpoint = get_winrm_endpoint(host, port)

    try:
        if endpoint.startswith("https://"):
            ssl=True
        else:
            ssl=False

        if ssl and ignore_ssl_cert:
            conn = Client(
                host,
                auth="ntlm",
                username=f"{domain}\\{username}",
                password=password,
                ssl=True,
                cert_validation=False,
            )
        elif ssl:
            conn = Client(
                host,
                auth="ntlm",
                username=f"{domain}\\{username}",
                password=password,
                ssl=True,
            )
        else:
            conn = Client(
                host,
                auth="ntlm",
                username=f"{domain}\\{username}",
                password=password,
                ssl=False,
            )

        # Original Comment
        # TO DO: right now we're just running the hostname command to make the winrm library auth to the server
        # we could just authenticate without running a command :) (probably)
        conn.execute_ps("hostname")

        return True
    except Exception as e:
        pass
    return False

def check_winrm_ntlm(host, port, username, ntlm_hash, domain, ignore_ssl_cert=True):
    endpoint = get_winrm_endpoint(host, port)

    if ntlm_hash.find(":") != -1:
        lmhash, nthash = ntlm_hash.split(":")
    else:
        nthash = ntlm_hash
        lmhash = "00000000000000000000000000000000"

    try:
        if endpoint.startswith("https://"):
            ssl=True
        else:
            ssl=False

        if ssl and ignore_ssl_cert:
            conn = Client(
                host,
                auth="ntlm",
                username=f"{domain}\\{username}",
                password=lmhash + ":" + nthash,
                ssl=True,
                cert_validation=False,
            )
        elif ssl:
            conn = Client(
                host,
                auth="ntlm",
                username=f"{domain}\\{username}",
                password=lmhash + ":" + nthash,
                ssl=True,
            )
        else:
            conn = Client(
                host,
                auth="ntlm",
                username=f"{domain}\\{username}",
                password=lmhash + ":" + nthash,
                ssl=False,
            )

        # Original Comment
        # TO DO: right now we're just running the hostname command to make the winrm library auth to the server
        # we could just authenticate without running a command :) (probably)
        conn.execute_ps("hostname")
        return True

    except Exception as e:
        pass
    return False



