import socket
from ftplib import FTP, error_reply, error_temp, error_perm, error_proto

# Basic Check of FTP
# Need to switch it to take a Credentials object to keep it generalized
#print(check_ftp("192.168.1.178", 21, "anonymous", "-"))

def check_ftp_local_password(host, port, username, password):

    if isinstance(port, str):
        port = int(port)

    conn = FTP()
    try:
        conn.connect(host=host, port=port)
    except error_reply:
        return False
    except error_temp:
        return False
    except error_perm:
        return False
    except error_proto:
        return False
    except socket.error:
        return False

    try:
        resp = conn.login(user=username, passwd=password)
    except Exception as e:
        conn.close()
        return False

    conn.close()

    # 230 is "User logged in, proceed" response, ftplib raises an exception on failed login
    # "anonymous" or ""
    # "-" or ""
    if "230" in resp:
        conn.close()
        return True   
    return False


