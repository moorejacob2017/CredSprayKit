from io import StringIO
import socket
import paramiko
from paramiko.ssh_exception import (
    AuthenticationException,
    NoValidConnectionsError,
    SSHException,
)

paramiko.util.log_to_file('/dev/null')

def create_ssh_connection(host, port):
    conn = paramiko.SSHClient()
    conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        conn.connect(host, port=port)
    except AuthenticationException:
        return conn
    except SSHException:
        return conn
    except NoValidConnectionsError:
        return None
    except socket.error:
        return None


# private_key is a read-in key file
def check_ssh_local_password(host, port, username, password, private_key=None):
    conn = create_ssh_connection(host, port)
    try:
        if private_key:
            pkey = paramiko.RSAKey.from_private_key(StringIO(private_key))

            conn.connect(
                host,
                port=port,
                username=username,
                passphrase=password if password != "" else None,
                pkey=pkey,
                look_for_keys=False,
                allow_agent=False,
            )
        else:
            conn.connect(
                host,
                port=port,
                username=username,
                password=password,
                look_for_keys=False,
                allow_agent=False,
            )
        conn.close()
        return True
    except (AuthenticationException, NoValidConnectionsError, ConnectionResetError) as e:
        #conn.close()
        return False
    except Exception as e:
        #conn.close()
        return False

