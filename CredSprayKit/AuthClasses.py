from CredClasses import *
from CredChecks import *
from Ansi import *

class Auth:
    def __init__(self, target, cred):
        if not isinstance(cred, PASSWORD) and not isinstance(cred, NTLM):
            raise Exception(f"Invalid Credential type for Auth object: Must be of type PASSWORD or NTLM")
        
        self.target = target
        self.cred = cred
        self.success = None

    def print(self, color=True):
        printable = ""

        if self.success:
            printable += "[+] " if not color else ANSI.BRIGHT_GREEN(f"[+] ")
        else:
            printable += "[-] " if not color else ANSI.BRIGHT_RED("[-] ")

        auth_type = f"{self.cred.__class__.__name__} + {self.__class__.__name__}"
        printable += f"{auth_type: <27} | "
        

        proto = ""
        if isinstance(self, KERBEROS_AUTH):
            proto += "kerberos+"
        proto += f"{self.target.proto}"
        printable += f"{proto: <15}"


        host_loc = f"{self.target.host}:{self.target.port}"
        printable += f"{host_loc: <23} "
        

        username = ""
        if isinstance(self, LOCAL_AUTH) and self.target.hostname:
            username += f"{self.target.hostname}\\"
        elif isinstance(self, DOMAIN_AUTH) and self.target.domain:
            username += f"{self.target.domain}\\"
        username += f"{self.cred.username} "
        printable += f"{username: <35} "


        if self.success:
            printable += f"( {self.cred.secret} ) " if not color else ANSI.BRIGHT_GREEN(f"( {self.cred.secret} ) ")
        else:
            printable += f"( {self.cred.secret} ) " if not color else ANSI.BRIGHT_RED(f"( {self.cred.secret} ) ")

        print(printable)


class NULL_DOMAIN_AUTH(Auth):
    def __init__(self, target, cred):
        super().__init__(target, cred)

    def check(self):
        if isinstance(self.cred, PASSWORD):
            self.success = check_cred_null_domain_password(self.target, self.cred)
        else:
            self.success = check_cred_null_domain_ntlm(self.target, self.cred)
        return self.success

class LOCAL_AUTH(Auth):
    def __init__(self, target, cred):
        super().__init__(target, cred)

    def check(self):
        if isinstance(self.cred, PASSWORD):
            self.success = check_cred_local_password(self.target, self.cred)
        else:
            self.success = check_cred_local_ntlm(self.target, self.cred)
        return self.success
    
class DOMAIN_AUTH(Auth):
    def __init__(self, target, cred):
        super().__init__(target, cred)

    def check(self):
        if isinstance(self.cred, PASSWORD):
            self.success = check_cred_domain_password(self.target, self.cred)
        else:
            self.success = check_cred_domain_ntlm(self.target, self.cred)
        return self.success

class KERBEROS_AUTH(Auth):
    def __init__(self, target, cred):
        super().__init__(target, cred)

    def check(self):
        if isinstance(self.cred, PASSWORD):
            self.success = check_cred_kerberos_password(self.target, self.cred)
        else:
            self.success = check_cred_kerberos_ntlm(self.target, self.cred)
        return self.success
