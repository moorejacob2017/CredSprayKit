import hashlib

class Target:
    def __init__(self, host, port, proto, hostname=None, domain=None, kdc=None):
        self.host = host
        self.port = port
        self.proto = proto
        self.hostname = hostname
        self.domain = domain
        self.kdc = kdc

    # HPP: Host, Port, Proto
    def get_hpp_id(self):
        encoded_string = f"{self.host}{self.port}{self.proto}".encode()
        sha256_hash = hashlib.sha256()
        sha256_hash.update(encoded_string)
        return sha256_hash.hexdigest()
    
    def debug_print(self):
        printable = "------------------------------------\n"
        printable += f"host={self.host}\n"
        printable += f"port={self.port}\n"
        printable += f"proto={self.proto}\n"
        printable += f"hostname={self.hostname}\n"
        printable += f"domain={self.domain}\n"
        printable += f"kdc={self.kdc}\n"
        print(printable)