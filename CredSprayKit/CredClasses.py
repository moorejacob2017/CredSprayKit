import hashlib

class Credential:
    def __init__(self, username, secret):
        self.username = username
        self.secret = secret

    def get_cred_id(self):
        encoded_string = f"{self.username}{self.secret}".encode()
        sha256_hash = hashlib.sha256()
        sha256_hash.update(encoded_string)
        return sha256_hash.hexdigest()

class PASSWORD(Credential):
    def __init__(self, username, secret):
        super().__init__(username, secret)

class NTLM(Credential):
    def __init__(self, username, secret):
        _hash = secret.strip().lower()
        valid_chars = "0123456789abcdef:"

        for x in _hash:
            if not x in valid_chars[:-1]:
                raise Exception(f"Invalid NTLM hash: {_hash}")

        if len(_hash) == 32:
            self.lmhash = "aad3b435b51404eeaad3b435b51404ee"
            self.nthash = _hash
        elif len(_hash) == 65 and ':' in _hash:
            self.lmhash, self.nthash = _hash.split(':')
        else:
            raise Exception(f"Invalid NTLM hash: {_hash}")
        
        super().__init__(username, f"{self.lmhash}:{self.nthash}")


