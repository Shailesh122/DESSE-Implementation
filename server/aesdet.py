import base64
from cipher import Cipher
#from Crypto import Cipher as CryptoCipher
from Cryptodome.Cipher import AES
from Cryptodome import Random
# from Crypto.Hash import SHA256
import hashlib

BS = 16
pad = lambda s: bytes(s + (BS - len(s) % BS) * chr(BS - len(s) % BS), 'utf-8')
unpad = lambda s : s[:-ord(s[len(s)-1:])]

class AESDet(Cipher):
    __map = {}

    # Generates a key using a hash of some passphrase
    @staticmethod
    def keygen(passphrase, secure=128):
        # if secure == 256:
        #     h = SHA256.new()
        # elif secure == 512:
        #     h = SHA256.new()
        # else:
        #     raise Exception("Unsupported security level")
        # h.update(passphrase)
        # return h.hexdigest()
        return hashlib.sha256(str(passphrase).encode('utf-8')).digest()

    def encrypt( self, raw ):
        raw = pad(str(raw))
        if raw not in self.__map.keys():
            iv = Random.new().read(AES.block_size )
            cipher = AES.new(
                            self.keys["priv"]["key"],
                            AES.MODE_CBC,
                            iv )
            self.__map[raw] = base64.b64encode( iv + cipher.encrypt( raw ) )
        return self.__map[raw]

    def decrypt( self, enc ):
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new( self.keys["priv"]["key"],
                                        AES.MODE_CBC,
                                        iv )
        return unpad(cipher.decrypt( enc[16:] ))