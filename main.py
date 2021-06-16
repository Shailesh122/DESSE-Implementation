from cryptography.fernet import Fernet
from aesdet import AESDet as PRF
from rake_nltk import Rake
from base64 import b64encode,b64decode
import os

def keygen(secpar):
    while True:
        key = os.urandom(secpar)
        if ',' not in str(key):
            return key
    return os.urandom(secpar)

def permute(key, msg):
    F1 = PRF()
    F1.add_to_private_key("key", key)
    val = F1.encrypt(msg)
    return val

def permuteInv( key, cipher):
    F2 = PRF()
    F2.add_to_private_key("key", key)
    dec = F2.decrypt(cipher)
    return dec

def ferKeygen():
    key = Fernet.generate_key()
    return key

def encryptFile(plainfilename,encfilename, key):
    fernet = Fernet(key)
    with open(plainfilename, 'rb') as file:
        original = file.read()
    encrypted = fernet.encrypt(original)
    with open(encfilename, 'wb') as encrypted_file:
        encrypted_file.write(encrypted)

def decryptFile(encfilename, plainfilename, key):
    fernet = Fernet(key)
    with open(encfilename, 'rb') as enc_file:
        encrypted = enc_file.read()
    decrypted = fernet.decrypt(encrypted)
    with open(plainfilename, 'wb') as dec_file:
        dec_file.write(decrypted)



k1 = keygen(32)
print(k1)
val = permute(k1,"I am shailesh")
print(val)
k3 = b64encode(k1).decode('utf-8')
print(type(k3))
print(k3)
print(b64decode(k3))
dec = permuteInv(b64decode(k3),val)
print(dec.decode())