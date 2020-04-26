import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
backend = default_backend()
key = os.urandom(32)
iv = os.urandom(16)
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)

c=b""

def enc(message):
    encryptor = cipher.encryptor()
    ct = encryptor.update(message.encode()) + encryptor.finalize()
    global c
    c=ct
    print("\nEncrypted Message: ",ct)

def dec():
    global c
    decryptor = cipher.decryptor()
    dc=decryptor.update(c) + decryptor.finalize()
    data = dc.decode()
    print("\nDecrypted Message: ",data)

m=input("\nEnter the message you want to encrypt and relay: ")
if len(m)%16 is not 0:
    x=16-len(m)%16
    m=m + " "*x


print("Random Session Key generated: ",key)
print("\niv generated: ",iv)

enc(m)
dec()

        

