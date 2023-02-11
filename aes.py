import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from os import urandom
import hashlib

def AESencrypt(plaintext, key):
    k = hashlib.sha256(KEY).digest()
    iv = 16 * b'\x00'
    plaintext = pad(plaintext, AES.block_size)
    cipher = AES.new(k, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext,key
  
def dropFile(key, ciphertext):
  with open("cipher.bin", "wb") as fc:
    fc.write(ciphertext)
  with open("key.bin", "wb") as fk:
    fk.write(key)
  #print('char AESkey[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in KEY) + ' };')
  #print('unsigned char AESshellcode[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in ciphertext) + ' };')
 

try:
    file = open(sys.argv[1], "rb")
    content = file.read()
except:
    print("Usage: .\AES_cryptor.py PAYLOAD_FILE")
    sys.exit()


KEY = urandom(16)
ciphertext, key = AESencrypt(content, KEY)

dropFile(KEY,ciphertext)

