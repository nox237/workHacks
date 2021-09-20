#!/usr/bin/python3

import re
import os
import sys
import getopt
from datetime import datetime
from termcolor import colored

CURRENT_DATE = datetime.now().strftime("%Y%m%d")
CURRENT_PATH = os.getcwd()
SOURCE_CODE_STATUS = False
APP_NAME = ""
TYPE_NAME = ""
URL_STATUS = False
IP_STATUS = False
OS_INFO = ""

if sys.platform == "linux" or sys.platform == "linux2":
    # linux
    OS_INFO = "Linux"
elif sys.platform == "darwin":
    # MAC OS X
    OS_INFO = "Mac"
elif sys.platform == "win32" or sys.platform == "win64":
    # Windows 32-bit or Windows 64-bit
    import colorama
    colorama.init()
    OS_INFO = "Windows"
    
def help(not_supplied=False):
    if not_supplied == False:
        print("Help Sections:")
    print("-h / --help         : get help")
    print("-n / --name         : name of the application")
    print("-s / --source-code  : template for source code")
    print("-i / --ip           : template for ip")
    print("-u / --url          : template for url")

def mkdate_directory(CURRENT_DATE):
    if os.path.exists(CURRENT_PATH + f'/{CURRENT_DATE}'):
        print('[!] Directory exists: '+ CURRENT_DATE)
    else:
        print('[!] Directory not exists: '+ CURRENT_DATE)
        print(f'[+] Creating directory {CURRENT_DATE} on {CURRENT_PATH}')
        os.mkdir(CURRENT_DATE)
    os.chdir(CURRENT_DATE)

def mktype_directory(TYPE_NAME, CURRENT_DATE):
    if os.path.exists(CURRENT_PATH + f'/{APP_NAME}/{TYPE_NAME}'):
        print('[!] Directory exists: '+ TYPE_NAME)
    else:
        print('[!] Directory not exists: '+ TYPE_NAME)
        print(f'[+] Creating directory {TYPE_NAME} on {CURRENT_PATH}')
        os.mkdir(TYPE_NAME)
    os.chdir(TYPE_NAME)
    mkdate_directory(CURRENT_DATE)

def mkapp_directory(APP_NAME, TYPE_NAME, CURRENT_DATE):
    if os.path.exists(CURRENT_PATH + f'/{APP_NAME}'):
        print('[!] Directory exists: '+ APP_NAME)
    else:
        print('[!] Directory not exists: '+ APP_NAME)
        print(f'[+] Creating directory {APP_NAME} on {CURRENT_PATH}')
        os.mkdir(APP_NAME)
    os.chdir(APP_NAME)
    mktype_directory(TYPE_NAME, CURRENT_DATE)

def generate_markdown(app="", type=TYPE_NAME):
    if os.path.exists(os.getcwd() + "/notes.md"):
        print('[!] Cancel overwriting notes.md file')
    else:
        with open("notes.md", "w") as f:
            if app == "":
                if OS_INFO == "Linux":
                    app = re.findall(r".*\/([\w\d\_\ ]+)\/(url|sourceCode|ip)\/\d{8}", str(os.getcwd()))[0][0]
            f.write(f"# {app}\n\n")
            f.write(f"Type : {TYPE_NAME}\n\n")
            f.write("## Checklist\n\n")
            
            f.write("### Global Check\n\n")
            for list in ("create ticket on asana", "copy ticket notes to asana","nmap target", "insert nmap result to asana", "perform scanning (fortify/nexpose/appspider)", "create and send email"):
                f.write(f"[ ] {list}\n")

            f.write("\n### Email Check\n\n")
            for list in ("opening sentence", "requestor name", "ticket and request number", "vulnerability table", "findings", "closing sentence"):
                f.write(f"[ ] {list}\n")

if __name__ == "__main__":
    opts, args = getopt.getopt(sys.argv[1:], "husin:", ["help","source-code","ip","url","name="])

    for opt, val in opts:
        if opt in ("-h", "--help"):
            help()
            exit(0)
        elif opt in ("-s", "--source-code"):
            SOURCE_CODE_STATUS = True
            TYPE_NAME = "sourceCode"
        elif opt in ("-u", "--url"):
            URL_STATUS = True
            TYPE_NAME = "url"
        elif opt in ("-i", "--ip"):
            IP_STATUS = True
            TYPE_NAME = "ip"
        elif opt in ("-n", "--name"):
            APP_NAME = val
    
    if SOURCE_CODE_STATUS == False and IP_STATUS == False and URL_STATUS == False:
        print(colored('[!] Please supply template tags:', "yellow"))
        help(not_supplied=True)
        exit(1)

    if re.match(r".*\/([\w\d\_\ ]+)\/(url|sourceCode|ip)\/\d{8}", str(os.getcwd())):
        print(f'[!] Generating markdown file on {CURRENT_DATE}')
        generate_markdown(app=APP_NAME)
    elif re.match(r".*\/[\w\d\_\ ]+\/(url|sourceCode|ip)", str(os.getcwd())):
        mkdate_directory(CURRENT_DATE)
        print(f'[!] Generating markdown file on {CURRENT_DATE}')
        generate_markdown(app=APP_NAME)
    elif APP_NAME != "":
        # From root VA directory
        mkapp_directory(APP_NAME, TYPE_NAME, CURRENT_DATE)
        print(f'[!] Generating markdown file on {CURRENT_DATE}')
        generate_markdown(app=APP_NAME, type=TYPE_NAME)