#!/usr/bin/python3

import sys
import getopt
from termcolor import colored

if sys.platform == "linux" or sys.platform == "linux2":
    # linux
    pass
elif sys.platform == "darwin":
    # MAC OS X
    pass
elif sys.platform == "win32" or sys.platform == "win64":
    # Windows 32-bit or Windows 64-bit
    import colorama
    colorama.init()
    
def help():
    print("-h       : get help")

if __name__ == "__main__":
    opts, args = getopt.getopt(sys.argv[1:], "h", ["help"])

    for opt, val in opts:
        if opt in ("-h", "--help"):
            help()
            exit(0)

    print("template success")