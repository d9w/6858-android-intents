#!/usr/bin/python

import sys
import getopt
import zipfile
import os
from androlyze import *

def main(argv):
    apk = ''
    try:
       opts, args = getopt.getopt(argv,"ha:",["apk="]) # add other options here
    except getopt.GetoptError:
       print 'test.py -a <apk>' # error ouput
       sys.exit(2)
    for opt, arg in opts: # handle options
       # help
       if opt == '-h':
           print 'test.py -a <apk>'
           sys.exit()
       # apk
       elif opt in ("-a", "--apk"):
           apk = arg
    print apk
    # analyze apk and get bytecode
    a, d, dx = AnalyzeAPK(apk)
    a.show()

if __name__ == "__main__":
   main(sys.argv[1:])
