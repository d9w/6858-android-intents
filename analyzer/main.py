#!/usr/bin/python

import sys
import getopt
import os
from androlyze import *
from permissions import *
from androguard.decompiler.dad import decompile
from androguard.core.analysis.analysis import *
from xmlparse import get_exploitable_methods, get_used_perms
from codeparse import get_permission_access

def main(argv):
    apk = None
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

    if apk is None:
        print 'test.py -a <apk>'
        sys.exit()
    # analyze apk and get bytecode
    a, d, dx = AnalyzeAPK(apk)
    #vm = dvm.DalvikVMFormat(a.get_dex())
    #vmx = analysis.VMAnalysis(vm)

    # vm is just d and so vmx is dx...
    vmx = dx

    # pass to parsers to find vulnerabilities
    openMethods = get_exploitable_methods(a,d, permissions)#vm.get_methods()
    usedPerms = get_used_perms(a)
    permKeys = [k.split('.')[-1] for k in permissions.keys()]
    permMethods = get_permission_access(d,dx,permKeys)

    print "perms manifest says app uses: " + str(usedPerms)
    print "perms actually used by app: " + str(permMethods.keys())
    # compare lists of methods
    for perm,methods in permMethods.items():
        for method in methods:
            if method in openMethods:
                # print code from matching methods
                print method.get_name()
                if method.get_code() == None:
                  continue

                print perm, method.get_class_name(), method.get_name(), method.get_descriptor()

                mx = vmx.get_method(method)
                ms = decompile.DvMethod(mx)
                # process to the decompilation
                ms.process()

                # get the source !
                print ms.get_source()

if __name__ == "__main__":
   main(sys.argv[1:])
