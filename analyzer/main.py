#!/usr/bin/python

import sys
import getopt
import os
from androlyze import *
from permissions import *
from androguard.decompiler.dad import decompile
from androguard.core.analysis.analysis import *
from xmlparse import get_exploitable_methods
from codeparse import get_permission_access
from androguard.core.bytecodes import dvm_permissions

def create_perms():
    new_perms = {}
    for k,v in dvm_permissions.DVM_PERMISSIONS['MANIFEST_PERMISSION'].items():
        new_perms[k] = text2perm[v[0]]
    return new_perms

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
    perms = create_perms()
    openMethods = get_exploitable_methods(a,d, perms)
    usedPerms = [p.split('.')[-1] for p in a.get_permissions()]
    permKeys = perms.keys()#[k.split('.')[-1] for k in permissions.keys()]
    permMethods = get_permission_access(d,dx)

    print "perms manifest says app uses: " + str(usedPerms)
    #print "perms actually used by app: " + str(permMethods.keys())
    print "other perms:"
    analysis.show_Permissions(dx)

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
