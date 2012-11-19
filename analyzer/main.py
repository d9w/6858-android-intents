#!/usr/bin/python

import sys
import os
import traceback
from optparse import OptionParser
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
    # set flag options
    parser = OptionParser()
    parser.add_option("-a", "--apk", dest="apk",
                      help="apk FILE", metavar="FILE")
    parser.add_option("-o", "--output", dest="output",
                      help="output FILE", metavar="FILE")
    parser.add_option("-d","--directory", dest="directory",
                      help="directory DIR", metavar="DIR")

    (options, args) = parser.parse_args()

    if options.apk is None:
        if options.directory is None:
            print 'main.py requires either -a <apk> or -d <directory>'
            sys.exit()
        else:
            d = options.directory
            apks = [d+'/'+f for f in os.listdir(d) if f.lower().endswith('apk')]
            outs = [f.rsplit('.',1)[0]+'.txt' for f in apks]
    else:
        apks = [options.apk]
        if options.output is None:
            outs = [apks[0].rsplit('.',1)[0]+'.txt']
        else:
            outs = [options.output]

    for i in range(len(apks)):
        try:
            apk = apks[i]
            print apk
            if apk is None:
                print 'main.py -a <apk> -o <output> -d <directory>' # error
                sys.exit()
            # analyze apk and get bytecode
            a, d, dx = AnalyzeAPK(apk)
            classdict = {c.get_name(): c for c in d.get_classes()}

            # xml parser finds accessible methods
            perms = create_perms()
            openMethods = get_exploitable_methods(a,d, perms)
            if len(openMethods) < 1:
                print "apk has no public entry points"
                continue
            out = open(outs[i],'w')
            openMethodsdic = {m[1].get_name()+m[1].get_class_name(): m for m in openMethods}
            usedPerms = [p.split('.')[-1] for p in a.get_permissions()]

            # code parser finds permission-using methods
            permMethods = get_permission_access(d,dx, [k for k in perms.keys() if perms[k] >= DANG])

            # write the used permissions
            out.write('Permissions declared in the manifest:\n')
            out.write(str(usedPerms))
            #print "perms actually used by app: " + str(permMethods.keys())
            #analysis.show_Permissions(dx)

            # write the source of accessible, permission-using methods
            out.write('\n\nMatching methods:\n')
            # compare lists of methods
            for perm,methods in permMethods.items():
                for method,inv in methods:
                    if method.get_name()+method.get_class_name() in openMethodsdic.keys():
                        comp,meth = openMethodsdic[method.get_name()+method.get_class_name()]
                        if perm != comp.perm:
                            s = "MATCH:%s %s with perm %s maps to %s with perm %s" % (perm, meth.get_name()+meth.get_class_name(), comp.perm, inv.get_name(), perm)
                            print s
                            #print 'MATCH: '+perm+' in '+method.get_name()+method.get_class_name()+'\n'
                            out.write('\n%s\n' % s)


                            # get method source object
                            mx = dx.get_method(meth)
                            ms = decompile.DvMethod(mx)
                            # process to the decompilation
                            ms.process()

                            # get the source !
                            out.write(ms.get_source()+'\n')
        except:
            if len(apks)>1:
                print 'FAILED'
            else:
                traceback.print_exc()

if __name__ == "__main__":
   main(sys.argv[1:])
