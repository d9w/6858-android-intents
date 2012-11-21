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

def path_search(startn,stopn,trace):
    if startn == stopn:
        return [True,trace]
    if len(startn.edges) == 0:
        return [False,trace]
    boolinit = False
    for e in startn.edges:
        t = trace
        t.append(e)
        boolinit = boolinit or path_search(e,stopn,t)[0]
    return [boolinit,trace]

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
            apks = [d+'/'+f for f in sorted(os.listdir(d),key=lambda x: x.lower()) if f.lower().endswith('apk')]
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
            # skip completed apks
            #try:
            #    open(outs[i])
            #    continue
            #except:
            #    pass
            print apk
            if apk is None:
                print 'main.py -a <apk> -o <output> -d <directory>' # error
                sys.exit()
            # analyze apk and get bytecode
            a, d, dx = AnalyzeAPK(apk)
            classdict = {c.get_name(): c for c in d.get_classes()}
            #print classdict.keys()
            methoddict = {m.get_class_name()+m.get_name(): m for m in d.get_methods()}
            #print methoddict.keys()

            print [c.get_class_name() for c in d.get_methods() if c.get_class_name() not in classdict.keys()]

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

            # get graph for matching
            gdx = d.CM.get_gvmanalysis()

            # write the source of accessible, permission-using methods
            out.write('\n\nMatching methods:\n')
            # compare lists of methods
            for comp,smethod in openMethods:
                startn = gdx._get_node(smethod.get_class_name(), smethod.get_name(), smethod.get_descriptor())
                for perm,methods in permMethods.items():
                    if perm != comp.perm:
                        for emethod,inv in methods:
                            stopn = gdx._get_node(emethod.get_class_name(), emethod.get_name(), emethod.get_descriptor())
                            try:
                                path,trace = path_search(startn,stopn,[startn])
                                if path:
                                    s = "MATCH:%s %s with perm %s maps to %s with perm %s" % (perm, smethod.get_name()+smethod.get_class_name(), comp.perm, inv.get_name(), perm)
                                    print s
                                    out.write('\n%s\n' % s)
                                    #for node in trace:
                                        #method lookup fails for classes with $ versions
                                        #mx = dx.get_method(methoddict[node.class_name+node.method_name])
                                        #ms = decompile.DvMethod(mx)
                                        #ms.process()
                                        #out.write(ms.get_source()+'\n')
                            except:
                                pass # recursion depth reached, look for other matches
        except Exception:
            if len(apks)>1:
                print 'FAILED'
            else:
                traceback.print_exc()

if __name__ == "__main__":
   main(sys.argv[1:])
