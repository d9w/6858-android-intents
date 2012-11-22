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

def get_reachable_exits(startn, exits):
    if startn in exits:
        return {startn:[[startn]]}
    if len(startn.edges) == 0:
        return {}
    reached = {}
    for e in startn.edges.keys():
        traces = get_reachable_exits(e, exits)
        for x in traces.keys():
            updated_traces = [[startn] + tr for tr in traces[x]]
            if x in reached.keys():
                reached[x].extend(updated_traces)
            else:
                reached[x] = updated_traces
    return reached

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

            # xml parser finds accessible methods
            perms = create_perms()
            openMethods = get_exploitable_methods(a,d, perms)
            out = open(outs[i],'w')
            if len(openMethods) < 1:
                print "apk has no public entry points"
                out.write('No public entry points')
                continue
            openMethodsdic = {m[1].get_name()+m[1].get_class_name(): m for m in openMethods}
            usedPerms = [p.split('.')[-1] for p in a.get_permissions()]

            # code parser finds permission-using methods
            permMethods = get_permission_access(d,dx, [k for k in perms.keys() if perms[k] >= DANG])

            # write the used permissions
            out.write('Permissions declared in the manifest:\n')
            out.write(str(usedPerms))

            # get graph for matching
            gdx = d.CM.get_gvmanalysis()

            # write the source of accessible, permission-using methods
            out.write('\n\nMatching methods:\n')
            # compare lists of methods
            for comp,smethod in openMethods:
                startn = gdx._get_node(smethod.get_class_name(), smethod.get_name(), smethod.get_descriptor())
                for perm,methods in permMethods.items():
                    if perm != comp.perm:
                        exits_dict = {}
                        for m,g in methods:
                            key = gdx._get_node(m.get_class_name(), m.get_name(), m.get_descriptor())
                            exits_dict[key] = exits_dict.get(key,[]) + [gdx._get_node(g.get_class_name(), g.get_name(), g.get_descriptor())]
                        try:
                            p = get_reachable_exits(startn,exits_dict.keys())
                        except:
                            # reached recursion depth...
                            continue
                        if p:
                            paths = []
                            for tr in p.values():
                                for path in tr:
                                    for end in exits_dict[path[-1]]:
                                        paths.append(path+[end])
                            for path in paths:
                                s = "pMATCH:%s %s with perm %s maps to %s with perm %s" % (perm, smethod.get_name()+smethod.get_class_name(), comp.perm, path[-1].method_name, perm)
                                print s
                                out.write('\n%s\n' % s)
                                out.write('trace:' + str([z.class_name+z.method_name for z in path])+'\n')
                                out.write('source for methods in trace:\n')
                                for node in path[:-1]:
                                    #print node.class_name+node.method_name
                                    #dx.get_tainted_packages().get_package(node.class_name).get_method(node.method_name, node.descriptor)[0].get_src(d.CM)
                                    #node_method = dx.get_tainted_packages().search_methods(node.class_name,node.method_name,'.')[0].get_src(d.CM)
                                    #print [j.get_class_name() + j.get_name() for j in d.get_methods_class(node.class_name)]
                                    node_method = d.get_method_descriptor(node.class_name,node.method_name,node.descriptor)
                                    #method lookup fails for start methods...
                                    if node_method is not None:
                                        mx = dx.get_method(node_method)
                                        ms = decompile.DvMethod(mx)
                                        ms.process()
                                        #print ms.get_source()
                                        out.write(ms.get_source()+'\n')
                                    else:
                                        out.write("could not find source for %s!\n"%(node.class_name+node.method_name))
        except Exception:
            if len(apks)>1:
                print 'FAILED'
            else:
                traceback.print_exc()

if __name__ == "__main__":
   main(sys.argv[1:])
