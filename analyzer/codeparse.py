#!/usr/bin/python
# Finds vulnerabilites in Dalvik bytecode

from androguard.core.analysis.analysis import PathP
import permissions

def get_permission_access(d,dx, perms=[]):
    cm = d.get_class_manager()
    permissions = dx.get_permissions(perms)
    methods ={}
    for p in permissions:
        methods[p]=[]
        for path in permissions[p]:
            try:#if isinstance(path,PathP):
                bad_thing =cm.get_method_ref(path.get_dst_idx())
                methods[p].append((cm.get_method_ref(path.get_src_idx()),bad_thing))
            except:# else:
                print str(p) + " Failed!"
                pass #methods[p].append(cm.get_method_ref(path.get_dst_idx()))
    return methods
