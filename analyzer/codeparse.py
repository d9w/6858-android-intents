#!/usr/bin/python
# Finds vulnerabilites in Dalvik bytecode

from androguard.core.analysis.analysis import PathP

def get_permission_access(d,dx,permission_names):
    cm = d.get_class_manager()
    permissions = dx.get_permissions(permission_names)
    methods ={}
    for p in permission_names:
        if p in permissions:
            methods[p]=[]
            for path in permissions[p]:
                try:#if isinstance(path,PathP):
                    methods[p].append(cm.get_method_ref(path.get_src_idx()))
                except:# else:
                    pass #methods[p].append(cm.get_method_ref(path.get_dst_idx()))
    return methods
