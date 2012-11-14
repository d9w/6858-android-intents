#!/usr/bin/python
# Finds vulnerabilites in Dalvik bytecode

def get_permission_access(d,dx,permission_names):
    cm = d.get_class_manager()
    permissions = dx.get_permissions(permission_names)
    methods ={}
    for p in permission_names:
        methods[p]=[]
        if p in permissions:
            for path in permissions[p]:
                methods[p].append(cm.get_method_ref(path.get_src_idx()))

    return methods
