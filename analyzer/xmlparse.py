#!/usr/bin/python
# Finds vulnerabilites in manifest files

import sys
from xml.dom.minidom import Element

from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm

import permissions


# Component Types Enum
ACTIVITY = 0
SERVICE = 1
RECEIVER = 2
PROVIDER = 3
tag2type = { "activity":ACTIVITY,
             "activity-alias":ACTIVITY,
             "service":SERVICE,
             "receiver":RECEIVER,
             "provider":PROVIDER}

type2tag = { ACTIVITY:"activity",
             SERVICE:"service",
             RECEIVER:"receiver",
             PROVIDER:"provider"}

type2methods = { ACTIVITY: ["onCreate"],
                 SERVICE: ["onStartCommand", "onBind"],
                 RECEIVER: ["onReceive"],
                 PROVIDER: []}

class Component:
    def __init__(self, element, perms, perm=None):
        self.element = element
        self.type = tag2type[element.tagName]
        if self.element.tagName == "activity-alias":
            self.name = self.element.getAttribute("android:targetActivity")
        else:
            self.name = self.element.getAttribute("android:name")
        self.path = '/'.join(self.name.split('.'))+";"
        self.perm_level = None
        self.perm = None
        if self.element.hasAttribute("android:permission"):
            self.perm = self.element.getAttribute("android:permission")
        elif perm:
            self.perm = perm
        if self.perm:
            self.perm_level = perms[self.perm]

    def __repr__(self):
        return "<"+type2tag[self.type] + " " + self.name + ">"

    def is_public(self):
        exported_set = False
        exported = False
        if self.element.hasAttribute("android:exported"):
            exported = self.element.getAttribute("android:exported") == "true"
        has_filter = False
        if self.element.hasChildNodes():
            for child in [c for c in self.element.childNodes if isinstance(c,Element)]:
                has_filter = has_filter or child.tagName == "intent-filter"
        # See http://developer.android.com/guide/topics/manifest/service-element.html#exported
        if has_filter:
            if exported_set: return exported
            else: return True
        else:
            if exported_set: return exported
            else: return False

    def is_exploitable(self):
        if self.perm:
            return self.is_public() and self.perm_level<permissions.DANG
        else:
            return self.is_public()

def cleanup_attributes(a, element):
    if isinstance(element,Element):
        for tag in ["android:name", "android:targetActivity"]:
            if element.hasAttribute(tag):
                name_attr = element.getAttributeNode(tag)
                name_attr.value = a.format_value(name_attr.value)
    if element.hasChildNodes():
        for e in element.childNodes:
            cleanup_attributes(a, e)

def extract_perms(manifest):
    new_perms = {}
    for p in manifest.getElementsByTagName("permission"):
        perm = p.getAttribute("android:name")
        level = permissions.NORMAL
        if p.hasAttribute("android:protectionLevel"):
            level = permissions.text2perm[p.getAttribute("android:protectionLevel")]
        new_perms[perm] = level
    return new_perms

def get_exploitable_methods(a, d, perms):
    xml = a.get_AndroidManifest()
    cleanup_attributes(a,xml.documentElement)
    perms.update(extract_perms(xml))

    app = xml.getElementsByTagName("application")[0]
    app_perm = None
    if app.hasAttribute("android:permission"):
        app_perm = activity.getAttribute("android:permission")

    components = []
    for comp_name in tag2type.keys():
        for item in xml.getElementsByTagName(comp_name):
            comp = Component(item, perms, app_perm)
            if comp.is_exploitable():
                components.append(comp)

    print components

    classes = d.get_classes()
    exploitable_methods = []
    for comp in components:
        c_objects = [k for k in classes if k.get_name().count(comp.path) > 0]
        if len(c_objects) != 1:
            print "oh no! Found %d classes for component %s" % (len(c_objects), comp.name)
            continue
        c_obj = c_objects[0]
        # TODO: perhaps we need to look for methods in superclass? For example:
        # BitCoin Wallet app has receiver
        # de.schildbach.wallet.WalletBalanceWidgetProvider
        # which subclasses android.appwidget.AppWidgetProvider, which is where
        # the onReceive method is implemented...
        method_objects = [m for m in c_obj.get_methods() if m.get_name() in type2methods[comp.type]]
        exploitable_methods = exploitable_methods + method_objects

    print [m.get_name() for m in exploitable_methods]
    # Links to check out:
    # http://developer.android.com/guide/topics/manifest/provider-element.html#gprmsn
    # http://developer.android.com/guide/topics/manifest/data-element.html
    # https://developer.android.com/guide/topics/security/permissions.html#enforcement

    return exploitable_methods


if __name__ == "__main__" :
    get_exploitable_methods(apk.APK(sys.argv[1]), dvm.DalvikVMFormat(a.get_dex()),permissions.permissions)
