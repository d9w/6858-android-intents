#!/usr/bin/python
# Finds vulnerabilites in manifest files

import sys
from xml.dom.minidom import Element

from androguard.core.bytecodes import apk
import permissions as perms


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

class Component:
    def __init__(self, element, perm=None):
        self.element = element
        self.type = tag2type[element.tagName]
        self.name = self.element.getAttribute("android:name")
        if self.element.hasAttribute("android:permission"):
            self.perm = self.element.getAttribute("android:permission")
        else:
            self.perm = perm

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
            return self.is_public() and perms.permissions[self.perm]<perms.SIG
        else:
            return self.is_public()

def cleanup_attributes(a, element):
    if isinstance(element,Element) and element.hasAttribute("android:name"):
        name_attr = element.getAttributeNode("android:name")
        name_attr.value = a.format_value(name_attr.value)
    if element.hasChildNodes():
        for e in element.childNodes:
            cleanup_attributes(a, e)

def extract_perms(manifest):
    for p in manifest.getElementsByTagName("permission"):
        perm = p.getAttribute("android:name")
        level = perms.NORMAL
        if p.hasAttribute("android:protectionLevel"):
            level = perms.text2perm[p.getAttribute("android:protectionLevel")]
        perms.permissions[perm] = level

def main(apk_file):
    a = apk.APK(apk_file)
    xml = a.get_AndroidManifest()
    cleanup_attributes(a,xml.documentElement)
    extract_perms(xml)

    activity = xml.getElementsByTagName("activity")[0]
    act_perm = None
    if activity.hasAttribute("android:permission"):
        act_perm = activity.getAttribute("android:permission")

    components = []
    for comp_name in tag2type.keys():
        for item in xml.getElementsByTagName(comp_name):
            components.append(Component(item, act_perm))

    print [c for c in components if c.is_exploitable()]

    # Links to check out:
    # http://developer.android.com/guide/topics/manifest/provider-element.html#gprmsn
    # http://developer.android.com/guide/topics/manifest/data-element.html
    # https://developer.android.com/guide/topics/security/permissions.html#enforcement


if __name__ == "__main__" :
    main(sys.argv[1])
