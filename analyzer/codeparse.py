#!/usr/bin/python
# Finds vulnerabilites in Dalvik bytecode

class PublicComponent:
    def __init__(self,name,component_type,bytecode):
        self.name = name
        self.bytecode = bytecode
    
    #find the class associated with this componenet
    def find_class(self):
        self.class_name = None
    

    def find_intent_object(self):
        #find the method that accepts the intent and start tracing the intent
        self.intent_object = None
        pass
    
    def trace_intent_data(self):
        #I think androguard can do this but I can't figure out what to pass in
        #output a list of methods that data from this intent gets used in
        pass
    
    def is_privileged(self,method):
        #check whether this method accesses something that we consider sensitive
        return False
    
    def uses_sqlite(self,method):
        #check whether this method accesses the app's sqlite database (internal data)
        return False

    def uses_protected_component(self,method):
        #check whether this method sends an intent to a component that should be protected by a privilege
        return False
