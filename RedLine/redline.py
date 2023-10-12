import base64
import itertools
import os
import sys, struct, clr
from System.Reflection import Assembly, MethodInfo, BindingFlags
from System import Type


DNLIB_PATH = '/root/dnlib.dll'
clr.AddReference(DNLIB_PATH)
clr.AddReference("System.Memory")
import dnlib
from dnlib.DotNet import *
from dnlib.DotNet.Emit import OpCodes

TARGET_PATH = input('Enter file path to RedLine payload:')
if os.path.exists(TARGET_PATH):
    file_data = open(TARGET_PATH,'rb').read()
else:
    sys.exit('File does not exist - terminating')

module = dnlib.DotNet.ModuleDefMD.Load(TARGET_PATH)

config = []
version_found = False

for mtype in module.GetTypes():
    if not mtype.HasMethods:
        continue
    for method in mtype.Methods:
        if not method.IsConstructor:
            continue
        if not method.HasBody: 
            continue
        if not method.Body.HasInstructions: 
            continue
        for ptr in range(len(method.Body.Instructions)):
            if "ret" in method.Body.Instructions[ptr].ToString() and "stsfld" in method.Body.Instructions[ptr-1].ToString() and "ldc.i4" in method.Body.Instructions[ptr-2].ToString():
                for ptr in range(len(method.Body.Instructions)):
                    if method.Body.Instructions[ptr].OpCode == OpCodes.Ldstr:
                        config.append((method.Body.Instructions[ptr].Operand))
                    if "ldc.i4" in method.Body.Instructions[ptr].ToString(): # grab the version value
                        if not version_found: # we only want to grab the first instance of ldc.i4
                            config.append(method.Body.Instructions[ptr].ToString()[-1])
                            version_found = True


def xor(data, key):
    out = []
    data = base64.b64decode(data)
    for i in range(len(data)):
        out.append(data[i] ^ key[i%len(key)])
    return base64.b64decode(bytes(out)).decode(errors='ignore')


labels = ['IP', 'ID', 'Message', 'Key', 'Version']
label_cycle = itertools.cycle(labels)

key = config[3].encode('utf-8')

for index, s in enumerate(config):
    if index < 3: # Only the first three elements of the array are encrypted; after decrypting them then skip the decryption for the remaining plaintext strings.
        decrypted = xor(s, key)
        label = next(label_cycle)
        print(f"{label}: {decrypted}")
    else:
        label = next(label_cycle)
        print(f"{label}: {s}")
