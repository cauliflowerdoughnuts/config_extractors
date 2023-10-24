import base64
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

TARGET_PATH = input('Enter file path to NjRAT payload:')
if os.path.exists(TARGET_PATH):
    file_data = open(TARGET_PATH,'rb').read()
else:
    sys.exit('File does not exist - terminating')

module = dnlib.DotNet.ModuleDefMD.Load(TARGET_PATH)

encoded = False
pastebin = False

def is_pastebin():
    for mtype in module.GetTypes():
        if not mtype.HasMethods:
            continue
        for method in mtype.Methods:
            if not method.HasBody: 
                continue
            if not method.Body.HasInstructions: 
                continue
            for ptr in range(len(method.Body.Instructions)):
                if "pastebin.com" in method.Body.Instructions[ptr].ToString():
                    global pastebin
                    global c2_config
                    pastebin = True
                    c2_config = method.Body.Instructions[ptr].Operand


def is_encoded():
    for mtype in module.GetTypes():
        if not mtype.HasMethods:
            continue
        for method in mtype.Methods:
            if not method.HasBody: 
                continue
            if not method.Body.HasInstructions: 
                continue
            for ptr in range(len(method.Body.Instructions)):
                if "ldstr" in method.Body.Instructions[ptr].ToString() and "|'|'|" in method.Body.Instructions[ptr].ToString():
                    if "nop" in method.Body.Instructions[ptr+2].ToString() and "ret" in method.Body.Instructions[ptr+3].ToString():
                        global encoded
                        encoded = True
                    else:
                        if "stsfld" in method.Body.Instructions[ptr+1].ToString() and "ldstr" in method.Body.Instructions[ptr+2].ToString() and "Conversions::ToBoolean" in method.Body.Instructions[ptr+3].ToString():
                            global c2_addr
                            global c2_port
                            c2_addr = method.Body.Instructions[ptr-4].Operand
                            c2_port = method.Body.Instructions[ptr-2].Operand
                            return c2_addr,c2_port


def get_encoded():
    for mtype in module.GetTypes():
        if not mtype.HasMethods:
            continue
        for method in mtype.Methods:
            if not method.HasBody: 
                continue
            if not method.Body.HasInstructions: 
                continue
            for ptr in range(len(method.Body.Instructions)):
                if "ldstr" in method.Body.Instructions[ptr].ToString() and "stsfld" in method.Body.Instructions[ptr+1].ToString() and "ldnull" in method.Body.Instructions[ptr+2].ToString():
                    global c2_port
                    c2_port = base64.b64decode(method.Body.Instructions[ptr].Operand).decode('utf-8')
                if "ldstr" in method.Body.Instructions[ptr].ToString() and "ldstr" in method.Body.Instructions[ptr+1].ToString() and "ldstr" in method.Body.Instructions[ptr+2].ToString() and "ldc.i4" in method.Body.Instructions[ptr+3].ToString() and "call" in method.Body.Instructions[ptr+6].ToString():
                    global c2_addr_enc
                    c2_addr_str_rep_1 = method.Body.Instructions[ptr+1].Operand
                    c2_addr_str_rep_2 = method.Body.Instructions[ptr+2].Operand
                    c2_addr_enc = bytearray(method.Body.Instructions[ptr].Operand.replace(c2_addr_str_rep_1, c2_addr_str_rep_2).encode('utf-8'))
                    return c2_port, c2_addr_enc

is_pastebin()

if pastebin: # Only 1 out of 5 samples tested stored the C2 config in a URL, and it was a pastebin URL. Added this function just in case it is a standard option.
    print(f'The C2 config is stored at: {c2_config}')
else:
    is_encoded()

    if encoded:
        get_encoded()
        try:
            c2_addr = base64.b64decode(c2_addr_enc).decode('utf-8') # The malware uses a character replace for the '==' at the end of the b64, I added this try except so that I do not have to loop through the instructions to find the replacement strings. It will try b64 decoding as is, and if there is an error then replace the last two characters with '=='
            print(f'C2 Address: {c2_addr}')
            print(f'C2 Port: {c2_port}')
        except Exception:
            c2_addr_enc[-2:] = b'=='
            c2_addr = base64.b64decode(c2_addr_enc).decode('utf-8')
            print(f'C2 Address: {c2_addr}')
            print(f'C2 Port: {c2_port}')
    else:
        print(f'C2 Address: {c2_addr}')
        print(f'C2 Port: {c2_port}')
