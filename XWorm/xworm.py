import base64
import malduck
import binascii
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

TARGET_PATH = input('Enter file path to XWorm payload:')
if os.path.exists(TARGET_PATH):
    file_data = open(TARGET_PATH,'rb').read()
else:
    sys.exit('File does not exist - terminating')

module = dnlib.DotNet.ModuleDefMD.Load(TARGET_PATH)

def filter_non_printable(str):
  return ''.join([c for c in str if ord(c) > 31 or ord(c) == 9])

def get_key_seed(config):
    seed = ''
    for i in config:
        if len(i) == 16:
            seed = i
    return bytes(seed, 'UTF-8')

def aes_dec(enc_str, key):
    enc_str_b64 = base64.b64decode(enc_str)
    dec_str = malduck.aes.ecb.decrypt(key, enc_str_b64)
    return dec_str.decode('UTF-8')


config = []

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
            if "ret" in method.Body.Instructions[ptr].ToString() and "stsfld" in method.Body.Instructions[ptr-1].ToString() and "ldstr" in method.Body.Instructions[ptr-2].ToString() or "ret" in method.Body.Instructions[ptr].ToString() and "stsfld" in method.Body.Instructions[ptr-1].ToString() and "call" in method.Body.Instructions[ptr-2].ToString():
                for ptr in range(len(method.Body.Instructions)):
                    if method.Body.Instructions[ptr].OpCode == OpCodes.Ldstr:
                        config.append((method.Body.Instructions[ptr].Operand))
                    if "ldc.i4" in method.Body.Instructions[ptr].ToString(): # grab the sleep time value "IL_0028: ldc.i4.3"
                        config.append(method.Body.Instructions[ptr].ToString()[-1])


key_seed = malduck.md5(get_key_seed(config))
key = key_seed[0:15] + key_seed[0:16] + bytearray(b'\x00')

enc_labels = ['Host', 'Port', 'AES Key', 'Splitter', 'USB Drop File', 'Telegram Token', 'Telegram Chat ID']
enc_label_cycle = itertools.cycle(enc_labels)

ptext_labels = ['Sleep Time', 'Install Directory', 'Mutex/Key Seed', 'Log File Directory', 'Log File']
ptext_label_cycle = itertools.cycle(ptext_labels)

for s in config:
    try:
        decrypted = aes_dec(s,key)
        printable_decrypted = filter_non_printable(decrypted)
        label = next(enc_label_cycle)
        print(f"{label}: {printable_decrypted}")
    except:
        label = next(ptext_label_cycle)
        print(f"{label}: {s}")
