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

enc_str = []
ptext = []
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
            if "\\Log.tmp" in method.Body.Instructions[ptr].ToString():
                enc_str.append((method.Body.Instructions[ptr-18].Operand))
                enc_str.append((method.Body.Instructions[ptr-16].Operand))
                enc_str.append((method.Body.Instructions[ptr-14].Operand))
                enc_str.append((method.Body.Instructions[ptr-12].Operand))
                enc_str.append((method.Body.Instructions[ptr-8].Operand))
                ptext.append((method.Body.Instructions[ptr-6].Operand))
                key_seed = bytes(method.Body.Instructions[ptr-4].Operand, 'utf-8')
                ptext.append((method.Body.Instructions[ptr-4].Operand))
                ptext.append((method.Body.Instructions[ptr-2].Operand))
                ptext.append((method.Body.Instructions[ptr].Operand))
                enc_str.append((method.Body.Instructions[ptr+3].Operand))
                enc_str.append((method.Body.Instructions[ptr+5].Operand))

key_seed = malduck.md5(key_seed)
key = key_seed[0:15] + key_seed[0:16] + bytearray(b'\x00')

enc_labels = ['Host', 'Port', 'AES Key', 'Splitter', 'USB Drop File', 'Telegram Token', 'Telegram Chat ID']
enc_label_cycle = itertools.cycle(enc_labels)

ptext_labels = ['Install Directory', 'Mutex/Key Seed', 'Log File Directory', 'Log File']
ptext_label_cycle = itertools.cycle(ptext_labels)

def aes_dec(enc_str, key):
    enc_str_b64 = base64.b64decode(enc_str)
    dec_str = malduck.aes.ecb.decrypt(key, enc_str_b64)
    return dec_str.decode('UTF-8')

for s in enc_str:
    decrypted = aes_dec(s,key)
    ascii_decrypted = filter_non_printable(decrypted)
    # print(ascii_decrypted)
    label = next(enc_label_cycle)
    print(f"{label}: {ascii_decrypted}")

for s in ptext:
    label = next(ptext_label_cycle)
    print(f"{label}: {s}")
