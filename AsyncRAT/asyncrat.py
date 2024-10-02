import os
import pefile
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA1
import base64
import itertools
import clr
clr.AddReference("System.Memory")
DNLIB_PATH = '/<path_to_dnlib>/dnlib.dll'
clr.AddReference(DNLIB_PATH)
import dnlib
from dnlib.DotNet import *


def read_file(file_path):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File does not exist: {file_path}")

    try:
        with open(file_path, 'rb') as file:
            return file.read()
    except Exception as e:
        raise IOError(f"Error reading file: {e}")


def filter_non_printable(str):
	return ''.join([c for c in str if ord(c) > 31 or ord(c) == 9])


def decrypt(ciphertext, key):
    iv = bytearray(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ptext = cipher.decrypt(base64.b64decode(ciphertext))
    plaintext = ptext[48:].decode('utf-8')
    plaintext = filter_non_printable(plaintext)
    return plaintext


def extract_salt(method, ptr):
    if "RuntimeHelpers::InitializeArray" in method.Body.Instructions[ptr].ToString() and "32" in method.Body.Instructions[ptr-4].ToString():
        arr_inst = method.Body.Instructions[ptr-1]
        arr_rva = int(arr_inst.Operand.RVA.ToString())
        arr_size = arr_inst.Operand.GetFieldSize()
        return pe.get_data(arr_rva, arr_size)
    elif "Client.Algorithm.Aes256::Salt" in method.Body.Instructions[ptr].ToString() and "ldstr" in method.Body.Instructions[ptr-2].ToString():
        return method.Body.Instructions[ptr-2].Operand
    return None


def extract_ciphertext(method, ptr):
    return [
        method.Body.Instructions[ptr-8].Operand,
        method.Body.Instructions[ptr-6].Operand,
        method.Body.Instructions[ptr-4].Operand,
        method.Body.Instructions[ptr+6].Operand
    ]


def parse_config(TARGET_PATH):
    salt = None
    ciphertext = []
    module = dnlib.DotNet.ModuleDefMD.Load(TARGET_PATH)

    for mtype in module.GetTypes():
        if not mtype.HasMethods:
            continue
        for method in mtype.Methods:
            if not (method.IsConstructor and method.HasBody and method.Body.HasInstructions):
                continue
            for ptr in range(len(method.Body.Instructions)):
                if salt is None:
                    salt = extract_salt(method, ptr)
                    if salt:
                        continue
                if "%Temp%" in method.Body.Instructions[ptr].ToString() or "%AppData%" in method.Body.Instructions[ptr].ToString():
                    key_seed = method.Body.Instructions[ptr+4].Operand
                    ciphertext.extend(extract_ciphertext(method, ptr))
    return salt, ciphertext, key_seed


def print_config(salt, ciphertext, key_seed):
    labels = ['Ports', 'C2', 'Version', 'Mutex']
    label_cycle = itertools.cycle(labels)

    if salt is None:
        raise ValueError('Could not locate salt')
    else:
        password = (base64.b64decode(key_seed))
        key = PBKDF2(password, salt, 32, count=50000, hmac_hash_module=SHA1)

    print(f'[!] Found Config:\n')
    for i in ciphertext:
        decrypted = decrypt(i, key)
        label = next(label_cycle)
        print(f'[+] {label}: {decrypted}')


def main(file_path):
    global pe
    print(f'Reading file: {file_path}\n')
    file_data = read_file(file_path)

    try:
        pe = pefile.PE(data=file_data)
    except pefile.PEFormatError as e:
        raise ValueError(f'Error parsing PE file: {e}')
    
    salt, ciphertext, key_seed = parse_config(TARGET_PATH)
    print_config(salt, ciphertext, key_seed)


if __name__ == '__main__':
    TARGET_PATH = input('Enter file path to AsyncRAT payload:')
    main(TARGET_PATH)
