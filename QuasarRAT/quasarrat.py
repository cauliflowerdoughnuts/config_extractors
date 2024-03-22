import os
import sys
import clr
import malduck
from Crypto.Protocol.KDF import PBKDF2
import base64
import itertools
clr.AddReference('System.Memory')
from System.Reflection import Assembly, MethodInfo, BindingFlags
from System import Type
DNLIB_PATH = '/<path to>/dnlib.dll'
clr.AddReference(DNLIB_PATH)
import dnlib
from dnlib.DotNet import *


SALT = bytes([191, 235, 30, 86, 251, 205, 151, 59, 178, 25, 2, 36, 48, 165, 120, 67, 0, 61, 86, 68, 210, 30, 98, 185, 212, 241, 128, 231, 230, 195, 57, 65]) # So far none of the malicious actors have changed the salt
LABELS = ['Version', 'C2', 'Install Directory', 'Install Name', 'Mutex', 'Registry Name', 'Tag', 'Logs Directory', 'Server Signature', 'Server Certificate']


def load_pefile(file_path):
    if os.path.exists(file_path):
        return open(file_path, 'rb').read()
    else:
        sys.exit('File does not exist - terminating')


def extract_cipher_strings(module):
    cipher = []
    key_password = None
    for mtype in module.GetTypes():
        if not mtype.HasMethods:
            continue
        for method in mtype.Methods:
            if not method.IsConstructor or not method.HasBody or not method.Body.HasInstructions:
                continue
            for ptr in range(len(method.Body.Instructions)):
                if len(cipher) >= 13:  # Only the first 13 strings are relevant
                    break
                if 'ldstr' in method.Body.Instructions[ptr].ToString() and 'stsfld' in method.Body.Instructions[ptr + 1].ToString():
                    operand = method.Body.Instructions[ptr].Operand
                    cipher.append(operand)
                    if operand.isalnum(): # The only string that is not base64 encoded should be the key password
                        key_password = operand
                        cipher.remove(key_password)
    return cipher, key_password


def decrypt_config(cipher, key_password):
    key_32 = PBKDF2(key_password, SALT, 32, count=50000)
    keys = [key_32[:16], key_32] # Some samples use 16 byte keys, some use 32 byte keys
    key_16_match = key_32_match = False

    print("[+] Testing AES keys...\n")
    for key in keys:
        if key_16_match and len(key) == 32:
            continue
        for i, s in enumerate(cipher):
            try:
                string_data_b64 = base64.b64decode(s)[32:]
                iv, enc_data = string_data_b64[:16], string_data_b64[16:]
                decoded_string = malduck.aes.cbc.decrypt(key, iv, enc_data).decode('utf-8', 'ignore')
                if i == 0 and not decoded_string[0].isdigit():
                    print(f"[!] {len(key)} byte key failed.\n")
                    break
                decoded_string = ''.join(ch if ch.isprintable() else '' for ch in decoded_string)
                if i == 0:
                    print(f"[+] Config has been decrypted with {len(key)} byte key derived from passphrase {key_password}:\n")
                print(f"{LABELS[i]}: {decoded_string}")
                if len(key) == 16:
                    key_16_match = True
                elif len(key) == 32:
                    key_32_match = True
            except Exception as e:
                pass
    if not key_16_match and not key_32_match:
        print(f"[!] Decryption failed with both 16 and 32 byte keys derived from passphrase {key_password}.\n")


def main():
    target_path = input('Enter file path to Quasar payload:')
    file_data = load_pefile(target_path)
    module = ModuleDefMD.Load(target_path)
    cipher, key_password = extract_cipher_strings(module)
    decrypt_config(cipher, key_password)


if __name__ == "__main__":
    main()
