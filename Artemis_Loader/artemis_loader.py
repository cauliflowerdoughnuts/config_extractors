# References: 
# https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/agent-teslas-new-ride-the-rise-of-a-novel-loader/


import os
import sys
import hashlib
import base64
import clr
clr.AddReference('System.Memory')
DNLIB_PATH = '/<path to>/dnlib.dll'
clr.AddReference(DNLIB_PATH)
from dnlib.DotNet import *
from dnlib.DotNet.Emit import OpCodes


def extract_ciphers_keys(file_data):
    strings = []
    config_found = False
    for mtype in file_data.GetTypes():
        if config_found:
            break
        if not mtype.HasMethods:
            continue
        for method in mtype.Methods:
            if config_found:
                break
            if not method.IsConstructor or not method.HasBody or not method.Body.HasInstructions:
                continue
            for ptr in range(len(method.Body.Instructions)):
                if config_found == False and method.Body.Instructions[ptr].OpCode == OpCodes.Ldstr and method.Body.Instructions[ptr+1].OpCode == OpCodes.Call:
                        config_found = True
                        strings.append(method.Body.Instructions[ptr].Operand)
                        continue
                if config_found and method.Body.Instructions[ptr].OpCode == OpCodes.Ldstr:
                    strings.append(method.Body.Instructions[ptr].Operand)
    return strings


def identify_variant_2(cipher):
    return all(ord(c) < 128 or ord(c) == 0 for c in cipher)


# The encrypted strings are stored in the format: cipher, key, cipher, key, etc.
def split_cipher_key(enc_strings): 
    cipher = enc_strings[::2]  
    key = enc_strings[1::2]
    return cipher, key


# The encrypted strings are stored in the format: key, cipher, key, cipher, etc.
def split_cipher_key_variant_2(enc_strings): 
    cipher = enc_strings[1::2]  
    key = enc_strings[::2]
    return cipher, key


# After the cipher is hashed, the hash is extended to the length of the key by repeating the hash until the key length is reached
def hash_sha256(cipher, key_length):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(cipher.encode('utf-8'))
    hash_bytes = sha256_hash.digest()
    return bytearray(hash_bytes[i % len(hash_bytes)] for i in range(key_length))


def add_sub(key_array, byte_cipher, bool_0):
    decrypted = bytearray(len(key_array))
    for i in range(len(key_array)):
        num = key_array[i]
        num2 = byte_cipher[i]
        if bool_0:
            decrypted[i] = (num + num2) % 256
        else:
            num3 = num - num2
            decrypted[i] = (256 + num3) if num3 < 0 else num3
    return decrypted


def decrypt_variant_1(cipher, key):
    key_length = len(key)
    key_array = bytearray(key_length // 2)
    for i in range(0, key_length, 2):
        key_array[i // 2] = int(key[i:i+2], 16)
    byte_cipher = hash_sha256(cipher, len(key_array))
    decrypted_bytes = add_sub(key_array, byte_cipher, False)
    return decrypted_bytes.decode('utf-8', errors='ignore')


def decrypt_variant_2(cipher, key):
    try:
        b64_decoded_cipher = base64.b64decode(cipher)
        bytes = key.encode('utf-8')
        decrypted_cipher = bytearray(len(b64_decoded_cipher))
        for i in range(len(b64_decoded_cipher)):
            decrypted_cipher[i] = b64_decoded_cipher[i] ^ bytes[i % len(bytes)]
        return decrypted_cipher.decode('utf-8')
    except:
        pass


def decrypt_and_print(cipher, key, decrypt_function):
    result = []
    for i in range(min(len(cipher), len(key))):
        result.append(decrypt_function(cipher[i], key[i]))
    for i in result:
        if i.startswith('http') and 'TheSpeedX' not in i:
            print(f'[!] Payload URI: {i}')
            result.remove(i)
    for i in result:
        if i.startswith('Mozilla'):
            print(f'[!] Required User-Agent For Payload: {i}\n')
            result.remove(i)
    print('[+] Decrypted Strings:')
    for i in result:
        print(i)


def main():
    target_path = input('Enter file path to Artemis Loader:')
    
    if os.path.exists(target_path):
        file_data = ModuleDefMD.Load(target_path)
    else:
        sys.exit('File does not exist - terminating')
    
    enc_strings = extract_ciphers_keys(file_data)
    variant_2 = identify_variant_2(enc_strings[0]) # Variant 2 uses printable ascii characters

    if variant_2:
        print(f'[!] Detected Artemis Variant 2 \n')
        cipher, key = split_cipher_key_variant_2(enc_strings)
        decrypt_and_print(cipher, key, decrypt_variant_2)
    else:
        print(f'[!] Detected Artemis Variant 1 \n')
        cipher, key = split_cipher_key(enc_strings)
        decrypt_and_print(cipher, key, decrypt_variant_1)


if __name__ == '__main__':
    main()