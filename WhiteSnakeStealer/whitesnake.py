import os
import sys
import clr
clr.AddReference('System.Memory')
DNLIB_PATH = '/<path to>/dnlib.dll'
clr.AddReference(DNLIB_PATH)
from dnlib.DotNet import *

LABELS = ['Log File', 'Loader URLs', 'Tag', 'Mutex', 'RSA Public Key', 'Telegram Token', 'Telegram Chat ID', 'Anti VM', 'Install Beacon', 'Auto Keylogger', 'Clipper Enabled',  'Version', 'Resident Method', 'Fake Message Box Icon', 'Fake Message Box Title', 'Fake Message Box Text',  'C2', 'Install Directory', 'Data Directory', 'Transfer Hosts']


def extract_cipher_strings(file_data):
    cipher = []
    config_found = False

    for mtype in file_data.GetTypes():
        if not mtype.HasMethods:
            continue
        for method in mtype.Methods:
            if not method.IsConstructor or not method.HasBody or not method.Body.HasInstructions:
                continue
            for ptr, instruction in enumerate(method.Body.Instructions):
                instruction_str = instruction.ToString()
                
                if 'System.IO.Path::GetTempPath' in instruction_str and 'ldstr' in method.Body.Instructions[ptr + 1].ToString(): # Start of config strings
                    config_found = True
                    continue
                
                if config_found and 'ldstr' in instruction_str:
                    if instruction.Operand is None:
                        cipher.append('Not Configured')
                    else:
                        cipher.append(instruction.Operand)
                
                if len(cipher) == 20:
                    break
            if len(cipher) == 20:
                break
        if len(cipher) == 20:
            break

    return cipher


def check_encryption(config):
    if '<RSAKeyValue>' in config[4]:
        return False
    else:
        return True


def xor_decrypt(enc_str):
    dec_strings = []
    text = 'decr:'

    for i in range(32, 127):
        key = chr(i) + 'sus'
        array = [chr(ord(enc_str[j]) ^ ord(key[j % len(key)])) for j in range(len(enc_str))]
        dec_string = ''.join(array)

        if dec_string.startswith(text):
            return dec_string[len(text):]

    return ''


def main():
    target_path = input('Enter file path to WhiteSnake payload:')
    file_data = ModuleDefMD.Load(target_path)
    cipher = extract_cipher_strings(file_data)
    encrypted = check_encryption(cipher)

    if encrypted:
        decrypted_strings = [xor_decrypt(c) if c not in ['0', '1', 'tor'] else c for c in cipher]
        print(f'[!] The config has been decrypted:\n')
        for label, string in zip(LABELS, decrypted_strings):
            defanged_string = ''.join(string).replace('http', 'hxxp') if string else 'Not Configured'
            print(f'{label}: {defanged_string}')
    else:
        print(f'[!] The config was not encrypted:\n')
        for label, string in zip(LABELS, cipher):
            defanged_string = ''.join(string).replace('http', 'hxxp') if string else 'Not Configured'
            print(f'{label}: {defanged_string}')


if __name__ == '__main__':
    main()
