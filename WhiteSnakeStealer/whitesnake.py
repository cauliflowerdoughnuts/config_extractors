import os
import sys
import clr
clr.AddReference('System.Memory')
DNLIB_PATH = '/<path to>/dnlib.dll'
clr.AddReference(DNLIB_PATH)
from dnlib.DotNet import *

LABELS = ['Log File', 'Loader URL', 'Tag', 'Mutex', 'RSA Public Key', 'Telegram Token', 'Telegram Chat ID', 'Version', 'C2', 'Install Directory', 'Data Directory', 'Transfer Hosts']


def extract_cipher_strings(file_data):
    cipher = []
    xor = True

    for mtype in file_data.GetTypes():
        if not mtype.HasMethods:
            continue
        for method in mtype.Methods:
            if not method.IsConstructor or not method.HasBody or not method.Body.HasInstructions:
                continue
            for ptr, instruction in enumerate(method.Body.Instructions):
                instruction_str = instruction.ToString()

                if 'ldstr "tor"' in instruction_str and 'ldstr ""' in method.Body.Instructions[ptr + 8].ToString(): # ptr+8 is the C2 config line. If it is configured it will get picked up by one of the if blocks below, otherwise it will be picked up here.
                    cipher.insert(8, 'Not configured')

                if 'ldstr "<RSAKeyValue>' in instruction_str:
                    xor = False
                    operands_to_check = [method.Body.Instructions[ptr - 6].Operand,
                                         method.Body.Instructions[ptr - 4].Operand,
                                         method.Body.Instructions[ptr - 2].Operand,
                                         method.Body.Instructions[ptr].Operand,
                                         method.Body.Instructions[ptr + 2].Operand,
                                         method.Body.Instructions[ptr + 4].Operand,
                                         method.Body.Instructions[ptr + 14].Operand,
                                         method.Body.Instructions[ptr + 24].Operand,
                                         method.Body.Instructions[ptr + 28].Operand,
                                         method.Body.Instructions[ptr + 33].Operand,
                                         method.Body.Instructions[ptr + 36].Operand]

                    cipher.extend(['Not configured' if not operand else operand for operand in operands_to_check])

                if 'ldstr' in instruction_str and 'call' in method.Body.Instructions[ptr + 1].ToString(): # This will always match on the first config string even if not encrypted. Because of this we will not extract the first string in the if 'ldstr "<RSAKeyValue>' block above.
                    operand = instruction.Operand
                    cipher.append("Not configured" if not operand else operand) 

    return cipher, xor


def xor_decrypt(enc_str):
    dec_strings = []
    text = "decr:"

    for i in range(32, 127):
        key = chr(i) + "sus"
        array = [chr(ord(enc_str[j]) ^ ord(key[j % len(key)])) for j in range(len(enc_str))]
        dec_string = ''.join(array)

        if dec_string.startswith(text):
            return dec_string[len(text):]

    return ''


def main():
    target_path = input('Enter file path to WhiteSnake payload:')
    file_data = ModuleDefMD.Load(target_path)
    cipher, xor = extract_cipher_strings(file_data)

    if xor:
        decrypted_strings = [xor_decrypt(c) if c != "Not configured" else c for c in cipher]
        for label, string in zip(LABELS, decrypted_strings):
            defanged_string = ''.join(string).replace("http", "hxxp")
            print(f"{label}: {defanged_string}")
    else:
        print(f'[!] The config was not encrypted.\n')
        for label, string in zip(LABELS, cipher):
            defanged_string = ''.join(string).replace("http", "hxxp")
            print(f"{label}: {defanged_string}")


if __name__ == "__main__":
    main()