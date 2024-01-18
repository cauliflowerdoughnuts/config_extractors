import os
import sys
import pefile
import base64
from malduck import rc4
import re

def read_file(file_path):
    if os.path.exists(file_path):
        with open(file_path, 'rb') as file:
            return file.read()
    else:
        sys.exit('File does not exist - terminating')

def is_ascii(s):
    return all(c < 128 or c == 0 for c in s)

def decrypt(cipher, key):
    global not_encrypted
    key = bytes(key)
    cipher = bytes(base64.b64decode(cipher))
    
    if is_ascii(cipher): # Some of the samples forgot to implement the RC4 encryption, so this is a check to see if the strings are only base64 encoded
        not_encrypted = True
        return cipher.decode(errors='ignore')
    else:
        return rc4(key, cipher).decode(errors='ignore')

def process_strings(section_rdata):
    REGEX_KEY = rb"[0-9]{10,}"
    REGEX_STRINGS_START = rb"[0-9]{10,}\x00{4}"
    
    key = next((item for item in re.findall(REGEX_KEY, section_rdata) if not item.startswith(b'0123456789')), None)

    for match in re.finditer(REGEX_STRINGS_START, section_rdata):
        strings_start = match.end()
        enc_strings = section_rdata[strings_start:strings_start + 10000]

    enc_strings_list = enc_strings.split(b'\x00\x00\x00\x00')

    dec_strings = []
    c2 = ""

    for i in enc_strings_list:
        try:
            dec_string = decrypt(i, key)
            if dec_string.startswith('http://') or dec_string.startswith('https://'):
                c2 += dec_string
            elif dec_string.endswith('.php'):
                c2 += dec_string
            else:
                dec_strings.append(dec_string)
        except Exception as e:
            continue

    return not_encrypted, key.decode(), dec_strings, c2

if __name__ == "__main__":
    TARGET_PATH = input('Enter file path to StealC payload:')
    file_data = read_file(TARGET_PATH)

    pe = pefile.PE(data=file_data)

    section_rdata = None
    for s in pe.sections:
        if ".rdata" in str(s.Name):
            section_rdata = s.get_data()

    not_encrypted = False
    not_encrypted, key, dec_strings, c2 = process_strings(section_rdata)

    if not_encrypted:
        print('[!] Strings were only base64 encoded...\n')
    print(f'[+] C2 Server: {c2}')
    print(f'[+] RC4 Key: {key}')
    print(f'[+] Decrypted Strings: {dec_strings}')
