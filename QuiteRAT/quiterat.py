import pefile
import re
import base64
import os
import sys

TARGET_PATH = input('Enter file path to QuiteRAT payload:')
if os.path.exists(TARGET_PATH):
    pe = pefile.PE(TARGET_PATH)
else:
    sys.exit('File does not exist - terminating')

# base64 strings with \x00\x00\x00\x00 as the config delimeter
REGEX_B64_STRINGS = rb'([a-zA-Z0-9=+]{6,})\x00{4}' 

for s in pe.sections:
    if s.Name.startswith(b'.rdata'):
        rdata_data = s.get_data()

# Find the encrypted strings in the .rdata section
enc_strings = []
string_candidates = re.findall(REGEX_B64_STRINGS, rdata_data)
for i, s in enumerate(string_candidates):
    if 2 < i < 15:  # Throw out the first 2 matches, and capture matches 3 to 15
        enc_strings.append(s)
    elif i >= 15:
        break

enc_strings = list(set(enc_strings))

def decrypt(data, key):
    data_enc = base64.b64decode(data)
    out = []
    for c in data_enc:
        out.append(c ^ key)
    return bytes(out)

target_substring = 'http'
correct_key = None

# Brute force the XOR key using http as the expected plaintext value
def brute_force_xor(ciphertext, target_substring):
    for key in range(256):
        decrypted = decrypt(ciphertext, key)
        decrypted_str = decrypted.decode(errors='ignore')
        if target_substring in decrypted_str:
            return key
    return None

for ciphertext in enc_strings:
    key = brute_force_xor(ciphertext, target_substring)
    if key is not None:
        correct_key = key
        break

# If the brute force is successful then use the key to decrypt all of the strings
if correct_key is not None:
    decrypted_strings = []
    for ciphertext in enc_strings:
        decrypted = decrypt(ciphertext, correct_key)
        decrypted_strings.append(decrypted.decode(errors='ignore'))
        
    for plaintext in decrypted_strings:
        print(plaintext)
else:
    print("Key not found.")
