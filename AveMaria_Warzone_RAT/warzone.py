import os
import sys
import pefile
import struct
from malduck import rc4

TARGET_PATH = input('Enter file path to AveMaria payload:')

if os.path.exists(TARGET_PATH):
    file_data = open(TARGET_PATH,'rb').read()
else:
    sys.exit('File does not exist - terminating')

pe = pefile.PE(data=file_data)
section_data = None
for s in pe.sections:
    if s.Name == b'.bss\x00\x00\x00\x00':
        section_data = s.get_data()


def decrypt(key, cipher):
    key = bytes(key)
    cipher = bytes(cipher)
    result = rc4(key, cipher)
    return result.replace(b'\x00', b'')


def parse_config(c2_config):
    c2_ip_domain = ''
    c2_port = ''
    bot_id = ''
    bot_id_count = 0
    for i in range(1, len(c2_config)): # The first byte in the config is discarded
        byte = c2_config[i]
        if 32 <= byte <= 126:  # Check if the byte represents a printable character
            if not c2_port:  
                c2_ip_domain += chr(byte)
            else:  
                bot_id += chr(byte)
                bot_id_count += 1
                if bot_id_count == 10:
                    break
        else:
            if not c2_port:  #
                c2_port = struct.unpack('<H', c2_config[i:i+2])[0] # Convert port from network byte order hex (big endian)
                i += 1 # We captured two bytes at once so we need to adjust the counter
    return c2_ip_domain, c2_port, bot_id


key_size = struct.unpack('<I', section_data[:4])[0]
key = section_data[4: key_size + 4] # I am not sure why the + 4 is needed after the key_size - without it the extracted key is 4 bytes short even though the key_size is correct (50 bytes)
enc_c2_config = section_data[4 + key_size:]


c2_config = decrypt(key, enc_c2_config)
c2_ip_domain, c2_port, bot_id = parse_config(c2_config)


print(f'C2 Address: {c2_ip_domain}')
print(f'C2 Port: {c2_port}')
print(f'Bot ID: {bot_id}')
