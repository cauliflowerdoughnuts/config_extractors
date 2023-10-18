import os
import sys
import pefile
import struct
from malduck import rc4

TARGET_PATH = input('Enter file path to AveMaria/WarZone payload:')

if os.path.exists(TARGET_PATH):
    file_data = open(TARGET_PATH,'rb').read()
else:
    sys.exit('File does not exist - terminating')

pe = pefile.PE(data=file_data)
for s in pe.sections:
    if s.Name.startswith(b'.bss'):
        section_data = s.get_data()


def decrypt(key, cipher):
    key = bytes(key)
    cipher = bytes(cipher)
    result = rc4(key, cipher)
    return result.replace(b'\x00', b'')


def parse_config(c2_config):
    c2_config_len = c2_config[0]
    c2_config = c2_config[1:c2_config_len + 1]
    bot_id = str(c2_config[c2_config_len - 10: c2_config_len], encoding="ASCII")
    c2_port_start = c2_config.find(b'\x88\x13') - 2 # These bytes have shown up as a common delimiter between the C2 and the bot ID
    c2_port = struct.unpack('<H', c2_config[c2_port_start:c2_port_start + 2])[0]
    c2_address = str(c2_config[:c2_port_start], encoding="ASCII")
    return c2_address, c2_port, bot_id


key_size = struct.unpack('<I', section_data[:4])[0]
key = section_data[4: 4 + key_size]
enc_c2_config = section_data[4 + key_size:]


c2_config = decrypt(key, enc_c2_config)
c2_address, c2_port, bot_id = parse_config(c2_config)


print(f'C2 Address: {c2_address}')
print(f'C2 Port: {c2_port}')
print(f'Bot ID: {bot_id}')
