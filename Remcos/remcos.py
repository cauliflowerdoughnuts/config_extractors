import os
import sys
import pefile
from malduck import rc4

TARGET_PATH = input('Enter file path to Remcos payload:')

if os.path.exists(TARGET_PATH):
    file_data = open(TARGET_PATH,'rb').read()
else:
    sys.exit('File does not exist - terminating')

payload = pefile.PE(data=file_data)


def decrypt(cipher, key):
    key = bytes(key)
    cipher = bytes(cipher)
    result = rc4(key, cipher)
    return result.decode(errors='ignore').replace('\x00', '')


def extract_config(payload, resource_type_to_find):
    if hasattr(payload, 'DIRECTORY_ENTRY_RESOURCE'):
        for resource_type in payload.DIRECTORY_ENTRY_RESOURCE.entries:
            if resource_type.id == resource_type_to_find:
                for resource_id in resource_type.directory.entries:
                    for resource_lang in resource_id.directory.entries:
                        offset = resource_lang.data.struct.OffsetToData
                        size = resource_lang.data.struct.Size
                        resource_data = payload.get_memory_mapped_image()[offset:offset + size]
                        return resource_data


resource_type_to_extract = pefile.RESOURCE_TYPE['RT_RCDATA']

try:
    enc_data = extract_config(payload, resource_type_to_extract)
    if enc_data:
        key_len = enc_data[0]
        key = enc_data[1:1 + key_len]
        enc_config = enc_data[1 + key_len: ]
        config = decrypt(enc_config, key)
        c2_server, rest_of_config = config.split('|', 1)
        print(f'[+] C2 Server: {c2_server[:-3]}\n')
        print(f'[+] Configuration Parameters: \n{rest_of_config}')

    else:
        print("Resource not found.")
except Exception as e:
    print(f"An error occurred: {e}")
