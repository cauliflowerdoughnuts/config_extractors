import os
import sys
import pefile


def read_file(file_path):
    if not os.path.exists(file_path):
        sys.exit('File does not exist - terminating')

    try:
        with open(file_path, 'rb') as file:
            return file.read()
    except Exception as e:
        sys.exit(f'Error reading file - terminating: {e}')


def extract_section_data(pe, section_name='.data'):
    for section in pe.sections:
        if section_name.encode() in section.Name:
            return section.get_data()
    sys.exit(f'Section {section_name} not found in PE file - terminating')


# Payload size format is 0x00 ?? ?? 0x00. Find the first occurrence of this pattern.
def find_payload_size(data):
    pattern_length = 4
    for i in range(len(data) - pattern_length + 1):
        if data[i] == 0x00 and data[i + 1] != 0x00 and data[i + 2] != 0x00 and data[i + 3] == 0x00:
            return i
    sys.exit(f'Failed to find payload size - terminating')


# XOR key is after the payload length (4 bytes). Use index function to find the position of the first null byte after the key.
def extract_xor_key(key_index, data):
    return data[key_index:data.index(0, key_index)]


'''
Loader uses two XOR keys. The 2nd key is a delimiter in the encrypted data located at each len(key) + 1 position. 
This key gets appended throughout the first decrypt loop, without XORing, and is then used as a single key to decrypt the data.
'''
def xor_decrypt(data, key):
    key_length = len(key)
    decrypted_data_1 = bytearray()
    
    # Decrypt with first rolling key
    for i in range(0, len(data), key_length + 1):
        chunk = data[i:i+key_length]
        decrypted_chunk = bytearray(chunk[j] ^ key[j] for j in range(len(chunk)))
        decrypted_data_1.extend(decrypted_chunk)
        if i + key_length < len(data):
            decrypted_data_1.append(data[i + key_length])
    
    decrypted_data_2 = bytearray()
    second_key = decrypted_data_1[3:4]
    
    # Decrypt with second single byte key
    for i in range(len(decrypted_data_1)):
        decrypted_data_2.append(decrypted_data_1[i] ^ second_key[i%len(second_key)])

    return decrypted_data_2


def parse_loader(section_data):
    payload_size_index = find_payload_size(section_data)
    payload_len = int.from_bytes(section_data[payload_size_index:payload_size_index + 4], byteorder='little')
    key_index = payload_size_index + 4
    key = extract_xor_key(key_index, section_data)
    payload_start = payload_size_index + 4 + len(key) + 1
    payload = section_data[payload_start:payload_start + payload_len + 1]
    
    return xor_decrypt(payload, key)


# Strings in the payload are not encrypted.
def extract_ascii_strings(byte_array, min_length=4):
    printable_ascii = set(range(0x20, 0x7F))
    ascii_strings, current_string = [], []

    for byte in byte_array:
        if byte in printable_ascii:
            current_string.append(chr(byte))
        else:
            if len(current_string) >= min_length:
                ascii_strings.append(''.join(current_string))
            current_string = []
    
    # Check the last string
    if len(current_string) >= min_length:
        ascii_strings.append(''.join(current_string))

    return ascii_strings


'''
POST is 4th or 5th string after exfil XOR key. The XOR key is 36 bytes.
Check if i-5 is 36 bytes, if not then the key is at i-4.
'''
def find_c2(ascii_strings):
    for i, string in enumerate(ascii_strings):
        if string == 'POST':
            start_index = max(0, i - 5)
            break
    else:
        return []

    if len(ascii_strings[start_index]) == 36:
        return ascii_strings[start_index:i]
    return ascii_strings[start_index+1:i]


def find_imports(ascii_strings):
    for i, string in enumerate(ascii_strings):
        if string == 'ReadFile':
            start_index = i
        if string == 'WriteConsoleW':
            return ascii_strings[start_index:i + 1]
    return []


def parse_config(ascii_strings):
    c2 = find_c2(ascii_strings)
    imports = find_imports(ascii_strings)

    # Remove the mutex xor key if it exists
    if len(c2) == 5:
        c2.pop(1)

    if c2:
        print(f'[!] C2 Config Found:')
        print(f'    [+] URI: {c2[1] + c2[2]}')
        print(f'    [+] User Agent: {c2[3]}')
        print(f'    [+] Exfil XOR Key: {c2[0]}')
    else:
        print(f'C2 not found')
    
    if imports:
        print(f'\n[!] Imports Found:')
        print(f'    [+] {imports}')
    else:
        print('\n[!] Imports not found')


def main(file_path):
    print(f'Reading file: {file_path}\n')
    file_data = read_file(file_path)

    try:
        pe = pefile.PE(data=file_data)
    except pefile.PEFormatError as e:
        sys.exit(f'Error parsing PE file - terminating: {e}')

    section_data = extract_section_data(pe)
    decrypted_payload = parse_loader(section_data)
    ascii_strings = extract_ascii_strings(decrypted_payload)
    parse_config(ascii_strings)


if __name__ == '__main__':
    TARGET_PATH = input('Enter file path to StrelaStealer loader:')
    main(TARGET_PATH)
