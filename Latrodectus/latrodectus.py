import os
import sys
import pefile
import re


def read_file(file_path):
    if os.path.exists(file_path):
        try:
            with open(file_path, 'rb') as file:
                return file.read()
        except Exception as e:
            print(f"Error reading file: {e}")
            sys.exit('Error reading file - terminating')
    else:
        print("File does not exist")
        sys.exit('File does not exist - terminating')


def decrypt(enc_data):
    xor_key = enc_data[0]
    enc_str_len = enc_data[4] ^ xor_key
    enc_string = enc_data[6:]

    dec_data_buffer = bytearray(enc_str_len)

    for i in range(enc_str_len):
        xor_key = (xor_key + 1) % 256
        dec_data_buffer[i] = xor_key ^ enc_string[i]

    try:
        if dec_data_buffer[1] == 0x00:
            return dec_data_buffer.decode('utf-16')
        else:
            return dec_data_buffer.decode('utf-8')
    except UnicodeDecodeError as e:
        print(f"Error decoding string: {e}")
        return ''


def extract_section_data(pe, section_name=".data"):
    for s in pe.sections:
        if section_name.encode() in s.Name:
            return s.get_data()
    print(f"Section {section_name} not found in PE file")
    return None


def main(file_path):
    print(f"Reading file: {file_path}")
    file_data = read_file(file_path)

    try:
        pe = pefile.PE(data=file_data)
    except pefile.PEFormatError as e:
        print(f"Error parsing PE file: {e}")
        sys.exit("Error parsing PE file - terminating")

    section_data = extract_section_data(pe)
    if not section_data:
        sys.exit("No data section found - terminating")

    delimiter = section_data[:4]
    split_pattern = re.compile(rb'(?=' + re.escape(delimiter) + rb')')
    encrypted_strings = split_pattern.split(section_data)[1:] # Using a positive lookahead so the first list element will be empty.

    strings = [decrypt(enc_str) for enc_str in encrypted_strings]
    rc4_key = next((strings[i + 1] for i in range(len(strings) - 1) if strings[i] == "ERROR\x00"), 'key not found')
    strings = list(set(filter(None, strings)))

    c2_uris = [i for i in strings if i.startswith('http')]
    strings = [i for i in strings if i not in c2_uris and i != rc4_key]

    print("[!] C2 URIs:")
    for uri in c2_uris:
        print(f'    -> {uri}')
    
    print(f"\n[+] C2 Comms RC4 Key: {rc4_key}")

    print("\n[+] Decrypted Strings:")
    for string in strings:
        print(f'    -> {string}')


if __name__ == "__main__":
    TARGET_PATH = input('Enter file path to Latrodectus payload:')
    main(TARGET_PATH)
