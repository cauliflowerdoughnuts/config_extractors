import os
import sys
import re
import base64

TARGET_PATH = input('Enter file path to Darkgate payload:')

if os.path.exists(TARGET_PATH):
    file_data = open(TARGET_PATH,'rb').read()
else:
    sys.exit('File does not exist - terminating')


def decode_with_custom_alphabets(encoded_string, possible_alphabets):
    for alphabet in possible_alphabets:
        try:
            padding_needed = len(encoded_string) % 4
            if padding_needed:
                encoded_string += b'=' * (4 - padding_needed)
            custom_translation = bytes.maketrans(alphabet, b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/')
            decoded = base64.b64decode(encoded_string.translate(custom_translation)).decode(errors='ignore')
            return decoded, alphabet
        except Exception as e:
            pass

    print("Unable to decode with any custom alphabet.")
    return None, None


def clean_alphabet(alpha_list):
    return [item for item in alpha_list if not (item.startswith(b'ABCD') or item.startswith(b'PADDING'))]


def extract_config(content):
    start_pattern = b'\x00\x00\x30\x3D'
    start_index = content.find(start_pattern)

    if start_index != -1:
        end_pattern = b'\x0D\x0A\x00\x00'
        end_index = content.find(end_pattern, start_index)

        if end_index != -1:
            extracted_data = content[start_index + 2:end_index]
            return extracted_data
        else:
            return None
    else:
        return None


def apply_config_labels(output):
    decoded_output = output.decode('utf-8')
    pairs = (pair.split('=') for pair in decoded_output.split('\r\n') if pair)
    labeled_output = {label_names.get(key, key): value for key, value in pairs}
    return labeled_output


label_names = {
    '0': 'C2 Port',
    '1': 'Startup Folder Persistence',
    '2': 'Rootkit',
    '3': 'VM Display Information Check',
    '4': 'Minimum Required Disk Space',
    '5': 'Check Disk Space',
    '6': 'VM Environment Check',
    '7': 'Minimum Required RAM',
    '8': 'Check RAM Size',
    '9': 'Xeon CPU Check',
    '10': 'Mutex Seed',
    '11': 'Unpacked Payload',
    '12': 'DLL Packed',
    '13': 'AutoIT Packed',
    '14': 'Unknown',
    '15': 'DLL Decryption Key',
    '16': 'C2 Delay Time',
    '17': 'BeingDebugged Check',
    '18': 'Unknown2',
    '19': '%LOCALAPPDATA% Persistence',
    '20': 'Contains Encoded Binary',
    '21': 'String',
    '22': 'Cryptomining Port',
    '23': 'Username',
    '24': 'Send Installation Path to C2',
    '25': 'Minutes to Listen',
    '26': 'Unknown3',
    '27': 'Hash System Info',
    '28': 'Kaspersky Bypass',
    '29': 'Unknown4',
}


REGEX_B64_ALPHABET_CANDIDATES = rb"[A-Za-z0-9+/=]{64}"
REGEX_B64_STRINGS = rb"[A-Za-z0-9+/=]{5,}"
custom_alphabet_candidates = re.findall(REGEX_B64_ALPHABET_CANDIDATES, file_data)
custom_alphabets_cleaned = clean_alphabet(custom_alphabet_candidates)
string_candidates = re.findall(REGEX_B64_STRINGS, file_data)

extracted_config_banner = """
######################
#  Extracted Config  #
######################
"""

for string in string_candidates:
    decoded_result, used_alphabet = decode_with_custom_alphabets(string, custom_alphabets_cleaned)
    if decoded_result is not None:
        if decoded_result.startswith("http"):
            custom_alphabet = used_alphabet.decode()
            c2 = [x for x in decoded_result.split("|") if x.strip() != ""]
            for host in c2: 
                if len(host) > 1:
                    extracted_c2 = host


extracted_config = extract_config(file_data)

if extracted_config is not None:
    print(f"{extracted_config_banner}")
    print(f'C2 Server: {extracted_c2}')
    print(f'Custom Alphabet: {custom_alphabet}')
    labeled_output = apply_config_labels(extracted_config)
    for key, value in labeled_output.items():
        print(f"{key}: {value}")
elif extracted_c2 is not None:
    print(f"{extracted_config_banner}")
    print(f'C2 Server: {extracted_c2}')
    print(f'Custom Alphabet: {custom_alphabet}')
    print(f'Additional config parameters not found...')
else:
    print("Config not found.")
