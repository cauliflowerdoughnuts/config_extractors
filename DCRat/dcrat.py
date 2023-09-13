import os
import sys
import base64
import gzip
import json
import urllib.parse

TARGET_PATH = input('Enter file path to DCRat payload:')
if os.path.exists(TARGET_PATH):
    pass
else:
    sys.exit('File does not exist - terminating')

def find_dict_c2(file_path, b64_gzip_header):
    with open(file_path, 'rb') as file:
        file_contents = bytearray(file.read())
    
    pattern_length = len(b64_gzip_header)
    matched_values_list = []
    
    i = 0
    while i < len(file_contents):
        if all(file_contents[i + j] == b64_gzip_header[j] for j in range(pattern_length)):
            matched_values = bytearray(b64_gzip_header)
            i += pattern_length
            while i < len(file_contents):
                if file_contents[i] == 0x00 and file_contents[i + 1] == 0x00:
                    # Stop when '0000' is found
                    break
                else:
                    matched_values.append(file_contents[i])
                    i += 1
            
            matched_values_list.append(matched_values)
        else:
            i += 1
    
    cleaned_matched_values_list = [value.replace(b'\x00', b'') for value in matched_values_list]
    
    if len(cleaned_matched_values_list) >= 3:
        return cleaned_matched_values_list[1], cleaned_matched_values_list[2]
    else:
        return None, None


def parse_dictionary(dictionary):
    decoded_dict = base64.b64decode(gzip.decompress(base64.b64decode(dictionary))[::-1]).decode('UTF-8').replace('\\', '').replace('\"{', '{').replace('}\"', '}')

    json_decoded_dict = json.loads(decoded_dict)

    # Find the first dictionary - this is used for decoding
    final_dict = None
    for key, value in json_decoded_dict.items():
        if isinstance(value, dict):
            final_dict = value
            return final_dict


def parse_c2_config(c2_config):
    decoded_c2_config = gzip.decompress(base64.b64decode(c2_config))[::-1].decode('UTF-8')

    for i in final_dict:
        decoded_c2_config = decoded_c2_config.replace(final_dict[i],i)

    json_decoded_c2_config = json.loads(base64.b64decode(decoded_c2_config))

    c2_list = []
    c2_list.append(json_decoded_c2_config.get("H1"))
    c2_list.append(json_decoded_c2_config.get("H2"))
    return c2_list


b64_gzip_header = [0x48, 0x00, 0x34, 0x00, 0x73, 0x00, 0x49, 0x00, 0x41]

dictionary, c2_config = find_dict_c2(TARGET_PATH, b64_gzip_header)

if dictionary:
    final_dict = parse_dictionary(dictionary)
else:
    sys.exit('Could not locate the malware dictionary config')


if c2_config:
    c2_list = parse_c2_config(c2_config)
else:
    sys.exit('Could not locate the malware C2 config')


for c2 in c2_list:
    # Parse the URL to extract the encoded URL path then rebuild it once decoded
    parsed_url = urllib.parse.urlparse(c2)
    domain = parsed_url.netloc
    decoded_url_path = parsed_url.path.strip('/@')
    decoded_url_path = decoded_url_path.replace('@', '')
    decoded_url_path = decoded_url_path[::-1]
    decoded_url_path = base64.b64decode(decoded_url_path).decode('UTF-8')
    decoded_urls = f"{parsed_url.scheme}://{domain}/{decoded_url_path}.php"
    print(decoded_urls)
