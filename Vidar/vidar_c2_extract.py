import os
import sys
import re
import pefile
import requests

TARGET_PATH = input('Enter file path to Vidar payload:')

if os.path.exists(TARGET_PATH):
    file_data = open(TARGET_PATH,'rb').read()
else:
    sys.exit('File does not exist - terminating')

pe = pefile.PE(data=file_data)

for s in pe.sections:
    if ".rdata" in str(s.Name):
        section_rdata = s.get_data()

C2_PATTERN = r'https?://\S+|www\.\S+'

def extract_urls(rdata):
    urls = re.findall(C2_PATTERN, rdata.decode('utf-8', 'ignore'))

    if b'\x00' in rdata:
        null_index = rdata.index(b'\x00')
        urls = [url.split('\x00')[0] for url in urls]
    
    return urls


def extract_ips_from_text(text):
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?\b'  # IPv4 with optional port
    url_pattern = r'https?://(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]{2,5})?'  # HTTP/HTTPS URLs with IPv4 and optional port

    combined_pattern = f'({ip_pattern})|({url_pattern})'

    ip_addresses = re.findall(combined_pattern, text)
    
    # Extract IPs from the tuple structure returned by re.findall()
    return list(set([ip[0] if ip[0] else ip[1] for ip in ip_addresses if any(ip)]))


int_c2 = extract_urls(section_rdata)


for url in int_c2:
    try:
        response = requests.get(url)
        
        if response.status_code == 200:
            print(f"Successful GET request to intermediate C2: {url}")
            response_text = response.text
            c2 = extract_ips_from_text(response_text)
            
            if c2:
                print("C2s found in the response content:")
                print(f'{c2}\n')
            else:
                print("No C2s found in the response content.")

        else:
            print(f"Failed GET request to intermediate C2: {url} - Status code: {response.status_code}")
    except requests.RequestException as e:
        print(f"Error making GET request to {url}: {e}")
