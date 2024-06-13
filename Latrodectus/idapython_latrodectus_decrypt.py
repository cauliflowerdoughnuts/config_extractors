import idautils
import idc


def decrypt_strings(encrypted_data, op_value):
    xor_key = encrypted_data[0]
    enc_str_len = encrypted_data[4] ^ xor_key
    enc_string = idc.get_bytes(op_value + 6, enc_str_len)

    dec_data_buffer = bytearray(enc_str_len)

    for i in range(enc_str_len):
        xor_key = (xor_key + 1) % 256
        dec_data_buffer[i] = xor_key ^ enc_string[i]

    # Cannot rely on UnicodeDecodeError, some UTF-8 strings will decode as UTF-16 and print garbage - instead perform a check to see if the second byte is '\x00' to determine UTF-16
    if dec_data_buffer[1] == 0x00:
        return dec_data_buffer.decode('utf-16')
    else:
        return dec_data_buffer.decode('utf-8')


def find_xrefs_and_decrypt(decrypt_func_address):
    for ref in XrefsTo(decrypt_func_address):
        caller_address = ref.frm
        prev_ea = idc.prev_head(caller_address)

        # The argument before the decrypt function call should be the address of the encrypted data
        if idc.print_insn_mnem(prev_ea) == 'lea':
            cipher_address = idc.get_operand_value(prev_ea, 1)

            # Get start of the encrypted data that contains the cipher length.
            encrypted_data = idc.get_bytes(cipher_address, data_size)

            decrypted_data = decrypt_strings(encrypted_data, cipher_address)
            print(f'0x{cipher_address:X} -> {decrypted_data}')

        idc.set_cmt(caller_address, decrypted_data, 0) # add the decrypted string as a comment to the decrypt call
        idc.set_cmt(cipher_address, decrypted_data, 0) # add the decrypted string as a comment to the cipher location


decrypt_func_address = 0x7FF93824AE78
find_xrefs_and_decrypt(decrypt_func_address)