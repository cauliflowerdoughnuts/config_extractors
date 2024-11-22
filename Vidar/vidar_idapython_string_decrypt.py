from idautils import *
from idaapi import *

def find_decrypt_func():

    # .text:00012CC3 E8 BA E6 FF FF                          call    mw_xor
    # .text:00012CC8 68 04 A9 01 00                          push    offset aGr2bgk4ycosr3t ; "GR2BGK4YCOSR3T"
    # .text:00012CCD 68 14 A9 01 00                          push    offset unk_1A914 ; key
    # .text:00012CD2 6A 0E                                   push    0Eh
    # .text:00012CD4 5B                                      pop     ebx             ; str_size
    # .text:00012CD5 A3 20 3E 22 00                          mov     dword_223E20, eax
    # .text:00012CDA E8 A3 E6 FF FF                          call    mw_xor
   
    sequence = ['push', 'push', 'push', 'pop', 'mov', 'call']
    
    # Dictionary to store the count of call targets
    call_target_counts = {}
    
    # Iterate through the disassembly
    for function_ea in Functions():
        func = ida_funcs.get_func(function_ea)
        if not func:
            continue
        
        # Iterate through the basic blocks
        for block in idaapi.FlowChart(func):
            mnemonics = []
            addresses = []
            ea = block.start_ea
            
            # Gather the mnemonics and addresses in the current basic block
            while ea < block.end_ea:
                insn = DecodeInstruction(ea)
                if not insn:
                    break
                
                disasm = GetDisasm(ea)
                mnemonic = disasm.split()[0] if disasm else None  # Fetch the mnemonic from the disassembly
                mnemonics.append(mnemonic)
                addresses.append(ea)  # Store the address
                
                ea = idaapi.next_head(ea, block.end_ea)  # Move to the next instruction
            
            # Check if the sequence exists in the current basic block
            i = 0
            while i <= len(mnemonics) - len(sequence):
                if all(mnemonics[i + j] == sequence[j] for j in range(len(sequence))):  # Compare mnemonic sequence
                    call_address = addresses[i + len(sequence) - 1]  # Get the address of the 'call' instruction
                    
                    # Get the call target address from the operand of the 'call' instruction
                    call_target = idc.get_operand_value(call_address, 0)
                    
                    # Update the count of the call_target
                    call_target_counts[call_target] = call_target_counts.get(call_target, 0) + 1
                    
                    i += len(sequence)
                else:
                    i += 1


    # Find the most common call_target address
    if call_target_counts:
        most_common_call_target = max(call_target_counts, key=call_target_counts.get)
        print(f"Most common call target address - likely decrypt function: 0x{most_common_call_target:08X} (Occurred {call_target_counts[most_common_call_target]} times)")
        return most_common_call_target
    else:
        print("No matching sequences found.")


def get_cipher_bytes(start_address, max_length=1000):
    result = []
    for _ in range(max_length):
        current_byte = idc.get_wide_byte(start_address)
        result.append(current_byte)
        start_address += 1
        if current_byte == 0 and len(result) > 1:
            break
    return result


def xor_decrypt(cipher, key):
    if len(key) == 0:
        return ""
    
    decrypted_text = bytearray(len(cipher))
    for i in range(len(cipher)):
        decrypted_text[i] = cipher[i] ^ key[i % len(key)]
    return bytes(decrypted_text).decode(errors='ignore')


def find_xrefs_and_decrypt(decrypt_func_address):
    for ref in XrefsTo(decrypt_func_address):
        # Get the address referencing the decrypt function
        caller_address = ref.frm

        # Extract arguments (cipher and key pointers)
        try:
            push_cipher_address = idaapi.get_arg_addrs(caller_address)[2]
            push_key_address = idaapi.get_arg_addrs(caller_address)[1]
        except:
            push_cipher_address = idaapi.get_arg_addrs(caller_address)[1]
            push_key_address = idaapi.get_arg_addrs(caller_address)[0]
        
        cipher_address = idc.get_operand_value(push_cipher_address, 0)
        key_address = idc.get_operand_value(push_key_address, 0)
        
        cipher = get_cipher_bytes(cipher_address) # for some reason idaapi.get_arg_addrs wont extract the cipher length argument so we cant use the built in get_bytes function
        cipher_len = len(cipher)
        key = get_bytes(key_address, cipher_len)
        
        decrypted_data = xor_decrypt(cipher, key)
        
        print(f"Decrypted data at address 0x{caller_address:X}: {decrypted_data}")

        idc.set_cmt(caller_address, decrypted_data, 0) # add the decrypted string as a comment to the XOR call
        idc.set_cmt(cipher_address, decrypted_data, 0) # add the decrypted string as a comment to the cipher location


decrypt_func_address = find_decrypt_func()

find_xrefs_and_decrypt(decrypt_func_address)