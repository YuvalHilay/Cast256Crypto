# Importing the CAST256 implementation
from CAST256.cast256 import cast256  # Ensure you have CAST256 implementation in this path
from CAST256.algorithm import *  # Ensure CAST256 algorithm methods are available

"""
parameter : ptext - string, key - hex, iv - hex 64bit
return ctext - hex
"""
def cbc_encrypt(ptext, key, iv):
    blocks = split_plaintext_to_hex_blocks(ptext)
    roundCbc = len(blocks)
    previous = iv
    ctext = ""
    for i in range(roundCbc):
        binary_value1 = bin(int(blocks[i], 16))[2:]
        binary_value2 = bin(int(previous, 16))[2:]
        max_length = max(len(binary_value1), len(binary_value2))
        binary_value1 = binary_value1.zfill(max_length)
        binary_value2 = binary_value2.zfill(max_length)
        xor = hex(int(binary_value1, 2) ^ int(binary_value2, 2))[2:]
        previous = cast256(xor, key, True)  # Updated to cast256
        ctext += previous
    return ctext

"""
parameter : ctext - hex, key - hex, iv - hex 64bit
return ptext - string
"""
def cbc_decrypt(ctext, key, iv):
    blocks = []
    roundCbc = len(ctext) // 32  # 256 bits = 32 hex characters
    for i in range(roundCbc):
        blocks.append(ctext[32*i:(i+1)*32])  # 256-bit blocks

    previous = iv
    ptext = ""
    for i in range(roundCbc):
        decryptBlock = cast256(blocks[i], key, False)  # Updated to cast256
        binary_value1 = bin(int(previous, 16))[2:]
        binary_value2 = bin(int(decryptBlock, 16))[2:]
        max_length = max(len(binary_value1), len(binary_value2))
        binary_value1 = binary_value1.zfill(max_length)
        binary_value2 = binary_value2.zfill(max_length)
        xor = hex(int(binary_value1, 2) ^ int(binary_value2, 2))[2:]
        ptext += xor
        previous = blocks[i]

    bytes_data = bytes.fromhex(ptext)
    return bytes_data.decode('utf-8')
