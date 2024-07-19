from CAST256.algorithm import algorithm  # Update import for CAST256
from CAST256.keyGenerator import getKeySize, checkKeyFormat  # Update import for CAST256

"""function that encrypts/decrypts 128-bit hex text 
if encORdec is True, it means encrypt, else decrypt"""
def cast256(txt, key, encORdec):
    h_size = getKeySize(key)
    isKeyValid = checkKeyFormat(key)
    
    # Key size checks for CAST256 (256-bit key)
    if h_size < 128:
        print("Key size must be greater than 128 bits!")
        exit(1)
    elif h_size % 8 != 0:
        print("Key size must be in 8-bit increments!")
        exit(1)
    elif h_size > 256:
        print("Key size must be less than 256 bits!")
        exit(1)
    elif not isKeyValid:
        print("Key must be in hexadecimal format!")
        exit(1)
    else:
        txtAfter = algorithm(txt, key, encORdec)
    
    return txtAfter
