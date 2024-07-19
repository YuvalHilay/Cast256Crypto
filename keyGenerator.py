from bitarray import bitarray
from CAST256.sboxes import calculatingSboxOutput  # Update import for CAST256

"""This code is for key generation according to CAST256 keys generation."""

def keyGenerator(keyBinary):
    keysArray = [None] * 32  # 32 keys for CAST256
    zArray = [None] * 8     # 8 z values for CAST256
    xArray = [None] * 9     # 9 x values for CAST256
    Km = [None] * 16
    Kr = [None] * 16
    xArray[0] = keyBinary

    for i in range(8):
        z = calculateZ(keyBinary)
        z1 = divideKeyTo16Parts(z)
        zArray[i] = z
        if i % 2 == 0:
            calculateKeys1(keysArray, z1, i)
        else:
            calculateKeys3(keysArray, z1, i)
        keyBinary = calculateBinaryKey(z, z1, keyBinary)
        xArray[i + 1] = keyBinary
        x = divideKeyTo16Parts(keyBinary)
        if i % 2 == 0:
            calculateKeys2(keysArray, x, i)
        else:
            calculateKeys4(keysArray, x, i)

    Km, Kr = generateMaskingAndRotationKeys(keysArray)

    return Km, Kr, keysArray, zArray, xArray


def addKeyToxArray(xArray, key, i):
    xArray[i] = key


def keyHexToBinaryAndNumberOfRounds(keyHex):
    h_size = len(keyHex) * 4

    # For key sizes less than 256 bits, pad the key with zero bytes
    if h_size < 256:
        int_value = (int(keyHex, 16)) << (256 - h_size)
    else:
        int_value = (int(keyHex, 16))
    binaryKeyString = (bin(int_value)[2:]).zfill(256)
    binaryKey = bitarray(binaryKeyString)
    if 192 < h_size <= 256:
        numberOfRounds = 24
    else:
        numberOfRounds = 12
    return binaryKey, numberOfRounds


def getKeySize(keyHex):
    h_size = len(keyHex) * 4
    return h_size


def checkKeyFormat(keyHex):
    try:
        int(keyHex, 16)
        return True
    except ValueError:
        return False


def divideKeyTo16Parts(keyBinary):
    x = []
    for i in range(16):
        x.append(keyBinary[i * 16:(i + 1) * 16])  # Updated to 16 bits each for CAST256
    return x


def divideKeyTo8Parts(keyBinary):
    x = []
    for i in range(8):
        x.append(keyBinary[i * 8:(i + 1) * 8])  # Updated to 8 bits each for CAST256
    return x


def divideKeyTo4Parts(keyBinary):
    x = []
    for i in range(4):
        x.append(keyBinary[i * 16:(i + 1) * 16])  # Updated to 16 bits each for CAST256
    return x


def calculateZ(keyBinary):
    z = bitarray(256)  # Updated to 256 bits
    z[:] = 0
    x = divideKeyTo16Parts(keyBinary)
    # Update the calculation to use 256-bit values
    z[0:64] = keyBinary[0:64] ^ calculatingSboxOutput(5, x[13]) ^ calculatingSboxOutput(6, x[15]) \
              ^ calculatingSboxOutput(7, x[12]) ^ calculatingSboxOutput(8, x[14]) ^ calculatingSboxOutput(7, x[8])

    z1 = divideKeyTo16Parts(z)
    z[64:128] = keyBinary[64:128] ^ calculatingSboxOutput(5, z1[0]) ^ calculatingSboxOutput(6, z1[2]) \
                ^ calculatingSboxOutput(7, z1[1]) ^ calculatingSboxOutput(8, z1[3]) ^ calculatingSboxOutput(8, x[10])

    z1 = divideKeyTo16Parts(z)
    z[128:192] = keyBinary[128:192] ^ calculatingSboxOutput(5, z1[7]) ^ calculatingSboxOutput(6, z1[6]) \
                 ^ calculatingSboxOutput(7, z1[5]) ^ calculatingSboxOutput(8, z1[4]) ^ calculatingSboxOutput(5, x[9])

    z1 = divideKeyTo16Parts(z)
    z[192:256] = keyBinary[192:256] ^ calculatingSboxOutput(5, z1[10]) ^ calculatingSboxOutput(6, z1[9]) \
                 ^ calculatingSboxOutput(7, z1[11]) ^ calculatingSboxOutput(8, z1[8]) ^ calculatingSboxOutput(6, x[11])
    return z


def calculateBinaryKey(z, z1, keyBinary):
    binaryKey1 = bitarray(256)  # Updated to 256 bits
    binaryKey1[:] = keyBinary
    # Update the calculation to use 256-bit values
    binaryKey1[0:64] = z[128:192] ^ calculatingSboxOutput(5, z1[5]) ^ calculatingSboxOutput(6, z1[7]) \
                      ^ calculatingSboxOutput(7, z1[4]) ^ calculatingSboxOutput(8, z1[6]) ^ calculatingSboxOutput(7, z1[0])

    x = divideKeyTo16Parts(binaryKey1)

    binaryKey1[64:128] = z[0:64] ^ calculatingSboxOutput(5, x[0]) ^ calculatingSboxOutput(6, x[2]) \
                       ^ calculatingSboxOutput(7, x[1]) ^ calculatingSboxOutput(8, x[3]) ^ calculatingSboxOutput(8, z1[2])

    x = divideKeyTo16Parts(binaryKey1)

    binaryKey1[128:192] = z[64:128] ^ calculatingSboxOutput(5, x[7]) ^ calculatingSboxOutput(6, x[6]) \
                       ^ calculatingSboxOutput(7, x[5]) ^ calculatingSboxOutput(8, x[4]) ^ calculatingSboxOutput(5, z1[1])

    x = divideKeyTo16Parts(binaryKey1)

    binaryKey1[192:256] = z[192:256] ^ calculatingSboxOutput(5, x[10]) ^ calculatingSboxOutput(6, x[9]) \
                        ^ calculatingSboxOutput(7, x[11]) ^ calculatingSboxOutput(8, x[8]) ^ calculatingSboxOutput(6, z1[3])
    return binaryKey1

def calculateKeys1(keysArray, z1, i):
    # Updated for CAST256
    keysArray[i * 8 + 0] = calculatingSboxOutput(5, z1[8]) ^ calculatingSboxOutput(6, z1[9]) \
                           ^ calculatingSboxOutput(7, z1[7]) ^ calculatingSboxOutput(8, z1[6]) ^ calculatingSboxOutput(5, z1[2])

    keysArray[i * 8 + 1] = calculatingSboxOutput(5, z1[10]) ^ calculatingSboxOutput(6, z1[11]) \
                           ^ calculatingSboxOutput(7, z1[5]) ^ calculatingSboxOutput(8, z1[4]) ^ calculatingSboxOutput(6, z1[6])

    keysArray[i * 8 + 2] = calculatingSboxOutput(5, z1[12]) ^ calculatingSboxOutput(6, z1[13]) \
                           ^ calculatingSboxOutput(7, z1[3]) ^ calculatingSboxOutput(8, z1[2]) ^ calculatingSboxOutput(7, z1[9])

    keysArray[i * 8 + 3] = calculatingSboxOutput(5, z1[14]) ^ calculatingSboxOutput(6, z1[15]) \
                           ^ calculatingSboxOutput(7, z1[1]) ^ calculatingSboxOutput(8, z1[0]) ^ calculatingSboxOutput(8, z1[12])


def calculateKeys2(keysArray, x, i):
    keysArray[i * 8 + 4] = calculatingSboxOutput(5, x[0]) ^ calculatingSboxOutput(6, x[1]) \
                           ^ calculatingSboxOutput(7, x[7]) ^ calculatingSboxOutput(8, x[5]) ^ calculatingSboxOutput(7, x[4])

    keysArray[i * 8 + 5] = calculatingSboxOutput(5, x[2]) ^ calculatingSboxOutput(6, x[3]) \
                           ^ calculatingSboxOutput(7, x[6]) ^ calculatingSboxOutput(8, x[5]) ^ calculatingSboxOutput(8, x[7])

    keysArray[i * 8 + 6] = calculatingSboxOutput(5, x[4]) ^ calculatingSboxOutput(6, x[5]) \
                           ^ calculatingSboxOutput(7, x[1]) ^ calculatingSboxOutput(8, x[0]) ^ calculatingSboxOutput(6, x[3])

    keysArray[i * 8 + 7] = calculatingSboxOutput(5, x[6]) ^ calculatingSboxOutput(6, x[7]) \
                           ^ calculatingSboxOutput(7, x[2]) ^ calculatingSboxOutput(8, x[1]) ^ calculatingSboxOutput(5, x[5])


def calculateKeys3(keysArray, z1, i):
    keysArray[i * 8 + 0] = calculatingSboxOutput(5, z1[8]) ^ calculatingSboxOutput(6, z1[9]) \
                           ^ calculatingSboxOutput(7, z1[7]) ^ calculatingSboxOutput(8, z1[6]) ^ calculatingSboxOutput(5, z1[2])

    keysArray[i * 8 + 1] = calculatingSboxOutput(5, z1[10]) ^ calculatingSboxOutput(6, z1[11]) \
                           ^ calculatingSboxOutput(7, z1[5]) ^ calculatingSboxOutput(8, z1[4]) ^ calculatingSboxOutput(6, z1[6])

    keysArray[i * 8 + 2] = calculatingSboxOutput(5, z1[12]) ^ calculatingSboxOutput(6, z1[13]) \
                           ^ calculatingSboxOutput(7, z1[3]) ^ calculatingSboxOutput(8, z1[2]) ^ calculatingSboxOutput(7, z1[9])

    keysArray[i * 8 + 3] = calculatingSboxOutput(5, z1[14]) ^ calculatingSboxOutput(6, z1[15]) \
                           ^ calculatingSboxOutput(7, z1[1]) ^ calculatingSboxOutput(8, z1[0]) ^ calculatingSboxOutput(8, z1[12])


def calculateKeys4(keysArray, x, i):
    keysArray[i * 8 + 4] = calculatingSboxOutput(5, x[0]) ^ calculatingSboxOutput(6, x[1]) \
                           ^ calculatingSboxOutput(7, x[7]) ^ calculatingSboxOutput(8, x[5]) ^ calculatingSboxOutput(7, x[4])

    keysArray[i * 8 + 5] = calculatingSboxOutput(5, x[2]) ^ calculatingSboxOutput(6, x[3]) \
                           ^ calculatingSboxOutput(7, x[6]) ^ calculatingSboxOutput(8, x[5]) ^ calculatingSboxOutput(8, x[7])

    keysArray[i * 8 + 6] = calculatingSboxOutput(5, x[4]) ^ calculatingSboxOutput(6, x[5]) \
                           ^ calculatingSboxOutput(7, x[1]) ^ calculatingSboxOutput(8, x[0]) ^ calculatingSboxOutput(6, x[3])

    keysArray[i * 8 + 7] = calculatingSboxOutput(5, x[6]) ^ calculatingSboxOutput(6, x[7]) \
                           ^ calculatingSboxOutput(7, x[2]) ^ calculatingSboxOutput(8, x[1]) ^ calculatingSboxOutput(5, x[5])


def generateMaskingAndRotationKeys(keysArray):
    Km = [None] * 16
    Kr = [None] * 16

    for i in range(16):
        Km[i] = keysArray[i * 2] ^ keysArray[i * 2 + 1]
        Kr[i] = keysArray[i * 2] & keysArray[i * 2 + 1]

    return Km, Kr
