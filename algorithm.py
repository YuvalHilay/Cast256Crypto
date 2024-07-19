from bitarray.util import *
from CAST256.keyGenerator import keyHexToBinaryAndNumberOfRounds, keyGenerator  # Update path if necessary
from CAST256.sboxes import calculatingSboxOutput  # Update path if necessary
from bitarray import bitarray

"""The Codes for encryption/decryption cast256 round include all methods in each round"""

def roundsForAlgorithm(L, R, Km, Kr, numberOfRounds, encryptionOrDecryption):
    I = [None] * numberOfRounds
    f = [None] * numberOfRounds
    if encryptionOrDecryption:
        for i in range(numberOfRounds):
            I1 = [None] * 4
            # 1, 4, 7, 10, 13, and 16
            if i % 3 == 0:
                sumBitArray = additionModulo2exp64(Km[i], R)
                I[i] = circularLeftRotation(sumBitArray, Kr[i])
                I1 = divideITo4Parts(I[i])
                f[i] = function1(I1)
            # Rounds 2, 5, 8, 11, and 14 use f function Type 2.
            elif i % 3 == 1:
                xorResult = Km[i] ^ R
                I[i] = circularLeftRotation(xorResult, Kr[i])
                I1 = divideITo4Parts(I[i])
                f[i] = function2(I1)
            # Rounds 3, 6, 9, 12, and 15 use f function Type 3.
            elif i % 3 == 2:
                subResult = subtractionModulo2exp64(Km[i], R)
                I[i] = circularLeftRotation(subResult, Kr[i])
                I1 = divideITo4Parts(I[i])
                f[i] = function3(I1)

            tmp = L
            L = R
            R = tmp ^ f[i]

    else:
        for i in range(numberOfRounds-1, -1, -1):
            I1 = [None] * 4
            # 1, 4, 7, 10, 13, and 16
            if i % 3 == 0:
                sumBitArray = additionModulo2exp64(Km[i], R)
                I[i] = circularLeftRotation(sumBitArray, Kr[i])
                I1 = divideITo4Parts(I[i])
                f[i] = function1(I1)
            # Rounds 2, 5, 8, 11, and 14 use f function Type 2.
            elif i % 3 == 1:
                xorResult = Km[i] ^ R
                I[i] = circularLeftRotation(xorResult, Kr[i])
                I1 = divideITo4Parts(I[i])
                f[i] = function2(I1)
            # Rounds 3, 6, 9, 12, and 15 use f function Type 3.
            elif i % 3 == 2:
                subResult = subtractionModulo2exp64(Km[i], R)
                I[i] = circularLeftRotation(subResult, Kr[i])
                I1 = divideITo4Parts(I[i])
                f[i] = function3(I1)

            tmp = L
            L = R
            R = tmp ^ f[i]

    return L, R, Km, Kr, I, f


def splitPlainOrCipherText(plaintext):
    binaryPlainText = plainOrCipherTextHexToBinary(plaintext)
    leftside = binaryPlainText[0:64]  # CAST256 uses 64 bits per side
    rightside = binaryPlainText[64:128]

    return leftside, rightside

def plainOrCipherTextHexToBinary(plaintextHex):
    h_size = len(plaintextHex) * 4
    int_value = int(plaintextHex, 16)
    plaintextString = bin(int_value)[2:].zfill(128)  # CAST256 uses 256 bits
    binaryPlaintext = bitarray(plaintextString)
    return binaryPlaintext


def split_plaintext_to_hex_blocks(plaintext):
    blocks_list = []
    for i in range(0, len(plaintext), 16):  # CAST256 blocks are larger
        block = plaintext[i:i + 16].ljust(16, "\0")
        hex_value = hex(int.from_bytes(block.encode('utf-8'), 'big'))[2:]
        blocks_list.append(hex_value)
    return blocks_list


def divideITo4Parts(I):
    x = []
    for i in range(4):
        x.append(I[i * 16:(i + 1) * 16])  # Adjust for 256-bit input
    return x


def circularLeftRotation(moduleResult, Kr):
    x = ba2int(Kr)
    temp = moduleResult[0:x]
    moduleResult <<= x
    moduleResult[64 - x:64] = temp  # Adjust for 256-bit
    return moduleResult


def additionModulo2exp64(term1, term2):
    sumInt = (ba2int(term1) + ba2int(term2)) % (2 ** 64)
    sumBitArray = int2ba(sumInt, 64)
    return sumBitArray


def subtractionModulo2exp64(term1, term2):
    sumInt = (ba2int(term1) - ba2int(term2)) % (2 ** 64)
    sumBitArray = int2ba(sumInt, 64)
    return sumBitArray


def function1(I):
    # f = ((S1[Ia] ^ S2[Ib]) - S3[Ic]) + S4[Id]
    xorResult = calculatingSboxOutput(1, I[0]) ^ calculatingSboxOutput(2, I[1])
    subResult = subtractionModulo2exp64(xorResult, calculatingSboxOutput(3, I[2]))
    sumResult = additionModulo2exp64(subResult, calculatingSboxOutput(4, I[3]))
    return sumResult


def function2(I):
    # f = ((S1[Ia] - S2[Ib]) + S3[Ic]) ^ S4[Id]
    subResult = subtractionModulo2exp64(calculatingSboxOutput(1, I[0]), calculatingSboxOutput(2, I[1]))
    sumResult = additionModulo2exp64(subResult, calculatingSboxOutput(3, I[2]))
    xorResult = sumResult ^ calculatingSboxOutput(4, I[3])
    return xorResult


def function3(I):
    # f = ((S1[Ia] + S2[Ib]) ^ S3[Ic]) - S4[Id]
    sumResult = additionModulo2exp64(calculatingSboxOutput(1, I[0]), calculatingSboxOutput(2, I[1]))
    xorResult = sumResult ^ calculatingSboxOutput(3, I[2])
    subResult = subtractionModulo2exp64(xorResult, calculatingSboxOutput(4, I[3]))
    return subResult


def algorithm(text, key, encryptionOrDecryption):
    keyBinary, numberOfRounds = keyHexToBinaryAndNumberOfRounds(key)
    Km, Kr, keysArray, zArray, xArray = keyGenerator(keyBinary)
    L, R = splitPlainOrCipherText(text)
    L, R, Km, Kr, I, f = roundsForAlgorithm(L, R, Km, Kr, numberOfRounds, encryptionOrDecryption)
    return ba2hex(R) + ba2hex(L)
