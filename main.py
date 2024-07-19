import random
import base64
import os
import sys
from CBC import cbc_encrypt, cbc_decrypt
from mac import generate_mac, verify_mac
from ec_elgamal import gen_keypair, ec_elgamal_encrypt, ec_elgamal_decrypt, Curve25519 as curve

pass_of_dataset ="12345" #we need to set hard password

# Alice Generates EC ElGamal keys
print(">>> Alice generates a pair of EC ElGamal keys <<<")
alice_private_key, alice_public_key = gen_keypair(curve)
print("\n>>> Alice shares her public key with Bob <<<")

# Bob Generates EC ElGamal keys
print("\n>>> Bob generates a pair of EC ElGamal keys <<<")
bob_private_key, bob_public_key = gen_keypair(curve)

print("\n>>> Bob shares his public key with Alice <<<")

# generates hex key (256 bit) and iv (64 bit) for Cast256 CBC
print("\n>>> Alice generates private cast256-CBC key and IV <<<")
key = random.getrandbits(256)
iv = hex(random.getrandbits(64))[2:]

# Conceptual placeholder for encrypting the CAST256 key and IV with Bob's public key
print("\n>>> Alice encrypts cast256-CBC key and IV using EC ElGamal with Bob's public key <<<")
encrypted_key_iv = ec_elgamal_encrypt(bob_public_key, key, curve)

while True:
    Alice_login=input("Please Alice enter the password of dataset:  ")
    if(Alice_login != pass_of_dataset):
        print("Password not valid try again please!!")
    else:
        break

print("\n>>> Alice sends encrypted image to Bob with encrypted key and IV to Bob <<<")    
image_path = input("Enter the path to the image (make sure without apostrophes): ")
with open(image_path, 'rb') as image_file:
    image_data = image_file.read()
print("\n>>> Please wait until Alice finishes the Encryption step <<<")

image = base64.b64encode(image_data).decode('utf-8')
hex_key = hex(key)[2:]
encrypted_image = cbc_encrypt(image, hex_key, iv)
encrypted_image_data = base64.b64decode(encrypted_image)
encrypted_image_path = "encrypted_" + os.path.basename(image_path)
with open(encrypted_image_path, 'wb') as encrypted_image_file:
    encrypted_image_file.write(encrypted_image_data)

print(f"\n>>> Encrypted image saved to {encrypted_image_path} <<<")

while True:
    Bob_login=input("Please Bob enter the password of dataset: ")
    if(Bob_login != pass_of_dataset):
        print("Password not valid try again please!!")
    else:
        break

# Conceptual placeholder for Bob decrypting the CAST256 key and IV with his private key
print("\n>>> Bob decrypts the CAST256 key and IV using EC ElGamal with his private key <<<")
decrypted_key_iv = ec_elgamal_decrypt(bob_private_key, encrypted_key_iv, curve)

# Assuming decrypted_key_iv somehow gives us access to the original key and IV
decrypted_key = hex_key  # Placeholder for the actual decrypted key
decrypted_iv = iv        # Placeholder for the actual decrypted IV

print("\n>>> Bob decrypts the image <<<")
print("\n>>> Please wait until Bob finishes the Decryption step <<<")
decrypted_image = cbc_decrypt(encrypted_image, decrypted_key, decrypted_iv)
decrypted_image_data = base64.b64decode(decrypted_image)
decrypted_image_path = "decrypted_" + os.path.basename(image_path)
with open(decrypted_image_path, 'wb') as decrypted_image_file:
    decrypted_image_file.write(decrypted_image_data)

print(f"\n>>> Decrypted image saved to {decrypted_image_path} <<<")

# Generate the MAC for the original image (base64-encoded)
mac_key, mac = generate_mac(image)
print(f"\nMAC for the original image: {mac}\n")

# Securely transmit mac_key to Bob along with the encrypted image and keys
decrypted_image_base64 = base64.b64encode(decrypted_image_data).decode('utf-8')

# Verify the MAC for the base64-encoded decrypted image
verify_mac(decrypted_image_base64, mac, mac_key)