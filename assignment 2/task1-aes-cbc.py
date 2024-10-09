from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
import os
import os.path

# This code was inspired by the code given in Lecture 5 
# (L5/Symmetric/aes_cbc_file.py)

# BASE variable to let all OS work
BASE = os.path.dirname(os.path.abspath(__file__))

# this function encrypts plain text files into encrypted files
# PBKDF derives a strong key from the password
# use salt to further improve security
# https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/
def encrypt_file(input_file_path, output_file_path, password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password.encode())

    # A random IV is generated for each encryption session to ensure that 
    # same data encryptions will result in different ciphertexts.
    # MODE = CBC
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    # open the plaintext file to be read bytewise
    with open(input_file_path, 'rb') as f:
        plaintext = f.read()

    # padding is necessary in a situation when a block
    # does not have the same amount of data as the other block 
    # AES operates on blocks of data, so PKCS7 padding is 
    # applied to ensure the plaintext is a multiple of the block size.
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    # encryption 
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # create the encrypted file.
    # The salt, IV, and encrypted data are all written to the output file.
    with open(output_file_path, 'wb') as f:
        f.write(salt + iv + ciphertext)

    return key



# this function decrypts the encrypted file
def decrypt_file(input_file_path, output_file_path, password):
    with open(input_file_path, 'rb') as f:
        salt = f.read(16)
        iv = f.read(16)
        ciphertext = f.read()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password.encode())
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    with open(output_file_path, 'wb') as f:
        f.write(plaintext)



# call encryption function

key = encrypt_file(BASE + '/input/task1.txt', BASE + '/output/task1_enc', 'p@33w0rd')

print('─' * 10) 

# prints key
print("Key:", key)

print('─' * 10)

print("encrypted file has been added into the output folder")


print('─' * 10) 

# call decryption function 

decrypt_file(BASE + '/output/task1_enc', BASE + '/output/task1_dec', 'p@33w0rd')
print("decrypted file has been added into the output folder")

print('─' * 10) 