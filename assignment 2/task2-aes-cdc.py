from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
import os
import os.path

# This code was inspired by the code given in Lecture 5 
# (L5/Symmetric/aes_cbc_file.py)

# BASE variable to let all OS work
BASE = os.path.dirname(os.path.abspath(__file__))

# this function decrypts the encrypted file
def decrypt_file(input, output_file_path, key):
    # with open(input_file_path, 'rb') as f:
        # salt = f.read(16)
    iv = input[:16]
    ciphertext = input[16:]

        # ciphertext = f.read()

        # kdf and salt is not needed since we already have the key

    # kdf = PBKDF2HMAC(
    #     algorithm=hashes.SHA256(),
    #     length=32,
    #     salt=salt,
    #     iterations=100000,
    # )
    # key = kdf.derive(password.encode())
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    decrypted_plaintext = plaintext
    with open(output_file_path, 'wb') as f:
        f.write(plaintext)
    
    return str(decrypted_plaintext)

# key and ciphertext recieved from task2.txt
    #string represents hexadecimal number
key = bytes.fromhex('140b41b22a29beb4061bda66b6747e14')
ciphertext = bytes.fromhex('4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81')

print('─' * 10)

print("Key:", key)

print('─' * 10)

# call decryption function 

decrypted_plaintext = decrypt_file(ciphertext, BASE + '/output/task2_dec', key)
print("Decryption: ", decrypted_plaintext)

print('─' * 10) 
