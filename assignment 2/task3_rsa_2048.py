import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

# all task3 related codes were inspired by codes found in Lecture 6

# a fix for making paths working on all OS
BASE = os.path.dirname(os.path.abspath(__file__))

# ------- i. Generate keys (1024-bit). -------------------------------------

def generate_keys(pri_output_path, pub_output_path):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,  # 2048-bit key
    )
    public_key = private_key.public_key()

    # the code below was recieved from a python cryptography documentation
    # Asymmetric/RSA/Keyserialization
    # https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#key-serialization

    # vvv STORES PRIVATE AND PUBLIC KEY vvv

    pri_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(b'mypassword')
    )

    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(pri_output_path, "wb") as file:
        file.write(pri_pem)

    with open(pub_output_path, "wb") as file:
        file.write(pub_pem)

     # ^^^ STORES PRIVATE AND PUBLIC KEY ^^^

    return private_key, public_key

# ------ ii. Encrypt the provided plaintext file using RSA and padding -----

# Encrypt the file
def encrypt_file(file_path, public_key, output_path):

    # Read the plaintext data from the file
    with open(file_path, "rb") as file:
        plaintext = file.read()

    # Encrypt the data using OAEP padding
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Write the encrypted data to the output file
    with open(output_path, "wb") as file:
        file.write(ciphertext)

# Decrypt the file
def decrypt_file(encrypted_file_path, private_key, output_path):
    with open(encrypted_file_path, "rb") as file:
        ciphertext = file.read()

    # Decrypt the data using OAEP padding
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Write the encrypted data to the output file
    with open(output_path, "wb") as file:
        file.write(plaintext)
    return plaintext

# ------- iii. Add support for RSA digital signatures: implement a function -
# ------- to sign messages with the private key and verify signatures with 
# ------- the public key.

# ChatGPT was used to provide an example of a code for hashing the data
# hashes the data
def hash(data):
    hashing = hashes.Hash(hashes.SHA256())
    hashing.update(data)
    hash_value = hashing.finalize()
    return hash_value

# Sign the data
def sign_data(data, private_key):
    signature = private_key.sign(
        data,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# Verify the signature
def verify_signature(data, signature, public_key):
    try:
        public_key.verify(
            signature,
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Signature verification failed: {e}")
        return False
