import time
import os
import task3_rsa_1024
import task3_rsa_2048
from cryptography.hazmat.primitives import serialization

# this code was inspired by the code found in Lecture 6 and is further
# improved by chat gpt

# a fix for making paths working on all OS
BASE = os.path.dirname(os.path.abspath(__file__))

# File paths
original_file = os.path.join(BASE, "input", "task3.txt")
enc_file_1024 = os.path.join(BASE, "output", "task3_enc_1024")
dec_file_1024 = os.path.join(BASE, "output", "task3_dec_1024")
enc_file_2048 = os.path.join(BASE, "output", "task3_enc_2048")
dec_file_2048 = os.path.join(BASE, "output", "task3_dec_2048")
pri_key_1024 = os.path.join(BASE, "Keys", "private_key_1024.pem")
pub_key_1024 = os.path.join(BASE, "Keys", "public_key_1024.pem")
pri_key_2048 = os.path.join(BASE, "Keys", "private_key_2048.pem")
pub_key_2048 = os.path.join(BASE, "Keys", "public_key_2048.pem")

# For storing elapsed times
time_1024 = 0
time_2048 = 0

print('─' * 10 + '1024-BIT' + '─' * 10)
print('─' * 10 + '1024-BIT' + '─' * 10)
print('─' * 10 + '1024-BIT' + '─' * 10)

# Measure time for 1024-bit encryption/decryption and signature
start_1024 = time.time()

# Generate keys for 1024-bit
private_key_1024, public_key_1024 = task3_rsa_1024.generate_keys(pri_key_1024, pub_key_1024)

# Print private and public keys
private_key_pem_1024 = private_key_1024.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
public_key_pem_1024 = public_key_1024.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

print("Private Key:\n", private_key_pem_1024.decode('utf-8'))
print("Public Key:\n", public_key_pem_1024.decode('utf-8'))

# Encrypts the file
task3_rsa_1024.encrypt_file(original_file, public_key_1024, enc_file_1024)

# Decrypts the file
decrypted_1024 = task3_rsa_1024.decrypt_file(enc_file_1024, private_key_1024, dec_file_1024)

# Ends timer for 1024-bit encryption/decryption and signature
end_1024 = time.time()
time_1024 = end_1024 - start_1024
print(f"1024-bit Encryption/Decryption Time: {time_1024:.4f} seconds")

# Sign and verify with 1024-bit keys
with open(original_file, "rb") as file:
    original_data = file.read()
hash_value_1024 = task3_rsa_1024.hash(original_data)
signature_1024 = task3_rsa_1024.sign_data(hash_value_1024, private_key_1024)

print('─' * 10) 

# Print the signature
print("Signature:\n", signature_1024.hex())

print('─' * 10) 

is_valid_1024 = task3_rsa_1024.verify_signature(hash_value_1024, signature_1024, public_key_1024)
print(f"1024-bit Signature Valid: {is_valid_1024}")

print('─' * 10 + '2048-BIT' + '─' * 10)
print('─' * 10 + '2048-BIT' + '─' * 10)
print('─' * 10 + '2048-BIT' + '─' * 10)

# Measure time for 2048-bit encryption/decryption and signature
start_2048 = time.time()

# Generate keys for 2048-bit
private_key_2048, public_key_2048 = task3_rsa_2048.generate_keys(pri_key_2048, pub_key_2048)

# Print private and public keys
private_key_pem_2048 = private_key_2048.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
public_key_pem_2048 = public_key_2048.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

print("Private Key:\n", private_key_pem_2048.decode('utf-8'))
print("Public Key:\n", public_key_pem_2048.decode('utf-8'))

# Encrypts the file
task3_rsa_2048.encrypt_file(original_file, public_key_2048, enc_file_2048)

# Decrypts the file
decrypted_2048 = task3_rsa_2048.decrypt_file(enc_file_2048, private_key_2048, dec_file_2048)

# Ends timer for 2048-bit encryption/decryption and signature
end_2048 = time.time()
time_2048 = end_2048 - start_2048
print(f"1024-bit Encryption/Decryption Time: {time_2048:.4f} seconds")

# Sign and verify with 2048-bit keys
with open(original_file, "rb") as file:
    original_data = file.read()
hash_value_2048 = task3_rsa_2048.hash(original_data)
signature_2048 = task3_rsa_2048.sign_data(hash_value_2048, private_key_2048)

print('─' * 10) 

# Print the signature
print("Signature:\n", signature_2048.hex())

print('─' * 10) 

is_valid_2048 = task3_rsa_2048.verify_signature(hash_value_2048, signature_2048, public_key_2048)
print(f"2048-bit Signature Valid: {is_valid_2048}")

# Print both time results at the end
print('─' * 10 + 'TIME SUMMARY' + '─' * 10)
print(f"1024-bit Total Time: {time_1024:.4f} seconds")
print(f"2048-bit Total Time: {time_2048:.4f} seconds")