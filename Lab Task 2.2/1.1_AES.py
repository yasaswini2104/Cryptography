#Implement AES using the available library to encrypt and decrypt a given plain text file.

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os

def pad(data):
    padding_length = 16-(len(data)%16)
    return data+bytes([padding_length])*padding_length

def unpad(data):
    return data[:-data[-1]]

def encrypt_file(input_file: str, output_file: str, password: str):
    key=password.ljust(32)[:32].encode() 
    iv=get_random_bytes(16)
    cipher=AES.new(key, AES.MODE_CBC, iv)
    
    with open(input_file, 'rb') as f:
        plaintext = f.read()
    
    ciphertext = cipher.encrypt(pad(plaintext))
    
    with open(output_file, 'wb') as f:
        f.write(iv+ciphertext)
    print("Encryption successful. Encrypted data saved to", output_file)

def decrypt_file(input_file: str, output_file: str, password: str):
    key = password.ljust(32)[:32].encode()
    
    with open(input_file, 'rb') as f:
        file_data = f.read()
    
    iv, ciphertext=file_data[:16], file_data[16:]
    cipher=AES.new(key, AES.MODE_CBC, iv)
    plaintext=unpad(cipher.decrypt(ciphertext))
    
    with open(output_file, 'wb') as f:
        f.write(plaintext)
    print("Decryption successful. Decrypted data saved to", output_file)

encrypt_file("plaintext.txt", "encrypted.aes", "strongpassword")
decrypt_file("encrypted.aes", "decrypted.txt", "strongpassword")
