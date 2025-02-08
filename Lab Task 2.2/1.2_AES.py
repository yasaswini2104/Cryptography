# Extend the program (2) to encrypt and decrypt a given file.

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os

def pad(data):
    padding_length = 16 - (len(data) % 16)
    return data + bytes([padding_length])*padding_length

def unpad(data):
    return data[:-data[-1]]

def encrypt_file(input_file: str, output_file: str, password: str):
    try:
        key = password.ljust(32)[:32].encode() 
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        with open(input_file, 'rb') as f:
            plaintext = f.read()
        
        ciphertext = cipher.encrypt(pad(plaintext))
        
        with open(output_file, 'wb') as f:
            f.write(iv + ciphertext)
        print("Encryption successful. Encrypted data saved to", output_file)
    except FileNotFoundError:
        print("Error: Input file not found.")
    except Exception as e:
        print("Encryption failed:", str(e))

def decrypt_file(input_file: str, output_file: str, password: str):
    try:
        key = password.ljust(32)[:32].encode()
        
        with open(input_file, 'rb') as f:
            file_data=f.read()
        
        iv, ciphertext=file_data[:16], file_data[16:]
        cipher=AES.new(key, AES.MODE_CBC, iv)
        plaintext=unpad(cipher.decrypt(ciphertext))
        
        with open(output_file, 'wb') as f:
            f.write(plaintext)
        print("Decryption successful. Decrypted data saved to", output_file)
    except FileNotFoundError:
        print("Error: Encrypted file not found.")
    except ValueError:
        print("Error: Incorrect password or corrupted file.")
    except Exception as e:
        print("Decryption failed:", str(e))

if __name__ == "__main__":
    action = input("Enter 'e' to encrypt or 'd' to decrypt: ").strip().lower()
    if action == 'e':
        input_file = input("Enter the name of the file to encrypt: ").strip()
        output_file = input("Enter the output encrypted file name: ").strip()
        password = input("Enter encryption password: ").strip()
        encrypt_file(input_file, output_file, password)
    elif action == 'd':
        input_file = input("Enter the name of the file to decrypt: ").strip()
        output_file = input("Enter the output decrypted file name: ").strip()
        password = input("Enter decryption password: ").strip()
        decrypt_file(input_file, output_file, password)
    else:
        print("Invalid action. Use 'e' for encryption or 'd' for decryption.")
