from cryptography.hazmat.primitives.asymmetric.dh import DHParameterNumbers
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import hashlib
import os
import base64

# Generate DH parameters and keys
parameters = dh.generate_parameters(generator=2, key_size=512, backend=default_backend())

private_key_A = parameters.generate_private_key()
public_key_A = private_key_A.public_key()
private_key_B = parameters.generate_private_key()
public_key_B = private_key_B.public_key()

shared_key_A = private_key_A.exchange(public_key_B)
shared_key_B = private_key_B.exchange(public_key_A)

def derive_key(shared_key):
    return HKDF(
        algorithm=SHA256(),
        length=32,  
        salt=None,
        info=b'session key',
        backend=default_backend()
    ).derive(shared_key)

aes_key = derive_key(shared_key_A)

# AES encryption function
def aes_encrypt(plaintext, key):
    iv = os.urandom(16) 
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    padding_length = 16 - (len(plaintext) % 16)
    plaintext += chr(padding_length) * padding_length  
    
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode()

def aes_decrypt(ciphertext, key):
    ciphertext = base64.b64decode(ciphertext)
    iv, ciphertext = ciphertext[:16], ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    padding_length = plaintext[-1]  
    return plaintext[:-padding_length].decode() 

# Compute SHA-256 hash of a message
def compute_hash(message):
    return hashlib.sha256(message.encode()).hexdigest()

# Sender encrypts 
def send_secure_message(message, key):
    message_hash = compute_hash(message) 
    combined_message = message + message_hash  
    encrypted_message = aes_encrypt(combined_message, key)  
    return encrypted_message

# Receiver decrypts 
def receive_secure_message(encrypted_message, key):
    decrypted_message = aes_decrypt(encrypted_message, key)  
    original_message, received_hash = decrypted_message[:-64], decrypted_message[-64:]  
    
    # Verify integrity
    computed_hash = compute_hash(original_message)
    if computed_hash == received_hash:
        return f"Message integrity verified! Received message: {original_message}"
    else:
        return "Integrity check failed! Message tampered."

message = input("Enter your message: ")

encrypted_msg = send_secure_message(message, aes_key)
print("\nEncrypted Message Sent:", encrypted_msg)
decryption_result = receive_secure_message(encrypted_msg, aes_key)
print("\nDecryption Result:", decryption_result)