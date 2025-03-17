from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

def ecc_key_exchange(curve):
    A_pri = ec.generate_private_key(curve())
    A_pri = ec.generate_private_key(curve())

    A_pub = A_pri.public_key()
    B_pub = A_pri.public_key()

    A_secret = A_pri.exchange(ec.ECDH(), B_pub)
    B_secret = A_pri.exchange(ec.ECDH(), A_pub)

    assert A_secret == B_secret, "Key exchange failed!"

    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  
        salt=None,
        info=b"ECC AES Key",
    ).derive(A_secret)

    return aes_key

#Function to encrypt message using AES-GCM
def encrypt_message(aes_key, plaintext):
    iv = os.urandom(12)  
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv))
    encryptor = cipher.encryptor()

    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return iv, ciphertext, encryptor.tag  

#Function to decrypt message using AES-GCM
def decrypt_message(aes_key, iv, ciphertext, tag):
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()

    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode()

message = "Hell0 SRM AP"

#Test with SECP256R1 curve
print("Using SECP256R1 curve:")
aes_key1 = ecc_key_exchange(ec.SECP256R1)
iv1, ciphertext1, tag1 = encrypt_message(aes_key1, message)
decrypted_message1 = decrypt_message(aes_key1, iv1, ciphertext1, tag1)
print("Ciphertext:", ciphertext1.hex())
print("Decrypted message:", decrypted_message1, "\n")

#Test with SECP384R1 curve
print("Using SECP384R1 curve:")
aes_key2 = ecc_key_exchange(ec.SECP384R1)
iv2, ciphertext2, tag2 = encrypt_message(aes_key2, message)
decrypted_message2 = decrypt_message(aes_key2, iv2, ciphertext2, tag2)
print("Ciphertext:", ciphertext2.hex())
print("Decrypted message:", decrypted_message2, "\n")
