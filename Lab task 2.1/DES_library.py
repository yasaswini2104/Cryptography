#Using pycryptodome library to encrypt and Decrypt by DES3

from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

key =get_random_bytes(24) #24-byte key for 3DES
iv =get_random_bytes(8)  #8-byte Initialization Vector

cipher = DES3.new(key, DES3.MODE_CBC, iv)

plaintextin =input("Please enter the message to Encrypt:\n")
padded_text =pad(plaintextin.encode(), DES3.block_size)
ciphertext =cipher.encrypt(padded_text)
print(f"Ciphertext (Hex): {ciphertext.hex()}")

decipher =DES3.new(key, DES3.MODE_CBC, iv)

ciphertextin_hex = input("Please enter the ciphertext to Decrypt (Hex format):\n")
ciphertextin = bytes.fromhex(ciphertextin_hex)  # Convert back from hex to bytes
decrypted_padded_text = decipher.decrypt(ciphertextin)
decrypted_text = unpad(decrypted_padded_text, DES3.block_size).decode()
print(f"Decrypted Text: {decrypted_text}")
