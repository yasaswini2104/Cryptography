import random
from math import gcd

def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(n ** 0.5) + 1):
        if n % i == 0:
            return False
    return True

def generate_prime(bits=8):
    while True:
        num = random.randint(2*(bits-1), 2*bits - 1)
        if is_prime(num):
            return num

def mod_inverse(e, phi):
    a, b = e, phi
    x0, x1 = 1, 0
    while b:
        q = a // b
        a, b = b, a % b
        x0, x1 = x1, x0 - q * x1
    return x0 % phi if a == 1 else None

def generate_keys():
    p = generate_prime()
    q = generate_prime()
    while p == q:
        q = generate_prime()
    n=p*q
    phi = (p - 1) * (q - 1)
    e = random.randint(2, phi - 1)
    while gcd(e, phi) != 1:
        e = random.randint(2, phi - 1)
    
    d = mod_inverse(e, phi)
    if d is None:
        return generate_keys()
    return ((e, n), (d, n))

def encrypt(plain_text, public_key):
    e, n = public_key
    encrypted_chars = [str(pow(ord(char), e, n)) for char in plain_text]
    return " ".join(encrypted_chars)

def decrypt(cipher_text, private_key):
    d, n = private_key
    encrypted_numbers = cipher_text.split()
    decrypted_chars = [chr(pow(int(num), d, n)) for num in encrypted_numbers]
    return "".join(decrypted_chars)

public_key, private_key = generate_keys()
message = input("Enter msg to encrypt:\n")
print(f"Original Message: {message}")

cipher = encrypt(message, public_key)
print(f"Encrypted Message: {cipher}")

cipher_text = input("Enter message to decrypt (as space-separated numbers):\n")
decrypted_message = decrypt(cipher_text, private_key)
print(f"Decrypted Message: {decrypted_message}")