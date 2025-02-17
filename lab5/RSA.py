import random

def generate_prime(bits=8):
    while True:
        num = random.randint(2*(bits-1), 2*bits - 1)
        if is_prime(num):
            return num
        
def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(n ** 0.5) + 1):
        if n % i == 0:
            return False
    return True

def generateKEYS():
    p=7919
    q=1009
    print(p,q)
    n=p*q
    phi=(p-1)*(q-1)

    e = random.randint(2, phi-1)
    while gcd(e, phi)!= 1:
        e = random.randint(2, phi-1)

    d = ModInverse(e,phi)
    if d==-1:
        raise ValueError("No modular inverse found for e. Try different p and q.")

    return e, d, n

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def power(base, expo, m):  # calculating (base^expo) mod m
    res = 1
    base = base % m
    while expo > 0:
        if expo & 1:
            res = (res * base) % m
        base = (base * base) % m
        expo = expo // 2
    return res

def ModInverse(e, phi):
    for d in range(2, phi):
        if (e*d) % phi==1:
            return d
    return -1  

# m^e mod n -- encryption
def encrypt(m, e, n):
    return power(m, e, n)

# c^d mod n -- decryption
def decrypt(c, d, n):
    return power(c, d, n)

if __name__ == "__main__":
    e, d, n = generateKEYS()
    print(f"Public Key (e, n): ({e}, {n})")
    print(f"Private Key (d, n): ({d}, {n})")

    with open("enc.txt", "r") as file:
        msg = int(file.read().strip())  # Read message from file and convert to integer
    
    C = encrypt(msg, e, n)
    print(f"Encrypted message: {C}")
    
    with open("encrypted.txt", "w") as file:
        file.write(str(C))
    
    D = decrypt(C, d, n)
    print(f"Decrypted message: {D}")
    
    with open("decrypted.txt", "w") as file:
        file.write(str(D))
