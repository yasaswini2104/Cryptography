import random

def diffie_hellman(p, g, private_a, private_b):
    public_a=pow(g, private_a, p)
    public_b=pow(g, private_b, p)
    shared_secret_a=pow(public_b, private_a, p)
    shared_secret_b=pow(public_a, private_b, p)
    return public_a, public_b, shared_secret_a, shared_secret_b

try:
    p=int(input("Enter a prime number (p): "))
    g=int(input("Enter a primitive root modulo (g): "))
    private_a = random.randint(1, p-1)
    private_b = random.randint(1, p-1)
    public_a, public_b, shared_secret_a, shared_secret_b = diffie_hellman(p, g, private_a, private_b)
    
    print("Private key of A:", private_a)
    print("Private key of B:", private_b)
    print("Public key of A:", public_a)
    print("Public key of B:", public_b)
    print("Shared secret key computed by A:", shared_secret_a)
    print("Shared secret key computed by B:", shared_secret_b)

    assert shared_secret_a==shared_secret_b, "Error: Shared secret keys do not match!"
    print("Key Exchange successful!!")
except ValueError:
    print("Invalid input, Please enter integer valu again")
    
   