from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# first party
priA=ec.generate_private_key(ec.SECP256R1())
pubA=priA.public_key()

#second party
priB=ec.generate_private_key(ec.SECP256R1())
pubB=priB.public_key()

# serialize and exchange the public keys through encoding(PEM)
S_A=pubA.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
S_B=pubB.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

# deserialization 
D_A=serialization.load_pem_public_key(S_A)
D_B=serialization.load_pem_public_key(S_B)

#key exchange in shared secret medium
A_secret=priA.exchange(ec.ECDH(), pubB)
B_secret=priB.exchange(ec.ECDH(), pubA)

assert A_secret == B_secret
print("Key exchange successful")
print("Shared secret: ", A_secret.hex())