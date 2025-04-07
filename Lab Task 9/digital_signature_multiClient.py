from py_ecc.bls.ciphersuites import G2ProofOfPossession as bls
import hashlib

noofclients = 3
clients = []

#Key generation for each client
for i in range(noofclients):
    prk = bls.KeyGen(i.to_bytes(2, 'big'))
    puk = bls.SkToPk(prk)
    clients.append({
        'id': f'Client{i+1}',
        'private_key': prk,
        'public_key': puk
    })

#Create messages and hash them
messages = [f"Hello from {client['id']}".encode('utf-8') for client in clients]
hashed_messages = [hashlib.sha256(msg).digest() for msg in messages]
signatures = []

#Sign hashed messages
for i, client in enumerate(clients):
    hashed_msg = hashed_messages[i]
    signature = bls.Sign(client['private_key'], hashed_msg)
    signatures.append(signature)
    print(f"{client['id']} signed (hashed): {messages[i].decode()} -> {hashed_msg.hex()}")

#Verify each individual signature
print("\nVerifying individual signatures:")
for i, client in enumerate(clients):
    is_valid = bls.Verify(client['public_key'], hashed_messages[i], signatures[i])
    print(f"{client['id']} signature valid: {is_valid}")
