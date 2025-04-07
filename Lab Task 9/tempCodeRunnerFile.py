from py_ecc.bls.ciphersuites import G2ProofOfPossession as bls
import hashlib

noofclients = 3
clients = []

# Step 1: Key generation for each client
for i in range(noofclients):
    privatekey = bls.KeyGen(i.to_bytes(2, 'big'))
    publickey = bls.SkToPk(privatekey)
    clients.append({
        'id': f'Client{i+1}',
        'private_key': privatekey,
        'public_key': publickey
    })

# Step 2: Create messages and hash them
messages = [f"Hello from {client['id']}".encode('utf-8') for client in clients]
hashed_messages = [hashlib.sha256(msg).digest() for msg in messages]  # Hash each message

signatures = []

# Step 3: Sign hashed messages
for i, client in enumerate(clients):
    hashed_msg = hashed_messages[i]
    signature = bls.Sign(client['private_key'], hashed_msg)
    signatures.append(signature)
    print(f"{client['id']} signed (hashed): {messages[i].decode()} -> {hashed_msg.hex()}")

# Step 4: Verify each individual signature
print("\nVerifying individual signatures:")
for i, client in enumerate(clients):
    is_valid = bls.Verify(client['public_key'], hashed_messages[i], signatures[i])
    print(f"{client['id']} signature valid: {is_valid}")
