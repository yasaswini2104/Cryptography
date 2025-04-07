from py_ecc.bls.ciphersuites import G2ProofOfPossession as bls

noofclients= 3
clients = []
for i in range(noofclients):
    privatekey=bls.KeyGen(i.to_bytes(2,'big'))
    publickey=bls.SkToPk(privatekey)
    clients.append({
        'id':f'Client{i+1}',
        'private_key':privatekey,
        'public_key':publickey
    })
messages=[f"Hello from {client['id']}".encode('utf-8') for client in clients]

signatures = []
for i, client in enumerate(clients):
    message = messages[i]
    signature = bls.Sign(client['private_key'], message)
    signatures.append(signature)
    print(f"{client['id']} signed: {message.decode()}")

#Verify each individual signature
print("\nVerifying individual signatures:")
for i, client in enumerate(clients):
    valid = bls.Verify(client['public_key'], messages[i], signatures[i])
    print(f"{client['id']} signature valid: {valid}")
