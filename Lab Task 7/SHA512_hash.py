import hashlib

def generate_sha512_hash(text):
    encoded_text = text.encode('utf-8')
    hash_object = hashlib.sha512(encoded_text)
    hash_hex = hash_object.hexdigest()
    
    return hash_hex

text = input("Enter text to hash: ")
hash_code = generate_sha512_hash(text)
print("SHA-512 Hash:", hash_code)
