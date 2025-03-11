import socket
import threading
import sys
import random
import hashlib
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

SERVER_IP = '192.168.143.47'
PORT = 12345

# AES Encryption/Decryption
class AESCipher:
    def __init__(self, key):
        self.key = hashlib.sha256(str(key).encode()).digest()

    def encrypt(self, raw):
        cipher = AES.new(self.key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(raw.encode(), AES.block_size))
        encrypted_message = base64.b64encode(cipher.iv + ct_bytes).decode('utf-8')
        print(f"Encrypted Message: {encrypted_message}")
        return encrypted_message

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted_message = unpad(cipher.decrypt(enc[AES.block_size:]), AES.block_size).decode('utf-8')
        print(f"Decrypted Message: {decrypted_message}")
        return decrypted_message

# Diffie-Hellman Key Exchange
def diffie_hellman(p, g, private_key):
    return pow(g, private_key, p)

def handle_server(sock, aes_cipher):
    def send_messages():
        while True:
            message = input("Client: ")
            encrypted_message = aes_cipher.encrypt(message)
            sock.sendall(encrypted_message.encode('utf-8'))

    def receive_messages():
        while True:
            data = sock.recv(1024).decode('utf-8')
            if not data:
                print("Server disconnected.")
                break
            decrypted_message = aes_cipher.decrypt(data)
            sys.stdout.write(f"\rServer: {decrypted_message}\n")
            sys.stdout.flush()
            sys.stdout.write("Client: ")
            sys.stdout.flush()

    send_thread = threading.Thread(target=send_messages)
    receive_thread = threading.Thread(target=receive_messages)
    send_thread.start()
    receive_thread.start()

    send_thread.join()
    receive_thread.join()
    sock.close()

def client():
    try:
        p = int(input("Enter a prime number (p): "))
        g = int(input("Enter a primitive root modulo (g): "))

        private_a = random.randint(1, p-1)
        public_a = diffie_hellman(p, g, private_a)

        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((SERVER_IP, PORT))
        print(f"Connected to server at {SERVER_IP}:{PORT}")

        client_socket.sendall(str(public_a).encode('utf-8'))
        public_b = int(client_socket.recv(1024).decode('utf-8'))

        shared_secret = pow(public_b, private_a, p)
        print(f"Shared Secret (Client): {shared_secret}")

        aes_cipher = AESCipher(shared_secret)
        handle_server(client_socket, aes_cipher)
    
    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_socket.close()
        print("Client disconnected.")

if __name__ == "__main__":
    client()
