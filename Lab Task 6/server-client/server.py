import socket
import threading
import sys
import random
import hashlib
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

HOST = '192.168.143.47'
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

def handle_client(conn, aes_cipher):
    def send_messages():
        while True:
            message = input("Server: ")
            encrypted_message = aes_cipher.encrypt(message)
            conn.sendall(encrypted_message.encode('utf-8'))

    def receive_messages():
        while True:
            data = conn.recv(1024).decode('utf-8')
            if not data:
                print("Client disconnected.")
                break
            decrypted_message = aes_cipher.decrypt(data)
            sys.stdout.write(f"\rClient: {decrypted_message}\n")
            sys.stdout.flush()
            sys.stdout.write("Server: ")
            sys.stdout.flush()

    send_thread = threading.Thread(target=send_messages)
    receive_thread = threading.Thread(target=receive_messages)
    send_thread.start()
    receive_thread.start()

    send_thread.join()
    receive_thread.join()
    conn.close()

def server():
    try:
        p = int(input("Enter a prime number (p): "))
        g = int(input("Enter a primitive root modulo (g): "))

        private_b = random.randint(1, p-1)
        public_b = diffie_hellman(p, g, private_b)

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((HOST, PORT))
        server_socket.listen(1)
        print(f"Server started on {HOST}:{PORT}. Waiting for a connection...")

        conn, addr = server_socket.accept()
        print(f"Connection established with {addr}")

        public_a = int(conn.recv(1024).decode('utf-8'))
        conn.sendall(str(public_b).encode('utf-8'))

        shared_secret = pow(public_a, private_b, p)
        print(f"Shared Secret (Server): {shared_secret}")

        aes_cipher = AESCipher(shared_secret)
        handle_client(conn, aes_cipher)
    
    except Exception as e:
        print(f"Error: {e}")
    finally:
        server_socket.close()
        print("Server closed.")

if __name__ == "__main__":
    server()
