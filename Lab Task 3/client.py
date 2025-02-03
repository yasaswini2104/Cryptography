import socket
import threading
import sys
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from Crypto.Random import get_random_bytes

SERVER_IP = '10.1.35.169'
PORT = 12345

KEY = b'SixteenByteKey!!SixteenByteKey!!' 

def encrypt_message(message):
    IV = get_random_bytes(16) 
    print(IV) 
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    padded_message = pad(message.encode(), AES.block_size)
    encrypted_bytes = cipher.encrypt(padded_message)
    return base64.b64encode(IV + encrypted_bytes).decode()  

def decrypt_message(encrypted_message):
    decoded_data = base64.b64decode(encrypted_message)
    IV = decoded_data[:16] 
    encrypted_bytes = decoded_data[16:]  
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    decrypted_bytes = cipher.decrypt(encrypted_bytes)
    return unpad(decrypted_bytes, AES.block_size).decode()


def send_message(client_socket):
    while True:
        message = input("Client: ")
        encrypted_message = encrypt_message(message)
        print(f" Encrypted Sent: {encrypted_message}")
        client_socket.sendall(encrypted_message.encode('utf-8'))

def receive_messages(client_socket):
    while True:
        encrypted_data = client_socket.recv(1024).decode('utf-8')
        if not encrypted_data:
            print("Server disconnected.")
            break

        decrypted_message = decrypt_message(encrypted_data)
        print(f"\nEncrypted Received: {encrypted_data}")
        sys.stdout.write(f"Server(decrypted): {decrypted_message}\n")
        sys.stdout.flush()

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((SERVER_IP, PORT))
print(f"Connected to server at {SERVER_IP}:{PORT}")

try:
    send_thread = threading.Thread(target=send_message, args=(client_socket,))
    receive_thread = threading.Thread(target=receive_messages, args=(client_socket,))
    send_thread.start()
    receive_thread.start()

    send_thread.join()
    receive_thread.join()
except Exception as e:
    print(f"Error: {e}")
finally:
    client_socket.close()
    print("Client disconnected.")
