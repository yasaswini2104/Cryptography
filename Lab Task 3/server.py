import socket
import threading
import sys
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


HOST = '10.1.35.169'
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
    print(IV)
    encrypted_bytes = decoded_data[16:]  
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    decrypted_bytes = cipher.decrypt(encrypted_bytes)
    return unpad(decrypted_bytes, AES.block_size).decode()


def send_messages(conn):
    while True:
        message = input("Server: ")
        encrypted_message = encrypt_message(message)
        print(f"Encrypted Sent: {encrypted_message}")
        conn.sendall(encrypted_message.encode('utf-8'))

def receive_messages(conn):
    while True:
        encrypted_data = conn.recv(1024).decode('utf-8')
        if not encrypted_data:
            print("Client disconnected.")
            break

        decrypted_message = decrypt_message(encrypted_data)
        print(f"\nEncrypted Received: {encrypted_data}")
        sys.stdout.write(f"Client (decrypted): {decrypted_message}\n")
        sys.stdout.flush()

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(1)
print(f"Server started on {HOST}:{PORT}. Waiting for a connection...")

conn, addr = server_socket.accept()
print(f"Connection established with {addr}")

try:
    send_thread = threading.Thread(target=send_messages, args=(conn,))
    receive_thread = threading.Thread(target=receive_messages, args=(conn,))
    send_thread.start()
    receive_thread.start()

    send_thread.join()
    receive_thread.join()
except Exception as e:
    print(f"Error: {e}")
finally:
    conn.close()
    server_socket.close()
    print("Server closed.")
