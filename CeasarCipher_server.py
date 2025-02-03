import socket
import threading
import sys  # Missing import fixed

HOST = '10.1.174.213'
PORT = 12345
SHIFT = 3  # Caesar cipher shift value

def caesar_cipher(text, shift):
    """Encrypt text using Caesar cipher."""
    encrypted_text = ""
    for char in text:
        if char.isalpha():
            shift_base = ord('A') if char.isupper() else ord('a')
            encrypted_text += chr((ord(char) - shift_base + shift) % 26 + shift_base)
        else:
            encrypted_text += char
    return encrypted_text

def caesar_decipher(text, shift):
    """Decrypt text using Caesar cipher."""
    return caesar_cipher(text, -shift)

def send_messages(conn):
    """Send encrypted messages to the client."""
    try:
        while True:
            sys.stdout.write("Server: ")  
            sys.stdout.flush()
            
            message = input()  # Taking input after printing prompt
            if message.lower() == "exit":
                print("Closing connection...")
                conn.sendall("exit".encode('utf-8'))
                break

            encrypted_message = caesar_cipher(message, SHIFT)  
            print(f"Encrypted Sent: {encrypted_message}")  
            conn.sendall(encrypted_message.encode('utf-8'))
    except:
        print("Connection closed by server.")

def receive_messages(conn):
    """Receive and decrypt messages from the client."""
    try:
        while True:
            data = conn.recv(1024).decode('utf-8')
            if not data or data.lower() == "exit":
                print("\nClient disconnected.")
                break

            decrypted_data = caesar_decipher(data, SHIFT)  
            print(f"\nEncrypted Received: {data}")  
            print(f"Client (Decrypted): {decrypted_data}")  

            sys.stdout.write("Server: ")  # Print Server prompt after receiving message
            sys.stdout.flush()
    except:
        print("Connection closed by client.")

# Setup server socket
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
except:
    print("Error occurred.")
finally:
    conn.close()  # Close connection only once
    server_socket.close()
    print("Server closed.")
