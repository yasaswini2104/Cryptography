import socket
import threading
import sys  # Needed for flushing output

HOST = '10.1.174.213'  # Server's IP address
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

def send_messages(client_socket):
    """Send encrypted messages to the server."""
    try:
        while True:
            sys.stdout.write("Client: ")  
            sys.stdout.flush()
            
            message = input()
            if message.lower() == "exit":
                print("Closing connection...")
                client_socket.sendall("exit".encode('utf-8'))
                break

            encrypted_message = caesar_cipher(message, SHIFT)  
            print(f"Encrypted Sent: {encrypted_message}")  
            client_socket.sendall(encrypted_message.encode('utf-8'))
    except:
        print("Connection closed by client.")

def receive_messages(client_socket):
    """Receive and decrypt messages from the server."""
    try:
        while True:
            data = client_socket.recv(1024).decode('utf-8')
            if not data or data.lower() == "exit":
                print("\nServer disconnected.")
                break

            decrypted_data = caesar_decipher(data, SHIFT)  
            print(f"\nEncrypted Received: {data}")  
            print(f"Server (Decrypted): {decrypted_data}")  

            sys.stdout.write("Client: ")  # Print Client prompt after receiving message
            sys.stdout.flush()
    except:
        print("Connection closed by server.")

# Connect to the server
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))
print(f"Connected to server at {HOST}:{PORT}")

try:
    send_thread = threading.Thread(target=send_messages, args=(client_socket,))
    receive_thread = threading.Thread(target=receive_messages, args=(client_socket,))
    
    send_thread.start()
    receive_thread.start()

    send_thread.join()
    receive_thread.join()
except:
    print("Error occurred.")
finally:
    client_socket.close()
    print("Client closed.")
