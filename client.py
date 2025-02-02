import socket
import threading
import sys

SERVER_IP = '192.168.31.47' # replace with server IP
PORT = 12345 # same port as the server has

def send_message(client_socket):
    while True:
        message = input("Client: ")
        client_socket.sendall(message.encode('utf-8'))

def receive_messages(client_socket):
    while True:
        data = client_socket.recv(1024).decode('utf-8')
        if not data:
            print("Server disconnected.")
            break

        sys.stdout.write(f"\rServer: {data}\n")
        sys.stdout.flush()

        sys.stdout.write("Client: ")
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

