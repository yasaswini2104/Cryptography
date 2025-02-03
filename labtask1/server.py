import socket
import threading
import sys

HOST = '192.168.31.47'
PORT = 12345

def send_messages(conn):
    while True:
        message=input("Server: ")
        conn.sendall(message.encode('utf-8'))

def receive_messages(conn):
    while True:
        data = conn.recv(1024).decode('utf-8')
        if not data:
            print("Client disconnected.")
            break

        sys.stdout.write(f"\rClient: {data}\n")
        sys.stdout.flush()
        
        sys.stdout.write("Server: ")
        sys.stdout.flush()

server_socket=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(1) #allowing only on client to connect at a time
print(f"Server started on {HOST}:{PORT}. Waiting for a connection...")
conn, addr = server_socket.accept()
print(f" connection established with {addr}")

try:
    send_thread = threading.Thread(target=send_messages, args=(conn,))
    recieve_thread = threading.Thread(target=receive_messages, args=(conn,))
    send_thread.start()
    recieve_thread.start()

    send_thread.join()
    recieve_thread.join()
except Exception as e:
    print(f"Error: {e}")
finally:
    conn.close()
    server_socket.close()
    print("Server closed.")