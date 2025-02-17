import socket
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Key (24 bytes) with parity adjustment
key = DES3.adjust_key_parity(b'!@#$%^&*TOP SECRET KEY98')

def des3_encrypt(plaintext):
    """Encrypts a plaintext message using 3DES in CBC mode."""
    iv = get_random_bytes(8)  # Generate a random IV for each encryption
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    padded_text = pad(plaintext.encode(), DES3.block_size)
    ciphertext = cipher.encrypt(padded_text)
    return iv.hex() + ciphertext.hex()

def des3_decrypt(ciphertext_hex):
    """Decrypts a ciphertext message using 3DES in CBC mode."""
    try:
        iv = bytes.fromhex(ciphertext_hex[:16])
        ciphertext = bytes.fromhex(ciphertext_hex[16:])
        decipher = DES3.new(key, DES3.MODE_CBC, iv)
        decrypted_padded_text = decipher.decrypt(ciphertext)
        return unpad(decrypted_padded_text, DES3.block_size).decode()
    except Exception as e:
        print(f"Decryption error: {e}")
        return None

def main():
    """Main server function to handle encrypted communication."""
    server_ip = '10.1.170.23'  # Server's IP address
    server_port = 21312

    # Create a TCP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((server_ip, server_port))
    server_socket.listen(1)

    print(f"Server started on {server_ip}:{server_port}. Waiting for connections...")

    try:
        while True:
            conn, addr = server_socket.accept()
            print(f"Connection established with {addr}")

            try:
                while True:
                    encrypted_message = conn.recv(1024).decode()
                    if not encrypted_message or encrypted_message.lower() == 'bye':
                        print("Client disconnected.")
                        break

                    print(f"CLIENT SENT (encrypted, HEX): {encrypted_message}")
                    decrypted_message = des3_decrypt(encrypted_message)
                    
                    if decrypted_message is None:
                        print("Invalid encrypted message received.")
                        continue

                    print(f"CLIENT SENT (decrypted): {decrypted_message}")

                    # Get server response
                    server_message = input("SERVER (plaintext): ")
                    encrypted_response = des3_encrypt(server_message)

                    print(f"SERVER SENDING (plaintext): {server_message}")
                    print(f"SERVER SENDING (encrypted, HEX): {encrypted_response}")

                    conn.send(encrypted_response.encode())

                    if server_message.lower() == "bye":
                        print("Closing connection...")
                        break
            finally:
                conn.close()
                print("Client connection closed.")

    except KeyboardInterrupt:
        print("\nServer shutting down.")

    finally:
        server_socket.close()
        print("Server socket closed.")

if __name__ == "__main__":
    main()
