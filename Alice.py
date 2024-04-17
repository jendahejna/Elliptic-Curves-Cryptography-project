import socket
import threading
import os
import ECDH

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature

def serialize_public_key(public_key):
    """Serializes the public key for transmission."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def derive_key(shared_secret):
    """Derives a key for AES encryption from the shared secret."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data'
    ).derive(shared_secret)

def create_encryptor_decryptor(key, iv=None):
    """Creates encryptor and decryptor objects using the derived key and an IV.
       If IV is None, generates a new one, otherwise uses the provided IV."""
    if iv is None:
        iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    return cipher.encryptor(), cipher.decryptor(), iv

def sign_message(private_key, message):
    """Signs a message using ECDSA."""
    return private_key.sign(message, ec.ECDSA(hashes.SHA256()))

def verify_signature(public_key, message, signature):
    """Verifies a message signature using ECDSA."""
    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False

# Communication functions
def send_messages(connection, user_name, encryptor, private_key):
    while True:
        message = input("")
        if message.lower() == 'quit':
            connection.send(b'quit')  # send quit signal
            break
        full_message = f"{user_name}: {message}"
        signature = sign_message(private_key, full_message.encode('utf-8'))
        full_message += '|' + signature.hex()  # Append signature in hex format for convenience
        encrypted_message = encryptor.update(full_message.encode('utf-8'))
        try:
            connection.send(encrypted_message)
            print(f"Sent encrypted message: {encrypted_message.hex()}")
        except Exception as e:
            print("\nFailed to send message. Error:", e)
            break

def receive_messages(connection, decryptor, public_key):
    while True:
        try:
            encrypted_message = connection.recv(1024)
            if not encrypted_message:
                print("\nPeer disconnected.")
                break
            message = decryptor.update(encrypted_message)
            if message:
                message, signature_hex = message.rsplit(b'|', 1)
                if verify_signature(public_key, message, bytes.fromhex(signature_hex.decode())):
                    print(f"\nDecrypted message: {message.decode('utf-8')}")
                else:
                    print("\nFailed to verify message signature.")
        except Exception as e:
            print("\nConnection lost. Error:", e)
            break

# The key exchange must now also handle the exchange of public keys for signature verification
def exchange_keys(connection, alicePrivKey, is_server):
    """Exchanges public keys and establishes encryption."""
    alicePubKey = alicePrivKey.public_key()
    public_key_bytes = serialize_public_key(alicePubKey)
    if is_server:
        # Server sends first, then receives
        connection.send(public_key_bytes)
        peer_public_key_bytes = connection.recv(1024)
    else:
        # Client receives first, then sendsA
        peer_public_key_bytes = connection.recv(1024)
        connection.send(public_key_bytes)

    bobPubKey = serialization.load_pem_public_key(peer_public_key_bytes)
    shared_secret = alicePrivKey.exchange(ec.ECDH(), bobPubKey)

    key = derive_key(shared_secret)
    encryptor, decryptor, iv = create_encryptor_decryptor(key)

    if is_server:
        connection.send(iv)  # Server sends IV
    else:
        iv = connection.recv(16)  # Client receives IV
        encryptor, decryptor, _ = create_encryptor_decryptor(key, iv)  # Use existing IV
    return encryptor, decryptor, bobPubKey

def main():
    user_name = input("Enter your name: ")
    peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    peer_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    alicePrivKey, alicePubKey, bobPrivKey, bobPubKey = ECDH.generate_ECDH_keys()


    if not attempt_connection(peer_socket):
        # Act as server
        is_server = True
        peer_socket = create_server()
    else:
        # Connected as client
        is_server = False
        print("Connected to Bob.")

    encryptor, decryptor, bobPubKey = exchange_keys(peer_socket, alicePrivKey, is_server)

    # Starting threads for sending and receiving messages
    receiver_thread = threading.Thread(target=receive_messages, args=(peer_socket, decryptor, bobPubKey))
    sender_thread = threading.Thread(target=send_messages, args=(peer_socket, user_name, encryptor, alicePrivKey))

    receiver_thread.start()
    sender_thread.start()

    receiver_thread.join()
    sender_thread.join()

    peer_socket.close()
    print("Chat ended.")

# Existing connection handling functions
def attempt_connection(peer_socket, target=('localhost', 8080)):
    try:
        peer_socket.connect(target)
        return True
    except ConnectionRefusedError:
        return False

def create_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('localhost', 8080))
    server_socket.listen(1)
    print("Waiting for connection on port 8080.")
    connection, address = server_socket.accept()
    print(f"Connection established with Bob {address}")
    return connection

if __name__ == "__main__":
    main()
