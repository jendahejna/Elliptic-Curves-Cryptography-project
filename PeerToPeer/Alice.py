"""
Alice peer file.

Functions:
    serialize_public_key:       Serializes the public key for transmission.
    derive_key:                 Derives a key for AES encryption from the shared key of this peer.
    create_encryptor_decryptor: Creates encryptor and decryptor objects using the derived key and an IV.
    sign_message:               Signs a message using ECDSA.
    verify_signature:           Verifies a message signature using ECDSA.
    send_messages:              Sends encrypted and signed messages from the user over a given connection.
    receive_messages:           Receives, decrypts, and verifies encrypted messages over a given connection.
    exchange_keys:              Exchanges public keys and establishes encryption.
    attempt_connection:         Attempts to establish a connection to a specified target using the given socket.
    create_server:              Creates a server socket, binds it to a local address, listens for incoming connections.
    main:                       Demonstrates created functions and their implementation.

File authors:
    Jan Hejna, 221545
    Daniel Kluka, 203251
    Jan Rezek, 227374
    Michal Rosa, 221012

Documentation author:
    Daniel Kluka, 203251

Version:
    3.0

Date:
    18.4.2024
"""
import socket
import threading
import os
from Protocols import ECDH

from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from Protocols.signature import key_generation, sign_message, verify_signature


def derive_key(shared_key):
    """
    Derives a key for AES encryption from the shared key of this peer.

    Args:
        shared_key: Shared key of this peer.
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data'
    ).derive(shared_key)


def create_encryptor_decryptor(key, iv=None):
    """
    Creates encryptor and decryptor objects using the derived key and an IV.
    If IV is None, generates a new one, otherwise uses the provided IV.

    Args:
        key:    Derived key from shared key.
        iv:     Initialization vector for increased security.

    Returns:
        encryptor:  Data encryptor object.
        decryptor:  Data decryptor object.
        iv:         Initialization vector.
    """
    if iv is None:
        iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    return cipher.encryptor(), cipher.decryptor(), iv


# def sign_file(private_key, message):
#    """
#    Signs a message using ECDSA.

#    Args:
#        private_key:    Private key of this peer.
#        message:        Message to be signed.

#    Return:
#        Digital signature of signed message to increase authentication.

#    """
#    return 0


def send_messages(connection, peer_name, encryptor, signature_priv_key, signature_name):
    """
    Sends encrypted and signed messages from the user over a given connection.

    Args:
        connection:         The communication channel used to send encrypted messages.
        peer_name:          Name of this peer.
        encryptor:          Data encryptor object.
        signature_priv_key: Private key of this peer.
        signature_name:

    Returns:
        The function returns None as it is designed to run indefinitely until
        the user decides to quit the messaging session.

    Exceptions:
        The function will catch and print any exceptions raised during the message
        sending process, mainly focusing on connection issues.
    """
    while True:
        message = input("Enter your message ('quit' to exit): ")
        if message.lower() == 'quit':
            connection.send(b'quit')  # Send quit signal
            break

        # print("Key type:", type(signature_priv_key))
        # print("Signature name:", signature_name)

        # Prepare the message by prefixing the username
        full_message = f"{peer_name}: {message}"
        # Sign the message
        signature = sign_message(signature_priv_key, full_message.encode('utf-8'), signature_name)
        # Encode signature in hex and append to the message
        full_message += '|' + signature.hex()

        # Encrypt the entire message, including the signature
        encrypted_message = encryptor.update(full_message.encode('utf-8')) + encryptor.finalize()

        try:
            connection.send(encrypted_message)
            print(f"Sent encrypted message: {encrypted_message.hex()}")
        except Exception as e:
            print("Failed to send message. Error:", e)
            break


def receive_messages(connection, decryptor, signature_pub_key, signature_name):
    """
    Receives, decrypts, and verifies encrypted messages over a given connection.

    Parameters:
        connection: The communication channel used to receive encrypted messages.
        decryptor:  Data decryptor object.
        signature_pub_key: Public key of other peer.
        signature_name:

    Exceptions:
        General exception handling to catch and handle unexpected errors
    """
    while True:
        try:
            encrypted_message = connection.recv(1024)
            if not encrypted_message:
                print("Peer disconnected.")
                break

            # Decrypt the received message
            message = decryptor.update(encrypted_message) + decryptor.finalize()

            # Split message and its signature
            message, signature_hex = message.rsplit(b'|', 1)

            # Verify the signature
            if verify_signature(signature_pub_key, message, bytes.fromhex(signature_hex.decode()), signature_name):
                print("Decrypted and verified message:", message.decode('utf-8'))
            else:
                print("Failed to verify message signature.")
        except Exception as e:
            print("Connection lost. Error:", e)
            break


def exchange_keys(connection, alice_priv_key, is_server):
    """
    Exchanges public keys and establishes encryption.

    Args:
        connection:     The communication channel used to send and receive public keys.
        alice_priv_key: Alice's private key used to generate her public key and to compute the shared ECDH key.
        is_server:      A flag indicating whether the caller is the server or client.

    Returns:
        tuple:  A tuple containing the encryptor, decryptor, and Bob's public key:
            encryptor:      Used to encrypt messages.
            decryptor:      Used to decrypt received messages.
            bob_pub_key:    Bob's public key for signature verification.

    Exceptions:
        This function handles connection and serialization errors internally, primarily
        during the key exchange or IV management phases. Any exceptions will cause
        an appropriate error message to be printed and will terminate the execution.
    """
    alice_pub_key = alice_priv_key.public_key()
    public_key_bytes = ECDH.serialize_pub_key(alice_pub_key)
    if is_server:
        # Server sends first, then receives
        connection.send(public_key_bytes)
        peer_public_key_bytes = connection.recv(1024)
    else:
        # Client receives first, then sends
        peer_public_key_bytes = connection.recv(1024)
        connection.send(public_key_bytes)

    bob_pub_key = serialization.load_pem_public_key(peer_public_key_bytes)
    alice_shared_key = ECDH.shared_ecdh_key(alice_priv_key, bob_pub_key)

    # Serialize the shared key for transmission
    shared_key_bytes = alice_shared_key.hex().encode('utf-8')  # Assuming shared_key is bytes-compatible

    # Exchange the shared key
    if is_server:
        connection.send(shared_key_bytes)  # Server sends the shared key
        peer_shared_key_bytes = connection.recv(1024)
    else:
        peer_shared_key_bytes = connection.recv(1024)
        connection.send(shared_key_bytes)  # Client sends the shared key

    # Confirm that both shared keys match (optional step for additional security)
    assert shared_key_bytes == peer_shared_key_bytes, "Shared keys do not match!"

    base_dir = "../Keys/ECDH/Alice"
    os.makedirs(base_dir, exist_ok=True)
    ECDH.save_ecdh_keys(alice_pub_key, alice_shared_key, base_dir)

    key = derive_key(alice_shared_key)
    encryptor, decryptor, iv = create_encryptor_decryptor(key)

    if is_server:
        connection.send(iv)  # Server sends IV
    else:
        iv = connection.recv(16)  # Client receives IV
        encryptor, decryptor, _ = create_encryptor_decryptor(key, iv)  # Use existing IV
    return encryptor, decryptor, bob_pub_key


def exchange_signature_keys(connection, local_signature_pub_key, is_server):
    """Exchange signature public keys between two communication parties."""
    # Ensure the public key is not already bytes and is the correct key object
    if not isinstance(local_signature_pub_key, (ec.EllipticCurvePublicKey, ed25519.Ed25519PublicKey)):
        raise TypeError("Provided public key is not a valid public key object.")

    local_pub_key_bytes = ECDH.serialize_pub_key(local_signature_pub_key)

    if is_server:
        # Server sends first, then receives
        connection.send(local_pub_key_bytes)
        peer_pub_key_bytes = connection.recv(1024)
    else:
        # Client receives first, then sends
        peer_pub_key_bytes = connection.recv(1024)
        connection.send(local_pub_key_bytes)

    # Convert received bytes back to public key
    peer_signature_pub_key = serialization.load_pem_public_key(peer_pub_key_bytes)
    return peer_signature_pub_key


def attempt_connection(peer_socket, target=('localhost', 8080)):
    """
    Attempts to establish a connection to a specified target using the given socket.

    Args:
        peer_socket:    The socket object configured for network communication.
        target:         A tuple containing the target host address and port number.

    Returns:
        Returns True if the connection is successfully established, False if not.

    Exceptions:
        This function catches this specific exception to return False.
    """
    try:
        peer_socket.connect(target)
        return True
    except ConnectionRefusedError:
        return False


def create_server():
    """
    Creates a server socket, binds it to a local address, and listens for incoming client connections.

    Returns:
        socket: Returns the client connection socket object, which can be used to send and receive data.

    Exceptions:
        Socket-related exceptions can occur during socket creation, binding, listening, or accepting connections.
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('localhost', 8080))
    server_socket.listen(1)
    print("Waiting for connection on port 8080.")
    connection, address = server_socket.accept()
    print(f"Connection established with Bob {address}")
    return connection


def main():
    """
    Initializes and runs the main functionality for Alice's side of a secure chat application.

    This function handles the setup and management of a peer-to-peer (P2P) encrypted chat session
    using elliptic curve cryptography (ECC) for secure key exchange and message encryption.

    Steps:
        1. Sets up Alice's identity and creates a socket for network communication.
        2. Prompts the user to enter the name of the elliptic curve for key generation.
        3. Attempts to establish a connection with Bob:
            - If a connection is not initially established, it assumes the role of server and waits for a client.
            - If connected, it assumes the role of client.
        4. Exchanges public keys and establishes encryption parameters including encryptor and decryptor.
        5. Starts separate threads for sending and receiving encrypted messages.
        6. Waits for both threads to finish, which occurs when the chat session ends.
        7. Closes the network socket and prints a message indicating the end of the chat.

    The user is responsible for specifying the correct elliptic curve name that must be agreed upon by both peers.
    """
    print("Peer name: Alice")
    peer_name = "Alice"
    peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    peer_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    curve_name = input("Enter the ECDH curve name, must be the same for both peers (e.g., SECP384R1, SECP521R1): ")
    signature_name = input("Enter algorithm for digital signature (e.g., ECDSA, EdDSA): ")
    alice_priv_key, alice_pub_key = ECDH.generate_ecdh_keys(curve_name)

    if not attempt_connection(peer_socket):
        # Act as server
        is_server = True
        peer_socket = create_server()
    else:
        # Connected as client
        is_server = False
        print("Connected to Bob.")

    encryptor, decryptor, bob_pub_key = exchange_keys(peer_socket, alice_priv_key, is_server)

    # Generate signature keys (replace 'ECDSA' with your desired algorithm, e.g., 'EdDSA')
    signature_private_key, signature_public_key = key_generation(signature_name, 'alice_priv.pem', 'alice_pub.pem')

    # Exchange signature public keys (assuming the exchange_keys function can be adjusted to handle this)
    peer_signature_pub_key = exchange_signature_keys(peer_socket, signature_public_key, is_server)

    # Starting threads for sending and receiving messages
    receiver_thread = threading.Thread(target=receive_messages,
                                       args=(peer_socket, decryptor, peer_signature_pub_key, signature_name))
    sender_thread = threading.Thread(target=send_messages,
                                     args=(peer_socket, peer_name, encryptor, signature_private_key, signature_name))

    receiver_thread.start()
    sender_thread.start()

    receiver_thread.join()
    sender_thread.join()

    peer_socket.close()
    print("Chat ended.")


if __name__ == "__main__":
    main()
