"""
Alice peer file.

Functions:
    derive_key:                 Derives a key for AES encryption from the shared key of this peer.
    create_encryptor_decryptor: Creates encryptor and decryptor objects using the derived key and an IV.
    send_messages:              Sends encrypted and signed messages or files from the user over a given connection.
    receive_messages:           Receives, decrypts, and verifies encrypted messages or files over a given connection.
    exchange_keys:              Exchanges ECDH public keys and establishes encryption.
    exchange_signature_keys:    Exchange signature public keys between two communication parties.
    attempt_connection:         Attempts to establish a connection to a specified target using the given socket.
    create_server:              Creates a server socket, binds it to a local address, listens for incoming connections.
    main:                       Demonstrates created functions and their implementation.

Authors:
    Jan Hejna, 221545
    Daniel Kluka, 203251
    Jan Rezek, 227374
    Michal Rosa, 221012

Documentation:
    Documentation is auto-generated and can be found in Documentation folders in index.html.
    Documentation authors:
        Daniel Kluka, 203251
        Michal Rosa, 221012

Version:
    5.0.1

Date:
    20.4.2024
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
from Protocols.ECIES import derive_encryption_parameters, encryption_chacha, encryption_aes, decrypt_message_aes, \
    decrypt_message_chacha
import logging


"""
Logger.

Function: 
    Logs and saves important actions and informations during peer to peer communication.

Author: 
    Daniel Kluka, 203251
"""
log_directory = "./Logs"
log_filename = "alice_peer.log"

if not os.path.exists(log_directory):
    os.makedirs(log_directory)

log_path = os.path.join(log_directory, log_filename)

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    filename=log_path,
                    filemode='w')
logger = logging.getLogger('AlicePeer')


def derive_key(shared_key):
    """
    Derives a key for AES encryption from the shared key of this peer.

    Args:
        shared_key: Shared key of this peer.

    Author:
        Jan Rezek, 227374
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

    Authors:
        Daniel Kluka, 203251
        Jan Rezek, 227374
    """
    if iv is None:
        iv = os.urandom(16)
        logger.debug("Generated new IV for AES encryption.")
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    return cipher.encryptor(), cipher.decryptor(), iv


def send_messages(connection, peer_name, alice_shared_key, ecies_type, signature_priv_key, signature_name):
    """
    Sends encrypted and signed messages or files from the user over a given connection.

    Args:
        connection:         The communication channel used to send encrypted messages.
        peer_name:          Name of this peer.
        alice_shared_key:   The shared secret key derived during the cryptographic session initialization, used for
                            encrypting message.
        ecies_type:         The type of symmetric encryption used in the ECIES scheme (AES, ChaCha).
        signature_priv_key: Private key of this peer.
        signature_name:     Specifies the type of signature scheme (ECDSA, EdDSA)

    Returns:
        The function returns None as it is designed to run indefinitely until
        the user decides to quit the messaging session.

    Exceptions:
        The function will catch and print any exceptions raised during the message
        sending process, mainly focusing on connection issues.

    Authors:
        Jan Hejna, 221545
        Daniel Kluka, 203251
        Jan Rezek, 227374
        Michal Rosa, 221012
    """
    separator = b"||"
    files_to_send_dir = "./Files/FilesToSend/"
    received_files_dir = "./Files/ReceivedFiles/"
    os.makedirs(received_files_dir, exist_ok=True)

    while True:
        command = input("Enter your message or type 'sendFile' to send a file: ")
        logger.debug(f"User input message: {command}")

        if command.lower() == 'quit':
            connection.send(b'quit')
            logger.info("User initiated quit.")
            break

        if command.lower() == 'sendfile':
            logger.info("User wants to send file")
            filename = input("Enter the filename to send: ")
            filepath = os.path.join(files_to_send_dir, filename)
            if os.path.exists(filepath):
                logger.info(f"File path: {filepath}")
                with open(filepath, 'rb') as f:
                    file_data = f.read()
                file_message = f"FILE::{filename}||".encode() + file_data
                connection.send(file_message)
                logger.info(f"Sent file: {filename}")
                print(f"Sent file: {filename}")
            else:
                logger.warning(f"File not found: {filename}")
                print(f"File not found: {filename}")
            continue

        # Encode the full message
        full_message = f"{peer_name}: {command}".encode('utf-8')

        # Sign the message
        signature = sign_message(signature_priv_key, full_message, signature_name)

        # Encrypt the entire message including the signature
        if ecies_type == "ChaCha":
            ecies_key, hmac_key = derive_encryption_parameters(alice_shared_key)
            nonce, encrypted_message, mac = encryption_chacha(ecies_key, hmac_key, full_message)
            final_message = nonce + separator + encrypted_message + separator + signature
        elif ecies_type == "AES":
            ecies_key, hmac_key = derive_encryption_parameters(alice_shared_key)
            iv, encrypted_message, mac = encryption_aes(ecies_key, hmac_key, full_message)
            final_message = iv + separator + encrypted_message + separator + signature

        try:
            connection.send(final_message)
            logger.debug(f"Sent encrypted and signed message: {encrypted_message.hex()}")
            print(f"Sent encrypted message: {final_message.hex()}")
        except Exception as e:
            logger.error(f"Failed to send message. Error: {e}", exc_info=True)
            print("Failed to send message. Error:", e)
            break


def receive_messages(connection, alice_shared_key, ecies_type, signature_pub_key, signature_name):
    """
    Receives, decrypts, and verifies encrypted messages or files over a given connection.

    Parameters:
        connection:         The communication channel used to receive encrypted messages.
        alice_shared_key:   The shared secret key derived during the cryptographic session initialization, used for
                            decrypting the encrypted message.
        ecies_type:         The type of symmetric encryption used in the ECIES scheme (AES, ChaCha).
        signature_pub_key:  Public key of other peer.
        signature_name:     Specifies the type of signature scheme (ECDSA, EdDSA)

    Exceptions:
        General exception handling to catch and handle unexpected errors.

    Authors:
        Jan Hejna, 221545
        Daniel Kluka, 203251
        Jan Rezek, 227374
        Michal Rosa, 221012
    """
    separator = b"||"
    received_files_dir = "Files/ReceivedFiles/"
    os.makedirs(received_files_dir, exist_ok=True)
    while True:
        try:
            encrypted_message = connection.recv(2048)  # Suggested buffer size for adequate capacity
            logger.info(f"Received encrypted message: {encrypted_message.hex()}")
            print(f"Received encrypted message: {encrypted_message.hex()}")

            parts = encrypted_message.split(separator)
            if len(parts) == 3:
                nonce_iv, ciphertext, signature = parts

                # Decrypt the message
                if ecies_type == "ChaCha":
                    ecies_key, hmac_key = derive_encryption_parameters(alice_shared_key)
                    message = decrypt_message_chacha(ecies_key, nonce_iv, ciphertext)
                elif ecies_type == "AES":
                    aes_key, hmac_key = derive_encryption_parameters(alice_shared_key)
                    message = decrypt_message_aes(aes_key, nonce_iv, ciphertext)

                # Verify the signature
                if message and verify_signature(signature_pub_key, message, signature, signature_name):
                    logger.info(f"Decrypted and verified message: {message.decode('utf-8')}")
                    print(f"Decrypted and verified message: {message.decode('utf-8')}")
                else:
                    logger.error("Failed to verify message signature.")
                    print("Failed to verify message signature or message is None.")
            elif len(parts) == 2:
                # File messages assumed to be in the format: FILE::filename||filedata
                filename = parts[0].split(b"::")[1].decode()
                file_data = parts[1]
                filepath = os.path.join(received_files_dir, filename)
                with open(filepath, 'wb') as f:
                    f.write(file_data)
                logger.info(f"Received and saved file: {filename}")
                print(f"Received and saved file: {filename}")
            else:
                logger.warning("Invalid message format, parts count: ", len(parts))
                print("Invalid message format, parts count: ", len(parts))
        except Exception as e:
            logger.error(f"Connection lost. Error: {e}", exc_info=True)
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

    Author:
        Daniel Kluka, 203251
        Jan Rezek, 227374
    """
    alice_pub_key = alice_priv_key.public_key()
    public_key_bytes = ECDH.serialize_pub_key(alice_pub_key)
    if is_server:
        # Server sends first, then receives
        connection.send(public_key_bytes)
        peer_public_key_bytes = connection.recv(1024)
        logger.info("Alice connected as server for ECDH key exchange.")
    else:
        # Client receives first, then sends
        peer_public_key_bytes = connection.recv(1024)
        connection.send(public_key_bytes)
        logger.info("Alice connected as client for ECDH key exchange.")

    bob_pub_key = serialization.load_pem_public_key(peer_public_key_bytes)
    alice_shared_key = ECDH.shared_ecdh_key(alice_priv_key, bob_pub_key)
    logger.debug(f"Alice generated shared key: {alice_shared_key.hex()}")

    # Serialize the shared key for transmission
    shared_key_bytes = alice_shared_key.hex().encode('utf-8')

    # Exchange the shared key
    if is_server:
        # Server sends the shared key
        connection.send(shared_key_bytes)
        peer_shared_key_bytes = connection.recv(1024)
        logger.info("Alice received Bob's shared key.")
    else:
        peer_shared_key_bytes = connection.recv(1024)
        # Client sends the shared key
        connection.send(shared_key_bytes)
        logger.info("Alice sends shared key to Bob.")

    # Confirm that both shared keys match (optional step for additional security)
    if shared_key_bytes != peer_shared_key_bytes:
        logger.error("Shared keys do not match!", exc_info=True)
        raise ValueError("Shared keys do not match!")

    base_dir = "../Keys/ECDH/Alice"
    os.makedirs(base_dir, exist_ok=True)
    ECDH.save_ecdh_keys(alice_pub_key, alice_shared_key, base_dir)
    logger.info("ECDH keys saved at: " + base_dir)

    key = derive_key(alice_shared_key)
    encryptor, decryptor, iv = create_encryptor_decryptor(key)

    if is_server:
        # Server sends IV
        connection.send(iv)
        logger.info("Alice sends IV.")
    else:
        # Client receives IV
        iv = connection.recv(16)
        logger.debug("Alice receives and uses IV.")
        # Use existing IV
        encryptor, decryptor, _ = create_encryptor_decryptor(key, iv)
    return encryptor, decryptor, bob_pub_key, alice_shared_key


def exchange_signature_keys(connection, local_signature_pub_key, is_server):
    """
    Exchange signature public keys between two communication parties.

    Args:
        connection:                 Active socket connection for data exchange.
        local_signature_pub_key:    Local user's public key.
        is_server:                  Indicates if the local party is the server (True) or the client (False). If True,
                                    sends first and receives second; if False, receives first and sends second.

    Returns:
        peer_signature_pub_key: The remote party's public key, deserialized from PEM format, for verifying signatures.

    Raises:
        TypeError: If `local_signature_pub_key` is not the correct type, indicating an invalid key.

    Notes:
        Keys are transmitted in PEM format and deserialized upon receipt to maintain cryptographic integrity and
        operability.

    Authors:
        Jan Hejna, 221545
        Daniel Kluka, 203251
    """
    if not isinstance(local_signature_pub_key, (ec.EllipticCurvePublicKey, ed25519.Ed25519PublicKey)):
        logger.error("Provided public key is not a valid public key object.", exc_info=True)
        raise TypeError("Provided public key is not a valid public key object.")

    local_pub_key_bytes = ECDH.serialize_pub_key(local_signature_pub_key)

    if is_server:
        # Server sends first, then receives
        connection.send(local_pub_key_bytes)
        peer_pub_key_bytes = connection.recv(1024)
        logger.info("Alice connected as server for signature exchange.")
    else:
        # Client receives first, then sends
        peer_pub_key_bytes = connection.recv(1024)
        connection.send(local_pub_key_bytes)
        logger.info("Alice connected as client for signature exchange.")

    # Convert received bytes back to public key
    peer_signature_pub_key = serialization.load_pem_public_key(peer_pub_key_bytes)
    logger.debug("Received peer signature public key.")
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

    Authors:
        Daniel Kluka, 203251
        Jan Rezek, 227374
    """
    try:
        peer_socket.connect(target)
        logger.debug("Attempted connection to localhost.")
        return True
    except ConnectionRefusedError:
        logger.error("Failed to create server or accept connection.", exc_info=True)
        return False


def create_server():
    """
    Creates a server socket, binds it to a local address, and listens for incoming client connections.

    Returns:
        socket: Returns the client connection socket object, which can be used to send and receive data.

    Exceptions:
        Socket-related exceptions can occur during socket creation, binding, listening, or accepting connections.

    Authors:
        Daniel Kluka, 203251
        Jan Rezek, 227374
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('localhost', 8080))
    server_socket.listen(1)
    logger.info("Alice is waiting for a connection on port 8080.")
    print("Waiting for connection on port 8080.")
    connection, address = server_socket.accept()
    logger.info(f"Connection established with Bob at {address}")
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
        3. Prompts the user to enter the name of the algorithm for digital signature.
        4. Prompts the user to enter the name encryption method for ECIES.
        5. Prompts the user to enter the new file password for file encryption.
        6. Attempts to establish a connection with Bob:
            - If a connection is not initially established, it assumes the role of server and waits for a client.
            - If connected, it assumes the role of client.
        7. Exchanges public keys and establishes encryption parameters including encryptor and decryptor.
        8. Starts separate threads for sending and receiving encrypted messages or files.
        9. Waits for both threads to finish, which occurs when the chat session ends.
        10. Closes the network socket and prints a message indicating the end of the chat.
        11. Saves log that was created during peer to peer communication.

    The user is responsible for specifying the correct elliptic curve name that must be agreed upon by both peers.
    The user is also responsible for choosing algorithm of digital signature, encryption method and file password,
    which must be agreed on the same way.

    Authors:
        Jan Hejna, 221545
        Daniel Kluka, 203251
        Jan Rezek, 227374
        Michal Rosa, 221012
    """
    print("Peer name: Alice")
    peer_name = "Alice"
    peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    peer_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    curve_name = input("Enter the ECDH curve name, must be the same for both peers (e.g., SECP384R1, SECP521R1): ")
    signature_name = input("Enter algorithm for digital signature (e.g., ECDSA, EdDSA): ")
    ecies_type = input("Enter encryption method for ECIES (e.g., ChaCha, AES): ")
    logger.info("User selected: " + curve_name + ", " + signature_name + ", " + ecies_type)

    password = input("Choose new key file password: ")
    logger.info("User password for key file: " + password)

    logger.info("Generating ECDH keys.")
    alice_priv_key, alice_pub_key = ECDH.generate_ecdh_keys(curve_name)
    logger.debug("Generated ECDH Alice private key and public key.")

    if not attempt_connection(peer_socket):
        # Act as server
        is_server = True
        peer_socket = create_server()
        logger.info("Server created.")
    else:
        # Connected as client
        is_server = False
        logger.info("Connected to Bob.")
        print("Connected to Bob.")

    logger.info("Exchanging ECDH keys.")
    encryptor, decryptor, bob_pub_key, alice_shared_key = exchange_keys(peer_socket, alice_priv_key, is_server)
    logger.debug("Exchanged ECDH keys.")

    logger.info("Generating and encrypting Alice's signature keys.")
    signature_private_key, signature_public_key = key_generation(signature_name, 'alice_priv.pem', 'alice_pub.pem',
                                                                 password)
    logger.debug("Generated and encrypted Alice's signature keys.")

    logger.info("Exchanging signature keys.")
    peer_signature_pub_key = exchange_signature_keys(peer_socket, signature_public_key, is_server)
    logger.debug("Exchanged signature keys.")

    logger.info("Starting receiver and sender threads.")
    receiver_thread = threading.Thread(target=receive_messages,
                                       args=(peer_socket, alice_shared_key, ecies_type, peer_signature_pub_key,
                                             signature_name))
    sender_thread = threading.Thread(target=send_messages,
                                     args=(peer_socket, peer_name, alice_shared_key, ecies_type, signature_private_key,
                                           signature_name))
    logger.info("Started receiver and sender threads.")

    receiver_thread.start()
    sender_thread.start()

    receiver_thread.join()
    sender_thread.join()

    peer_socket.close()
    print("Chat ended.")


if __name__ == "__main__":
    main()
