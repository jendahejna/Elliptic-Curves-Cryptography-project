# main.py
import os
import socket
import threading
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature

# Import or define the necessary functions from ECDH, ECDSA, EdDSA, and peer1 modules
from ECDH import generate_ECDH_keys, approve_ECDH_keys, save_ECDH_keys
from ECDSA import generate_ECDSA_keys, sign_message as sign_message_ecdsa, verify_message as verify_message_ecdsa
from EdDSA import generate_EdDSA_keys, sign_message as sign_message_eddsa, verify_message as verify_message_eddsa


def setup_connection():
    # Socket setup and attempt to connect or create server
    peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    peer_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    if not attempt_connection(peer_socket):
        peer_socket = create_server()
    else:
        print("Connected to the peer.")

    return peer_socket


def secure_key_exchange(peer_socket):
    # Generate ECDH keys and exchange them
    alicePrivKey, alicePubKey, bobPrivKey, bobPubKey = generate_ECDH_keys()
    aliceSharedKey, bobSharedKey = approve_ECDH_keys(alicePrivKey, alicePubKey, bobPrivKey, bobPubKey)
    save_ECDH_keys(alicePubKey, bobPubKey, aliceSharedKey, bobSharedKey)
    # Use shared keys for further encryption of messages


def main():
    user_name = input("Enter your name: ")
    peer_socket = setup_connection()

    # Start threads for sending and receiving messages
    receiver_thread = threading.Thread(target=receive_messages, args=(peer_socket,))
    sender_thread = threading.Thread(target=send_messages, args=(peer_socket, user_name,))

    receiver_thread.start()
    sender_thread.start()

    receiver_thread.join()
    sender_thread.join()

    peer_socket.close()
    print("Chat ended.")


if __name__ == "__main__":
    main()
